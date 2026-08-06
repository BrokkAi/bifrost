//! The analyzer-owned half of Python's import analysis: the two per-file moka
//! caches and the reverse-import index behind [`ImportAnalysisProvider`].
//!
//! Every resolution rule these methods apply lives in
//! [`brokk_bifrost_python::imports`]; what stays here is the memoization and the
//! bulk store reads, which need `PythonAnalyzer`'s own cells and
//! `TreeSitterAnalyzer`.

use super::PythonAnalyzer;
use crate::analyzer::{CodeUnit, CodeUnitIndex, ImportAnalysisProvider, ImportInfo, ProjectFile};
use crate::hash::{HashMap, HashSet};
use brokk_bifrost_python::declarations::python_module_name;
use brokk_bifrost_python::graph_support::extract_type_identifiers;
use brokk_bifrost_python::imports::{
    PythonImportDetails, extract_package_from_python_wildcard, python_import_details,
    resolve_import_bindings, resolve_imports_batched, resolve_python_relative_module,
};
use std::sync::Arc;

impl ImportAnalysisProvider for PythonAnalyzer {
    fn imported_code_units_of(&self, file: &ProjectFile) -> Arc<HashSet<CodeUnit>> {
        if let Some(cached) = self.imported_code_units.get(file) {
            return cached;
        }

        let resolved = Arc::new(resolve_import_bindings(self, file).into_values().collect());
        self.imported_code_units
            .insert(file.clone(), Arc::clone(&resolved));
        resolved
    }

    fn referencing_files_of(&self, file: &ProjectFile) -> HashSet<ProjectFile> {
        if let Some(cached) = self.referencing_files.get(file) {
            return (*cached).clone();
        }

        let referencing = self
            .build_reverse_import_index()
            .get(file)
            .map(|files| (**files).clone())
            .unwrap_or_default();
        self.referencing_files
            .insert(file.clone(), Arc::new(referencing.clone()));
        referencing
    }

    fn import_info_of(&self, file: &ProjectFile) -> Vec<ImportInfo> {
        self.inner.import_info_of(file)
    }

    /// Flattens every import's resolved targets without collapsing by binding name -- unlike
    /// `imported_code_units_of`, whose result is built from a binding-name-keyed map and would
    /// silently drop one target when two imports share a local binding (e.g. a try/except fallback
    /// import), losing a real dependency edge. This is `could_import_file`'s fallback, called once
    /// per non-matching candidate file across the whole workspace, so resolving from the
    /// already-fetched `imports` via the batched path (not re-fetching, not re-resolving per import)
    /// is what keeps that walk affordable.
    fn imported_code_units_from_infos(
        &self,
        file: &ProjectFile,
        imports: &[ImportInfo],
    ) -> Option<Arc<HashSet<CodeUnit>>> {
        Some(Arc::new(
            resolve_imports_batched(self, file, imports)
                .into_iter()
                .flatten()
                .map(|(_, code_unit)| code_unit)
                .collect(),
        ))
    }

    /// Without this, `scan_usages` falls back to `import_info_of` one file at
    /// a time across the whole workspace (see #602) -- the other languages
    /// already implement this bulk hook.
    fn import_infos_for_files(
        &self,
        files: &[ProjectFile],
    ) -> Option<HashMap<ProjectFile, Vec<ImportInfo>>> {
        Some(self.inner.bulk_import_infos(files.iter().cloned()))
    }

    fn relevant_imports_for(&self, code_unit: &CodeUnit) -> HashSet<String> {
        let Some(source) = self.inner.get_source(code_unit, false) else {
            return HashSet::default();
        };

        let extracted = extract_type_identifiers(&source);
        if extracted.is_empty() {
            return HashSet::default();
        }

        let imports = self.inner.import_info_of(code_unit.source());
        if imports.is_empty() {
            return HashSet::default();
        }

        let mut matched = HashSet::default();
        let mut resolved = HashSet::default();
        let mut wildcard_imports = Vec::new();

        for info in imports {
            if info.is_wildcard {
                wildcard_imports.push(info.clone());
                continue;
            }

            if let Some(identifier) = info.identifier.as_deref()
                && extracted.contains(identifier)
            {
                matched.insert(info.raw_snippet.clone());
                resolved.insert(identifier.to_string());
            }

            if let Some(alias) = info.alias.as_deref()
                && extracted.contains(alias)
            {
                matched.insert(info.raw_snippet.clone());
                resolved.insert(alias.to_string());
            }
        }

        let unresolved: HashSet<_> = extracted
            .into_iter()
            .filter(|identifier| !resolved.contains(identifier))
            .collect();
        if unresolved.is_empty() || wildcard_imports.is_empty() {
            return matched;
        }

        let mut resolved_via_wildcard = HashSet::default();
        let mut used_wildcards = HashSet::default();
        for ident in &unresolved {
            for wildcard in &wildcard_imports {
                let Some(package_name) = extract_package_from_python_wildcard(wildcard) else {
                    continue;
                };

                if self
                    .inner
                    .definitions(&format!("{package_name}.{ident}"))
                    .next()
                    .is_some()
                {
                    used_wildcards.insert(wildcard.raw_snippet.clone());
                    resolved_via_wildcard.insert(ident.clone());
                }
            }
        }

        matched.extend(used_wildcards);

        let remaining: HashSet<_> = unresolved.difference(&resolved_via_wildcard).collect();
        if !remaining.is_empty() {
            matched.extend(wildcard_imports.into_iter().map(|info| info.raw_snippet));
        }

        matched
    }

    fn could_import_file(
        &self,
        source_file: &ProjectFile,
        imports: &[ImportInfo],
        target: &ProjectFile,
    ) -> bool {
        // Relative imports keep their own per-import resolution (including the conservative
        // "unresolvable -> assume yes" fallback) since that's specific to each import, not a
        // file-wide property. Non-relative imports are checked once against the cached, file-wide
        // resolved-target set below rather than re-resolving every import on every call -- the
        // final answer is the same disjunction either way, just evaluated in a different order.
        for import in imports {
            let Some(details) = python_import_details(import) else {
                continue;
            };
            if let PythonImportDetails::FromImport { module, name, .. } = &details
                && module.starts_with('.')
            {
                let Some(resolved_module) = resolve_python_relative_module(source_file, module)
                else {
                    return true;
                };
                let candidate_module = format!("{resolved_module}.{name}");
                if python_module_name(target) == candidate_module
                    || python_module_name(target) == resolved_module
                {
                    return true;
                }
            }
        }
        self.resolve_import_target_files(source_file)
            .contains(target)
    }
}
