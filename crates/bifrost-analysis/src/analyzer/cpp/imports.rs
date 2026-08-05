//! The `CppAnalyzer` half of C++ include analysis.
//!
//! `#include` parsing, the workspace-wide [`IncludeTargetIndex`] and every
//! target-resolution rule moved to [`brokk_bifrost_cpp::imports`]; what stays
//! here is the two provider impls the analyzer satisfies and the memo cells
//! (`OnceLock`, `PoolSafeMemo`) whose contents those functions produce.

use super::*;
use brokk_bifrost_cpp::imports::{
    parse_quoted_include, quoted_include_paths, resolve_direct_include_targets_with_index,
};
use std::path::Path;
use std::sync::Arc;

impl TestDetectionProvider for CppAnalyzer {}

impl ImportAnalysisProvider for CppAnalyzer {
    fn imported_code_units_of(&self, file: &ProjectFile) -> HashSet<CodeUnit> {
        if let Some(cached) = self.imported_code_units.get(file) {
            return (*cached).clone();
        }

        let mut resolved = HashSet::default();
        let include_targets = self.include_target_index();
        let imports = self.inner.import_statements(file);
        for path in quoted_include_paths(&imports) {
            for target in resolve_direct_include_targets_with_index(file, &path, include_targets) {
                resolved.extend(self.inner.top_level_declarations(&target));
            }
        }

        self.imported_code_units
            .insert(file.clone(), Arc::new(resolved.clone()));
        resolved
    }

    fn referencing_files_of(&self, file: &ProjectFile) -> HashSet<ProjectFile> {
        if let Some(cached) = self.referencing_files.get(file) {
            return (*cached).clone();
        }

        let references = self
            .reverse_include_index()
            .get(file)
            .map(|files| (**files).clone())
            .unwrap_or_default();

        self.referencing_files
            .insert(file.clone(), Arc::new(references.clone()));
        references
    }

    fn import_info_of(&self, file: &ProjectFile) -> Vec<ImportInfo> {
        self.inner.import_info_of(file)
    }

    fn imported_files_from_infos(
        &self,
        file: &ProjectFile,
        imports: &[ImportInfo],
    ) -> Option<HashSet<ProjectFile>> {
        let include_targets = self.include_target_index();
        Some(
            imports
                .iter()
                .filter_map(|import| parse_quoted_include(&import.raw_snippet))
                .flat_map(|path| {
                    resolve_direct_include_targets_with_index(file, &path, include_targets)
                })
                .collect(),
        )
    }

    fn relevant_imports_for(&self, code_unit: &CodeUnit) -> HashSet<String> {
        let source = code_unit.source();
        let identifiers = self
            .extract_type_identifiers(&self.inner.get_source(code_unit, true).unwrap_or_default());
        self.inner
            .import_statements(source)
            .iter()
            .filter(|line| {
                parse_quoted_include(line).is_some_and(|path| {
                    let stem = Path::new(&path)
                        .file_stem()
                        .and_then(|value| value.to_str())
                        .unwrap_or("");
                    identifiers.contains(stem)
                })
            })
            .cloned()
            .collect()
    }

    fn could_import_file(
        &self,
        source_file: &ProjectFile,
        imports: &[ImportInfo],
        target: &ProjectFile,
    ) -> bool {
        let target_name = target
            .rel_path()
            .file_name()
            .and_then(|value| value.to_str());
        imports.iter().any(|import| {
            parse_quoted_include(&import.raw_snippet).is_some_and(|include| {
                target.rel_path() == Path::new(&include)
                    || target_name.is_some_and(|name| include.ends_with(name))
                    || source_file.parent().join(&include) == target.rel_path()
            })
        })
    }
}

impl CppAnalyzer {
    pub(crate) fn include_target_index(&self) -> &IncludeTargetIndex {
        self.include_target_index.get_or_init(|| {
            let files = self.inner.all_files();
            IncludeTargetIndex::build(files.iter())
        })
    }

    fn reverse_include_index(&self) -> Arc<HashMap<ProjectFile, Arc<HashSet<ProjectFile>>>> {
        crate::analyzer::memoized_reverse_file_index(
            &self.reverse_include_index,
            || self.inner.all_files(),
            |candidate| self.include_targets_for_file(candidate),
        )
    }

    fn include_targets_for_file(&self, candidate: &ProjectFile) -> Vec<ProjectFile> {
        let include_targets = self.include_target_index();
        let mut matched_targets = HashSet::default();
        let mut resolved_targets = Vec::new();
        let imports = self.inner.import_statements(candidate);
        for include in quoted_include_paths(&imports) {
            for target in include_targets.resolve_indexed(&include) {
                if matched_targets.insert(target.clone()) {
                    resolved_targets.push(target);
                }
            }
        }
        resolved_targets
    }
}
