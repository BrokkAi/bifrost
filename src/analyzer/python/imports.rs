use super::*;
use crate::analyzer::ImportInfo;
use std::collections::VecDeque;
use std::sync::Arc;

impl PythonAnalyzer {
    pub(super) fn resolve_import_bindings(&self, file: &ProjectFile) -> HashMap<String, CodeUnit> {
        let mut bindings = HashMap::default();
        for import in self.inner.import_info_of(file) {
            for (binding, code_unit) in self.resolve_import(file, &import) {
                bindings.insert(binding, code_unit);
            }
        }
        bindings
    }

    pub(super) fn resolve_import(
        &self,
        file: &ProjectFile,
        import: &ImportInfo,
    ) -> Vec<(String, CodeUnit)> {
        if let Some(details) = parse_python_import_details(&import.raw_snippet) {
            match details {
                PythonImportDetails::Import { module, alias } => {
                    if let Some(module_code_unit) = self.resolve_module_code_unit(&module) {
                        let binding = alias.unwrap_or_else(|| {
                            module
                                .split('.')
                                .next_back()
                                .unwrap_or(module.as_str())
                                .to_string()
                        });
                        return vec![(binding, module_code_unit)];
                    }
                }
                PythonImportDetails::FromImport {
                    module,
                    name,
                    alias,
                    wildcard,
                } => {
                    let resolved_module = if module.starts_with('.') {
                        resolve_python_relative_module(file, &module)
                    } else {
                        Some(module)
                    };
                    let Some(resolved_module) = resolved_module else {
                        return Vec::new();
                    };
                    if wildcard {
                        return self
                            .public_declarations_in_module(&resolved_module)
                            .into_iter()
                            .map(|code_unit| (code_unit.identifier().to_string(), code_unit))
                            .collect();
                    }

                    let binding = alias.clone().unwrap_or_else(|| name.clone());
                    let module_candidate = format!("{resolved_module}.{name}");
                    if let Some(code_unit) = self.resolve_module_code_unit(&module_candidate) {
                        return vec![(binding, code_unit)];
                    }
                    let exported = self.resolve_exported_name_from_module(&resolved_module, &name);
                    if !exported.is_empty() {
                        return exported
                            .into_iter()
                            .map(|code_unit| (binding.clone(), code_unit))
                            .collect();
                    }
                    let definitions: Vec<_> = self.inner.definitions(&module_candidate).collect();
                    if !definitions.is_empty() {
                        return definitions
                            .into_iter()
                            .map(|code_unit| (binding.clone(), code_unit))
                            .collect();
                    }
                    let package_candidate: Vec<_> = self
                        .inner
                        .definitions(&format!("{resolved_module}.{name}"))
                        .collect();
                    if !package_candidate.is_empty() {
                        return package_candidate
                            .into_iter()
                            .map(|code_unit| (binding.clone(), code_unit))
                            .collect();
                    }
                }
            }
        }
        Vec::new()
    }

    pub(crate) fn resolve_exported_fqn(&self, fqn: &str) -> Vec<CodeUnit> {
        let Some((module, name)) = fqn.rsplit_once('.') else {
            return Vec::new();
        };
        self.resolve_exported_name_from_module(module, name)
    }

    /// Resolve an unambiguous chain of explicit named reexports without
    /// constructing export indexes for each intermediate module. Star exports,
    /// shadowing, and every other ambiguous shape return `None` so callers can
    /// use the complete, source-order-aware export resolver below.
    fn resolve_direct_named_exported_fqn(&self, fqn: &str) -> Option<Vec<CodeUnit>> {
        let (module, name) = fqn.rsplit_once('.')?;
        let mut results = Vec::new();
        let mut queue = VecDeque::from([(module.to_string(), name.to_string())]);
        let mut visited = HashSet::default();

        while let Some((module, export_name)) = queue.pop_front() {
            if !visited.insert((module.clone(), export_name.clone())) {
                continue;
            }
            let module_unit = self.resolve_module_code_unit(&module)?;
            let file = module_unit.source();
            let local = self
                .inner
                .top_level_declarations(file)
                .into_iter()
                .filter(|unit| unit.identifier() == export_name)
                .collect::<Vec<_>>();
            let binder = self.import_binder_of(file);
            let binding = binder.bindings.get(&export_name);
            if !local.is_empty() && binding.is_some() {
                return None;
            }
            if !local.is_empty() {
                results.extend(local);
                continue;
            }
            let binding = binding?;
            if binding.kind != ImportKind::Named {
                return None;
            }
            let imported_name = binding.imported_name.as_ref()?;
            queue.push_back((binding.module_specifier.clone(), imported_name.clone()));
        }

        results.sort_by(|left, right| {
            left.source()
                .cmp(right.source())
                .then_with(|| left.fq_name().cmp(&right.fq_name()))
        });
        results.dedup();
        (!results.is_empty()).then_some(results)
    }

    /// Resolve a Python FQN with the cheapest semantically complete tier that
    /// can answer it. The direct reexport walk handles only proven,
    /// collision-free chains; ambiguous shapes use the ordered export index,
    /// and the exact lookup remains the final fallback for non-export symbols.
    pub(crate) fn resolve_fqn_candidates(
        &self,
        fqn: &str,
        exact: impl FnOnce(&str) -> Vec<CodeUnit>,
    ) -> Vec<CodeUnit> {
        if let Some(candidates) = self.resolve_direct_named_exported_fqn(fqn) {
            return candidates;
        }
        let candidates = self.resolve_exported_fqn(fqn);
        if !candidates.is_empty() {
            return candidates;
        }
        exact(fqn)
    }

    fn resolve_exported_name_from_module(&self, module: &str, name: &str) -> Vec<CodeUnit> {
        let Some(module_unit) = self.resolve_module_code_unit(module) else {
            return Vec::new();
        };
        self.resolve_exported_name(module_unit.source(), name)
    }

    fn resolve_exported_name(&self, module_file: &ProjectFile, name: &str) -> Vec<CodeUnit> {
        let mut results = Vec::new();
        let mut queue = VecDeque::from([(module_file.clone(), name.to_string())]);
        let mut visited = HashSet::default();

        while let Some((file, export_name)) = queue.pop_front() {
            if !visited.insert((file.clone(), export_name.clone())) {
                continue;
            }

            let index = self.export_index_of(&file);
            if let Some(entry) = index.exports_by_name.get(&export_name) {
                match entry {
                    ExportEntry::Local { local_name } => {
                        results.extend(self.local_export_declarations(&file, local_name));
                    }
                    ExportEntry::ReexportedNamed {
                        module_specifier,
                        imported_name,
                    } => {
                        for target_file in
                            self.resolve_module_files_for_export(&file, module_specifier)
                        {
                            queue.push_back((target_file, imported_name.clone()));
                        }
                    }
                    ExportEntry::Default { local_name } => {
                        if let Some(local_name) = local_name {
                            results.extend(self.local_export_declarations(&file, local_name));
                        }
                    }
                }
                continue;
            }

            if !export_name.starts_with('_') {
                for star in index.reexport_stars {
                    for target_file in
                        self.resolve_module_files_for_export(&file, &star.module_specifier)
                    {
                        queue.push_back((target_file, export_name.clone()));
                    }
                }
            }
        }

        results.sort_by(|left, right| {
            left.source()
                .cmp(right.source())
                .then_with(|| left.fq_name().cmp(&right.fq_name()))
        });
        results.dedup();
        results
    }

    fn local_export_declarations(&self, file: &ProjectFile, local_name: &str) -> Vec<CodeUnit> {
        self.inner
            .top_level_declarations(file)
            .into_iter()
            .filter(|unit| unit.identifier() == local_name)
            .collect()
    }

    fn resolve_module_files_for_export(
        &self,
        importing_file: &ProjectFile,
        module_specifier: &str,
    ) -> Vec<ProjectFile> {
        let resolved_module = if module_specifier.starts_with('.') {
            resolve_python_relative_module(importing_file, module_specifier)
        } else {
            Some(module_specifier.to_string())
        };
        let Some(resolved_module) = resolved_module else {
            return Vec::new();
        };
        // Tree-sitter tells us the import syntax, but module-to-file resolution
        // is analyzer state. Use the prebuilt module code-unit map here instead
        // of the usage index so interactive definition lookup stays lightweight.
        self.resolve_module_code_unit(&resolved_module)
            .map(|unit| vec![unit.source().clone()])
            .unwrap_or_default()
    }
}

impl ImportAnalysisProvider for PythonAnalyzer {
    fn imported_code_units_of(&self, file: &ProjectFile) -> HashSet<CodeUnit> {
        if let Some(cached) = self.imported_code_units.get(file) {
            return (*cached).clone();
        }

        let resolved: HashSet<_> = self.resolve_import_bindings(file).into_values().collect();
        self.imported_code_units
            .insert(file.clone(), Arc::new(resolved.clone()));
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

    fn relevant_imports_for(&self, code_unit: &CodeUnit) -> HashSet<String> {
        let Some(source) = self.inner.get_source(code_unit, false) else {
            return HashSet::default();
        };

        let extracted = self.extract_type_identifiers(&source);
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
                let Some(package_name) =
                    extract_package_from_python_wildcard(&wildcard.raw_snippet)
                else {
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
        for import in imports {
            let Some(details) = parse_python_import_details(&import.raw_snippet) else {
                continue;
            };
            match details {
                PythonImportDetails::FromImport { module, name, .. } if module.starts_with('.') => {
                    let Some(resolved_module) =
                        resolve_python_relative_module(source_file, &module)
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
                _ => {
                    if self
                        .resolve_import(source_file, import)
                        .into_iter()
                        .any(|(_, code_unit)| code_unit.source() == target)
                    {
                        return true;
                    }
                }
            }
        }
        false
    }
}

pub(super) fn extract_package_from_python_wildcard(raw: &str) -> Option<String> {
    let details = parse_python_import_details(raw)?;
    match details {
        PythonImportDetails::FromImport {
            module, wildcard, ..
        } if wildcard => Some(module),
        _ => None,
    }
}

#[derive(Debug, Clone)]
pub(super) enum PythonImportDetails {
    Import {
        module: String,
        alias: Option<String>,
    },
    FromImport {
        module: String,
        name: String,
        alias: Option<String>,
        wildcard: bool,
    },
}

pub(super) fn parse_python_import_infos(raw: &str) -> Vec<ImportInfo> {
    let mut infos = Vec::new();
    if let Some(body) = raw.strip_prefix("import ") {
        for part in split_top_level_commas(body) {
            let (module, alias) = split_alias(&part);
            infos.push(ImportInfo {
                raw_snippet: if let Some(alias) = &alias {
                    format!("import {module} as {alias}")
                } else {
                    format!("import {module}")
                },
                is_wildcard: false,
                identifier: Some(alias.clone().unwrap_or_else(|| {
                    module
                        .split('.')
                        .next_back()
                        .unwrap_or(module.as_str())
                        .to_string()
                })),
                alias,
            });
        }
    } else if let Some((module, names)) = raw
        .strip_prefix("from ")
        .and_then(|tail| tail.split_once(" import "))
    {
        if names.trim() == "*" {
            infos.push(ImportInfo {
                raw_snippet: format!("from {module} import *"),
                is_wildcard: true,
                identifier: None,
                alias: None,
            });
        } else {
            for part in split_top_level_commas(names) {
                let (name, alias) = split_alias(&part);
                infos.push(ImportInfo {
                    raw_snippet: if let Some(alias) = &alias {
                        format!("from {module} import {name} as {alias}")
                    } else {
                        format!("from {module} import {name}")
                    },
                    is_wildcard: false,
                    identifier: Some(alias.clone().unwrap_or_else(|| name.clone())),
                    alias,
                });
            }
        }
    }
    infos
}

pub(super) fn parse_python_import_details(raw: &str) -> Option<PythonImportDetails> {
    if let Some(body) = raw.strip_prefix("import ") {
        let part = split_top_level_commas(body).into_iter().next()?;
        let (module, alias) = split_alias(&part);
        return Some(PythonImportDetails::Import { module, alias });
    }
    let (module, names) = raw.strip_prefix("from ")?.split_once(" import ")?;
    if names.trim() == "*" {
        return Some(PythonImportDetails::FromImport {
            module: module.to_string(),
            name: "*".to_string(),
            alias: None,
            wildcard: true,
        });
    }
    let part = split_top_level_commas(names).into_iter().next()?;
    let (name, alias) = split_alias(&part);
    Some(PythonImportDetails::FromImport {
        module: module.to_string(),
        name,
        alias,
        wildcard: false,
    })
}

fn split_top_level_commas(input: &str) -> Vec<String> {
    input
        .split(',')
        .map(normalize_python_import_part)
        .filter(|part| !part.is_empty())
        .collect()
}

fn normalize_python_import_part(input: &str) -> String {
    input
        .trim()
        .trim_start_matches('(')
        .trim_end_matches(')')
        .trim()
        .to_string()
}

fn split_alias(input: &str) -> (String, Option<String>) {
    input
        .rsplit_once(" as ")
        .map(|(name, alias)| (name.trim().to_string(), Some(alias.trim().to_string())))
        .unwrap_or_else(|| (input.trim().to_string(), None))
}

pub(super) fn resolve_python_relative_module(
    source_file: &ProjectFile,
    module_expr: &str,
) -> Option<String> {
    let level = module_expr.chars().take_while(|ch| *ch == '.').count();
    let suffix = module_expr[level..].trim_matches('.');
    let current_package = python_current_package(source_file);
    let mut parts: Vec<_> = current_package
        .split('.')
        .filter(|part| !part.is_empty())
        .map(str::to_string)
        .collect();
    if level == 0 {
        return Some(module_expr.to_string());
    }
    if level > 0 {
        if level - 1 > parts.len() {
            return None;
        }
        parts.truncate(parts.len() - (level - 1));
    }
    if !suffix.is_empty() {
        parts.extend(suffix.split('.').map(str::to_string));
    }
    Some(parts.join("."))
}

fn python_current_package(source_file: &ProjectFile) -> String {
    let module = python_module_name(source_file);
    if source_file
        .rel_path()
        .file_name()
        .and_then(|name| name.to_str())
        == Some("__init__.py")
    {
        module
    } else {
        module
            .rsplit_once('.')
            .map(|(package, _)| package.to_string())
            .unwrap_or_default()
    }
}
