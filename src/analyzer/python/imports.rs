use super::*;
use crate::analyzer::{ImportInfo, StructuredImportPath, StructuredImportPathKind};
use std::collections::VecDeque;
use std::sync::Arc;
use tree_sitter::Node;

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
        if let Some(details) = python_import_details(import) {
            match details {
                PythonImportDetails::Import { module, alias } => {
                    let binding = python_namespace_binding_name(import, alias.as_deref(), &module);
                    let bound_module =
                        python_namespace_binding_module(import, alias.as_deref(), &module);
                    if let Some(module_code_unit) = self.resolve_module_code_unit(&bound_module) {
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
        for import in imports {
            let Some(details) = python_import_details(import) else {
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

pub(super) fn extract_package_from_python_wildcard(import: &ImportInfo) -> Option<String> {
    let details = python_import_details(import)?;
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

pub(super) fn python_import_infos_from_node(node: Node<'_>, source: &str) -> Vec<ImportInfo> {
    match node.kind() {
        "import_statement" => python_namespace_import_infos(node, source),
        "import_from_statement" => python_from_import_infos(node, source),
        _ => Vec::new(),
    }
}

pub(super) fn python_import_details(import: &ImportInfo) -> Option<PythonImportDetails> {
    let path = import.path.as_ref()?;
    match path.kind? {
        StructuredImportPathKind::Namespace => Some(PythonImportDetails::Import {
            module: join_python_import_segments(&path.segments),
            alias: import.alias.clone(),
        }),
        StructuredImportPathKind::ImportFrom => {
            let (name, module_segments) = if import.is_wildcard {
                ("*".to_string(), path.segments.as_slice())
            } else {
                let (name, module_segments) = path.segments.split_last()?;
                (name.clone(), module_segments)
            };
            Some(PythonImportDetails::FromImport {
                module: join_python_import_segments(module_segments),
                name,
                alias: import.alias.clone(),
                wildcard: import.is_wildcard,
            })
        }
    }
}

fn python_namespace_import_infos(node: Node<'_>, source: &str) -> Vec<ImportInfo> {
    let mut infos = Vec::new();
    let mut cursor = node.walk();
    for imported in node.children_by_field_name("name", &mut cursor) {
        let (module_node, alias) = if imported.kind() == "aliased_import" {
            let Some(name) = imported.child_by_field_name("name") else {
                continue;
            };
            let alias = imported
                .child_by_field_name("alias")
                .map(|alias| py_node_text(alias, source).trim().to_string())
                .filter(|alias| !alias.is_empty());
            (name, alias)
        } else {
            (imported, None)
        };
        let segments = python_path_segments(module_node, source);
        if segments.is_empty() {
            continue;
        }
        let module = join_python_import_segments(&segments);
        let identifier = alias.clone().or_else(|| segments.first().cloned());
        infos.push(ImportInfo {
            raw_snippet: if let Some(alias) = &alias {
                format!("import {module} as {alias}")
            } else {
                format!("import {module}")
            },
            is_wildcard: false,
            identifier,
            alias,
            path: Some(StructuredImportPath {
                segments,
                kind: Some(StructuredImportPathKind::Namespace),
                lexical_prefixes: Vec::new(),
                lexical_scopes: Vec::new(),
                declaration_start_byte: node.start_byte(),
            }),
        });
    }
    infos
}

fn python_from_import_infos(node: Node<'_>, source: &str) -> Vec<ImportInfo> {
    let Some(module_node) = node.child_by_field_name("module_name") else {
        return Vec::new();
    };
    let module_segments = python_module_segments(module_node, source);
    if module_segments.is_empty() {
        return Vec::new();
    }

    let mut infos = Vec::new();
    let has_wildcard_import = {
        let mut cursor = node.walk();
        node.named_children(&mut cursor)
            .any(|child| child.kind() == "wildcard_import")
    };
    let mut cursor = node.walk();
    let imported_names: Vec<_> = node.children_by_field_name("name", &mut cursor).collect();
    if has_wildcard_import {
        let module = join_python_import_segments(&module_segments);
        infos.push(ImportInfo {
            raw_snippet: format!("from {module} import *"),
            is_wildcard: true,
            identifier: None,
            alias: None,
            path: Some(StructuredImportPath {
                segments: module_segments,
                kind: Some(StructuredImportPathKind::ImportFrom),
                lexical_prefixes: Vec::new(),
                lexical_scopes: Vec::new(),
                declaration_start_byte: node.start_byte(),
            }),
        });
        return infos;
    }
    if imported_names.is_empty() {
        return infos;
    }

    for imported in imported_names {
        let (name_node, alias) = if imported.kind() == "aliased_import" {
            let Some(name) = imported.child_by_field_name("name") else {
                continue;
            };
            let alias = imported
                .child_by_field_name("alias")
                .map(|alias| py_node_text(alias, source).trim().to_string())
                .filter(|alias| !alias.is_empty());
            (name, alias)
        } else {
            (imported, None)
        };
        let name_segments = python_path_segments(name_node, source);
        if name_segments.is_empty() {
            continue;
        }
        let imported_name = join_python_import_segments(&name_segments);
        let mut segments = module_segments.clone();
        segments.extend(name_segments);
        let module = join_python_import_segments(&module_segments);
        infos.push(ImportInfo {
            raw_snippet: if let Some(alias) = &alias {
                format!("from {module} import {imported_name} as {alias}")
            } else {
                format!("from {module} import {imported_name}")
            },
            is_wildcard: false,
            identifier: Some(alias.clone().unwrap_or_else(|| imported_name.clone())),
            alias,
            path: Some(StructuredImportPath {
                segments,
                kind: Some(StructuredImportPathKind::ImportFrom),
                lexical_prefixes: Vec::new(),
                lexical_scopes: Vec::new(),
                declaration_start_byte: node.start_byte(),
            }),
        });
    }
    infos
}

fn python_module_segments(module: Node<'_>, source: &str) -> Vec<String> {
    if module.kind() == "relative_import" {
        let mut cursor = module.walk();
        let mut prefix = String::new();
        let mut path_node = None;
        for child in module.named_children(&mut cursor) {
            match child.kind() {
                "import_prefix" if prefix.is_empty() => {
                    prefix = py_node_text(child, source).trim().to_string();
                }
                "dotted_name" if path_node.is_none() => {
                    path_node = Some(child);
                }
                _ => {}
            }
        }
        let mut segments = path_node
            .map(|path| python_path_segments(path, source))
            .unwrap_or_default();
        if !prefix.is_empty() {
            if let Some(first) = segments.first_mut() {
                first.insert_str(0, &prefix);
            } else {
                segments.push(prefix);
            }
        }
        return segments;
    }
    python_path_segments(module, source)
}

fn python_path_segments(node: Node<'_>, source: &str) -> Vec<String> {
    match node.kind() {
        "identifier" => vec![py_node_text(node, source).trim().to_string()],
        "dotted_name" => {
            let mut segments = Vec::new();
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                segments.extend(python_path_segments(child, source));
            }
            segments
        }
        _ => {
            let mut segments = Vec::new();
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                segments.extend(python_path_segments(child, source));
            }
            segments
        }
    }
}

fn join_python_import_segments(segments: &[String]) -> String {
    let Some((first, rest)) = segments.split_first() else {
        return String::new();
    };
    if first.starts_with('.') && !rest.is_empty() {
        format!("{first}.{}", rest.join("."))
    } else {
        segments.join(".")
    }
}

pub(super) fn python_namespace_binding_name(
    import: &ImportInfo,
    alias: Option<&str>,
    module: &str,
) -> String {
    import
        .identifier
        .clone()
        .or_else(|| alias.map(str::to_string))
        .unwrap_or_else(|| module.to_string())
}

pub(super) fn python_namespace_binding_module(
    import: &ImportInfo,
    alias: Option<&str>,
    module: &str,
) -> String {
    if alias.is_some() {
        return module.to_string();
    }
    import
        .path
        .as_ref()
        .and_then(|path| path.segments.first().cloned())
        .unwrap_or_else(|| module.to_string())
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
