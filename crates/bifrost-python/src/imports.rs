//! Python import syntax, binding, and FQN resolution.
//!
//! Everything here is a free function over [`PythonSource`]; the
//! `ImportAnalysisProvider` impl that memoizes the per-file results stays on
//! `PythonAnalyzer` in `analyzer/python/imports.rs`.

use crate::bindings::python_direct_scope_bindings_bounded;
use crate::declarations::{parse_python_tree, py_node_text, python_module_name};
use crate::graph_support::{
    PythonSource, import_binder_from_imports, public_declarations_in_module,
    resolve_module_code_unit, resolve_module_code_units_batch,
};
use brokk_bifrost_core::analyzer::common::node_source_text;
use brokk_bifrost_core::analyzer::model::{
    ImportInfo, StructuredImportPath, StructuredImportPathKind,
};
use brokk_bifrost_core::analyzer::usages::model::{ExportEntry, ImportBinding, ImportKind};
use brokk_bifrost_core::analyzer::{CodeUnit, CodeUnitIndex, ProjectFile};
use brokk_bifrost_core::hash::{HashMap, HashSet};
use std::collections::VecDeque;
use tree_sitter::Node;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PythonModuleReplacement {
    pub target_module: String,
}

/// Recognize the compatibility-shim idiom that replaces the current module
/// object with an imported workspace module:
///
/// `sys.modules[__name__] = imported_module`
///
/// Every component is resolved from tree-sitter fields and the import binder;
/// similarly spelled attributes or locals do not create an alias edge.
fn module_replacement_from_assignment(
    assignment: Node<'_>,
    source: &str,
    bindings: &HashMap<String, ImportBinding>,
) -> Option<PythonModuleReplacement> {
    let (left, right) = (
        assignment.child_by_field_name("left")?,
        assignment.child_by_field_name("right")?,
    );
    if left.kind() != "subscript" || right.kind() != "identifier" {
        return None;
    }
    let (value, subscript) = (
        left.child_by_field_name("value")?,
        left.child_by_field_name("subscript")?,
    );
    if value.kind() != "attribute"
        || subscript.kind() != "identifier"
        || node_source_text(subscript, source) != "__name__"
    {
        return None;
    }
    let (sys_local, modules) = (
        value.child_by_field_name("object")?,
        value.child_by_field_name("attribute")?,
    );
    if sys_local.kind() != "identifier"
        || modules.kind() != "identifier"
        || node_source_text(modules, source) != "modules"
    {
        return None;
    }
    let sys_binding = bindings.get(node_source_text(sys_local, source))?;
    let sys_module = sys_binding
        .namespace_imported_module
        .as_deref()
        .unwrap_or(&sys_binding.module_specifier);
    if sys_binding.kind != ImportKind::Namespace || sys_module != "sys" {
        return None;
    }

    let target_binding = bindings.get(node_source_text(right, source))?;
    if target_binding.kind != ImportKind::Namespace {
        return None;
    }
    Some(PythonModuleReplacement {
        target_module: target_binding
            .namespace_imported_module
            .clone()
            .unwrap_or_else(|| target_binding.module_specifier.clone()),
    })
}

fn remove_direct_scope_bindings(
    statement: Node<'_>,
    source: &str,
    bindings: &mut HashMap<String, ImportBinding>,
) {
    let mut stack = vec![statement];
    while let Some(node) = stack.pop() {
        for binding in python_direct_scope_bindings_bounded(node, source, || true)
            .expect("unbounded binding collection cannot be cancelled")
        {
            bindings.remove(node_source_text(binding.declaration, source));
        }
        if matches!(
            node.kind(),
            "function_definition" | "class_definition" | "lambda"
        ) {
            continue;
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
}

/// Parse the structured import facts for a Python document without executing
/// it. LSP model binding uses the same AST-derived representation as the
/// analyzer so external APIs are never selected by a terminal-name scan.
pub fn parse_python_import_infos(source: &str) -> Vec<ImportInfo> {
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_python::LANGUAGE.into())
        .expect("failed to load Python parser");
    let Some(tree) = parser.parse(source, None) else {
        return Vec::new();
    };
    let mut pending = vec![tree.root_node()];
    let mut imports = Vec::new();
    while let Some(node) = pending.pop() {
        if matches!(node.kind(), "import_statement" | "import_from_statement") {
            imports.extend(python_import_infos_from_node(node, source));
            continue;
        }
        let mut cursor = node.walk();
        pending.extend(node.named_children(&mut cursor));
    }
    imports
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PythonImportBinding {
    pub start_byte: usize,
    pub scope_start_byte: usize,
    pub scope_end_byte: usize,
    pub local_name: String,
    pub qualified_name: String,
}

/// Return source-ordered, parser-derived local bindings for explicit Python
/// imports. The byte offset lets callers select the last visible binding rather
/// than treating a whole document as one unordered import scope.
pub fn parse_python_import_bindings(source: &str) -> Vec<PythonImportBinding> {
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_python::LANGUAGE.into())
        .expect("failed to load Python parser");
    let Some(tree) = parser.parse(source, None) else {
        return Vec::new();
    };
    let mut pending = vec![tree.root_node()];
    let mut nodes = Vec::new();
    while let Some(node) = pending.pop() {
        if matches!(node.kind(), "import_statement" | "import_from_statement") {
            nodes.push(node);
            continue;
        }
        let mut cursor = node.walk();
        pending.extend(node.named_children(&mut cursor));
    }
    nodes.sort_by_key(Node::start_byte);
    nodes
        .into_iter()
        .flat_map(|node| {
            let (scope_start_byte, scope_end_byte) =
                python_import_binding_scope(node, source.len());
            python_import_infos_from_node(node, source)
                .into_iter()
                .filter_map(move |import| {
                    let path = import.path.as_ref()?;
                    let details = python_import_details(&import)?;
                    match details {
                        PythonImportDetails::Import { module, alias } => {
                            Some(PythonImportBinding {
                                start_byte: node.start_byte(),
                                scope_start_byte,
                                scope_end_byte,
                                local_name: alias.or_else(|| path.segments.first().cloned())?,
                                qualified_name: module,
                            })
                        }
                        PythonImportDetails::FromImport {
                            module,
                            name,
                            alias,
                            wildcard: false,
                        } => Some(PythonImportBinding {
                            start_byte: node.start_byte(),
                            scope_start_byte,
                            scope_end_byte,
                            local_name: alias.unwrap_or(name.clone()),
                            qualified_name: format!("{module}.{name}"),
                        }),
                        PythonImportDetails::FromImport { wildcard: true, .. } => None,
                    }
                })
        })
        .collect()
}

fn python_import_binding_scope(node: Node<'_>, source_len: usize) -> (usize, usize) {
    let mut parent = node.parent();
    while let Some(scope) = parent {
        if matches!(scope.kind(), "function_definition" | "lambda") {
            return (scope.start_byte(), scope.end_byte());
        }
        parent = scope.parent();
    }
    (0, source_len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_core::analyzer::usages::model::ImportBinder;

    fn replacement_for(source: &str, binder: &ImportBinder) -> Option<PythonModuleReplacement> {
        let tree = parse_python_tree(source).expect("valid Python fixture");
        let root = tree.root_node();
        let mut replacement = None;
        let mut cursor = root.walk();
        for statement in root.named_children(&mut cursor) {
            let statement = if statement.kind() == "expression_statement" {
                statement.named_child(0).expect("fixture expression")
            } else {
                statement
            };
            if statement.kind() == "assignment"
                && let Some(next) =
                    module_replacement_from_assignment(statement, source, &binder.bindings)
                && replacement.replace(next).is_some()
            {
                return None;
            }
        }
        replacement
    }

    #[test]
    fn module_replacement_requires_exact_structured_import_bindings() {
        let source = r#"import sys as _sys
from routes.contacts import contacts_routes as _canonical

_sys.modules[__name__] = _canonical
"#;
        let mut binder = ImportBinder::empty();
        binder.bindings.insert(
            "_sys".to_string(),
            ImportBinding {
                module_specifier: "sys".to_string(),
                namespace_imported_module: Some("sys".to_string()),
                kind: ImportKind::Namespace,
                imported_name: None,
            },
        );
        binder.bindings.insert(
            "_canonical".to_string(),
            ImportBinding {
                module_specifier: "routes.contacts.contacts_routes".to_string(),
                namespace_imported_module: None,
                kind: ImportKind::Namespace,
                imported_name: None,
            },
        );

        assert_eq!(
            replacement_for(source, &binder),
            Some(PythonModuleReplacement {
                target_module: "routes.contacts.contacts_routes".to_string(),
            })
        );

        for near_miss in [
            "cache.modules[__name__] = _canonical\n",
            "_sys.modules[module_name] = _canonical\n",
            "_sys.modules[__name__] = build()\n",
            "def replace():\n    _sys.modules[__name__] = _canonical\n",
        ] {
            assert_eq!(
                replacement_for(near_miss, &binder),
                None,
                "near miss must not replace module identity: {near_miss:?}"
            );
        }
    }
}

pub fn module_replacement_of(
    python: &dyn PythonSource,
    file: &ProjectFile,
    source: &str,
) -> Option<PythonModuleReplacement> {
    let tree = parse_python_tree(source)?;
    let root = tree.root_node();
    let mut bindings: HashMap<String, ImportBinding> = HashMap::default();
    let mut replacement = None;
    let mut cursor = root.walk();
    for statement in root.named_children(&mut cursor) {
        let statement = if statement.kind() == "expression_statement" {
            let Some(expression) = statement.named_child(0) else {
                continue;
            };
            expression
        } else {
            statement
        };
        match statement.kind() {
            "import_statement" | "import_from_statement" => {
                let imports = python_import_infos_from_node(statement, source);
                bindings.extend(import_binder_from_imports(python, file, &imports).bindings);
            }
            "assignment" => {
                if let Some(next) = module_replacement_from_assignment(statement, source, &bindings)
                    && replacement.replace(next).is_some()
                {
                    return None;
                }
                remove_direct_scope_bindings(statement, source, &mut bindings);
            }
            _ => remove_direct_scope_bindings(statement, source, &mut bindings),
        }
    }
    replacement
}

pub fn resolve_import_bindings(
    python: &dyn PythonSource,
    file: &ProjectFile,
) -> HashMap<String, CodeUnit> {
    let imports = python.import_info_of(file);
    let mut bindings = HashMap::default();
    for resolved in resolve_imports_batched(python, file, &imports) {
        for (binding, code_unit) in resolved {
            bindings.insert(binding, code_unit);
        }
    }
    bindings
}

/// Resolves every import in `imports` (`file`'s own imports), batching each import's primary
/// module FQN lookup (see `primary_module_fqn`) into one store transaction instead of one per
/// import. Shared by `resolve_import_bindings` and `resolve_import_target_files`, the two per-file
/// "resolve everything" entry points -- both are called once per candidate file by the usages
/// candidate walker, so unbatched resolution here means one store transaction per import times
/// every file in the workspace.
pub fn resolve_imports_batched(
    python: &dyn PythonSource,
    file: &ProjectFile,
    imports: &[ImportInfo],
) -> Vec<Vec<(String, CodeUnit)>> {
    let primary_fqns: Vec<Option<String>> = imports
        .iter()
        .map(|import| primary_module_fqn(file, import))
        .collect();
    let to_resolve: Vec<String> = primary_fqns.iter().flatten().cloned().collect();
    let mut batch_results = resolve_module_code_units_batch(python, &to_resolve).into_iter();

    imports
        .iter()
        .zip(primary_fqns.iter())
        .map(|(import, primary_fqn)| {
            let hint = primary_fqn.as_ref().map(|_| batch_results.next().unwrap());
            resolve_import_with_hint(python, file, import, hint.as_ref())
        })
        .collect()
}

/// The module FQN `resolve_import`'s fast path checks first, if any -- must stay in sync with the
/// two `resolve_module_code_unit` call sites in `resolve_import_with_hint` below, since it's what
/// lets `resolve_import_target_files` batch-resolve them ahead of the serial fallback logic.
fn primary_module_fqn(file: &ProjectFile, import: &ImportInfo) -> Option<String> {
    match python_import_details(import)? {
        PythonImportDetails::Import { module, alias } => Some(python_namespace_binding_module(
            import,
            alias.as_deref(),
            &module,
        )),
        PythonImportDetails::FromImport {
            module,
            name,
            wildcard,
            ..
        } => {
            if wildcard {
                return None;
            }
            let resolved_module = if module.starts_with('.') {
                resolve_python_relative_module(file, &module)
            } else {
                Some(module)
            };
            resolved_module.map(|resolved_module| format!("{resolved_module}.{name}"))
        }
    }
}

pub fn resolve_import(
    python: &dyn PythonSource,
    file: &ProjectFile,
    import: &ImportInfo,
) -> Vec<(String, CodeUnit)> {
    resolve_import_with_hint(python, file, import, None)
}

/// `primary_hint`, when `Some`, is the already-resolved result of this import's primary module FQN
/// (see `primary_module_fqn`) so the batched caller doesn't pay for a second lookup of the same FQN.
fn resolve_import_with_hint(
    python: &dyn PythonSource,
    file: &ProjectFile,
    import: &ImportInfo,
    primary_hint: Option<&Option<CodeUnit>>,
) -> Vec<(String, CodeUnit)> {
    if let Some(details) = python_import_details(import) {
        match details {
            PythonImportDetails::Import { module, alias } => {
                let binding = python_namespace_binding_name(import, alias.as_deref(), &module);
                let bound_module =
                    python_namespace_binding_module(import, alias.as_deref(), &module);
                let resolved = match primary_hint {
                    Some(hint) => hint.clone(),
                    None => resolve_module_code_unit(python, &bound_module),
                };
                if let Some(module_code_unit) = resolved {
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
                    return public_declarations_in_module(python, &resolved_module)
                        .into_iter()
                        .map(|code_unit| (code_unit.identifier().to_string(), code_unit))
                        .collect();
                }

                let binding = alias.clone().unwrap_or_else(|| name.clone());
                let module_candidate = format!("{resolved_module}.{name}");
                let resolved = match primary_hint {
                    Some(hint) => hint.clone(),
                    None => resolve_module_code_unit(python, &module_candidate),
                };
                if let Some(code_unit) = resolved {
                    return vec![(binding, code_unit)];
                }
                let exported = resolve_exported_name_from_module(python, &resolved_module, &name);
                if !exported.is_empty() {
                    return exported
                        .into_iter()
                        .map(|code_unit| (binding.clone(), code_unit))
                        .collect();
                }
                let definitions: Vec<_> = python.definitions(&module_candidate).collect();
                if !definitions.is_empty() {
                    return definitions
                        .into_iter()
                        .map(|code_unit| (binding.clone(), code_unit))
                        .collect();
                }
                let package_candidate: Vec<_> = python
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

pub fn resolve_exported_fqn(python: &dyn PythonSource, fqn: &str) -> Vec<CodeUnit> {
    let Some((module, name)) = fqn.rsplit_once('.') else {
        return Vec::new();
    };
    resolve_exported_name_from_module(python, module, name)
}

/// Resolve an unambiguous chain of explicit named reexports without
/// constructing export indexes for each intermediate module. Star exports,
/// shadowing, and every other ambiguous shape return `None` so callers can
/// use the complete, source-order-aware export resolver below.
fn resolve_direct_named_exported_fqn(
    python: &dyn PythonSource,
    fqn: &str,
) -> Option<Vec<CodeUnit>> {
    let (module, name) = fqn.rsplit_once('.')?;
    let mut results = Vec::new();
    let mut queue = VecDeque::from([(module.to_string(), name.to_string())]);
    let mut visited = HashSet::default();

    while let Some((module, export_name)) = queue.pop_front() {
        if !visited.insert((module.clone(), export_name.clone())) {
            continue;
        }
        let module_unit = resolve_module_code_unit(python, &module)?;
        let file = module_unit.source();
        let local = python
            .top_level_declarations(file)
            .into_iter()
            .filter(|unit| unit.identifier() == export_name)
            .collect::<Vec<_>>();
        let binder = python.import_binder_of(file);
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
pub fn resolve_fqn_candidates(
    python: &dyn PythonSource,
    fqn: &str,
    exact: impl FnOnce(&str) -> Vec<CodeUnit>,
) -> Vec<CodeUnit> {
    if let Some(candidates) = resolve_direct_named_exported_fqn(python, fqn) {
        return candidates;
    }
    let candidates = resolve_exported_fqn(python, fqn);
    if !candidates.is_empty() {
        return candidates;
    }
    exact(fqn)
}

fn resolve_exported_name_from_module(
    python: &dyn PythonSource,
    module: &str,
    name: &str,
) -> Vec<CodeUnit> {
    let Some(module_unit) = resolve_module_code_unit(python, module) else {
        return Vec::new();
    };
    resolve_exported_name(python, module_unit.source(), name)
}

fn resolve_exported_name(
    python: &dyn PythonSource,
    module_file: &ProjectFile,
    name: &str,
) -> Vec<CodeUnit> {
    let mut results = Vec::new();
    let mut queue = VecDeque::from([(module_file.clone(), name.to_string())]);
    let mut visited = HashSet::default();

    while let Some((file, export_name)) = queue.pop_front() {
        if !visited.insert((file.clone(), export_name.clone())) {
            continue;
        }

        let index = python.export_index_of(&file);
        if let Some(entry) = index.exports_by_name.get(&export_name) {
            match entry {
                ExportEntry::Local { local_name } => {
                    results.extend(local_export_declarations(python, &file, local_name));
                }
                ExportEntry::ReexportedNamed {
                    module_specifier,
                    imported_name,
                } => {
                    for target_file in
                        resolve_module_files_for_export(python, &file, module_specifier)
                    {
                        queue.push_back((target_file, imported_name.clone()));
                    }
                }
                ExportEntry::Default { local_name } => {
                    if let Some(local_name) = local_name {
                        results.extend(local_export_declarations(python, &file, local_name));
                    }
                }
            }
            continue;
        }

        if !export_name.starts_with('_') {
            for star in &index.reexport_stars {
                for target_file in
                    resolve_module_files_for_export(python, &file, &star.module_specifier)
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

fn local_export_declarations(
    index: &dyn CodeUnitIndex,
    file: &ProjectFile,
    local_name: &str,
) -> Vec<CodeUnit> {
    index
        .top_level_declarations(file)
        .into_iter()
        .filter(|unit| unit.identifier() == local_name)
        .collect()
}

fn resolve_module_files_for_export(
    python: &dyn PythonSource,
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
    resolve_module_code_unit(python, &resolved_module)
        .map(|unit| vec![unit.source().clone()])
        .unwrap_or_default()
}

pub fn extract_package_from_python_wildcard(import: &ImportInfo) -> Option<String> {
    let details = python_import_details(import)?;
    match details {
        PythonImportDetails::FromImport {
            module, wildcard, ..
        } if wildcard => Some(module),
        _ => None,
    }
}

#[derive(Debug, Clone)]
pub enum PythonImportDetails {
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

pub fn python_import_infos_from_node(node: Node<'_>, source: &str) -> Vec<ImportInfo> {
    match node.kind() {
        "import_statement" => python_namespace_import_infos(node, source),
        "import_from_statement" => python_from_import_infos(node, source),
        _ => Vec::new(),
    }
}

pub fn python_import_details(import: &ImportInfo) -> Option<PythonImportDetails> {
    let path = import.path.as_ref()?;
    match path.kind? {
        StructuredImportPathKind::Namespace => Some(PythonImportDetails::Import {
            module: join_python_import_segments(&path.segments),
            alias: import.alias.clone(),
        }),
        // Python has no static imports; the variant belongs to Java.
        StructuredImportPathKind::StaticMember => None,
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
        let (module_node, alias_node) = if imported.kind() == "aliased_import" {
            let Some(name) = imported.child_by_field_name("name") else {
                continue;
            };
            (name, imported.child_by_field_name("alias"))
        } else {
            (imported, None)
        };
        let alias = alias_node
            .map(|alias| py_node_text(alias, source).trim().to_string())
            .filter(|alias| !alias.is_empty());
        let segments = python_path_segments(module_node, source);
        if segments.is_empty() {
            continue;
        }
        // `import a.b` binds `a`: the first segment's own token. A renamed
        // import binds its alias token instead.
        let binder_span = alias
            .is_some()
            .then_some(alias_node)
            .flatten()
            .or_else(|| python_first_segment_node(module_node))
            .map(brokk_bifrost_core::analyzer::common::node_span);
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
            binder_span,
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
            binder_span: None,
        });
        return infos;
    }
    if imported_names.is_empty() {
        return infos;
    }

    for imported in imported_names {
        let (name_node, alias_node) = if imported.kind() == "aliased_import" {
            let Some(name) = imported.child_by_field_name("name") else {
                continue;
            };
            (name, imported.child_by_field_name("alias"))
        } else {
            (imported, None)
        };
        let alias = alias_node
            .map(|alias| py_node_text(alias, source).trim().to_string())
            .filter(|alias| !alias.is_empty());
        let name_segments = python_path_segments(name_node, source);
        if name_segments.is_empty() {
            continue;
        }
        // `from m import x` binds `x`'s own token; a rename binds the alias
        // token. A multi-segment imported name binds no single token.
        let binder_span = alias
            .is_some()
            .then_some(alias_node)
            .flatten()
            .or_else(|| {
                (name_segments.len() == 1)
                    .then(|| python_first_segment_node(name_node))
                    .flatten()
            })
            .map(brokk_bifrost_core::analyzer::common::node_span);
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
            binder_span,
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

/// The token that spells a path's first segment: the identifier itself, or a
/// dotted name's first identifier. `None` when the shape has no leading
/// identifier token of its own (e.g. a relative-import prefix).
fn python_first_segment_node(node: Node<'_>) -> Option<Node<'_>> {
    match node.kind() {
        "identifier" => Some(node),
        "dotted_name" => {
            let mut cursor = node.walk();
            node.named_children(&mut cursor)
                .find(|child| child.kind() == "identifier")
        }
        _ => None,
    }
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

pub fn python_namespace_binding_name(
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

pub fn python_namespace_binding_module(
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

pub fn resolve_python_relative_module(
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
