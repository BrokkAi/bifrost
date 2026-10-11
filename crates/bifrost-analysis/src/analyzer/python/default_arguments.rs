//! Query-local mutability evidence for Python's saved callable defaults.
//!
//! Positional defaults live in the function's `__defaults__` tuple, so reading
//! that attribute cannot replace an entry. Keyword-only defaults live in the
//! mutable `__kwdefaults__` dictionary, so a read may expose mutable metadata.
//! Writes are tracked separately and are scoped to a uniquely bound module
//! function when the syntax establishes that receiver.

use super::PythonAnalyzer;
use crate::analyzer::languages::{
    SavedDefaultArgumentSafety, SavedDefaultFunction, SavedDefaultKind,
};
use crate::analyzer::{AnalyzerQueryScope, QueryToken};
use brokk_bifrost_core::analyzer::CodeUnitIndex;
use brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxTree;
use brokk_bifrost_core::analyzer::query_token::QueryScope;
use brokk_bifrost_core::analyzer::tree_walk::named_children_iter;
use brokk_bifrost_core::hash::HashMap;
use brokk_bifrost_python::bindings::{
    PythonDirectScopeBindingKind, PythonLexicalNameResolution,
    python_direct_scope_bindings_bounded, python_name_resolution_at,
};
use brokk_bifrost_python::syntax::python_plain_string_literal;
use tree_sitter::Node;

/// Keep parsing, binding discovery, and the AST walk bounded for very large
/// workspaces. An incomplete scan never authorizes an implicit default.
const MAX_METADATA_SCAN_NODES: usize = 1_000_000;
const MAX_METADATA_SCAN_SOURCE_BYTES: usize = 64 * 1024 * 1024;
const MAX_METADATA_SCAN_FILE_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ScanIncomplete;

pub(super) fn saved_default_argument_safety(
    analyzer: &PythonAnalyzer,
) -> Option<SavedDefaultArgumentSafety> {
    let scope = AnalyzerQueryScope::new(analyzer);
    scan_workspace(analyzer, scope.token()).ok()
}

fn scan_workspace(
    analyzer: &PythonAnalyzer,
    token: QueryToken<'_>,
) -> Result<SavedDefaultArgumentSafety, ScanIncomplete> {
    let mut safety = SavedDefaultArgumentSafety::default();
    let mut remaining_nodes = MAX_METADATA_SCAN_NODES;
    let mut remaining_source_bytes = MAX_METADATA_SCAN_SOURCE_BYTES;

    for file in analyzer.analyzed_files() {
        if remaining_nodes == 0 || remaining_source_bytes == 0 {
            return Err(ScanIncomplete);
        }
        let path = crate::analyzer::semantic::WorkspaceRelativePath::try_from_path(file.rel_path())
            .map_err(|_| ScanIncomplete)?;
        let max_source_bytes = remaining_source_bytes.min(MAX_METADATA_SCAN_FILE_BYTES);
        let Some((_, prepared)) = analyzer
            .inner
            .prepared_syntax_limited(token, &file, max_source_bytes)
            .map_err(|_| ScanIncomplete)?
        else {
            return Err(ScanIncomplete);
        };

        remaining_source_bytes = remaining_source_bytes.saturating_sub(prepared.source().len());
        remaining_nodes = remaining_nodes.saturating_sub(scan_prepared(
            &prepared,
            &path,
            remaining_nodes,
            &mut safety,
        )?);
    }

    Ok(safety)
}

fn scan_prepared(
    prepared: &PreparedSyntaxTree,
    path: &crate::analyzer::semantic::WorkspaceRelativePath,
    max_nodes: usize,
    safety: &mut SavedDefaultArgumentSafety,
) -> Result<usize, ScanIncomplete> {
    if prepared.tree().root_node().has_error() {
        return Err(ScanIncomplete);
    }
    scan_tree(
        prepared.tree().root_node(),
        prepared.source(),
        path,
        max_nodes,
        safety,
    )
}

#[derive(Clone, Copy)]
struct ScanFrame<'tree> {
    node: Node<'tree>,
    module_scope: bool,
    callable_scope: Option<u32>,
}

#[derive(Clone, Copy)]
struct MetadataEvent<'tree> {
    receiver: Option<Node<'tree>>,
    positional: bool,
    keyword_only: bool,
    write: bool,
}

fn scan_tree(
    root: Node<'_>,
    source: &str,
    path: &crate::analyzer::semantic::WorkspaceRelativePath,
    max_nodes: usize,
    safety: &mut SavedDefaultArgumentSafety,
) -> Result<usize, ScanIncomplete> {
    let mut remaining = max_nodes;
    let mut module_functions: HashMap<Box<str>, Option<SavedDefaultFunction>> = HashMap::default();
    let mut local_function_scopes: HashMap<u32, HashMap<Box<str>, Option<SavedDefaultFunction>>> =
        HashMap::default();
    let mut has_wildcard_import = false;
    let mut events = Vec::new();
    let mut stack = vec![ScanFrame {
        node: root,
        module_scope: true,
        callable_scope: None,
    }];

    while let Some(frame) = stack.pop() {
        consume(&mut remaining)?;
        let node = frame.node;

        if frame.module_scope || frame.callable_scope.is_some() {
            if frame.module_scope && node.kind() == "wildcard_import" {
                has_wildcard_import = true;
            }
            if matches!(
                node.kind(),
                "function_definition"
                    | "class_definition"
                    | "import_statement"
                    | "import_from_statement"
                    | "assignment"
                    | "augmented_assignment"
                    | "type_alias_statement"
                    | "named_expression"
                    | "for_statement"
                    | "delete_statement"
                    | "as_pattern"
                    | "except_clause"
                    | "case_clause"
            ) {
                let bindings = python_direct_scope_bindings_bounded(node, source, || {
                    consume(&mut remaining).is_ok()
                })
                .ok_or(ScanIncomplete)?;
                for binding in bindings {
                    let Some(name) = binding.declaration.utf8_text(source.as_bytes()).ok() else {
                        continue;
                    };
                    let definition = binding
                        .declaration
                        .parent()
                        .filter(|parent| parent.kind() == "function_definition");
                    if frame.module_scope {
                        let function = (binding.kind
                            == PythonDirectScopeBindingKind::FunctionDeclaration)
                            .then(|| {
                                let definition = definition.expect(
                                    "function binding names belong to function definitions",
                                );
                                function_key(path, definition)
                            });
                        match module_functions.entry(name.into()) {
                            std::collections::hash_map::Entry::Vacant(entry) => {
                                entry.insert(function);
                            }
                            std::collections::hash_map::Entry::Occupied(mut entry) => {
                                entry.insert(None);
                            }
                        }
                    } else if let Some(scope) = frame.callable_scope {
                        let function = definition.map(|definition| function_key(path, definition));
                        insert_scope_binding(
                            local_function_scopes.entry(scope).or_default(),
                            name,
                            function,
                        );
                    }
                }
            }
        }

        if matches!(node.kind(), "function_definition" | "lambda") {
            let layout =
                crate::analyzer::lexical_definitions::formal_parameter_slots_for_owner_bounded(
                    crate::analyzer::Language::Python,
                    node,
                    source,
                    || consume(&mut remaining).is_ok(),
                )
                .ok_or(ScanIncomplete)?;
            let scope =
                u32::try_from(node.start_byte()).expect("bounded Python source fits in u32");
            let bindings = local_function_scopes.entry(scope).or_default();
            for slot in layout.slots {
                if let Some(name) = slot.unique_name() {
                    insert_scope_binding(bindings, name, None);
                }
            }
        }

        if let Some(event) = metadata_event(node, source) {
            events.push(event);
        }

        let excluded_body = matches!(
            node.kind(),
            "function_definition" | "class_definition" | "lambda"
        )
        .then(|| node.child_by_field_name("body").map(|body| body.id()))
        .flatten();
        let callable_body = matches!(node.kind(), "function_definition" | "lambda")
            .then(|| node.child_by_field_name("body"))
            .flatten();
        for child in named_children_iter(node) {
            let callable_scope = if Some(child) == callable_body {
                Some(u32::try_from(node.start_byte()).expect("bounded Python source fits in u32"))
            } else if node.kind() == "class_definition" && Some(child.id()) == excluded_body {
                None
            } else {
                frame.callable_scope
            };
            stack.push(ScanFrame {
                node: child,
                module_scope: frame.module_scope && Some(child.id()) != excluded_body,
                callable_scope,
            });
        }
    }

    for event in events {
        let function = event.receiver.and_then(|receiver| {
            function_for_receiver(
                receiver,
                source,
                &module_functions,
                &local_function_scopes,
                has_wildcard_import,
            )
        });
        if function.is_none() && !event.write {
            continue;
        }
        if event.positional {
            mark(safety, function.clone(), SavedDefaultKind::Positional);
        }
        if event.keyword_only {
            mark(safety, function, SavedDefaultKind::KeywordOnly);
        }
    }

    Ok(max_nodes - remaining)
}

fn function_key(
    path: &crate::analyzer::semantic::WorkspaceRelativePath,
    definition: Node<'_>,
) -> SavedDefaultFunction {
    SavedDefaultFunction::new(
        path.clone(),
        u32::try_from(definition.start_byte()).expect("bounded Python source fits in u32"),
    )
}

fn insert_scope_binding(
    scope: &mut HashMap<Box<str>, Option<SavedDefaultFunction>>,
    name: &str,
    function: Option<SavedDefaultFunction>,
) {
    match scope.entry(name.into()) {
        std::collections::hash_map::Entry::Vacant(entry) => {
            entry.insert(function);
        }
        std::collections::hash_map::Entry::Occupied(mut entry) => {
            entry.insert(None);
        }
    }
}

fn consume(remaining: &mut usize) -> Result<(), ScanIncomplete> {
    if *remaining == 0 {
        return Err(ScanIncomplete);
    }
    *remaining -= 1;
    Ok(())
}

fn function_for_receiver(
    receiver: Node<'_>,
    source: &str,
    module_functions: &HashMap<Box<str>, Option<SavedDefaultFunction>>,
    local_function_scopes: &HashMap<u32, HashMap<Box<str>, Option<SavedDefaultFunction>>>,
    has_wildcard_import: bool,
) -> Option<SavedDefaultFunction> {
    if receiver.kind() != "identifier" {
        return None;
    }
    let name = receiver.utf8_text(source.as_bytes()).ok()?;
    match python_name_resolution_at(name, receiver, source) {
        PythonLexicalNameResolution::Local => {
            let mut current = receiver;
            while let Some(parent) = current.parent() {
                if parent.kind() == "function_definition" {
                    let scope = u32::try_from(parent.start_byte()).ok()?;
                    if let Some(binding) = local_function_scopes
                        .get(&scope)
                        .and_then(|bindings| bindings.get(name))
                    {
                        return binding.clone();
                    }
                }
                current = parent;
            }
            return None;
        }
        PythonLexicalNameResolution::Nonlocal => return None,
        PythonLexicalNameResolution::Global | PythonLexicalNameResolution::Unbound => {}
    }
    if has_wildcard_import {
        return None;
    }
    module_functions.get(name).cloned().flatten()
}

fn mark(
    safety: &mut SavedDefaultArgumentSafety,
    function: Option<SavedDefaultFunction>,
    kind: SavedDefaultKind,
) {
    match function {
        Some(function) => safety.mark_function_open(function, kind),
        None => safety.mark_workspace_open(kind),
    }
}

fn metadata_event<'tree>(node: Node<'tree>, source: &str) -> Option<MetadataEvent<'tree>> {
    match node.kind() {
        "attribute" => direct_attribute_event(node, source)
            .or_else(|| reflective_attribute_escape(node, source)),
        "call" => reflective_call_event(node, source),
        "identifier" => reflective_identifier_escape(node, source),
        _ => None,
    }
}

fn direct_attribute_event<'tree>(node: Node<'tree>, source: &str) -> Option<MetadataEvent<'tree>> {
    let name = node
        .child_by_field_name("attribute")?
        .utf8_text(source.as_bytes())
        .ok()?;
    let write = attribute_is_written(node);
    let (positional, keyword_only) = match (name, write) {
        ("__defaults__", true) => (true, false),
        ("__kwdefaults__", _) => (false, true),
        _ => return None,
    };
    Some(MetadataEvent {
        receiver: node.child_by_field_name("object"),
        positional,
        keyword_only,
        write,
    })
}

fn attribute_is_written(node: Node<'_>) -> bool {
    let mut current = node;
    while let Some(parent) = current.parent() {
        match parent.kind() {
            "assignment" | "augmented_assignment" => {
                return parent.child_by_field_name("left").is_some_and(|left| {
                    left.start_byte() <= node.start_byte() && node.end_byte() <= left.end_byte()
                });
            }
            "delete_statement" => return true,
            "attribute" | "subscript" | "parenthesized_expression" | "tuple" | "list" => {
                current = parent;
            }
            _ => return false,
        }
    }
    false
}

fn reflective_call_event<'tree>(node: Node<'tree>, source: &str) -> Option<MetadataEvent<'tree>> {
    let function = node.child_by_field_name("function")?;
    let arguments = node.child_by_field_name("arguments")?;
    let name = match function.kind() {
        "identifier" => function.utf8_text(source.as_bytes()).ok()?,
        "attribute" => function
            .child_by_field_name("attribute")?
            .utf8_text(source.as_bytes())
            .ok()?,
        _ => return None,
    };
    let (write, bound_special) = match name {
        "getattr" | "__getattribute__" | "__getattr__" => {
            (false, name != "getattr" && function.kind() == "attribute")
        }
        "setattr" | "delattr" | "__setattr__" | "__delattr__" => (
            true,
            name.starts_with("__") && function.kind() == "attribute",
        ),
        _ => return None,
    };
    let receiver = if bound_special {
        function.child_by_field_name("object")
    } else {
        positional_argument(arguments, 0)
    };
    let name_index = if bound_special { 0 } else { 1 };
    let name_node = positional_argument(arguments, name_index);
    let metadata_name = name_node.and_then(|name| python_plain_string_literal(name, source));
    let (positional, keyword_only) = affected_defaults(metadata_name, write);
    (positional || keyword_only).then_some(MetadataEvent {
        receiver,
        positional,
        keyword_only,
        write,
    })
}

fn positional_argument(arguments: Node<'_>, index: usize) -> Option<Node<'_>> {
    let mut cursor = arguments.walk();
    arguments
        .named_children(&mut cursor)
        .filter(|argument| argument.kind() != "keyword_argument")
        .nth(index)
}

fn affected_defaults(name: Option<&str>, write: bool) -> (bool, bool) {
    match (write, name) {
        (true, None) => (true, true),
        (true, Some("__defaults__")) => (true, false),
        (true, Some("__kwdefaults__")) => (false, true),
        (false, None | Some("__kwdefaults__")) => (false, true),
        (false, Some("__defaults__")) | (_, Some(_)) => (false, false),
    }
}

fn reflective_identifier_escape<'tree>(
    node: Node<'tree>,
    source: &str,
) -> Option<MetadataEvent<'tree>> {
    let name = node.utf8_text(source.as_bytes()).ok()?;
    if is_definition_name(node) || is_direct_call_function(node) {
        return None;
    }
    let (positional, keyword_only) = match name {
        "getattr" | "__getattribute__" | "__getattr__" => (false, true),
        "setattr" | "delattr" | "__setattr__" | "__delattr__" => (true, true),
        _ => return None,
    };
    Some(MetadataEvent {
        receiver: None,
        positional,
        keyword_only,
        write: matches!(name, "setattr" | "delattr" | "__setattr__" | "__delattr__"),
    })
}

fn reflective_attribute_escape<'tree>(
    node: Node<'tree>,
    source: &str,
) -> Option<MetadataEvent<'tree>> {
    let name = node
        .child_by_field_name("attribute")?
        .utf8_text(source.as_bytes())
        .ok()?;
    if is_direct_call_function(node) {
        return None;
    }
    let (positional, keyword_only) = match name {
        "getattr" | "__getattribute__" | "__getattr__" => (false, true),
        "setattr" | "delattr" | "__setattr__" | "__delattr__" => (true, true),
        _ => return None,
    };
    Some(MetadataEvent {
        receiver: None,
        positional,
        keyword_only,
        write: matches!(name, "setattr" | "delattr" | "__setattr__" | "__delattr__"),
    })
}

fn is_definition_name(node: Node<'_>) -> bool {
    ["function_definition", "class_definition"]
        .iter()
        .any(|kind| {
            node.parent().is_some_and(|parent| {
                parent.kind() == *kind && parent.child_by_field_name("name") == Some(node)
            })
        })
}

fn is_direct_call_function(node: Node<'_>) -> bool {
    if node.parent().is_some_and(|parent| {
        parent.kind() == "call" && parent.child_by_field_name("function") == Some(node)
    }) {
        return true;
    }
    node.parent().is_some_and(|attribute| {
        attribute.kind() == "attribute"
            && attribute.parent().is_some_and(|call| {
                call.kind() == "call" && call.child_by_field_name("function") == Some(attribute)
            })
    })
}

#[cfg(test)]
fn scan(source: &str) -> Result<SavedDefaultArgumentSafety, ScanIncomplete> {
    let tree =
        brokk_bifrost_python::declarations::parse_python_tree(source).ok_or(ScanIncomplete)?;
    let path = crate::analyzer::semantic::WorkspaceRelativePath::new("fixture.py")
        .expect("test path is portable");
    let mut safety = SavedDefaultArgumentSafety::default();
    scan_tree(
        tree.root_node(),
        source,
        &path,
        MAX_METADATA_SCAN_NODES,
        &mut safety,
    )?;
    Ok(safety)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[brokk_bifrost_test_macros::hardwon(
        "#4724: one dynamic getattr disabled every omitted default argument"
    )]
    #[test]
    fn reads_only_open_keyword_defaults_and_writes_follow_receivers() {
        let safety = scan(
            "def target(value=False, *, enabled=True):\n    pass\ndef reader(obj, name):\n    return getattr(target, name), getattr(obj, name), target.__defaults__\n",
        )
        .expect("bounded scan");
        assert!(!safety.workspace_is_open(SavedDefaultKind::Positional));
        assert!(!safety.workspace_is_open(SavedDefaultKind::KeywordOnly));
        let target = SavedDefaultFunction::new(
            crate::analyzer::semantic::WorkspaceRelativePath::new("fixture.py").unwrap(),
            0,
        );
        assert!(!safety.function_is_open(&target, SavedDefaultKind::Positional));
        assert!(safety.function_is_open(&target, SavedDefaultKind::KeywordOnly));

        let safety = scan(
            "def target(value=False):\n    pass\ndef writer():\n    setattr(target, name, value)\n",
        )
        .expect("bounded scan");
        let target = SavedDefaultFunction::new(
            crate::analyzer::semantic::WorkspaceRelativePath::new("fixture.py").unwrap(),
            0,
        );
        assert!(!safety.workspace_is_open(SavedDefaultKind::Positional));
        assert!(safety.function_is_open(&target, SavedDefaultKind::Positional));
        assert!(safety.function_is_open(&target, SavedDefaultKind::KeywordOnly));

        for source in [
            "def target(value=False):\n    pass\ntarget.__defaults__ = ()\n",
            "def target(value=False):\n    pass\ndel target.__defaults__\n",
            "def target(value=False):\n    pass\ndelattr(target, '__defaults__')\n",
        ] {
            let safety = scan(source).expect("bounded scan");
            assert!(!safety.workspace_is_open(SavedDefaultKind::Positional));
            assert!(safety.function_is_open(&target, SavedDefaultKind::Positional));
        }

        let source = "def outer(name, value):\n    def local_target():\n        pass\n    setattr(local_target, name, value)\n";
        let safety = scan(source).expect("bounded scan");
        let local_target = SavedDefaultFunction::new(
            crate::analyzer::semantic::WorkspaceRelativePath::new("fixture.py").unwrap(),
            u32::try_from(source.find("def local_target").unwrap()).unwrap(),
        );
        assert!(!safety.workspace_is_open(SavedDefaultKind::Positional));
        assert!(safety.function_is_open(&local_target, SavedDefaultKind::Positional));
        assert!(safety.function_is_open(&local_target, SavedDefaultKind::KeywordOnly));

        let safety = scan("def writer(obj, name, value):\n    setattr(obj, name, value)\n")
            .expect("bounded scan");
        assert!(safety.workspace_is_open(SavedDefaultKind::Positional));
        assert!(safety.workspace_is_open(SavedDefaultKind::KeywordOnly));
    }
}
