//! Workspace-wide availability of Python's saved default metadata.
//!
//! A Python function's `__defaults__` and `__kwdefaults__` are mutable
//! metadata. A default value is therefore safe to use for an omitted call
//! argument only while this generation has no structured evidence that code
//! can read or mutate that metadata. The scan is intentionally conservative:
//! dynamic or incomplete evidence leaves the result unknown rather than
//! authorizing a default binding.

use super::PythonAnalyzer;
use crate::analyzer::{AnalyzerQueryScope, QueryToken};
use brokk_bifrost_core::analyzer::CodeUnitIndex;
use brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxTree;
use brokk_bifrost_core::analyzer::query_token::QueryScope;
use brokk_bifrost_core::analyzer::tree_walk::{
    BoundedNamedTreeWalk, walk_named_tree_preorder_bounded,
};
use brokk_bifrost_python::syntax::python_plain_string_literal;
use tree_sitter::Node;

/// Keep both parsing and the AST walk bounded for very large workspaces.
///
/// The scan is a conservative optimization. If either limit is reached, the
/// caller receives `None` and the memo does not publish a partial answer.
const MAX_METADATA_SCAN_NODES: usize = 1_000_000;
const MAX_METADATA_SCAN_SOURCE_BYTES: usize = 64 * 1024 * 1024;
const MAX_METADATA_SCAN_FILE_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ScanIncomplete;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScanOutcome {
    Complete { visited: usize },
    Open,
}

pub(super) fn saved_default_arguments_available(analyzer: &PythonAnalyzer) -> Option<bool> {
    let scope = AnalyzerQueryScope::new(analyzer);
    analyzer
        .saved_default_arguments
        .get_or_try_build_pool_independent(|| scan_workspace(analyzer, scope.token()))
        .ok()
        .map(|available| *available)
}

fn scan_workspace(
    analyzer: &PythonAnalyzer,
    token: QueryToken<'_>,
) -> Result<bool, ScanIncomplete> {
    let mut remaining_nodes = MAX_METADATA_SCAN_NODES;
    let mut remaining_source_bytes = MAX_METADATA_SCAN_SOURCE_BYTES;

    for file in analyzer.analyzed_files() {
        if remaining_nodes == 0 || remaining_source_bytes == 0 {
            return Err(ScanIncomplete);
        }
        let max_source_bytes = remaining_source_bytes.min(MAX_METADATA_SCAN_FILE_BYTES);
        let Some((_, prepared)) = analyzer
            .inner
            .prepared_syntax_limited(token, &file, max_source_bytes)
            .map_err(|_| ScanIncomplete)?
        else {
            return Err(ScanIncomplete);
        };

        remaining_source_bytes = remaining_source_bytes.saturating_sub(prepared.source().len());
        match scan_prepared(&prepared, remaining_nodes)? {
            ScanOutcome::Complete { visited } => {
                remaining_nodes = remaining_nodes.saturating_sub(visited);
            }
            ScanOutcome::Open => return Ok(false),
        }
    }

    Ok(true)
}

fn scan_prepared(
    prepared: &PreparedSyntaxTree,
    max_nodes: usize,
) -> Result<ScanOutcome, ScanIncomplete> {
    if prepared.tree().root_node().has_error() {
        return Err(ScanIncomplete);
    }
    scan_tree(prepared.tree().root_node(), prepared.source(), max_nodes)
}

fn scan_tree(
    root: Node<'_>,
    source: &str,
    max_nodes: usize,
) -> Result<ScanOutcome, ScanIncomplete> {
    let mut metadata_open = false;
    let walk = walk_named_tree_preorder_bounded(root, true, max_nodes, None, |node| {
        metadata_open |= node_can_open_saved_defaults(node, source);
    });

    if metadata_open {
        return Ok(ScanOutcome::Open);
    }
    match walk {
        BoundedNamedTreeWalk::Complete { visited } => Ok(ScanOutcome::Complete { visited }),
        BoundedNamedTreeWalk::Exceeded { .. } | BoundedNamedTreeWalk::Cancelled => {
            Err(ScanIncomplete)
        }
    }
}

fn node_can_open_saved_defaults(node: Node<'_>, source: &str) -> bool {
    match node.kind() {
        "identifier" => reflective_identifier_reference(node, source),
        "attribute" => {
            attribute_is_saved_default_metadata(node, source)
                || reflective_attribute_reference(node, source)
        }
        "call" => call_can_open_saved_defaults(node, source),
        "string" => {
            python_plain_string_literal(node, source).is_some_and(is_saved_default_metadata_name)
        }
        _ => false,
    }
}

fn reflective_identifier_reference(node: Node<'_>, source: &str) -> bool {
    node.utf8_text(source.as_bytes())
        .ok()
        .is_some_and(is_reflective_name)
        && !is_direct_call_function(node)
}

fn reflective_attribute_reference(node: Node<'_>, source: &str) -> bool {
    node.child_by_field_name("attribute")
        .and_then(|attribute| attribute.utf8_text(source.as_bytes()).ok())
        .is_some_and(is_reflective_name)
        && !is_direct_call_function(node)
}

fn is_direct_call_function(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    if parent.kind() == "call"
        && parent
            .child_by_field_name("function")
            .is_some_and(|function| function.id() == node.id())
    {
        return true;
    }

    // In `obj.setattr(...)`, the attribute identifier is nested below the
    // attribute expression that occupies the call's function field.
    parent.kind() == "attribute"
        && parent.parent().is_some_and(|call| {
            call.kind() == "call"
                && call
                    .child_by_field_name("function")
                    .is_some_and(|function| function.id() == parent.id())
        })
}

fn attribute_is_saved_default_metadata(node: Node<'_>, source: &str) -> bool {
    node.child_by_field_name("attribute")
        .and_then(|attribute| attribute.utf8_text(source.as_bytes()).ok())
        .is_some_and(is_saved_default_metadata_name)
}

fn call_can_open_saved_defaults(node: Node<'_>, source: &str) -> bool {
    let Some(function) = node.child_by_field_name("function") else {
        return false;
    };
    let Some(arguments) = node.child_by_field_name("arguments") else {
        return false;
    };

    let name_index = match function.kind() {
        "identifier" => matches!(
            function.utf8_text(source.as_bytes()).ok(),
            Some(
                "getattr"
                    | "setattr"
                    | "delattr"
                    | "__getattribute__"
                    | "__getattr__"
                    | "__setattr__"
                    | "__delattr__",
            )
        )
        .then_some(1),
        "attribute" => {
            let attribute = function
                .child_by_field_name("attribute")
                .and_then(|attribute| attribute.utf8_text(source.as_bytes()).ok());
            if matches!(attribute, Some("getattr" | "setattr" | "delattr")) {
                Some(1)
            } else if matches!(
                attribute,
                Some("__getattribute__" | "__getattr__" | "__setattr__" | "__delattr__")
            ) {
                Some(0)
            } else {
                None
            }
        }
        _ => None,
    };

    let Some(name_index) = name_index else {
        return false;
    };
    // For direct getattr/setattr/delattr calls the metadata name is the second
    // argument. Bound __setattr__/__delattr__ methods receive it first.
    let name = named_child_at(arguments, name_index);
    name.is_none_or(|name| {
        python_plain_string_literal(name, source).is_none_or(is_saved_default_metadata_name)
    })
}

fn named_child_at(node: Node<'_>, index: usize) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).nth(index)
}

fn is_saved_default_metadata_name(name: &str) -> bool {
    matches!(name, "__defaults__" | "__kwdefaults__")
}

fn is_reflective_name(name: &str) -> bool {
    matches!(
        name,
        "getattr"
            | "setattr"
            | "delattr"
            | "__getattribute__"
            | "__getattr__"
            | "__setattr__"
            | "__delattr__"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_python::declarations::parse_python_tree;

    fn scan(source: &str) -> Result<ScanOutcome, ScanIncomplete> {
        let tree = parse_python_tree(source).expect("python tree");
        scan_tree(tree.root_node(), source, MAX_METADATA_SCAN_NODES)
    }

    #[test]
    fn metadata_access_and_dynamic_names_are_open() {
        assert!(matches!(scan("target.__defaults__"), Ok(ScanOutcome::Open)));
        assert!(matches!(
            scan("getattr(target, '__kwdefaults__')"),
            Ok(ScanOutcome::Open)
        ));
        assert!(matches!(
            scan("setattr(target, name, value)"),
            Ok(ScanOutcome::Open)
        ));
        assert!(matches!(
            scan("target.__delattr__('__defaults__')"),
            Ok(ScanOutcome::Open)
        ));
        assert!(matches!(
            scan("builtins.getattr(target, name)"),
            Ok(ScanOutcome::Open)
        ));
        assert!(matches!(
            scan("target.__getattribute__('__defaults__')"),
            Ok(ScanOutcome::Open)
        ));
        assert!(matches!(
            scan("from builtins import setattr as patch\npatch(target, 'other', value)"),
            Ok(ScanOutcome::Open)
        ));
        assert!(matches!(
            scan("patch = setattr\npatch(target, name, value)"),
            Ok(ScanOutcome::Open)
        ));
        assert!(matches!(scan("register(setattr)"), Ok(ScanOutcome::Open)));
        assert!(matches!(
            scan("patch(target, '__kwdefaults__', value)"),
            Ok(ScanOutcome::Open)
        ));
    }

    #[test]
    fn unrelated_attribute_names_are_closed() {
        assert!(matches!(
            scan("target.other"),
            Ok(ScanOutcome::Complete { visited }) if visited > 0
        ));
        assert!(matches!(
            scan("getattr(target, 'other')"),
            Ok(ScanOutcome::Complete { visited }) if visited > 0
        ));
        assert!(matches!(
            scan("target.__setattr__('other', value)"),
            Ok(ScanOutcome::Complete { visited }) if visited > 0
        ));
    }
}
