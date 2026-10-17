//! Rust-native failure-handler shapes for the empty failure-handler policy.

use crate::analyzer::structural::failure_handlers::{
    HandlerBodyGap, HandlerBodyShape, HandlerBodyState, NativeFailureBranch,
};
use crate::analyzer::tree_sitter_analyzer::PreparedSyntaxTree;
use crate::analyzer::{ProjectFile, Range, WorkspaceAnalyzer};
use brokk_bifrost_core::analyzer::tree_walk::node_range;
use tree_sitter::Node;

use super::std_types::{RustResultVariant, rust_standard_result_variant};

/// Find Rust's native failure branches inside one callable.
///
/// Rust does not have a catch clause. A `Result::Err` match arm, an `if let
/// Err(..)` consequence, and the else branch paired with an `if let Ok(..)`
/// are the language-native failure branches covered by B6. The walk is
/// iterative and does not inspect nested callables: closures and async blocks
/// are separate callable seeds and are analyzed on their own.
pub fn rust_failure_handler_body_shapes(
    workspace: &WorkspaceAnalyzer,
    file: &ProjectFile,
    syntax: &PreparedSyntaxTree,
    callable: Range,
) -> Vec<NativeFailureBranch> {
    let Some(callable_node) = syntax
        .tree()
        .root_node()
        .named_descendant_for_byte_range(callable.start_byte, callable.end_byte)
        .filter(|node| {
            node.start_byte() == callable.start_byte && node.end_byte() == callable.end_byte
        })
    else {
        return Vec::new();
    };
    let Some(body) = callable_node.child_by_field_name("body") else {
        return Vec::new();
    };
    let body_range = node_range(body);
    let mut stack = vec![body];
    let mut branches = Vec::new();
    while let Some(node) = stack.pop() {
        if node_range(node) != body_range && is_nested_callable(node) {
            continue;
        }
        // Macro token trees are not source-level Rust branches. Skipping the
        // whole container also prevents a match written inside a macro
        // definition from becoming a fact owned by the surrounding callable.
        if is_macro_container(node) {
            continue;
        }
        let branch = match node.kind() {
            "match_arm" => match_arm_branch(workspace, file, syntax, node),
            "let_condition" => let_condition_branch(workspace, file, syntax, node),
            _ => None,
        };
        if let Some(branch) = branch {
            branches.push(branch);
        }
        let mut cursor = node.walk();
        let children = node.named_children(&mut cursor).collect::<Vec<_>>();
        stack.extend(children.into_iter().rev());
    }
    branches.sort_by_key(|branch: &NativeFailureBranch| branch.handler.start_byte);
    branches
}

fn match_arm_branch(
    workspace: &WorkspaceAnalyzer,
    file: &ProjectFile,
    syntax: &PreparedSyntaxTree,
    arm: Node<'_>,
) -> Option<NativeFailureBranch> {
    if has_macro_ancestor(arm) {
        return None;
    }
    let shape = match_arm_shape(workspace, file, syntax, arm)?;
    Some(NativeFailureBranch {
        handler: node_range(arm),
        shape,
    })
}

fn let_condition_branch(
    workspace: &WorkspaceAnalyzer,
    file: &ProjectFile,
    syntax: &PreparedSyntaxTree,
    condition: Node<'_>,
) -> Option<NativeFailureBranch> {
    if has_macro_ancestor(condition) {
        return None;
    }
    condition
        .parent()
        .filter(|parent| parent.kind() == "if_expression")?;
    let shape = let_condition_shape(workspace, file, syntax, condition)?;
    Some(NativeFailureBranch {
        // Keep the selector as the stable handler anchor, matching the
        // source-level node that identifies this native failure branch. The
        // shape carries the selected consequence or alternative body.
        handler: node_range(condition),
        shape,
    })
}

fn match_arm_shape(
    workspace: &WorkspaceAnalyzer,
    file: &ProjectFile,
    syntax: &PreparedSyntaxTree,
    arm: Node<'_>,
) -> Option<HandlerBodyShape> {
    let pattern = arm.child_by_field_name("pattern")?;
    let constructor = result_constructor(pattern)?;
    let name = constructor_name(syntax, constructor)?;
    if name != "Err" {
        return None;
    }
    if rust_standard_result_variant(
        workspace.analyzer(),
        file,
        syntax.source(),
        constructor.byte_range(),
    ) != Some(RustResultVariant::Err)
    {
        return Some(open_shape(
            HandlerBodyGap::SyntaxRecovery,
            arm.child_by_field_name("value").map(node_range),
        ));
    }
    if has_syntax_recovery(arm) {
        return Some(open_shape(
            HandlerBodyGap::SyntaxRecovery,
            arm.child_by_field_name("value").map(node_range),
        ));
    }
    Some(classify_body(arm.child_by_field_name("value")))
}

fn let_condition_shape(
    workspace: &WorkspaceAnalyzer,
    file: &ProjectFile,
    syntax: &PreparedSyntaxTree,
    condition: Node<'_>,
) -> Option<HandlerBodyShape> {
    let pattern = condition.child_by_field_name("pattern")?;
    let constructor = result_constructor(pattern)?;
    let name = constructor_name(syntax, constructor)?;
    let owner = condition
        .parent()
        .filter(|parent| parent.kind() == "if_expression")?;
    let body = match name {
        "Err" => {
            if rust_standard_result_variant(
                workspace.analyzer(),
                file,
                syntax.source(),
                constructor.byte_range(),
            ) != Some(RustResultVariant::Err)
            {
                return Some(open_shape(
                    HandlerBodyGap::SyntaxRecovery,
                    owner.child_by_field_name("consequence").map(node_range),
                ));
            }
            owner.child_by_field_name("consequence")?
        }
        "Ok" => {
            if rust_standard_result_variant(
                workspace.analyzer(),
                file,
                syntax.source(),
                constructor.byte_range(),
            ) != Some(RustResultVariant::Ok)
            {
                return Some(open_shape(
                    HandlerBodyGap::SyntaxRecovery,
                    alternative_body(owner).map(node_range),
                ));
            }
            alternative_body(owner)?
        }
        _ => return None,
    };
    if has_syntax_recovery(condition) {
        return Some(open_shape(
            HandlerBodyGap::SyntaxRecovery,
            Some(node_range(body)),
        ));
    }
    Some(classify_body(Some(body)))
}

fn is_nested_callable(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "function_item" | "function_signature_item" | "closure_expression" | "async_block"
    )
}

fn is_macro_container(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "macro_invocation" | "macro_definition" | "token_tree"
    )
}

fn result_constructor(pattern: Node<'_>) -> Option<Node<'_>> {
    let mut current = pattern;
    loop {
        current = match current.kind() {
            "match_pattern" => current.named_child(0)?,
            "tuple_struct_pattern" => return current.child_by_field_name("type"),
            "ref_pattern" | "mut_pattern" | "parenthesized_pattern" => current.named_child(0)?,
            _ => return None,
        };
    }
}

fn constructor_name<'a>(syntax: &'a PreparedSyntaxTree, constructor: Node<'_>) -> Option<&'a str> {
    let name = match constructor.kind() {
        "scoped_identifier" | "scoped_type_identifier" => {
            constructor.child_by_field_name("name")?
        }
        _ => constructor,
    };
    syntax.source().get(name.byte_range())
}

fn alternative_body(if_expression: Node<'_>) -> Option<Node<'_>> {
    let alternative = if_expression.child_by_field_name("alternative")?;
    if alternative.kind() == "else_clause" {
        alternative
            .child_by_field_name("body")
            .or_else(|| alternative.named_child(0))
    } else {
        Some(alternative)
    }
}

fn classify_body(body: Option<Node<'_>>) -> HandlerBodyShape {
    let Some(body) = body else {
        return open_shape(HandlerBodyGap::MissingBody, None);
    };
    let range = node_range(body);
    if has_syntax_recovery(body) {
        return open_shape(HandlerBodyGap::SyntaxRecovery, Some(range));
    }
    let empty = match body.kind() {
        "unit_expression" => true,
        "block" => {
            let mut cursor = body.walk();
            !body
                .named_children(&mut cursor)
                .any(|child| !child.is_extra())
        }
        _ => false,
    };
    HandlerBodyShape {
        state: if empty {
            HandlerBodyState::Empty
        } else {
            HandlerBodyState::Nonempty
        },
        body: Some(range),
        try_body: None,
    }
}

fn open_shape(gap: HandlerBodyGap, body: Option<Range>) -> HandlerBodyShape {
    HandlerBodyShape {
        state: HandlerBodyState::Open(gap),
        body,
        try_body: None,
    }
}

fn has_syntax_recovery(node: Node<'_>) -> bool {
    if node.has_error() {
        return true;
    }
    let mut ancestor = node.parent();
    while let Some(parent) = ancestor {
        if parent.is_error() {
            return true;
        }
        ancestor = parent.parent();
    }
    false
}

fn has_macro_ancestor(node: Node<'_>) -> bool {
    let mut ancestor = node.parent();
    while let Some(parent) = ancestor {
        if matches!(
            parent.kind(),
            "macro_invocation" | "macro_definition" | "token_tree"
        ) {
            return true;
        }
        ancestor = parent.parent();
    }
    false
}
