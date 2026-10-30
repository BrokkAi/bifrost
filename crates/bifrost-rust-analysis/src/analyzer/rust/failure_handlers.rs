//! Rust-native failure-handler shapes for the empty failure-handler policy.

use brokk_bifrost_analysis::analyzer::structural::failure_handlers::HandlerBodyGap;

use brokk_bifrost_analysis::analyzer::structural::failure_handlers::HandlerBodyShape;

use brokk_bifrost_analysis::analyzer::structural::failure_handlers::HandlerBodyState;

use brokk_bifrost_analysis::analyzer::structural::failure_handlers::{
    HandlerIdentityProof, NativeFailureBranch,
};

use brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxTree;

use brokk_bifrost_core::analyzer::model::ProjectFile;

use brokk_bifrost_core::analyzer::model::Range;

use brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer;
use brokk_bifrost_core::analyzer::tree_walk::node_range;
use tree_sitter::Node;

use crate::analyzer::rust::std_types::RustResultVariant;

use crate::analyzer::rust::std_types::{
    RustProofAttempt, completed_proof, rust_standard_result_variant,
};

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
    let (identity, shape) = match_arm_shape(workspace, file, syntax, arm)?;
    Some(NativeFailureBranch {
        handler: node_range(arm),
        identity,
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
    let (identity, shape) = let_condition_shape(workspace, file, syntax, condition)?;
    Some(NativeFailureBranch {
        // Keep the selector as the stable handler anchor, matching the
        // source-level node that identifies this native failure branch. The
        // shape carries the selected consequence or alternative body.
        handler: node_range(condition),
        identity,
        shape,
    })
}

fn match_arm_shape(
    workspace: &WorkspaceAnalyzer,
    file: &ProjectFile,
    syntax: &PreparedSyntaxTree,
    arm: Node<'_>,
) -> Option<(HandlerIdentityProof, HandlerBodyShape)> {
    let pattern = arm.child_by_field_name("pattern")?;
    let constructor = result_constructor(pattern)?;
    if constructor_name(syntax, constructor)? != "Err" {
        return None;
    }
    let identity = result_identity(workspace, file, syntax, constructor, RustResultVariant::Err);
    let shape = if has_syntax_recovery(arm) {
        open_shape(
            HandlerBodyGap::SyntaxRecovery,
            arm.child_by_field_name("value").map(node_range),
        )
    } else {
        classify_body(arm.child_by_field_name("value"))
    };
    Some((identity, shape))
}

fn let_condition_shape(
    workspace: &WorkspaceAnalyzer,
    file: &ProjectFile,
    syntax: &PreparedSyntaxTree,
    condition: Node<'_>,
) -> Option<(HandlerIdentityProof, HandlerBodyShape)> {
    let pattern = condition.child_by_field_name("pattern")?;
    let constructor = result_constructor(pattern)?;
    let owner = condition
        .parent()
        .filter(|parent| parent.kind() == "if_expression")?;
    let (variant, body) = match constructor_name(syntax, constructor)? {
        "Err" => (
            RustResultVariant::Err,
            owner.child_by_field_name("consequence"),
        ),
        "Ok" => (RustResultVariant::Ok, alternative_body(owner)),
        _ => return None,
    };
    let identity = result_identity(workspace, file, syntax, constructor, variant);
    if identity == HandlerIdentityProof::Exact && body.is_none() {
        return None;
    }
    let shape = if has_syntax_recovery(condition) {
        open_shape(HandlerBodyGap::SyntaxRecovery, body.map(node_range))
    } else {
        classify_body(body)
    };
    Some((identity, shape))
}

fn result_identity(
    workspace: &WorkspaceAnalyzer,
    file: &ProjectFile,
    syntax: &PreparedSyntaxTree,
    constructor: Node<'_>,
    variant: RustResultVariant,
) -> HandlerIdentityProof {
    let proof = completed_proof(None, || {
        rust_standard_result_variant(
            workspace.analyzer(),
            file,
            syntax.source(),
            constructor.byte_range(),
        )
    });
    if matches!(&proof, RustProofAttempt::Incomplete { .. }) {
        workspace.analyzer().mark_execution_dependent();
    }
    if proof.into_value() == Some(variant) {
        HandlerIdentityProof::Exact
    } else {
        HandlerIdentityProof::Open
    }
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
    brokk_bifrost_core::analyzer::structural::adapter_helpers::if_alternative_body(if_expression)
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
