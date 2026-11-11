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
use brokk_bifrost_core::hash::HashMap;
use tree_sitter::Node;

use crate::analyzer::rust::std_types::RustResultVariant;

use crate::analyzer::rust::std_types::{
    RustProofAttempt, RustResultVariantProver, completed_proof,
};

/// The standard `Result` identity proof of every native failure-branch
/// constructor in one file, keyed by the constructor's start byte.
///
/// Proving that a constructor names the prelude `Result` variant needs a
/// selected resolution operation. One operation answers every constructor of
/// the file, and the caller keeps this table for its query lifetime, so the
/// per-callable walks share it.
#[derive(Debug, Default)]
pub struct RustFailureIdentities {
    proofs: HashMap<usize, HandlerIdentityProof>,
}

/// Prove the identity of every native failure-branch constructor in `file`.
///
/// The walk visits the whole file, including nested callables, so it covers
/// every constructor that [`rust_failure_handler_body_shapes`] selects for
/// any callable of the file.
pub fn rust_failure_handler_identities(
    workspace: &WorkspaceAnalyzer,
    file: &ProjectFile,
    syntax: &PreparedSyntaxTree,
) -> RustFailureIdentities {
    let mut constructors = Vec::new();
    let mut stack = vec![syntax.tree().root_node()];
    while let Some(node) = stack.pop() {
        if is_macro_container(node) {
            continue;
        }
        if let Some(constructor) = failure_constructor(syntax, node) {
            constructors.push(constructor);
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    if constructors.is_empty() {
        return RustFailureIdentities::default();
    }
    let analyzer = workspace.analyzer();
    let prover = completed_proof(None, || {
        RustResultVariantProver::new(analyzer, file, syntax.source())
    });
    let prover = match prover {
        RustProofAttempt::Complete(prover) => prover,
        RustProofAttempt::Incomplete { .. } => {
            // Every constructor's proof would stop the same way.
            analyzer.mark_execution_dependent();
            None
        }
    };
    let proofs = constructors
        .into_iter()
        .map(|(constructor, variant)| {
            let identity = match &prover {
                Some(prover) => {
                    let proof = completed_proof(None, || prover.variant(constructor.byte_range()));
                    if matches!(&proof, RustProofAttempt::Incomplete { .. }) {
                        analyzer.mark_execution_dependent();
                    }
                    if proof.into_value() == Some(variant) {
                        HandlerIdentityProof::Exact
                    } else {
                        HandlerIdentityProof::Open
                    }
                }
                None => HandlerIdentityProof::Open,
            };
            (constructor.start_byte(), identity)
        })
        .collect();
    RustFailureIdentities { proofs }
}

/// Find Rust's native failure branches inside one callable.
///
/// Rust does not have a catch clause. A `Result::Err` match arm, an `if let
/// Err(..)` consequence, and the else branch paired with an `if let Ok(..)`
/// are the language-native failure branches covered by B6. The walk is
/// iterative and does not inspect nested callables: closures and async blocks
/// are separate callable seeds and are analyzed on their own. `identities`
/// comes from [`rust_failure_handler_identities`] over the same syntax.
pub fn rust_failure_handler_body_shapes(
    identities: &RustFailureIdentities,
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
        if let Some((constructor, variant)) = failure_constructor(syntax, node) {
            let identity = *identities
                .proofs
                .get(&constructor.start_byte())
                .expect("the file walk proves every failure-branch constructor");
            if let Some(branch) = failure_branch(node, variant, identity) {
                branches.push(branch);
            }
        }
        let mut cursor = node.walk();
        let children = node.named_children(&mut cursor).collect::<Vec<_>>();
        stack.extend(children.into_iter().rev());
    }
    branches.sort_by_key(|branch: &NativeFailureBranch| branch.handler.start_byte);
    branches
}

/// The `Result` constructor of a native failure branch selected at `node`,
/// with the variant whose proof makes the branch exact: the `Err` pattern of
/// a match arm, or the `Err`/`Ok` pattern of an `if let` condition.
fn failure_constructor<'tree>(
    syntax: &PreparedSyntaxTree,
    node: Node<'tree>,
) -> Option<(Node<'tree>, RustResultVariant)> {
    let let_condition = match node.kind() {
        "match_arm" => false,
        "let_condition" => true,
        _ => return None,
    };
    if has_macro_ancestor(node) {
        return None;
    }
    if let_condition {
        node.parent()
            .filter(|parent| parent.kind() == "if_expression")?;
    }
    let constructor = result_constructor(node.child_by_field_name("pattern")?)?;
    let variant = match constructor_name(syntax, constructor)? {
        "Err" => RustResultVariant::Err,
        "Ok" if let_condition => RustResultVariant::Ok,
        _ => return None,
    };
    Some((constructor, variant))
}

/// The failure branch selected at `node`, whose constructor names `variant`.
fn failure_branch(
    node: Node<'_>,
    variant: RustResultVariant,
    identity: HandlerIdentityProof,
) -> Option<NativeFailureBranch> {
    if node.kind() == "match_arm" {
        let shape = if has_syntax_recovery(node) {
            open_shape(
                HandlerBodyGap::SyntaxRecovery,
                node.child_by_field_name("value").map(node_range),
            )
        } else {
            classify_body(node.child_by_field_name("value"))
        };
        return Some(NativeFailureBranch {
            handler: node_range(node),
            identity,
            shape,
        });
    }
    let owner = node
        .parent()
        .expect("a selected let condition has an if expression parent");
    let body = match variant {
        RustResultVariant::Err => owner.child_by_field_name("consequence"),
        RustResultVariant::Ok => alternative_body(owner),
    };
    if identity == HandlerIdentityProof::Exact && body.is_none() {
        return None;
    }
    let shape = if has_syntax_recovery(node) {
        open_shape(HandlerBodyGap::SyntaxRecovery, body.map(node_range))
    } else {
        classify_body(body)
    };
    Some(NativeFailureBranch {
        // Keep the selector as the stable handler anchor, matching the
        // source-level node that identifies this native failure branch. The
        // shape carries the selected consequence or alternative body.
        handler: node_range(node),
        identity,
        shape,
    })
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::rust::RustAnalyzer;
    use crate::analyzer::rust::native_points::{
        reset_rust_definition_operation_open_count_for_test,
        rust_definition_operation_open_count_for_test,
    };
    use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;
    use brokk_bifrost_analysis::analyzer::resolve_analyzer;
    use brokk_bifrost_analysis::test_support::AnalyzerFixture;
    use brokk_bifrost_core::analyzer::model::Language;
    use brokk_bifrost_core::analyzer::query_token::QueryScope;
    use brokk_bifrost_test_macros::hardwon;

    #[hardwon("#8853: each Result constructor opened its own selected resolution operation")]
    #[test]
    fn one_operation_proves_every_constructor_of_a_file() {
        let source = r#"
pub fn matched(r: Result<u8, u8>) { match r { Ok(_) => {} Err(_) => {} } }
pub fn guarded(r: Result<u8, u8>) { if let Err(_) = r {} }
pub fn otherwise(r: Result<u8, u8>) { if let Ok(_) = r { drop(1) } else {} }
mod other { pub struct Err(pub u8); }
mod inner {
    use super::other::Err;
    pub fn shadowed(r: Result<u8, u8>) { match r { Ok(_) => {} Err(_) => {} } }
}
"#;
        let fixture = AnalyzerFixture::new_for_language(Language::Rust, &[("lib.rs", source)]);
        let workspace = fixture.analyzer();
        let file = ProjectFile::new(fixture.project_root(), "lib.rs");
        let syntax = {
            let scope = AnalyzerQueryScope::new(workspace.analyzer());
            resolve_analyzer::<RustAnalyzer>(workspace.analyzer())
                .expect("Rust analyzer")
                .prepared_syntax(scope.token(), &file)
                .expect("prepared Rust syntax")
        };
        reset_rust_definition_operation_open_count_for_test();
        let identities = rust_failure_handler_identities(workspace, &file, &syntax);
        assert_eq!(rust_definition_operation_open_count_for_test(), 1);

        let mut callables = Vec::new();
        let mut stack = vec![syntax.tree().root_node()];
        while let Some(node) = stack.pop() {
            if node.kind() == "function_item" {
                let name = node.child_by_field_name("name").expect("function name");
                callables.push((&source[name.byte_range()], node_range(node)));
            }
            let mut cursor = node.walk();
            stack.extend(node.named_children(&mut cursor));
        }
        callables.sort_by_key(|(_, range)| range.start_byte);
        let found = callables
            .into_iter()
            .map(|(name, range)| {
                let branches = rust_failure_handler_body_shapes(&identities, &syntax, range)
                    .into_iter()
                    .map(|branch| (branch.identity, branch.shape.state))
                    .collect::<Vec<_>>();
                (name, branches)
            })
            .collect::<Vec<_>>();
        let exact_empty = vec![(HandlerIdentityProof::Exact, HandlerBodyState::Empty)];
        assert_eq!(
            found,
            vec![
                ("matched", exact_empty.clone()),
                ("guarded", exact_empty.clone()),
                ("otherwise", exact_empty),
                (
                    "shadowed",
                    vec![(HandlerIdentityProof::Open, HandlerBodyState::Empty)]
                ),
            ]
        );
    }
}
