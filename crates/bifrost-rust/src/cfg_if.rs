//! The documented cfg_if item grammar, read from structural token trees.
//!
//! This is not macro expansion. Each arm contributes ordinary item ranges
//! guarded by its predicate and the negation of every preceding predicate.

use brokk_bifrost_core::analyzer::rust_facts::{RustCfgCondition, RustCfgInstruction};
use tree_sitter::{Node, Range};

use crate::declarations::{
    rust_macro_invocation_arguments, rust_macro_token_tree_interior, rust_node_text,
};
use crate::graph_support::rust_path_segments;
use crate::macro_matcher::interior_tokens;

/// Only the documented spelling and its imported, unqualified spelling.
/// Other qualified macros retain their existing unsupported route behavior.
pub(crate) fn is_cfg_if(node: Node<'_>, source: &str) -> bool {
    let Some(path) = node
        .child_by_field_name("macro")
        .and_then(rust_path_segments)
    else {
        return false;
    };
    match path.as_slice() {
        [name] => rust_node_text(*name, source) == "cfg_if",
        [owner, name] => {
            rust_node_text(*owner, source) == "cfg_if" && rust_node_text(*name, source) == "cfg_if"
        }
        _ => false,
    }
}

struct CfgIfArm {
    range: Range,
    condition: RustCfgCondition,
}

/// Read `if #[cfg(...)] { items } (else if ...)* (else { items })?`.
/// Delimiters and item ranges come exclusively from tree-sitter nodes.
fn arms(node: Node<'_>, source: &str) -> Option<Vec<CfgIfArm>> {
    if node.has_error() {
        return None;
    }
    let arguments = rust_macro_invocation_arguments(node)?;
    let (tokens, _) = interior_tokens(arguments);
    let mut tokens = tokens
        .into_iter()
        .filter(|token| !token.is_extra())
        .peekable();
    let mut arms = Vec::new();
    let mut previous = Vec::new();
    loop {
        let keyword = tokens.next()?;
        if keyword.utf8_text(source.as_bytes()).ok()? != "if" {
            return None;
        }
        if tokens.next()?.kind() != "#" {
            return None;
        }
        let attribute = tokens.next()?;
        if attribute.kind() != "token_tree" || attribute.child(0)?.kind() != "[" {
            return None;
        }
        let (attribute_tokens, _) = interior_tokens(attribute);
        let attribute_tokens = attribute_tokens
            .into_iter()
            .filter(|token| !token.is_extra())
            .collect::<Vec<_>>();
        let [cfg, predicate] = attribute_tokens.as_slice() else {
            return None;
        };
        if cfg.utf8_text(source.as_bytes()).ok()? != "cfg" || predicate.child(0)?.kind() != "(" {
            return None;
        }
        let predicate = crate::lexical_scope::rust_cfg_argument_condition(*predicate, source)
            .unwrap_or(RustCfgCondition::Unknown);
        let body = tokens.next()?;
        if body.kind() != "token_tree" || body.child(0)?.kind() != "{" {
            return None;
        }
        arms.push(CfgIfArm {
            range: rust_macro_token_tree_interior(body)?,
            condition: RustCfgCondition::conjunction(
                previous.iter().cloned().chain([predicate.clone()]),
            ),
        });
        let mut negated = predicate.instructions();
        negated.push(RustCfgInstruction::Not);
        previous.push(RustCfgCondition::Expression(negated.into_boxed_slice()));
        let Some(next) = tokens.next() else {
            break;
        };
        if next.utf8_text(source.as_bytes()).ok()? != "else" {
            return None;
        }
        if tokens
            .peek()
            .is_some_and(|token| token.utf8_text(source.as_bytes()) == Ok("if"))
        {
            continue;
        }
        let body = tokens.next()?;
        if body.kind() != "token_tree" || body.child(0)?.kind() != "{" || tokens.next().is_some() {
            return None;
        }
        arms.push(CfgIfArm {
            range: rust_macro_token_tree_interior(body)?,
            condition: RustCfgCondition::conjunction(previous),
        });
        break;
    }
    Some(arms)
}

/// Parse arm interiors as ordinary items at their original source offsets.
/// The per-tree cache seeds each item's effective cfg with its arm guard;
/// descendants inherit that guard through the ordinary cfg ancestry walk.
pub(crate) fn item_tree(
    node: Node<'_>,
    source: &str,
) -> Option<(
    tree_sitter::Tree,
    brokk_bifrost_core::hash::HashMap<usize, RustCfgCondition>,
)> {
    let arms = arms(node, source)?;
    let ranges = arms.iter().map(|arm| arm.range).collect::<Vec<_>>();
    let tree = crate::lexical_scope::parse_rust_included_ranges_tree(source, &ranges)?;
    let mut conditions = brokk_bifrost_core::hash::HashMap::default();
    let root = tree.root_node();
    crate::declarations::rust_reparsed_item_count(root)?;
    let mut arm_index = 0;
    for child in root.named_children(&mut root.walk()) {
        while arms.get(arm_index)?.range.end_byte < child.end_byte() {
            arm_index += 1;
        }
        let arm = &arms[arm_index];
        // Do not join half an item or its attributes across two arms.
        if child.start_byte() < arm.range.start_byte || child.kind() == "inner_attribute_item" {
            return None;
        }
        let item = crate::syntax::unwrap_attributes(child);
        assert!(
            conditions
                .insert(
                    item.id(),
                    RustCfgCondition::conjunction([
                        arm.condition.clone(),
                        crate::lexical_scope::rust_cfg_condition(item, source),
                    ]),
                )
                .is_none(),
            "one arm item has one effective cfg guard"
        );
    }
    Some((tree, conditions))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::selected_context::RustSelectedActivation::{Active, Inactive};
    use brokk_bifrost_test_macros::hardwon;
    use std::collections::BTreeSet;

    #[test]
    #[hardwon("#5172: cfg_if arm items were not extracted from structural token trees")]
    fn cfg_if_delimiters_preserve_item_ranges_and_first_matching_guards() {
        let source = r#"cfg_if::cfg_if! {
            if /* if { else */ #[cfg(windows)] {
                pub mod first;
            } else if #[cfg(all(unix, target_pointer_width = "64"))] {
                pub fn second() { let text = "else if { }"; }
            } else {
                pub struct Last;
            }
        }"#;
        let tree = crate::lexical_scope::parse_rust_tree(source).unwrap();
        let invocation = tree.root_node().named_child(0).unwrap();
        assert!(is_cfg_if(invocation, source));
        let arms = arms(invocation, source).unwrap();
        assert_eq!(arms.len(), 3);
        let parsed = arms
            .iter()
            .map(|arm| crate::lexical_scope::parse_rust_range_tree(source, arm.range).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            parsed
                .iter()
                .map(|tree| tree.root_node().named_child(0).unwrap().kind())
                .collect::<Vec<_>>(),
            ["mod_item", "function_item", "struct_item"]
        );
        for (arm, tree) in arms.iter().zip(&parsed) {
            let item = tree.root_node().named_child(0).unwrap();
            assert!(
                arm.range.start_byte <= item.start_byte() && item.end_byte() <= arm.range.end_byte
            );
            assert!(
                !tree.root_node().has_error(),
                "{}",
                tree.root_node().to_sexp()
            );
        }
        for (atoms, expected) in [
            (
                BTreeSet::from([
                    "windows".into(),
                    "unix".into(),
                    "target_pointer_width = \"64\"".into(),
                    "target_endian = \"little\"".into(),
                ]),
                [Active, Inactive, Inactive],
            ),
            (
                BTreeSet::from([
                    "unix".into(),
                    "target_pointer_width = \"64\"".into(),
                    "target_endian = \"little\"".into(),
                ]),
                [Inactive, Active, Inactive],
            ),
            (
                BTreeSet::from(["target_endian = \"little\"".into()]),
                [Inactive, Inactive, Active],
            ),
        ] {
            assert_eq!(
                arms.iter()
                    .map(|arm| crate::cfg::crate_activation(&atoms, &arm.condition))
                    .collect::<Vec<_>>(),
                expected
            );
        }
        for (source, accepted) in [
            ("cfg_if! { if #[cfg(windows)] {} else {} }", true),
            ("cfg_if! { if #[cfg(windows)] { 1 + 2 } }", false),
            ("cfg_if! { r#if #[cfg(windows)] { mod fake; } }", false),
            ("cfg_if! { if #[cfg(windows)] { mod broken; }", false),
        ] {
            let tree = crate::lexical_scope::parse_rust_tree(source).unwrap();
            let invocation = tree.root_node().named_child(0).unwrap();
            assert_eq!(
                item_tree(invocation, source).is_some(),
                accepted,
                "{source}"
            );
        }
    }
}
