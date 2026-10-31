//! RQL projection of source-backed branch and loop body relations.

use super::language_rules::{LanguageRuleMatches, UndecidedSite};
use crate::analyzer::ProjectFile;
use crate::analyzer::usages::get_definition::parse_tree_for_language_preprocessed;
use brokk_bifrost_core::analyzer::Language;
use brokk_bifrost_core::analyzer::structural::body_relations::{
    BodyOwner, BodyState, BodyStateAnswer, body_relation_for_block, body_state,
};
use brokk_bifrost_core::analyzer::tree_walk::named_children_iter;
use brokk_bifrost_core::analyzer::tree_walk::node_range;
use tree_sitter::Node;

/// Return exact block ranges satisfying the shared body relation. The query
/// seed still verifies its ordinary normalized kind/name fields; this helper
/// only supplies the source-backed relation ranges.
pub(super) fn matches_for_file(
    file: &ProjectFile,
    source: &str,
    language: Language,
    state: BodyState,
    owner: Option<BodyOwner>,
) -> LanguageRuleMatches {
    let Some((tree, preprocessor)) = parse_tree_for_language_preprocessed(file, language, source)
    else {
        return LanguageRuleMatches::default();
    };
    let regions = preprocessor
        .as_ref()
        .map(|p| p.conditional_regions(source))
        .unwrap_or_default();
    let mut undecided = Vec::new();
    let mut pending = vec![tree.root_node()];
    let mut ranges = Vec::new();
    while let Some(node) = pending.pop() {
        if let Some(relation) = body_relation_for_block(node, language, &regions)
            && owner.is_none_or(|expected| relation.owner_kind == expected)
            && !(state == BodyState::Empty && relation.for_has_update)
        {
            match relation.state {
                BodyStateAnswer::Decided(actual) if actual == state => {
                    ranges.push(node_range(relation.block))
                }
                BodyStateAnswer::Undecided => undecided.push(UndecidedSite::at(
                    node_range(relation.block),
                    "conditional-compilation activation is unproven",
                )),
                _ => {}
            }
        }
        // Callable bodies use the same structured state classifier as branch
        // and loop blocks. Returning the owner range lets a method pattern
        // compose its name with `:body-state` without a framework-specific
        // relation.
        if owner.is_none()
            && matches!(language, Language::CSharp)
            && matches!(
                node.kind(),
                "method_declaration" | "constructor_declaration" | "local_function_statement"
            )
            && let Some(body) = node.child_by_field_name("body")
        {
            match body_state(body, &regions) {
                BodyStateAnswer::Decided(actual) if actual == state => {
                    ranges.push(node_range(node))
                }
                BodyStateAnswer::Undecided => undecided.push(UndecidedSite::at(
                    node_range(node),
                    "conditional-compilation activation is unproven",
                )),
                _ => {}
            }
        }
        let children = named_children_iter(node).collect::<Vec<Node<'_>>>();
        pending.extend(children.into_iter().rev());
    }
    ranges.sort_by_key(|range| (range.start_byte, range.end_byte));
    ranges.dedup();
    LanguageRuleMatches::decided(
        ranges,
        undecided,
        language.config_label(),
        "body-state",
        file,
    )
}
