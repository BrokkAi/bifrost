//! RQL projection of source-backed branch and loop body relations.

use crate::analyzer::usages::get_definition::parse_tree_for_language;
use crate::analyzer::{ProjectFile, Range};
use brokk_bifrost_core::analyzer::Language;
use brokk_bifrost_core::analyzer::structural::body_relations::{
    BodyOwner, BodyState, body_relation_for_block, body_state,
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
) -> Vec<Range> {
    let Some(tree) = parse_tree_for_language(file, language, source) else {
        return Vec::new();
    };
    let mut pending = vec![tree.root_node()];
    let mut ranges = Vec::new();
    while let Some(node) = pending.pop() {
        if let Some(relation) = body_relation_for_block(node, language)
            && relation.state == state
            && owner.is_none_or(|expected| relation.owner_kind == expected)
            && !(state == BodyState::Empty && relation.for_has_update)
        {
            ranges.push(node_range(relation.block));
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
            && node
                .child_by_field_name("body")
                .is_some_and(|body| body_state(body) == state)
        {
            ranges.push(node_range(node));
        }
        let children = named_children_iter(node).collect::<Vec<Node<'_>>>();
        pending.extend(children.into_iter().rev());
    }
    ranges.sort_by_key(|range| (range.start_byte, range.end_byte));
    ranges.dedup();
    ranges
}
