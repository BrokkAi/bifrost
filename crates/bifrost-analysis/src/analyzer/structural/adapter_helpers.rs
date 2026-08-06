//! Test-only assertions for structural-search language adapters.
//!
//! The production mechanics -- field lookup, role attachment, the argument and
//! callee helpers, and the qualified-chain walks -- are pure node arithmetic
//! and live in [`brokk_bifrost_core::analyzer::structural::adapter_helpers`];
//! they are re-exported below so every adapter still reaches them through
//! `crate::analyzer::structural::adapter_helpers`.
//!
//! These three stay because [`occurrence_roles_of`] extracts facts through
//! [`super::extract`], which is the engine this crate owns; keeping its two
//! companions beside it keeps adapter test support in one place.

pub(crate) use brokk_bifrost_core::analyzer::structural::adapter_helpers::{
    attach_positional_argument_roles, attach_role_with_derived_name, attach_terminal_callee,
    field_name_in_parent, first_named_child, linear_chain_tokens, nearest_ancestor, node_range,
    qualified_chain_root, spelled_generic_arity,
};

#[cfg(test)]
use super::kinds::NormalizedKind;

#[cfg(test)]
pub fn assert_kind_table_matches_grammar(
    grammar: tree_sitter::Language,
    grammar_name: &str,
    table: &[(&str, NormalizedKind)],
) {
    for (name, kind) in table {
        assert_ne!(
            grammar.id_for_node_kind(name, true),
            0,
            "node type {name:?} (mapped to {kind:?}) does not exist in {grammar_name}"
        );
    }
}

/// Every [`NormalizedKind::Block`] fact a spec produces for `source`, as its
/// exact source text in fact (pre-order) order.
///
/// A scope is only usable as a join key if its arena subtree agrees with its
/// byte range, so this also asserts the arena invariant for every block it
/// returns: the nodes at `(id + 1)..subtree_end` are exactly the facts whose
/// range lies inside the block. An adapter test therefore only has to state
/// which statement lists it expects.
#[cfg(test)]
pub(crate) fn block_facts_of<'source>(
    spec: &dyn super::spec::StructuralSpec,
    grammar: &tree_sitter::Language,
    source: &'source str,
) -> Vec<&'source str> {
    let facts = super::extract::extract_file_facts(spec, grammar, source)
        .expect("structural extraction should succeed for the fixture");
    let mut blocks = Vec::new();
    for id in 0..facts.nodes().len() as u32 {
        let node = facts.node(id);
        if node.kind != NormalizedKind::Block {
            continue;
        }
        for other in 0..facts.nodes().len() as u32 {
            let candidate = facts.node(other);
            let inside_range = candidate.range.start_byte >= node.range.start_byte
                && candidate.range.end_byte <= node.range.end_byte;
            let inside_subtree = other > id && other < node.subtree_end;
            assert_eq!(
                inside_subtree,
                inside_range && other != id,
                "block at {:?} disagrees with its subtree at node {other} ({:?} {:?}); subtree_end {}",
                node.range,
                candidate.kind,
                candidate.range,
                node.subtree_end
            );
        }
        blocks.push(&source[node.range.start_byte..node.range.end_byte]);
    }
    blocks
}

/// Every occurrence role a spec classifies for `source`, as
/// `(start byte, source text, role)` triples in fact order.
///
/// Occurrence roles are a pure function of the source and the spec, so adapter
/// tests extract facts directly rather than standing up a project: the analyzer
/// and cache layers in between cannot change the answer, and the triples carry
/// enough context to make a failure readable.
#[cfg(test)]
pub fn occurrence_roles_of<'source>(
    spec: &dyn super::spec::StructuralSpec,
    grammar: &tree_sitter::Language,
    source: &'source str,
) -> Vec<(usize, &'source str, super::occurrences::OccurrenceRole)> {
    let facts = super::extract::extract_file_facts(spec, grammar, source)
        .expect("structural extraction should succeed for the fixture");
    let mut found = Vec::new();
    for id in 0..facts.nodes().len() as u32 {
        let node = facts.node(id);
        for &role in facts.occurrence_roles(id) {
            found.push((
                node.range.start_byte,
                &source[node.range.start_byte..node.range.end_byte],
                role,
            ));
        }
    }
    found
}

/// Assert that the token starting at `needle`'s first occurrence carries
/// exactly `role`, naming every classified token when it does not.
#[cfg(test)]
pub fn assert_occurrence_role(
    found: &[(usize, &str, super::occurrences::OccurrenceRole)],
    start_byte: usize,
    role: super::occurrences::OccurrenceRole,
) {
    let actual = found
        .iter()
        .filter(|(offset, _, _)| *offset == start_byte)
        .map(|(_, _, role)| *role)
        .collect::<Vec<_>>();
    assert_eq!(
        actual,
        vec![role],
        "expected exactly {role:?} at byte {start_byte}; all classified tokens: {found:?}"
    );
}
