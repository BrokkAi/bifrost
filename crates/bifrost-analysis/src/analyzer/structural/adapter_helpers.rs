//! Test-only assertions for structural-search language adapters.
//!
//! The production mechanics -- field lookup, role attachment, the argument and
//! callee helpers -- are pure node arithmetic and live in
//! [`brokk_bifrost_core::analyzer::structural::adapter_helpers`]; they are
//! re-exported below so every adapter still reaches them through
//! `crate::analyzer::structural::adapter_helpers`.
//!
//! These three stay because [`occurrence_roles_of`] extracts facts through
//! [`super::extract`], which is the engine this crate owns; keeping its two
//! companions beside it keeps adapter test support in one place.

pub(crate) use brokk_bifrost_core::analyzer::structural::adapter_helpers::{
    attach_argument_role_with_derived_name, attach_positional_argument_roles,
    attach_role_with_derived_name, attach_terminal_callee, field_name_in_parent, first_named_child,
    is_field_of, is_spread_argument_node,
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
