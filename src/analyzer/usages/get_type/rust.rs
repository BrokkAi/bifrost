use super::{TypeLookupOutcome, candidates_outcome, no_type};
use crate::analyzer::usages::get_definition::{
    RustTypeLookupCache, rust_expression_type_definition_fqn_cached, rust_is_type_definition,
};
use crate::analyzer::usages::reference_site::{
    ResolvedReferenceSite, smallest_named_node_covering,
};
use crate::analyzer::{IAnalyzer, ProjectFile};
use tree_sitter::{Node, Tree};

pub(super) fn resolve_rust_type(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
    cache: &mut RustTypeLookupCache,
) -> TypeLookupOutcome {
    let Some(tree) = tree else {
        return no_type("rust_parse_failed", "Rust source could not be parsed");
    };
    let Some(node) =
        smallest_named_node_covering(tree.root_node(), site.focus_start_byte, site.focus_end_byte)
    else {
        return no_type(
            "no_reference_node",
            "no Rust syntax node at reference location",
        );
    };
    let expression = rust_type_lookup_expression(node);
    let support = analyzer.definition_lookup_index();
    let Some(fqn) = rust_expression_type_definition_fqn_cached(
        analyzer,
        support,
        file,
        source,
        tree.root_node(),
        expression,
        site.range.start_byte,
        cache,
    ) else {
        return no_type(
            "no_explicit_type",
            format!(
                "`{}` does not have a supported explicit Rust type",
                site.text
            ),
        );
    };
    let candidates: Vec<_> = support
        .fqn(&fqn)
        .into_iter()
        .filter(|unit| rust_is_type_definition(analyzer, unit))
        .collect();
    if candidates.is_empty() {
        return no_type(
            "no_indexed_type_definition",
            format!("`{fqn}` resolved as a Rust type but has no indexed definition"),
        );
    }
    candidates_outcome(fqn, candidates)
}

fn rust_type_lookup_expression(mut node: Node<'_>) -> Node<'_> {
    loop {
        let Some(parent) = node.parent() else {
            return node;
        };
        let node_id = node.id();
        let parent_is_semantic_expression = match parent.kind() {
            "call_expression" => parent
                .child_by_field_name("function")
                .is_some_and(|function| function.id() == node_id),
            "struct_expression" => parent
                .child_by_field_name("name")
                .is_some_and(|name| name.id() == node_id),
            "field_expression" => parent
                .child_by_field_name("field")
                .is_some_and(|field| field.id() == node_id),
            "await_expression"
            | "parenthesized_expression"
            | "reference_expression"
            | "try_expression" => true,
            _ => false,
        };
        if !parent_is_semantic_expression {
            return node;
        }
        node = parent;
    }
}
