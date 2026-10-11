use brokk_bifrost_core::analyzer::parsed_file::{ParsedFile, ParsedSourceFacts};
use brokk_bifrost_core::analyzer::source_facts::SourceDeclarationId;
use brokk_bifrost_core::analyzer::tree_walk::{WalkControl, walk_named_tree_preorder};
use tree_sitter::Node;

pub(crate) fn source_facts(parsed: &ParsedFile) -> &ParsedSourceFacts {
    parsed
        .source_facts
        .as_ref()
        .expect("Java producer publishes source facts")
}

pub(crate) fn source_declaration_for_node(
    parsed: &ParsedFile,
    node: Node<'_>,
    candidates: impl IntoIterator<Item = SourceDeclarationId>,
) -> SourceDeclarationId {
    let facts = source_facts(parsed);
    let expected_name = node
        .child_by_field_name("name")
        .map(|name| (name.start_byte(), name.end_byte()));
    let mut matches = candidates
        .into_iter()
        .filter(|declaration| {
            let row = facts.occurrences.declaration(*declaration);
            let occurrence = facts.occurrences.occurrence(row.occurrence);
            if (occurrence.range.start_byte, occurrence.range.end_byte)
                != (node.start_byte(), node.end_byte())
            {
                return false;
            }
            match (expected_name, row.name) {
                (None, None) => true,
                (Some((start, end)), Some(name)) => {
                    let range = facts.occurrences.occurrence(name).range;
                    (range.start_byte, range.end_byte) == (start, end)
                }
                _ => false,
            }
        })
        .collect::<Vec<_>>();
    assert_eq!(
        matches.len(),
        1,
        "one source declaration matches the AST node"
    );
    matches.pop().expect("source declaration for AST node")
}

pub(crate) fn named_nodes<'tree>(
    root: Node<'tree>,
    source: &str,
    kind: &str,
    name: &str,
) -> Vec<Node<'tree>> {
    let mut matches = Vec::new();
    walk_named_tree_preorder(root, true, |node| {
        if node.kind() == kind
            && node
                .child_by_field_name("name")
                .and_then(|name_node| source.get(name_node.byte_range()))
                == Some(name)
        {
            matches.push(node);
        }
        WalkControl::Continue
    });
    matches
}
