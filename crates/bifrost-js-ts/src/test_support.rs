use tree_sitter::{Parser, Tree};

#[cfg(test)]
pub(crate) fn assert_callable_metadata_flags(
    parsed: &brokk_bifrost_core::analyzer::parsed_file::ParsedFile,
    name: &str,
    is_static: bool,
    is_constructor: bool,
) {
    let metadata = parsed
        .signature_metadata
        .iter()
        .find(|(unit, _)| unit.identifier() == name)
        .and_then(|(_, metadata)| metadata.first())
        .unwrap_or_else(|| {
            panic!(
                "missing callable {name}; recorded {:?}",
                parsed
                    .signature_metadata
                    .keys()
                    .map(|unit| unit.identifier().to_owned())
                    .collect::<Vec<_>>()
            )
        });
    assert!(
        metadata.callable_modifiers_recorded(),
        "{name} must record that the walk read its modifiers"
    );
    assert_eq!(
        metadata.callable_is_static(),
        is_static,
        "{name} static flag"
    );
    assert_eq!(
        metadata.callable_is_constructor(),
        is_constructor,
        "{name} constructor flag"
    );
}

pub fn parse_javascript(source: &str) -> Tree {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_javascript::LANGUAGE.into())
        .expect("JavaScript grammar");
    parser.parse(source, None).expect("JavaScript tree")
}

pub fn parse_typescript(source: &str) -> Tree {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
        .expect("TypeScript grammar");
    parser.parse(source, None).expect("TypeScript tree")
}

#[cfg(test)]
pub(crate) fn first_named_node_matching_reverse_preorder<'tree>(
    root: tree_sitter::Node<'tree>,
    mut matches: impl FnMut(tree_sitter::Node<'tree>) -> bool,
) -> Option<tree_sitter::Node<'tree>> {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if matches(node) {
            return Some(node);
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    None
}
