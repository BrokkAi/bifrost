use crate::analyzer::rust::semantic::*;

fn assert_use_bindings(source: &str, expected: Option<&[(&str, &[&str])]>) {
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_rust::LANGUAGE.into())
        .expect("the rust grammar loads");
    let tree = parser.parse(source, None).expect("rust source parses");
    let root = tree.root_node();
    let mut cursor = root.walk();
    let clause = root
        .children(&mut cursor)
        .find(|node| node.kind() == "use_declaration")
        .and_then(|declaration| declaration.named_child(0))
        .expect("one top-level use clause");
    let bindings = rust_use_clause_bindings(clause, source);
    let Some(expected) = expected else {
        assert!(bindings.is_none(), "unexpected bindings: {bindings:?}");
        return;
    };
    let bindings = bindings.expect("structured use bindings");
    assert_eq!(bindings.len(), expected.len(), "binding count for {source}");
    for ((terminal, segments), (expected_terminal, expected_segments)) in
        bindings.iter().zip(expected)
    {
        assert_eq!(
            terminal.as_ref(),
            *expected_terminal,
            "terminal for {source}"
        );
        let rendered = segments
            .iter()
            .map(|segment| segment.as_ref())
            .collect::<Vec<_>>();
        assert_eq!(rendered.as_slice(), *expected_segments, "path for {source}");
    }
}

#[test]
fn use_bindings_cover_qualified_grouped_and_keyword_paths() {
    assert_use_bindings(
        "use std::collections::HashMap;\n",
        Some(&[("HashMap", &["std", "collections", "HashMap"])]),
    );
    assert_use_bindings(
        "use std::collections::{HashMap, BTreeMap};\n",
        Some(&[
            ("HashMap", &["std", "collections", "HashMap"]),
            ("BTreeMap", &["std", "collections", "BTreeMap"]),
        ]),
    );
    assert_use_bindings(
        "use a::{b::{C, D}, E};\n",
        Some(&[
            ("C", &["a", "b", "C"]),
            ("D", &["a", "b", "D"]),
            ("E", &["a", "E"]),
        ]),
    );
    assert_use_bindings(
        "use crate::collections::HashMap;\n",
        Some(&[("HashMap", &["crate", "collections", "HashMap"])]),
    );
}
