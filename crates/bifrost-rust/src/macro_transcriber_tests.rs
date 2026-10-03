use super::*;

fn transcriber(tree: &tree_sitter::Tree) -> Node<'_> {
    let definition = named_descendant(tree.root_node(), "macro_definition").unwrap();
    let rule = named_child_of_kind(definition, "macro_rule").unwrap();
    rule.child_by_field_name("right").unwrap()
}

#[test]
fn transcriber_emission_preserves_tokens_and_metavariable_identity() {
    let source =
        "macro_rules! m { ($name:ident, $other:ident) => { fn $name() { let $other = $name; } }; }";
    let tree = parse_rust_tree(source).unwrap();
    assert!(!tree.root_node().has_error());
    let mut emitted = String::new();
    let mut saw = false;
    emit_transcriber_for_reparse(
        transcriber(&tree),
        source,
        "name",
        "DummyIdent",
        &mut emitted,
        &mut saw,
    );
    assert!(saw);
    assert_eq!(
        emitted,
        "{ fn DummyIdent ( ) { let DummyOther = DummyIdent ; } } "
    );
}

#[test]
fn transcriber_emission_does_not_mark_other_metavariables_as_requested() {
    let source = "macro_rules! m { ($other:ident) => { struct $other; }; }";
    let tree = parse_rust_tree(source).unwrap();
    let mut emitted = String::new();
    let mut saw = false;
    emit_transcriber_for_reparse(
        transcriber(&tree),
        source,
        "name",
        "DummyIdent",
        &mut emitted,
        &mut saw,
    );
    assert!(!saw);
    assert_eq!(emitted, "{ struct DummyOther ; } ");
}

#[test]
fn transcriber_emission_preserves_existing_repetition_projection() {
    let source = "macro_rules! m { ($($name:ident),*) => { $(struct $name;)* }; }";
    let tree = parse_rust_tree(source).unwrap();
    assert!(!tree.root_node().has_error());
    let mut emitted = String::new();
    let mut saw = false;
    emit_transcriber_for_reparse(
        transcriber(&tree),
        source,
        "name",
        "DummyIdent",
        &mut emitted,
        &mut saw,
    );
    assert!(saw);
    assert_eq!(emitted, "{ ( struct DummyIdent ; ) } ");
}

#[test]
fn deeply_nested_transcriber_emits_on_a_small_stack() {
    let depth = 2048;
    let source = format!(
        "macro_rules! m {{ ($name:ident) => {{ {}$name{} }}; }}",
        "[".repeat(depth),
        "]".repeat(depth)
    );
    let tree = parse_rust_tree(&source).unwrap();
    assert!(!tree.root_node().has_error());
    // Parse and drop the tree outside the small stack: this law exercises our
    // Rust traversal, not the parser's own implementation or destructor.
    let (tree, emitted, saw) = std::thread::Builder::new()
        .stack_size(64 * 1024)
        .spawn(move || {
            let mut emitted = String::new();
            let mut saw = false;
            emit_transcriber_for_reparse(
                transcriber(&tree),
                &source,
                "name",
                "DummyIdent",
                &mut emitted,
                &mut saw,
            );
            (tree, emitted, saw)
        })
        .unwrap()
        .join()
        .unwrap();
    assert!(saw);
    assert_eq!(
        emitted,
        format!(
            "{{ {}DummyIdent {}}} ",
            "[ ".repeat(depth),
            "] ".repeat(depth)
        )
    );
    drop(tree);
}
