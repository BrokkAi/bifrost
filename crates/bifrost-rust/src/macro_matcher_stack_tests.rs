use super::*;

fn match_in_tree(tree: &tree_sitter::Tree, source: &str) -> MacroArmMatch {
    let definition = named_descendant(tree.root_node(), "macro_definition").unwrap();
    let invocation = named_descendant(tree.root_node(), "macro_invocation").unwrap();
    let arguments = named_child_of_kind(invocation, "token_tree").unwrap();
    match_syntax_macro_rules(definition, source, arguments, source).unwrap()
}

fn matches(source: &str) -> MacroArmMatch {
    let tree = parse_rust_tree(source).unwrap();
    assert!(!tree.root_node().has_error());
    match_in_tree(&tree, source)
}

#[test]
fn nested_repetitions_retain_each_binding_path() {
    let source = "macro_rules! m { ($( [ $($item:ident),+ ] );+) => {}; } m!([a,b];[c]);";
    let matched = matches(source);
    let bindings: Vec<_> = matched
        .bindings
        .iter()
        .map(|binding| {
            (
                &source[binding.start_byte..binding.end_byte],
                binding.repetition_path.as_slice(),
            )
        })
        .collect();
    assert_eq!(
        bindings,
        [("a", &[0, 0][..]), ("b", &[0, 1][..]), ("c", &[1, 0][..])]
    );
}

#[test]
fn failed_group_rolls_back_bindings_and_separator_before_following_pattern() {
    let source = "macro_rules! m { ($( [$item:ident marker] ),* , [$tail:ident]) => {}; } m!([a marker], [b]);";
    let matched = matches(source);
    let bindings: Vec<_> = matched
        .bindings
        .iter()
        .map(|binding| {
            (
                binding.name.as_str(),
                &source[binding.start_byte..binding.end_byte],
                binding.repetition_path.as_slice(),
            )
        })
        .collect();
    assert_eq!(bindings, [("item", "a", &[0][..]), ("tail", "b", &[][..])]);
}

#[test]
fn successful_greedy_repetition_does_not_backtrack_for_later_patterns() {
    let source = "macro_rules! m { ($($item:ident),* , done) => {}; ($($fallback:ident),*) => {}; } m!(a,done);";
    let matched = matches(source);
    assert_eq!(matched.arm_index, 1);
    assert!(
        matched
            .bindings
            .iter()
            .all(|binding| binding.name == "fallback")
    );
    assert_eq!(matched.bindings.len(), 2);
}

#[test]
fn zero_width_repetition_rejects_the_arm_without_leaking_bindings() {
    let source = "macro_rules! m { ($($v:vis)*) => {}; () => {}; } m!();";
    let matched = matches(source);
    assert_eq!(matched.arm_index, 1);
    assert!(matched.bindings.is_empty());
}

#[test]
fn nested_group_delimiters_must_match_but_root_delimiters_need_not() {
    let source = "macro_rules! m { ([$wrong:ident]) => {}; {($right:ident)} => {}; } m!((name));";
    let matched = matches(source);
    assert_eq!(matched.arm_index, 1);
    assert_eq!(matched.bindings[0].name, "right");
}

#[test]
fn deeply_nested_matcher_groups_run_on_a_small_stack() {
    let depth = 2048;
    let source = format!(
        "macro_rules! m {{ ({}$name:ident{}) => {{}}; }} m!({}value{});",
        "[".repeat(depth),
        "]".repeat(depth),
        "[".repeat(depth),
        "]".repeat(depth),
    );
    let tree = parse_rust_tree(&source).unwrap();
    assert!(!tree.root_node().has_error());
    let (tree, matched) = std::thread::Builder::new()
        .stack_size(64 * 1024)
        .spawn(move || {
            let matched = match_in_tree(&tree, &source);
            (tree, matched)
        })
        .unwrap()
        .join()
        .unwrap();
    assert_eq!(matched.bindings.len(), 1);
    assert_eq!(matched.bindings[0].name, "name");
    assert!(matched.bindings[0].repetition_path.is_empty());
    drop(tree);
}

#[test]
fn deeply_nested_repetition_frames_run_on_a_small_stack() {
    let depth = 256;
    let source = format!(
        "macro_rules! m {{ ({}$name:ident{}) => {{}}; }} m!(value);",
        "$(".repeat(depth),
        ")+".repeat(depth),
    );
    let tree = parse_rust_tree(&source).unwrap();
    assert!(!tree.root_node().has_error());
    let (tree, matched) = std::thread::Builder::new()
        .stack_size(64 * 1024)
        .spawn(move || {
            let matched = match_in_tree(&tree, &source);
            (tree, matched)
        })
        .unwrap()
        .join()
        .unwrap();
    assert_eq!(matched.bindings.len(), 1);
    assert_eq!(matched.bindings[0].repetition_path, vec![0; depth]);
    drop(tree);
}

#[test]
fn canonical_matcher_interrupts_during_indexing_and_matching_then_retries() {
    use std::cell::Cell;
    let source = "macro_rules! m { ($([$($name:ident),+]);+) => {}; } m!([a,b];[c]);";
    let tree = parse_rust_tree(source).unwrap();
    let definition = named_descendant(tree.root_node(), "macro_definition").unwrap();
    let invocation = named_descendant(tree.root_node(), "macro_invocation").unwrap();
    let arguments = named_child_of_kind(invocation, "token_tree").unwrap();
    let definition = capture_syntax_macro_definition(definition, source);
    let steps = Cell::new(0usize);
    let expected = match_macro_rules(&definition, arguments, source, &|| {
        steps.set(steps.get() + 1);
        true
    })
    .unwrap();
    for limit in 0..steps.get() {
        let remaining = Cell::new(limit);
        let result = match_macro_rules(&definition, arguments, source, &|| {
            if remaining.get() == 0 {
                false
            } else {
                remaining.set(remaining.get() - 1);
                true
            }
        });
        assert_eq!(result, Err(MacroMatchError::Interrupted), "limit={limit}");
    }
    assert_eq!(
        match_macro_rules(&definition, arguments, source, &|| true).unwrap(),
        expected
    );
}

#[test]
fn canonical_missing_pattern_is_not_an_empty_matcher() {
    let source = "macro_rules! m { () => {}; () => {}; } m!();";
    let tree = parse_rust_tree(source).unwrap();
    let definition = named_descendant(tree.root_node(), "macro_definition").unwrap();
    let invocation = named_descendant(tree.root_node(), "macro_invocation").unwrap();
    let arguments = named_child_of_kind(invocation, "token_tree").unwrap();
    let mut definition = capture_syntax_macro_definition(definition, source);
    // Exercise the explicit unavailable-pattern representation independently
    // of which malformed trees the current parser can recover.
    definition.arms[0].pattern = None;
    definition.arms[0].patterns.clear();
    let matched = match_macro_rules(&definition, arguments, source, &|| true).unwrap();
    assert_eq!(matched.arm_index, 1);
    assert!(matched.bindings.is_empty());
}
