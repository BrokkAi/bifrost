use super::syntax::body_contains_free_this;
use super::*;

#[test]
fn free_this_scan_honors_cancellation() {
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&crate::analyzer::kotlin::language::LANGUAGE.into())
        .expect("Kotlin grammar must load");
    let tree = parser
        .parse(
            "class Example {\n    fun value(): Any {\n        val first = 1\n        val second = 2\n        return this\n    }\n}\n",
            None,
        )
        .expect("Kotlin source must parse");
    let mut body = None;
    crate::analyzer::tree_sitter_analyzer::walk_named_tree_preorder(
        tree.root_node(),
        true,
        |node| {
            if node.kind() == "statements" {
                body = Some(node);
                WalkControl::Break
            } else {
                WalkControl::Continue
            }
        },
    );

    let cancellation = CancellationToken::cancel_after_checks_for_test(2);
    assert_eq!(
        body_contains_free_this(body.expect("function body"), &cancellation),
        Err(LoweringCancelled)
    );
}

#[test]
fn capability_table_is_total_and_partitioned() {
    let capabilities = kotlin_capabilities();
    let counts = capabilities
        .iter()
        .fold([0_usize; 3], |mut counts, (_, support)| {
            let index = match support {
                CapabilitySupport::Complete => 0,
                CapabilitySupport::Partial => 1,
                CapabilitySupport::Unsupported => 2,
            };
            counts[index] += 1;
            counts
        });

    assert_eq!(counts.iter().sum::<usize>(), SemanticCapability::COUNT);
    assert_eq!(counts, [9, 18, 5]);
}
