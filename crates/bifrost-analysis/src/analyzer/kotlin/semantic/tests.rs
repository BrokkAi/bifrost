use super::control::kotlin_range_has_first_iteration;
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
    assert_eq!(counts, [9, 19, 4]);
}

/// Whether the adapter proves a first iteration for `for (i in <iterable>)`.
fn proves_first_iteration(iterable: &str) -> bool {
    let source =
        format!("fun run() {{\n    for (i in {iterable}) {{\n        use(i)\n    }}\n}}\n");
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&crate::analyzer::kotlin::language::LANGUAGE.into())
        .expect("Kotlin grammar must load");
    let tree = parser
        .parse(source.as_str(), None)
        .expect("Kotlin source must parse");
    let mut statement = None;
    crate::analyzer::tree_sitter_analyzer::walk_named_tree_preorder(
        tree.root_node(),
        true,
        |node| {
            if node.kind() == "for_statement" {
                statement = Some(node);
                WalkControl::Break
            } else {
                WalkControl::Continue
            }
        },
    );
    let statement = statement.expect("for statement");
    let (_, iterable, _) = super::syntax::for_statement_parts(statement).expect("for-in parts");
    kotlin_range_has_first_iteration(&source, iterable)
}

#[test]
fn literal_bounded_ranges_prove_a_first_iteration() {
    for iterable in [
        "0..3",
        "3..3",
        "0..<3",
        "0 until 3",
        "3 downTo 0",
        "3 downTo 3",
    ] {
        assert!(
            proves_first_iteration(iterable),
            "`{iterable}` yields at least one element"
        );
    }
}

#[test]
fn empty_or_unprovable_ranges_prove_nothing() {
    for iterable in [
        // Provably empty, so the body may never run.
        "3..0",
        "3..<3",
        "3 until 3",
        "0 downTo 3",
        // No literal bound, or a builder the adapter declines to unwrap.
        "0..limit",
        "0..10 step 2",
        "0 until 10 step 2",
        "items",
        "listOf(1, 2)",
        "0 rangeTo 3",
    ] {
        assert!(
            !proves_first_iteration(iterable),
            "`{iterable}` must not be claimed non-empty"
        );
    }
}
