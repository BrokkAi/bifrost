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
    brokk_bifrost_core::analyzer::tree_walk::walk_named_tree_preorder(
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

use brokk_bifrost_test_macros::hardwon;

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
    brokk_bifrost_core::analyzer::tree_walk::walk_named_tree_preorder(
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
#[hardwon("#2660: literal Kotlin ranges were treated as possibly empty")]
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
#[hardwon("#2660: empty or unknown Kotlin ranges were treated as guaranteed non-empty")]
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

/// A unique constructor still needs evidence that its actual fits the carrier.
#[test]
fn value_class_construction_requires_known_actual_compatibility() {
    use crate::analyzer::{AnalyzerConfig, Language};
    use crate::inline_project::InlineTestProject;

    let project = InlineTestProject::with_language(Language::Kotlin)
        .file(
            "value.kt",
            "import kotlin.jvm.JvmInline\n@JvmInline value class Value(val raw: Long)\nfun known(raw: Long): Value = Value(raw)\nfun <T> unknown(raw: T): Value = Value(raw)\n",
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let cancellation = CancellationToken::default();
    let mut budget = SemanticBudget::default();
    let artifact = workspace
        .materialize_program_semantics(
            &project.file("value.kt"),
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("Kotlin semantic materialization succeeds")
        .available_value()
        .cloned()
        .expect("Kotlin semantic artifact is available");
    for (name, expected) in [("known", true), ("unknown", false)] {
        let procedure = artifact
            .procedures()
            .iter()
            .find(|procedure| {
                procedure
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|segment| segment.name())
                    == Some(name)
            })
            .expect("fixture procedure");
        let transfers: Vec<_> = procedure
            .points()
            .iter()
            .flat_map(|point| &point.events)
            .filter_map(|event| match event.effect {
                SemanticEffect::ValueFlow {
                    kind: ValueFlowKind::Transfer(transfer),
                    ..
                } => Some(transfer),
                _ => None,
            })
            .collect();
        assert_eq!(!transfers.is_empty(), expected, "{name}: {transfers:#?}");
        if !expected {
            assert!(
                procedure.gaps().iter().any(|gap| {
                    gap.detail.as_ref()
                        == KotlinAdaptationIncomplete::UnderlyingTypeUnknown.detail()
                }),
                "missing typed compatibility gap: {procedure:#?}"
            );
        }
    }
}

#[test]
fn compound_indexed_assignments_validate_with_one_calls_gap() {
    use crate::analyzer::{AnalyzerConfig, Language};
    use crate::inline_project::InlineTestProject;

    let source = r#"
class Box(var x: Int)

fun indexed(a: IntArray, i: Int) {
    a[i] += 1
}

fun matrix(m: Matrix, i: Int, j: Int, x: Int) {
    m[i, j] /= x
}

fun member(o: Box) {
    o.x += 1
}
"#;
    let project = InlineTestProject::with_language(Language::Kotlin)
        .file("assignments.kt", source)
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let cancellation = CancellationToken::default();
    let mut budget = SemanticBudget::default();
    let artifact = workspace
        .materialize_program_semantics(
            &project.file("assignments.kt"),
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("Kotlin semantic materialization succeeds")
        .available_value()
        .cloned()
        .expect("compound assignments must leave a valid semantic artifact");

    for (name, indexed) in [("indexed", true), ("matrix", true), ("member", false)] {
        let procedure = artifact
            .procedures()
            .iter()
            .find(|procedure| {
                procedure
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|segment| segment.name())
                    == Some(name)
            })
            .unwrap_or_else(|| panic!("missing fixture procedure {name}"));
        let calls = procedure
            .gaps()
            .iter()
            .filter(|gap| {
                gap.subject == SemanticGapSubject::Point
                    && gap.capability == SemanticCapability::Calls
            })
            .collect::<Vec<_>>();
        assert_eq!(calls.len(), 1, "{name}: {calls:#?}");
        assert_eq!(calls[0].kind, SemanticGapKind::Unsupported, "{name}");
        if indexed {
            assert!(
                calls[0].detail.contains("compound")
                    && calls[0].detail.contains("indexed")
                    && calls[0].detail.contains("set"),
                "{name}: combined operator details must remain visible: {calls:#?}"
            );
        } else {
            assert!(
                calls[0].detail.contains("compound") && calls[0].detail.contains("op or opAssign"),
                "{name}: compound operator detail must remain visible: {calls:#?}"
            );
        }
    }
}
