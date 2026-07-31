//! Kotlin structural clone smell detection (issue #1371): renamed-variable
//! clones across files, AST-refinement near-misses, threshold suppression,
//! and the Kotlin-specific callable shapes from the acceptance criteria:
//! expression-body functions, trailing-lambda call styles, and
//! companion-object members. Mirrors `ruby_structural_clone_smells.rs`.
//!
//! All fixtures keep statements on their own lines: the vendored Kotlin
//! grammar emits MISSING `_automatic_semicolon` nodes on single-line bodies.

use brokk_bifrost::{CloneSmell, CloneSmellWeights, IAnalyzer, KotlinAnalyzer, Language};

use crate::common::InlineTestProject;

fn analyze(
    files: &[(&str, &str)],
    requested_paths: &[&str],
    weights: CloneSmellWeights,
) -> Vec<CloneSmell> {
    let mut builder = InlineTestProject::with_language(Language::Kotlin);
    for (path, source) in files {
        builder = builder.file(*path, *source);
    }
    let project = builder.build();
    let analyzer = KotlinAnalyzer::from_project(project.project().clone());
    let requested = requested_paths
        .iter()
        .map(|path| project.file(path))
        .collect::<Vec<_>>();
    analyzer.find_structural_clone_smells_for_files(&requested, weights)
}

fn default_weights() -> CloneSmellWeights {
    CloneSmellWeights::defaults()
}

const ALPHA: &str = r#"
package com.example

fun alpha(value: Int): Int {
    var total = value + 2
    if (total > 20) {
        return total * 3
    }
    return total - 4
}
"#;

const BETA: &str = r#"
package com.example

fun beta(seed: Int): Int {
    var amount = seed + 2
    if (amount > 20) {
        return amount * 3
    }
    return amount - 4
}
"#;

#[test]
fn flags_renamed_variable_clone_in_kotlin() {
    let findings = analyze(
        &[("src/A.kt", ALPHA), ("src/B.kt", BETA)],
        &["src/A.kt"],
        default_weights(),
    );

    assert!(
        findings.iter().any(|finding| {
            finding.enclosing_fq_name.contains("alpha")
                && finding.peer_enclosing_fq_name.contains("beta")
        }),
        "{findings:#?}"
    );
}

#[test]
fn ast_refinement_suppresses_different_kotlin_control_flow() {
    let loop_body = r#"
package com.example

fun beta(seed: Int): Int {
    var amount = seed + 2
    while (amount > 20) {
        amount -= 1
    }
    amount *= 3
    return amount
}
"#;
    let files = [("src/A.kt", ALPHA), ("src/B.kt", loop_body)];
    let permissive = analyze(
        &files,
        &["src/A.kt"],
        CloneSmellWeights {
            min_normalized_tokens: 12,
            min_similarity_percent: 30,
            shingle_size: 2,
            min_shared_shingles: 3,
            ast_similarity_percent: 1,
        },
    );
    assert!(!permissive.is_empty(), "{permissive:#?}");

    let findings = analyze(
        &files,
        &["src/A.kt"],
        CloneSmellWeights {
            min_normalized_tokens: 12,
            min_similarity_percent: 30,
            shingle_size: 2,
            min_shared_shingles: 3,
            ast_similarity_percent: 85,
        },
    );

    assert!(findings.is_empty(), "{findings:#?}");
}

#[test]
fn strict_threshold_suppresses_small_kotlin_functions() {
    let findings = analyze(
        &[
            (
                "src/A.kt",
                "fun alpha(x: Int): Int {\n    return x + 1\n}\n",
            ),
            ("src/B.kt", "fun beta(y: Int): Int {\n    return y + 1\n}\n"),
        ],
        &["src/A.kt"],
        CloneSmellWeights {
            min_normalized_tokens: 30,
            min_similarity_percent: 50,
            shingle_size: 2,
            min_shared_shingles: 2,
            ast_similarity_percent: 70,
        },
    );

    assert!(findings.is_empty(), "{findings:#?}");
}

#[test]
fn kotlin_findings_have_stable_report_order() {
    let gamma = BETA.replace("beta", "gamma").replace("seed", "start");
    let findings = analyze(
        &[
            ("src/C.kt", gamma.as_str()),
            ("src/B.kt", BETA),
            ("src/A.kt", ALPHA),
        ],
        &["src/C.kt", "src/B.kt", "src/A.kt"],
        default_weights(),
    );
    let pairs = findings
        .iter()
        .map(|finding| {
            (
                finding.file.to_string().replace('\\', "/"),
                finding.peer_file.to_string().replace('\\', "/"),
            )
        })
        .collect::<Vec<_>>();

    assert_eq!(
        vec![
            ("src/A.kt".to_string(), "src/B.kt".to_string()),
            ("src/A.kt".to_string(), "src/C.kt".to_string()),
            ("src/B.kt".to_string(), "src/C.kt".to_string()),
        ],
        pairs
    );
}

#[test]
fn flags_expression_body_function_clones() {
    let alpha = r#"
package com.example

fun alpha(values: List<Int>): Int =
    values
        .map { entry -> entry + 7 }
        .filter { entry -> entry > 10 }
        .fold(0) { acc, entry -> acc + entry * 3 }
"#;
    let beta = r#"
package com.example

fun beta(items: List<Int>): Int =
    items
        .map { element -> element + 7 }
        .filter { element -> element > 10 }
        .fold(0) { total, element -> total + element * 3 }
"#;
    let findings = analyze(
        &[("src/A.kt", alpha), ("src/B.kt", beta)],
        &["src/A.kt"],
        default_weights(),
    );

    assert!(
        findings.iter().any(|finding| {
            finding.enclosing_fq_name.contains("alpha")
                && finding.peer_enclosing_fq_name.contains("beta")
        }),
        "{findings:#?}"
    );
}

#[test]
fn flags_trailing_lambda_call_clones() {
    let alpha = r#"
package com.example

fun alpha(values: List<Int>): Int {
    val doubled = values.map { entry ->
        entry * 2 + 5
    }
    val kept = doubled.filter { entry ->
        entry > 10
    }
    return kept.sum()
}
"#;
    let beta = r#"
package com.example

fun beta(items: List<Int>): Int {
    val scaled = items.map { element ->
        element * 2 + 5
    }
    val chosen = scaled.filter { element ->
        element > 10
    }
    return chosen.sum()
}
"#;
    let findings = analyze(
        &[("src/A.kt", alpha), ("src/B.kt", beta)],
        &["src/A.kt"],
        default_weights(),
    );

    assert!(
        findings.iter().any(|finding| {
            finding.enclosing_fq_name.contains("alpha")
                && finding.peer_enclosing_fq_name.contains("beta")
        }),
        "{findings:#?}"
    );
}

#[test]
fn includes_companion_object_member_candidates() {
    let alpha = r#"
package com.example

class Alpha {
    companion object {
        fun compute(value: Int): Int {
            var total = value + 2
            if (total > 20) {
                return total * 3
            }
            return total - 4
        }
    }
}
"#;
    let beta = r#"
package com.example

class Beta {
    companion object {
        fun calculate(seed: Int): Int {
            var amount = seed + 2
            if (amount > 20) {
                return amount * 3
            }
            return amount - 4
        }
    }
}
"#;
    let findings = analyze(
        &[("src/A.kt", alpha), ("src/B.kt", beta)],
        &["src/A.kt"],
        default_weights(),
    );

    assert!(
        findings.iter().any(|finding| {
            finding.enclosing_fq_name.contains("compute")
                && finding.peer_enclosing_fq_name.contains("calculate")
        }),
        "{findings:#?}"
    );
}
