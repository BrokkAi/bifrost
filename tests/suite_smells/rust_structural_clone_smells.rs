use brokk_bifrost::{CloneSmell, CloneSmellWeights, IAnalyzer, Language, RustAnalyzer};

use crate::common::InlineTestProject;

fn analyze(
    files: &[(&str, &str)],
    requested_paths: &[&str],
    weights: CloneSmellWeights,
) -> Vec<CloneSmell> {
    let mut builder = InlineTestProject::with_language(Language::Rust);
    for (path, source) in files {
        builder = builder.file(*path, *source);
    }
    let project = builder.build();
    let analyzer = RustAnalyzer::from_project(project.project().clone());
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
fn alpha(value: i32) -> i32 {
    let total = value + 2;
    if total > 20 {
        return total * 3;
    }
    total - 4
}
"#;

const BETA: &str = r#"
fn beta(seed: i32) -> i32 {
    let amount = seed + 2;
    if amount > 20 {
        return amount * 3;
    }
    amount - 4
}
"#;

#[test]
fn flags_renamed_variable_clone_in_rust() {
    let findings = analyze(
        &[("src/a.rs", ALPHA), ("src/b.rs", BETA)],
        &["src/a.rs"],
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
fn includes_associated_function_candidates() {
    let alpha = r#"
struct Alpha;

impl Alpha {
    fn compute(value: i32) -> i32 {
        let total = value + 2;
        if total > 20 {
            return total * 3;
        }
        total - 4
    }
}
"#;
    let beta = r#"
struct Beta;

impl Beta {
    fn calculate(seed: i32) -> i32 {
        let amount = seed + 2;
        if amount > 20 {
            return amount * 3;
        }
        amount - 4
    }
}
"#;
    let findings = analyze(
        &[("src/a.rs", alpha), ("src/b.rs", beta)],
        &["src/a.rs"],
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

#[test]
fn ast_refinement_suppresses_different_rust_control_flow() {
    let loop_body = r#"
fn beta(seed: i32) -> i32 {
    let mut amount = seed + 2;
    while amount > 20 {
        amount -= 1;
    }
    amount *= 3;
    amount
}
"#;
    let files = [("src/a.rs", ALPHA), ("src/b.rs", loop_body)];
    let permissive = analyze(
        &files,
        &["src/a.rs"],
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
        &["src/a.rs"],
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
fn strict_threshold_suppresses_small_rust_functions() {
    let findings = analyze(
        &[
            ("src/a.rs", "fn alpha(x: i32) -> i32 { x + 1 }"),
            ("src/b.rs", "fn beta(y: i32) -> i32 { y + 1 }"),
        ],
        &["src/a.rs"],
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
fn rust_findings_have_stable_report_order() {
    let gamma = BETA.replace("beta", "gamma");
    let findings = analyze(
        &[
            ("src/c.rs", gamma.as_str()),
            ("src/b.rs", BETA),
            ("src/a.rs", ALPHA),
        ],
        &["src/c.rs", "src/b.rs", "src/a.rs"],
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
            ("src/a.rs".to_string(), "src/b.rs".to_string()),
            ("src/a.rs".to_string(), "src/c.rs".to_string()),
            ("src/b.rs".to_string(), "src/c.rs".to_string()),
        ],
        pairs
    );
}

#[test]
fn ignores_trait_signatures_without_bodies() {
    let findings = analyze(
        &[
            (
                "src/a.rs",
                "trait Alpha { fn transform(value: i32, other: i32, third: i32) -> i32; }",
            ),
            (
                "src/b.rs",
                "trait Beta { fn calculate(seed: i32, extra: i32, last: i32) -> i32; }",
            ),
        ],
        &["src/a.rs", "src/b.rs"],
        CloneSmellWeights {
            min_normalized_tokens: 1,
            min_similarity_percent: 1,
            shingle_size: 1,
            min_shared_shingles: 1,
            ast_similarity_percent: 1,
        },
    );

    assert!(findings.is_empty(), "{findings:#?}");
}
