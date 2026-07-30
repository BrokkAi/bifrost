use brokk_bifrost::{CloneSmell, CloneSmellWeights, GoAnalyzer, IAnalyzer, Language};

use crate::common::InlineTestProject;

fn analyze(
    files: &[(&str, &str)],
    requested_paths: &[&str],
    weights: CloneSmellWeights,
) -> Vec<CloneSmell> {
    let mut builder = InlineTestProject::with_language(Language::Go);
    for (path, source) in files {
        builder = builder.file(*path, *source);
    }
    let project = builder.build();
    let analyzer = GoAnalyzer::from_project(project.project().clone());
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
package sample

func Alpha(value int) int {
    total := value + 2
    if total > 20 {
        return total * 3
    }
    return total - 4
}
"#;

const BETA: &str = r#"
package sample

func Beta(seed int) int {
    amount := seed + 2
    if amount > 20 {
        return amount * 3
    }
    return amount - 4
}
"#;

#[test]
fn flags_renamed_variable_clone_in_go() {
    let findings = analyze(
        &[("src/a.go", ALPHA), ("src/b.go", BETA)],
        &["src/a.go"],
        default_weights(),
    );

    assert!(
        findings.iter().any(|finding| {
            finding.enclosing_fq_name.contains("Alpha")
                && finding.peer_enclosing_fq_name.contains("Beta")
        }),
        "{findings:#?}"
    );
}

#[test]
fn includes_receiver_method_candidates() {
    let alpha = r#"
package sample

type Alpha struct{}

func (Alpha) Compute(value int) int {
    total := value + 2
    if total > 20 {
        return total * 3
    }
    return total - 4
}
"#;
    let beta = r#"
package sample

type Beta struct{}

func (Beta) Calculate(seed int) int {
    amount := seed + 2
    if amount > 20 {
        return amount * 3
    }
    return amount - 4
}
"#;
    let findings = analyze(
        &[("src/a.go", alpha), ("src/b.go", beta)],
        &["src/a.go"],
        default_weights(),
    );

    assert!(
        findings.iter().any(|finding| {
            finding.enclosing_fq_name.contains("Compute")
                && finding.peer_enclosing_fq_name.contains("Calculate")
        }),
        "{findings:#?}"
    );
}

#[test]
fn ast_refinement_suppresses_different_go_control_flow() {
    let loop_body = r#"
package sample

func Beta(seed int) int {
    amount := seed + 2
    for amount > 20 {
        amount = amount - 1
    }
    amount = amount * 3
    return amount
}
"#;
    let files = [("src/a.go", ALPHA), ("src/b.go", loop_body)];
    let permissive = analyze(
        &files,
        &["src/a.go"],
        CloneSmellWeights {
            min_normalized_tokens: 12,
            min_similarity_percent: 50,
            shingle_size: 2,
            min_shared_shingles: 3,
            ast_similarity_percent: 1,
        },
    );
    assert!(!permissive.is_empty(), "{permissive:#?}");

    let findings = analyze(
        &files,
        &["src/a.go"],
        CloneSmellWeights {
            min_normalized_tokens: 12,
            min_similarity_percent: 50,
            shingle_size: 2,
            min_shared_shingles: 3,
            ast_similarity_percent: 85,
        },
    );

    assert!(findings.is_empty(), "{findings:#?}");
}

#[test]
fn strict_threshold_suppresses_small_go_functions() {
    let findings = analyze(
        &[
            (
                "src/a.go",
                "package sample\nfunc Alpha(x int) int { return x + 1 }",
            ),
            (
                "src/b.go",
                "package sample\nfunc Beta(y int) int { return y + 1 }",
            ),
        ],
        &["src/a.go"],
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
fn go_findings_have_stable_report_order() {
    let gamma = BETA.replace("Beta", "Gamma");
    let findings = analyze(
        &[
            ("src/c.go", gamma.as_str()),
            ("src/b.go", BETA),
            ("src/a.go", ALPHA),
        ],
        &["src/c.go", "src/b.go", "src/a.go"],
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
            ("src/a.go".to_string(), "src/b.go".to_string()),
            ("src/a.go".to_string(), "src/c.go".to_string()),
            ("src/b.go".to_string(), "src/c.go".to_string()),
        ],
        pairs
    );
}
