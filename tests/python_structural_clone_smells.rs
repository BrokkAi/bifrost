use brokk_bifrost::{
    AnalyzerDelegate, CloneSmellWeights, IAnalyzer, JavaAnalyzer, Language, MultiAnalyzer,
    PythonAnalyzer,
};
use std::collections::BTreeMap;

mod common;

use common::InlineTestProject;

fn analyze_pair(
    path_a: &str,
    source_a: &str,
    path_b: &str,
    source_b: &str,
    weights: CloneSmellWeights,
) -> Vec<brokk_bifrost::CloneSmell> {
    analyze(
        &[(path_a, source_a), (path_b, source_b)],
        &[path_a],
        weights,
    )
}

fn analyze_both_requested(
    path_a: &str,
    source_a: &str,
    path_b: &str,
    source_b: &str,
    weights: CloneSmellWeights,
) -> Vec<brokk_bifrost::CloneSmell> {
    analyze(
        &[(path_a, source_a), (path_b, source_b)],
        &[path_a, path_b],
        weights,
    )
}

fn analyze(
    files: &[(&str, &str)],
    requested: &[&str],
    weights: CloneSmellWeights,
) -> Vec<brokk_bifrost::CloneSmell> {
    let project = files
        .iter()
        .fold(
            InlineTestProject::with_language(Language::Python),
            |project, (path, contents)| project.file(*path, *contents),
        )
        .build();
    let analyzer = PythonAnalyzer::from_project(project.project().clone());
    let requested_files = requested
        .iter()
        .map(|path| project.file(path))
        .collect::<Vec<_>>();
    analyzer.find_structural_clone_smells_for_files(&requested_files, weights)
}

fn default_weights() -> CloneSmellWeights {
    CloneSmellWeights::defaults()
}

#[test]
fn flags_renamed_variable_clone_in_python() {
    let alpha = r#"
        def alpha(value):
            total = value + 2
            if total > 20:
                return total * 3
            return total - 4
    "#;
    let beta = r#"
        def beta(seed):
            amount = seed + 2
            if amount > 20:
                return amount * 3
            return amount - 4
    "#;

    let findings = analyze_pair("pkg/a.py", alpha, "pkg/b.py", beta, default_weights());

    assert!(findings.iter().any(|finding| {
        finding.enclosing_fq_name.contains("alpha")
            && finding.peer_enclosing_fq_name.contains("beta")
    }));
}

#[test]
fn small_snippet_is_suppressed_by_min_token_threshold() {
    let alpha = r#"
        def alpha(x):
            return x + 1
    "#;
    let beta = r#"
        def beta(y):
            return y + 1
    "#;

    let findings = analyze_pair(
        "pkg/a.py",
        alpha,
        "pkg/b.py",
        beta,
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
fn treats_extra_logging_as_equivalent_clone() {
    let alpha = r#"
        def alpha(value):
            total = value + 2
            if total > 20:
                return total * 3
            return total - 4
    "#;
    let beta = r#"
        def beta(seed):
            print(seed)
            amount = seed + 2
            if amount > 20:
                print(amount)
                return amount * 3
            print(amount - 4)
            return amount - 4
    "#;

    let findings = analyze_pair(
        "pkg/a.py",
        alpha,
        "pkg/b.py",
        beta,
        CloneSmellWeights {
            min_normalized_tokens: 12,
            min_similarity_percent: 55,
            shingle_size: 2,
            min_shared_shingles: 3,
            ast_similarity_percent: 70,
        },
    );

    assert!(findings.iter().any(|finding| {
        finding.enclosing_fq_name.contains("alpha")
            && finding.peer_enclosing_fq_name.contains("beta")
    }));
}

#[test]
fn ast_refinement_suppresses_different_control_flow() {
    let alpha = r#"
        def alpha(value):
            total = value + 2
            if total > 20:
                return total * 3
            return total - 4
    "#;
    let beta = r#"
        def beta(seed):
            amount = seed + 2
            while amount > 20:
                amount = amount - 1
            amount = amount * 3
            return amount
    "#;

    let findings = analyze_pair(
        "pkg/a.py",
        alpha,
        "pkg/b.py",
        beta,
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
fn does_not_return_symmetric_pairs_when_both_files_are_requested() {
    let alpha = r#"
        def alpha(value):
            total = value + 2
            if total > 20:
                return total * 3
            return total - 4
    "#;
    let beta = r#"
        def beta(seed):
            amount = seed + 2
            if amount > 20:
                return amount * 3
            return amount - 4
    "#;

    let findings = analyze_both_requested("pkg/a.py", alpha, "pkg/b.py", beta, default_weights());

    let forward = findings
        .iter()
        .filter(|finding| {
            finding.enclosing_fq_name.contains("alpha")
                && finding.peer_enclosing_fq_name.contains("beta")
        })
        .count();
    let reverse = findings
        .iter()
        .filter(|finding| {
            finding.enclosing_fq_name.contains("beta")
                && finding.peer_enclosing_fq_name.contains("alpha")
        })
        .count();
    assert_eq!(1, forward + reverse, "{findings:#?}");
}

#[test]
fn multi_analyzer_returns_java_and_python_clone_findings() {
    let java_alpha = r#"
        class Alpha {
            int compute(int input) {
                int total = input + 1;
                if (total > 10) {
                    return total * 2;
                }
                return total - 3;
            }
        }
    "#;
    let java_beta = r#"
        class Beta {
            int calculate(int seed) {
                int amount = seed + 1;
                if (amount > 10) {
                    return amount * 2;
                }
                return amount - 3;
            }
        }
    "#;
    let py_alpha = r#"
        def alpha(value):
            total = value + 2
            if total > 20:
                return total * 3
            return total - 4
    "#;
    let py_beta = r#"
        def beta(seed):
            amount = seed + 2
            if amount > 20:
                return amount * 3
            return amount - 4
    "#;

    let project = InlineTestProject::new()
        .file("src/Alpha.java", java_alpha)
        .file("src/Beta.java", java_beta)
        .file("pkg/a.py", py_alpha)
        .file("pkg/b.py", py_beta)
        .build();
    let multi = MultiAnalyzer::new(BTreeMap::from([
        (
            Language::Java,
            AnalyzerDelegate::Java(JavaAnalyzer::from_project(project.project().clone())),
        ),
        (
            Language::Python,
            AnalyzerDelegate::Python(PythonAnalyzer::from_project(project.project().clone())),
        ),
    ]));
    let requested = vec![
        project.file("src/Alpha.java"),
        project.file("src/Beta.java"),
        project.file("pkg/a.py"),
        project.file("pkg/b.py"),
    ];

    let findings = multi.find_structural_clone_smells_for_files(&requested, default_weights());

    assert!(findings.iter().any(|finding| {
        finding.enclosing_fq_name.contains("Alpha.compute")
            && finding.peer_enclosing_fq_name.contains("Beta.calculate")
    }));
    assert!(findings.iter().any(|finding| {
        finding.enclosing_fq_name.contains("alpha")
            && finding.peer_enclosing_fq_name.contains("beta")
    }));
}
