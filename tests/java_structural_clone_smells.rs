use brokk_analyzer::code_quality::{
    ReportStructuralCloneSmellsParams, report_structural_clone_smells,
};
use brokk_analyzer::{
    AnalyzerDelegate, CloneSmellWeights, IAnalyzer, JavaAnalyzer, Language, MultiAnalyzer,
};
use std::collections::BTreeMap;

mod common;

use common::InlineTestProject;

fn analyze(
    files: &[(&str, &str)],
    requested: &[&str],
    weights: CloneSmellWeights,
) -> Vec<brokk_analyzer::CloneSmell> {
    let project = files
        .iter()
        .fold(
            InlineTestProject::with_language(Language::Java),
            |project, (path, contents)| project.file(*path, *contents),
        )
        .build();
    let analyzer = JavaAnalyzer::from_project(project.project().clone());
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
fn flags_renamed_variable_clones_across_files() {
    let alpha = r#"
        package com.example;
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
    let beta = r#"
        package com.example;
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

    let findings = analyze(
        &[
            ("com/example/Alpha.java", alpha),
            ("com/example/Beta.java", beta),
        ],
        &["com/example/Alpha.java"],
        default_weights(),
    );

    assert!(findings.iter().any(|finding| {
        finding.enclosing_fq_name.contains("Alpha.compute")
            && finding.peer_enclosing_fq_name.contains("Beta.calculate")
    }));
}

#[test]
fn ast_refinement_suppresses_different_control_flow() {
    let alpha = r#"
        package com.example;
        class Alpha {
            int compute(int input) {
                int total = input + 1;
                if (total > 10) {
                    total = total * 2;
                } else {
                    total = total - 3;
                }
                return total;
            }
        }
    "#;
    let beta = r#"
        package com.example;
        class Beta {
            int calculate(int seed) {
                int amount = seed + 1;
                while (amount > 10) {
                    amount = amount - 1;
                }
                amount = amount * 2;
                return amount;
            }
        }
    "#;

    let findings = analyze(
        &[
            ("com/example/Alpha.java", alpha),
            ("com/example/Beta.java", beta),
        ],
        &["com/example/Alpha.java"],
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
        package com.example;
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
    let beta = r#"
        package com.example;
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

    let findings = analyze(
        &[
            ("com/example/Alpha.java", alpha),
            ("com/example/Beta.java", beta),
        ],
        &["com/example/Alpha.java", "com/example/Beta.java"],
        default_weights(),
    );

    let forward = findings
        .iter()
        .filter(|finding| {
            finding.enclosing_fq_name.contains("Alpha.compute")
                && finding.peer_enclosing_fq_name.contains("Beta.calculate")
        })
        .count();
    let reverse = findings
        .iter()
        .filter(|finding| {
            finding.enclosing_fq_name.contains("Beta.calculate")
                && finding.peer_enclosing_fq_name.contains("Alpha.compute")
        })
        .count();
    assert_eq!(1, forward + reverse, "{findings:#?}");
}

#[test]
fn report_wrapper_dedupes_and_renders_clone_table() {
    let alpha = r#"
        package com.example;
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
    let beta = r#"
        package com.example;
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
    let project = InlineTestProject::with_language(Language::Java)
        .file("com/example/Alpha.java", alpha)
        .file("com/example/Beta.java", beta)
        .build();
    let analyzer = JavaAnalyzer::from_project(project.project().clone());

    let result = report_structural_clone_smells(
        &analyzer as &dyn IAnalyzer,
        ReportStructuralCloneSmellsParams {
            file_paths: vec![
                "com/example/Alpha.java".to_string(),
                "com/example/Beta.java".to_string(),
            ],
            ..ReportStructuralCloneSmellsParams {
                file_paths: Vec::new(),
                min_score: 0,
                min_normalized_tokens: 0,
                shingle_size: 0,
                min_shared_shingles: 0,
                ast_similarity_percent: 0,
                max_findings: 0,
            }
        },
    );

    assert!(result.report.starts_with("## Structural clone smells"));
    assert!(result.report.contains("Alpha.compute"));
    assert!(result.report.contains("Beta.calculate"));
    assert_eq!(
        1,
        result
            .report
            .lines()
            .filter(|line| line.starts_with("| ") && line.contains("Alpha.compute"))
            .count(),
        "{}",
        result.report
    );
}

#[test]
fn multi_analyzer_matches_direct_java_clone_results() {
    let alpha = r#"
        package com.example;
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
    let beta = r#"
        package com.example;
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
    let project = InlineTestProject::with_language(Language::Java)
        .file("com/example/Alpha.java", alpha)
        .file("com/example/Beta.java", beta)
        .build();
    let direct = JavaAnalyzer::from_project(project.project().clone());
    let multi = MultiAnalyzer::new(BTreeMap::from([(
        Language::Java,
        AnalyzerDelegate::Java(JavaAnalyzer::from_project(project.project().clone())),
    )]));
    let requested = vec![project.file("com/example/Alpha.java")];

    let direct_findings =
        direct.find_structural_clone_smells_for_files(&requested, default_weights());
    let multi_findings =
        multi.find_structural_clone_smells_for_files(&requested, default_weights());

    assert_eq!(direct_findings, multi_findings);
}
