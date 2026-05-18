use brokk_analyzer::{CloneSmellWeights, IAnalyzer, Language, ScalaAnalyzer};

mod common;

use common::InlineTestProject;

fn analyze_pair(
    path_a: &str,
    source_a: &str,
    path_b: &str,
    source_b: &str,
    weights: CloneSmellWeights,
) -> Vec<brokk_analyzer::CloneSmell> {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(path_a, source_a)
        .file(path_b, source_b)
        .build();
    let analyzer = ScalaAnalyzer::from_project(project.project().clone());
    let requested = vec![project.file(path_a)];
    analyzer.find_structural_clone_smells_for_files(&requested, weights)
}

fn default_weights() -> CloneSmellWeights {
    CloneSmellWeights::defaults()
}

#[test]
fn flags_renamed_variable_clone_in_scala() {
    let alpha = r#"
        object Alpha {
          def alpha(value: Int): Int = {
            val total = value + 2
            if (total > 20) {
              total * 3
            } else {
              total - 4
            }
          }
        }
    "#;
    let beta = r#"
        object Beta {
          def beta(seed: Int): Int = {
            val amount = seed + 2
            if (amount > 20) {
              amount * 3
            } else {
              amount - 4
            }
          }
        }
    "#;

    let findings = analyze_pair("src/A.scala", alpha, "src/B.scala", beta, default_weights());

    assert!(findings.iter().any(|finding| {
        finding.enclosing_fq_name.contains("alpha")
            && finding.peer_enclosing_fq_name.contains("beta")
    }));
}

#[test]
fn strict_threshold_can_suppress_small_scala_snippet() {
    let alpha = r#"
        object Alpha {
          def alpha(x: Int): Int = x + 1
        }
    "#;
    let beta = r#"
        object Beta {
          def beta(y: Int): Int = y + 1
        }
    "#;

    let findings = analyze_pair(
        "src/A.scala",
        alpha,
        "src/B.scala",
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
fn ast_refinement_suppresses_different_scala_control_flow() {
    let alpha = r#"
        object Alpha {
          def alpha(value: Int): Int = {
            val total = value + 2
            if (total > 20) {
              total * 3
            } else {
              total - 4
            }
          }
        }
    "#;
    let beta = r#"
        object Beta {
          def beta(seed: Int): Int = {
            var amount = seed + 2
            while (amount > 20) {
              amount = amount - 1
            }
            amount * 3
          }
        }
    "#;

    let findings = analyze_pair(
        "src/A.scala",
        alpha,
        "src/B.scala",
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
