use brokk_analyzer::{CloneSmellWeights, CppAnalyzer, IAnalyzer, Language};

mod common;

use common::InlineTestProject;

fn analyze_pair(
    path_a: &str,
    source_a: &str,
    path_b: &str,
    source_b: &str,
    weights: CloneSmellWeights,
) -> Vec<brokk_analyzer::CloneSmell> {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(path_a, source_a)
        .file(path_b, source_b)
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    let requested = vec![project.file(path_a)];
    analyzer.find_structural_clone_smells_for_files(&requested, weights)
}

fn default_weights() -> CloneSmellWeights {
    CloneSmellWeights::defaults()
}

#[test]
fn flags_renamed_variable_clone_in_cpp() {
    let alpha = r#"
        class Alpha {
        public:
          int compute(int value) {
            int total = value + 2;
            if (total > 20) {
              return total * 3;
            }
            return total - 4;
          }
        };
    "#;
    let beta = r#"
        class Beta {
        public:
          int calculate(int seed) {
            int amount = seed + 2;
            if (amount > 20) {
              return amount * 3;
            }
            return amount - 4;
          }
        };
    "#;

    let findings = analyze_pair("src/a.cpp", alpha, "src/b.cpp", beta, default_weights());

    assert!(findings.iter().any(|finding| {
        finding.enclosing_fq_name.contains("compute")
            && finding.peer_enclosing_fq_name.contains("calculate")
    }));
}

#[test]
fn strict_threshold_can_suppress_small_cpp_snippet() {
    let alpha = r#"
        int alpha(int x) {
          return x + 1;
        }
    "#;
    let beta = r#"
        int beta(int y) {
          return y + 1;
        }
    "#;

    let findings = analyze_pair(
        "src/a.cpp",
        alpha,
        "src/b.cpp",
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
fn ast_refinement_suppresses_different_cpp_control_flow() {
    let alpha = r#"
        int alpha(int value) {
          int total = value + 2;
          if (total > 20) {
            return total * 3;
          }
          return total - 4;
        }
    "#;
    let beta = r#"
        int beta(int seed) {
          int amount = seed + 2;
          while (amount > 20) {
            amount = amount - 1;
          }
          amount = amount * 3;
          return amount;
        }
    "#;

    let findings = analyze_pair(
        "src/a.cpp",
        alpha,
        "src/b.cpp",
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
