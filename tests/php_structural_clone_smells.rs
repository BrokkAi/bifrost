use brokk_analyzer::{CloneSmellWeights, IAnalyzer, Language, PhpAnalyzer};

mod common;

use common::InlineTestProject;

fn analyze_pair(
    path_a: &str,
    source_a: &str,
    path_b: &str,
    source_b: &str,
    weights: CloneSmellWeights,
) -> Vec<brokk_analyzer::CloneSmell> {
    let project = InlineTestProject::with_language(Language::Php)
        .file(path_a, source_a)
        .file(path_b, source_b)
        .build();
    let analyzer = PhpAnalyzer::from_project(project.project().clone());
    let requested = vec![project.file(path_a)];
    analyzer.find_structural_clone_smells_for_files(&requested, weights)
}

#[test]
fn flags_renamed_variable_clone_in_php() {
    let alpha = r#"
        <?php
        function alpha($value) {
            $total = $value + 2;
            if ($total > 20) {
                return $total * 3;
            }
            return $total - 4;
        }
    "#;
    let beta = r#"
        <?php
        function beta($seed) {
            $amount = $seed + 2;
            if ($amount > 20) {
                return $amount * 3;
            }
            return $amount - 4;
        }
    "#;

    let findings = analyze_pair(
        "src/a.php",
        alpha,
        "src/b.php",
        beta,
        CloneSmellWeights {
            min_normalized_tokens: 12,
            min_similarity_percent: 55,
            shingle_size: 2,
            min_shared_shingles: 3,
            ast_similarity_percent: 70,
        },
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
fn strict_threshold_can_suppress_small_php_snippet() {
    let alpha = r#"
        <?php
        function alpha($x) {
            return $x + 1;
        }
    "#;
    let beta = r#"
        <?php
        function beta($y) {
            return $y + 1;
        }
    "#;

    let findings = analyze_pair(
        "src/a.php",
        alpha,
        "src/b.php",
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
fn ast_refinement_suppresses_different_php_control_flow() {
    let alpha = r#"
        <?php
        function alpha($value) {
            $total = $value + 2;
            if ($total > 20) {
                return $total * 3;
            }
            return $total - 4;
        }
    "#;
    let beta = r#"
        <?php
        function beta($seed) {
            $amount = $seed + 2;
            while ($amount > 20) {
                $amount = $amount - 1;
            }
            $amount = $amount * 3;
            return $amount;
        }
    "#;

    let findings = analyze_pair(
        "src/a.php",
        alpha,
        "src/b.php",
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
