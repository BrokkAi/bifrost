use brokk_bifrost::{
    AnalyzerDelegate, CloneSmellWeights, IAnalyzer, JavascriptAnalyzer, Language, MultiAnalyzer,
    TypescriptAnalyzer,
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

fn analyze(
    files: &[(&str, &str)],
    requested: &[&str],
    weights: CloneSmellWeights,
) -> Vec<brokk_bifrost::CloneSmell> {
    let project = files
        .iter()
        .fold(
            InlineTestProject::with_language(Language::TypeScript),
            |project, (path, contents)| project.file(*path, *contents),
        )
        .build();
    let analyzer = TypescriptAnalyzer::from_project(project.project().clone());
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
fn flags_renamed_variable_clone_in_typescript() {
    let alpha = r#"
        export function alpha(input: number): number {
          const total = input + 2;
          if (total > 20) {
            return total * 3;
          }
          return total - 4;
        }
    "#;
    let beta = r#"
        export function beta(seed: number): number {
          const amount = seed + 2;
          if (amount > 20) {
            return amount * 3;
          }
          return amount - 4;
        }
    "#;

    let findings = analyze_pair("src/a.ts", alpha, "src/b.ts", beta, default_weights());

    assert!(findings.iter().any(|finding| {
        finding.enclosing_fq_name.contains("alpha")
            && finding.peer_enclosing_fq_name.contains("beta")
    }));
}

#[test]
fn tiny_typescript_functions_can_be_ignored_by_min_tokens() {
    let alpha = r#"
        export function alpha(x: number): number {
          return x + 1;
        }
    "#;
    let beta = r#"
        export function beta(y: number): number {
          return y + 1;
        }
    "#;

    let findings = analyze_pair(
        "src/a.ts",
        alpha,
        "src/b.ts",
        beta,
        CloneSmellWeights {
            min_normalized_tokens: 40,
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
        export function alpha(input: number): number {
          const total = input + 2;
          if (total > 20) {
            return total * 3;
          }
          return total - 4;
        }
    "#;
    let beta = r#"
        export function beta(seed: number): number {
          console.log(seed);
          const amount = seed + 2;
          if (amount > 20) {
            console.log(amount);
            return amount * 3;
          }
          console.log(amount - 4);
          return amount - 4;
        }
    "#;

    let findings = analyze_pair(
        "src/a.ts",
        alpha,
        "src/b.ts",
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
        export function alpha(input: number): number {
          const total = input + 2;
          if (total > 20) {
            return total * 3;
          }
          return total - 4;
        }
    "#;
    let beta = r#"
        export function beta(seed: number): number {
          let amount = seed + 2;
          while (amount > 20) {
            amount = amount - 1;
          }
          amount = amount * 3;
          return amount;
        }
    "#;

    let findings = analyze_pair(
        "src/a.ts",
        alpha,
        "src/b.ts",
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
fn finds_clone_in_javascript_too() {
    let alpha = r#"
        export function alpha(input) {
          const total = input + 2;
          if (total > 20) {
            return total * 3;
          }
          return total - 4;
        }
    "#;
    let beta = r#"
        export function beta(seed) {
          const amount = seed + 2;
          if (amount > 20) {
            return amount * 3;
          }
          return amount - 4;
        }
    "#;
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file("src/a.js", alpha)
        .file("src/b.js", beta)
        .build();
    let analyzer = JavascriptAnalyzer::from_project(project.project().clone());
    let requested = vec![project.file("src/a.js")];

    let findings = analyzer.find_structural_clone_smells_for_files(&requested, default_weights());

    assert!(findings.iter().any(|finding| {
        finding.enclosing_fq_name.contains("alpha")
            && finding.peer_enclosing_fq_name.contains("beta")
    }));
}

#[test]
fn multi_analyzer_returns_typescript_and_javascript_clone_findings() {
    let js_alpha = r#"
        export function alpha(input) {
          const total = input + 2;
          if (total > 20) {
            return total * 3;
          }
          return total - 4;
        }
    "#;
    let js_beta = r#"
        export function beta(seed) {
          const amount = seed + 2;
          if (amount > 20) {
            return amount * 3;
          }
          return amount - 4;
        }
    "#;
    let ts_alpha = r#"
        export function gamma(input: number): number {
          const total = input + 2;
          if (total > 20) {
            return total * 3;
          }
          return total - 4;
        }
    "#;
    let ts_beta = r#"
        export function delta(seed: number): number {
          const amount = seed + 2;
          if (amount > 20) {
            return amount * 3;
          }
          return amount - 4;
        }
    "#;
    let project = InlineTestProject::new()
        .file("src/a.js", js_alpha)
        .file("src/b.js", js_beta)
        .file("src/c.ts", ts_alpha)
        .file("src/d.ts", ts_beta)
        .build();
    let multi = MultiAnalyzer::new(BTreeMap::from([
        (
            Language::JavaScript,
            AnalyzerDelegate::JavaScript(JavascriptAnalyzer::from_project(
                project.project().clone(),
            )),
        ),
        (
            Language::TypeScript,
            AnalyzerDelegate::TypeScript(TypescriptAnalyzer::from_project(
                project.project().clone(),
            )),
        ),
    ]));
    let requested = vec![
        project.file("src/a.js"),
        project.file("src/b.js"),
        project.file("src/c.ts"),
        project.file("src/d.ts"),
    ];

    let findings = multi.find_structural_clone_smells_for_files(&requested, default_weights());

    assert!(findings.iter().any(|finding| {
        finding.enclosing_fq_name.contains("alpha")
            && finding.peer_enclosing_fq_name.contains("beta")
    }));
    assert!(findings.iter().any(|finding| {
        finding.enclosing_fq_name.contains("gamma")
            && finding.peer_enclosing_fq_name.contains("delta")
    }));
}
