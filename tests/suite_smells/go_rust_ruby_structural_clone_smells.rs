use brokk_bifrost::code_quality::{
    ReportStructuralCloneSmellsParams, report_structural_clone_smells,
};
use brokk_bifrost::{
    AnalyzerDelegate, GoAnalyzer, Language, MultiAnalyzer, RubyAnalyzer, RustAnalyzer,
};
use std::collections::BTreeMap;

use crate::common::InlineTestProject;

#[test]
fn mixed_go_rust_ruby_mcp_report_contains_each_language() {
    let project = InlineTestProject::new()
        .file(
            "go/a.go",
            r#"package sample
func Alpha(value int) int {
    total := value + 2
    if total > 20 { return total * 3 }
    return total - 4
}"#,
        )
        .file(
            "go/b.go",
            r#"package sample
func Beta(seed int) int {
    amount := seed + 2
    if amount > 20 { return amount * 3 }
    return amount - 4
}"#,
        )
        .file(
            "rust/a.rs",
            r#"fn gamma(value: i32) -> i32 {
    let total = value + 2;
    if total > 20 { return total * 3; }
    total - 4
}"#,
        )
        .file(
            "rust/b.rs",
            r#"fn delta(seed: i32) -> i32 {
    let amount = seed + 2;
    if amount > 20 { return amount * 3; }
    amount - 4
}"#,
        )
        .file(
            "ruby/a.rb",
            r#"def epsilon(value)
  total = value + 2
  return total * 3 if total > 20
  total - 4
end"#,
        )
        .file(
            "ruby/b.rb",
            r#"def zeta(seed)
  amount = seed + 2
  return amount * 3 if amount > 20
  amount - 4
end"#,
        )
        .build();
    let multi = MultiAnalyzer::new(BTreeMap::from([
        (
            Language::Go,
            AnalyzerDelegate::Go(GoAnalyzer::from_project(project.project().clone())),
        ),
        (
            Language::Rust,
            AnalyzerDelegate::Rust(RustAnalyzer::from_project(project.project().clone())),
        ),
        (
            Language::Ruby,
            AnalyzerDelegate::Ruby(RubyAnalyzer::from_project(project.project().clone())),
        ),
    ]));

    let result = report_structural_clone_smells(
        &multi,
        ReportStructuralCloneSmellsParams {
            file_paths: [
                "go/a.go",
                "go/b.go",
                "rust/a.rs",
                "rust/b.rs",
                "ruby/a.rb",
                "ruby/b.rb",
            ]
            .into_iter()
            .map(str::to_string)
            .collect(),
            min_score: 0,
            min_normalized_tokens: 0,
            shingle_size: 0,
            min_shared_shingles: 0,
            ast_similarity_percent: 0,
            max_findings: 0,
        },
    );

    assert!(result.report.contains("Alpha"), "{}", result.report);
    assert!(result.report.contains("Beta"), "{}", result.report);
    assert!(result.report.contains("gamma"), "{}", result.report);
    assert!(result.report.contains("delta"), "{}", result.report);
    assert!(result.report.contains("epsilon"), "{}", result.report);
    assert!(result.report.contains("zeta"), "{}", result.report);
    assert!(
        result.report.contains("- Findings shown: 3 of 3"),
        "{}",
        result.report
    );
    assert!(!result.truncated);
}
