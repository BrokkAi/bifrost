mod common;

use brokk_bifrost::code_quality::{
    ReportDeadCodeAndUnusedAbstractionSmellsParams, report_dead_code_and_unused_abstraction_smells,
};
use brokk_bifrost::{IAnalyzer, Language, RustAnalyzer};
use common::InlineTestProject;

fn rust_analyzer_with_files(
    files: &[(&str, &str)],
) -> (common::BuiltInlineTestProject, RustAnalyzer) {
    let mut builder = InlineTestProject::with_language(Language::Rust);
    for (path, contents) in files {
        builder = builder.file(path, *contents);
    }
    let project = builder.build();
    let analyzer = RustAnalyzer::from_project(project.project().clone());
    (project, analyzer)
}

fn report(
    analyzer: &dyn IAnalyzer,
    params: ReportDeadCodeAndUnusedAbstractionSmellsParams,
) -> String {
    report_dead_code_and_unused_abstraction_smells(analyzer, params).report
}

#[test]
fn rust_dead_code_smell_reports_unused_private_helper() {
    let (_project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/helpers.rs",
            r#"
fn helper() {}

pub fn entry() {}
"#,
        ),
        (
            "src/main.rs",
            r#"
use crate::helpers::entry;

fn main() {
    entry();
}
"#,
        ),
    ]);

    let report = report(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["src/helpers.rs".to_string(), "src/main.rs".to_string()],
            fq_names: vec!["helpers.helper".to_string()],
            ..Default::default()
        },
    );

    assert!(report.starts_with("## Dead code and unused abstraction smells"));
    assert!(report.contains("helpers.helper"), "{report}");
    assert!(report.contains("no non-self usages found"), "{report}");
}

#[test]
fn rust_dead_code_smell_reports_one_call_wrapper() {
    let (_project, analyzer) = rust_analyzer_with_files(&[(
        "src/helpers.rs",
        r#"
fn wrapper() {
    leaf();
}

fn leaf() {}

fn entry() {
    wrapper();
}
"#,
    )]);

    let report = report(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["src/helpers.rs".to_string()],
            fq_names: vec!["helpers.wrapper".to_string()],
            ..Default::default()
        },
    );

    assert!(report.contains("helpers.wrapper"), "{report}");
    assert!(report.contains("only usage: src/helpers.rs"), "{report}");
    assert!(report.contains("| 1 | 1 |"), "{report}");
}

#[test]
fn rust_dead_code_smell_ignores_self_recursive_usage() {
    let (_project, analyzer) = rust_analyzer_with_files(&[(
        "src/helpers.rs",
        r#"
fn recurse(n: u32) {
    if n > 0 {
        recurse(n - 1);
    }
}
"#,
    )]);

    let report = report(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["src/helpers.rs".to_string()],
            fq_names: vec!["helpers.recurse".to_string()],
            ..Default::default()
        },
    );

    assert!(report.contains("helpers.recurse"), "{report}");
    assert!(report.contains("no non-self usages found"), "{report}");
}

#[test]
fn rust_dead_code_smell_skips_truncated_usage_candidates() {
    let (_project, analyzer) = rust_analyzer_with_files(&[
        ("src/helpers.rs", "fn helper() {}\n"),
        ("src/other1.rs", "fn other1() {}\n"),
        ("src/other2.rs", "fn other2() {}\n"),
    ]);

    let result = report_dead_code_and_unused_abstraction_smells(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec![
                "src/helpers.rs".to_string(),
                "src/other1.rs".to_string(),
                "src/other2.rs".to_string(),
            ],
            fq_names: vec!["helpers.helper".to_string()],
            max_usage_candidate_files: 1,
            ..Default::default()
        },
    );

    assert!(
        result
            .report
            .contains("usage candidate files exceeded cap 1"),
        "{}",
        result.report
    );
    assert!(
        result
            .report
            .contains("No dead code or unused abstraction smells met minScore 8."),
        "{}",
        result.report
    );
}

#[test]
fn rust_dead_code_smell_respects_explicit_fq_name_targeting() {
    let (_project, analyzer) = rust_analyzer_with_files(&[(
        "src/helpers.rs",
        r#"
fn helper() {}
fn ignored() {}
"#,
    )]);

    let report = report(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["src/helpers.rs".to_string()],
            fq_names: vec!["helpers.helper".to_string()],
            ..Default::default()
        },
    );

    assert!(report.contains("helpers.helper"), "{report}");
    assert!(!report.contains("helpers.ignored"), "{report}");
}

#[test]
fn rust_dead_code_smell_honors_threshold() {
    let (_project, analyzer) = rust_analyzer_with_files(&[(
        "src/helpers.rs",
        r#"
fn wrapper() {
    leaf();
}

fn leaf() {}

fn entry() {
    wrapper();
}
"#,
    )]);

    let report = report(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["src/helpers.rs".to_string()],
            fq_names: vec!["helpers.wrapper".to_string()],
            min_score: 100,
            ..Default::default()
        },
    );

    assert_eq!(
        "## Dead code and unused abstraction smells\n\n- Min score: 100\n- Input files analyzed cap: 25\n- Candidate symbol cap: 200\n- Usage candidate file cap: 1000\n- Usage cap per symbol: 100\n- Analysis mode: graph-backed tree-sitter usage analysis (best-effort).\n- Candidate symbols analyzed: 1\n- Findings shown: 0 of 0\n\nNo dead code or unused abstraction smells met minScore 100.",
        report
    );
}
