mod common;

use brokk_bifrost::code_quality::{
    ReportDeadCodeAndUnusedAbstractionSmellsParams, report_dead_code_and_unused_abstraction_smells,
};
use brokk_bifrost::{CodeUnit, IAnalyzer, Language, RustAnalyzer};
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

fn rust_definition(analyzer: &RustAnalyzer, fq_name: &str) -> CodeUnit {
    analyzer
        .get_definitions(fq_name)
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("missing definition for {fq_name}"))
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
    assert!(
        report.contains("one workspace inbound edge from helpers.entry"),
        "{report}"
    );
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
fn rust_bulk_unproven_receiver_usage_is_inconclusive_not_dead() {
    let (_project, analyzer) = rust_analyzer_with_files(&[(
        "src/service.rs",
        r#"
fn activate() {}

trait Runner {}

fn execute(value: Box<dyn Runner>) {
    value.activate();
}
"#,
    )]);
    let run = rust_definition(&analyzer, "service.activate");

    let report = report(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["src/service.rs".to_string()],
            fq_names: vec![run.fq_name()],
            ..Default::default()
        },
    );

    assert!(
        report.contains("could not be proven or disproven"),
        "trait-object receiver should make bulk evidence inconclusive: {report}"
    );
    assert!(
        !report.contains("| `function` | `service.activate`"),
        "unproven-only bulk evidence must not report the target as dead: {report}"
    );
}

#[test]
fn rust_dead_code_smell_skips_truncated_usage_candidates() {
    let mut files = vec![(
        "src/helpers.rs".to_string(),
        "pub fn helper() {}\n".to_string(),
    )];
    for index in 0..=1000 {
        files.push((
            format!("src/caller_{index}.rs"),
            format!("use crate::helpers::helper;\n\nfn caller_{index}() {{\n    helper();\n}}\n"),
        ));
    }
    let borrowed_files: Vec<(&str, &str)> = files
        .iter()
        .map(|(path, contents)| (path.as_str(), contents.as_str()))
        .collect();
    let (_project, analyzer) = rust_analyzer_with_files(&borrowed_files);

    let result = report_dead_code_and_unused_abstraction_smells(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["src/helpers.rs".to_string()],
            fq_names: vec!["helpers.helper".to_string()],
            max_usage_candidate_files: 2000,
            ..Default::default()
        },
    );

    assert!(
        result
            .report
            .contains("too many workspace inbound call sites"),
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
fn rust_dead_code_smell_honors_usage_candidate_file_cap() {
    let (_project, analyzer) = rust_analyzer_with_files(&[
        ("src/helpers.rs", "fn helper() {}\n"),
        ("src/other.rs", "fn other() {}\n"),
    ]);

    let result = report_dead_code_and_unused_abstraction_smells(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["src/helpers.rs".to_string(), "src/other.rs".to_string()],
            fq_names: vec!["helpers.helper".to_string()],
            max_usage_candidate_files: 1,
            ..Default::default()
        },
    );

    assert!(
        result
            .report
            .contains("Rust usage graph candidate files exceeded cap 1"),
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
fn rust_dead_code_smell_honors_usage_cap() {
    let (_project, analyzer) = rust_analyzer_with_files(&[
        ("src/helpers.rs", "pub fn helper() {}\n"),
        (
            "src/callers.rs",
            r#"
use crate::helpers::helper;

fn caller_one() {
    helper();
}

fn caller_two() {
    helper();
}
"#,
        ),
    ]);

    let result = report_dead_code_and_unused_abstraction_smells(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["src/helpers.rs".to_string(), "src/callers.rs".to_string()],
            fq_names: vec!["helpers.helper".to_string()],
            max_usages_per_symbol: 1,
            ..Default::default()
        },
    );

    assert!(
        result
            .report
            .contains("too many workspace inbound call sites (2, limit 1)"),
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
fn rust_dead_code_smell_does_not_undercount_instance_method_usage() {
    let (_project, analyzer) = rust_analyzer_with_files(&[(
        "src/service.rs",
        r#"
pub struct Service {}

impl Service {
    pub fn used(&self) {}
}

fn entry() {
    let service = Service {};
    service.used();
    service.used();
}
"#,
    )]);
    let used = rust_definition(&analyzer, "service.Service.used");

    let result = report_dead_code_and_unused_abstraction_smells(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["src/service.rs".to_string()],
            fq_names: vec![used.fq_name()],
            ..Default::default()
        },
    );

    assert!(
        result
            .report
            .contains("No dead code or unused abstraction smells met minScore 8."),
        "{}",
        result.report
    );
    assert!(
        !result.report.contains("Skipped symbols"),
        "{}",
        result.report
    );
}

#[test]
fn rust_dead_code_smell_clamps_usage_cap_to_graph_callsite_limit() {
    let (_project, analyzer) =
        rust_analyzer_with_files(&[("src/helpers.rs", "pub fn helper() {}\n")]);

    let result = report_dead_code_and_unused_abstraction_smells(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["src/helpers.rs".to_string()],
            fq_names: vec!["helpers.helper".to_string()],
            max_usages_per_symbol: 2000,
            ..Default::default()
        },
    );

    assert!(
        result
            .report
            .contains("Usage cap per symbol: 1000 (clamped from 2000 by graph call-site cap)"),
        "{}",
        result.report
    );
}

#[test]
fn rust_dead_code_smell_reports_public_api_with_conservative_wording() {
    let (_project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/helpers.rs",
            r#"
pub fn public_surface() {}
"#,
        ),
        (
            "src/main.rs",
            r#"
fn main() {}
"#,
        ),
    ]);

    let report = report(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["src/helpers.rs".to_string(), "src/main.rs".to_string()],
            fq_names: vec!["helpers.public_surface".to_string()],
            ..Default::default()
        },
    );

    assert!(report.contains("helpers.public_surface"), "{report}");
    assert!(report.contains("unreferenced in workspace"), "{report}");
    assert!(report.contains("consumed externally"), "{report}");
    assert!(report.contains("| 10 | 0.55 |"), "{report}");
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
