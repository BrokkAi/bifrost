mod common;

use brokk_analyzer::usages::{FuzzyResult, UsageAnalyzer, UsageFinder};
use brokk_analyzer::{
    AnalyzerDelegate, CodeUnit, IAnalyzer, Language, MultiAnalyzer, ProjectFile, RustAnalyzer,
};
use common::InlineTestProject;
use std::collections::BTreeSet;

fn definition(analyzer: &RustAnalyzer, fq_name: &str) -> CodeUnit {
    analyzer
        .get_definitions(fq_name)
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("missing definition for {fq_name}"))
}

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

#[test]
fn usage_finder_routes_seeded_public_rust_export_through_graph() {
    let (project, analyzer) = rust_analyzer_with_files(&[
        ("src/service.rs", "pub struct Service;\n"),
        (
            "src/main.rs",
            r#"
use crate::service::Service;

fn run() {
    let _ = Service {};
}
"#,
        ),
    ]);

    let target = definition(&analyzer, "service.Service");
    let result = UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&target));
    let hits = result
        .into_either()
        .expect("expected Rust graph or fallback success");
    assert_eq!(1, hits.len());
    assert!(
        hits.iter()
            .all(|hit| hit.file == project.file("src/main.rs"))
    );
}

#[test]
fn rust_graph_strategy_finds_same_file_private_function_calls() {
    let (_project, analyzer) = rust_analyzer_with_files(&[(
        "src/searchtools.rs",
        r#"
fn summarize_symbol_targets() {}

pub fn get_summaries() {
    summarize_symbol_targets();
}
"#,
    )]);

    let target = definition(&analyzer, "searchtools.summarize_symbol_targets");
    let candidates = BTreeSet::new();

    let result = brokk_analyzer::usages::RustExportUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates.into_iter().collect(),
        1000,
    );
    let hits = result
        .into_either()
        .expect("expected same-file private function usage");
    assert_eq!(1, hits.len());
}

#[test]
fn rust_graph_strategy_respects_explicit_candidate_files() {
    let (project, analyzer) = rust_analyzer_with_files(&[
        ("src/service.rs", "pub struct Service;\n"),
        (
            "src/main.rs",
            r#"
use crate::service::Service;

fn run() {
    let _ = Service {};
}
"#,
        ),
        ("src/other.rs", "fn unrelated() {}\n"),
    ]);

    let target = definition(&analyzer, "service.Service");
    let candidates = [project.file("src/other.rs")].into_iter().collect();

    let result = brokk_analyzer::usages::RustExportUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates,
        1000,
    );
    let hits = result.into_either().expect("expected success");
    assert!(hits.is_empty());
}

#[test]
fn rust_graph_strategy_filters_non_rust_candidates_without_widening() {
    let (_project, analyzer) = rust_analyzer_with_files(&[
        ("src/service.rs", "pub struct Service;\n"),
        (
            "src/main.rs",
            r#"
use crate::service::Service;

fn run() {
    let _ = Service {};
}
"#,
        ),
        ("README.md", "# notes\n"),
        ("Cargo.toml", "[package]\nname = \"demo\"\n"),
    ]);

    let target = definition(&analyzer, "service.Service");
    let broad_candidates = analyzer.get_analyzed_files().into_iter().collect();
    let non_rust_only = [ProjectFile::new(
        analyzer.project().root().to_path_buf(),
        "README.md",
    )]
    .into_iter()
    .collect();

    let broad = brokk_analyzer::usages::RustExportUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &broad_candidates,
        1000,
    );
    let narrowed = brokk_analyzer::usages::RustExportUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &non_rust_only,
        1000,
    );

    assert_eq!(1, broad.into_either().expect("broad success").len());
    assert!(narrowed.into_either().expect("narrowed success").is_empty());
}

#[test]
fn rust_graph_strategy_returns_too_many_callsites_when_hits_exceed_limit() {
    let (_project, analyzer) = rust_analyzer_with_files(&[
        ("src/service.rs", "pub struct Service;\n"),
        (
            "src/first.rs",
            r#"
use crate::service::Service;
fn first() { let _ = Service {}; }
"#,
        ),
        (
            "src/second.rs",
            r#"
use crate::service::Service;
fn second() { let _ = Service {}; }
"#,
        ),
    ]);

    let target = definition(&analyzer, "service.Service");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();

    let result = brokk_analyzer::usages::RustExportUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates,
        1,
    );

    match result {
        FuzzyResult::TooManyCallsites { limit, .. } => assert_eq!(1, limit),
        other => panic!("expected TooManyCallsites, got {other:?}"),
    }
}

#[test]
fn rust_graph_strategy_finds_same_file_struct_references_in_types_and_literals() {
    let (_project, analyzer) = rust_analyzer_with_files(&[(
        "src/summary.rs",
        r#"
pub struct RenderedSummary {
    pub label: String,
    pub text: String,
}

pub fn summarize_inputs(inputs: &[String]) -> Result<Vec<RenderedSummary>, String> {
    inputs
        .iter()
        .map(|input| summarize_input(input))
        .collect()
}

fn summarize_input(input: &str) -> Result<RenderedSummary, String> {
    Ok(RenderedSummary {
        label: input.to_string(),
        text: input.to_string(),
    })
}
"#,
    )]);

    let target = definition(&analyzer, "summary.RenderedSummary");
    let candidates = std::collections::HashSet::default();

    let result = brokk_analyzer::usages::RustExportUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates,
        1000,
    );
    assert_eq!(
        3,
        result
            .into_either()
            .expect("same-file struct success")
            .len()
    );
}

#[test]
fn usage_finder_routes_rust_targets_through_multi_analyzer_delegate() {
    let (project, rust) = rust_analyzer_with_files(&[
        ("src/service.rs", "pub struct Service;\n"),
        (
            "src/main.rs",
            r#"
use crate::service::Service;

fn run() {
    let _ = Service {};
}
"#,
        ),
    ]);
    let analyzer = MultiAnalyzer::new(std::collections::BTreeMap::from([(
        Language::Rust,
        AnalyzerDelegate::Rust(rust),
    )]));

    let target = analyzer
        .get_definitions("service.Service")
        .into_iter()
        .next()
        .expect("missing multi-analyzer target");
    let hits = UsageFinder::new()
        .find_usages_default(&analyzer, std::slice::from_ref(&target))
        .into_either()
        .expect("expected Rust graph success via MultiAnalyzer");

    assert_eq!(1, hits.len());
    assert!(
        hits.iter()
            .all(|hit| hit.file == project.file("src/main.rs"))
    );
}
