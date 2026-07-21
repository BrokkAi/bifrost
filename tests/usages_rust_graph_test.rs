mod common;

use brokk_bifrost::hash::HashSet;
use brokk_bifrost::usages::{
    ExplicitCandidateProvider, FuzzyResult, UsageAnalyzer, UsageFinder, UsageHit, UsageHitKind,
};
use brokk_bifrost::{
    AnalyzerDelegate, CodeUnit, IAnalyzer, Language, MultiAnalyzer, ProjectFile, RustAnalyzer,
};
use common::InlineTestProject;
use std::collections::BTreeSet;
use std::sync::Arc;

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
fn rust_import_hits_ignore_unrelated_aliased_use_path() {
    let consumer = r#"
use crate::target::Target;
use crate::other::Target as OtherTarget;

fn run(value: Target, other: OtherTarget) {}
"#;
    let (_project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/lib.rs",
            "pub mod target;\npub mod other;\npub mod consumer;\n",
        ),
        ("src/target.rs", "pub struct Target;\n"),
        ("src/other.rs", "pub struct Target;\n"),
        ("src/consumer.rs", consumer),
    ]);

    let target = definition(&analyzer, "target.Target");
    let result = UsageFinder::new().find_usages_default(&analyzer, &[target]);
    let editor_hits = result.all_hits_including_imports();
    let target_import_line = consumer[..consumer.find("use crate::target::Target").unwrap()]
        .matches('\n')
        .count()
        + 1;
    let other_import_line = consumer[..consumer.find("use crate::other::Target").unwrap()]
        .matches('\n')
        .count()
        + 1;

    assert!(
        editor_hits.iter().any(|hit| hit.line == target_import_line),
        "expected target import hit: {editor_hits:#?}"
    );
    assert!(
        editor_hits.iter().all(|hit| hit.line != other_import_line),
        "unrelated aliased import must not be reported as target hit: {editor_hits:#?}"
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

    let result = brokk_bifrost::usages::RustExportUsageGraphStrategy::new().find_usages(
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
fn rust_graph_strategy_finds_same_file_private_module_function_calls() {
    let (_project, analyzer) = rust_analyzer_with_files(&[
        ("src/lib.rs", "mod agent;\n"),
        (
            "src/agent.rs",
            r#"
fn parse_setup_bool(value: &str) -> Option<bool> {
    match value {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

fn parse_flag(value: &str) -> Option<bool> {
    parse_setup_bool(value)
}

fn parse_other(value: &str) -> Option<bool> {
    match parse_setup_bool(value) {
        Some(value) => Some(value),
        None => None,
    }
}
"#,
        ),
    ]);

    let target = definition(&analyzer, "agent.parse_setup_bool");
    let result = UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&target));
    let hits = result
        .into_either()
        .expect("expected same-file private module function usages");

    assert_eq!(
        2,
        hits.len(),
        "expected both same-file call sites: {hits:#?}"
    );
}

#[test]
fn rust_graph_strategy_finds_private_member_usages_without_export_seed() {
    let (project, analyzer) = rust_analyzer_with_files(&[
        ("src/lib.rs", "mod tracker;\nmod consumer;\n"),
        (
            "src/tracker.rs",
            r#"
struct RequestTracker;

impl RequestTracker {
    fn run_request(&self) {}
}
"#,
        ),
        (
            "src/consumer.rs",
            r#"
use crate::tracker::RequestTracker;

fn drive(tracker: RequestTracker) {
    tracker.run_request();
}
"#,
        ),
    ]);

    let target = member(
        &analyzer,
        &project.file("src/tracker.rs"),
        "RequestTracker",
        "run_request",
    );
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let result = brokk_bifrost::usages::RustExportUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates,
        1000,
    );
    let hits = match result {
        FuzzyResult::Success {
            hits_by_overload, ..
        } => hits_by_overload
            .into_values()
            .flat_map(BTreeSet::into_iter)
            .collect::<BTreeSet<_>>(),
        other => panic!("expected private member usage success, got {other:#?}"),
    };

    assert!(
        hits.iter()
            .any(|hit| hit.file == project.file("src/consumer.rs")
                && hit.snippet.contains("tracker.run_request")),
        "expected private member call in consumer.rs: {hits:#?}"
    );
}

#[test]
fn rust_graph_strategy_finds_imported_type_impl_target_usages_without_export_seed() {
    let (project, analyzer) = rust_analyzer_with_files(&[
        ("src/lib.rs", "pub mod ast;\npub mod utils;\n"),
        ("src/ast.rs", "pub struct StorageField;\n"),
        ("src/utils/mod.rs", "pub mod language;\n"),
        (
            "src/utils/language.rs",
            r#"
use crate::ast::StorageField;

pub trait Format {
    fn format(&self);
}

impl Format for StorageField {
    fn format(&self) {}
}

pub fn render(field: StorageField) {
    field.format();
}
"#,
        ),
    ]);

    let target = definition(&analyzer, "ast.StorageField");
    assert_eq!(project.file("src/ast.rs"), *target.source());

    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let result = brokk_bifrost::usages::RustExportUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates,
        1000,
    );
    let hits = match result {
        FuzzyResult::Success {
            hits_by_overload, ..
        } => hits_by_overload
            .into_values()
            .flat_map(BTreeSet::into_iter)
            .collect::<BTreeSet<_>>(),
        other => panic!("expected imported type impl target usage success, got {other:#?}"),
    };

    assert!(
        hits.iter().any(|hit| {
            hit.file == project.file("src/utils/language.rs")
                && hit.snippet.contains("StorageField")
        }),
        "expected local imported type references in language.rs: {hits:#?}"
    );
}

#[test]
fn rust_graph_strategy_finds_pub_cfg_test_async_function_calls() {
    let (_project, analyzer) = rust_analyzer_with_files(&[(
        "src/db.rs",
        r#"
#[cfg(test)]
pub async fn memory_pool() {}

#[cfg(test)]
pub async fn caller_one() {
    memory_pool().await;
}
"#,
    )]);

    let target = definition(&analyzer, "db.memory_pool");
    let candidates = BTreeSet::new();

    let result = brokk_bifrost::usages::RustExportUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates.into_iter().collect(),
        1000,
    );
    let hits = result
        .into_either()
        .expect("expected cfg(test) async function usages");
    assert_eq!(1, hits.len(), "expected the memory_pool() call: {hits:?}");
}

#[test]
fn rust_graph_strategy_does_not_treat_negated_cfg_test_as_same_file_only() {
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/db.rs",
            r#"
#[cfg(not(test))]
pub fn runtime_pool() {}
"#,
        ),
        (
            "src/lib.rs",
            r#"
pub mod db;

use crate::db::runtime_pool;

pub fn caller() {
    runtime_pool();
}
"#,
        ),
    ]);

    let target = definition(&analyzer, "db.runtime_pool");
    let candidates = BTreeSet::new();

    let result = brokk_bifrost::usages::RustExportUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates.into_iter().collect(),
        1000,
    );
    let hits = result
        .into_either()
        .expect("expected public function usages outside cfg(test) fast path");
    assert!(
        hits.iter()
            .any(|hit| hit.file == project.file("src/lib.rs")),
        "expected cross-file runtime_pool() usage, got {hits:?}"
    );
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

    let result = brokk_bifrost::usages::RustExportUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates,
        1000,
    );
    let hits = result.into_either().expect("expected success");
    assert!(hits.is_empty());
}

#[test]
fn rust_graph_strategy_finds_aliased_import_usage() {
    let (_project, analyzer) = rust_analyzer_with_files(&[
        ("src/service.rs", "pub struct Service;\n"),
        (
            "src/main.rs",
            r#"
use crate::service::Service as S;

fn run() {
    let _ = S {};
}
"#,
        ),
    ]);

    let target = definition(&analyzer, "service.Service");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();

    let result = brokk_bifrost::usages::RustExportUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates,
        1000,
    );
    assert_eq!(
        1,
        result.into_either().expect("aliased import success").len()
    );
}

#[test]
fn rust_graph_strategy_finds_grouped_import_usages() {
    let (_project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/service.rs",
            r#"
pub struct Service;
pub struct Helper;
"#,
        ),
        (
            "src/main.rs",
            r#"
use crate::service::{Service, Helper};

fn run() {
    let _ = Service {};
    let _ = Helper {};
}
"#,
        ),
    ]);

    let service = definition(&analyzer, "service.Service");
    let helper = definition(&analyzer, "service.Helper");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();

    let strategy = brokk_bifrost::usages::RustExportUsageGraphStrategy::new();
    assert_eq!(
        1,
        strategy
            .find_usages(&analyzer, std::slice::from_ref(&service), &candidates, 1000)
            .into_either()
            .expect("grouped Service success")
            .len()
    );
    assert_eq!(
        1,
        strategy
            .find_usages(&analyzer, std::slice::from_ref(&helper), &candidates, 1000)
            .into_either()
            .expect("grouped Helper success")
            .len()
    );
}

#[test]
fn rust_graph_strategy_finds_self_import_module_qualified_usage() {
    let (_project, analyzer) = rust_analyzer_with_files(&[
        ("src/service.rs", "pub fn factory() {}\n"),
        (
            "src/main.rs",
            r#"
use crate::service::{self};

fn run() {
    service::factory();
}
"#,
        ),
    ]);

    let target = definition(&analyzer, "service.factory");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();

    let result = brokk_bifrost::usages::RustExportUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates,
        1000,
    );
    assert_eq!(1, result.into_either().expect("self import success").len());
}

#[test]
fn rust_graph_strategy_finds_public_reexport_alias_usage() {
    let (_project, analyzer) = rust_analyzer_with_files(&[
        ("src/service.rs", "pub struct Service;\n"),
        (
            "src/index.rs",
            "pub use crate::service::Service as PublicService;\n",
        ),
        (
            "src/main.rs",
            r#"
use crate::index::PublicService;

fn run() {
    let _ = PublicService {};
}
"#,
        ),
    ]);

    let target = definition(&analyzer, "service.Service");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();

    let result = brokk_bifrost::usages::RustExportUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates,
        1000,
    );
    assert_eq!(
        1,
        result.into_either().expect("reexport alias success").len()
    );
}

#[test]
fn rust_graph_strategy_resolves_relative_module_layouts() {
    let (_project, analyzer) = rust_analyzer_with_files(&[
        ("src/pkg/service.rs", "pub struct Service;\n"),
        (
            "src/pkg/nested/mod.rs",
            r#"
use super::service::Service;

fn run() {
    let _ = Service {};
}
"#,
        ),
    ]);

    let target = definition(&analyzer, "pkg.service.Service");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();

    let result = brokk_bifrost::usages::RustExportUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates,
        1000,
    );
    assert_eq!(
        1,
        result
            .into_either()
            .expect("relative module layout success")
            .len()
    );
}

#[test]
fn rust_graph_strategy_counts_function_parameter_type_usages() {
    let (_project, analyzer) = rust_analyzer_with_files(&[
        ("src/service.rs", "pub struct SearchSymbolsParams;\n"),
        (
            "src/searchtools.rs",
            r#"
use crate::service::SearchSymbolsParams;

pub fn search_symbols(
    analyzer: &dyn IAnalyzer,
    params: SearchSymbolsParams,
) {
    let _ = analyzer;
    let _ = params;
}
"#,
        ),
    ]);

    let target = definition(&analyzer, "service.SearchSymbolsParams");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();

    let result = brokk_bifrost::usages::RustExportUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates,
        1000,
    );
    assert_eq!(
        1,
        result.into_either().expect("parameter type success").len()
    );
}

#[test]
fn private_rust_items_do_not_seed_graph_exports() {
    let (project, analyzer) = rust_analyzer_with_files(&[("src/service.rs", "struct Service;\n")]);
    let index = analyzer.export_index_of(&project.file("src/service.rs"));
    assert!(!index.exports_by_name.contains_key("Service"));
}

#[test]
fn local_definition_shadows_imported_rust_name() {
    let (_project, analyzer) = rust_analyzer_with_files(&[
        ("src/service.rs", "pub struct Service;\n"),
        (
            "src/main.rs",
            r#"
use crate::service::Service;

struct Service;

fn run() {
    let _ = Service {};
}
"#,
        ),
    ]);
    let target = definition(&analyzer, "service.Service");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();

    let result = brokk_bifrost::usages::RustExportUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates,
        1000,
    );
    assert!(result.into_either().expect("shadowed success").is_empty());
}

#[test]
fn rust_graph_shadow_detection_uses_tree_sitter_declaration_nodes() {
    let (_project, analyzer) = rust_analyzer_with_files(&[
        ("src/service.rs", "pub struct Service;\n"),
        (
            "src/main.rs",
            r#"
use crate::service::Service;

struct /* local shadow */ Service;

fn run() {
    let _ = Service {};
}
"#,
        ),
    ]);
    let target = definition(&analyzer, "service.Service");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();

    let result = brokk_bifrost::usages::RustExportUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates,
        1000,
    );
    assert!(
        result
            .into_either()
            .expect("tree-sitter shadowed success")
            .is_empty()
    );
}

#[test]
fn private_unseeded_rust_target_scans_to_empty_success() {
    let (_project, analyzer) = rust_analyzer_with_files(&[("src/service.rs", "struct Service;\n")]);
    let target = definition(&analyzer, "service.Service");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();

    let hits = brokk_bifrost::usages::RustExportUsageGraphStrategy::new()
        .find_usages(&analyzer, std::slice::from_ref(&target), &candidates, 1000)
        .into_either()
        .expect("private local target scan success");
    assert!(hits.is_empty(), "expected empty local scan: {hits:#?}");
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

    let broad = brokk_bifrost::usages::RustExportUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &broad_candidates,
        1000,
    );
    let narrowed = brokk_bifrost::usages::RustExportUsageGraphStrategy::new().find_usages(
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

    let result = brokk_bifrost::usages::RustExportUsageGraphStrategy::new().find_usages(
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

    let result = brokk_bifrost::usages::RustExportUsageGraphStrategy::new().find_usages(
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
fn private_same_file_function_without_call_produces_no_hit() {
    let (_project, analyzer) = rust_analyzer_with_files(&[(
        "src/searchtools.rs",
        r#"
fn summarize_symbol_targets() {}

pub fn get_summaries() {}
"#,
    )]);

    let target = definition(&analyzer, "searchtools.summarize_symbol_targets");
    let result = brokk_bifrost::usages::RustExportUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &std::collections::HashSet::default(),
        1000,
    );
    assert!(result.into_either().expect("no-call success").is_empty());
}

#[test]
fn local_binding_shadows_private_same_file_function() {
    let (_project, analyzer) = rust_analyzer_with_files(&[(
        "src/searchtools.rs",
        r#"
fn summarize_symbol_targets() {}

pub fn get_summaries() {
    let summarize_symbol_targets = 1;
    let _ = summarize_symbol_targets;
}
"#,
    )]);

    let target = definition(&analyzer, "searchtools.summarize_symbol_targets");
    let result = brokk_bifrost::usages::RustExportUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &std::collections::HashSet::default(),
        1000,
    );
    assert!(
        result
            .into_either()
            .expect("shadowed same-file success")
            .is_empty()
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

fn member(
    analyzer: &RustAnalyzer,
    file: &ProjectFile,
    owner_name: &str,
    member_name: &str,
) -> CodeUnit {
    analyzer
        .exact_member(file, owner_name, member_name, true)
        .or_else(|| analyzer.exact_member(file, owner_name, member_name, false))
        .unwrap_or_else(|| panic!("missing member {owner_name}.{member_name}"))
}

fn authoritative_hits(
    analyzer: &RustAnalyzer,
    target: &CodeUnit,
    files: HashSet<ProjectFile>,
) -> BTreeSet<UsageHit> {
    let provider = ExplicitCandidateProvider::new(Arc::new(files));
    match UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(
            analyzer,
            std::slice::from_ref(target),
            Some(&provider),
            100,
            100,
        )
        .result
    {
        FuzzyResult::Success {
            hits_by_overload, ..
        } => hits_by_overload
            .into_values()
            .flat_map(BTreeSet::into_iter)
            .collect(),
        other => panic!("expected authoritative Rust usage success, got {other:#?}"),
    }
}

#[test]
fn authoritative_rust_usage_finds_bare_types_imported_from_private_file_module() {
    let (project, analyzer) = rust_analyzer_with_files(&[
        ("crates/cli/src/lib.rs", "mod ux;\nmod analyze;\n"),
        ("crates/cli/src/ux.rs", "pub struct CheckResult;\n"),
        (
            "crates/cli/src/analyze.rs",
            r#"
use crate::ux::CheckResult;

fn group_checks(first: &CheckResult, rest: Vec<CheckResult>) {}
"#,
        ),
    ]);
    let target = definition(&analyzer, "crates.cli.src.ux.CheckResult");
    let analyze = project.file("crates/cli/src/analyze.rs");

    let hits = authoritative_hits(&analyzer, &target, [analyze.clone()].into_iter().collect());
    let references: Vec<_> = hits
        .iter()
        .filter(|hit| hit.kind == UsageHitKind::Reference)
        .collect();

    assert_eq!(
        2,
        references.len(),
        "expected both imported bare type annotations: {hits:#?}"
    );
    assert!(references.iter().all(|hit| hit.file == analyze));
}

fn assert_capital_self_reference_hits(
    result: &FuzzyResult,
    file: &ProjectFile,
    expected_token_hits: usize,
) {
    let external_hits = result.all_hits();
    let editor_hits = result.all_hits_including_imports();
    let source = file.read_to_string().expect("read self-reference fixture");
    for (surface, hits) in [("external", external_hits), ("editor", editor_hits)] {
        let self_hits: Vec<_> = hits
            .iter()
            .filter(|hit| &hit.file == file && "Self" == &source[hit.start_offset..hit.end_offset])
            .collect();
        assert_eq!(
            expected_token_hits,
            self_hits.len(),
            "capital-Self hits on {surface} surface: {hits:#?}"
        );
        assert!(
            self_hits
                .iter()
                .all(|hit| hit.kind == UsageHitKind::Reference),
            "capital Self must be an ordinary type reference: {hits:#?}"
        );
    }
}

fn assert_lowercase_self_receiver_omitted(result: &FuzzyResult, file: &ProjectFile) {
    let source = file.read_to_string().expect("read self-reference fixture");
    for (surface, hits) in [
        ("external", result.all_hits()),
        ("editor", result.all_hits_including_imports()),
    ] {
        assert!(
            hits.iter()
                .all(|hit| "self" != &source[hit.start_offset..hit.end_offset]),
            "lowercase self is not a type reference on the {surface} surface: {hits:#?}"
        );
    }
}

#[test]
fn rust_class_usage_records_bare_self_as_type_reference() {
    let (project, analyzer) = rust_analyzer_with_files(&[(
        "src/service.rs",
        r#"
pub struct Service {}

impl Service {
    fn same_type() -> Self {
        Self {}
    }
}
"#,
    )]);
    let file = project.file("src/service.rs");
    let target = definition(&analyzer, "service.Service");

    let result = UsageFinder::new().find_usages_default(&analyzer, &[target]);

    assert_capital_self_reference_hits(&result, &file, 2);
}

#[test]
fn rust_class_usage_records_self_path_owner_as_type_reference() {
    let (project, analyzer) = rust_analyzer_with_files(&[(
        "src/service.rs",
        r#"
pub struct Service;

impl Service {
    fn make() {}

    fn caller() {
        Self::make();
    }
}
"#,
    )]);
    let file = project.file("src/service.rs");
    let target = definition(&analyzer, "service.Service");

    let result = UsageFinder::new().find_usages_default(&analyzer, &[target]);

    assert_capital_self_reference_hits(&result, &file, 1);
}

#[test]
fn rust_class_usage_omits_lowercase_self_receiver() {
    let (project, analyzer) = rust_analyzer_with_files(&[(
        "src/service.rs",
        r#"
pub struct Service {
    value: usize,
}

impl Service {
    fn read(&self) -> usize {
        self.value
    }
}
"#,
    )]);
    let file = project.file("src/service.rs");
    let target = definition(&analyzer, "service.Service");

    let result = UsageFinder::new().find_usages_default(&analyzer, &[target]);

    assert_lowercase_self_receiver_omitted(&result, &file);
}

#[test]
fn rust_class_self_hits_require_the_matching_impl_owner() {
    let source = r#"
pub struct Service {
    value: usize,
}

pub struct Other {
    value: usize,
}

impl Service {
    fn copy(&self) -> Self {
        let _ = self.value;
        Self { value: 0 }
    }
}

impl Other {
    fn copy(&self) -> Self {
        let _ = self.value;
        Self { value: 0 }
    }
}
"#;
    let (project, analyzer) = rust_analyzer_with_files(&[("src/service.rs", source)]);
    let file = project.file("src/service.rs");
    let target = definition(&analyzer, "service.Service");

    let result = UsageFinder::new().find_usages_default(&analyzer, &[target]);

    assert_capital_self_reference_hits(&result, &file, 2);
    assert_lowercase_self_receiver_omitted(&result, &file);
    let editor_hits = result.all_hits_including_imports();
    let service_hits: Vec<_> = editor_hits
        .iter()
        .filter(|hit| "Self" == &source[hit.start_offset..hit.end_offset])
        .collect();
    let other_impl = source.find("impl Other").expect("Other impl");
    assert!(
        service_hits.iter().all(|hit| hit.start_offset < other_impl),
        "unrelated Other impl must not contribute self hits: {editor_hits:#?}"
    );
}

#[test]
fn authoritative_rust_usage_finds_enum_variant_through_self() {
    let (project, analyzer) = rust_analyzer_with_files(&[(
        "src/status.rs",
        r#"
pub enum Status {
    Ready,
}

impl Status {
    fn current() -> Self {
        Self::Ready
    }
}
"#,
    )]);
    let file = project.file("src/status.rs");
    let target = member(&analyzer, &file, "Status", "Ready");

    let hits = authoritative_hits(&analyzer, &target, [file.clone()].into_iter().collect());

    assert_eq!(
        1,
        hits.len(),
        "expected terminal Self::Ready hit: {hits:#?}"
    );
    assert!(hits.iter().all(|hit| hit.file == file));
    assert!(hits.iter().all(|hit| hit.snippet.contains("Self::Ready")));
}

#[test]
fn authoritative_rust_field_initializers_are_not_routed_to_same_named_trait_methods() {
    let source = r#"
pub trait Link {
    fn pointers(&self) -> usize;
}

pub struct Waiter {
    pub pointers: usize,
}

impl Link for Waiter {
    fn pointers(&self) -> usize {
        self.pointers
    }
}

impl Waiter {
    fn from_self(pointers: usize) -> Self {
        Self { pointers }
    }
}

fn from_explicit(pointers: usize) -> Waiter {
    Waiter { pointers }
}

fn call_trait_method(waiter: &impl Link) -> usize {
    waiter.pointers()
}
"#;
    let (project, analyzer) = rust_analyzer_with_files(&[("src/model.rs", source)]);
    let file = project.file("src/model.rs");
    let target = analyzer
        .get_definitions("model.Waiter.pointers")
        .into_iter()
        .find(|candidate| candidate.is_field() && !analyzer.is_type_alias(candidate))
        .expect("Waiter.pointers field");

    let hits = authoritative_hits(&analyzer, &target, [file].into_iter().collect());
    let expected: Vec<_> = ["Self { pointers }", "Waiter { pointers }"]
        .into_iter()
        .map(|initializer| {
            source.find(initializer).expect("field initializer")
                + initializer.find("pointers").expect("initializer field")
        })
        .collect();
    let trait_call = source
        .find("waiter.pointers()")
        .expect("same-named trait method call")
        + "waiter.".len();

    for start in expected {
        assert!(
            hits.iter()
                .any(|hit| (hit.start_offset, hit.end_offset) == (start, start + "pointers".len())),
            "explicit-owner and Self initializers must resolve to the struct field: {hits:#?}"
        );
    }
    assert!(
        hits.iter()
            .all(|hit| (hit.start_offset, hit.end_offset)
                != (trait_call, trait_call + "pointers".len())),
        "same-named trait method calls must not resolve to the struct field: {hits:#?}"
    );
}

#[test]
fn authoritative_rust_enum_variants_are_not_routed_to_same_named_trait_methods() {
    let source = r#"
#[allow(non_snake_case)]
pub trait Transition {
    fn Ready(&self) -> bool;
}

pub enum Status {
    Ready,
}

#[allow(non_snake_case)]
impl Transition for Status {
    fn Ready(&self) -> bool {
        true
    }
}

impl Status {
    fn from_self() -> Self {
        Self::Ready
    }
}

fn from_explicit() -> Status {
    Status::Ready
}

fn call_trait_method(status: &impl Transition) -> bool {
    status.Ready()
}
"#;
    let (project, analyzer) = rust_analyzer_with_files(&[("src/model.rs", source)]);
    let file = project.file("src/model.rs");
    let target = analyzer
        .get_definitions("model.Status.Ready")
        .into_iter()
        .find(|candidate| candidate.is_field())
        .expect("Status::Ready variant");

    let hits = authoritative_hits(&analyzer, &target, [file].into_iter().collect());
    let expected: Vec<_> = ["Self::Ready", "Status::Ready"]
        .into_iter()
        .map(|expression| {
            source.find(expression).expect("variant expression")
                + expression.find("Ready").expect("variant name")
        })
        .collect();
    let trait_call = source
        .find("status.Ready()")
        .expect("same-named trait method call")
        + "status.".len();

    for start in expected {
        assert!(
            hits.iter()
                .any(|hit| (hit.start_offset, hit.end_offset) == (start, start + "Ready".len())),
            "explicit-owner and Self variant expressions must preserve enum identity: {hits:#?}"
        );
    }
    assert!(
        hits.iter()
            .all(|hit| (hit.start_offset, hit.end_offset)
                != (trait_call, trait_call + "Ready".len())),
        "same-named trait method calls must not resolve to the enum variant: {hits:#?}"
    );
}

#[test]
fn authoritative_rust_usage_finds_private_self_associated_method() {
    let (project, analyzer) = rust_analyzer_with_files(&[(
        "src/service.rs",
        r#"
pub struct Service;

impl Service {
    fn target() {}

    fn caller() {
        Self::target();
    }
}
"#,
    )]);
    let file = project.file("src/service.rs");
    let target = member(&analyzer, &file, "Service", "target");

    let hits = authoritative_hits(&analyzer, &target, [file.clone()].into_iter().collect());

    assert_eq!(
        1,
        hits.len(),
        "expected terminal Self::target hit: {hits:#?}"
    );
    assert!(hits.iter().all(|hit| hit.file == file));
    assert!(hits.iter().all(|hit| hit.snippet.contains("Self::target")));
}

#[test]
fn authoritative_rust_usage_finds_private_field_in_macro_tokens() {
    let (project, analyzer) = rust_analyzer_with_files(&[(
        "src/service.rs",
        r#"
macro_rules! capture {
    ($($tokens:tt)*) => {};
}

pub struct Service {
    secret: usize,
}

impl Service {
    fn caller(&self) {
        capture!(self.secret);
    }
}
"#,
    )]);
    let file = project.file("src/service.rs");
    let target = member(&analyzer, &file, "Service", "secret");

    let hits = authoritative_hits(&analyzer, &target, [file.clone()].into_iter().collect());

    assert_eq!(1, hits.len(), "private macro field hits: {hits:#?}");
    assert!(hits.iter().all(|hit| hit.file == file));
    assert!(hits.iter().all(|hit| hit.snippet.contains("self.secret")));
}

#[test]
fn authoritative_rust_usage_resolves_every_qualified_macro_path_segment() {
    let lib_source = r#"
pub mod wanted;
pub mod decoy;

macro_rules! define_calls {
    () => {{
        $crate::wanted::free();
        $crate::wanted::Owner::assoc();
    }};
}

macro_rules! consume { ($($tokens:tt)*) => {}; }

pub fn invoke() {
    consume!(wanted::free());
    consume!({ wanted::Owner::assoc(); });
    consume!((wanted::Alias));
    consume!({ decoy::free(); });
    consume!({ decoy::Owner::assoc(); });
    consume!((decoy::Alias));
}
"#;
    let owner_source = r#"
pub struct Owner;
pub type Alias = Owner;
impl Owner { pub fn assoc() {} }
pub fn free() {}
"#;
    let (project, analyzer) = rust_analyzer_with_files(&[
        ("src/lib.rs", lib_source),
        ("src/wanted.rs", owner_source),
        ("src/decoy.rs", owner_source),
    ]);
    let file = project.file("src/lib.rs");

    for (target_fqn, expected, required_snippets) in [
        (
            "wanted",
            5,
            vec!["$crate::wanted::free", "consume!(wanted::free())"],
        ),
        (
            "wanted.Owner",
            2,
            vec!["$crate::wanted::Owner::assoc", "wanted::Owner::assoc"],
        ),
        ("wanted.Alias", 1, vec!["wanted::Alias"]),
        (
            "wanted.free",
            2,
            vec!["$crate::wanted::free", "consume!(wanted::free())"],
        ),
        (
            "wanted.Owner.assoc",
            2,
            vec!["$crate::wanted::Owner::assoc", "wanted::Owner::assoc"],
        ),
    ] {
        let target = definition(&analyzer, target_fqn);
        let hits = authoritative_hits(
            &analyzer,
            &target,
            analyzer.get_analyzed_files().into_iter().collect(),
        );
        let macro_hits: Vec<_> = hits.iter().filter(|hit| hit.file == file).collect();
        assert_eq!(expected, macro_hits.len(), "{target_fqn} hits: {hits:#?}");
        for snippet in required_snippets {
            assert!(
                macro_hits.iter().any(|hit| hit.snippet.contains(snippet)),
                "{target_fqn} should include `{snippet}`: {hits:#?}"
            );
        }
        let expected_segment = target_fqn
            .rsplit('.')
            .next()
            .expect("qualified target terminal");
        assert!(
            macro_hits.iter().all(|hit| {
                lib_source.get(hit.start_offset..hit.end_offset) == Some(expected_segment)
            }),
            "{target_fqn} must retain its exact segment ranges: {hits:#?}"
        );
    }
}

#[test]
fn authoritative_rust_private_members_respect_candidate_scope_and_owner_identity() {
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/lib.rs",
            r#"
pub struct Service {
    secret: usize,
}

pub mod child;
mod other;

impl Service {
    fn hidden(&self) {}
}
"#,
        ),
        (
            "src/child.rs",
            r#"
use crate::Service;

fn caller(service: &Service) {
    let _ = service.secret;
    service.hidden();
}
"#,
        ),
        (
            "src/other.rs",
            r#"
pub struct Service {
    secret: usize,
}

impl Service {
    fn hidden(&self) {
        let _ = self.secret;
    }
}
"#,
        ),
    ]);
    let service = project.file("src/lib.rs");
    let child = project.file("src/child.rs");
    let other = project.file("src/other.rs");
    let field = member(&analyzer, &service, "Service", "secret");
    let method = member(&analyzer, &service, "Service", "hidden");

    let field_hits = authoritative_hits(
        &analyzer,
        &field,
        [child.clone(), other.clone()].into_iter().collect(),
    );
    assert_eq!(1, field_hits.len(), "private field hits: {field_hits:#?}");
    assert!(field_hits.iter().all(|hit| hit.file == child));

    let method_hits = authoritative_hits(
        &analyzer,
        &method,
        [child.clone(), other.clone()].into_iter().collect(),
    );
    assert_eq!(
        1,
        method_hits.len(),
        "private method hits: {method_hits:#?}"
    );
    assert!(method_hits.iter().all(|hit| hit.file == child));
    assert!(
        method_hits
            .iter()
            .all(|hit| hit.kind == UsageHitKind::Reference)
    );

    assert!(
        authoritative_hits(&analyzer, &field, [other.clone()].into_iter().collect()).is_empty(),
        "same-named unrelated owner must not match the private field"
    );
    assert!(
        authoritative_hits(&analyzer, &method, [other].into_iter().collect()).is_empty(),
        "same-named unrelated owner must not match the private method"
    );
}

#[test]
fn rust_self_receiver_is_editor_only_member_usage() {
    let (project, analyzer) = rust_analyzer_with_files(&[(
        "src/service.rs",
        r#"
pub struct Foo;
impl Foo {
    pub fn target(&self) {}
    pub fn caller(&self) {
        self.target();
    }
}
"#,
    )]);

    let target = member(&analyzer, &project.file("src/service.rs"), "Foo", "target");
    let result = UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&target));

    assert!(
        result.all_hits().is_empty(),
        "scan_usages/external surface must not count self-receiver hits: {:?}",
        result.all_hits()
    );
    let editor_hits = result.all_hits_including_imports();
    assert_eq!(1, editor_hits.len(), "editor hits: {editor_hits:?}");
    assert!(
        editor_hits
            .iter()
            .all(|hit| hit.snippet.contains("self.target"))
    );
}

#[test]
fn rust_self_receiver_hits_do_not_trigger_external_usage_cap() {
    let (project, analyzer) = rust_analyzer_with_files(&[(
        "src/service.rs",
        r#"
pub struct Foo;
impl Foo {
    pub fn target(&self) {}
    pub fn caller(&self) {
        self.target();
        self.target();
    }
}
"#,
    )]);

    let target = member(&analyzer, &project.file("src/service.rs"), "Foo", "target");
    let result = UsageFinder::new()
        .query(&analyzer, std::slice::from_ref(&target), 1000, 0)
        .result;

    assert!(
        !matches!(result, FuzzyResult::TooManyCallsites { .. }),
        "self-receiver hits are editor-visible but must not count against the external usage cap: {result:?}"
    );
    assert!(result.all_hits().is_empty(), "result: {result:?}");
    assert_eq!(2, result.all_hits_including_imports().len());
}

#[test]
fn rust_seedless_local_external_hits_still_enforce_usage_cap() {
    let (project, analyzer) = rust_analyzer_with_files(&[(
        "src/service.rs",
        r#"
pub struct Foo;
impl Foo {
    pub fn target(&self) {}
}

fn caller(foo: Foo) {
    foo.target();
    foo.target();
}
"#,
    )]);

    let target = member(&analyzer, &project.file("src/service.rs"), "Foo", "target");
    let result = UsageFinder::new()
        .query(&analyzer, std::slice::from_ref(&target), 1000, 1)
        .result;

    match result {
        FuzzyResult::TooManyCallsites {
            total_callsites,
            limit,
            ..
        } => {
            assert_eq!(2, total_callsites);
            assert_eq!(1, limit);
        }
        other => panic!("expected seedless local external hits to enforce cap, got {other:?}"),
    }
}

#[test]
fn usage_finder_routes_rust_member_targets_through_graph() {
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/service.rs",
            r#"
pub struct Service;
impl Service {
    pub fn run(&self) {}
}
"#,
        ),
        (
            "src/main.rs",
            r#"
use crate::service::Service;

fn main() {
    let service: Service = Service {};
    service.run();
}
"#,
        ),
    ]);

    let target = member(&analyzer, &project.file("src/service.rs"), "Service", "run");
    let hits = UsageFinder::new()
        .find_usages_default(&analyzer, std::slice::from_ref(&target))
        .into_either()
        .expect("expected member graph success");
    assert_eq!(1, hits.len());
    assert!(
        hits.iter()
            .all(|hit| hit.file == project.file("src/main.rs"))
    );
}

#[test]
fn rust_exact_member_lookup_is_stable_across_repeated_calls() {
    let (project, analyzer) = rust_analyzer_with_files(&[(
        "src/service.rs",
        r#"
pub struct Service;
impl Service {
    pub fn run(&self) {}
}
"#,
    )]);

    let file = project.file("src/service.rs");
    let first = analyzer
        .exact_member(&file, "Service", "run", true)
        .expect("first member");
    let second = analyzer
        .exact_member(&file, "Service", "run", true)
        .expect("second member");

    assert_eq!(first, second);
    assert!(!first.is_synthetic());
}

#[test]
fn rust_member_candidate_funnel_keeps_likely_files_and_drops_unrelated_ones() {
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/service.rs",
            r#"
pub struct Service;
impl Service {
    pub fn run(&self) {}
}
"#,
        ),
        (
            "src/main.rs",
            r#"
use crate::service::Service;
fn main() {
    let service: Service = Service {};
    service.run();
}
"#,
        ),
        (
            "src/other.rs",
            r#"
fn unrelated() {
    let value = 1;
}
"#,
        ),
    ]);

    let target = member(&analyzer, &project.file("src/service.rs"), "Service", "run");
    let candidates =
        analyzer.rust_usage_candidate_files(["Service".to_string()].into_iter().collect(), &target);

    assert!(candidates.contains(&project.file("src/main.rs")));
    assert!(!candidates.contains(&project.file("src/other.rs")));
}

#[test]
fn rust_graph_strategy_resolves_typed_receiver_instance_method() {
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/service.rs",
            r#"
pub struct Foo;
impl Foo {
    pub fn bar(&self) {}
}
"#,
        ),
        (
            "src/main.rs",
            r#"
use crate::service::Foo;

fn run(x: Foo) {
    let y: Foo = x;
    y.bar();
}
"#,
        ),
    ]);

    let target = member(&analyzer, &project.file("src/service.rs"), "Foo", "bar");
    let hits = brokk_bifrost::usages::RustExportUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&target),
            &analyzer.get_analyzed_files().into_iter().collect(),
            1000,
        )
        .into_either()
        .expect("typed receiver success");
    assert_eq!(1, hits.len());
}

#[test]
fn rust_graph_strategy_resolves_constructor_and_alias_receivers() {
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/service.rs",
            r#"
pub struct Foo;
impl Foo {
    pub fn new() -> Foo { Foo }
    pub fn bar(&self) {}
}
"#,
        ),
        (
            "src/main.rs",
            r#"
use crate::service::Foo;

fn run() {
    let a = Foo::new();
    a.bar();
    let b = Foo {};
    b.bar();
    let c = a;
    c.bar();
}
"#,
        ),
    ]);

    let target = member(&analyzer, &project.file("src/service.rs"), "Foo", "bar");
    let hits = brokk_bifrost::usages::RustExportUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&target),
            &analyzer.get_analyzed_files().into_iter().collect(),
            1000,
        )
        .into_either()
        .expect("constructor receiver success");
    assert_eq!(3, hits.len());
}

#[test]
fn rust_graph_strategy_resolves_ast_constructor_return_shapes() {
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/models.rs",
            r#"
pub struct MemoryRepository;
pub struct Error;

impl MemoryRepository {
    pub fn new() -> Self { Self }
    pub fn scoped() -> crate::models::MemoryRepository { MemoryRepository }
    pub fn boxed() -> Box<Self> { Box::new(Self) }
    pub fn maybe() -> Option<Self> { Some(Self) }
    pub fn fallible() -> Result<Self, Error> { Ok(Self) }
    pub fn many() -> Vec<Self> { vec![Self] }
    pub fn save(&self) {}
}
"#,
        ),
        (
            "src/main.rs",
            r#"
use crate::models::MemoryRepository;

fn run() {
    let direct = MemoryRepository::new();
    direct.save();

    let scoped = MemoryRepository::scoped();
    scoped.save();

    let boxed = MemoryRepository::boxed();
    boxed.save();

    let maybe = MemoryRepository::maybe().unwrap();
    maybe.save();

    let fallible = MemoryRepository::fallible().expect("repository");
    fallible.save();

    let many = MemoryRepository::many();
    many.save();
}
"#,
        ),
    ]);

    let target = member(
        &analyzer,
        &project.file("src/models.rs"),
        "MemoryRepository",
        "save",
    );
    let hits = brokk_bifrost::usages::RustExportUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&target),
            &analyzer.get_analyzed_files().into_iter().collect(),
            1000,
        )
        .into_either()
        .expect("AST constructor return receiver success");
    assert_eq!(5, hits.len());
}

#[test]
fn rust_graph_strategy_resolves_multiline_constructor_receiver() {
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/service.rs",
            r#"
pub struct Foo;
impl Foo {
    pub fn new() -> Foo { Foo }
    pub fn bar(&self) {}
}
"#,
        ),
        (
            "src/main.rs",
            r#"
use crate::service::Foo;

fn run() {
    let a = Foo::new(
    );
    a.bar();
}
"#,
        ),
    ]);

    let target = member(&analyzer, &project.file("src/service.rs"), "Foo", "bar");
    let hits = brokk_bifrost::usages::RustExportUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&target),
            &analyzer.get_analyzed_files().into_iter().collect(),
            1000,
        )
        .into_either()
        .expect("multiline constructor receiver success");
    assert_eq!(1, hits.len());
}

#[test]
fn rust_graph_strategy_resolves_associated_method_and_const_without_receiver_inference() {
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/service.rs",
            r#"
pub struct Foo;
impl Foo {
    pub const CONST: usize = 1;
    pub fn make() -> Foo { Foo }
}
"#,
        ),
        (
            "src/main.rs",
            r#"
use crate::service::Foo;

fn run() {
    let _ = Foo::make();
    let _ = Foo::CONST;
}
"#,
        ),
    ]);

    let make = member(&analyzer, &project.file("src/service.rs"), "Foo", "make");
    let constant = member(&analyzer, &project.file("src/service.rs"), "Foo", "CONST");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let strategy = brokk_bifrost::usages::RustExportUsageGraphStrategy::new();

    assert_eq!(
        1,
        strategy
            .find_usages(&analyzer, std::slice::from_ref(&make), &candidates, 1000)
            .into_either()
            .expect("associated make success")
            .len()
    );
    assert_eq!(
        1,
        strategy
            .find_usages(
                &analyzer,
                std::slice::from_ref(&constant),
                &candidates,
                1000
            )
            .into_either()
            .expect("associated const success")
            .len()
    );
}

#[test]
fn rust_graph_counts_static_qualifier_references_for_struct_targets() {
    let (_project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/service.rs",
            r#"
pub struct Foo;
impl Foo {
    pub const CONST: usize = 1;
    pub fn assoc_fn() -> Foo { Foo }
}
"#,
        ),
        (
            "src/main.rs",
            r#"
use crate::service::Foo;

fn run() {
    let _ = Foo::assoc_fn();
    let _ = Foo::CONST;
}
"#,
        ),
    ]);

    let target = definition(&analyzer, "service.Foo");
    let hits = rust_graph_hits(&analyzer, &target.fq_name());

    assert!(
        hits.iter()
            .any(|hit| hit.snippet.contains("Foo::assoc_fn()")),
        "expected associated function qualifier hit: {hits:#?}"
    );
    assert!(
        hits.iter().any(|hit| hit.snippet.contains("Foo::CONST")),
        "expected associated const qualifier hit: {hits:#?}"
    );
}

#[test]
fn rust_graph_strategy_resolves_ufcs_trait_method_through_implementer() {
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/contracts.rs",
            r#"
pub trait Trait {
    fn frobnicate();
}
"#,
        ),
        (
            "src/service.rs",
            r#"
use crate::contracts::Trait;

pub struct Foo;
impl Trait for Foo {}
"#,
        ),
        (
            "src/main.rs",
            r#"
use crate::contracts::Trait;
use crate::service::Foo;

fn run() {
    Foo::frobnicate();
}
"#,
        ),
    ]);

    let target = member(
        &analyzer,
        &project.file("src/contracts.rs"),
        "Trait",
        "frobnicate",
    );
    let hits = brokk_bifrost::usages::RustExportUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&target),
            &analyzer.get_analyzed_files().into_iter().collect(),
            1000,
        )
        .into_either()
        .expect("UFCS trait method success");

    assert_eq!(1, hits.len(), "hits: {hits:?}");
    assert!(
        hits.iter()
            .all(|hit| hit.file == project.file("src/main.rs"))
    );
}

#[test]
fn rust_graph_strategy_resolves_trait_ufcs_through_barrel_reexport() {
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/service.rs",
            r#"
pub trait Worker {
    fn run(&self);
}

pub struct Local;

impl Worker for Local {
    fn run(&self) {}
}
"#,
        ),
        (
            "src/facade.rs",
            r#"
pub use crate::service::{Local, Worker};

pub type LocalAlias = Local;

pub fn build() -> Local { Local }
"#,
        ),
        (
            "src/lib.rs",
            r#"
mod service;
pub mod facade;

pub use facade::Worker;

pub fn consume() {
    let worker = facade::build();
    Worker::run(&worker);
    let other: facade::LocalAlias = facade::build();
    Worker::run(&other);
}
"#,
        ),
    ]);

    let run = member(&analyzer, &project.file("src/service.rs"), "Worker", "run");
    let worker = definition(&analyzer, "service.Worker");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let strategy = brokk_bifrost::usages::RustExportUsageGraphStrategy::new();

    let run_hits = strategy
        .find_usages(&analyzer, &[run], &candidates, 1000)
        .into_either()
        .expect("barrel-reexported trait method lookup should succeed");
    assert_eq!(
        2,
        run_hits
            .iter()
            .filter(|hit| hit.file == project.file("src/lib.rs"))
            .count(),
        "both Worker::run calls should resolve to the trait method: {run_hits:#?}"
    );
    assert!(
        run_hits.iter().all(
            |hit| hit.file != project.file("src/facade.rs") && !hit.snippet.contains("pub use")
        ),
        "import and re-export sites stay filtered: {run_hits:#?}"
    );

    let worker_hits = strategy
        .find_usages(&analyzer, &[worker], &candidates, 1000)
        .into_either()
        .expect("barrel-reexported trait qualifier lookup should succeed");
    assert_eq!(
        2,
        worker_hits
            .iter()
            .filter(|hit| {
                hit.file == project.file("src/lib.rs") && hit.snippet.contains("Worker::run")
            })
            .count(),
        "both UFCS qualifiers should resolve to the original trait: {worker_hits:#?}"
    );
    assert!(
        worker_hits.iter().all(
            |hit| hit.file != project.file("src/facade.rs") && !hit.snippet.contains("pub use")
        ),
        "import and re-export sites stay filtered: {worker_hits:#?}"
    );
}

#[test]
fn rust_graph_strategy_resolves_trait_ufcs_through_aliased_barrel_namespace() {
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/service.rs",
            "pub trait Worker { fn run(&self); }\npub struct Local;\nimpl Worker for Local { fn run(&self) {} }\n",
        ),
        (
            "src/facade.rs",
            "pub use crate::service::{Local, Worker};\npub fn build() -> Local { Local }\n",
        ),
        (
            "src/lib.rs",
            "mod service;\npub mod facade;\nuse crate::facade as api;\npub fn consume() { let worker = api::build(); api::Worker::run(&worker); }\n",
        ),
    ]);
    let run = member(&analyzer, &project.file("src/service.rs"), "Worker", "run");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let hits = brokk_bifrost::usages::RustExportUsageGraphStrategy::new()
        .find_usages(&analyzer, &[run], &candidates, 1000)
        .into_either()
        .expect("aliased barrel UFCS lookup should succeed");

    assert_eq!(
        vec![4],
        hits.iter()
            .filter(|hit| hit.file == project.file("src/lib.rs"))
            .map(|hit| hit.line)
            .collect::<Vec<_>>(),
        "the aliased namespace call should resolve through the barrel: {hits:#?}"
    );
}

#[test]
fn rust_graph_strategy_prefers_local_declaration_over_glob_reexport() {
    let (project, analyzer) = rust_analyzer_with_files(&[
        ("src/service.rs", "pub trait Worker { fn run(); }\n"),
        ("src/facade.rs", "pub use crate::service::Worker;\n"),
        (
            "src/lib.rs",
            "mod service;\nmod facade;\nuse crate::facade::*;\nstruct Worker;\nimpl Worker { fn run() {} }\nfn consume() { Worker::run(); }\n",
        ),
    ]);
    let run = member(&analyzer, &project.file("src/service.rs"), "Worker", "run");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let hits = brokk_bifrost::usages::RustExportUsageGraphStrategy::new()
        .find_usages(&analyzer, &[run], &candidates, 1000)
        .into_either()
        .expect("shadowed glob lookup should complete");

    assert!(
        hits.iter()
            .all(|hit| hit.file != project.file("src/lib.rs")),
        "the local Worker must shadow the glob-reexported trait: {hits:#?}"
    );
}

#[test]
fn rust_graph_strategy_resolves_impl_side_trait_method_through_implementer_export() {
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/lib.rs",
            r#"
pub struct Bson;

impl From<i32> for Bson {
    fn from(_value: i32) -> Self {
        Bson
    }
}

pub mod caller;
"#,
        ),
        (
            "src/caller.rs",
            r#"
use crate::Bson;

pub fn make() {
    let _ = Bson::from(1);
}
"#,
        ),
    ]);

    let target = member(&analyzer, &project.file("src/lib.rs"), "Bson", "from");
    let hits = brokk_bifrost::usages::RustExportUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&target),
            &analyzer.get_analyzed_files().into_iter().collect(),
            1000,
        )
        .into_either()
        .expect("impl-side trait method success");

    assert_eq!(1, hits.len(), "hits: {hits:?}");
    assert!(
        hits.iter()
            .all(|hit| hit.file == project.file("src/caller.rs"))
    );
}

#[test]
fn rust_graph_strategy_resolves_ufcs_trait_method_through_module_qualified_implementer() {
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/service.rs",
            r#"
pub trait Trait {
    fn frobnicate();
}

pub struct Foo;
impl Trait for Foo {}
"#,
        ),
        (
            "src/main.rs",
            r#"
use crate::service::{self, Trait};

fn run() {
    service::Foo::frobnicate();
}
"#,
        ),
    ]);

    let target = member(
        &analyzer,
        &project.file("src/service.rs"),
        "Trait",
        "frobnicate",
    );
    let hits = brokk_bifrost::usages::RustExportUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&target),
            &analyzer.get_analyzed_files().into_iter().collect(),
            1000,
        )
        .into_either()
        .expect("module-qualified UFCS trait method success");

    assert_eq!(1, hits.len(), "hits: {hits:?}");
    assert!(
        hits.iter()
            .all(|hit| hit.file == project.file("src/main.rs"))
    );
}

#[test]
fn rust_graph_strategy_requires_visible_trait_for_ufcs_trait_method() {
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/service.rs",
            r#"
pub trait Trait {
    fn frobnicate();
}

pub struct Foo;
impl Trait for Foo {}
"#,
        ),
        (
            "src/main.rs",
            r#"
use crate::service;

fn run() {
    service::Foo::frobnicate();
}
"#,
        ),
    ]);

    let target = member(
        &analyzer,
        &project.file("src/service.rs"),
        "Trait",
        "frobnicate",
    );
    let hits = brokk_bifrost::usages::RustExportUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&target),
            &analyzer.get_analyzed_files().into_iter().collect(),
            1000,
        )
        .into_either()
        .expect("non-visible UFCS trait method success");

    assert!(hits.is_empty(), "hits: {hits:?}");
}

#[test]
fn rust_graph_strategy_prefers_inherent_static_method_over_trait_method() {
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/service.rs",
            r#"
pub trait Trait {
    fn frobnicate();
}

pub struct Foo;
impl Foo {
    pub fn frobnicate() {}
}
impl Trait for Foo {}
"#,
        ),
        (
            "src/main.rs",
            r#"
use crate::service::Trait;
use crate::service::Foo;

fn run() {
    Foo::frobnicate();
}
"#,
        ),
    ]);

    let trait_method = member(
        &analyzer,
        &project.file("src/service.rs"),
        "Trait",
        "frobnicate",
    );
    let inherent_method = member(
        &analyzer,
        &project.file("src/service.rs"),
        "Foo",
        "frobnicate",
    );
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let strategy = brokk_bifrost::usages::RustExportUsageGraphStrategy::new();

    assert!(
        strategy
            .find_usages(
                &analyzer,
                std::slice::from_ref(&trait_method),
                &candidates,
                1000
            )
            .into_either()
            .expect("trait method success")
            .is_empty()
    );
    assert_eq!(
        1,
        strategy
            .find_usages(
                &analyzer,
                std::slice::from_ref(&inherent_method),
                &candidates,
                1000
            )
            .into_either()
            .expect("inherent method success")
            .len()
    );
}

#[test]
fn rust_graph_strategy_does_not_guess_ambiguous_ufcs_trait_method() {
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/contracts.rs",
            r#"
pub trait One {
    fn frobnicate();
}

pub trait Two {
    fn frobnicate();
}
"#,
        ),
        (
            "src/service.rs",
            r#"
use crate::contracts::{One, Two};

pub struct Foo;
impl One for Foo {}
impl Two for Foo {}
"#,
        ),
        (
            "src/main.rs",
            r#"
use crate::contracts::{One, Two};
use crate::service::Foo;

fn run() {
    Foo::frobnicate();
}
"#,
        ),
    ]);

    let one = member(
        &analyzer,
        &project.file("src/contracts.rs"),
        "One",
        "frobnicate",
    );
    let two = member(
        &analyzer,
        &project.file("src/contracts.rs"),
        "Two",
        "frobnicate",
    );
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let strategy = brokk_bifrost::usages::RustExportUsageGraphStrategy::new();

    assert!(
        strategy
            .find_usages(&analyzer, std::slice::from_ref(&one), &candidates, 1000)
            .into_either()
            .expect("ambiguous One success")
            .is_empty()
    );
    assert!(
        strategy
            .find_usages(&analyzer, std::slice::from_ref(&two), &candidates, 1000)
            .into_either()
            .expect("ambiguous Two success")
            .is_empty()
    );
}

#[test]
fn rust_graph_strategy_filters_ufcs_trait_candidates_by_visible_trait() {
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/contracts.rs",
            r#"
pub trait One {
    fn frobnicate();
}

pub trait Two {
    fn frobnicate();
}
"#,
        ),
        (
            "src/service.rs",
            r#"
use crate::contracts::{One, Two};

pub struct Foo;
impl One for Foo {}
impl Two for Foo {}
"#,
        ),
        (
            "src/main.rs",
            r#"
use crate::contracts::One;
use crate::service::Foo;

fn run() {
    Foo::frobnicate();
}
"#,
        ),
    ]);

    let one = member(
        &analyzer,
        &project.file("src/contracts.rs"),
        "One",
        "frobnicate",
    );
    let two = member(
        &analyzer,
        &project.file("src/contracts.rs"),
        "Two",
        "frobnicate",
    );
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let strategy = brokk_bifrost::usages::RustExportUsageGraphStrategy::new();

    assert_eq!(
        1,
        strategy
            .find_usages(&analyzer, std::slice::from_ref(&one), &candidates, 1000)
            .into_either()
            .expect("visible One success")
            .len()
    );
    assert!(
        strategy
            .find_usages(&analyzer, std::slice::from_ref(&two), &candidates, 1000)
            .into_either()
            .expect("hidden Two success")
            .is_empty()
    );
}

#[test]
fn rust_graph_strategy_resolves_comment_separated_member_references() {
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/service.rs",
            r#"
pub struct Foo;
impl Foo {
    pub const CONST: usize = 1;
    pub fn make() -> Foo { Foo }
    pub fn bar(&self) {}
}
"#,
        ),
        (
            "src/main.rs",
            r#"
use crate::service::Foo;

fn run(x: Foo) {
    x. /* member */ bar();
    let _ = Foo:: /* static */ make();
    let _ = Foo:: /* const */ CONST;
}
"#,
        ),
    ]);

    let bar = member(&analyzer, &project.file("src/service.rs"), "Foo", "bar");
    let make = member(&analyzer, &project.file("src/service.rs"), "Foo", "make");
    let constant = member(&analyzer, &project.file("src/service.rs"), "Foo", "CONST");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let strategy = brokk_bifrost::usages::RustExportUsageGraphStrategy::new();

    assert_eq!(
        1,
        strategy
            .find_usages(&analyzer, std::slice::from_ref(&bar), &candidates, 1000)
            .into_either()
            .expect("commented instance member success")
            .len()
    );
    assert_eq!(
        1,
        strategy
            .find_usages(&analyzer, std::slice::from_ref(&make), &candidates, 1000)
            .into_either()
            .expect("commented static method success")
            .len()
    );
    assert_eq!(
        1,
        strategy
            .find_usages(
                &analyzer,
                std::slice::from_ref(&constant),
                &candidates,
                1000
            )
            .into_either()
            .expect("commented static const success")
            .len()
    );
}

#[test]
fn rust_graph_strategy_finds_in_crate_member_usages_on_private_owner() {
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/service.rs",
            r#"
struct Foo;
impl Foo {
    pub fn public(&self) {}
}
"#,
        ),
        (
            "src/main.rs",
            r#"
use crate::service::Foo;

fn run(x: Foo) {
    x.public();
}
"#,
        ),
    ]);

    let target = member(&analyzer, &project.file("src/service.rs"), "Foo", "public");
    let hits = brokk_bifrost::usages::RustExportUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&target),
            &analyzer.get_analyzed_files().into_iter().collect(),
            1000,
        )
        .into_either();
    assert_eq!(1, hits.expect("private owner member local scan").len());
}

#[test]
fn rust_graph_strategy_does_not_cross_match_duplicate_owner_names() {
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/service.rs",
            r#"
pub struct Foo;
impl Foo {
    pub fn bar(&self) {}
}
"#,
        ),
        (
            "src/other.rs",
            r#"
pub struct Foo;
impl Foo {
    pub fn bar(&self) {}
}
"#,
        ),
        (
            "src/main.rs",
            r#"
use crate::service::Foo;

fn run() {
    let x: Foo = Foo {};
    x.bar();
}
"#,
        ),
    ]);

    let service_target = member(&analyzer, &project.file("src/service.rs"), "Foo", "bar");
    let other_target = member(&analyzer, &project.file("src/other.rs"), "Foo", "bar");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let strategy = brokk_bifrost::usages::RustExportUsageGraphStrategy::new();

    assert_eq!(
        1,
        strategy
            .find_usages(
                &analyzer,
                std::slice::from_ref(&service_target),
                &candidates,
                1000,
            )
            .into_either()
            .expect("service foo member success")
            .len()
    );
    assert!(
        strategy
            .find_usages(
                &analyzer,
                std::slice::from_ref(&other_target),
                &candidates,
                1000
            )
            .into_either()
            .expect("other foo member success")
            .is_empty()
    );
}

#[test]
fn rust_graph_strategy_uses_function_parameter_type_as_receiver_seed() {
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/service.rs",
            r#"
pub struct Foo;
impl Foo {
    pub fn bar(&self) {}
}
"#,
        ),
        (
            "src/main.rs",
            r#"
use crate::service::Foo;

fn run(x: Foo) {
    x.bar();
}
"#,
        ),
    ]);

    let target = member(&analyzer, &project.file("src/service.rs"), "Foo", "bar");
    let hits = brokk_bifrost::usages::RustExportUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&target),
            &analyzer.get_analyzed_files().into_iter().collect(),
            1000,
        )
        .into_either()
        .expect("parameter receiver success");
    assert_eq!(1, hits.len());
}

#[test]
fn rust_graph_strategy_finds_private_same_file_function_call_inside_closure() {
    let (_project, analyzer) = rust_analyzer_with_files(&[(
        "src/summary.rs",
        r#"
pub struct RenderedSummary;

pub fn summarize_inputs(inputs: &[String]) -> Result<Vec<RenderedSummary>, String> {
    inputs
        .iter()
        .map(|input| summarize_input(input))
        .collect()
}

fn summarize_input(input: &str) -> Result<RenderedSummary, String> {
    Ok(RenderedSummary)
}
"#,
    )]);

    let target = definition(&analyzer, "summary.summarize_input");
    let hits = brokk_bifrost::usages::RustExportUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&target),
            &std::collections::HashSet::default(),
            1000,
        )
        .into_either()
        .expect("closure private call success");
    assert_eq!(1, hits.len());
}

#[test]
fn rust_graph_strategy_does_not_cross_match_same_private_function_name_in_another_module() {
    let (_project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/a.rs",
            r#"
fn summarize_symbol_targets(targets: Vec<String>) -> SummaryResult {
    SummaryResult {}
}
"#,
        ),
        (
            "src/b.rs",
            r#"
fn summarize_symbol_targets(targets: Vec<String>) -> SummaryResult {
    SummaryResult {}
}

pub fn get_summaries(params: SummariesParams) -> SummaryResult {
    summarize_symbol_targets(params.targets)
}
"#,
        ),
    ]);

    let target = definition(&analyzer, "a.summarize_symbol_targets");
    let candidates = [ProjectFile::new(
        analyzer.project().root().to_path_buf(),
        "src/b.rs",
    )]
    .into_iter()
    .collect();

    let hits = brokk_bifrost::usages::RustExportUsageGraphStrategy::new()
        .find_usages(&analyzer, std::slice::from_ref(&target), &candidates, 1000)
        .into_either()
        .expect("cross-module private success");
    assert!(hits.is_empty());
}

#[test]
fn rust_graph_strategy_does_not_seed_pub_self_exports() {
    let (_project, analyzer) =
        rust_analyzer_with_files(&[("src/service.rs", "pub(self) struct Hidden;\n")]);
    let target = definition(&analyzer, "service.Hidden");
    let hits = brokk_bifrost::usages::RustExportUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&target),
            &analyzer.get_analyzed_files().into_iter().collect(),
            1000,
        )
        .into_either()
        .expect("pub(self) local declaration scan success");
    assert!(
        hits.is_empty(),
        "pub(self) item has no references: {hits:#?}"
    );
}

#[test]
fn rust_graph_strategy_keeps_pub_crate_exports_graph_visible() {
    let (_project, analyzer) = rust_analyzer_with_files(&[
        ("src/service.rs", "pub(crate) struct Local;\n"),
        (
            "src/main.rs",
            r#"
use crate::service::Local;

fn run() {
    let _ = Local {};
}
"#,
        ),
    ]);
    let target = definition(&analyzer, "service.Local");
    let hits = brokk_bifrost::usages::RustExportUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&target),
            &analyzer.get_analyzed_files().into_iter().collect(),
            1000,
        )
        .into_either()
        .expect("pub(crate) success");
    assert_eq!(1, hits.len());
}

#[test]
fn rust_graph_strategy_reads_visibility_from_tree_sitter_nodes() {
    let (_project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/service.rs",
            r#"
pub(in crate::service) struct Scoped;
pub/**/ struct CommentedPublic;
struct Private;
"#,
        ),
        (
            "src/main.rs",
            r#"
use crate::service::{CommentedPublic, Private, Scoped};

fn run() {
    let _ = Scoped {};
    let _ = CommentedPublic {};
    let _ = Private {};
}
"#,
        ),
    ]);
    let scoped = definition(&analyzer, "service.Scoped");
    let commented = definition(&analyzer, "service.CommentedPublic");
    let private = definition(&analyzer, "service.Private");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let strategy = brokk_bifrost::usages::RustExportUsageGraphStrategy::new();

    assert_eq!(
        1,
        strategy
            .find_usages(&analyzer, std::slice::from_ref(&scoped), &candidates, 1000)
            .into_either()
            .expect("scoped visibility success")
            .len()
    );
    assert_eq!(
        1,
        strategy
            .find_usages(
                &analyzer,
                std::slice::from_ref(&commented),
                &candidates,
                1000,
            )
            .into_either()
            .expect("commented pub visibility success")
            .len()
    );
    assert_eq!(
        1,
        strategy
            .find_usages(&analyzer, std::slice::from_ref(&private), &candidates, 1000)
            .into_either()
            .expect("private local declaration scan success")
            .len()
    );
}

#[test]
fn rust_graph_strategy_resolves_barrel_reexport_from_private_module() {
    let (_project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/lib.rs",
            r#"
mod service;
pub use service::Foo;
"#,
        ),
        ("src/service.rs", "pub struct Foo;\n"),
        (
            "src/main.rs",
            r#"
use crate::Foo;

fn run() {
    let _ = Foo {};
}
"#,
        ),
    ]);

    let target = definition(&analyzer, "service.Foo");
    let result = brokk_bifrost::usages::RustExportUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &analyzer.get_analyzed_files().into_iter().collect(),
        1000,
    );
    let hits = result.into_either().expect("barrel reexport success");
    assert_eq!(1, hits.len());
}

#[test]
fn rust_graph_strategy_does_not_treat_self_reexport_as_public_barrel() {
    let (_project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/lib.rs",
            r#"
mod service;
pub(self) use service::Foo;
"#,
        ),
        ("src/service.rs", "pub struct Foo;\n"),
        (
            "src/main.rs",
            r#"
use crate::Foo;

fn run() {
    let _ = Foo {};
}
"#,
        ),
    ]);

    let target = definition(&analyzer, "service.Foo");
    let result = brokk_bifrost::usages::RustExportUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &analyzer.get_analyzed_files().into_iter().collect(),
        1000,
    );
    let hits = result
        .into_either()
        .expect("pub(self) local declaration scan success");
    assert!(
        hits.iter().all(|hit| hit.file
            != ProjectFile::new(analyzer.project().root().to_path_buf(), "src/main.rs")),
        "pub(self) use must not expose Foo as a public barrel reexport: {hits:#?}"
    );
}

#[test]
fn rust_graph_strategy_resolves_chained_and_aliased_barrel_reexports() {
    let (_project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/service.rs",
            r#"
pub struct Foo;
pub struct Bar;
"#,
        ),
        (
            "src/first.rs",
            r#"
pub use crate::service::{Foo, Bar as PublicBar};
"#,
        ),
        (
            "src/second.rs",
            r#"
pub use crate::first::Foo;
pub use crate::first::PublicBar;
"#,
        ),
        (
            "src/main.rs",
            r#"
use crate::second::{Foo, PublicBar};

fn run() {
    let _ = Foo {};
    let _ = PublicBar {};
}
"#,
        ),
    ]);

    let foo = definition(&analyzer, "service.Foo");
    let bar = definition(&analyzer, "service.Bar");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let strategy = brokk_bifrost::usages::RustExportUsageGraphStrategy::new();

    assert_eq!(
        1,
        strategy
            .find_usages(&analyzer, std::slice::from_ref(&foo), &candidates, 1000)
            .into_either()
            .expect("chained Foo success")
            .len()
    );
    assert_eq!(
        1,
        strategy
            .find_usages(&analyzer, std::slice::from_ref(&bar), &candidates, 1000)
            .into_either()
            .expect("chained Bar success")
            .len()
    );
}

#[test]
fn rust_graph_strategy_uses_simple_type_alias_as_receiver_seed() {
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/service.rs",
            r#"
pub struct Foo;
impl Foo {
    pub fn bar(&self) {}
}
"#,
        ),
        (
            "src/main.rs",
            r#"
use crate::service::Foo;

type Alias = Foo;

fn run(value: Alias) {
    value.bar();
}
"#,
        ),
    ]);

    let target = member(&analyzer, &project.file("src/service.rs"), "Foo", "bar");
    let hits = brokk_bifrost::usages::RustExportUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&target),
            &analyzer.get_analyzed_files().into_iter().collect(),
            1000,
        )
        .into_either()
        .expect("type alias receiver success");
    assert_eq!(1, hits.len());
}

#[test]
fn rust_graph_strategy_uses_self_like_constructor_chain_as_receiver_seed() {
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/service.rs",
            r#"
pub struct ChangeDelta;
pub struct ProjectChangeWatcher;
impl ProjectChangeWatcher {
    pub fn start() -> Result<Self, String> {
        todo!()
    }
    pub fn other() -> ChangeDelta {
        todo!()
    }
    pub fn take_changed_files(&self) -> ChangeDelta {
        todo!()
    }
}
"#,
        ),
        (
            "src/main.rs",
            r#"
use crate::service::ProjectChangeWatcher;

fn run() {
    let watcher = ProjectChangeWatcher::start().unwrap();
    watcher.take_changed_files();
}

fn unrelated() {
    let delta = ProjectChangeWatcher::other();
    delta.take_changed_files();
}
"#,
        ),
    ]);

    let target = member(
        &analyzer,
        &project.file("src/service.rs"),
        "ProjectChangeWatcher",
        "take_changed_files",
    );
    let hits = brokk_bifrost::usages::RustExportUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&target),
            &analyzer.get_analyzed_files().into_iter().collect(),
            1000,
        )
        .into_either()
        .expect("self-like constructor success");
    assert_eq!(1, hits.len());
}

#[test]
fn rust_graph_strategy_resolves_bounded_glob_imports_for_public_exports_only() {
    let (_project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/service.rs",
            r#"
pub struct Foo;
struct Hidden;
"#,
        ),
        (
            "src/main.rs",
            r#"
use crate::service::*;

fn run() {
    let _ = Foo {};
    let _ = Hidden {};
}
"#,
        ),
    ]);

    let foo = definition(&analyzer, "service.Foo");
    let hidden = definition(&analyzer, "service.Hidden");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let strategy = brokk_bifrost::usages::RustExportUsageGraphStrategy::new();

    assert_eq!(
        1,
        strategy
            .find_usages(&analyzer, std::slice::from_ref(&foo), &candidates, 1000)
            .into_either()
            .expect("glob Foo success")
            .len()
    );
    let hidden_hits = strategy
        .find_usages(&analyzer, std::slice::from_ref(&hidden), &candidates, 1000)
        .into_either()
        .expect("private glob local declaration scan success");
    assert!(
        hidden_hits.is_empty(),
        "glob imports only bind public exports: {hidden_hits:#?}"
    );
}

#[test]
fn rust_graph_strategy_resolves_bounded_glob_reexports() {
    let (_project, analyzer) = rust_analyzer_with_files(&[
        ("src/service.rs", "pub struct Foo;\n"),
        ("src/index.rs", "pub use crate::service::*;\n"),
        (
            "src/main.rs",
            r#"
use crate::index::Foo;

fn run() {
    let _ = Foo {};
}
"#,
        ),
    ]);

    let foo = definition(&analyzer, "service.Foo");
    let hits = brokk_bifrost::usages::RustExportUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&foo),
            &analyzer.get_analyzed_files().into_iter().collect(),
            1000,
        )
        .into_either()
        .expect("glob reexport success");
    assert_eq!(1, hits.len());
}

#[test]
fn rust_graph_strategy_resolves_enum_variants_as_associated_fields() {
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/service.rs",
            r#"
pub enum Foo {
    Variant,
    TupleVariant(usize),
    StructVariant { value: usize },
}
"#,
        ),
        (
            "src/main.rs",
            r#"
use crate::service::Foo;

fn run() {
    let _ = Foo::Variant;
    let _ = Foo::TupleVariant(1);
    let _ = Foo::StructVariant { value: 1 };
}
"#,
        ),
    ]);

    let variant = member(&analyzer, &project.file("src/service.rs"), "Foo", "Variant");
    let tuple_variant = member(
        &analyzer,
        &project.file("src/service.rs"),
        "Foo",
        "TupleVariant",
    );
    let struct_variant = member(
        &analyzer,
        &project.file("src/service.rs"),
        "Foo",
        "StructVariant",
    );
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let strategy = brokk_bifrost::usages::RustExportUsageGraphStrategy::new();

    assert_eq!(
        1,
        strategy
            .find_usages(&analyzer, std::slice::from_ref(&variant), &candidates, 1000)
            .into_either()
            .expect("variant success")
            .len()
    );
    assert_eq!(
        1,
        strategy
            .find_usages(
                &analyzer,
                std::slice::from_ref(&tuple_variant),
                &candidates,
                1000,
            )
            .into_either()
            .expect("tuple variant success")
            .len()
    );
    assert_eq!(
        1,
        strategy
            .find_usages(
                &analyzer,
                std::slice::from_ref(&struct_variant),
                &candidates,
                1000,
            )
            .into_either()
            .expect("struct variant success")
            .len()
    );
}

#[test]
fn rust_graph_strategy_resolves_associated_type_as_static_field() {
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/service.rs",
            r#"
pub struct Foo;
impl Foo {
    pub type AssocType = usize;
}
"#,
        ),
        (
            "src/main.rs",
            r#"
use crate::service::Foo;

fn run(_: Foo::AssocType) {}
"#,
        ),
    ]);

    let assoc_type = member(
        &analyzer,
        &project.file("src/service.rs"),
        "Foo",
        "AssocType",
    );
    let hits = brokk_bifrost::usages::RustExportUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&assoc_type),
            &analyzer.get_analyzed_files().into_iter().collect(),
            1000,
        )
        .into_either()
        .expect("associated type success");
    assert_eq!(1, hits.len());
}

#[test]
fn rust_graph_strategy_does_not_resolve_private_item_behind_barrel_reexport() {
    let (_project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/lib.rs",
            r#"
mod service;
pub use service::Hidden;
"#,
        ),
        ("src/service.rs", "struct Hidden;\n"),
        (
            "src/main.rs",
            r#"
use crate::Hidden;

fn run() {
    let _ = Hidden {};
}
"#,
        ),
    ]);

    let target = definition(&analyzer, "service.Hidden");
    let result = brokk_bifrost::usages::RustExportUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &analyzer.get_analyzed_files().into_iter().collect(),
        1000,
    );
    let hits = result
        .into_either()
        .expect("private item behind reexport local scan success");
    assert!(
        hits.iter().all(|hit| hit.file
            != ProjectFile::new(analyzer.project().root().to_path_buf(), "src/main.rs")),
        "private item is not exposed as a public barrel reexport: {hits:#?}"
    );
}

#[test]
fn rust_graph_strategy_seeds_receiver_from_self_field_as_ref_let_else() {
    let (project, analyzer) = rust_analyzer_with_files(&[(
        "src/service.rs",
        r#"
pub struct ChangeDelta;
pub struct ProjectChangeWatcher;
impl ProjectChangeWatcher {
    pub fn take_changed_files(&self) -> ChangeDelta {
        todo!()
    }
}

pub struct SearchToolsService {
    watcher: Option<ProjectChangeWatcher>,
}
impl SearchToolsService {
    pub fn apply_watcher_delta(&mut self) {
        let Some(watcher) = self.watcher.as_ref() else {
            return;
        };
        watcher.take_changed_files();
    }
}
"#,
    )]);

    let target = member(
        &analyzer,
        &project.file("src/service.rs"),
        "ProjectChangeWatcher",
        "take_changed_files",
    );
    let hits = brokk_bifrost::usages::RustExportUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&target),
            &analyzer.get_analyzed_files().into_iter().collect(),
            1000,
        )
        .into_either()
        .expect("self field let-else success");
    assert_eq!(1, hits.len());
}

#[test]
fn rust_graph_strategy_does_not_seed_receiver_from_wrapped_pattern_destructuring() {
    let (project, analyzer) = rust_analyzer_with_files(&[(
        "src/service.rs",
        r#"
pub struct ProjectChangeWatcher;
impl ProjectChangeWatcher {
    pub fn take_changed_files(&self) {}
}

pub struct Other;
impl Other {
    pub fn take_changed_files(&self) {}
}

pub struct SearchToolsService {
    watcher: Option<(ProjectChangeWatcher, Other)>,
}
impl SearchToolsService {
    pub fn apply_watcher_delta(&mut self) {
        let Some((watcher, other)) = self.watcher.as_ref() else {
            return;
        };
        watcher.take_changed_files();
        other.take_changed_files();
    }
}
"#,
    )]);

    let target = member(
        &analyzer,
        &project.file("src/service.rs"),
        "ProjectChangeWatcher",
        "take_changed_files",
    );
    let hits = brokk_bifrost::usages::RustExportUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&target),
            &analyzer.get_analyzed_files().into_iter().collect(),
            1000,
        )
        .into_either()
        .expect("wrapped destructuring success");
    assert!(hits.is_empty());
}

#[test]
fn rust_graph_strategy_does_not_seed_receiver_from_tuple_destructuring_patterns() {
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/service.rs",
            r#"
pub struct Foo;
impl Foo {
    pub fn foo_method(&self) {}
}

pub struct Bar;
impl Bar {
    pub fn foo_method(&self) {}
}
"#,
        ),
        (
            "src/main.rs",
            r#"
use crate::service::{Bar, Foo};

fn tuple_parameter((foo, _bar): (Foo, Bar)) {
    foo.foo_method();
}

fn tuple_let(pair: (Foo, Bar)) {
    let (foo, _bar): (Foo, Bar) = pair;
    foo.foo_method();
}
"#,
        ),
    ]);

    let target = member(
        &analyzer,
        &project.file("src/service.rs"),
        "Bar",
        "foo_method",
    );
    let hits = brokk_bifrost::usages::RustExportUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&target),
            &analyzer.get_analyzed_files().into_iter().collect(),
            1000,
        )
        .into_either()
        .expect("tuple destructuring success");
    assert!(hits.is_empty());
}

#[test]
fn rust_graph_strategy_resolves_trait_method_for_explicit_trait_path_and_proven_receiver() {
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/service.rs",
            r#"
pub struct Foo;
pub trait Worker {
    fn work(&self);
}
impl Worker for Foo {
    fn work(&self) {}
}
"#,
        ),
        (
            "src/main.rs",
            r#"
use crate::service::{Foo, Worker};

fn run() {
    let x: Foo = Foo {};
    Worker::work(&x);
    x.work();
}
"#,
        ),
    ]);

    let target = member(&analyzer, &project.file("src/service.rs"), "Worker", "work");
    let hits = brokk_bifrost::usages::RustExportUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&target),
            &analyzer.get_analyzed_files().into_iter().collect(),
            1000,
        )
        .into_either()
        .expect("trait method success");
    assert_eq!(2, hits.len());
}

#[test]
fn rust_graph_strategy_reads_trait_impls_from_tree_sitter_nodes() {
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/traits.rs",
            r#"
pub trait Worker {
    fn work(&self);
}
"#,
        ),
        (
            "src/service.rs",
            r#"
pub struct Foo;
impl /* trait impl */ crate::traits::Worker for Foo {
    fn work(&self) {}
}
"#,
        ),
        (
            "src/main.rs",
            r#"
use crate::service::Foo;

fn run(x: Foo) {
    x.work();
}
"#,
        ),
    ]);

    let target = member(&analyzer, &project.file("src/traits.rs"), "Worker", "work");
    let hits = brokk_bifrost::usages::RustExportUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&target),
            &analyzer.get_analyzed_files().into_iter().collect(),
            1000,
        )
        .into_either()
        .expect("commented trait impl success");
    assert_eq!(1, hits.len());
}

#[test]
fn rust_graph_strategy_requires_proven_trait_impl_and_receiver_type() {
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/service.rs",
            r#"
pub struct Foo;
pub trait Worker {
    fn work(&self);
}
pub trait Other {
    fn work(&self);
}
impl Worker for Foo {
    fn work(&self) {}
}
"#,
        ),
        (
            "src/main.rs",
            r#"
use crate::service::Foo;

fn known() {
    let x: Foo = Foo {};
    x.work();
}

fn unknown(x: impl std::fmt::Debug) {
    x.work();
}
"#,
        ),
    ]);

    let worker = member(&analyzer, &project.file("src/service.rs"), "Worker", "work");
    let other = member(&analyzer, &project.file("src/service.rs"), "Other", "work");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let strategy = brokk_bifrost::usages::RustExportUsageGraphStrategy::new();

    assert_eq!(
        1,
        strategy
            .find_usages(&analyzer, std::slice::from_ref(&worker), &candidates, 1000)
            .into_either()
            .expect("Worker trait receiver success")
            .len()
    );
    assert!(
        strategy
            .find_usages(&analyzer, std::slice::from_ref(&other), &candidates, 1000)
            .into_either()
            .expect("Other trait receiver success")
            .is_empty()
    );
}

#[test]
fn rust_graph_strategy_resolves_cross_file_trait_impl_to_trait_owner_file() {
    let (_project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/traits.rs",
            r#"
pub trait Worker {
    fn work(&self);
}
"#,
        ),
        (
            "src/other.rs",
            r#"
pub trait Worker {
    fn work(&self);
}
"#,
        ),
        (
            "src/service.rs",
            r#"
use crate::traits::Worker;

pub struct Foo;
impl Worker for Foo {
    fn work(&self) {}
}
"#,
        ),
        (
            "src/main.rs",
            r#"
use crate::service::Foo;

fn run(x: Foo) {
    x.work();
}
"#,
        ),
    ]);

    let traits_target = member(
        &analyzer,
        &ProjectFile::new(analyzer.project().root().to_path_buf(), "src/traits.rs"),
        "Worker",
        "work",
    );
    let other_target = member(
        &analyzer,
        &ProjectFile::new(analyzer.project().root().to_path_buf(), "src/other.rs"),
        "Worker",
        "work",
    );
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let strategy = brokk_bifrost::usages::RustExportUsageGraphStrategy::new();

    assert_eq!(
        1,
        strategy
            .find_usages(
                &analyzer,
                std::slice::from_ref(&traits_target),
                &candidates,
                1000,
            )
            .into_either()
            .expect("traits owner success")
            .len()
    );
    assert!(
        strategy
            .find_usages(
                &analyzer,
                std::slice::from_ref(&other_target),
                &candidates,
                1000,
            )
            .into_either()
            .expect("other owner success")
            .is_empty()
    );
}

#[test]
fn rust_graph_strategy_resolves_dyn_and_impl_trait_receivers() {
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/service.rs",
            r#"
pub struct Foo;
pub trait Worker {
    fn work(&self);
}
pub trait Other {
    fn work(&self);
}
impl Worker for Foo {
    fn work(&self) {}
}
pub struct Inherent;
impl Inherent {
    pub fn work(&self) {}
}
"#,
        ),
        (
            "src/main.rs",
            r#"
use crate::service::{Inherent, Other, Worker};

fn generic<T: Worker>(x: T) {
    x.work();
}

fn opaque(x: impl Worker) {
    x.work();
}

fn dynamic(x: &dyn Worker) {
    x.work();
}

fn bounded_opaque(x: impl Worker + Send) {
    x.work();
}

fn bounded_dynamic(x: &dyn Worker + Send) {
    x.work();
}

fn higher_ranked_dynamic(x: &dyn for<'a> Worker) {
    x.work();
}

fn other_opaque(x: impl Other) {
    x.work();
}

fn other_dynamic(x: &dyn Other) {
    x.work();
}

fn other_bounded_opaque(x: impl Other + Send) {
    x.work();
}

fn other_bounded_dynamic(x: &dyn Other + Send) {
    x.work();
}

fn other_higher_ranked_dynamic(x: &dyn for<'a> Other) {
    x.work();
}

fn inherent(x: &Inherent) {
    x.work();
}
"#,
        ),
    ]);

    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let strategy = brokk_bifrost::usages::RustExportUsageGraphStrategy::new();
    for (owner, expected) in [("Worker", 5), ("Other", 5), ("Inherent", 1)] {
        let target = member(&analyzer, &project.file("src/service.rs"), owner, "work");
        let hits = strategy
            .find_usages(&analyzer, std::slice::from_ref(&target), &candidates, 1000)
            .into_either()
            .expect("structured trait receiver success");
        assert_eq!(
            expected,
            hits.len(),
            "{owner}.work receiver hits: {hits:#?}"
        );
    }
}

#[test]
fn rust_graph_strategy_resolves_public_inline_module_exports() {
    let (_project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/lib.rs",
            r#"
pub mod service;
pub mod inline {
    pub struct Inline;
}
"#,
        ),
        ("src/service.rs", "pub struct FileBacked;\n"),
        (
            "src/main.rs",
            r#"
use crate::service::FileBacked;
use crate::inline::Inline;

fn run() {
    let _ = FileBacked {};
    let _ = Inline {};
}
"#,
        ),
    ]);

    let file_backed = definition(&analyzer, "service.FileBacked");
    let inline = definition(&analyzer, "inline.Inline");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let strategy = brokk_bifrost::usages::RustExportUsageGraphStrategy::new();

    assert_eq!(
        1,
        strategy
            .find_usages(
                &analyzer,
                std::slice::from_ref(&file_backed),
                &candidates,
                1000
            )
            .into_either()
            .expect("file-backed module success")
            .len()
    );
    assert_eq!(
        1,
        strategy
            .find_usages(&analyzer, std::slice::from_ref(&inline), &candidates, 1000)
            .into_either()
            .expect("inline module success")
            .len()
    );
}

#[test]
fn rust_graph_strategy_resolves_basic_crate_import_struct_usage() {
    let (_project, analyzer) = rust_analyzer_with_files(&[
        ("src/service.rs", "pub struct Service;\n"),
        (
            "src/main.rs",
            r#"
use crate::service::Service;

fn run() {
    let _ = Service::new();
}
"#,
        ),
    ]);

    let target = definition(&analyzer, "service.Service");
    let hits = brokk_bifrost::usages::RustExportUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&target),
            &analyzer.get_analyzed_files().into_iter().collect(),
            1000,
        )
        .into_either()
        .expect("crate import success");
    assert_eq!(1, hits.len());
}

#[test]
fn rust_graph_strategy_counts_type_argument_usages() {
    let (_project, analyzer) = rust_analyzer_with_files(&[
        ("src/service.rs", "pub struct Foo;\n"),
        (
            "src/main.rs",
            r#"
use crate::service::Foo;
use std::collections::HashMap;

struct Holder {
    a: Vec<Foo>,
    b: Option<Foo>,
    c: HashMap<String, Foo>,
    d: Result<Vec<Foo>, Error>,
}
"#,
        ),
    ]);

    let target = definition(&analyzer, "service.Foo");
    let hits = brokk_bifrost::usages::RustExportUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&target),
            &analyzer.get_analyzed_files().into_iter().collect(),
            1000,
        )
        .into_either()
        .expect("type argument success");
    assert_eq!(4, hits.len());
}

#[test]
fn rust_graph_strategy_does_not_resolve_private_inherent_associated_items() {
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/service.rs",
            r#"
pub struct Foo;
impl Foo {
    fn private(&self) {}
    const PRIVATE: usize = 1;
    type Private = usize;
}
"#,
        ),
        (
            "src/main.rs",
            r#"
use crate::service::Foo;

fn run() {
    let x: Foo = Foo {};
    x.private();
    let _ = Foo::PRIVATE;
    let _: Foo::Private;
}
"#,
        ),
    ]);

    let private_method = member(&analyzer, &project.file("src/service.rs"), "Foo", "private");
    let private_const = member(&analyzer, &project.file("src/service.rs"), "Foo", "PRIVATE");
    let private_type = member(&analyzer, &project.file("src/service.rs"), "Foo", "Private");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let strategy = brokk_bifrost::usages::RustExportUsageGraphStrategy::new();

    assert!(
        strategy
            .find_usages(
                &analyzer,
                std::slice::from_ref(&private_method),
                &candidates,
                1000,
            )
            .into_either()
            .expect("private method success")
            .is_empty()
    );
    assert!(
        strategy
            .find_usages(
                &analyzer,
                std::slice::from_ref(&private_const),
                &candidates,
                1000,
            )
            .into_either()
            .expect("private const success")
            .is_empty()
    );
    assert!(
        strategy
            .find_usages(
                &analyzer,
                std::slice::from_ref(&private_type),
                &candidates,
                1000,
            )
            .into_either()
            .expect("private type success")
            .is_empty()
    );
}

#[test]
fn rust_graph_strategy_records_external_frontier_for_unresolved_public_reexport() {
    let (project, analyzer) =
        rust_analyzer_with_files(&[("src/index.rs", "pub use external_crate::Foo;\n")]);

    let index_file = project.file("src/index.rs");
    let candidates = [index_file.clone()].into_iter().collect();
    let result = brokk_bifrost::usages::RustExportUsageGraphStrategy::find_export_usages(
        &analyzer,
        &index_file,
        "Foo",
        None,
        &candidates,
        1000,
    );

    assert!(result.hits.is_empty());
    assert!(
        result
            .external_frontier_specifiers
            .contains("external_crate")
    );
}

#[test]
fn rust_graph_strategy_records_external_frontier_for_unresolved_glob_reexport() {
    let (project, analyzer) =
        rust_analyzer_with_files(&[("src/index.rs", "pub use external_crate::*;\n")]);

    let index_file = project.file("src/index.rs");
    let candidates = [index_file.clone()].into_iter().collect();
    let result = brokk_bifrost::usages::RustExportUsageGraphStrategy::find_export_usages(
        &analyzer,
        &index_file,
        "Foo",
        None,
        &candidates,
        1000,
    );

    assert!(result.hits.is_empty());
    assert!(
        result
            .external_frontier_specifiers
            .contains("external_crate")
    );
}

#[test]
fn rust_graph_strategy_finds_private_inline_module_usages_via_named_import() {
    let (_project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/lib.rs",
            r#"
mod service {
    pub struct Foo;
}
"#,
        ),
        (
            "src/main.rs",
            r#"
use crate::service::Foo;

fn run() {
    let _ = Foo {};
}
"#,
        ),
    ]);

    let target = definition(&analyzer, "service.Foo");
    let result = brokk_bifrost::usages::RustExportUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &analyzer.get_analyzed_files().into_iter().collect(),
        1000,
    );
    assert_eq!(
        1,
        result
            .into_either()
            .expect("private inline module local scan success")
            .len()
    );
}

#[test]
fn rust_graph_strategy_resolves_private_inline_module_when_explicitly_reexported() {
    let (_project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/lib.rs",
            r#"
mod service {
    pub struct Foo;
}
pub use service::Foo;
"#,
        ),
        (
            "src/main.rs",
            r#"
use crate::Foo;

fn run() {
    let _ = Foo {};
}
"#,
        ),
    ]);

    let target = definition(&analyzer, "service.Foo");
    let hits = brokk_bifrost::usages::RustExportUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&target),
            &analyzer.get_analyzed_files().into_iter().collect(),
            1000,
        )
        .into_either()
        .expect("private inline reexport success");
    assert_eq!(1, hits.len());
}

#[test]
fn rust_graph_strategy_finds_public_and_private_inline_module_usages() {
    let (_project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/lib.rs",
            r#"
pub mod service {
    pub struct Foo;
    struct Hidden;
}
"#,
        ),
        (
            "src/main.rs",
            r#"
use crate::service::{Foo, Hidden};

fn run() {
    let _ = Foo {};
    let _ = Hidden {};
}
"#,
        ),
    ]);

    let foo = definition(&analyzer, "service.Foo");
    let hidden = definition(&analyzer, "service.Hidden");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let strategy = brokk_bifrost::usages::RustExportUsageGraphStrategy::new();

    assert_eq!(
        1,
        strategy
            .find_usages(&analyzer, std::slice::from_ref(&foo), &candidates, 1000)
            .into_either()
            .expect("public inline item success")
            .len()
    );
    assert_eq!(
        1,
        strategy
            .find_usages(&analyzer, std::slice::from_ref(&hidden), &candidates, 1000)
            .into_either()
            .expect("private inline local declaration scan success")
            .len()
    );
}

// Regression for #233: references that reach the crate's public API only through a
// `pub use` re-export of a private module must resolve on the graph path — a
// re-exported free function call, a method on a constructor-returned local, and a
// struct field read through a `self.field` receiver. Before this, seed inference
// bailed on the empty per-file export index and the regex fallback masked the gap.
fn build_233_reexport_project() -> (common::BuiltInlineTestProject, RustAnalyzer) {
    rust_analyzer_with_files(&[
        (
            "src/service.rs",
            r#"
pub struct MemoryRepository {
    pub last: String,
}

pub struct Service {
    repository: MemoryRepository,
}

impl Service {
    pub fn execute(&self) -> &str {
        &self.repository.last
    }
}

pub fn build_service() -> Service {
    Service {
        repository: MemoryRepository {
            last: "demo".to_string(),
        },
    }
}
"#,
        ),
        (
            "src/lib.rs",
            r#"
mod service;

pub use service::{build_service, MemoryRepository, Service};

pub fn run() -> String {
    let service = build_service();
    service.execute().to_string()
}
"#,
        ),
    ])
}

fn rust_graph_hits(analyzer: &RustAnalyzer, fq_name: &str) -> Vec<brokk_bifrost::usages::UsageHit> {
    let target = definition(analyzer, fq_name);
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    brokk_bifrost::usages::RustExportUsageGraphStrategy::new()
        .find_usages(analyzer, std::slice::from_ref(&target), &candidates, 1000)
        .into_either()
        .unwrap_or_else(|_| panic!("expected graph success (not a fallback/failure) for {fq_name}"))
        .into_iter()
        .collect()
}

#[test]
fn rust_graph_strategy_finds_unique_trait_associated_function_candidate() {
    let (_project, analyzer) = rust_analyzer_with_files(&[(
        "src/lib.rs",
        r#"
pub trait Trait {
    fn frobnicate();
}

pub struct Foo;

impl Trait for Foo {}

fn bar() {
    Foo::frobnicate();
}
"#,
    )]);

    let hits = rust_graph_hits(&analyzer, "Trait.frobnicate");
    assert_eq!(
        1,
        hits.len(),
        "expected the Foo::frobnicate() call to hit Trait.frobnicate: {hits:?}"
    );
    assert!(
        hits.iter()
            .any(|hit| hit.snippet.contains("Foo::frobnicate()")),
        "hit should be the static associated call site: {hits:?}"
    );
}

#[test]
fn rust_graph_strategy_ignores_ambiguous_trait_associated_function_candidates() {
    let (_project, analyzer) = rust_analyzer_with_files(&[(
        "src/lib.rs",
        r#"
pub trait Trait {
    fn frobnicate();
}

pub trait OtherTrait {
    fn frobnicate();
}

pub struct Foo;

impl Trait for Foo {}
impl OtherTrait for Foo {}

fn bar() {
    Foo::frobnicate();
}
"#,
    )]);

    let trait_hits = rust_graph_hits(&analyzer, "Trait.frobnicate");
    let other_hits = rust_graph_hits(&analyzer, "OtherTrait.frobnicate");
    assert!(
        trait_hits.is_empty() && other_hits.is_empty(),
        "ambiguous trait candidates must not emit partial hits: Trait={trait_hits:?}, OtherTrait={other_hits:?}"
    );
}

#[test]
fn rust_graph_strategy_counts_type_aliases_used_as_static_qualifiers() {
    let (_project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/lib.rs",
            r#"
pub mod left;
pub mod right;

fn run() {
    let _ = left::Alias::new();
    let _ = right::Alias::new();
}
"#,
        ),
        (
            "src/left.rs",
            "pub struct Owner;\nimpl Owner { pub fn new() -> Self { Self } }\npub type Alias = Owner;\n",
        ),
        (
            "src/right.rs",
            "pub struct Owner;\nimpl Owner { pub fn new() -> Self { Self } }\npub type Alias = Owner;\n",
        ),
    ]);

    let hits = rust_graph_hits(&analyzer, "left.Alias");
    assert_eq!(1, hits.len(), "alias qualifier hits: {hits:?}");
    assert!(hits[0].snippet.contains("left::Alias::new"));
}

#[test]
fn rust_graph_strategy_resolves_bare_module_const_and_turbofish_free_function() {
    let (_project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/lib.rs",
            r#"
pub mod fixtures;
pub mod other;
pub fn is_unpin<T>() {}
"#,
        ),
        ("src/fixtures.rs", "pub const MANIFESTS: &[&str] = &[];\n"),
        (
            "src/other.rs",
            "pub const MANIFESTS: &[&str] = &[];\npub fn is_unpin<T>() {}\n",
        ),
        (
            "src/main.rs",
            r#"
use crate::fixtures::MANIFESTS;

fn run() {
    let _ = MANIFESTS;
    let _ = crate::other::MANIFESTS;
    crate::is_unpin::<u8>();
    crate::other::is_unpin::<u8>();
}
"#,
        ),
    ]);

    let constant_hits = rust_graph_hits(&analyzer, "fixtures._module_.MANIFESTS");
    assert_eq!(
        1,
        constant_hits.len(),
        "module const hits: {constant_hits:?}"
    );
    assert!(constant_hits[0].snippet.contains("MANIFESTS"));

    let function_hits = rust_graph_hits(&analyzer, "is_unpin");
    assert_eq!(1, function_hits.len(), "turbofish hits: {function_hits:?}");
    assert!(function_hits[0].snippet.contains("is_unpin::<u8>"));
}

#[test]
fn authoritative_rust_usage_resolves_private_root_function_and_nested_module_constant() {
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/lib.rs",
            "mod blocking;\nmod consumer;\nfn is_unpin<T>() {}\n",
        ),
        ("src/blocking.rs", "pub(crate) const LIMIT: usize = 8;\n"),
        (
            "src/consumer.rs",
            r#"
#[cfg(test)]
mod tests {
    use crate::blocking::LIMIT;

    fn first() { let _ = LIMIT; }
    fn second() {
        let n = 1;
        let _ = LIMIT - n;
        crate::is_unpin::<()>();
    }
}
"#,
        ),
    ]);
    let candidates: HashSet<_> = analyzer.get_analyzed_files().into_iter().collect();

    let limit = definition(&analyzer, "blocking._module_.LIMIT");
    let limit_hits = authoritative_hits(&analyzer, &limit, candidates.clone());
    let references: Vec<_> = limit_hits
        .iter()
        .filter(|hit| hit.kind == UsageHitKind::Reference)
        .collect();
    assert_eq!(2, references.len(), "nested constant hits: {limit_hits:#?}");
    assert!(
        references
            .iter()
            .all(|hit| hit.file == project.file("src/consumer.rs"))
    );

    let is_unpin = definition(&analyzer, "is_unpin");
    let function_hits = authoritative_hits(&analyzer, &is_unpin, candidates);
    assert_eq!(
        1,
        function_hits.len(),
        "private turbofish hits: {function_hits:#?}"
    );
    assert!(
        function_hits
            .iter()
            .all(|hit| hit.snippet.contains("crate::is_unpin::<()>"))
    );
}

#[test]
fn authoritative_rust_usage_keeps_impl_self_associated_type_identity() {
    let (_project, analyzer) = rust_analyzer_with_files(&[(
        "src/lib.rs",
        r#"
pub trait Future { type Output; }
pub struct Flush;
impl Future for Flush {
    type Output = ();
    fn poll() -> Self::Output { () }
}

pub struct Decoy;
impl Future for Decoy {
    type Output = ();
    fn poll() -> Self::Output { () }
}
"#,
    )]);
    let candidates: HashSet<_> = analyzer.get_analyzed_files().into_iter().collect();

    let output = definition(&analyzer, "Flush.Output");
    let hits = authoritative_hits(&analyzer, &output, candidates);
    assert_eq!(1, hits.len(), "impl Self::Output hits: {hits:#?}");
    assert!(hits.iter().all(|hit| hit.snippet.contains("Self::Output")));
}

#[test]
fn authoritative_rust_usage_resolves_glob_imported_paths_in_nested_macro_tokens() {
    let lib_source = r#"
pub mod task;
pub mod other_task;
mod runtime;
pub struct EventInfo;
impl EventInfo { pub fn default() -> Self { Self } }
pub struct OtherInfo;
impl OtherInfo { pub fn default() -> Self { Self } }

mod tests {
    use super::*;
    macro_rules! consume { ($($tokens:tt)*) => {}; }

    fn run() {
        consume!([EventInfo::default(), EventInfo::default()]);
        consume!([OtherInfo::default()]);
    }
}
"#;
    let coop_source = r#"
use super::*;
macro_rules! consume { ($($tokens:tt)*) => {}; }
fn run() {
    consume!({ task::spawn(); });
    consume!({ other_task::spawn(); });
}
"#;
    let (project, analyzer) = rust_analyzer_with_files(&[
        ("src/lib.rs", lib_source),
        ("src/task.rs", "pub fn spawn() {}\n"),
        ("src/other_task.rs", "pub fn spawn() {}\n"),
        (
            "src/runtime/mod.rs",
            "use crate::{other_task, task};\nmod coop;\n",
        ),
        ("src/runtime/coop.rs", coop_source),
    ]);
    let candidates: HashSet<_> = analyzer.get_analyzed_files().into_iter().collect();

    let event_ranges: Vec<_> = lib_source
        .match_indices("EventInfo::default")
        .map(|(start, _)| (start, start + "EventInfo".len()))
        .collect();
    let default_ranges: Vec<_> = event_ranges
        .iter()
        .map(|(start, _)| {
            let start = start + "EventInfo::".len();
            (start, start + "default".len())
        })
        .collect();
    let task_start = coop_source.find("task::spawn").expect("task macro path");
    let other_event_start = lib_source
        .find("OtherInfo::default()")
        .expect("decoy event macro path");
    let other_default_start = other_event_start + "OtherInfo::".len();
    let other_task_start = coop_source
        .find("other_task::spawn")
        .expect("decoy task macro path");
    for (target_fqn, file, expected, forbidden) in [
        (
            "EventInfo",
            "src/lib.rs",
            event_ranges,
            vec![(other_event_start, other_event_start + "OtherInfo".len())],
        ),
        (
            "EventInfo.default",
            "src/lib.rs",
            default_ranges,
            vec![(other_default_start, other_default_start + "default".len())],
        ),
        (
            "task",
            "src/runtime/coop.rs",
            vec![(task_start, task_start + "task".len())],
            vec![(other_task_start, other_task_start + "other_task".len())],
        ),
    ] {
        let target = definition(&analyzer, target_fqn);
        let hits = authoritative_hits(&analyzer, &target, candidates.clone());
        let expected_file = project.file(file);
        let actual: Vec<_> = hits
            .iter()
            .filter(|hit| hit.file == expected_file)
            .map(|hit| (hit.start_offset, hit.end_offset))
            .collect();
        assert!(
            expected.iter().all(|range| actual.contains(range)),
            "{target_fqn} expected macro ranges {expected:?}: {hits:#?}"
        );
        assert!(
            forbidden.iter().all(|range| !actual.contains(range)),
            "{target_fqn} crossed into decoy macro ranges {forbidden:?}: {hits:#?}"
        );
    }
}

#[test]
fn authoritative_rust_usage_resolves_crate_module_paths_in_macro_tokens() {
    let source = r#"
pub mod task;
pub mod other_task;

macro_rules! call_task {
    () => { $crate::task::spawn(); };
}
macro_rules! call_other_task {
    () => { $crate::other_task::spawn(); };
}
"#;
    let (project, analyzer) = rust_analyzer_with_files(&[
        ("src/lib.rs", source),
        ("src/task.rs", "pub fn spawn() {}\n"),
        ("src/other_task.rs", "pub fn spawn() {}\n"),
    ]);
    let candidates: HashSet<_> = analyzer.get_analyzed_files().into_iter().collect();
    let target = definition(&analyzer, "task");
    let hits = authoritative_hits(&analyzer, &target, candidates);
    let expected_start = source.find("$crate::task").expect("crate task path") + "$crate::".len();
    let forbidden_start =
        source.find("$crate::other_task").expect("decoy crate path") + "$crate::".len();
    let actual: Vec<_> = hits
        .iter()
        .filter(|hit| hit.file == project.file("src/lib.rs"))
        .map(|hit| (hit.start_offset, hit.end_offset))
        .collect();

    assert!(
        actual.contains(&(expected_start, expected_start + "task".len())),
        "crate-qualified macro module segment must be found: {hits:#?}"
    );
    assert!(
        !actual.contains(&(forbidden_start, forbidden_start + "other_task".len())),
        "crate-qualified macro module segment must preserve identity: {hits:#?}"
    );
}

#[test]
fn rust_graph_strategy_counts_associated_functions_used_as_values() {
    let (_project, analyzer) = rust_analyzer_with_files(&[(
        "src/lib.rs",
        r#"
pub struct Left;
impl Left { pub fn new() -> Self { Self } }
pub struct Right;
impl Right { pub fn new() -> Self { Self } }

fn run(value: Option<()>) {
    let _ = value.map(|_| Left::new);
    let _ = value.map(|_| Right::new);
}
"#,
    )]);

    let hits = rust_graph_hits(&analyzer, "Left.new");
    assert_eq!(1, hits.len(), "associated function value hits: {hits:?}");
    assert!(hits[0].snippet.contains("Left::new"));
}

#[test]
fn rust_graph_strategy_resolves_self_associated_types_to_the_exact_trait_owner() {
    let (_project, analyzer) = rust_analyzer_with_files(&[(
        "src/lib.rs",
        r#"
pub trait Left {
    type Handle;
    fn consume(_: Self::Handle);
}

pub trait Right {
    type Handle;
    fn consume(_: Self::Handle);
}
"#,
    )]);

    let left_hits = rust_graph_hits(&analyzer, "Left.Handle");
    let right_hits = rust_graph_hits(&analyzer, "Right.Handle");
    assert_eq!(
        1,
        left_hits.len(),
        "left associated type hits: {left_hits:?}"
    );
    assert_eq!(
        1,
        right_hits.len(),
        "right associated type hits: {right_hits:?}"
    );
    assert!(left_hits[0].snippet.contains("Self::Handle"));
}

#[test]
fn rust_graph_strategy_resolves_concrete_owner_trait_associated_types() {
    let (_project, analyzer) = rust_analyzer_with_files(&[(
        "src/lib.rs",
        r#"
pub trait Trait { type Handle; }
pub struct Owner;
impl Trait for Owner { type Handle = usize; }
pub trait OtherTrait { type Handle; }
pub struct OtherOwner;
impl OtherTrait for OtherOwner { type Handle = usize; }

fn consume(_: Owner::Handle) {}
fn consume_other(_: OtherOwner::Handle) {}
"#,
    )]);

    let hits = rust_graph_hits(&analyzer, "Trait.Handle");
    assert_eq!(1, hits.len(), "trait associated type hits: {hits:?}");
    assert!(hits[0].snippet.contains("Owner::Handle"));
}

#[test]
fn rust_graph_strategy_finds_reexported_free_function_call() {
    let (project, analyzer) = build_233_reexport_project();
    let hits = rust_graph_hits(&analyzer, "service.build_service");
    assert_eq!(
        1,
        hits.len(),
        "expected the build_service() call in run(): {hits:?}"
    );
    assert!(
        hits.iter()
            .all(|hit| hit.file == project.file("src/lib.rs")),
        "hit should be the call site in lib.rs: {hits:?}",
    );
}

#[test]
fn rust_graph_strategy_finds_method_call_on_constructor_returned_local() {
    let (project, analyzer) = build_233_reexport_project();
    let hits = rust_graph_hits(&analyzer, "service.Service.execute");
    assert_eq!(
        1,
        hits.len(),
        "expected service.execute() in run(): {hits:?}"
    );
    assert!(
        hits.iter()
            .all(|hit| hit.file == project.file("src/lib.rs")),
        "hit should be the call site in lib.rs: {hits:?}",
    );
}

#[test]
fn rust_graph_strategy_finds_field_read_through_self_field_receiver() {
    let (project, analyzer) = build_233_reexport_project();
    let hits = rust_graph_hits(&analyzer, "service.MemoryRepository.last");
    // Two references to `MemoryRepository.last`: the `self.repository.last` read
    // in `Service::execute`, and the `MemoryRepository { last: .. }` struct-literal
    // field initializer in `build_service` (a struct-literal field read).
    let lines: std::collections::BTreeSet<usize> = hits.iter().map(|hit| hit.line).collect();
    assert_eq!(
        [12usize, 19]
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>(),
        lines,
        "expected the self.repository.last read and the struct-literal field init: {hits:?}",
    );
    assert!(
        hits.iter()
            .all(|hit| hit.file == project.file("src/service.rs")),
        "hits should be in service.rs: {hits:?}",
    );
}

#[test]
fn rust_graph_strategy_finds_field_assignment_through_direct_self_receiver() {
    let (_project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/service.rs",
            r#"
pub const DEFAULT_PREFIX: &str = "job";

#[derive(Default)]
pub struct MemoryRepository {
    pub last: String,
}

impl MemoryRepository {
    pub fn save(&mut self, value: &str) -> String {
        self.last = value.to_string();
        value.trim().to_string()
    }
}

pub struct Service {
    repository: MemoryRepository,
}

impl Service {
    pub fn new(repository: MemoryRepository) -> Self {
        Self { repository }
    }

    pub fn execute(mut self, name: &str) -> String {
        let stored = self.repository.save(name);
        format!("{DEFAULT_PREFIX}:{stored}")
    }
}

pub fn build_service(repository: MemoryRepository) -> Service {
    Service::new(repository)
}
"#,
        ),
        (
            "src/lib.rs",
            r#"
pub mod service;

pub use service::{DEFAULT_PREFIX, MemoryRepository, Service, build_service};

pub fn run_demo() -> String {
    let mut repository = MemoryRepository::default();
    repository.save("Ada");
    let service = build_service(repository);
    service.execute(" Grace ")
}
"#,
        ),
    ]);

    let hits = rust_graph_hits(&analyzer, "service.MemoryRepository.last");
    assert_eq!(
        1,
        hits.len(),
        "expected self.last assignment in MemoryRepository::save: {hits:?}",
    );
    assert!(
        hits.iter()
            .any(|hit| hit.snippet.contains("self.last = value.to_string()")),
        "expected hit snippet to include the self.last assignment: {hits:?}",
    );
}

#[test]
fn rust_graph_strategy_finds_grouped_reexported_free_function_call_with_argument() {
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/service.rs",
            r#"
pub const DEFAULT_PREFIX: &str = "job";

#[derive(Default)]
pub struct MemoryRepository {
    pub last: String,
}

impl MemoryRepository {
    pub fn save(&mut self, value: &str) -> String {
        self.last = value.to_string();
        value.trim().to_string()
    }
}

pub struct Service {
    repository: MemoryRepository,
}

impl Service {
    pub fn new(repository: MemoryRepository) -> Self {
        Self { repository }
    }

    pub fn execute(mut self, name: &str) -> String {
        let stored = self.repository.save(name);
        format!("{DEFAULT_PREFIX}:{stored}")
    }
}

pub fn build_service(repository: MemoryRepository) -> Service {
    Service::new(repository)
}
"#,
        ),
        (
            "src/lib.rs",
            r#"
pub mod service;

pub use service::{DEFAULT_PREFIX, MemoryRepository, Service, build_service};

pub fn run_demo() -> String {
    let mut repository = MemoryRepository::default();
    repository.save("Ada");
    let service = build_service(repository);
    service.execute(" Grace ")
}
"#,
        ),
    ]);

    let hits = rust_graph_hits(&analyzer, "service.build_service");
    assert_eq!(
        1,
        hits.len(),
        "expected build_service(repository) call in run_demo: {hits:?}",
    );
    assert!(
        hits.iter().any(|hit| hit.file == project.file("src/lib.rs")
            && hit.snippet.contains("build_service(repository)")),
        "expected hit snippet to include the grouped re-exported bare call: {hits:?}",
    );
}

#[test]
fn rust_usage_finder_finds_macro_method_call_on_grouped_reexported_factory_returned_local() {
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/service.rs",
            r#"
pub const DEFAULT_PREFIX: &str = "job";

#[derive(Default)]
pub struct MemoryRepository {
    pub last: String,
}

impl MemoryRepository {
    pub fn save(&mut self, value: &str) -> String {
        self.last = value.to_string();
        value.trim().to_string()
    }
}

pub struct Service {
    repository: MemoryRepository,
}

impl Service {
    pub fn new(repository: MemoryRepository) -> Self {
        Self { repository }
    }

    pub fn execute(mut self, name: &str) -> String {
        let stored = self.repository.save(name);
        format!("{DEFAULT_PREFIX}:{stored}")
    }
}

pub fn build_service(repository: MemoryRepository) -> Service {
    Service::new(repository)
}
"#,
        ),
        (
            "src/lib.rs",
            r#"
pub mod service;

pub use service::{DEFAULT_PREFIX, MemoryRepository, Service, build_service};

pub fn run_demo() -> String {
    let mut repository = MemoryRepository::default();
    repository.save("Ada");
    let service = build_service(repository);
    format!("{}:done", service.execute(" Grace "))
}
"#,
        ),
    ]);

    let target = definition(&analyzer, "service.Service.execute");
    let hits = UsageFinder::new()
        .find_usages_default(&analyzer, std::slice::from_ref(&target))
        .into_either()
        .expect("expected Rust graph success");

    assert!(
        hits.iter().any(|hit| hit.file == project.file("src/lib.rs")
            && hit.snippet.contains(r#"service.execute(" Grace ")"#)),
        "expected macro argument method call on factory-returned local: {hits:?}",
    );
}

#[test]
fn rust_graph_strategy_finds_direct_self_field_in_qualified_cross_module_impl() {
    let (project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/service.rs",
            r#"
pub struct MemoryRepository {
    pub last: String,
}
"#,
        ),
        (
            "src/lib.rs",
            r#"
pub mod service;

pub use service::MemoryRepository;

impl crate::service::MemoryRepository {
    pub fn save(&mut self, value: &str) {
        self.last = value.to_string();
    }
}
"#,
        ),
    ]);

    let hits = rust_graph_hits(&analyzer, "service.MemoryRepository.last");
    assert_eq!(
        1,
        hits.len(),
        "expected self.last assignment in qualified cross-module impl: {hits:?}",
    );
    assert!(
        hits.iter()
            .all(|hit| hit.file == project.file("src/lib.rs")),
        "hit should be the field assignment in lib.rs: {hits:?}",
    );
}

#[test]
fn rust_graph_strategy_does_not_count_direct_self_field_on_other_impl() {
    let (_project, analyzer) = rust_analyzer_with_files(&[(
        "src/service.rs",
        r#"
pub struct MemoryRepository {
    pub last: String,
}

pub struct Other {
    pub last: String,
}

impl Other {
    pub fn save(&mut self, value: &str) {
        self.last = value.to_string();
    }
}
"#,
    )]);

    let hits = rust_graph_hits(&analyzer, "service.MemoryRepository.last");
    assert!(
        hits.is_empty(),
        "Other::save self.last assignment must not count as MemoryRepository.last usage: {hits:?}",
    );
}

// A field whose declared type only *wraps* the owner (a map value here) is not a
// field of the owner type, so a read through it must not be a false-positive usage.
#[test]
fn rust_graph_strategy_does_not_treat_map_valued_field_as_owner_receiver() {
    let (_project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/service.rs",
            r#"
use std::collections::HashMap;

pub struct MemoryRepository {
    pub last: String,
}

pub struct Cache {
    entries: HashMap<String, MemoryRepository>,
}

impl Cache {
    pub fn peek(&self) -> bool {
        self.entries.last.is_empty()
    }
}
"#,
        ),
        (
            "src/lib.rs",
            r#"
mod service;

pub use service::{Cache, MemoryRepository};
"#,
        ),
    ]);

    let hits = rust_graph_hits(&analyzer, "service.MemoryRepository.last");
    assert!(
        hits.is_empty(),
        "self.entries.last where entries is a HashMap must not be a MemoryRepository.last usage: {hits:?}",
    );
}

// A free function whose return type only *wraps* the owner (a `Vec` here) is not a
// constructor of the owner, so a method call on the local it binds must not resolve.
#[test]
fn rust_graph_strategy_does_not_treat_vec_returning_function_as_constructor() {
    let (_project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/service.rs",
            r#"
pub struct Service;

impl Service {
    pub fn execute(&self) -> &str {
        ""
    }
}

pub fn list_all() -> Vec<Service> {
    Vec::new()
}
"#,
        ),
        (
            "src/lib.rs",
            r#"
mod service;

pub use service::{list_all, Service};

pub fn run() {
    let items = list_all();
    let _ = items.execute();
}
"#,
        ),
    ]);

    let hits = rust_graph_hits(&analyzer, "service.Service.execute");
    assert!(
        hits.is_empty(),
        "items.execute() where items is Vec<Service> must not be a Service.execute usage: {hits:?}",
    );
}

#[test]
fn rust_graph_strategy_does_not_treat_unbound_bare_call_as_constructor() {
    let (_project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/service.rs",
            r#"
pub struct Service;

impl Service {
    pub fn execute(&self) -> &str {
        ""
    }
}

pub fn build_service() -> Service {
    Service
}
"#,
        ),
        (
            "src/lib.rs",
            r#"
mod service;

pub use service::{build_service, Service};
"#,
        ),
        (
            "src/client.rs",
            r#"
use crate::Service;

struct Other;

fn build_service() -> Other {
    Other
}

pub fn run() {
    let service = build_service();
    let _ = service.execute();
}
"#,
        ),
    ]);

    let hits = rust_graph_hits(&analyzer, "service.Service.execute");
    assert!(
        hits.is_empty(),
        "a local build_service() returning another type must not seed Service receivers: {hits:?}",
    );
}

#[test]
fn rust_graph_strategy_does_not_treat_option_result_return_as_direct_receiver() {
    let (_project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/service.rs",
            r#"
pub struct Service;

impl Service {
    pub fn execute(&self) -> &str {
        ""
    }
}

pub fn maybe_service() -> Option<Service> {
    Some(Service)
}

pub fn result_service() -> Result<Service, String> {
    Ok(Service)
}
"#,
        ),
        (
            "src/lib.rs",
            r#"
mod service;

pub use service::{maybe_service, result_service, Service};

pub fn run() {
    let maybe = maybe_service();
    let _ = maybe.execute();
    let result = result_service();
    let _ = result.execute();
}
"#,
        ),
    ]);

    let hits = rust_graph_hits(&analyzer, "service.Service.execute");
    assert!(
        hits.is_empty(),
        "Option<Service> and Result<Service, _> values must not be direct Service receivers: {hits:?}",
    );
}

#[test]
fn rust_graph_strategy_does_not_match_qualified_field_type_by_final_segment() {
    let (_project, analyzer) = rust_analyzer_with_files(&[
        (
            "src/service.rs",
            r#"
use crate::other;

pub struct MemoryRepository {
    pub last: String,
}

pub struct Cache {
    repository: other::MemoryRepository,
}

impl Cache {
    pub fn peek(&self) -> bool {
        self.repository.last.is_empty()
    }
}
"#,
        ),
        (
            "src/other.rs",
            r#"
pub struct MemoryRepository {
    pub last: String,
}
"#,
        ),
        (
            "src/lib.rs",
            r#"
mod other;
mod service;

pub use service::{Cache, MemoryRepository};
"#,
        ),
    ]);

    let hits = rust_graph_hits(&analyzer, "service.MemoryRepository.last");
    assert!(
        hits.is_empty(),
        "other::MemoryRepository.last must not be counted as service::MemoryRepository.last: {hits:?}",
    );
}

#[test]
fn rust_graph_resolves_fields_on_explicitly_typed_same_fqn_local_receivers() {
    let target_source = r#"
#[derive(FromArgs)]
#[argh(description = "proxy")]
pub struct Args {
    #[argh(option)] log_format: usize,
    #[argh(option)] server_addr: usize,
}
pub struct OtherArgs { log_format: usize, server_addr: usize }

fn make_args() -> Args { todo!() }
fn make_other() -> OtherArgs { todo!() }
fn run() {
    let args: Args = make_args();
    let other: OtherArgs = make_other();
    let _ = args.log_format;
    let _ = args.server_addr;
    let _ = other.log_format;
    let _ = other.server_addr;
}
"#;
    let sibling_source = r#"
#[derive(FromArgs)]
pub struct Args {
    #[argh(option)] log_format: usize,
    #[argh(option)] server_addr: usize,
}

fn make_args() -> Args { todo!() }
fn run() {
    let args: Args = make_args();
    let _ = args.log_format;
    let _ = args.server_addr;
}
"#;
    let (project, analyzer) = rust_analyzer_with_files(&[
        ("examples/examples/proxy.rs", target_source),
        ("examples/examples/toggle.rs", sibling_source),
    ]);
    let target_file = project.file("examples/examples/proxy.rs");
    let target = analyzer
        .declarations(&target_file)
        .into_iter()
        .find(|unit| unit.is_field() && unit.short_name() == "Args.log_format")
        .expect("proxy Args.log_format field");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let found = authoritative_hits(&analyzer, &target, candidates);
    let expected = target_source
        .find("args.log_format")
        .map(|start| start + "args.".len())
        .map(|start| (start, start + "log_format".len()))
        .expect("typed target receiver field");

    assert!(
        found.iter().any(|hit| {
            hit.file == target_file && (hit.start_offset, hit.end_offset) == expected
        }),
        "the local physical Args declaration must survive a sibling same-FQN Args: {found:#?}"
    );
    assert!(
        found
            .iter()
            .all(|hit| hit.file == target_file && !hit.snippet.contains("other.log_format")),
        "sibling and explicitly unrelated receiver fields must not cross-match: {found:#?}"
    );
}

#[test]
fn rust_graph_proves_field_through_self_field_receiver_chain() {
    let source = r#"
pub struct BlockHeader { pub start_index: usize }
pub struct Block { pub header: BlockHeader }
pub struct OtherHeader { pub start_index: usize }
pub struct OtherBlock { pub header: OtherHeader }

impl Block {
    fn next(&self) -> usize { self.header.start_index.wrapping_add(1) }
}
impl OtherBlock {
    fn next(&self) -> usize { self.header.start_index.wrapping_add(1) }
}
"#;
    let (project, analyzer) = rust_analyzer_with_files(&[("tokio/src/block.rs", source)]);
    let file = project.file("tokio/src/block.rs");
    let target = analyzer
        .declarations(&file)
        .into_iter()
        .find(|unit| unit.is_field() && unit.short_name() == "BlockHeader.start_index")
        .expect("BlockHeader.start_index field");
    let found = authoritative_hits(&analyzer, &target, [file].into_iter().collect());
    let expected = source
        .find("self.header.start_index")
        .map(|start| start + "self.header.".len())
        .map(|start| (start, start + "start_index".len()))
        .expect("self field receiver chain");

    assert_eq!(
        1,
        found.len(),
        "only the BlockHeader field may match: {found:#?}"
    );
    let hit = found.iter().next().expect("the BlockHeader field hit");
    assert_eq!(
        expected,
        (hit.start_offset, hit.end_offset),
        "self.header must prove the terminal field owner"
    );
}

#[test]
fn rust_graph_resolves_dotted_member_chains_inside_macro_token_trees() {
    let source = r#"
pub struct AlertType;
impl AlertType { pub fn default_title(&self) -> &'static str { "Alert" } }
pub struct OtherAlertType;
impl OtherAlertType { pub fn default_title(&self) -> &'static str { "Other" } }
pub struct NodeAlert { pub alert_type: AlertType }
pub struct OtherAlert { pub alert_type: OtherAlertType }

fn render(output: &mut String, alert: &NodeAlert, other: &OtherAlert) {
    write!(output, "{}", alert.alert_type.default_title());
    write!(output, "{}", other.alert_type.default_title());
}
"#;
    let (project, analyzer) = rust_analyzer_with_files(&[("src/lib.rs", source)]);
    let target = definition(&analyzer, "AlertType.default_title");
    let found = authoritative_hits(
        &analyzer,
        &target,
        [project.file("src/lib.rs")].into_iter().collect(),
    );
    let expected = source
        .find("alert.alert_type.default_title")
        .map(|start| start + "alert.alert_type.".len())
        .map(|start| (start, start + "default_title".len()))
        .expect("macro token-tree member chain");

    assert_eq!(
        1,
        found.len(),
        "the unrelated macro chain must not match: {found:#?}"
    );
    let hit = found.iter().next().expect("the AlertType method hit");
    assert_eq!(
        expected,
        (hit.start_offset, hit.end_offset),
        "the token-tree receiver chain must retain its intermediate field type"
    );
}
