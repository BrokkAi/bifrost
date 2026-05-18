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

    let result = brokk_analyzer::usages::RustExportUsageGraphStrategy::new().find_usages(
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

    let strategy = brokk_analyzer::usages::RustExportUsageGraphStrategy::new();
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

    let result = brokk_analyzer::usages::RustExportUsageGraphStrategy::new().find_usages(
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

    let result = brokk_analyzer::usages::RustExportUsageGraphStrategy::new().find_usages(
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

    let result = brokk_analyzer::usages::RustExportUsageGraphStrategy::new().find_usages(
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

    let result = brokk_analyzer::usages::RustExportUsageGraphStrategy::new().find_usages(
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

    let result = brokk_analyzer::usages::RustExportUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates,
        1000,
    );
    assert!(result.into_either().expect("shadowed success").is_empty());
}

#[test]
fn private_unseeded_rust_target_falls_back_to_no_graph_hits() {
    let (_project, analyzer) = rust_analyzer_with_files(&[("src/service.rs", "struct Service;\n")]);
    let target = definition(&analyzer, "service.Service");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();

    match brokk_analyzer::usages::RustExportUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates,
        1000,
    ) {
        FuzzyResult::Failure { .. } => {}
        other => panic!("expected Failure for private unseeded target, got {other:?}"),
    }
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
fn private_same_file_function_without_call_produces_no_hit() {
    let (_project, analyzer) = rust_analyzer_with_files(&[(
        "src/searchtools.rs",
        r#"
fn summarize_symbol_targets() {}

pub fn get_summaries() {}
"#,
    )]);

    let target = definition(&analyzer, "searchtools.summarize_symbol_targets");
    let result = brokk_analyzer::usages::RustExportUsageGraphStrategy::new().find_usages(
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
    let result = brokk_analyzer::usages::RustExportUsageGraphStrategy::new().find_usages(
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
    let hits = brokk_analyzer::usages::RustExportUsageGraphStrategy::new()
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
    let hits = brokk_analyzer::usages::RustExportUsageGraphStrategy::new()
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
    let strategy = brokk_analyzer::usages::RustExportUsageGraphStrategy::new();

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
fn rust_graph_strategy_does_not_resolve_public_member_on_private_owner() {
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
    let hits = brokk_analyzer::usages::RustExportUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&target),
            &analyzer.get_analyzed_files().into_iter().collect(),
            1000,
        )
        .into_either();
    assert!(hits.is_err() || hits.expect("private owner member").is_empty());
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
    let strategy = brokk_analyzer::usages::RustExportUsageGraphStrategy::new();

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
    let hits = brokk_analyzer::usages::RustExportUsageGraphStrategy::new()
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
    let hits = brokk_analyzer::usages::RustExportUsageGraphStrategy::new()
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

    let hits = brokk_analyzer::usages::RustExportUsageGraphStrategy::new()
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
    let hits = brokk_analyzer::usages::RustExportUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &analyzer.get_analyzed_files().into_iter().collect(),
        1000,
    );
    assert!(matches!(hits, FuzzyResult::Failure { .. }));
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
    let hits = brokk_analyzer::usages::RustExportUsageGraphStrategy::new()
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
    let hits = brokk_analyzer::usages::RustExportUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&target),
            &analyzer.get_analyzed_files().into_iter().collect(),
            1000,
        )
        .into_either()
        .expect("barrel reexport success");
    assert_eq!(1, hits.len());
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
    let strategy = brokk_analyzer::usages::RustExportUsageGraphStrategy::new();

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
    let hits = brokk_analyzer::usages::RustExportUsageGraphStrategy::new()
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
    let hits = brokk_analyzer::usages::RustExportUsageGraphStrategy::new()
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
    let strategy = brokk_analyzer::usages::RustExportUsageGraphStrategy::new();

    assert_eq!(
        1,
        strategy
            .find_usages(&analyzer, std::slice::from_ref(&foo), &candidates, 1000)
            .into_either()
            .expect("glob Foo success")
            .len()
    );
    assert!(matches!(
        strategy.find_usages(&analyzer, std::slice::from_ref(&hidden), &candidates, 1000),
        FuzzyResult::Failure { .. }
    ));
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
    let hits = brokk_analyzer::usages::RustExportUsageGraphStrategy::new()
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
    let strategy = brokk_analyzer::usages::RustExportUsageGraphStrategy::new();

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
    let hits = brokk_analyzer::usages::RustExportUsageGraphStrategy::new()
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
    let result = brokk_analyzer::usages::RustExportUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &analyzer.get_analyzed_files().into_iter().collect(),
        1000,
    );
    assert!(matches!(result, FuzzyResult::Failure { .. }));
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
    let hits = brokk_analyzer::usages::RustExportUsageGraphStrategy::new()
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
    let hits = brokk_analyzer::usages::RustExportUsageGraphStrategy::new()
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
    let hits = brokk_analyzer::usages::RustExportUsageGraphStrategy::new()
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
    let hits = brokk_analyzer::usages::RustExportUsageGraphStrategy::new()
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
    let strategy = brokk_analyzer::usages::RustExportUsageGraphStrategy::new();

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
    let strategy = brokk_analyzer::usages::RustExportUsageGraphStrategy::new();

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
fn rust_graph_strategy_does_not_seed_trait_receivers_from_non_concrete_parameter_types() {
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
use crate::service::Worker;

fn generic<T: Worker>(x: T) {
    x.work();
}

fn opaque(x: impl Worker) {
    x.work();
}

fn dynamic(x: &dyn Worker) {
    x.work();
}
"#,
        ),
    ]);

    let target = member(&analyzer, &project.file("src/service.rs"), "Worker", "work");
    let hits = brokk_analyzer::usages::RustExportUsageGraphStrategy::new()
        .find_usages(
            &analyzer,
            std::slice::from_ref(&target),
            &analyzer.get_analyzed_files().into_iter().collect(),
            1000,
        )
        .into_either()
        .expect("non-concrete trait receiver success");
    assert!(hits.is_empty());
}
