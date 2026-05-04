mod common;

use brokk_analyzer::usages::{
    FuzzyResult, JsTsExportUsageGraphStrategy, RegexUsageAnalyzer, UsageAnalyzer, UsageFinder,
};
use brokk_analyzer::{CodeUnit, IAnalyzer, JavascriptAnalyzer, ProjectFile, TypescriptAnalyzer};
use common::{js_fixture_project, ts_fixture_project};
use std::collections::BTreeSet;

fn js_analyzer() -> JavascriptAnalyzer {
    JavascriptAnalyzer::from_project(js_fixture_project())
}

fn ts_analyzer() -> TypescriptAnalyzer {
    TypescriptAnalyzer::from_project(ts_fixture_project())
}

fn definition_in<'a, I>(units: I, predicate: impl Fn(&CodeUnit) -> bool) -> CodeUnit
where
    I: IntoIterator<Item = &'a CodeUnit>,
{
    units
        .into_iter()
        .find(|cu| predicate(cu))
        .cloned()
        .expect("definition not found")
}

#[test]
fn js_graph_strategy_finds_in_file_references() {
    let analyzer = js_analyzer();
    let units: Vec<_> = analyzer.all_declarations().cloned().collect();
    let target = definition_in(units.iter(), |cu| {
        cu.is_class()
            && cu.identifier() == "BaseClass"
            && cu.source().rel_path().ends_with("ClassUsagePatterns.js")
    });

    let strategy = JsTsExportUsageGraphStrategy::new(RegexUsageAnalyzer::new());
    let candidate_files: brokk_analyzer::hash::HashSet<ProjectFile> =
        std::iter::once(target.source().clone()).collect();
    let result = strategy.find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidate_files,
        1000,
    );

    let hits: BTreeSet<_> = match result {
        FuzzyResult::Success { hits_by_overload } => hits_by_overload
            .into_values()
            .flat_map(BTreeSet::into_iter)
            .collect(),
        other => panic!("expected Success, got {other:?}"),
    };

    assert!(
        hits.len() >= 3,
        "graph strategy should resolve multiple in-file BaseClass references, got {} hits",
        hits.len()
    );
    for hit in &hits {
        assert!(hit.start_offset < hit.end_offset);
        assert_ne!(hit.enclosing, target);
    }
}

#[test]
fn ts_graph_strategy_finds_in_file_references() {
    let analyzer = ts_analyzer();
    let units: Vec<_> = analyzer.all_declarations().cloned().collect();
    let target = definition_in(units.iter(), |cu| {
        cu.is_class()
            && cu.identifier() == "BaseClass"
            && cu.source().rel_path().ends_with("ClassUsagePatterns.ts")
    });

    let strategy = JsTsExportUsageGraphStrategy::new(RegexUsageAnalyzer::new());
    let candidate_files: brokk_analyzer::hash::HashSet<ProjectFile> =
        std::iter::once(target.source().clone()).collect();
    let result = strategy.find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidate_files,
        1000,
    );

    let hits: BTreeSet<_> = match result {
        FuzzyResult::Success { hits_by_overload } => hits_by_overload
            .into_values()
            .flat_map(BTreeSet::into_iter)
            .collect(),
        other => panic!("expected Success, got {other:?}"),
    };

    assert!(
        hits.len() >= 4,
        "ts graph strategy should pick up extends/new/type annotations, got {} hits",
        hits.len()
    );
}

#[test]
fn usage_finder_routes_jsts_targets_to_graph_strategy() {
    let analyzer = ts_analyzer();
    let units: Vec<_> = analyzer.all_declarations().cloned().collect();
    let target = definition_in(units.iter(), |cu| {
        cu.is_class()
            && cu.identifier() == "BaseClass"
            && cu.source().rel_path().ends_with("ClassUsagePatterns.ts")
    });

    let finder = UsageFinder::new();
    let result = finder.find_usages_default(&analyzer, std::slice::from_ref(&target));
    let hits = result.into_either().expect("expected Ok hits");
    assert!(
        !hits.is_empty(),
        "UsageFinder should resolve at least one reference for BaseClass via the graph strategy"
    );
}
