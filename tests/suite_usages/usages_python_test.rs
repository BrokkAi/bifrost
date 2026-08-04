use crate::common::{InlineTestProject, py_fixture_project};
use brokk_bifrost::CodeUnitIndex;
use brokk_bifrost::usages::CandidateFileProvider as _;
use brokk_bifrost::usages::{
    FuzzyResult, PythonExportUsageGraphStrategy, TextSearchCandidateProvider, UsageAnalyzer,
    UsageFinder,
};
use brokk_bifrost::{CodeUnit, IAnalyzer, PythonAnalyzer};

fn fixture_analyzer() -> PythonAnalyzer {
    PythonAnalyzer::from_project(py_fixture_project())
}

fn definition(analyzer: &PythonAnalyzer, fq_name: &str) -> CodeUnit {
    analyzer
        .get_definitions(fq_name)
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("missing definition for {fq_name}"))
}

#[test]
fn usage_finder_default_strategy_returns_results() {
    let analyzer = fixture_analyzer();
    let target = definition(&analyzer, "class_usage_patterns.BaseClass");

    let result = analyzer.find_usages(&[target]);
    let hits = result.into_either().expect("either should succeed");
    assert!(
        !hits.is_empty(),
        "expected non-empty usages via UsageFinder"
    );
}

#[test]
fn python_graph_strategy_finds_fixture_class_usages() {
    let analyzer = fixture_analyzer();
    let target = definition(&analyzer, "class_usage_patterns.BaseClass");

    let provider = TextSearchCandidateProvider::new();
    let candidates = provider.find_candidates(&target, &analyzer);

    let strategy = PythonExportUsageGraphStrategy::new();
    let result = strategy.find_usages(&analyzer, std::slice::from_ref(&target), &candidates, 1000);
    let hits = result.into_either().expect("graph strategy should succeed");
    assert!(
        !hits.is_empty(),
        "expected graph strategy to find fixture BaseClass usages"
    );
}

#[test]
fn python_graph_strategy_seeds_private_module_function() {
    let analyzer = fixture_analyzer();
    let target = definition(&analyzer, "underscore_functions._private_function");

    let provider = TextSearchCandidateProvider::new();
    let candidates = provider.find_candidates(&target, &analyzer);

    let strategy = PythonExportUsageGraphStrategy::new();
    match strategy.find_usages(&analyzer, std::slice::from_ref(&target), &candidates, 1000) {
        FuzzyResult::Success {
            hits_by_overload, ..
        } => {
            // The fixture declares _private_function but never calls it; the
            // scan must complete (module-local declarations seed themselves)
            // and report zero hits rather than failing to seed.
            let hits = hits_by_overload.values().flatten().count();
            assert_eq!(hits, 0, "fixture has no callsites for _private_function");
        }
        other => panic!("expected Success for private module-level function, got {other:?}"),
    }
}

#[test]
fn empty_overloads_yields_empty_success() {
    let analyzer = fixture_analyzer();

    let finder = UsageFinder::new();
    let result = finder.find_usages_default(&analyzer, &[]);
    match result {
        FuzzyResult::Success {
            hits_by_overload, ..
        } => {
            assert!(hits_by_overload.is_empty());
        }
        other => panic!("expected empty Success, got {other:?}"),
    }
}

#[test]
fn usage_finder_finds_cross_package_python_method_importers() {
    let project = InlineTestProject::with_language(brokk_bifrost::Language::Python)
        .file("pkg/__init__.py", "")
        .file(
            "pkg/api.py",
            "class Command:\n    def main(self):\n        return 0\n",
        )
        .file(
            "app.py",
            "from pkg.api import Command\n\ncommand = Command()\ncommand.main()\n",
        )
        .build();
    let analyzer = PythonAnalyzer::new(project.project_dyn());
    let target = definition(&analyzer, "pkg.api.Command.main");

    let hits = analyzer
        .find_usages(&[target])
        .into_either()
        .expect("Python usage query should succeed");

    assert!(
        hits.iter()
            .any(|hit| hit.file.rel_path() == std::path::Path::new("app.py")),
        "structured Python importer candidates must retain the cross-package method call"
    );
}
