mod common;

use brokk_analyzer::usages::CandidateFileProvider as _;
use brokk_analyzer::usages::{
    CONFIDENCE_THRESHOLD, FuzzyResult, RegexUsageAnalyzer, TextSearchCandidateProvider,
    UsageAnalyzer, UsageFinder,
};
use brokk_analyzer::{CodeUnit, IAnalyzer, Language, ProjectFile, PythonAnalyzer};
use common::py_fixture_project;
use std::collections::BTreeSet;

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
fn regex_usage_analyzer_finds_class_usages() {
    let analyzer = fixture_analyzer();
    let target = definition(&analyzer, "class_usage_patterns.BaseClass");

    let provider = TextSearchCandidateProvider::new();
    let candidates = provider.find_candidates(&target, &analyzer);
    assert!(
        !candidates.is_empty(),
        "TextSearchCandidateProvider should find at least one file containing BaseClass"
    );

    let regex = RegexUsageAnalyzer::new();
    let result = regex.find_usages(&analyzer, std::slice::from_ref(&target), &candidates, 1000);

    let hits = match result {
        FuzzyResult::Success { hits_by_overload } => hits_by_overload
            .into_values()
            .flat_map(BTreeSet::into_iter)
            .collect::<Vec<_>>(),
        FuzzyResult::Ambiguous {
            hits_by_overload, ..
        } => hits_by_overload
            .into_values()
            .flat_map(BTreeSet::into_iter)
            .collect::<Vec<_>>(),
        other => panic!("expected Success or Ambiguous, got {other:?}"),
    };

    assert!(
        !hits.is_empty(),
        "RegexUsageAnalyzer should report at least one BaseClass usage in class_usage_patterns.py"
    );

    let usage_file = ProjectFile::new(
        analyzer.project().root().to_path_buf(),
        "class_usage_patterns.py",
    );
    assert!(
        hits.iter().any(|hit| hit.file == usage_file),
        "expected at least one hit in class_usage_patterns.py"
    );

    for hit in &hits {
        assert!(hit.confidence >= CONFIDENCE_THRESHOLD);
        assert!(hit.start_offset < hit.end_offset);
        assert!(hit.line >= 1);
        assert!(!hit.snippet.is_empty(), "snippet must include context");
        // The target itself should never appear among the hits.
        assert_ne!(hit.enclosing, target);
    }
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
fn empty_overloads_yields_empty_success() {
    let analyzer = fixture_analyzer();

    let finder = UsageFinder::new();
    let result = finder.find_usages_default(&analyzer, &[]);
    match result {
        FuzzyResult::Success { hits_by_overload } => {
            assert!(hits_by_overload.is_empty());
        }
        other => panic!("expected empty Success, got {other:?}"),
    }
}

#[test]
fn search_patterns_table_is_populated_for_known_languages() {
    use brokk_analyzer::CodeUnitType;

    // Function patterns we explicitly ported.
    for lang in [
        Language::Java,
        Language::Python,
        Language::Rust,
        Language::Cpp,
        Language::Scala,
        Language::Go,
    ] {
        let patterns = lang.search_patterns(CodeUnitType::Function);
        assert!(
            patterns.iter().any(|p| p.contains("$ident")),
            "{lang:?} function search patterns must include $ident placeholder"
        );
    }

    // Class patterns for the languages that ship them.
    for lang in [
        Language::Java,
        Language::Python,
        Language::Rust,
        Language::Cpp,
        Language::Scala,
    ] {
        let patterns = lang.search_patterns(CodeUnitType::Class);
        assert!(
            patterns.iter().any(|p| p.contains("$ident")),
            "{lang:?} class search patterns must include $ident placeholder"
        );
    }

    // Default fallback for any pair without an override.
    let default_patterns = Language::CSharp.search_patterns(CodeUnitType::Class);
    assert_eq!(default_patterns.len(), 1);
    assert!(default_patterns[0].contains("$ident"));
}
