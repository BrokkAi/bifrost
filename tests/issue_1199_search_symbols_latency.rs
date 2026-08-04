//! Issue #1199: broad `search_symbols` requests must stay interactive.
//!
//! The first fix (#1209) removed the *per-pattern* multiplication: four
//! patterns went from four persisted declaration scans to one. What it did not
//! bound is the cost of that one scan. Every declaration in the workspace was
//! still read with its signature text and primary range, and constructed into a
//! `CodeUnit`, before any pattern was consulted -- so a request that matched
//! almost nothing paid exactly as much as one that matched everything, and the
//! bill grew with the workspace rather than with the answer. That is the shape
//! David reported again on 2026-07-29 (three plain-identifier patterns,
//! 10.603 s, cancelled with no matches).
//!
//! These pins are counter-based on purpose. A wall-clock assertion on a shared
//! CI box is a flake generator; what actually characterizes the bug is that the
//! *work* is proportional to the workspace instead of to the result, so that is
//! what is asserted.

mod common;

use brokk_bifrost::{
    IAnalyzer, Language, RustAnalyzer,
    searchtools::{SearchSymbolsParams, search_symbols},
};
use common::InlineTestProject;

/// A workspace whose declarations vastly outnumber the ones any request can
/// match. `haystack_*` declarations exist only to be scanned past.
fn haystack_project(files: usize, declarations_per_file: usize) -> InlineTestProject {
    let mut project = InlineTestProject::with_language(Language::Rust).file(
        "src/needle.rs",
        "pub fn graph_find_usages() {}\npub fn find_usages() {}\n",
    );
    for file in 0..files {
        let mut source = String::new();
        for decl in 0..declarations_per_file {
            source.push_str(&format!("pub fn haystack_{file}_{decl}() {{}}\n"));
        }
        project = project.file(format!("src/haystack_{file}.rs"), source);
    }
    project
}

#[test]
fn issue_1199_zero_hit_symbol_search_hydrates_no_candidates() {
    let project = haystack_project(8, 40).build();
    let analyzer = RustAnalyzer::from_project(project.project().clone());
    analyzer
        .test_hooks()
        .reset_full_declaration_scan_count_for_test();
    analyzer
        .test_hooks()
        .reset_search_candidate_hydration_count_for_test();

    // Exactly David's shape: tool names searched as symbol patterns, which the
    // workspace mostly does not define.
    let search = search_symbols(
        &analyzer,
        SearchSymbolsParams {
            patterns: vec![
                "scan_usages_by_location".to_string(),
                "publish_workspace_diagnostic".to_string(),
            ],
            include_tests: true,
            limit: 100,
        },
    );

    assert!(search.files.is_empty(), "{search:#?}");
    assert_eq!(
        analyzer.test_hooks().full_declaration_scan_count_for_test(),
        1,
        "one request must still share one persisted candidate scan"
    );
    assert_eq!(
        analyzer
            .test_hooks()
            .search_candidate_hydration_count_for_test(),
        0,
        "a request that matches nothing must not hydrate a single declaration; \
         before #1199's follow-up the whole workspace projection was hydrated first"
    );
}

#[test]
fn issue_1199_symbol_search_hydration_tracks_matches_not_workspace_size() {
    let small = haystack_project(2, 10).build();
    let large = haystack_project(20, 40).build();
    let patterns = vec![
        "graph_find_usages".to_string(),
        "scan_usages_by_location".to_string(),
        "find_usages".to_string(),
    ];

    let mut hydrations = Vec::new();
    let mut matched_symbols = Vec::new();
    for project in [&small, &large] {
        let analyzer = RustAnalyzer::from_project(project.project().clone());
        analyzer
            .test_hooks()
            .reset_search_candidate_hydration_count_for_test();
        let search = search_symbols(
            &analyzer,
            SearchSymbolsParams {
                patterns: patterns.clone(),
                include_tests: true,
                limit: 100,
            },
        );
        hydrations.push(
            analyzer
                .test_hooks()
                .search_candidate_hydration_count_for_test(),
        );
        matched_symbols.push(
            search
                .files
                .iter()
                .flat_map(|file| file.functions.iter().map(|hit| hit.symbol.clone()))
                .collect::<Vec<_>>(),
        );
    }

    // The 20x larger workspace holds the same two matching declarations, so the
    // same two declarations must be hydrated. The previous implementation
    // hydrated 30 and 820 respectively.
    assert_eq!(
        hydrations[0], hydrations[1],
        "candidate hydration must not grow with unrelated workspace declarations: {hydrations:?}"
    );
    assert_eq!(
        hydrations[0], 2,
        "only the two matching declarations may be hydrated: {hydrations:?}"
    );
    assert_eq!(
        matched_symbols[0], matched_symbols[1],
        "narrowing the scan must not change which symbols are reported"
    );
    assert_eq!(
        matched_symbols[0],
        vec![
            "needle.graph_find_usages".to_string(),
            "needle.find_usages".to_string(),
        ],
        "{matched_symbols:#?}"
    );
}

/// The package prefix, not just the short name, participates in matching: a
/// pattern naming a module must keep finding that module's declarations. This
/// pins the boundary that a naive `short_name`-only pre-filter would break.
#[test]
fn issue_1199_narrowed_scan_still_matches_package_qualified_names() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file("src/usages/finder.rs", "pub fn locate() {}\n")
        .file("src/unrelated.rs", "pub fn locate_other() {}\n")
        .build();
    let analyzer = RustAnalyzer::from_project(project.project().clone());

    let search = search_symbols(
        &analyzer,
        SearchSymbolsParams {
            patterns: vec!["usages.finder".to_string()],
            include_tests: true,
            limit: 100,
        },
    );

    assert_eq!(
        search
            .files
            .iter()
            .map(|file| file.path.as_str())
            .collect::<Vec<_>>(),
        vec!["src/usages/finder.rs"],
        "{search:#?}"
    );
}
