//! Canonical Go package identity: same-named packages in different
//! directories must produce distinct, import-path-qualified fully-qualified
//! names so a bare `pkg.Symbol` is only ever a fuzzy query, never an exact
//! identity.

mod common;

use brokk_bifrost::{
    GoAnalyzer, IAnalyzer, ImportAnalysisProvider, Language, ProjectFile,
    searchtools::{
        ScanUsagesParams, SearchSymbolsParams, SymbolLookupParams, get_symbol_locations,
        get_symbol_sources, scan_usages, search_symbols,
    },
};
use common::InlineTestProject;

fn canonical_project() -> common::BuiltInlineTestProject {
    InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.com/repo\n")
        .file("a/list/list.go", "package list\nfunc Run() string { return \"a\" }\n")
        .file("b/list/list.go", "package list\nfunc Run() string { return \"b\" }\n")
        .file(
            "a/srv/server.go",
            "package srv\ntype Server struct{}\nfunc (s *Server) New() string { return \"method\" }\n",
        )
        .file("Server/pkg.go", "package Server\nfunc New() string { return \"package\" }\n")
        .file("gin/gin.go", "package gin\ntype Engine struct{}\nfunc New() *Engine { return &Engine{} }\n")
        .file(
            "a/list/list_test.go",
            "package list\nimport \"testing\"\nfunc TestListRun(t *testing.T) {}\n",
        )
        .file(
            "b/list/list_test.go",
            "package list\nimport \"testing\"\nfunc TestListRun(t *testing.T) {}\n",
        )
        .file(
            "consumer/main.go",
            "package consumer\nimport \"example.com/repo/a/list\"\nfunc Use() string { return list.Run() }\n",
        )
        .build()
}

#[test]
fn definitions_are_import_path_qualified_not_bare_package() {
    let project = canonical_project();
    let analyzer = GoAnalyzer::from_project(project.project().clone());

    assert_eq!(
        1,
        analyzer
            .get_definitions("example.com/repo/a/list.TestListRun")
            .len()
    );
    assert_eq!(
        1,
        analyzer
            .get_definitions("example.com/repo/b/list.TestListRun")
            .len()
    );
    assert_eq!(
        1,
        analyzer
            .get_definitions("example.com/repo/a/list.Run")
            .len()
    );
    // The bare package-clause name must never be an exact identity.
    assert!(
        analyzer.get_definitions("list.TestListRun").is_empty(),
        "bare `list.TestListRun` must not resolve as an exact definition"
    );
}

#[test]
fn search_symbols_reports_canonical_symbols() {
    let project = canonical_project();
    let analyzer = GoAnalyzer::from_project(project.project().clone());

    let result = search_symbols(
        &analyzer,
        SearchSymbolsParams {
            patterns: vec!["TestListRun".to_string()],
            include_tests: true,
            limit: 10,
        },
    );

    let symbols: std::collections::BTreeSet<String> = result
        .files
        .iter()
        .flat_map(|file| file.functions.iter().map(|hit| hit.symbol.clone()))
        .collect();

    assert!(
        symbols.contains("example.com/repo/a/list.TestListRun"),
        "{symbols:#?}"
    );
    assert!(
        symbols.contains("example.com/repo/b/list.TestListRun"),
        "{symbols:#?}"
    );
    assert!(
        !symbols.contains("list.TestListRun"),
        "canonical output must not emit the bare package name: {symbols:#?}"
    );
}

#[test]
fn get_symbol_sources_resolves_exact_canonical_and_flags_bare_ambiguity() {
    let project = canonical_project();
    let analyzer = GoAnalyzer::from_project(project.project().clone());

    let exact = get_symbol_sources(
        &analyzer,
        SymbolLookupParams {
            symbols: vec!["example.com/repo/a/list.TestListRun".to_string()],
        },
    );
    assert!(exact.not_found.is_empty(), "{exact:#?}");
    assert!(exact.ambiguous.is_empty(), "{exact:#?}");
    assert_eq!(1, exact.sources.len(), "{exact:#?}");

    let bare = get_symbol_sources(
        &analyzer,
        SymbolLookupParams {
            symbols: vec!["list.TestListRun".to_string()],
        },
    );
    assert_eq!(1, bare.ambiguous.len(), "{bare:#?}");
    let matches: std::collections::BTreeSet<String> =
        bare.ambiguous[0].matches.iter().cloned().collect();
    assert!(
        matches.contains("example.com/repo/a/list.TestListRun")
            && matches.contains("example.com/repo/b/list.TestListRun"),
        "ambiguity matches must be canonical: {matches:#?}"
    );
}

#[test]
fn get_symbol_locations_uses_canonical_suffix_without_losing_ambiguity() {
    let project = canonical_project();
    let analyzer = GoAnalyzer::from_project(project.project().clone());

    let exact = get_symbol_locations(
        &analyzer,
        SymbolLookupParams {
            symbols: vec!["example.com/repo/a/list.Run".to_string()],
        },
    );
    assert!(exact.not_found.is_empty(), "{exact:#?}");
    assert_eq!(1, exact.locations.len(), "{exact:#?}");
    assert_eq!("example.com/repo/a/list.Run", exact.locations[0].symbol);

    let bare = get_symbol_locations(
        &analyzer,
        SymbolLookupParams {
            symbols: vec!["list.Run".to_string()],
        },
    );
    assert_eq!(
        vec!["list.Run".to_string()],
        bare.not_found,
        "ambiguous bare suffix must not collapse to one location: {bare:#?}"
    );
    assert!(bare.locations.is_empty(), "{bare:#?}");
}

#[test]
fn get_symbol_locations_resolves_unique_short_go_suffix() {
    let project = canonical_project();
    let analyzer = GoAnalyzer::from_project(project.project().clone());

    let result = get_symbol_locations(
        &analyzer,
        SymbolLookupParams {
            symbols: vec!["gin.New".to_string()],
        },
    );

    assert!(result.not_found.is_empty(), "{result:#?}");
    assert_eq!(1, result.locations.len(), "{result:#?}");
    assert_eq!("example.com/repo/gin.New", result.locations[0].symbol);
}

#[test]
fn get_symbol_locations_prefers_full_match_over_suffix_sibling() {
    let project = canonical_project();
    let analyzer = GoAnalyzer::from_project(project.project().clone());

    let result = get_symbol_locations(
        &analyzer,
        SymbolLookupParams {
            symbols: vec!["Server.New".to_string()],
        },
    );

    assert!(result.not_found.is_empty(), "{result:#?}");
    assert_eq!(1, result.locations.len(), "{result:#?}");
    assert_eq!(
        "example.com/repo/a/srv.Server.New",
        result.locations[0].symbol
    );
}

#[test]
fn scan_usages_resolves_canonical_and_flags_bare_ambiguity() {
    let project = canonical_project();
    let analyzer = GoAnalyzer::from_project(project.project().clone());

    let canonical = scan_usages(
        &analyzer,
        ScanUsagesParams {
            symbols: Some(vec!["example.com/repo/a/list.Run".to_string()]),
            targets: Vec::new(),
            include_tests: true,
            paths: None,
        },
    );
    assert!(canonical.ambiguous.is_empty(), "{canonical:#?}");
    assert_eq!(1, canonical.usages.len(), "{canonical:#?}");
    assert!(
        canonical.usages[0]
            .files
            .iter()
            .any(|file| file.path == "consumer/main.go"),
        "{canonical:#?}"
    );

    let bare = scan_usages(
        &analyzer,
        ScanUsagesParams {
            symbols: Some(vec!["list.Run".to_string()]),
            targets: Vec::new(),
            include_tests: true,
            paths: None,
        },
    );
    assert_eq!(1, bare.ambiguous.len(), "{bare:#?}");
    let targets: std::collections::BTreeSet<String> = bare.ambiguous[0]
        .candidate_targets
        .iter()
        .cloned()
        .collect();
    assert!(
        targets.contains("example.com/repo/a/list.Run")
            && targets.contains("example.com/repo/b/list.Run"),
        "candidate targets must be canonical: {targets:#?}"
    );
}

#[test]
fn imports_resolve_to_the_exact_canonical_package() {
    let project = canonical_project();
    let analyzer = GoAnalyzer::from_project(project.project().clone());
    let consumer = ProjectFile::new(project.root().to_path_buf(), "consumer/main.go");

    let resolved = analyzer.imported_code_units_of(&consumer);
    assert!(
        resolved
            .iter()
            .any(|cu| cu.package_name() == "example.com/repo/a/list" && cu.identifier() == "Run"),
        "{resolved:#?}"
    );
    assert!(
        !resolved
            .iter()
            .any(|cu| cu.package_name() == "example.com/repo/b/list"),
        "import of a/list must not pull in the same-named b/list: {resolved:#?}"
    );
}

#[test]
fn list_symbols_keeps_bare_identifiers_with_canonical_group_header() {
    let project = canonical_project();
    let analyzer = GoAnalyzer::from_project(project.project().clone());
    let file = ProjectFile::new(project.root().to_path_buf(), "a/list/list.go");

    let outline = analyzer.list_symbols(&file);
    assert!(
        outline.contains("- Run"),
        "outline must list the bare identifier: {outline}"
    );
    assert!(
        outline.contains("# example.com/repo/a/list"),
        "group header should carry the canonical import path: {outline}"
    );
}
