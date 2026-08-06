//! One `get_symbol_sources` request must not walk the workspace once per
//! symbol — issue #1334.
//!
//! `WorkspaceFileResolver` answers "does this bare name spell a workspace
//! file?" from a basename index, and building that index costs a full
//! ignore-aware traversal of the repository. A dotted C# fully-qualified name
//! contains no `/`, so every one of its prefixes is a *bare literal candidate*:
//! once exact symbol resolution misses, `dotted_file_symbol_selector` asks the
//! resolver about `Lib.Widget0` and then `Lib`, and `resolve_file_patterns`
//! asks about the whole name — each miss falling through to the basename
//! search.
//!
//! Nothing shared that index. `get_symbol_sources` builds resolvers inside its
//! per-symbol `rayon` closure — `split_workspace_definition_selector`,
//! `split_path_qualified_definition_selector` ->
//! `dotted_file_symbol_selector`, and `resolve_file_patterns` each construct
//! their own — so a request over N dotted names walked the whole repository
//! several times *per name* (9/12 gdb samples of the 4.4s probes on
//! `TUnit.Aspire.AspireFixture\`1.*`).
//!
//! The fix memoizes the listing against the request's read-cache scope (the
//! `AnalyzerQueryScope`/`QueryReadCache` lifetime, cleared at the outermost
//! scope end and fresh per clone) rather than a process-global cache, and opens
//! that scope at the tool entry. Results are unchanged; only the walk count is.
//!
//! These are perf pins in the shape of `issue_1194_csharp_scan_complexity.rs`
//! and `issue_1325_csharp_census_complexity.rs`: they assert a deterministic
//! *count* of work rather than wall time, using the per-project-instance walk
//! counter so background threads from other tests cannot bleed in.

use crate::common::InlineTestProject;
use brokk_bifrost::searchtools::{SymbolLookupParams, SymbolSourcesResult, get_symbol_sources};
use brokk_bifrost::{CSharpAnalyzer, Language, Project};

/// A C# workspace of `classes` single-class files plus unrelated bystanders.
///
/// The bystanders are load-bearing: they cost nothing to *render*, but every
/// one of them is an entry a whole-workspace traversal has to visit.
fn dotted_symbol_project(
    classes: usize,
    bystanders: usize,
) -> (crate::common::BuiltInlineTestProject, CSharpAnalyzer) {
    let mut builder = InlineTestProject::with_language(Language::CSharp);
    for index in 0..classes {
        builder = builder.file(
            format!("Lib/Widget{index}.cs"),
            format!(
                "namespace Lib;\n\npublic class Widget{index}\n{{\n    public int Size() => {index};\n}}\n"
            ),
        );
    }
    for index in 0..bystanders {
        builder = builder.file(
            format!("Noise/Bystander{index}.cs"),
            format!("namespace Noise;\n\npublic class Bystander{index}\n{{\n}}\n"),
        );
    }
    let project = builder.build();
    let analyzer = CSharpAnalyzer::from_project(project.project().clone());
    (project, analyzer)
}

/// Dotted names that exact resolution misses — the fuzzer-probe shape that
/// reaches the file resolver. A name the analyzer resolves outright never gets
/// that far, so it is the *unresolved* dotted name that pays for the
/// repository, exactly as on the TUnit census.
fn probe_symbols(count: usize) -> Vec<String> {
    (0..count)
        .map(|index| format!("Lib.Widget{index}.NoSuchMember"))
        .collect()
}

/// Dotted names that do resolve, used to pin that sharing the listing does not
/// change what a request answers.
fn member_symbols(count: usize) -> Vec<String> {
    (0..count)
        .map(|index| format!("Lib.Widget{index}.Size"))
        .collect()
}

fn sources(analyzer: &CSharpAnalyzer, symbols: Vec<String>) -> SymbolSourcesResult {
    get_symbol_sources(analyzer, SymbolLookupParams { symbols })
}

/// The bound, stated over symbol count: N dotted names in one request cost the
/// same number of workspace traversals as one — at most one.
///
/// Before the fix the count grew with N (each symbol's resolvers walked the
/// tree independently), which is the shape that made the fuzzer's
/// `get_symbol_sources` probes cost the repository once per requested symbol.
#[test]
fn dotted_symbol_requests_walk_the_workspace_at_most_once() {
    let (built, analyzer) = dotted_symbol_project(8, 40);
    let project = built.project().clone();

    // Analyzer construction legitimately enumerates the workspace; the pin is
    // about what a *request* costs, so baseline from here.
    let baseline = project.workspace_file_listing_count();
    let single = sources(&analyzer, probe_symbols(1));
    let single_walks = project.workspace_file_listing_count() - baseline;
    assert_eq!(
        single.not_found.len(),
        1,
        "the unresolved dotted name must still be reported: {single:#?}"
    );
    assert!(
        single_walks <= 1,
        "one dotted-symbol request must walk the workspace at most once, walked {single_walks}"
    );

    let baseline = project.workspace_file_listing_count();
    let batch = sources(&analyzer, probe_symbols(8));
    let batch_walks = project.workspace_file_listing_count() - baseline;
    assert_eq!(
        batch.not_found.len(),
        8,
        "every unresolved dotted name in the batch must still be reported: {batch:#?}"
    );
    assert_eq!(
        batch_walks, single_walks,
        "a request's workspace traversals must not grow with the number of \
         symbols in it (1 symbol: {single_walks}, 8 symbols: {batch_walks})"
    );
}

/// The same bound stated over workspace size: the walk count of a fixed request
/// does not change when the repository grows.
#[test]
fn dotted_symbol_walks_do_not_grow_with_the_workspace() {
    let mut counts = Vec::new();
    for bystanders in [4_usize, 40] {
        let (built, analyzer) = dotted_symbol_project(4, bystanders);
        let project = built.project().clone();
        let baseline = project.workspace_file_listing_count();
        let result = sources(&analyzer, probe_symbols(4));
        assert_eq!(
            result.not_found.len(),
            4,
            "every unresolved dotted name must be reported (bystanders={bystanders}): {result:#?}"
        );
        counts.push(project.workspace_file_listing_count() - baseline);
    }
    assert!(
        counts.iter().all(|walks| *walks <= 1),
        "a dotted-symbol request must walk the workspace at most once, \
         regardless of workspace size: {counts:?}"
    );
}

/// Sharing the listing across a request must not change what the request
/// answers: batching symbols into one call returns exactly what asking for them
/// one at a time does, and the file, bare-name, ambiguous, and not-found shapes
/// that route through the same resolver are unchanged.
#[test]
fn shared_listing_returns_identical_results() {
    let (_built, analyzer) = dotted_symbol_project(4, 6);

    let mixed: Vec<_> = member_symbols(4)
        .into_iter()
        .chain(probe_symbols(4))
        .chain(["Lib/Widget0.cs".to_string(), "Widget1.cs".to_string()])
        .collect();
    let batch = sources(&analyzer, mixed.clone());
    let mut individually = SymbolSourcesResult {
        sources: Vec::new(),
        not_found: Vec::new(),
        ambiguous: Vec::new(),
        ambiguous_paths: Vec::new(),
        too_broad: Vec::new(),
    };
    for symbol in mixed {
        let one = sources(&analyzer, vec![symbol]);
        individually.sources.extend(one.sources);
        individually.not_found.extend(one.not_found);
        individually.ambiguous.extend(one.ambiguous);
        individually.ambiguous_paths.extend(one.ambiguous_paths);
    }
    assert_eq!(
        format!("{batch:#?}"),
        format!("{individually:#?}"),
        "batched and one-at-a-time lookups must render identically"
    );
    assert_eq!(
        batch.sources.len(),
        6,
        "the four members and two file targets must resolve: {batch:#?}"
    );
    assert_eq!(
        batch.not_found.len(),
        4,
        "the four unresolved dotted names must be reported: {batch:#?}"
    );

    let ambiguous = InlineTestProject::with_language(Language::CSharp)
        .file("A/Same.cs", "namespace A;\n\npublic class SameA\n{\n}\n")
        .file("B/Same.cs", "namespace B;\n\npublic class SameB\n{\n}\n")
        .build();
    let ambiguous_analyzer = CSharpAnalyzer::from_project(ambiguous.project().clone());
    let collided = sources(&ambiguous_analyzer, vec!["Same.cs".to_string()]);
    assert_eq!(
        collided.ambiguous_paths.len(),
        1,
        "a colliding bare filename must still be reported ambiguous: {collided:#?}"
    );
    assert_eq!(
        collided.ambiguous_paths[0].matches,
        vec!["A/Same.cs".to_string(), "B/Same.cs".to_string()],
        "the ambiguous match list must still be the sorted workspace matches: {collided:#?}"
    );
}
