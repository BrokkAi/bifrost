//! `get_summaries` must not walk the whole workspace tree to answer a
//! per-target question — issue #1325.
//!
//! The MCP property fuzzer's deterministic *service-symbol census* issues one
//! `get_summaries` call per distinct file in the sampled symbol set. Stack
//! sampling a `thomhurst__TUnit` shard put the census's single largest cost in
//! one frame:
//!
//! ```text
//! searchtools::summaries::get_summaries_with_cancellation
//!   -> route_summary_targets_with_cancellation
//!     -> Project::all_files
//!       -> collect_workspace_files            (ignore::WalkParallel, whole tree)
//! ```
//!
//! Summary routing materialized the entire workspace file set up front, for
//! every request, purely so `directory_listing` could test whether a target
//! names a container. The overwhelmingly common target — a plain file path —
//! never needs that set at all, so each call paid a full ignore-aware traversal
//! of the repository across `available_parallelism` walker threads. On TUnit
//! that was ~4-9s per call and roughly half of the whole census's tool time,
//! and it scales with repository size rather than with the request.
//!
//! The fix answers "is this target a directory?" with a `stat`
//! (`Project::has_directory`) and builds the file set lazily, only when the
//! answer is yes. Directory listings, file summaries, and every not-found
//! shape are unchanged; only the number of traversals differs.
//!
//! These are perf pins in the shape of `issue_1194_csharp_scan_complexity.rs`:
//! they assert a deterministic *count* of work rather than wall time.

mod common;

use brokk_bifrost::searchtools::{SummariesParams, get_summaries};
use brokk_bifrost::{
    CSharpAnalyzer, Language, reset_workspace_file_listing_count_for_test,
    workspace_file_listing_count_for_test,
};
use common::InlineTestProject;
use std::sync::{Mutex, MutexGuard};

/// The walk counter is process-global, so the counting tests take turns.
static COUNTER: Mutex<()> = Mutex::new(());

fn counter_guard() -> MutexGuard<'static, ()> {
    COUNTER
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// A C# workspace with one interesting file and `bystanders` unrelated ones.
///
/// The bystanders are the load-bearing part: they cost nothing to *summarize*,
/// but each one is an entry a whole-workspace traversal has to visit. A pin
/// that holds while their number grows tenfold is a pin on "the request does
/// not pay for the repository".
fn bystander_heavy_project(bystanders: usize) -> (common::BuiltInlineTestProject, CSharpAnalyzer) {
    let mut builder = InlineTestProject::with_language(Language::CSharp).file(
        "Lib/Widget.cs",
        "namespace Lib;\n\npublic class Widget\n{\n    public int Size() => 1;\n}\n",
    );
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

fn summarize(analyzer: &CSharpAnalyzer, target: &str) -> brokk_bifrost::searchtools::SummaryResult {
    get_summaries(
        analyzer,
        SummariesParams {
            targets: vec![target.to_string()],
        },
    )
}

/// The pin: summarizing a plain file target performs no whole-workspace
/// traversal at all, however large the workspace is.
///
/// Before the fix this was exactly one traversal per request — the shape that
/// made the census's per-file `get_summaries` probes cost the repository.
#[test]
fn file_summaries_do_not_walk_the_workspace() {
    let _guard = counter_guard();
    for bystanders in [4_usize, 40] {
        let (_project, analyzer) = bystander_heavy_project(bystanders);
        // Analyzer construction legitimately enumerates the workspace; the pin
        // is about what a *request* costs, so count from here.
        reset_workspace_file_listing_count_for_test();

        let result = summarize(&analyzer, "Lib/Widget.cs");
        assert_eq!(
            result.summaries.len(),
            1,
            "the file target must still be summarized: {result:#?}"
        );

        assert_eq!(
            workspace_file_listing_count_for_test(),
            0,
            "summarizing one file must not traverse the workspace \
             (bystanders={bystanders})"
        );
    }
}

/// The same bound stated over request count: ten file summaries cost ten times
/// nothing, not ten whole-workspace traversals.
#[test]
fn repeated_file_summaries_do_not_accumulate_workspace_walks() {
    let _guard = counter_guard();
    let (_project, analyzer) = bystander_heavy_project(8);
    reset_workspace_file_listing_count_for_test();

    for index in 0..10 {
        let target = format!("Noise/Bystander{}.cs", index % 8);
        let result = summarize(&analyzer, &target);
        assert_eq!(
            result.summaries.len(),
            1,
            "every repeated file summary must resolve: {result:#?}"
        );
    }

    assert_eq!(
        workspace_file_listing_count_for_test(),
        0,
        "repeated file summaries must not each traverse the workspace"
    );
}

/// The behaviour the pre-check must not break: a directory target still lists
/// its entries, and a name that is neither file nor directory still routes on
/// to symbol resolution.
#[test]
fn directory_and_symbol_targets_are_unchanged() {
    let (_project, analyzer) = bystander_heavy_project(3);

    let listed = summarize(&analyzer, "Noise");
    assert_eq!(
        listed.listings.len(),
        1,
        "a real workspace directory must still list: {listed:#?}"
    );
    let listing = &listed.listings[0];
    assert_eq!(listing.target, "Noise");
    assert_eq!(
        listing.entries.len(),
        3,
        "the listing must still name every file in the directory: {listing:#?}"
    );

    let root = summarize(&analyzer, ".");
    assert_eq!(
        root.listings.len(),
        1,
        "the workspace root must still list: {root:#?}"
    );

    let symbol = summarize(&analyzer, "Lib.Widget");
    assert_eq!(
        symbol.summaries.len(),
        1,
        "a symbol target must still resolve through summary routing: {symbol:#?}"
    );

    let missing = summarize(&analyzer, "Nope/Missing.cs");
    assert_eq!(
        missing.not_found.len(),
        1,
        "an unmatched file target must still report not_found: {missing:#?}"
    );
}
