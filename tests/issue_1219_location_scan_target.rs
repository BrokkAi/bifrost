//! A Rust `scan_usages_by_location` scan must not re-parse a file once per
//! reference site it inspects — issue #1219.
//!
//! A line-only target (`{path, line, column}`, no `symbol`) against Bifrost's
//! own tree ran ~21 minutes at 1200-1600% CPU. Symbol selectors were historically
//! fully qualified, so the reported bare `"resolve_scan_usages_target"` selector
//! initially returned `not_found`; #1228 made a matching short selector valid at
//! an exact declaration location. Either way there is no line-only-specific
//! expansion: line-only targets bind to the same declaration a matching selector
//! binds to, and the cost is the ordinary Rust usage scan.
//!
//! Stack sampling put tree-sitter parsing under `parse_rust_tree` in the
//! overwhelming majority of samples, reached from three independent directions
//! inside the parallel per-file scan:
//!
//! ```text
//! scan_files_for_target
//!   -> rust_forward_bare_token_reference_fqn
//!        -> rust_visible_import_resolution -> visible_import_binders_with_scopes_at -> parse_rust_tree
//!        -> rust_current_module_candidates -> rust_declaration_matches          -> parse_rust_tree
//!   -> reference_context_of -> canonical_export_fqn -> is_export_public_declaration
//!        -> rust_declaration_node_is                                            -> parse_rust_tree
//! ```
//!
//! Every one of those asks a question *about a file* and answers it by reading
//! and re-parsing that whole file from scratch — once per reference site, once
//! per candidate declaration. `parse_rust_tree` is a pure function of its
//! source bytes, so it is now memoized on exactly those bytes: same trees, same
//! answers, one parse per distinct source instead of hundreds of thousands.
//!
//! These are perf pins in the shape of `issue_1175_scan_usages_reparse.rs` and
//! `issue_1194_csharp_scan_complexity.rs`: they assert a *count* of work, which
//! is deterministic, rather than wall time, which is not.

mod common;

use brokk_bifrost::searchtools::{
    ScanUsagesByLocationParams, ScanUsagesEntry, ScanUsagesStatus, ScanUsagesTarget,
    scan_usages_by_location,
};
use brokk_bifrost::{Language, RustAnalyzer};
// The counters are gated behind `test-support`, which this package cannot turn
// on for its own lib. The `analyzer` module re-export carries them instead: the
// dev-dependency on brokk-bifrost-analysis enables that crate's `test-support`
// for these test targets.
use brokk_bifrost::analyzer::{
    reset_rust_tree_parse_counters_for_test, rust_tree_parse_count_for_test,
    rust_tree_parse_request_count_for_test, rust_tree_parsed_bytes_for_test,
};
use common::InlineTestProject;
use std::sync::{Mutex, MutexGuard, OnceLock};

/// The parse counters are process-global (the memo they measure is), so the
/// tests in this binary take turns rather than interleave their deltas.
fn counter_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// A crate whose `lib.rs` declares the scan target, plus three consumer modules
/// that each reference it `references_per_file` times.
///
/// The reference *sites* are the load-bearing part. The Rust scan walks every
/// identifier of every candidate file and asks the forward resolver "what does
/// this name bind to here?" — a question whose answer depends on the reference
/// byte, so it cannot be cached per file. Before the fix each such question
/// re-parsed the whole enclosing file, so the work grew with (files x sites)
/// while the workspace's *content* stayed the same size in files.
fn reference_heavy_project(references_per_file: usize) -> common::BuiltInlineTestProject {
    let mut builder = InlineTestProject::with_language(Language::Rust).file(
        "src/lib.rs",
        "pub mod consumer0;\npub mod consumer1;\npub mod consumer2;\n\n\
         pub struct Widget;\n\npub fn target_helper(value: usize) -> usize {\n    value + 1\n}\n",
    );
    for index in 0..3 {
        // The calls sit inside macro token trees on purpose. A token tree is
        // unparsed by definition, so the scan cannot rely on the declaration
        // graph there: it runs the *forward* resolver on every bare identifier
        // to decide what the name binds to at that byte. That resolver is the
        // one the issue's stack samples were pinned in, and it is the one that
        // re-parsed the whole enclosing file per site.
        let calls = (0..references_per_file)
            .map(|call| format!("    total += vec![target_helper({call})][0];\n"))
            .collect::<String>();
        builder = builder.file(
            format!("src/consumer{index}.rs"),
            format!(
                "use crate::target_helper;\nuse crate::Widget;\n\n\
                 pub fn consume{index}() -> usize {{\n    \
                 let _widget = Widget;\n    let mut total = 0;\n{calls}    total\n}}\n"
            ),
        );
    }
    builder.build()
}

/// `src/lib.rs:7` is `pub fn target_helper(...)`; column 8 is inside the name
/// token — the exact `{path, line, column}` shape the issue reported.
fn scan_target_helper_by_location(analyzer: &RustAnalyzer) -> ScanUsagesEntry {
    scan_at(analyzer, None)
}

fn scan_at(analyzer: &RustAnalyzer, symbol: Option<&str>) -> ScanUsagesEntry {
    let mut result = scan_usages_by_location(
        analyzer,
        ScanUsagesByLocationParams {
            targets: vec![ScanUsagesTarget {
                path: "src/lib.rs".to_string(),
                line: 7,
                column: Some(8),
                symbol: symbol.map(str::to_string),
            }],
            include_tests: true,
            paths: None,
            include_same_owner: false,
            max_duration_secs: None,
        },
    );
    assert_eq!(result.results.len(), 1, "one requested target");
    result.results.remove(0)
}

/// Total bytes of Rust source in the built workspace — the yardstick the parse
/// budget is stated against.
fn workspace_bytes(project: &common::BuiltInlineTestProject) -> usize {
    let mut total = 0;
    for entry in std::fs::read_dir(project.root().join("src")).expect("workspace src directory") {
        let entry = entry.expect("workspace entry");
        total += entry.metadata().expect("workspace file metadata").len() as usize;
    }
    total
}

fn call_sites(entry: &ScanUsagesEntry) -> Vec<String> {
    let mut files: Vec<String> = entry
        .files
        .iter()
        .map(|file| {
            let hits = file.hit_count.unwrap_or(file.hits.len());
            format!("{}:{hits}", file.path)
        })
        .collect();
    files.sort();
    files
}

/// The pin, stated as a complexity bound: multiplying the number of reference
/// sites by ten must not multiply the source *bytes* handed to tree-sitter.
///
/// Bytes, not call count, is the load-bearing measure. The resolver legitimately
/// parses one small token-tree fragment per site, which grows the call count no
/// matter what; what must not grow is re-parsing the whole enclosing file per
/// site, which is what turned one `scan_usages_by_location` request on Bifrost's
/// own tree into 20+ minutes of pure compute.
#[test]
fn rust_parsed_bytes_do_not_grow_with_reference_sites() {
    let _guard = counter_lock();
    let mut measurements = Vec::new();
    for references in [2_usize, 20] {
        let project = reference_heavy_project(references);
        let analyzer = RustAnalyzer::from_project(project.project().clone());
        reset_rust_tree_parse_counters_for_test();

        let entry = scan_target_helper_by_location(&analyzer);
        assert_eq!(
            entry.status,
            ScanUsagesStatus::Found,
            "the location target must still resolve and find its callers: {entry:#?}"
        );

        measurements.push((
            rust_tree_parsed_bytes_for_test(),
            rust_tree_parse_count_for_test(),
            rust_tree_parse_request_count_for_test(),
            workspace_bytes(&project),
        ));
    }

    let [
        (small_bytes, _, _, small_workspace),
        (large_bytes, large_parses, large_requests, large_workspace),
    ] = measurements[..]
    else {
        unreachable!("two measurements");
    };
    // Stated scale-free, as an amplification factor: bytes parsed per byte of
    // workspace. Adding reference sites grows the workspace a little (each site
    // is a line of code) but must not grow how many times the scan reads it.
    // Cross-multiplied to stay in integers.
    assert!(
        large_bytes.saturating_mul(small_workspace)
            <= small_bytes
                .saturating_mul(large_workspace)
                .saturating_mul(2),
        "parsed Rust bytes per workspace byte must not grow with the number of reference sites: \
         2 sites per file parsed {small_bytes} bytes of a {small_workspace}-byte workspace, \
         20 sites per file parsed {large_bytes} bytes of a {large_workspace}-byte workspace \
         ({large_parses} parses over {large_requests} requests)"
    );
    assert!(
        large_parses < large_requests,
        "the reference-site resolvers must be reaching the memo at all \
         ({large_parses} parses for {large_requests} parse requests)"
    );
}

/// The absolute bound behind the growth pin: a scan reads each distinct Rust
/// source through the parser about once, so the parsed byte count stays within
/// a small multiple of the workspace's own size however many times the
/// resolvers ask about those files.
#[test]
fn one_scan_parses_the_workspace_about_once() {
    let _guard = counter_lock();
    let project = reference_heavy_project(20);
    let analyzer = RustAnalyzer::from_project(project.project().clone());
    reset_rust_tree_parse_counters_for_test();

    let entry = scan_target_helper_by_location(&analyzer);
    assert_eq!(entry.status, ScanUsagesStatus::Found, "{entry:#?}");

    let workspace = workspace_bytes(&project);
    let parsed = rust_tree_parsed_bytes_for_test();
    assert!(
        parsed <= workspace.saturating_mul(3),
        "one scan_usages_by_location request must hand tree-sitter about one copy of the \
         workspace, got {parsed} bytes parsed for a {workspace}-byte workspace"
    );
}

/// The fix is a memo, not a behavior change: the usages themselves — status,
/// files, and per-file call-site counts — must be exactly what they were, and
/// must not depend on how many times a file was parsed.
#[test]
fn every_call_site_is_still_reported() {
    let _guard = counter_lock();
    let project = reference_heavy_project(3);
    let analyzer = RustAnalyzer::from_project(project.project().clone());

    let entry = scan_target_helper_by_location(&analyzer);
    assert_eq!(entry.status, ScanUsagesStatus::Found, "{entry:#?}");
    assert_eq!(
        call_sites(&entry),
        vec![
            "src/consumer0.rs:3".to_string(),
            "src/consumer1.rs:3".to_string(),
            "src/consumer2.rs:3".to_string(),
        ],
        "each consumer calls the target three times: {entry:#?}"
    );
}

/// The issue's second observation, pinned: a line-only target binds to the
/// declaration that owns the location, exactly as a matching fully qualified
/// selector does — same status, same call sites. Adding `symbol` is a
/// disambiguator, not a different query.
#[test]
fn line_only_and_selector_qualified_targets_agree() {
    let _guard = counter_lock();
    let project = reference_heavy_project(3);
    let analyzer = RustAnalyzer::from_project(project.project().clone());

    let line_only = scan_at(&analyzer, None);
    let selector = line_only
        .symbol
        .clone()
        .expect("a resolved location target reports the selector it bound to");
    let qualified = scan_at(&analyzer, Some(&selector));

    assert_eq!(line_only.status, ScanUsagesStatus::Found, "{line_only:#?}");
    assert_eq!(qualified.status, ScanUsagesStatus::Found, "{qualified:#?}");
    assert_eq!(
        call_sites(&line_only),
        call_sites(&qualified),
        "line-only and selector-qualified targets must report the same usages"
    );
}

#[test]
fn issue_1228_short_selector_at_exact_location_resolves_the_declaration() {
    let _guard = counter_lock();
    let project = reference_heavy_project(3);
    let analyzer = RustAnalyzer::from_project(project.project().clone());

    let short_qualified = scan_at(&analyzer, Some("target_helper"));

    assert_eq!(
        short_qualified.status,
        ScanUsagesStatus::Found,
        "a precise source location makes its matching short selector unambiguous: {short_qualified:#?}"
    );
    assert_eq!(
        call_sites(&short_qualified),
        vec![
            "src/consumer0.rs:3".to_string(),
            "src/consumer1.rs:3".to_string(),
            "src/consumer2.rs:3".to_string(),
        ]
    );
}
