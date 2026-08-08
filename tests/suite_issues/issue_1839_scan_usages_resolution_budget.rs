//! Issue #1839: `scan_usages` symbol resolution had no budget of its own.
//!
//! The resolve path reads the identifier index and then charges one
//! `definitions` store read per matched declaration. On the rustc tree the
//! bare name `main` matched 20,935 declarations and the phase ran 653-749 s
//! against a 3 s scan budget, producing a `candidate_targets` list far larger
//! than the reply can carry.
//!
//! The fan-out half is pinned here, at the tool surface: an identifier that
//! more declarations answer than `SCAN_USAGES_MAX_RESOLUTION_CANDIDATES`
//! reports the true count and skips the candidate list, and the same tool call
//! one identifier under the cap is untouched. The cancellation half and the
//! per-candidate read counts are pinned inside the crate, next to the resolver
//! (`analyzer::symbol_lookup::tests`) and next to the store read
//! (`analyzer::tree_sitter_analyzer::tests`), where the budget and the
//! counters can be driven deterministically.
//!
//! The fixture puts every namesake in ONE file, as inline modules. The count
//! has to exceed a two-hundred-declaration cap, and two hundred separate files
//! would measure workspace analysis rather than resolution fan-out.

use crate::common::InlineTestProject;
use brokk_bifrost::searchtools::{
    SCAN_USAGES_MAX_RESOLUTION_CANDIDATES, ScanUsagesByReferenceParams, ScanUsagesEntry,
    ScanUsagesIncompleteReason, ScanUsagesStatus, scan_usages_by_reference,
};
use brokk_bifrost::{Language, RustAnalyzer};

/// A crate whose single source file declares `shared` in `count` distinct
/// modules, so one identifier names `count` distinct fq names.
fn namesakes(count: usize) -> ScanUsagesEntry {
    let mut lib = String::new();
    for index in 0..count {
        lib.push_str(&format!(
            "pub mod m{index} {{\n    pub fn shared() -> i32 {{ {index} }}\n}}\n"
        ));
    }
    lib.push_str("pub fn call_one() -> i32 {\n    m0::shared()\n}\n");

    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"namesakes\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[lib]\npath = \"src/lib.rs\"\n",
        )
        .file("src/lib.rs", lib)
        .build();
    let analyzer = RustAnalyzer::from_project(project.project().clone());

    let mut result = scan_usages_by_reference(
        &analyzer,
        ScanUsagesByReferenceParams {
            symbols: vec!["shared".to_string()],
            include_tests: true,
            paths: None,
            include_same_owner: false,
            max_duration_secs: None,
        },
    );
    assert_eq!(1, result.results.len(), "one requested symbol");
    result.results.remove(0)
}

#[test]
fn issue_1839_an_over_cap_identifier_reports_its_true_count_instead_of_a_candidate_list() {
    let over = SCAN_USAGES_MAX_RESOLUTION_CANDIDATES + 10;
    let entry = namesakes(over);

    assert_eq!(ScanUsagesStatus::Ambiguous, entry.status, "{entry:#?}");
    let too_many = entry
        .too_many_candidates
        .expect("an over-cap identifier reports the typed count block");
    assert_eq!(
        over, too_many.total_candidates,
        "the reported count must be the true match count, not the cap"
    );
    assert_eq!(SCAN_USAGES_MAX_RESOLUTION_CANDIDATES, too_many.cap);

    // Skipped, not truncated: an arbitrary subset of two hundred namesakes
    // would read as the answer while being useless.
    assert!(
        entry.candidate_targets.is_empty(),
        "no candidate list may be produced: {entry:#?}"
    );
    assert!(!entry.complete, "{entry:#?}");
    assert_eq!(
        Some(ScanUsagesIncompleteReason::ResolutionCandidates),
        entry.incomplete_reason,
        "{entry:#?}"
    );
    let message = entry.message.as_deref().unwrap_or_default();
    assert!(
        message.contains(&over.to_string())
            && message.contains(&SCAN_USAGES_MAX_RESOLUTION_CANDIDATES.to_string()),
        "the message must name the count and the cap: {message}"
    );
}

#[test]
fn issue_1839_an_under_cap_identifier_still_lists_its_candidates() {
    let entry = namesakes(5);

    assert_eq!(ScanUsagesStatus::Ambiguous, entry.status, "{entry:#?}");
    assert!(
        entry.too_many_candidates.is_none(),
        "an under-cap identifier must not trip the guard: {entry:#?}"
    );
    assert_eq!(
        5,
        entry.candidate_targets.len(),
        "every candidate must still be offered: {entry:#?}"
    );
    assert_ne!(
        Some(ScanUsagesIncompleteReason::ResolutionCandidates),
        entry.incomplete_reason,
        "{entry:#?}"
    );
}
