use super::*;

#[test]
fn usage_graph_incompleteness_names_missing_edges() {
    let result = MostRelevantFilesResult {
        session_subset: None,
        files: Vec::new(),
        not_found: Vec::new(),
        ambiguous_paths: Vec::new(),
        duplicates: Vec::new(),
        complete: false,
        ranking_mode_used: crate::relevance::MostRelevantFilesRankingMode::UsageGraphExact,
        incomplete_reason: Some(MostRelevantFilesIncompleteReason::UsageGraphIncomplete),
    };

    let text = result.render_text(RenderOptions::default());
    assert!(text.contains("complete edge inventory"), "{text}");
    assert!(!text.contains("recent commit history"), "{text}");
}

#[test]
fn source_lookup_cancelled_before_any_verdict_reports_incompleteness() {
    let result = SymbolSourcesResult {
        sources: Vec::new(),
        not_found: Vec::new(),
        ambiguous: Vec::new(),
        ambiguous_paths: Vec::new(),
        too_broad: Vec::new(),
        complete: false,
        incomplete: Vec::new(),
    };

    let text = result.render_text(RenderOptions::default());
    assert!(
        text.contains("Incomplete: source lookup was cancelled"),
        "{text}"
    );
}

#[test]
fn source_lookup_unavailable_source_renders_target_and_detail_or_fallback() {
    use crate::searchtools::{SymbolSourcesIncomplete, SymbolSourcesIncompleteReason};

    let with_detail = SymbolSourcesResult {
        sources: Vec::new(),
        not_found: Vec::new(),
        ambiguous: Vec::new(),
        ambiguous_paths: Vec::new(),
        too_broad: Vec::new(),
        complete: false,
        incomplete: vec![SymbolSourcesIncomplete {
            target: "include/bad.h".to_string(),
            reason: SymbolSourcesIncompleteReason::SourceUnavailable,
            detail: Some("permission denied".to_string()),
        }],
    };
    let text_with_detail = with_detail.render_text(RenderOptions::default());
    assert_eq!(
        "Incomplete: `include/bad.h` (permission denied)",
        text_with_detail
    );

    let without_detail = SymbolSourcesResult {
        incomplete: vec![SymbolSourcesIncomplete {
            target: "include/bad.h".to_string(),
            reason: SymbolSourcesIncompleteReason::SourceUnavailable,
            detail: None,
        }],
        ..with_detail
    };
    let text_without_detail = without_detail.render_text(RenderOptions::default());
    assert_eq!(
        "Incomplete: `include/bad.h` (source content was unavailable)",
        text_without_detail
    );
}
