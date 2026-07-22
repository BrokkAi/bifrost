//! Service-probe tests for the MCP property fuzzer
//! (`src/mcp_property_fuzzer/service_probes.rs`).
//!
//! The firing tests fabricate `ProbeRecord`s directly so behavior is
//! deterministic and independent of whatever the analyzer/service happen to
//! do at HEAD (the same discipline as the I1 pure-checker tests); the
//! integration test runs the full pipeline — probe generation, service
//! execution in both render modes, all checkers — over a healthy
//! `InlineTestProject` fixture through a real `SearchToolsService`.

mod common;

use brokk_bifrost::Language;
use brokk_bifrost::mcp_property_fuzzer::service_probes::{
    ProbeKind, ProbeOutcome, ProbeRecord, ProbeSummary, check_i1c, check_i2, check_i3a, check_i3b,
    check_i3c, check_i4, check_i5, check_render_mode_drift, disputed_name, minimize_batch,
};
use brokk_bifrost::mcp_property_fuzzer::{
    FuzzerConfig, I1File, I1Input, InvariantKind, Violation, run_invariants_with_service,
};
use brokk_bifrost::searchtools_service::SearchToolsService;
use common::InlineTestProject;
use serde_json::{Value, json};

fn record(id: &str, tool: &'static str, kind: ProbeKind, structured: Value) -> ProbeRecord {
    ProbeRecord {
        id: id.to_string(),
        tool,
        arguments: json!({}),
        symbol_fq: "a.b.Foo".to_string(),
        symbol_path: "src/Foo.scala".to_string(),
        kind,
        outcome: Some(ProbeOutcome::Structured {
            structured,
            rendered_text: None,
            mode_b_structured: None,
        }),
        elapsed_ms: None,
    }
}

fn spelling(order: usize, spelling: &str, structured: Value) -> ProbeRecord {
    record(
        &format!("test#{order}"),
        "get_symbol_sources",
        ProbeKind::Spelling {
            order,
            spelling: spelling.to_string(),
        },
        structured,
    )
}

fn sources_block(path: &str, start_line: u64) -> Value {
    json!({"sources": [{"label": "a.b.Foo", "path": path, "start_line": start_line, "end_line": start_line + 5, "text": "..."}]})
}

fn refs(records: &[ProbeRecord]) -> Vec<&ProbeRecord> {
    records.iter().collect()
}

fn fuzzer_config(language: &str) -> FuzzerConfig {
    FuzzerConfig {
        corpus_language: language.to_string(),
        invariants: vec![
            InvariantKind::I1,
            InvariantKind::I2,
            InvariantKind::I3,
            InvariantKind::I4,
            InvariantKind::I5,
        ],
        max_symbols: 5_000,
        max_service_symbols: 1_000,
        max_scan_probes: 100,
        symbol_filter: None,
        path_filter: None,
        seed: 0,
    }
}

// ---------------------------------------------------------------------------
// I2 — selector-form equivalence
// ---------------------------------------------------------------------------

#[test]
fn i2_fires_when_more_specific_spelling_fails() {
    let records = vec![
        spelling(0, "Foo", sources_block("src/Foo.scala", 10)),
        spelling(1, "a.b.Foo", sources_block("src/Foo.scala", 10)),
        spelling(
            2,
            "src/Foo.scala#Foo",
            json!({"not_found": [{"input": "src/Foo.scala#Foo", "note": "no symbol matched"}]}),
        ),
        spelling(
            3,
            "src/Foo.scala#a.b.Foo",
            json!({"not_found": [{"input": "src/Foo.scala#a.b.Foo", "note": "no symbol matched"}]}),
        ),
    ];
    let mut sink = Default::default();
    let mut summary = ProbeSummary::default();
    check_i2(&refs(&records), "scala", &mut sink, &mut summary);
    let violations: Vec<Violation> = sink.into_sorted_vec();
    assert_eq!(violations.len(), 1, "{violations:?}");
    assert_eq!(violations[0].shape, "more-specific-spelling-fails");
    assert_eq!(
        violations[0].signature,
        "(I2, scala, get_symbol_sources, more-specific-spelling-fails)"
    );
}

#[test]
fn i2_silent_when_spellings_agree() {
    let records = vec![
        spelling(0, "Foo", sources_block("src/Foo.scala", 10)),
        spelling(1, "a.b.Foo", sources_block("src/Foo.scala", 10)),
        spelling(2, "src/Foo.scala#Foo", sources_block("src/Foo.scala", 10)),
        spelling(
            3,
            "src/Foo.scala#a.b.Foo",
            sources_block("src/Foo.scala", 10),
        ),
    ];
    let mut sink = Default::default();
    let mut summary = ProbeSummary::default();
    check_i2(&refs(&records), "scala", &mut sink, &mut summary);
    assert!(sink.into_sorted_vec().is_empty());
    assert_eq!(summary.i2_spelling_groups, 1);
}

#[test]
fn i2_fires_when_spellings_resolve_to_different_declarations() {
    let records = vec![
        spelling(0, "Foo", sources_block("src/One.scala", 10)),
        spelling(1, "a.b.Foo", sources_block("src/Two.scala", 20)),
        spelling(2, "src/One.scala#Foo", sources_block("src/One.scala", 10)),
        spelling(
            3,
            "src/One.scala#a.b.Foo",
            sources_block("src/One.scala", 10),
        ),
    ];
    let mut sink = Default::default();
    let mut summary = ProbeSummary::default();
    check_i2(&refs(&records), "scala", &mut sink, &mut summary);
    let violations = sink.into_sorted_vec();
    assert_eq!(violations.len(), 1, "{violations:?}");
    assert_eq!(
        violations[0].shape,
        "spelling-resolves-to-different-declaration"
    );
}

// Two files can define the same fq display name (parallel packages,
// cross-built source trees). Their spelling sets must stay separate groups:
// each is internally consistent, and merging them fabricates cross-file
// declaration drift no single symbol exhibits.
#[test]
fn i2_silent_when_same_fq_symbols_live_in_different_files() {
    let core_path = "packages/lsp-core/src/lsp/workspace-edit.ts";
    let senpi_path = "packages/omo-senpi/src/components/lsp/lsp/workspace-edit.ts";
    let mut records = vec![
        spelling(1, "ApplyResult.success", sources_block(core_path, 9)),
        spelling(
            3,
            "packages/lsp-core/src/lsp/workspace-edit.ts#ApplyResult.success",
            sources_block(core_path, 9),
        ),
        spelling(1, "ApplyResult.success", sources_block(senpi_path, 14)),
        spelling(
            3,
            "packages/omo-senpi/src/components/lsp/lsp/workspace-edit.ts#ApplyResult.success",
            sources_block(senpi_path, 14),
        ),
    ];
    for (index, record) in records.iter_mut().enumerate() {
        record.symbol_fq = "ApplyResult.success".to_string();
        record.symbol_path = if index < 2 { core_path } else { senpi_path }.to_string();
    }
    let mut sink = Default::default();
    let mut summary = ProbeSummary::default();
    check_i2(&refs(&records), "ts", &mut sink, &mut summary);
    assert_eq!(summary.i2_spelling_groups, 2);
    assert!(sink.into_sorted_vec().is_empty());
}

fn defs_spelling(
    order: usize,
    spelling: &str,
    context: &str,
    target: &str,
    status: &str,
) -> ProbeRecord {
    let mut record = record(
        &format!("defs#{order}"),
        "get_definitions_by_reference",
        ProbeKind::Spelling {
            order,
            spelling: spelling.to_string(),
        },
        json!({"results": [{"status": status}]}),
    );
    record.arguments = json!({
        "references": [{"context": context, "symbol": spelling, "target": target}],
    });
    record
}

fn defs_batch(spellings: &[&str], references: &[(&str, &str)], statuses: &[&str]) -> ProbeRecord {
    let mut record = record(
        "batch",
        "get_definitions_by_reference",
        ProbeKind::DefinitionBatch {
            spellings: spellings
                .iter()
                .map(|spelling| spelling.to_string())
                .collect(),
        },
        json!({"results": statuses.iter().map(|status| json!({"status": status})).collect::<Vec<_>>()}),
    );
    record.arguments = json!({
        "references": references.iter().zip(spellings.iter()).map(|((context, target), spelling)| {
            json!({"context": context, "symbol": spelling, "target": target})
        }).collect::<Vec<_>>(),
    });
    record
}

#[test]
fn i2_fires_when_batch_differs_from_single() {
    let records = vec![
        defs_spelling(0, "Foo", "ctx", "t", "resolved"),
        defs_spelling(2, "src/Foo.scala#Foo", "ctx", "t", "resolved"),
        defs_batch(
            &["Foo", "src/Foo.scala#Foo"],
            &[("ctx", "t"), ("ctx", "t")],
            &["resolved", "not_found"],
        ),
    ];
    let mut sink = Default::default();
    let mut summary = ProbeSummary::default();
    check_i2(&refs(&records), "scala", &mut sink, &mut summary);
    let violations = sink.into_sorted_vec();
    assert_eq!(violations.len(), 1, "{violations:?}");
    assert_eq!(violations[0].shape, "batch-outcome-differs-from-single");
}

// The bfg BenchmarkConfig shape: one spelling serves unrelated reference
// probes from different symbols, so the batch entry must be compared against
// the single call for its own reference, not whichever single the spelling
// last mapped.
#[test]
fn i2_silent_when_batch_entry_matches_its_own_references_single() {
    let mut scratch = defs_spelling(
        0,
        "BenchmarkConfig",
        "scratchDir: Path",
        "scratchDir",
        "no_definition",
    );
    scratch.symbol_fq = "BenchmarkConfig".to_string();
    let mut parser = defs_spelling(
        0,
        "BenchmarkConfig",
        "val parser = ...",
        "parser",
        "invalid_location",
    );
    parser.symbol_fq = "BenchmarkConfig$".to_string();
    let records = vec![
        scratch,
        parser,
        defs_batch(
            &["BenchmarkConfig"],
            &[("scratchDir: Path", "scratchDir")],
            &["no_definition"],
        ),
    ];
    let mut sink = Default::default();
    let mut summary = ProbeSummary::default();
    check_i2(&refs(&records), "scala", &mut sink, &mut summary);
    assert!(sink.into_sorted_vec().is_empty());
}

#[test]
fn minimize_batch_drops_only_entries_irrelevant_to_reproduction() {
    let references = vec![json!("a"), json!("b"), json!("c"), json!("d")];
    // The failure reproduces exactly while "b" is present in the batch.
    let shrunk = minimize_batch(&references, |candidate| {
        candidate.iter().any(|entry| entry == "b")
    });
    assert_eq!(shrunk, vec![json!("b")]);
}

#[test]
fn minimize_batch_keeps_every_entry_when_all_are_load_bearing() {
    let references = vec![json!("a"), json!("b"), json!("c")];
    // The failure reproduces only with the full batch: nothing can drop.
    let shrunk = minimize_batch(&references, |candidate| candidate.len() == 3);
    assert_eq!(shrunk, references);
}

#[test]
fn minimize_batch_keeps_a_two_entry_minimum_for_pair_dependent_failures() {
    let references = vec![json!("a"), json!("b"), json!("c")];
    // The failure needs "a" and "c" together; "b" is noise, and shrinking
    // below the reproducing pair must stop even though "a" alone fails too.
    let shrunk = minimize_batch(&references, |candidate| {
        candidate.iter().any(|entry| entry == "a") && candidate.iter().any(|entry| entry == "c")
    });
    assert_eq!(shrunk, vec![json!("a"), json!("c")]);
}

// Scala class/companion pairs share a user-level name but are distinct
// declarations: `$` spellings resolve to the companion object, stripped
// spellings to the class. Both are correct; consistency is required only
// within each declaration's spellings.
#[test]
fn i2_silent_when_class_and_companion_spellings_resolve_to_their_own_declarations() {
    let records = vec![
        spelling(0, "Foo", sources_block("src/One.scala", 10)),
        spelling(1, "Foo$", sources_block("src/One.scala", 1)),
        spelling(2, "src/One.scala#Foo", sources_block("src/One.scala", 10)),
        spelling(3, "src/One.scala#Foo$", sources_block("src/One.scala", 1)),
    ];
    let mut sink = Default::default();
    let mut summary = ProbeSummary::default();
    check_i2(&refs(&records), "scala", &mut sink, &mut summary);
    assert!(sink.into_sorted_vec().is_empty());
    assert_eq!(summary.i2_spelling_groups, 1);
}

#[test]
fn i2_silent_when_class_and_companion_diverge_at_the_location_stage() {
    let records = vec![
        defs_spelling(0, "Foo", "ctx", "t", "invalid_location"),
        defs_spelling(1, "Foo$", "ctx", "t", "resolved"),
        defs_spelling(2, "src/Foo.scala#Foo", "ctx", "t", "invalid_location"),
        defs_spelling(3, "src/Foo.scala#Foo$", "ctx", "t", "resolved"),
    ];
    let mut sink = Default::default();
    let mut summary = ProbeSummary::default();
    check_i2(&refs(&records), "scala", &mut sink, &mut summary);
    assert!(sink.into_sorted_vec().is_empty());
}

#[test]
fn i2_fires_when_one_declarations_spellings_drift_at_the_location_stage() {
    let records = vec![
        defs_spelling(0, "Foo", "ctx", "t", "invalid_location"),
        defs_spelling(1, "a.b.Foo", "ctx", "t", "no_definition"),
    ];
    let mut sink = Default::default();
    let mut summary = ProbeSummary::default();
    check_i2(&refs(&records), "scala", &mut sink, &mut summary);
    let violations = sink.into_sorted_vec();
    assert_eq!(violations.len(), 1, "{violations:?}");
    assert_eq!(violations[0].shape, "spelling-status-drift");
}

// ---------------------------------------------------------------------------
// I3 — cross-tool round-trips
// ---------------------------------------------------------------------------

#[test]
fn i3a_fires_when_summaries_listed_symbol_is_unresolvable() {
    let records = vec![record(
        "i3a",
        "get_symbol_sources",
        ProbeKind::SummaryElementSource {
            element_path: "src/Foo.scala".to_string(),
        },
        json!({"not_found": [{"input": "a.b.Foo.bar"}]}),
    )];
    let mut sink = Default::default();
    let mut summary = ProbeSummary::default();
    check_i3a(&refs(&records), "scala", &mut sink, &mut summary);
    let violations = sink.into_sorted_vec();
    assert_eq!(violations.len(), 1, "{violations:?}");
    assert_eq!(violations[0].shape, "summaries-listed-symbol-unresolvable");
}

// Bare element names collide across a large workspace; ambiguity that offers
// the listed file's own `path#symbol` selector resolves the element from its
// listing context and is not a violation (the oh-my-openagent ts shape).
#[test]
fn i3a_silent_when_ambiguity_offers_the_listed_paths_own_selector() {
    let records = vec![record(
        "i3a",
        "get_symbol_sources",
        ProbeKind::SummaryElementSource {
            element_path: "packages/a/install.mjs".to_string(),
        },
        json!({
            "ambiguous": [{
                "target": "resolveXdgDataDir",
                "matches": [
                    "packages/a/install.mjs#resolveXdgDataDir",
                    "packages/utils/xdg.ts#resolveXdgDataDir"
                ]
            }],
            "not_found": [],
            "sources": []
        }),
    )];
    let mut sink = Default::default();
    let mut summary = ProbeSummary::default();
    check_i3a(&refs(&records), "ts", &mut sink, &mut summary);
    assert!(sink.into_sorted_vec().is_empty());
}

// Ambiguity whose matches exclude the listed path leaves the element
// unresolvable from its listing context (the bfg shape: the emitted spelling
// maps to no exact declaration).
#[test]
fn i3a_fires_when_ambiguity_excludes_the_listed_path() {
    let records = vec![record(
        "i3a",
        "get_symbol_sources",
        ProbeKind::SummaryElementSource {
            element_path: "src/LFS.scala".to_string(),
        },
        json!({
            "ambiguous": [{
                "target": "com.madgag.git.LFS.Pointer",
                "matches": [
                    "com.madgag.git.LFS$.Pointer",
                    "com.madgag.git.LFS$.Pointer$"
                ]
            }],
            "not_found": [],
            "sources": []
        }),
    )];
    let mut sink = Default::default();
    let mut summary = ProbeSummary::default();
    check_i3a(&refs(&records), "scala", &mut sink, &mut summary);
    let violations = sink.into_sorted_vec();
    assert_eq!(violations.len(), 1, "{violations:?}");
    assert_eq!(violations[0].shape, "summaries-listed-symbol-unresolvable");
}

#[test]
fn i3a_fires_when_reported_path_differs_from_listed_path() {
    let records = vec![record(
        "i3a",
        "get_symbol_sources",
        ProbeKind::SummaryElementSource {
            element_path: "src/Foo.scala".to_string(),
        },
        sources_block("src/Other.scala", 3),
    )];
    let mut sink = Default::default();
    let mut summary = ProbeSummary::default();
    check_i3a(&refs(&records), "scala", &mut sink, &mut summary);
    let violations = sink.into_sorted_vec();
    assert_eq!(violations.len(), 1, "{violations:?}");
    assert_eq!(violations[0].shape, "summaries-listed-symbol-path-mismatch");
}

#[test]
fn i3b_fires_when_scan_resolved_symbol_is_absent_from_search() {
    let records = vec![record(
        "i3b",
        "search_symbols",
        ProbeKind::ScanSearch {
            expected_display_fq: "a.b.Foo.bar".to_string(),
            expected_path: "src/Foo.scala".to_string(),
            is_module: false,
        },
        json!({"files": [], "total_files": 0, "note": "No files matched."}),
    )];
    let mut sink = Default::default();
    let mut summary = ProbeSummary::default();
    check_i3b(&refs(&records), "scala", &mut sink, &mut summary);
    let violations = sink.into_sorted_vec();
    assert_eq!(violations.len(), 1, "{violations:?}");
    assert_eq!(
        violations[0].shape,
        "scan-resolved-symbol-absent-from-search"
    );
}

#[test]
fn i3b_silent_when_search_lists_the_declaration() {
    let records = vec![record(
        "i3b",
        "search_symbols",
        ProbeKind::ScanSearch {
            expected_display_fq: "a.b.Foo.bar".to_string(),
            expected_path: "src/Foo.scala".to_string(),
            is_module: false,
        },
        json!({"files": [{"path": "src/Foo.scala", "functions": [{"symbol": "a.b.Foo.bar", "line": 12}]}]}),
    )];
    let mut sink = Default::default();
    let mut summary = ProbeSummary::default();
    check_i3b(&refs(&records), "scala", &mut sink, &mut summary);
    assert!(sink.into_sorted_vec().is_empty());
    assert_eq!(summary.i3b_scan_resolution_checks, 1);
}

// Absence from a result set cut by the file limit is unverifiable (the
// "constructor" case: hundreds of legit hits, the target ranked out).
#[test]
fn i3b_skips_truncated_result_sets() {
    let records = vec![record(
        "i3b",
        "search_symbols",
        ProbeKind::ScanSearch {
            expected_display_fq: "a.b.Foo.bar".to_string(),
            expected_path: "src/Foo.scala".to_string(),
            is_module: false,
        },
        json!({"files": [{"path": "src/Other.scala", "functions": [{"symbol": "a.b.Other.bar", "line": 1}]}], "total_files": 40, "truncated": true}),
    )];
    let mut sink = Default::default();
    let mut summary = ProbeSummary::default();
    check_i3b(&refs(&records), "scala", &mut sink, &mut summary);
    assert_eq!(summary.skipped_scan_search_truncated, 1);
    assert!(sink.into_sorted_vec().is_empty());
}

// A module unit's "name" is its file path; search_symbols has no contract
// to find it as a symbol (the I1(b) module naming convention).
#[test]
fn i3b_skips_module_scan_targets() {
    let records = vec![record(
        "i3b",
        "search_symbols",
        ProbeKind::ScanSearch {
            expected_display_fq: "aggregate-model-catalog.test.mjs".to_string(),
            expected_path: "scripts/aggregate-model-catalog.test.mjs".to_string(),
            is_module: true,
        },
        json!({"files": [], "total_files": 0, "truncated": false}),
    )];
    let mut sink = Default::default();
    let mut summary = ProbeSummary::default();
    check_i3b(&refs(&records), "ts", &mut sink, &mut summary);
    assert_eq!(summary.skipped_scan_search_module, 1);
    assert!(sink.into_sorted_vec().is_empty());
}

#[test]
fn i3c_fires_when_response_renders_and_not_founds_same_target() {
    // The doctrine/orm shape: the response rendered every member file of
    // `src/Query/Expr` and then appended `Not found: src/Query/Expr`.
    let records = vec![record(
        "i3c",
        "get_summaries",
        ProbeKind::SummaryFile,
        json!({
            "summaries": [{"label": "src/Query/Expr", "elements": []}],
            "not_found": [{"input": "src/Query/Expr", "note": "no workspace file matched"}],
        }),
    )];
    let mut sink = Default::default();
    let mut summary = ProbeSummary::default();
    check_i3c(&refs(&records), "php", &mut sink, &mut summary);
    let violations = sink.into_sorted_vec();
    assert_eq!(violations.len(), 1, "{violations:?}");
    assert_eq!(
        violations[0].shape,
        "response-renders-and-not-founds-same-target"
    );
}

#[test]
fn i3c_silent_when_not_found_targets_have_no_content() {
    let records = vec![record(
        "i3c",
        "get_summaries",
        ProbeKind::SummaryFile,
        json!({
            "summaries": [{"label": "src/Foo.scala", "elements": []}],
            "not_found": [{"input": "src/Missing.scala", "note": "no workspace file matched"}],
        }),
    )];
    let mut sink = Default::default();
    let mut summary = ProbeSummary::default();
    check_i3c(&refs(&records), "scala", &mut sink, &mut summary);
    assert!(sink.into_sorted_vec().is_empty());
    assert_eq!(summary.i3c_contradiction_checks, 1);
}

// ---------------------------------------------------------------------------
// I4 — diagnostic honesty
// ---------------------------------------------------------------------------

#[test]
fn i4_fires_when_failure_claims_not_indexed_but_symbol_exists() {
    let records = vec![record(
        "i4",
        "search_symbols",
        ProbeKind::HonestySearch {
            failed_selector: "a.b.Foo.bar".to_string(),
            disputed_name: "a.b.Foo.bar".to_string(),
            claim_excerpt: "unresolvable_import_boundary: bar is not indexed in this workspace"
                .to_string(),
            origin_tool: "get_definitions_by_reference",
        },
        json!({"files": [{"path": "src/Foo.scala", "functions": [{"symbol": "a.b.Foo.bar", "line": 12}]}]}),
    )];
    let mut sink = Default::default();
    let mut summary = ProbeSummary::default();
    check_i4(&refs(&records), "scala", &mut sink, &mut summary);
    let violations = sink.into_sorted_vec();
    assert_eq!(violations.len(), 1, "{violations:?}");
    assert_eq!(
        violations[0].signature,
        "(I4, scala, get_definitions_by_reference, failure-message-claims-not-indexed-but-symbol-exists)"
    );
}

#[test]
fn i4_silent_when_search_confirms_the_absence() {
    let records = vec![record(
        "i4",
        "search_symbols",
        ProbeKind::HonestySearch {
            failed_selector: "a.b.Foo.missing".to_string(),
            disputed_name: "a.b.Foo.missing".to_string(),
            claim_excerpt: "not indexed in this workspace".to_string(),
            origin_tool: "scan_usages_by_reference",
        },
        json!({"files": [], "total_files": 0}),
    )];
    let mut sink = Default::default();
    let mut summary = ProbeSummary::default();
    check_i4(&refs(&records), "scala", &mut sink, &mut summary);
    assert!(sink.into_sorted_vec().is_empty());
    assert_eq!(summary.i4_honesty_checks, 1);
}

// The bfg/TheHive family: resolving `ConcurrentSet` fails honestly because
// the reference chain crosses to the (genuinely unindexed) stdlib
// `AbstractSet`; the message never claims the selector itself is unindexed,
// so the indexed selector is not a contradiction.
#[test]
fn i4_silent_when_the_disputed_boundary_name_is_genuinely_unindexed() {
    let records = vec![record(
        "i4",
        "search_symbols",
        ProbeKind::HonestySearch {
            failed_selector: "com.madgag.collection.concurrent.ConcurrentSet".to_string(),
            disputed_name: "AbstractSet".to_string(),
            claim_excerpt: "`AbstractSet[A]` appears to cross a Scala import boundary not indexed in this workspace".to_string(),
            origin_tool: "get_definitions_by_reference",
        },
        json!({"files": [], "total_files": 0}),
    )];
    let mut sink = Default::default();
    let mut summary = ProbeSummary::default();
    check_i4(&refs(&records), "scala", &mut sink, &mut summary);
    assert!(sink.into_sorted_vec().is_empty());
    assert_eq!(summary.i4_honesty_checks, 1);
}

#[test]
fn i4_fires_when_the_disputed_name_is_indexed() {
    let records = vec![record(
        "i4",
        "search_symbols",
        ProbeKind::HonestySearch {
            failed_selector: "a.b.Foo.bar".to_string(),
            disputed_name: "a.b.Baz.quux".to_string(),
            claim_excerpt: "`quux` is bound by an explicit Scala import whose declaration is not indexed in this workspace".to_string(),
            origin_tool: "get_definitions_by_reference",
        },
        json!({"files": [{"path": "src/Baz.scala", "functions": [{"symbol": "a.b.Baz.quux", "line": 7}]}]}),
    )];
    let mut sink = Default::default();
    let mut summary = ProbeSummary::default();
    check_i4(&refs(&records), "scala", &mut sink, &mut summary);
    let violations = sink.into_sorted_vec();
    assert_eq!(violations.len(), 1, "{violations:?}");
    assert_eq!(
        violations[0].signature,
        "(I4, scala, get_definitions_by_reference, failure-message-claims-not-indexed-but-symbol-exists)"
    );
}

// The TheHive getHealth shape: "`Success[_]` not indexed" is honest about
// scala.util.Success even though an unrelated JobStatus.Success exists in
// the workspace — an unqualified disputed name is scope-relative, and a hit
// outside the probed file proves nothing.
#[test]
fn i4_silent_when_unqualified_hit_is_outside_the_probed_file() {
    let records = vec![record(
        "i4",
        "search_symbols",
        ProbeKind::HonestySearch {
            failed_selector: "org.thp.cortex.client.CortexClient.getHealth".to_string(),
            disputed_name: "Success".to_string(),
            claim_excerpt: "`Success[_]` appears to cross a Scala import boundary not indexed in this workspace".to_string(),
            origin_tool: "get_definitions_by_reference",
        },
        json!({"files": [{"path": "cortex/dto/src/main/scala/org/thp/cortex/dto/v0/Job.scala", "classes": [{"symbol": "org.thp.cortex.dto.v0.JobStatus.Success", "line": 12}]}]}),
    )];
    let mut sink = Default::default();
    let mut summary = ProbeSummary::default();
    check_i4(&refs(&records), "scala", &mut sink, &mut summary);
    assert!(sink.into_sorted_vec().is_empty());
    assert_eq!(summary.i4_honesty_checks, 1);
}

#[test]
fn i4_fires_when_unqualified_disputed_name_is_in_the_probed_file() {
    let records = vec![record(
        "i4",
        "search_symbols",
        ProbeKind::HonestySearch {
            failed_selector: "a.b.Foo.quux".to_string(),
            disputed_name: "quux".to_string(),
            claim_excerpt: "`quux` is bound by an explicit Scala import whose declaration is not indexed in this workspace".to_string(),
            origin_tool: "get_definitions_by_reference",
        },
        json!({"files": [{"path": "src/Foo.scala", "functions": [{"symbol": "a.b.Foo.quux", "line": 7}]}]}),
    )];
    let mut sink = Default::default();
    let mut summary = ProbeSummary::default();
    check_i4(&refs(&records), "scala", &mut sink, &mut summary);
    let violations = sink.into_sorted_vec();
    assert_eq!(violations.len(), 1, "{violations:?}");
    assert_eq!(
        violations[0].signature,
        "(I4, scala, get_definitions_by_reference, failure-message-claims-not-indexed-but-symbol-exists)"
    );
}

// The claim templates name their subject in backticks: the first form leads
// with it, the PHP form puts the boundary owner last, type arguments are
// stripped, and a subject-less message falls back to the failed selector.
#[test]
fn i4_disputed_name_extraction_matches_claim_templates() {
    let cases = [
        (
            "sel",
            "`AbstractSet[A]` appears to cross a Scala import boundary not indexed in this workspace",
            "AbstractSet",
        ),
        (
            "sel",
            "`ConcurrentSet` appears to cross a PHP boundary at `AbstractSet` not indexed in this workspace",
            "AbstractSet",
        ),
        (
            "sel",
            "`Reads` is bound by an explicit Scala import whose declaration is not indexed in this workspace",
            "Reads",
        ),
        (
            "a.b.Foo.bar",
            "bar is not indexed in this workspace",
            "a.b.Foo.bar",
        ),
    ];
    for (selector, message, expected) in cases {
        assert_eq!(disputed_name(selector, message), expected, "{message}");
    }
}

// ---------------------------------------------------------------------------
// I5 — hint presence
// ---------------------------------------------------------------------------

#[test]
fn i5_fires_on_failure_responses_without_hints() {
    let records = vec![
        record(
            "i5:sources",
            "get_symbol_sources",
            ProbeKind::Negative {
                shape: "keyword-prefixed-selector",
            },
            json!({"not_found": [{"input": "src/foo.c::struct Foo"}]}),
        ),
        record(
            "i5:scan",
            "scan_usages_by_reference",
            ProbeKind::Negative {
                shape: "path-passed-as-symbol",
            },
            json!({"results": [{"input": "src/Foo.scala", "status": "ambiguous"}]}),
        ),
        record(
            "i5:search",
            "search_symbols",
            ProbeKind::HonestySearch {
                failed_selector: "a.b.Foo".to_string(),
                disputed_name: "a.b.Foo".to_string(),
                claim_excerpt: String::new(),
                origin_tool: "get_symbol_sources",
            },
            json!({"files": [], "total_files": 0}),
        ),
    ];
    let mut sink = Default::default();
    let mut summary = ProbeSummary::default();
    check_i5(&refs(&records), "scala", &mut sink, &mut summary);
    let violations = sink.into_sorted_vec();
    assert_eq!(violations.len(), 3, "{violations:?}");
    assert!(
        violations
            .iter()
            .all(|violation| violation.shape == "empty-failure-hint")
    );
    assert_eq!(summary.i5_hint_checks, 3);
}

#[test]
fn i5_silent_when_failures_carry_hints() {
    let records = vec![
        record(
            "i5:sources",
            "get_symbol_sources",
            ProbeKind::Negative {
                shape: "keyword-prefixed-selector",
            },
            json!({"not_found": [{"input": "src/foo.c::struct Foo", "note": "no symbol matched; try search_symbols with a substring or regex pattern"}]}),
        ),
        record(
            "i5:definitions",
            "get_definitions_by_reference",
            ProbeKind::Spelling {
                order: 0,
                spelling: "Foo".to_string(),
            },
            json!({"results": [{"status": "not_found", "diagnostics": [{"kind": "symbol_not_found", "message": "`Foo` does not resolve to a workspace symbol"}]}]}),
        ),
        // Path ambiguity with re-callable matches is actionable guidance,
        // not an empty refusal (go/cli `main` shape).
        record(
            "i5:path-ambiguity",
            "get_symbol_sources",
            ProbeKind::Spelling {
                order: 0,
                spelling: "main".to_string(),
            },
            json!({"ambiguous": [], "ambiguous_paths": [{"input": "main", "matches": ["git/fixtures/simple.git/refs/heads/main"]}], "not_found": [], "sources": []}),
        ),
    ];
    let mut sink = Default::default();
    let mut summary = ProbeSummary::default();
    check_i5(&refs(&records), "scala", &mut sink, &mut summary);
    assert!(sink.into_sorted_vec().is_empty());
}

#[test]
fn i5_fires_when_ambiguous_paths_carry_no_matches() {
    let records = vec![record(
        "i5:path-ambiguity",
        "get_symbol_sources",
        ProbeKind::Spelling {
            order: 0,
            spelling: "main".to_string(),
        },
        json!({"ambiguous": [], "ambiguous_paths": [{"input": "main", "matches": []}], "not_found": [], "sources": []}),
    )];
    let mut sink = Default::default();
    let mut summary = ProbeSummary::default();
    check_i5(&refs(&records), "scala", &mut sink, &mut summary);
    let violations = sink.into_sorted_vec();
    assert_eq!(violations.len(), 1, "{violations:?}");
    assert_eq!(violations[0].shape, "empty-failure-hint");
}

// ---------------------------------------------------------------------------
// I1(c) and render-mode drift
// ---------------------------------------------------------------------------

#[test]
fn i1c_fires_when_source_text_differs_from_range() {
    let input = I1Input {
        files: vec![I1File {
            path: "src/Foo.scala".to_string(),
            text: Some("class Foo {\n  def bar: Int = 1\n}\n".to_string()),
            parse_errors: Some(vec![]),
        }],
        symbols: vec![],
    };
    let records = vec![record(
        "i1c",
        "get_symbol_sources",
        ProbeKind::Spelling {
            order: 0,
            spelling: "Foo".to_string(),
        },
        json!({"sources": [{"label": "a.b.Foo", "path": "src/Foo.scala", "start_line": 1, "end_line": 3, "text": "class Foo {\n  def bar: Int = 2\n}"}]}),
    )];
    let mut sink = Default::default();
    let mut summary = ProbeSummary::default();
    check_i1c(&refs(&records), &input, "scala", &mut sink, &mut summary);
    let violations = sink.into_sorted_vec();
    assert_eq!(violations.len(), 1, "{violations:?}");
    assert_eq!(
        violations[0].signature,
        "(I1, scala, get_symbol_sources, source-text-differs-from-range)"
    );
}

// A block from a file outside the sample is unverifiable from this run's
// input: skip, never fire (the oh-my-openagent case — a probe resolved into
// a file no sampled symbol declares in).
#[test]
fn i1c_skips_blocks_in_files_outside_the_sample() {
    let input = I1Input {
        files: vec![I1File {
            path: "src/hook.ts".to_string(),
            text: Some("export const x = 1\n".to_string()),
            parse_errors: Some(vec![]),
        }],
        symbols: vec![],
    };
    let records = vec![record(
        "i1c",
        "get_symbol_sources",
        ProbeKind::Spelling {
            order: 0,
            spelling: "getCachedVersion".to_string(),
        },
        json!({"sources": [{"label": "getCachedVersion", "path": "src/checker/cached-version.ts", "start_line": 22, "end_line": 79, "text": "export function getCachedVersion() {}"}]}),
    )];
    let mut sink = Default::default();
    let mut summary = ProbeSummary::default();
    check_i1c(&refs(&records), &input, "ts", &mut sink, &mut summary);
    assert_eq!(summary.skipped_unsampled_source, 1);
    assert!(sink.into_sorted_vec().is_empty());
}

// With the file's text in hand, a range running past indexed EOF is the
// genuine violation the shape exists for.
#[test]
fn i1c_fires_when_reported_range_exceeds_the_sampled_file() {
    let input = I1Input {
        files: vec![I1File {
            path: "src/Foo.scala".to_string(),
            text: Some("class Foo {\n  def bar: Int = 1\n}\n".to_string()),
            parse_errors: Some(vec![]),
        }],
        symbols: vec![],
    };
    let records = vec![record(
        "i1c",
        "get_symbol_sources",
        ProbeKind::Spelling {
            order: 0,
            spelling: "Foo".to_string(),
        },
        json!({"sources": [{"label": "a.b.Foo", "path": "src/Foo.scala", "start_line": 2, "end_line": 9, "text": "def bar: Int = 1"}]}),
    )];
    let mut sink = Default::default();
    let mut summary = ProbeSummary::default();
    check_i1c(&refs(&records), &input, "scala", &mut sink, &mut summary);
    let violations = sink.into_sorted_vec();
    assert_eq!(violations.len(), 1, "{violations:?}");
    assert_eq!(
        violations[0].signature,
        "(I1, scala, get_symbol_sources, source-range-outside-sampled-source)"
    );
}

#[test]
fn i1c_silent_when_text_matches_range() {
    let input = I1Input {
        files: vec![I1File {
            path: "src/Foo.scala".to_string(),
            text: Some("class Foo {\n  def bar: Int = 1\n}\n".to_string()),
            parse_errors: Some(vec![]),
        }],
        symbols: vec![],
    };
    let records = vec![record(
        "i1c",
        "get_symbol_sources",
        ProbeKind::Spelling {
            order: 0,
            spelling: "Foo".to_string(),
        },
        json!({"sources": [{"label": "a.b.Foo", "path": "src/Foo.scala", "start_line": 1, "end_line": 3, "text": "class Foo {\n  def bar: Int = 1\n}"}]}),
    )];
    let mut sink = Default::default();
    let mut summary = ProbeSummary::default();
    check_i1c(&refs(&records), &input, "scala", &mut sink, &mut summary);
    assert!(sink.into_sorted_vec().is_empty());
    assert_eq!(summary.i1c_source_text_checks, 1);
}

// The tool slices the declaration's exact byte range, so an indented
// declaration's first line starts at its first token rather than at line
// start (this is the shape every nested method/class block takes).
#[test]
fn i1c_silent_when_indented_declaration_starts_mid_line() {
    let input = I1Input {
        files: vec![I1File {
            path: "src/Foo.scala".to_string(),
            text: Some("class Foo {\n  def bar: Int = 1\n  def baz: Int = 2\n}\n".to_string()),
            parse_errors: Some(vec![]),
        }],
        symbols: vec![],
    };
    let records = vec![record(
        "i1c",
        "get_symbol_sources",
        ProbeKind::Spelling {
            order: 0,
            spelling: "Foo.bar".to_string(),
        },
        json!({"sources": [{"label": "a.b.Foo.bar", "path": "src/Foo.scala", "start_line": 2, "end_line": 3, "text": "def bar: Int = 1\n  def baz: Int = 2"}]}),
    )];
    let mut sink = Default::default();
    let mut summary = ProbeSummary::default();
    check_i1c(&refs(&records), &input, "scala", &mut sink, &mut summary);
    assert!(sink.into_sorted_vec().is_empty());
    assert_eq!(summary.i1c_source_text_checks, 1);
}

// A single-line declaration nested mid-line (compact code) is a substring of
// its reported line, not necessarily an affix.
#[test]
fn i1c_silent_when_single_line_block_sits_mid_line() {
    let input = I1Input {
        files: vec![I1File {
            path: "src/Foo.scala".to_string(),
            text: Some("class Foo { def bar: Int = 1 }\n".to_string()),
            parse_errors: Some(vec![]),
        }],
        symbols: vec![],
    };
    let records = vec![record(
        "i1c",
        "get_symbol_sources",
        ProbeKind::Spelling {
            order: 0,
            spelling: "Foo.bar".to_string(),
        },
        json!({"sources": [{"label": "a.b.Foo.bar", "path": "src/Foo.scala", "start_line": 1, "end_line": 1, "text": "def bar: Int = 1"}]}),
    )];
    let mut sink = Default::default();
    let mut summary = ProbeSummary::default();
    check_i1c(&refs(&records), &input, "scala", &mut sink, &mut summary);
    assert!(sink.into_sorted_vec().is_empty());
    assert_eq!(summary.i1c_source_text_checks, 1);
}

// The bfg InvocableBFG.processFor shape: the reported range's last line is
// blank and the returned text faithfully carries it. The comparison must not
// lose that trailing blank line to a join/re-split round trip.
#[test]
fn i1c_silent_when_block_ends_with_a_blank_line() {
    let input = I1Input {
        files: vec![I1File {
            path: "src/Foo.scala".to_string(),
            text: Some("def processFor =\n    Process(x)\n\ndef next = 2\n".to_string()),
            parse_errors: Some(vec![]),
        }],
        symbols: vec![],
    };
    let records = vec![record(
        "i1c",
        "get_symbol_sources",
        ProbeKind::Spelling {
            order: 0,
            spelling: "Foo.processFor".to_string(),
        },
        json!({"sources": [{"label": "a.b.Foo.processFor", "path": "src/Foo.scala", "start_line": 1, "end_line": 3, "text": "def processFor =\n    Process(x)\n\n"}]}),
    )];
    let mut sink = Default::default();
    let mut summary = ProbeSummary::default();
    check_i1c(&refs(&records), &input, "scala", &mut sink, &mut summary);
    assert!(sink.into_sorted_vec().is_empty());
    assert_eq!(summary.i1c_source_text_checks, 1);
}

// The TheHive CortexClientTest.client shape: a file-target probe returns a
// synthetic flat outline whose range is expressed in the outline's own
// coordinates (start 1..outline length), marked with a `note`. Like
// `presentation` blocks, it makes no whole-source claim.
#[test]
fn i1c_silent_for_noted_file_outline_blocks() {
    let input = I1Input {
        files: vec![I1File {
            path: "src/Foo.scala".to_string(),
            text: Some("package a.b\n\nclass Foo\n".to_string()),
            parse_errors: Some(vec![]),
        }],
        symbols: vec![],
    };
    let records = vec![record(
        "i1c",
        "get_symbol_sources",
        ProbeKind::Spelling {
            order: 0,
            spelling: "Foo".to_string(),
        },
        json!({"sources": [{"label": "src/Foo.scala", "path": "src/Foo.scala", "start_line": 1, "end_line": 2, "text": "# a.b\n- Foo", "note": "file target: showing a flat outline of top-level symbols, not the full source"}]}),
    )];
    let mut sink = Default::default();
    let mut summary = ProbeSummary::default();
    check_i1c(&refs(&records), &input, "scala", &mut sink, &mut summary);
    assert!(sink.into_sorted_vec().is_empty());
    assert_eq!(summary.i1c_source_text_checks, 0);
}

#[test]
fn render_mode_drift_fires_when_structured_payload_differs() {
    let mut drifted = record(
        "drift",
        "get_summaries",
        ProbeKind::SummaryFile,
        json!({"summaries": [{"label": "src/Foo.scala"}]}),
    );
    if let Some(ProbeOutcome::Structured {
        mode_b_structured, ..
    }) = &mut drifted.outcome
    {
        *mode_b_structured = Some(json!({"summaries": []}));
    }
    let records = vec![drifted];
    let mut sink = Default::default();
    check_render_mode_drift(&refs(&records), "scala", &mut sink);
    let violations = sink.into_sorted_vec();
    assert_eq!(violations.len(), 1, "{violations:?}");
    assert_eq!(violations[0].shape, "render-mode-structured-drift");
}

// ---------------------------------------------------------------------------
// Full-pipeline integration: healthy fixture through a real service
// ---------------------------------------------------------------------------

/// Healthy Scala fixture, all five invariants: probe generation, execution in
/// both render modes, and every checker run for real — and report nothing.
/// The summary counters pin down that each checker actually saw input, so
/// silence here is audited, not vacuous.
#[test]
fn service_invariants_silent_on_healthy_scala_fixture() {
    let project = InlineTestProject::new()
        .file(
            "src/Greeter.scala",
            "package com.example\n\nclass Greeter {\n  def greet(name: String): String = \"hello \" + name\n  def twice(name: String): String = greet(name) + greet(name)\n}\n",
        )
        .file(
            "src/Main.scala",
            "package com.example\n\nobject Main {\n  def run(): Unit = {\n    val greeter = new Greeter()\n    println(greeter.twice(\"world\"))\n  }\n}\n",
        )
        .build();
    let service =
        SearchToolsService::new_manual_without_semantic_index(project.root().to_path_buf())
            .expect("service");
    let workspace = service.analyzer_snapshot().expect("analyzer snapshot");
    let report = run_invariants_with_service(
        &service,
        workspace.analyzer(),
        &fuzzer_config("scala"),
        None,
        // Exercise the parallel probe path even in tests: outcomes land in
        // fixed slots, so parallelism must not change findings.
        4,
    )
    .expect("run invariants");
    let summary = report.probe_summary.as_ref().expect("probe summary");
    assert!(summary.symbols_sampled > 0, "{summary:?}");
    assert!(summary.selector_probes > 0, "{summary:?}");
    assert!(summary.definition_probes > 0, "{summary:?}");
    assert!(summary.summary_probes > 0, "{summary:?}");
    assert!(summary.scan_probes > 0, "{summary:?}");
    assert!(summary.negative_probes > 0, "{summary:?}");
    assert!(summary.calls_executed > 0, "{summary:?}");
    assert!(summary.render_mode_comparisons > 0, "{summary:?}");
    assert_eq!(summary.calls_errored, 0, "{summary:?}");
    assert!(summary.i2_spelling_groups > 0, "{summary:?}");
    assert!(summary.i1c_source_text_checks > 0, "{summary:?}");
    assert!(summary.i3a_summary_element_checks > 0, "{summary:?}");
    assert!(summary.i5_hint_checks > 0, "{summary:?}");
    assert!(
        report.violations.is_empty(),
        "{}",
        serde_json::to_string_pretty(&report.violations).expect("violations json")
    );
}

// Java package declarations appear as module-kind summary elements under
// every file that declares them; they must not generate I3(a) follow-ups.
#[test]
fn java_module_summary_elements_are_skipped() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "src/main/java/com/example/Greeter.java",
            "package com.example;\n\npublic class Greeter {\n    public String greet(String name) {\n        return \"hello \" + name;\n    }\n}\n",
        )
        .build();
    let service =
        SearchToolsService::new_manual_without_semantic_index(project.root().to_path_buf())
            .expect("service");
    let workspace = service.analyzer_snapshot().expect("analyzer snapshot");
    let report = run_invariants_with_service(
        &service,
        workspace.analyzer(),
        &fuzzer_config("java"),
        None,
        4,
    )
    .expect("run invariants");
    let summary = report.probe_summary.as_ref().expect("probe summary");
    assert!(
        summary.skipped_module_summary_element > 0,
        "package element should be skipped: {summary:?}"
    );
}

// Go package-level blank identifiers (`var _ = ...`) are unaddressable and
// share one fq per package; probing them fabricates path mismatches.
#[test]
fn go_blank_identifiers_are_excluded_from_probing() {
    let project = InlineTestProject::with_language(Language::Go)
        .file(
            "pkg/obs/telemetry.go",
            "package obs\n\nvar _ = compute()\n\nfunc compute() int { return 1 }\n\ntype Meter struct{ v int }\n\nfunc (m *Meter) Inc() { m.v++ }\n",
        )
        .build();
    let service =
        SearchToolsService::new_manual_without_semantic_index(project.root().to_path_buf())
            .expect("service");
    let workspace = service.analyzer_snapshot().expect("analyzer snapshot");
    let report = run_invariants_with_service(
        &service,
        workspace.analyzer(),
        &fuzzer_config("go"),
        None,
        4,
    )
    .expect("run invariants");
    let summary = report.probe_summary.as_ref().expect("probe summary");
    assert!(
        summary.symbols_excluded_blank_identifier > 0,
        "blank identifier should be excluded: {summary:?}"
    );
}
