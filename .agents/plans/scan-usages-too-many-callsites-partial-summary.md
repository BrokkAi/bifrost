# Render scan_usages too_many_callsites as a partial summary

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This plan follows `.agents/PLANS.md` from the repository root. It is self-contained so a future contributor can continue from only this file and the working tree.

## Purpose / Big Picture

When `scan_usages` hits the high-fanout `too_many_callsites` guardrail, callers currently receive only the symbol, cap, count, and a note. That confirms the query was too broad but does not show where to narrow next. The practical recovery lever is `paths`, so the result should show a bounded summary of files and enclosing symbols observed before stopping, while clearly saying the summary is incomplete.

After this change, a high-fanout symbol such as `Logger.debug` in a huge Java project can still trip the guardrail, but the caller receives a `usages` entry in the usual summary shape. The entry contains observed file counts and observed enclosing-symbol counts from the sampled hits, and the note says to re-call with `paths` from the files list for line-level detail.

## Progress

- [x] (2026-07-06T22:18Z) Confirmed an interrupted prior patch partially added `sample_hits` to `FuzzyResult::TooManyCallsites` and updated C#, C++, and PHP constructors.
- [x] (2026-07-06T22:24Z) Finished threading `sample_hits` through every `TooManyCallsites` constructor and exact match site.
- [x] (2026-07-06T22:24Z) Converted `scan_usages` TMC results into partial summary-shaped `SymbolUsages` entries backed by observed hits.
- [x] (2026-07-06T22:24Z) Kept top-level `too_many_callsites` for compatibility, while moving useful path-narrowing data into `usages`.
- [x] (2026-07-06T22:24Z) Added focused public regression coverage and ran validation.
- [ ] Commit and push the follow-up.

## Surprises & Discoveries

- Observation: Most language graph strategies already have a `BTreeSet<UsageHit>` available when they decide a query exceeded `max_usages`.
  Evidence: `src/analyzer/usages/java_graph/shared.rs`, `src/analyzer/usages/python_graph.rs`, `src/analyzer/usages/js_ts_graph.rs`, and other strategies all construct `FuzzyResult::TooManyCallsites` immediately after counting `hits`.

## Decision Log

- Decision: Add `sample_hits: BTreeSet<UsageHit>` to `FuzzyResult::TooManyCallsites`.
  Rationale: `scan_usages` cannot build an observed file/enclosing summary from only `total_callsites` and `limit`; carrying the bounded observed hits preserves enough structured information without forcing exhaustive enumeration.
  Date/Author: 2026-07-06 / Codex.

- Decision: Render TMC in `scan_usages` as a `SymbolUsages` summary entry with an explicit incomplete note, while keeping the existing top-level `too_many_callsites` array.
  Rationale: The summary shape gives callers the file paths they can use to narrow. Keeping the old array avoids abruptly removing the machine-readable high-fanout signal.
  Date/Author: 2026-07-06 / Codex.

## Outcomes & Retrospective

Implementation and validation are complete. The remaining work is to commit and push the follow-up.

Validation completed on 2026-07-06T22:24Z:

    cargo fmt
    cargo test --test searchtools_service scan_usages_too_many_callsites_returns_incomplete_summary_with_observed_files
    cargo test --test searchtools_service scan_usages
    cargo test --test usages_java_graph_test java_graph_strategy_reports_too_many_callsites_for_high_fanout_symbol
    cargo check
    cargo check --tests

The new public regression passed, the full service-level `scan_usages` suite passed 29 tests, the representative Java graph high-fanout test passed, and both library and test compilation checks passed.

## Context and Orientation

The internal usage result type is `FuzzyResult` in `src/analyzer/usages/model.rs`. Its `TooManyCallsites` variant represents a resolved symbol whose usage count exceeded a configured cap. Language-specific strategies create that variant in files such as `src/analyzer/usages/java_graph/shared.rs`, `src/analyzer/usages/python_graph.rs`, and `src/analyzer/usages/js_ts_graph.rs`.

The public `scan_usages` tool lives in `src/searchtools.rs`. It converts successful usage hits into `SymbolUsageRenderState`, then into `SymbolUsages`. `SymbolUsages` is already the useful shape for callers because it has `files`, `top_enclosing`, `rendering`, `note`, and count fields. The `too_many_callsites` array is currently separate and less useful.

## Plan of Work

First, update every `FuzzyResult::TooManyCallsites` constructor to populate `sample_hits` with the observed `BTreeSet<UsageHit>`. For strategies whose cap is based on external hits but whose set may include imports or self-receiver hits, it is acceptable to pass the full set and let `scan_usages` filter to external usage hits when rendering.

Second, update `src/searchtools.rs` so the TMC match arm filters/deduplicates `sample_hits` through the same `filter_and_dedupe_hits` helper used by successful hits, then pushes a `SymbolUsageRenderState` with `UsageRendering::Summary` and a base note explaining that the summary is incomplete. The top-level `TooManyCallsitesInfo` should remain and may gain no new fields.

Third, update tests. Add or adjust a public `scan_usages` test that forces high-fanout behavior if practical; otherwise run existing language-strategy TMC tests plus `searchtools_service scan_usages`. The test should prove the public response contains a summary-shaped usage entry and an incomplete/narrow-by-path note.

## Concrete Steps

Run commands from `/home/jonathan/Projects/bifrost`.

Search and patch constructors:

    rg -n "FuzzyResult::TooManyCallsites" src tests

Then validate:

    cargo fmt
    cargo test --test searchtools_service scan_usages
    cargo test --test usages_java_graph_test java_graph_strategy_reports_too_many_callsites_for_high_fanout_symbol
    cargo check

Commit and push only the changed files.

## Validation and Acceptance

The change is accepted when a TMC result in `scan_usages` yields an entry in `usages` with `rendering: "summary"`, file counts from observed hits, top enclosing counts from observed hits, and a note that states the summary is incomplete and recommends narrowing with `paths`. Focused tests and `cargo check` must pass.

## Idempotence and Recovery

These are source and test edits only. `cargo fmt` and tests can be rerun safely. If adding `sample_hits` breaks exact pattern matches, add `..` where the sample is irrelevant or assert the sample where it is part of the new behavior. Do not use destructive git commands.

## Artifacts and Notes

Important files:

    src/analyzer/usages/model.rs
    src/analyzer/usages/*_graph*.rs
    src/searchtools.rs
    tests/searchtools_service.rs

## Interfaces and Dependencies

At completion, `FuzzyResult::TooManyCallsites` must have:

    TooManyCallsites {
        short_name: String,
        total_callsites: usize,
        limit: usize,
        sample_hits: BTreeSet<UsageHit>,
    }

No new dependencies are required.

Revision note, 2026-07-06T22:24Z: Recorded the completed implementation and validation commands after adding partial summary rendering for high-fanout `scan_usages` results.
