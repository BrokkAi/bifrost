# Remove C++ selector FileState hydration

This ExecPlan is a living document. Keep it in line with `.agents/PLANS.md`.

## Purpose / Big Picture

C++ navigation must render a canonical selector without loading every stored fact for a large source file. This change will read only selector facts. A Phalcon navigation probe must then pass the old 40-record stop point.

## Progress

- [x] (2026-08-06 18:16Z) Reproduced the stop with four and one worker on a fresh Phalcon checkout.
- [x] (2026-08-06 18:16Z) Captured samples. Both show C++ selector rendering entering full FileState hydration.
- [x] Replace selector signature, role, linkage, range, and include reads with persisted projections.
- [x] Add a persisted C++ behavior test that proves selector rendering does not hydrate a FileState.
- [x] Run focused tests and the repeat Phalcon probe.
- [x] Persist C++ global-field linkage and read it without preparing source syntax.
- [x] Run a focused linkage regression and repeat the Phalcon probe.
- [ ] Avoid repeated syntax preparation in unconditional C++ include-reachability checks.
- [ ] Run the required policy check after MCP tool registration is repaired.

## Surprises & Discoveries

- Observation: One worker also stops after 40 records.
  Evidence: At 5:02 it used 99 percent CPU and 866 MB RSS with no record after number 40.
- Observation: The existing cache limit change does not remove selector hydration.
  Evidence: Samples enter `cpp_canonical_selectors`, then `signatures_vec_of`, then `hydrate_file_state_with_source`.
- Observation: The projection change increased progress from 40 to 44 records in five minutes.
  Evidence: The original one-worker run stopped at 40 records after 5:02. The changed run reached 44 records by 2:49 and still had 44 records at 5:00.
- Observation: The changed selector uses bounded SQLite projections.
  Evidence: The changed sample records `CppSelectorFacts::load`, `signatures_limited`, and `ranges_limited` without a FileState hydration below that stack.
- Observation: The remaining dominant cost is C++ reference resolution, not selector rendering.
  Evidence: The changed sample shows `get_definitions_by_reference` building `VisibilityIndex`, which calls `cpp_global_field_declaration_linkage` and parses full source through `prepared_syntax`.
- Observation: Persisted C++ global-field linkage removes that visibility-build syntax path.
  Evidence: The focused regression preserves an `extern const` peer result with zero full FileState hydrations. The repeat sample calls `CppAnalyzer::cpp_field_linkage` directly.
- Observation: The second change improves early progress but not the five-minute total.
  Evidence: It reached 40 records at 1:40, but stayed at 44 records through 5:40. The selector-only run also reached 44.
- Observation: Include-reachability is now the dominant syntax cost.
  Evidence: The repeat sample attributes 1,237 `prepared_syntax` calls to `unconditional_include_reaches` during C++ reference resolution.

## Decision Log

- Decision: Use existing persisted, bounded projections before adding another general cache.
  Rationale: The selector needs a small subset of FileState. The store already supports direct metadata and range queries.
  Date/Author: 2026-08-06 / Codex

## Outcomes & Retrospective

The selector path no longer needs full FileState hydration when persisted rows are complete. The dedicated test proves this behavior. Persisted global-field linkage also prevents a visibility-build parse. The Phalcon probe still stops at 44 records because unconditional include-reachability reparses the large include graph. The next focused change must persist or directly project the guard facts that this check needs.

Focused validation passed: `cargo fmt --check`, the persisted selector test, the six issue-1092 C++ identity tests, the global-field linkage regression, and `cargo clippy -p brokk-bifrost-analysis --all-targets -- -D warnings`. The policy skill is installed, but `list_policies` and `run_policy` are not registered in this task. The required policy result is therefore unavailable.

## Context and Orientation

`crates/bifrost-analysis/src/searchtools/selectors.rs` builds the selectors that navigation tools return. C++ callables need a signature label, a declaration or definition role, linkage, a primary range, and include evidence. The old path reads these values through `IAnalyzer`. A persisted C++ file can then load its complete `FileState`.

`crates/bifrost-analysis/src/analyzer/tree_sitter_analyzer.rs` has bounded direct reads for signature metadata and ranges. `crates/bifrost-analysis/src/analyzer/cpp/identity.rs` reads a source file's include lines when it checks a header and implementation pair.

## Plan of Work

Add a local selector-facts helper in `selectors.rs`. It will read complete direct projections when they fit the existing byte bounds. It will use the old analyzer accessors only when a projection is incomplete. It will derive C++ callable role and linkage from the projected metadata. It will use projected signature labels and ranges.

Change C++ header and implementation evidence in `cpp/identity.rs` to use `ImportAnalysisProvider::import_info_of`. C++ stores the same normalized include text in `ImportInfo.raw_snippet`, and this provider reads import rows without full FileState hydration.

Add a persisted C++ selector behavior test. It will query header and implementation definitions, render their selectors, and assert the canonical result and zero full hydrations.

## Concrete Steps

From the repository root, run:

    cargo fmt
    cargo test -p brokk-bifrost-analysis searchtools::selectors
    cargo build --release --bin bifrost_mcp_property_fuzzer
    target/release/bifrost_mcp_property_fuzzer --clones-root /tmp/local-clones --language php --repo phalcon__cphalcon --repo-jobs 1 --jobs 1 --shard 3/5 --max-service-symbols 200 --max-scan-probes 20 --cache-mode ephemeral --out /tmp/issue-1707-after.jsonl --dump-probes /tmp/issue-1707-after-dump.jsonl

## Validation and Acceptance

The new test must show that canonical C++ selector output remains stable while full hydration stays at zero. The Phalcon run must make progress beyond 40 records within five minutes.

## Idempotence and Recovery

The test and fuzzer commands are read-only for the checkout. They write only temporary caches and output files. Repeat them after a failed build. Do not change branches or remove the saved diagnostic files.

## Artifacts and Notes

The before samples are `/tmp/issue-1707-phfresh-sample.txt` and `/tmp/issue-1707-phfresh-j1-sample.txt`.

## Interfaces and Dependencies

The change uses `LanguageSupport::signature_metadata_limited`, `LanguageSupport::declaration_ranges_limited`, and `ImportAnalysisProvider::import_info_of`. It does not add a crate, a database schema change, or a new cache.

Plan revision: 2026-08-06. Created after the reproducible one-worker result. The plan selects direct projections because they remove the observed hydration path with less retained state.
