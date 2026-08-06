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
- [x] Reuse unconditional C++ include-reachability answers across visibility indexes.
- [x] Reuse the request FileState snapshot for C++ signature metadata during visibility construction.
- [x] Stop source rendering when `get_symbol_sources` exceeds its MCP response budget.
- [x] Reuse same-name function range groups while rendering broad source results.
- [x] Skip C++ field-linkage checks for sources already in a root's include closure.
- [x] Read C++ type-alias facts without hydrating a complete FileState.
- [x] Read enclosing declaration facts without hydrating a complete FileState.
- [x] Read alias signatures without hydrating a complete FileState.
- [x] Index large cached declaration-range sets for owner lookup.
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
- Observation: Retained include-reachability answers do not improve the first visibility build.
  Evidence: The first Phalcon request still reached 44 records and then stopped. The cache helps only later visibility indexes in the same analyzer.
- Observation: C++ visibility construction now completes before the slow source lookup.
  Evidence: The post-change sample at 1:46 is in `get_symbol_sources`, not `get_definitions_by_reference`, and contains no `signature_metadata_for_unit_limited` frames.
- Observation: A broad `PHP_METHOD` source lookup renders 18,280,879 bytes before MCP rejects it.
  Evidence: Two raw-symbol probes each take about 41 seconds and exceed the 16 MiB response budget. File-anchored probes finish in less than one second.
- Observation: The byte budget alone does not improve the broad source lookup time.
  Evidence: It stops materialization at 16 MiB, but the two raw `PHP_METHOD` probes still take 40,338 ms and 40,257 ms.
- Observation: The broad-source hot loop repeats one same-name definition lookup for every source file.
  Evidence: `source_blocks_for_code_unit_with_cache` called `definitions(PHP_METHOD)` for each resolved generated file before it collected that file's ranges.
- Observation: Caching each same-name range group cuts broad source lookup time by about 84 percent.
  Evidence: The two raw `PHP_METHOD` probes now take 6,534 ms and 6,409 ms. The prior budget-only probes took 40,338 ms and 40,257 ms.
- Observation: Linkage classification ran before the visibility index checked whether the field source was already reachable.
  Evidence: The counter test observed two needless classifications for fields from a shared included header. Reordering the checks makes this zero.
- Observation: The linkage-order change reaches the first 44 Phalcon probes faster.
  Evidence: The new run wrote probe 44 after about 83 seconds. The prior run reached 44 after about 89 seconds.
- Observation: C++ alias checks hydrate complete FileState values during the next slow definition probe.
  Evidence: The post-change sample attributes 522 samples to `TreeSitterAnalyzer::is_type_alias`, through `fetch_file_state` and `AnalyzerStore::hydrate_file_state_with_source`.
- Observation: A persisted alias-unit projection removes that hydration path.
  Evidence: The new test checks 1,025 C++ aliases, one above the source-snapshot capacity, with zero full hydrations.
- Observation: The next slow definition probe hydrates FileState values to find each enclosing lexical owner.
  Evidence: The post-alias sample attributes 719 `fetch_file_state_for_key_with_source` calls to `enclosing_code_unit` through `resolve_cpp_type_without_focused_qualifier`.
- Observation: A direct declaration-range projection removes this owner lookup hydration.
  Evidence: The new test checks 1,025 C++ methods, one above the source-snapshot capacity, and returns each exact owner with zero full hydrations.
- Observation: After the owner projection, alias-target signature lookup becomes the largest FileState hydration path.
  Evidence: The 10-second sample attributes 6,745 samples to `signatures_vec_of`, called from `cpp_alias_target_texts`, through `hydrate_file_state_with_source`.
- Observation: The first 44 navigation records still take 17 seconds after workspace setup.
  Evidence: The owner-projection dump was created at 23:12:25Z and wrote record 44 at 23:12:42Z. The two preceding dumps have the same 17-second interval.
- Observation: A stored signature projection removes alias signature hydration.
  Evidence: The new test reads 1,025 C++ alias signatures, one above the source-snapshot capacity, with zero full hydrations.
- Observation: The signature projection removes full FileState hydration from the stalled request.
  Evidence: The post-signature 10-second sample has no `hydrate_file_state_with_source` frames. It reaches record 44 in 15 seconds after workspace setup, compared with 17 seconds in the preceding run.
- Observation: Cached large files still scan every declaration for each lexical-owner lookup.
  Evidence: The post-signature sample attributes 1,057 samples to `enclosing_code_unit`, primarily iterating `HashSet<CodeUnit>` values under 1,693 `indexed_enclosing_owner_scope` calls.
- Observation: A prefix-max range index can stop the owner lookup after its overlapping declaration ranges.
  Evidence: The new regression resolves 129 functions in one C++ file, builds one index, and has zero full hydrations.

## Decision Log

- Decision: Use existing persisted, bounded projections before adding another general cache.
  Rationale: The selector needs a small subset of FileState. The store already supports direct metadata and range queries.
  Date/Author: 2026-08-06 / Codex
- Decision: Retain only persisted type-alias units, keyed by content OID and path.
  Rationale: Alias checks need a small fact set. A byte-bounded projection avoids source and side-table retention while keeping warm requests fast.
  Date/Author: 2026-08-06 / Codex
- Decision: Query stored declaration ranges before full state hydration for owner lookup.
  Rationale: Persisted declarations include the identity and ordered ranges needed for the existing smallest-enclosing selection. Empty or unavailable projections retain the full-state fallback for file scope and incomplete storage.
  Date/Author: 2026-08-06 / Codex
- Decision: Use the complete stored signature projection before generic signature hydration.
  Rationale: Alias resolution needs the same ordered signature strings that the store retains. An incomplete result keeps the complete FileState fallback. Source retrieval remains a lazy final fallback for aliases without usable signature text.
  Date/Author: 2026-08-06 / Codex
- Decision: Retain a byte-bounded prefix-max interval index for large cached FileState declaration ranges.
  Rationale: A content-keyed index makes each owner lookup inspect only overlapping ranges. A 32 MiB bound prevents the copied CodeUnit values from becoming an unbounded second FileState cache.
  Date/Author: 2026-08-06 / Codex

## Outcomes & Retrospective

The selector path no longer needs full FileState hydration when persisted rows are complete. The dedicated test proves this behavior. Persisted global-field linkage also prevents a visibility-build parse. C++ include reachability now retains bounded answers across visibility indexes. Request-local metadata reads reuse the FileState already hydrated by the visibility build. The Phalcon navigation part now completes before `get_symbol_sources`. Broad source lookup now stops at the response limit and reuses same-name range groups. This cuts the rejected `PHP_METHOD` source probes from about 40 seconds to about 6.5 seconds.

Focused validation passed: `cargo fmt --check`, the persisted selector and alias tests, the enclosing-owner, signature, and large-range index tests, the six issue-1092 C++ identity tests, the global-field linkage regression, two BehaviorTree alias regression tests, and `cargo clippy -p brokk-bifrost-analysis -p brokk-bifrost-cpp --all-targets -- -D warnings`. The policy skill is installed, but `list_policies` and `run_policy` are not registered in this task. The required policy result is therefore unavailable.

## Context and Orientation

`crates/bifrost-analysis/src/searchtools/selectors.rs` builds the selectors that navigation tools return. C++ callables need a signature label, a declaration or definition role, linkage, a primary range, and include evidence. The old path reads these values through `IAnalyzer`. A persisted C++ file can then load its complete `FileState`.

`crates/bifrost-analysis/src/analyzer/tree_sitter_analyzer.rs` has bounded direct reads for signature metadata and ranges. It now uses stored declarations and ordered ranges for a smallest-enclosing owner query. `crates/bifrost-analysis/src/analyzer/cpp/identity.rs` reads a source file's include lines when it checks a header and implementation pair.

## Plan of Work

Add a local selector-facts helper in `selectors.rs`. It will read complete direct projections when they fit the existing byte bounds. It will use the old analyzer accessors only when a projection is incomplete. It will derive C++ callable role and linkage from the projected metadata. It will use projected signature labels and ranges.

Change C++ header and implementation evidence in `cpp/identity.rs` to use `ImportAnalysisProvider::import_info_of`. C++ stores the same normalized include text in `ImportInfo.raw_snippet`, and this provider reads import rows without full FileState hydration.

Add a persisted C++ selector behavior test. It will query header and implementation definitions, render their selectors, and assert the canonical result and zero full hydrations.

Give source-block collection an explicit byte budget for MCP requests. It must stop before it allocates all source blocks for a response that MCP will reject. It must keep the existing error contract: an oversized request returns `InvalidParams`, not partial source text. Cache the `definitions(fq_name)` ranges by source during one source request so a broad macro lookup does not repeat the same candidate scan for every resolved file.

## Concrete Steps

From the repository root, run:

    cargo fmt
    cargo test -p brokk-bifrost-analysis searchtools::selectors
    cargo build --release --bin bifrost_mcp_property_fuzzer
    target/release/bifrost_mcp_property_fuzzer --clones-root /tmp/local-clones --language php --repo phalcon__cphalcon --repo-jobs 1 --jobs 1 --shard 3/5 --max-service-symbols 200 --max-scan-probes 20 --cache-mode ephemeral --out /tmp/issue-1707-after.jsonl --dump-probes /tmp/issue-1707-after-dump.jsonl

## Validation and Acceptance

The new test must show that canonical C++ selector output remains stable while full hydration stays at zero. The Phalcon run must make progress beyond 40 records within five minutes. An oversized source lookup must stop collection before it renders all oversized blocks and must return the existing response-budget error.

## Idempotence and Recovery

The test and fuzzer commands are read-only for the checkout. They write only temporary caches and output files. Repeat them after a failed build. Do not change branches or remove the saved diagnostic files.

## Artifacts and Notes

The before samples are `/tmp/issue-1707-phfresh-sample.txt` and `/tmp/issue-1707-phfresh-j1-sample.txt`.

## Interfaces and Dependencies

The change uses `LanguageSupport::signature_metadata_limited`, `LanguageSupport::declaration_ranges_limited`, and `ImportAnalysisProvider::import_info_of`. It does not add a crate or a database schema change. It adds one bounded in-memory include-reachability cache.

Plan revision: 2026-08-06. Created after the reproducible one-worker result. The plan selects direct projections because they remove the observed hydration path with less retained state.
