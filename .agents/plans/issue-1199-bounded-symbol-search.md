# Make broad symbol search share work and honor cancellation

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. This document is maintained in accordance with `.agents/PLANS.md`.

## Purpose / Big Picture

`search_symbols` is an interactive navigation tool, but a request containing several broad patterns currently repeats the same complete persisted declaration scan once per pattern. In the Bifrost repository, the issue #1199 reproduction remained blocked for more than 90 seconds. After this change, all patterns in one request will be evaluated against one analyzer snapshot scan per language, and an MCP cancellation request will cooperatively stop candidate enumeration and return an explicitly partial response instead of leaving the worker busy. The exact issue query should return the same matches during a normal run, while tests prove that four patterns cause one persisted scan and that cancellation marks the response truncated.

## Progress

- [x] (2026-07-27 08:16Z) Reproduced the live MCP request for more than 90 seconds on the current issue branch and traced the repeated scan through `searchtools::search_symbols`, `IAnalyzer::search_symbol_candidates`, `MultiAnalyzer`, `TreeSitterAnalyzer`, and `AnalyzerStore`.
- [x] (2026-07-27 08:39Z) Refactored the analyzer search-candidate interface to accept the full pattern batch and enumerate persisted candidates once per language.
- [x] (2026-07-27 09:12Z) Threaded the existing MCP request cancellation token through SQLite enumeration, qualified-name hydration, dirty state, path-synthetic modules, ranking, rendering, and the service boundary; interrupted responses use `truncated` plus an explicit partial-result note.
- [x] (2026-07-27 09:18Z) Added work-count, pre-cancelled service/search, and deterministic mid-scan cancellation regressions; all four issue-focused tests pass.
- [x] (2026-07-27 09:36Z) Ran `cargo fmt`, the four focused tests, the exact current-source timing twice, and the all-target/all-feature clippy gate successfully.

## Surprises & Discoveries

- Observation: `include_tests` is not responsible for the delay. Test filtering happens only after every pattern has separately fetched and hydrated its complete declaration projection.
  Evidence: `src/searchtools/navigation.rs` calls `analyzer.search_symbol_candidates(pattern, false)` inside `patterns.par_iter()`, while `src/analyzer/store/mod.rs::search_candidate_rows_by_pattern_for_langs` ignores its `_pattern` parameter and loads all declaration rows.

- Observation: The service already receives a `CancellationToken` for standard MCP tool calls, but only `query_code` consumes it; `search_symbols` currently calls its non-cancellable function.
  Evidence: `src/searchtools_service.rs::call_tool_output_with_cancellation` accepts the token but the `search_symbols` match arm invokes `search_symbols(workspace.analyzer(), params)` without it.

- Observation: The installed command-line binary is older than the current schema and cannot provide a trustworthy current-source timing baseline. A clean current-source build did not finish within the initial four-minute compile window, so that run never reached the query.
  Evidence: installed `bifrost 0.8.9` rejected schema version 12; the isolated `cargo run` was terminated while compiling and emitted no `bifrost-timing` query scopes.

- Observation: Featureless focused tests link and run, but an all-feature integration-test binary does not link in the current shell because PyO3 cannot resolve Python symbols.
  Evidence: the issue test passed featurelessly in 0.03 seconds; the preceding `--features nlp,python` build compiled Rust successfully, then failed at `cc` with undefined `_Py*` symbols. The shell resolves `python3` to Xcode Python 3.9 while `python3-config` reports Homebrew Python 3.14, so this is an environment/toolchain mismatch to keep separate from the symbol-search code.

- Observation: The patched exact query completes well inside the prior cancellation window, while ranking is not the bottleneck.
  Evidence: a reconciled current-source run completed `searchtools::search_symbols` in 5287.7 ms (2667.5 ms resolve, 22.4 ms rank); a warmed repeat completed in 7246.9 ms (4076.2 ms resolve, 23.1 ms rank). Both returned 18 files without truncation, versus the original request still running at 41 and 91 seconds.

- Observation: This shell had two Rust 1.96 clippy installations with the same release number but incompatible compiler metadata.
  Evidence: `cargo-clippy` on `PATH` came from Homebrew (LLVM 22.1.6), while `cargo`/`rustc` came from rustup (LLVM 22.1.2). Invoking the rustup toolchain's `cargo-clippy` directly made the required all-target/all-feature gate pass.

## Decision Log

- Decision: Batch patterns at the `IAnalyzer` boundary instead of adding a timeout only in the MCP transport.
  Rationale: Every bundled language delegates to the same persisted tree-sitter analyzer path. A batch interface removes the multiplicative `patterns × full scan` work without changing matches, ranking, or language semantics, while a transport timeout would leave the underlying blocking work running.
  Date/Author: 2026-07-27 / Codex

- Decision: Reuse the request's cooperative `CancellationToken` and represent an interrupted candidate stream with the existing public `truncated` flag plus a precise note.
  Rationale: Cancellation already crosses the MCP boundary and is the repository's established mechanism for long-running in-process analysis. Reusing it avoids a second deadline system and makes partial results explicit to every host.
  Date/Author: 2026-07-27 / Codex

- Decision: Preserve regex and qualified-name semantics by applying the same language adapter normalization and Rust regex matching after candidate hydration; do not introduce a text or regex fallback over source files.
  Rationale: The durable optimization is shared enumeration, not a narrower approximation. Some language qualified names depend on file paths, so an eager SQL substring filter could silently discard valid matches.
  Date/Author: 2026-07-27 / Codex

- Decision: Compile a request's valid patterns into one case-insensitive `RegexSet` after retaining the existing per-pattern validation and sigil escaping.
  Rationale: The set shares automaton work across every target language without changing adapter normalization, raw-name handling, or invalid-pattern behavior.
  Date/Author: 2026-07-27 / Codex

## Outcomes & Retrospective

The implementation now performs one persisted candidate scan per language for any number of request patterns, uses a shared regex set for the union, and preserves the language adapters' structured FQN hydration. Cancellation is cooperative through all large search loops, including JavaScript/TypeScript/Python path-synthetic module discovery, and callers receive explicit partial/truncated output.

The exact issue request now completes in 5.29-7.25 seconds in two current-source runs and returns 18 files without truncation. Four focused regressions pass in under a tenth of a second once linked, and the repository's all-target/all-feature clippy gate passes with warnings denied.

## Context and Orientation

`src/searchtools/navigation.rs` defines the public `SearchSymbolsParams` and `SearchSymbolsResult` models and implements ranking and rendering. It currently fans patterns out in parallel and unions their candidate vectors.

`src/analyzer/i_analyzer.rs` defines `IAnalyzer`, the language-neutral analyzer interface. Each concrete language wrapper delegates symbol candidate search to an inner `TreeSitterAnalyzer`, and `src/analyzer/multi_analyzer.rs` combines language delegates for mixed workspaces.

`src/analyzer/tree_sitter_analyzer.rs` owns persisted candidate loading and reconstructs each language's structured qualified name using its adapter. `src/analyzer/store/mod.rs` reads the `code_units` projection and primary ranges from SQLite. A persisted candidate scan means enumerating those declaration rows; it is independent of the final file result `limit`.

`src/searchtools_service.rs` is the shared tool service used by CLI and MCP. MCP calls arrive through `src/mcp_common.rs` with a cloneable `CancellationToken`. Cancellation is cooperative: long loops must call `is_cancelled()` and stop themselves.

## Plan of Work

First, replace the single-pattern `IAnalyzer::search_symbol_candidates` contract with a batch contract that accepts all normalized request patterns. The default implementation will preserve extension-analyzer compatibility by combining per-pattern `search_definitions` results. Every built-in language wrapper will delegate the batch unchanged, `MultiAnalyzer` will fan the batch to each language once, and `TreeSitterAnalyzer` will compile all valid patterns and load its persisted declaration projection only once. The misleading store method name and unused pattern parameter will be removed.

Second, define an internal candidate batch outcome that carries candidates, inspected work, and completeness. Pass the optional `CancellationToken` from `SearchToolsService` through `search_symbols`, the analyzer trait, SQLite row enumeration, qualified-name hydration, and dirty/path-synthetic candidate loops. Preserve candidates completed before cancellation, mark the public result `truncated`, and include a note that the shown files are partial because cancellation stopped candidate enumeration. A normal file-limit truncation retains its existing note.

Third, add an issue-shaped regression using the shared `InlineTestProject` harness. It will use four literal/regex patterns, verify the expected union and ranking behavior, reset the analyzer's full-declaration-scan counter, and assert that one search request performs one scan rather than four. Add a pre-cancelled or deterministic cancel-after-checks test at the searchtools/service boundary and assert `truncated` plus the partial-result note. Keep latency validation measurement-based rather than a flaky wall-clock assertion.

Finally, format and run focused tests, then the repository's all-feature clippy gate. Build the current CLI in an isolated cargo target and execute the exact issue query with `BIFROST_TIMING=1`, recording the total and named scopes. If the query is still outside interactive latency, use the profile to refine the shared enumeration without changing result semantics.

## Concrete Steps

All commands run from `/Users/dave/.codex/worktrees/6799/bifrost`.

Implement and format:

    cargo fmt

Run the focused regression suites through the managed isolated-target helper:

    scripts/with-isolated-cargo-target.sh cargo test --lib --test searchtools_fuzzy_symbol_lookup issue_1199 -- --nocapture

Run the core Rust quality gate:

    PYO3_PYTHON=/opt/homebrew/bin/python3.14 scripts/with-isolated-cargo-target.sh /Users/dave/.rustup/toolchains/1.96.0-aarch64-apple-darwin/bin/cargo-clippy --all-targets --all-features -- -D warnings

Run the exact dogfood query with current source and timing enabled:

    BIFROST_TIMING=1 scripts/with-isolated-cargo-target.sh cargo run --quiet --bin bifrost -- --root /Users/dave/.codex/worktrees/6799/bifrost --tool search_symbols --args '{"patterns":["semantic_diagnostics","collect_.*semantic_diagnostics","DiagnosticPublisher","publish.*diagnostic"],"include_tests":true,"limit":100}'

The timing transcript must show one persisted candidate scan per active language rather than one per pattern, and the command must produce a normal `search_symbols` payload without external cancellation.

## Validation and Acceptance

The focused multi-pattern test must fail on the original implementation because its full-declaration-scan counter observes four scans, then pass with exactly one. It must also prove that both literal and regex patterns still contribute their expected symbols.

The cancellation test must show that a cancelled request terminates through cooperative checkpoints, returns `truncated: true`, and includes a note clearly saying the results are partial due to cancellation. It must not report an authoritative empty result after interrupted enumeration.

The exact issue query must complete with current source and preserve ordinary search output. `cargo fmt` must leave no diff, and `cargo clippy --all-targets --all-features -- -D warnings` must pass.

## Idempotence and Recovery

The code edits and tests are safe to repeat. Isolated cargo targets are created and removed by `scripts/with-isolated-cargo-target.sh`; do not create manually named temporary target directories. The persistent `.brokk` cache is rebuildable and should not be deleted as part of this work. If a compile or test is interrupted, rerun the same helper command. Stage and commit only the plan and source/test files changed for this issue.

## Artifacts and Notes

Live MCP reproduction on commit `d2fdf88701c22e854d281edc08986b8713e25d41`:

    exact search_symbols request: still running at 60 seconds
    same request: still running at 91 seconds
    request terminated after reproduction was established

Persisted declaration counts in the worktree's current analyzer cache total about 52,000 rows, led by about 47,000 Rust declarations. The problem is therefore repeated projection/hydration work and contention, not an infinite language parser loop.

Focused milestone-1 validation:

    test issue_1199_multi_pattern_symbol_search_scans_persisted_candidates_once ... ok
    test result: ok. 1 passed; 0 failed; 41 filtered out; finished in 0.03s

Focused complete validation:

    searchtools_service::search_symbols_cancellation_tests::issue_1199_service_forwards_cancellation_to_search_symbols ... ok
    analyzer::tree_sitter_analyzer::tests::issue_1199_symbol_candidate_scan_honors_midstream_cancellation ... ok
    issue_1199_cancelled_symbol_search_returns_explicit_partial_result ... ok
    issue_1199_multi_pattern_symbol_search_scans_persisted_candidates_once ... ok
    test result: ok. 4 passed; 0 failed

Current-source exact query timings:

    searchtools::search_symbols (5287.7 ms), resolve 2667.5 ms, rank 22.4 ms
    warmed searchtools::search_symbols (7246.9 ms), resolve 4076.2 ms, rank 23.1 ms
    both: total_files=18, truncated=false

Final quality gate:

    cargo clippy --all-targets --all-features -- -D warnings
    Finished dev profile; exit 0

## Interfaces and Dependencies

No new crate dependency is required. The implementation must use `crate::CancellationToken`, the existing Rayon fan-out across language delegates where useful, the persisted `AnalyzerStore`, and the current adapter-driven qualified-name hydration. The final internal interface will accept a pattern slice and optional cancellation token and return a candidate batch outcome with a completeness bit; `search_symbols` remains available as the non-cancellable public convenience function, with a cancellation-aware sibling used by `SearchToolsService`.

Plan revision note (2026-07-27 08:39Z): Completed the shared-scan milestone, recorded its focused regression evidence, and separated the local all-feature PyO3 linker mismatch from product behavior. The next milestone threads cancellation through the new batch.

Plan revision note (2026-07-27 09:27Z): Completed cancellation and all focused regressions, added shared regex-set matching and cancellable synthetic-module enumeration, and recorded two successful exact-query timings. Final clippy and cleanup remain.

Plan revision note (2026-07-27 09:36Z): Re-ran all four focused tests after the final hot-path specialization and completed the all-target/all-feature clippy gate. Implementation and validation are complete; only checkpoint commit and generated-artifact cleanup remain.
