# Harden Bifrost tests without lengthening CI

This ExecPlan is a living document. Maintain it according to `.agents/PLANS.md`; the `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` sections are part of the deliverable.

## Purpose / Big Picture

Bifrost needs tests that catch realistic failures in the analyzer, its persistence layer, and its editor and protocol boundaries without converting CI time into a proxy for confidence. After this work, each audited high-risk test surface will have a recorded behavioral contract, deterministic adversarial coverage for meaningful gaps, and a measured explanation of any CI-time reduction. A contributor can verify the result by running the focused tests for each milestone, then the project gates described below.

## Progress

- [x] (2026-07-21 13:30Z) Refreshed `origin`, verified the issue branch is clean and aligned with `origin/master` at `0955e1c7`, and fetched issue #872.
- [x] (2026-07-21 13:35Z) Inventoried the CI matrix, large integration suites, lazy-cache/deadlock tests, and ignored-test candidates; recorded the first bounded milestone.
- [ ] Establish a completed, reproducible focused baseline for the concurrency/cache milestone. Two isolated-Cargo attempts began cold dependency builds but the execution host ended each 30-second capture before Cargo returned a result; do not treat either as a pass or failure. Re-run in a session that can retain the command to completion before editing the test fixture.
- [ ] Audit and, only with equivalent behavioral evidence, reduce the JS/TS lazy-index deadlock regression's generated fixture cost. The test now asserts its triggering imported-call contract rather than only a broad node count; fixture reduction still requires a completed baseline and pre-fix reproduction.
- [ ] Audit persistence, reconciliation, and interrupted-state transitions with deterministic low-budget corruption and cancellation probes. Added the first recovery probe: a single corrupted cached Python blob must reparse while its clean peer hydrates, then hydrate normally after repair.
- [x] (2026-07-21 14:20Z) Audited protocol, parser, and boundary inputs: JSON, RQL, Rune, LSP, MCP, CLI, source text, Unicode, CRLF, and paths. Existing query-file service tests already cover malformed RQL/JSON, invalid query shapes, missing/oversized/directory files, traversal, symlink escape, Unicode paths, and portable Windows prefixes. Existing LSP tests cover malformed language input, CRLF/Unicode incremental edits, stale document versions, cancellation, and unknown requests. Added the missing direct Rune handler contracts for backwards selections and empty documents.
- [ ] Audit watcher lifecycle, incremental invalidation, cancellation, and stale generations using barriers/channels instead of elapsed-time races. Fixed and covered the coalesced source-plus-Git event case: any refresh-fallback path must force a full refresh even when the same event has an incremental source path.
- [ ] Audit analyzer ambiguity and structural-query behavior across import, receiver, ordering, and platform boundaries; use `InlineTestProject` for small projects. Deferred from the active sweep at user direction.
- [ ] Review ignored, flaky, duplicate, and implementation-mirroring tests; removed six ignored parity-marker non-tests with empty or unconditional-panic bodies. Continue reviewing the remaining ignored tests, retaining only documented opt-in benchmarks/external-model tests or explicitly justified deferred contracts.
- [ ] Run the full acceptance matrix and publish the final report in this plan.

## Surprises & Discoveries

- Observation: the Bifrost code-navigation MCP tools are not exposed in this session, despite the installed skill. The sweep uses bounded `rg`, file reads, and git history as a documented fallback.
  Evidence: the callable-tool inventory contains no `search_symbols`, `get_symbol_locations`, `scan_usages`, or `most_relevant_files` entry.
- Observation: the live CI critical path is Rust testing, not the VS Code or fixture-provenance jobs. The five executable Rust test jobs take approximately 11m37s (Linux), 13m17s (ARM Linux), 15m44s (macOS), and 16m23s (Windows); Python waits on the Rust job group and then adds up to about 2m30s.
  Evidence: GitHub Actions run `29823845761` completed from 10:51:35Z to 11:15:13Z; job timing shows the listed `cargo test` intervals and `python` has `needs: rust` in `.github/workflows/ci.yml`.
- Observation: `tests/jsts_usage_graph_deadlock.rs` creates 300 noise files plus eight 4,000-function files and allows a 240-second wait. It protects a real end-to-end JS/TS wiring contract, while `src/analyzer/pool_memo.rs` already has a smaller controlled unit regression for the generic memo mechanism.
  Evidence: `tests/jsts_usage_graph_deadlock.rs:24-116` and `src/analyzer/pool_memo.rs:218-264`.
- Observation: the integration test currently proves completion and a broad node-count floor, but does not assert the imported `makeThing` call that causes receiver analysis to consult the lazy index. Existing TypeScript tests use `common::usage_graph::has_edge` to assert that exact observable graph relation.
  Evidence: `tests/jsts_usage_graph_deadlock.rs:102-115` compared with `tests/usage_graph_ts_test.rs:51-69`.
- Observation: the first implementation change replaces the broad node-count floor with `run0 -> makeThing`, a cross-file imported-call edge produced by the triggering input. It improves the test's behavioral evidence without changing its workload or watchdog.
  Evidence: `tests/jsts_usage_graph_deadlock.rs` imports `common::usage_graph::has_edge` and asserts that edge after the bounded pool execution.
- Observation: local focused Cargo evidence is incomplete because the execution host terminated capture while compiling a fresh isolated target. This is an environment limitation, not a test result.
  Evidence: both helper-created directories `/private/tmp/bifrost-cargo-target.Fu9mNt` and `/private/tmp/bifrost-cargo-target.75F82c` remain younger than the cleanup script's 24-hour safety threshold after output ended in dependency compilation.
- Observation: a later retained-background attempt did not launch because this sandbox rejects the `nice` operation used by its process wrapper. The focused persistence test therefore still has no pass/fail result.
  Evidence: `nohup scripts/with-isolated-cargo-target.sh cargo test ...` reported `nice(5) failed: operation not permitted` and the process exited without a test log.
- Observation: ignored tests have several distinct classes: intentionally opt-in measurement benchmarks, external model downloads, known analyzer gaps, a 10k-file smoke, and stress cases. They must not be treated as one category.
  Evidence: `rg -n '#\\[ignore' tests src` identifies explicit reasons at `tests/measure_*.rs`, `tests/nlp_*`, `tests/searchtools_service.rs:7185`, `tests/lsp_click_around_regression.rs`, and language parity suites.
- Observation: store-unit tests prove a corrupted blob is excluded from hydration, but persisted workspace tests did not prove the next build reparses and repairs just that blob while retaining a clean peer as warm state.
  Evidence: `src/analyzer/store/mod.rs` has `metadata_unit_count_mismatch_is_treated_as_incomplete`; `tests/analyzer_persistence.rs` had warm and dirty-file reconciliation coverage but no externally corrupted-cache repair scenario.
- Observation: the initial LSP/MCP boundary audit found mature, behavior-focused coverage for malformed language input, cancellation, CRLF and Unicode incremental edits, stale `didChange` versions, and unknown requests. Adding another test in those shapes would duplicate existing contracts.
  Evidence: `tests/bifrost_lsp_server.rs` covers malformed diagnostics around lines 7156-7520, formatting cancellation around 8941-9030, CRLF/Unicode edits around 9400-9475, stale changes around 9579-9627, and unknown requests at 7662; `src/lsp/handlers/formatting.rs` retains one explicit opt-in integration test.
- Observation: `ProjectChangeWatcher` only requested a full refresh for fallback paths when no source path appeared in the same event. Filesystem backends may coalesce a `.git/HEAD` change with a source edit, and a ref change invalidates workspace state beyond that source file.
  Evidence: `src/project_watcher.rs::handle_event` previously gated `mark_full_refresh` on `!saw_relevant_path`; the new unit regression supplies both paths in one `notify::Event`.
- Observation: the RQL/CLI boundary behavior is already concentrated in behavior-focused tests rather than only parser units; adding another malformed-file test at the CLI shim would duplicate the service contract.
  Evidence: `tests/searchtools_service.rs::query_code_file_input_reports_validation_and_workspace_errors` covers malformed, invalid, oversized, non-regular, traversal, symlink, and mixed-input failures; `tests/policy_loading_workspace.rs` covers normalized, Unicode, and Windows-like paths; `tests/bifrost_tool_cli.rs` exercises both RQL and JSON one-shot success paths and incompatible modes.
- Observation: focused test execution again began a clean isolated Cargo build but the host terminated the captured command before Cargo completed.
  Evidence: `scripts/with-isolated-cargo-target.sh cargo test --features nlp project_watcher::tests --lib` reached dependency compilation only; no test result was emitted.
- Observation: six ignored parity markers do not exercise code: three Python markers and one Git-hotspot marker panic unconditionally, while two JS/TS markers have empty bodies. They add no executable contract and turn `--ignored` into a knowingly failing/non-informative mode.
  Evidence: `tests/usages_python_graph_test.rs`, `tests/usages_js_ts_graph_test.rs`, and `src/code_quality/git_hotspots.rs` each contained the named ignored marker functions.
- Observation: three retained stress tests do exercise real behavior but two had only the uninformative reason `stress`, and the 10k-file smoke reason omitted its execution command.
  Evidence: `tests/lsp_click_around_regression.rs` generates the Go embedding and Rust trait-implementation fixtures; `tests/searchtools_service.rs` generates 10,000 tracked Java files.

## Decision Log

- Decision: begin with concurrency and lazy cache initialization rather than a broad full-suite run.
  Rationale: it is a high-impact category named by issue #872, has an existing large regression likely to affect CI time, and can be validated with a narrow exact integration target before any broad build.
  Date/Author: 2026-07-21 / Codex.
- Decision: retain the full cross-platform CI matrix as the final correctness gate; do not reduce platform coverage merely to shorten wall-clock time.
  Rationale: Bifrost supports Linux, macOS, and Windows. The first performance goal is to remove accidental test cost while preserving behavior, then consider CI topology only if measurement proves a safe opportunity.
  Date/Author: 2026-07-21 / Codex.
- Decision: treat every timeout test as a bounded watchdog, not a duration assertion. Lower a watchdog only after the test's controlled coordination or workload makes a substantially smaller bound credible on the slowest supported runner.
  Rationale: timing-only tests are flaky, but an unreasonably high watchdog inflates failure diagnosis and masks hangs.
  Date/Author: 2026-07-21 / Codex.
- Decision: strengthen the integration test before reducing its generated workload.
  Rationale: node count was not the behavior that reaches the lazy index. The imported-call edge is a stable observable result, while a workload reduction needs separate evidence that the former deadlock shape remains reproducible.
  Date/Author: 2026-07-21 / Codex.
- Decision: add recovery coverage at the persisted-workspace boundary rather than duplicating the store's metadata-mismatch unit assertions.
  Rationale: deleting one `code_units` row through a second SQLite connection simulates externally interrupted/corrupt cache state. The test proves observable recovery: one parse to repair the affected Git blob, no parse for its peer, and zero parses on the following warm build.
  Date/Author: 2026-07-21 / Codex.
- Decision: remove ignored parity-marker non-tests rather than converting them into comments or retaining their test names.
  Rationale: the markers contain neither a fixture nor a behavioral assertion, so they are not regressions and cannot become useful by being run. The relevant supported behavior remains covered by nearby real tests; future parity work needs an issue or an executable contract, not a placeholder test.
  Date/Author: 2026-07-21 / Codex.
- Decision: retain the three stress tests, but make their ignore messages describe the generated workload and exact opt-in command.
  Rationale: each test has a distinct behavior assertion and deliberately large fixture. Explicit messages make the skip auditable without running a host-costly workload in ordinary CI.
  Date/Author: 2026-07-21 / Codex.
- Decision: treat any coalesced watcher event containing a refresh-fallback path as a full refresh.
  Rationale: incremental file updates are still collected for diagnostics, but a Git or out-of-project path means the watcher cannot soundly claim the event is limited to those files.
  Date/Author: 2026-07-21 / Codex.
- Decision: focus the remaining active sweep on protocol/input boundaries and watcher lifecycle/incremental behavior; defer analyzer ambiguity work.
  Rationale: this is the requested scope split, keeping the next changes independently reviewable.
  Date/Author: 2026-07-21 / Codex.

## Context and Orientation

The Rust crate is rooted at `Cargo.toml`. The primary CI definition is `.github/workflows/ci.yml`; it runs clippy and a feature-enabled Rust suite on Linux, ARM Linux, macOS, and Windows, then runs Python tests after all Rust jobs. `scripts/with-isolated-cargo-target.sh` creates and removes a private Cargo build directory, preventing this worktree's ordinary `target/` directory from retaining binaries.

An integration test in `tests/jsts_usage_graph_deadlock.rs` builds an in-memory JavaScript project with `tests/common/inline_project.rs::InlineTestProject`, calls `tests/common/usage_graph::usage_graph_at`, and uses a Rayon worker pool. Rayon is the Rust parallel-work library. The test defends against lazy initialization of the JS/TS usage index re-entering a parallel scan and deadlocking workers. `src/analyzer/pool_memo.rs::PoolSafeMemo` is the common cache primitive designed to avoid that deadlock; its in-module tests separately validate the primitive with channels and barriers.

Later milestones cover the persistence store in `src/analyzer/store/mod.rs`, compact graph storage in `src/compact_graph.rs`, structural search in `src/analyzer/structural/search.rs`, protocol/server boundaries in `tests/bifrost_mcp_server.rs` and `tests/bifrost_lsp_server.rs`, and the large analyzer suites listed in issue #872. These are separate milestones so a defect or a larger product decision cannot silently broaden the active work.

## Plan of Work

### Milestone 1: Make the lazy-cache regression deterministic and proportionate

First record a passing focused baseline for `tests/jsts_usage_graph_deadlock.rs` and the `PoolSafeMemo` module, including elapsed wall time and the exact feature flags. Read the actual JS/TS usage-index initialization path and the `usage_graph_at` helper to identify which project shapes are necessary to enter the production path. Map the generic unit regression and the end-to-end integration regression to their distinct contracts.

If the integration fixture contains redundant work, replace it only with the smallest fixture that still hangs against a temporary local pre-fix reproduction and completes against the current implementation. Prefer explicit synchronization through an existing injectable seam; if the production path has no safe seam, retain a bounded realistic fixture and describe why. A successful change must preserve the end-to-end assertion that a generated imported receiver is included in the usage graph, not merely that the call returns. Lower the watchdog only after repeatable evidence on the local platform; never add sleeps or retries.

Run the exact integration target and the smallest library-test filter that contains `PoolSafeMemo` tests. Then run neighboring JS/TS usage graph tests affected by the changed code or test helper. Record before/after wall time and the result in this plan.

### Milestone 2: Persistence and cache state transitions

Audit `src/analyzer/store/mod.rs`, its persistence integration tests, and compact graph storage for partially written snapshots, corrupt or incompatible rows, cancellation during initialization, invalidation after a failed write, and retry behavior. Each probe must set a small explicit data budget and use repository test support rather than host resource exhaustion. For each discovered bug, first preserve a minimized failing regression, then correct the production path and rerun the local persistence neighborhood.

### Milestone 3: Protocol and input boundaries

Audit `tests/bifrost_mcp_server.rs`, `tests/bifrost_lsp_server.rs`, structural query parsing/execution, Rune, CLI, and source-language entry points. Select malformed, truncated, Unicode, CRLF, empty, duplicate, and path-boundary inputs where the interface can plausibly mis-handle them. Verify protocol behavior through observable responses, diagnostics, or state, not private collection layouts. Keep JSON documents outside the RQL host boundary unless the host has identified them as `bifrost-rql`.

### Milestone 4: Lifecycle and incremental correctness

Audit watcher lifecycle, cancellation, stale generations, lazy initialization, and incremental updates. Use barriers, channels, controlled executors, and short bounded watchdogs so the outcome is scheduling-independent. Check that a cancelled or failed operation neither publishes stale state nor blocks a later valid request. Validate the LSP boundary with `tests/common/lsp_client.rs` where applicable.

### Milestone 5: Analyzer ambiguity and test value review

Audit the large definition, usage-graph, search-tools, and CodeQuery suites for import/receiver/order/platform ambiguity, then review ignored and weak tests. For every removal or consolidation, document the exact observable behavior and the retained test that replaces it. Keep opt-in measurement tests and real-model tests ignored only when their annotations accurately state the external cost and command required. Do not add string or regex fallbacks to make analyzer tests pass; repair structured resolution or graph construction instead.

### Milestone 6: Full validation and report

After every bounded milestone passes locally, run formatting, all-feature linting, feature-complete Rust tests, Python tests, and VS Code tests. Confirm the GitHub platform matrix after the resulting changes are pushed by an authorized contributor. Write the final plan retrospective with bugs fixed, regression tests, removed/consolidated tests and retained coverage, exact command outcomes, timing data, and explicitly accepted limitations.

## Concrete Steps

All commands run from the repository root `/Users/dave/.codex/worktrees/53f5/bifrost`.

1. Inspect without editing:

       git status --short --branch
       git fetch origin --prune
       rg -n '#\\[ignore' tests src
       rg -n 'cargo test|cargo clippy|needs: rust' .github/workflows/ci.yml

2. Establish the Milestone 1 baseline with the exact integration target so Cargo does not enumerate unrelated test binaries:

       scripts/with-isolated-cargo-target.sh cargo test --features nlp --test jsts_usage_graph_deadlock -- --nocapture

   Expect exactly one test named `jsts_usage_graph_receiver_analysis_does_not_deadlock_on_pool` to pass. Record the wall time and any compiler/toolchain problem rather than suppressing it.

3. Run the memo unit tests after the integration baseline:

       scripts/with-isolated-cargo-target.sh cargo test --features nlp analyzer::pool_memo::tests --lib -- --nocapture

   Expect the controlled re-entrant test to pass without a hang.

   If an execution environment interrupts a cold isolated build before Cargo exits, record the interruption, preserve the source unchanged, and retry from a retained terminal rather than treating partial compiler output as test evidence.

4. After a narrowly scoped test or production change, run the focused target first, then only the neighboring usage suite identified by source dependencies. Use the same isolated target helper for any Cargo command that can create artifacts.

5. At the final milestone, run:

       cargo fmt --check
       scripts/with-isolated-cargo-target.sh cargo clippy --all-targets --all-features -- -D warnings
       scripts/with-isolated-cargo-target.sh cargo test --features nlp,python
       bash scripts/test_python.sh
       (cd editors/vscode && npm test)

## Validation and Acceptance

Milestone 1 is accepted only if its end-to-end test exercises JS/TS usage-graph receiver analysis under a controlled Rayon pool, the generic memo test covers re-entrant initialization independently, both focused targets pass, and any fixture reduction has a measured before/after result without weaker behavior assertions. It is not accepted merely because a timeout is shortened.

The complete issue is accepted only when each selected category above has an evidence-backed result or an explicit inapplicability explanation; every discovered bug has a minimized permanent regression; ignored tests have current, specific justification; and all commands in the final validation matrix pass. CI performance claims must quote comparable job or command timing before and after the change.

## Idempotence and Recovery

The inventory and focused tests are safe to repeat. The isolated Cargo helper removes its own target directory when it exits normally; use `scripts/cleanup-bifrost-tmp.sh` in dry-run mode to inspect any stale helper directory before an explicit cleanup. If a deadlock probe times out, preserve its exact fixture and output, do not retry indefinitely, and diagnose the structured initialization path before changing it. Do not delete ordinary workspace `target/` directories during this exercise.

## Artifacts and Notes

Baseline CI observation from run `29823845761`:

    rust (x86_64-unknown-linux-gnu) cargo test: 11m37s
    rust (aarch64-unknown-linux-gnu) cargo test: 11m32s
    rust (aarch64-apple-darwin) cargo test: 12m58s
    rust (x86_64-pc-windows-msvc) cargo test: 16m23s
    python jobs begin only after rust because the workflow declares needs: rust

## Interfaces and Dependencies

Use `tests/common/inline_project.rs::InlineTestProject` for small analyzer projects. Use `std::sync::Barrier` or channels for test scheduling control. The lazy cache interface under test is `crate::analyzer::pool_memo::PoolSafeMemo<T>`: `get_or_build` must select serial construction from a Rayon worker, publish at most one `Arc<T>`, and let callers observe the stored value. It must not block workers on a cache initializer that itself needs Rayon work.

Plan created on 2026-07-21 to start issue #872 with the bounded concurrency/cache milestone and live CI timing evidence.
