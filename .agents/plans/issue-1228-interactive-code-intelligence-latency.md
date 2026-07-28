# Restore interactive code-intelligence latency and cancellation

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. This document must be maintained in accordance with `.agents/PLANS.md` from the repository root.

## Purpose / Big Picture

Common Bifrost MCP code-intelligence requests must not leave an agent waiting behind abandoned analysis. After this work, a warm symbol search, exact source read, definition/navigation request, summary request, or usage scan against a repository the size of Bifrost will either complete with a warm p95 below five seconds in the stable release benchmark or return an explicitly incomplete result within its bounded work budget. Cancelling a usage scan will reach the analyzer work, stop it cooperatively, and leave a following lightweight request responsive.

The visible proof has two parts. Deterministic tests will prove cancellation propagation, bounded work, truthful incomplete-result semantics, and the absence of transport head-of-line blocking without relying on machine speed. A release-mode benchmark over a pinned Bifrost source snapshot will record warm p50 and p95, queue wait, execution, response delivery, and the dominant execution phase. Ordinary CI will not fail on noisy wall-clock assertions; the stable Benchmark workflow lane will enforce the five-second product threshold.

## Progress

- [x] (2026-07-28 08:32Z) Fetched `origin/master`, advanced the clean checkout through `53cc729d`, and verified the source matched the remote before implementation.
- [x] (2026-07-28 08:32Z) Reproduced a current-plugin line-only `SemanticProcedureSummary` scan for more than 42 seconds, then terminated the caller; the plugin runtime may predate the current source build, so this is consumer evidence rather than a benchmark of `53cc729d`.
- [x] (2026-07-28 08:32Z) Traced MCP admission, service dispatch, scan rendering, `UsageFinder`, cross-language cancellation checks, profiling, and benchmark/report seams on current source.
- [x] (2026-07-28 08:32Z) Reviewed Benchmark Actions runs from July 24 through July 27 and separated persistent Click/Python latency signals from unrelated PHP and C++ correctness failures.
- [x] (2026-07-28 08:32Z) Wrote this implementation plan with deterministic behavior gates and a separate stable wall-clock lane.
- [x] (2026-07-28 09:21Z) Milestone 1 implementation complete: both scan surfaces share request cancellation and bounded candidate/source/callsite work, every bounded result carries a typed incomplete reason, five issue-specific unit/service tests and the large-response integration test pass, and the checkpoint is ready to commit on the existing issue branch.
- [ ] Milestone 2: remove MCP reader head-of-line blocking for analyzer-backed query tools, add deterministic transport/concurrency tests and lifecycle timing spans, update this plan, and commit the milestone.
- [ ] Milestone 3: extend the benchmark client and report with p50/p95, concurrent heavy/light and cancellation scenarios, phase attribution, and a pinned Bifrost corpus; validate and commit the milestone.
- [ ] Milestone 4: run the full Rust gates and a fresh release-mode self-repository campaign, compare it with the recent Actions evidence, resolve any issue-scoped failures, complete the retrospective, and commit the post-milestone review.

## Surprises & Discoveries

- Observation: Current master already contains two important pieces that the issue described as missing. Issue #1199 made multi-pattern symbol search share work and propagate cancellation; issue #1219 memoized Rust parsing and added deterministic parsed-byte complexity tests for location scans.
  Evidence: `tests/issue_1219_location_scan_target.rs` pins one-parse-per-source behavior and line-only versus fully-qualified selector equivalence. The four-pattern issue query completed warm in about 252 ms during diagnosis, while commit `53cc729d` includes the Rust parse memo.

- Observation: Cancellation infrastructure exists below the missing service seam. `UsageFinder` owns a `CancellationToken`, candidate discovery checks it, `UsageScanScope` carries it into graph strategies, and current Java, JavaScript/TypeScript, Python, Go, Ruby, C++, C#, PHP, Rust, and Scala usage paths all contain cooperative checks.
  Evidence: `src/analyzer/usages/finder.rs::UsageFinder::with_cancellation`, `src/analyzer/usages/traits.rs::UsageScanScope::with_cancellation`, and the language graph modules all use the shared token or scope.

- Observation: The current cancellation return is semantically unsafe for a public scan result. `cancelled_query_result` returns an empty successful `FuzzyResult` with no truncation or completion cause, so a caller that wires the token through without changing the model can incorrectly receive `verified_absent`.
  Evidence: `src/analyzer/usages/finder.rs::cancelled_query_result` constructs `FuzzyResult::empty_success()`, while `src/searchtools/scan_usages.rs` treats exhaustive zero-hit results as verified absence.

- Observation: The MCP transport already has most of the machinery required for background standard calls. `PreparedToolCall::Standard` captures normalized arguments and a workspace generation, but `cancellable_tool_request` admits only `query_code`, `search_symbols`, and `run_policy`, so a usage scan remains on the stdin reader and prevents the reader from receiving its cancellation notification.
  Evidence: `src/mcp_common.rs::cancellable_tool_request`, `prepare_tool_call`, `PreparedToolCall`, and `spawn_cancellable_tool_call`.

- Observation: The benchmark already produces synchronized per-request timing traces when profiling is enabled, but ordinary scenario reports omit p95 and the client is synchronous. The required concurrent fairness benchmark therefore needs request-ID-aware send/receive primitives, not a second ad hoc process wrapper.
  Evidence: `src/benchmark/mcp_iteration.rs` brackets each request with profile boundaries; `src/benchmark/report.rs::ScenarioReport::from_timings` sets `p95_ms` to `None`; `src/benchmark/mcp_session.rs::McpSession::call_tool` immediately waits for the next response.

- Observation: The issue's short Rust selector and the source-level #1219 test describe different contracts. The issue calls `SemanticProcedureSummary` exact, while #1219 documents that a bare Rust identifier is not a fully-qualified definition selector. A latency benchmark that accepts a fast `not_found` would be invalid either way.
  Evidence: The short selector returned `not_found` in about 35 ms during diagnosis, while the declaration exists at `src/analyzer/dataflow/reusable_summary.rs:911` and the line-only/canonical scan performs the expensive work.

- Observation: Recent scheduled benchmark failures include a persistent Python signal but do not establish one root cause for issue #1228. Click/Python `scan_usages` rose from a 2469 ms baseline median to 7474, 7780, and 6318 ms on July 25-27; `dead_code_smells` rose from 1240 ms to 6585, 6695, and 5357 ms. FastRoute/PHP usage and fmt/C++ location failures are correctness regressions, and several Python graph changes landed after the last run.
  Evidence: Benchmark workflow runs `30153610367`, `30197412629`, and `30258351822` failed after run `30084696939` succeeded. A fresh current-master campaign is required before attributing causation.

- Observation: A completion cause has to remain separate from the legacy `candidate_files_truncated` boolean. Source-byte admission also omits candidate files, so retaining the boolean preserves existing safety checks and samples while the new typed cause distinguishes candidate-count exhaustion from source-byte exhaustion.
  Evidence: The zero-byte Rust fixture produces `complete: false`, `incomplete_reason: source_bytes`, and no `verified_absent`; the existing classification matrix still treats ordinary candidate truncation as `incomplete_reason: candidate_files`.

- Observation: Fresh isolated Rust test builds spend most of their time compiling and linking rather than exercising the new tests. The five issue-specific tests execute in 0.06 seconds after a 1 minute 45 second clean build; the 350-file response-budget integration fixture executes in 2.89 seconds after a 3 minute clean integration build.
  Evidence: The exact validation transcripts are recorded below. This reinforces the decision to keep ordinary acceptance deterministic rather than enforcing five-second wall time in debug tests.

## Decision Log

- Decision: Stage the work as scan truthfulness, transport responsiveness, then benchmarking rather than changing every analyzer API at once.
  Rationale: Current scan internals already have cancellation hooks. First making the token and completion cause reach those hooks gives a small, independently verifiable safety improvement before concurrency and benchmark-client changes increase the blast radius.
  Date/Author: 2026-07-28 / Codex

- Decision: Represent interruption as an explicit completion cause orthogonal to the existing usage status.
  Rationale: A scan may find real usages before a candidate or response budget is exhausted. Replacing `found` with a generic cancelled status would discard useful meaning, while `complete: false` plus `incomplete_reason` preserves findings and prevents an authoritative absence claim.
  Date/Author: 2026-07-28 / Codex

- Decision: Use deterministic work limits and cancellation checkpoints in ordinary tests; reserve five-second assertions for the stable release benchmark.
  Rationale: Scheduler load and debug builds make wall-clock unit tests flaky. Candidate counts, source-byte admission, test-controlled cancellation checks, and explicit worker barriers prove the behavior independent of host speed.
  Date/Author: 2026-07-28 / Codex

- Decision: Reuse `PreparedToolCall::Standard` and the bounded in-flight registry for analyzer-backed read-only tools rather than building a second executor.
  Rationale: The existing path already captures workspace generation, suppresses stale responses, admits only a bounded number of requests, and lets the stdin reader continue processing notifications. The special workspace-mutating `activate_workspace` path must remain ordered on the reader.
  Date/Author: 2026-07-28 / Codex

- Decision: Benchmark the exact issue payload and a canonical or line-only control against a pinned Bifrost corpus.
  Rationale: This catches any selector-contract change while ensuring a fast resolution failure cannot satisfy the latency target. The control must resolve the declaration and either report usages or an explicit bounded incomplete result.
  Date/Author: 2026-07-28 / Codex

- Decision: Keep the recent Click/Python, FastRoute/PHP, and fmt/C++ failures as validation evidence, not presumed implementation scope.
  Rationale: The data shows persistent latency and correctness signals across different language paths, but no bisect proves a shared cause. This issue will rerun and report them; unrelated correctness fixes should be handled separately unless this implementation directly causes or resolves them.
  Date/Author: 2026-07-28 / Codex

- Decision: Apply a 64 MiB source-byte ceiling to every public usage scan while retaining the existing 1,000-file whole-workspace cap, 10,000-file path-scoped cap, and 1,000-callsite cap.
  Rationale: `scan_usages` previously left source volume unbounded even though `UsageFinder` already had deterministic source admission. A relatively generous ceiling bounds pathological scans without changing ordinary small and medium repository behavior, and every omission is now explicit rather than presented as exhaustive absence.
  Date/Author: 2026-07-28 / Codex

## Outcomes & Retrospective

Milestone 1 is implemented. `UsageFinder::QueryResult` now distinguishes complete, cancelled, candidate-file-bounded, and source-byte-bounded queries; cancellation is checked during source admission as well as candidate and graph work. Both public scan surfaces receive the service token and one bounded execution context. Public results retain useful statuses and hits while serializing `complete: false` plus one of `cancelled`, `candidate_files`, `source_bytes`, `callsites`, or `response_budget`. A cancelled scan is an explicit failure rather than an empty success, and bounded zero-hit scans cannot become `verified_absent`.

The remaining work is transport responsiveness and benchmark evidence: scans are now cancellable once they receive a request token, but the MCP reader still has to move analyzer-backed standard requests onto the bounded background path so it can receive cancellation notifications and lightweight requests while a scan runs.

This section must be updated after each milestone with observed behavior, test counts, benchmark results, residual risks, and any scope moved to a follow-up issue.

## Context and Orientation

Model Context Protocol (MCP) requests arrive as newline-delimited JSON-RPC messages in `src/mcp_common.rs`. The stdin loop must remain free to read `notifications/cancelled` and later requests. A background request is registered in `McpRequestCancellations`, given a cloneable `CancellationToken`, and executed by `spawn_cancellable_tool_call`. The token is cooperative: it only stops work when code calls `is_cancelled()`.

`src/searchtools_service.rs` is the tool dispatch boundary. `SearchToolsService::call_tool_output_with_cancellation` receives the optional request token, acquires an immutable analyzer snapshot, decodes arguments, calls the selected searchtool, and renders structured and text output. Symbol search consumes the token today; the two usage-scan arms do not.

`src/searchtools/scan_usages.rs` resolves a location or reference selector to declarations, selects candidate files, invokes `UsageFinder`, classifies the result, and renders `ScanUsagesEntry` values. A result's `status` says what was observed, such as `found`, `verified_absent`, or `unverified_absent`. Its `complete` flag says whether the evidence is exhaustive. An incomplete reason is the machine-readable reason exhaustive evidence was unavailable; this plan adds that distinction explicitly.

`src/analyzer/usages/finder.rs` discovers candidate files and dispatches them to the language-specific usage graph. It already accepts maximum candidate-file and call-site counts, has an internal source-byte admission path, and passes cancellation into `UsageScanScope` in `src/analyzer/usages/traits.rs`. Candidate-file, source-byte, call-site, cancellation, and response-rendering limits are different completion causes and must not be collapsed into one misleading flag.

`src/profiling.rs` provides disabled-by-default timing scopes. With `BIFROST_TIMING=1`, the MCP benchmark captures synchronized traces through `src/benchmark/mcp_iteration.rs`. `src/benchmark/mcp_session.rs` owns the child process and currently sends one request then waits synchronously. `src/benchmark/runner.rs` executes warmups and measured samples. `src/benchmark/report.rs` serializes scenario statistics, and `.github/workflows/benchmark.yml` runs the scheduled regression lane.

## Plan of Work

### Milestone 1: Truthful bounded usage scans

Add an internal scan execution context in `src/searchtools/scan_usages.rs` that owns the request `CancellationToken` and a `ScanUsagesBudget`. The production MCP default will bound candidate files, call sites, and admitted source bytes; direct library convenience functions may construct the normal default context so existing callers remain simple. Add cancellation-aware siblings for both `scan_usages_by_reference` and `scan_usages_by_location`, and pass the context into `scan_usages_backend`.

Change `scoped_usage_finder` to apply the context token through `UsageFinder::with_cancellation`. Use the existing source-byte admission path in `UsageFinder` instead of introducing a timer-only cutoff. Extend `QueryResult` with a completion value that distinguishes `Complete`, `Cancelled`, and `BudgetExhausted` with a stable dimension such as `candidate_files`, `source_bytes`, or `callsites`. Do not make `cancelled_query_result` look like an empty successful exhaustive query. For a batch, keep completed earlier targets, stop starting new expensive target work after cancellation, and emit an incomplete entry for every unfinished requested target so response cardinality remains predictable.

Extend `ScanUsagesEntry` with an optional `incomplete_reason` enum and make `summary.partial` derive from entry completeness. A partial entry that has proven hits retains `status: found`; a zero-hit interrupted entry is `unverified_absent` or `failure` with `reason_kind: cancelled` as appropriate, never `verified_absent`. Preserve candidate/source/callsite/response limits as distinct reasons and give a concise recovery note, such as narrowing `paths` or retrying when cancellation was external. Update the text renderer and structured renderer together.

In `src/searchtools_service.rs::call_tool_output_with_cancellation`, forward the same request token and production budget into both scan arms. Add profiling scopes for target resolution, candidate admission, provider/graph work, and rendering around existing work rather than duplicating language-specific timers.

Focused tests will live beside the behavior they pin. `src/analyzer/usages/finder.rs` will use `CancellationToken::cancel_after_checks_for_test` and a deterministic candidate provider to prove pre-cancelled and mid-discovery queries report cancellation, while a deliberately small source budget reports budget exhaustion. `src/searchtools_service.rs` tests will call both scan endpoints through the cancellation-aware service path and assert `complete: false`, the correct `incomplete_reason`, and no `verified_absent`. An integration test using `tests/common/inline_project.rs` will prove an ordinary completed scan retains exact found/absence behavior and an interrupted multi-target scan preserves completed entries without making claims for unfinished ones.

At the milestone boundary, run the focused tests, `cargo fmt`, update every living section of this plan, and commit only the plan and milestone files on the current checkout.

### Milestone 2: Responsive MCP dispatch and lifecycle evidence

In `src/mcp_common.rs`, replace the three-name background predicate with one central classification for workspace-bound, read-only analyzer tool calls. Every analyzer-backed query exposed by the active server spec must use the bounded background registry. `activate_workspace` and any future connection/workspace mutation must remain ordered on the reader thread. Preparation still occurs on the reader so argument normalization and workspace-generation capture are deterministic; execution occurs after registration on the existing background path.

Keep responses associated with their JSON-RPC request IDs and allow completion order to differ from submission order. Preserve the existing in-flight cap, duplicate-ID rejection, stale-workspace cancellation, response-queue backpressure behavior, and completion cleanup. Audit snapshot acquisition, analyzer query scopes, store locks, lazy cache initialization, and Rayon/provider work while the new concurrency tests run; fix any shared lock held across expensive computation instead of adding a text fallback or hiding the symptom with a larger thread pool.

Add request-lifecycle profiling scopes in `src/mcp_common.rs` for accepted-to-worker-start queue wait, worker execution, response-queue wait, and writer delivery. Include request ID only for trace correlation and a bounded-cardinality tool name/phase label; never log arguments or source. Retain `SearchToolsService::snapshot_for_query` as its own execution phase. The benchmark parser will later combine these transport scopes with the scan phases from Milestone 1.

Tests must prove behavior, not merely mirror the tool-name registry. Refactor the reader/dispatcher into a testable function over generic buffered input/output or add a test-only execution gate at the existing prepared-call boundary. Hold a real background scan after it has registered, feed a lightweight exact source request and a cancellation notification through the same dispatcher, and assert by request ID that the lightweight response is delivered and the scan token is cancelled before releasing the gate. Separately assert that workspace mutation remains ordered, the in-flight cap still rejects excess work, stale generations suppress responses, and cancelling one request does not cancel another. The gate or barrier must make ordering deterministic; do not assert that an operation happens within an arbitrary number of milliseconds.

Add one real service/inline-project regression that exercises scan cancellation beneath the transport test. Together the tests prove transport admission, notification delivery, service forwarding, analyzer observation, truthful rendering, and post-cancellation capacity release without depending on a single fragile end-to-end timer.

At the milestone boundary, run the focused MCP and scan tests, `cargo fmt`, update the plan, and commit only the milestone files.

### Milestone 3: Actionable release benchmark

In `src/benchmark/report.rs`, calculate p95 for every measured scenario in `ScenarioReport::from_timings`. Add an explicit serialized `p50_ms` equal to the median and retain `median_ms` while current baseline comparison and summaries use that field; add report tests proving the percentile calculation for ordered and unordered samples. Extend the comparison/summary output to show p50 and p95 without changing regression classification silently.

In `src/benchmark/mcp_session.rs`, split synchronous `call_tool` into request-ID-aware primitives that can send a tool request, send the MCP cancellation notification, and receive/cache responses until a requested ID arrives. The ordinary synchronous method becomes a small wrapper over those primitives. Handle out-of-order responses without losing unmatched results, reject duplicate/unexpected IDs clearly, and keep profile-boundary handling synchronized. Use the protocol's `notifications/cancelled` message with `requestId`, matching the server implementation; do not invent a second cancellation method.

Add an interactive-latency benchmark case to `src/benchmark/manifest.rs`, `src/benchmark/runner.rs`, and `benchmark/targets.toml` using a pinned Bifrost repository snapshot. Extend `BenchmarkLocationSelector` so the fixture can carry an optional exact symbol. Include the original short-selector payload and a line-only or canonical fully-qualified control that must resolve and do actual scan work. Add the four-pattern `search_symbols` case and the four-symbol `get_symbol_sources` case from the issue comment. Result invariants must reject `not_found` for the canonical/line-only performance control and accept only a complete answer or an explicitly bounded incomplete answer.

Add a paired heavy/light scenario. Send the heavy usage scan, wait for a server-side started marker in the synchronized profile trace or a benchmark-only handshake, send an exact lightweight source lookup, then cancel the heavy request. Record light-request latency, cancellation-to-heavy-completion latency, and whether the heavy result was explicitly incomplete. The benchmark must not rely on submission order and must fail if the light response is trapped behind the heavy response.

Parse the synchronized `BIFROST_TIMING` trace for stable transport and execution phase labels. Store per-iteration queue, execution, delivery, snapshot, target-resolution, candidate-discovery, provider/graph, ranking, and rendering durations in the report, plus the dominant phase when end-to-end time exceeds five seconds. Keep raw trace artifacts for diagnosis. If a phase is missing, report that as a benchmark instrumentation failure rather than guessing from total time.

Update `.github/workflows/benchmark.yml` and `tests/benchmark_workflow_policy.rs` so the pinned self-repository interactive profile runs in release mode in the stable scheduled performance lane. Ordinary CI will validate schemas, percentile math, out-of-order response handling, cancellation behavior, and work budgets deterministically. The performance lane will use two warmups and at least ten measured samples, enforce warm p95 below 5000 ms for each named common request or an explicit bounded incomplete result returned within 5000 ms, upload traces, and publish p50/p95 plus dominant phase. Keep the existing environment-variance reporting visible so a broad runner slowdown is distinguishable from one query regression.

At the milestone boundary, run benchmark unit/integration tests, a small release-mode smoke campaign, `cargo fmt`, update the plan, and commit only the benchmark milestone files.

### Milestone 4: Current-master validation and regression review

Run the complete quality gates through `scripts/with-isolated-cargo-target.sh`: focused issue tests, all-target/all-feature Clippy with warnings denied, and the feature-enabled test suites. Tests must disable the real semantic model/indexer as repository guidance requires. Do not create a manually named cargo target directory.

Run the release benchmark against the pinned Bifrost corpus and capture every measured duration and phase aggregate. The four-pattern search, exact source fixture, and valid scan control must either have warm p95 below five seconds or return the specified bounded incomplete result inside five seconds. The heavy/light case must show the lightweight response is independent of the heavy response and that cancellation releases the in-flight slot.

Refresh the latest scheduled Benchmark Actions data. Recheck Click/Python `scan_usages` and `dead_code_smells`, FastRoute/PHP usage, and fmt/C++ location on a run containing the implemented changes. If the Python latency signal remains, use the new dominant-phase evidence to decide whether an issue-scoped optimization remains in this plan. Do not fold the PHP or C++ correctness regressions into this issue unless the new transport or budget work is their direct cause. Record follow-up issue recommendations in `Outcomes & Retrospective` without creating them unless requested.

Complete the plan's evidence and retrospective, perform a post-milestone review of the whole diff, rerun any gate affected by review fixes, and commit that review checkpoint on the current checkout.

## Concrete Steps

All commands run from `/Users/dave/.codex/worktrees/8c634a25-8cac-4fde-9fd1-704a5b4025a8/bifrost`.

Before each milestone, confirm the checkout and preserve unrelated work:

    git status --short --branch
    git rev-parse HEAD origin/master

Format after Rust edits:

    cargo fmt

Run focused library and integration tests through the managed temporary target helper. Update the exact filters as test names are finalized, but keep separate commands for the finder/service, MCP, and benchmark milestones so failures are attributable:

    scripts/with-isolated-cargo-target.sh cargo test --lib cancellation -- --nocapture
    scripts/with-isolated-cargo-target.sh cargo test --lib scan_usages -- --nocapture
    scripts/with-isolated-cargo-target.sh cargo test --lib mcp_common -- --nocapture
    scripts/with-isolated-cargo-target.sh cargo test --lib benchmark -- --nocapture
    scripts/with-isolated-cargo-target.sh cargo test --test issue_1228_interactive_latency -- --nocapture
    scripts/with-isolated-cargo-target.sh cargo test --test bifrost_benchmark_run --test benchmark_workflow_policy -- --nocapture

Run the core Rust lint gate:

    scripts/with-isolated-cargo-target.sh cargo clippy --all-targets --all-features -- -D warnings

Run full feature-enabled tests as separate library and integration commands if the local PyO3 linker requires it, always preserving `--features nlp,python` so the NLP suites are not silently skipped:

    scripts/with-isolated-cargo-target.sh cargo test --features nlp,python --lib
    scripts/with-isolated-cargo-target.sh cargo test --features nlp,python --tests

Run the release self-repository benchmark using the final CLI arguments added in Milestone 3. Record the exact final command here when the manifest and selector names are implemented. It must use the pinned Bifrost target, enable profiling, and write into the normal benchmark output directory; it must not write a persistent analyzer cache during a one-off smoke run if the benchmark offers an ephemeral mode.

After each milestone, update this document's `Progress`, `Surprises & Discoveries`, `Decision Log`, validation transcripts, and revision note. Stage only files changed for the milestone and make the required multiline checkpoint commit on the current issue branch. Record checkpoint hashes in the next plan revision. Do not create or switch branches, rebase, push, or open a pull request without explicit user instruction.

## Validation and Acceptance

Milestone 1 is accepted when both public scan surfaces receive one shared token and bounded work context; pre-cancelled, mid-candidate, source-budget, callsite-budget, and multi-target cases are deterministic; every interrupted or bounded response is `complete: false` with the correct machine-readable reason; and no interrupted zero-hit response is `verified_absent`.

Milestone 2 is accepted when a deterministic transport test holds a heavy scan worker, sends cancellation and a lightweight exact source lookup through the same reader, receives the lightweight response by its own ID before releasing the heavy worker, observes cancellation in the real scan token, and proves the in-flight slot is released. Existing duplicate-ID, capacity, stale-workspace, and writer-backpressure tests must still pass.

Milestone 3 is accepted when all benchmark scenarios serialize p50 and p95, the client safely receives responses out of order, the pinned Bifrost target exercises the issue requests plus a resolution-valid scan control, and profiled output separates queue, execution, delivery, and named internal phases. Ordinary CI coverage must contain no five-second debug-build assertion.

The full issue is accepted when the release stable-lane report shows each named warm common request has p95 below 5000 ms or returns an explicitly incomplete bounded response within 5000 ms; a cancelled symbol-qualified scan stops underlying work and does not starve the following source lookup; the benchmark identifies a dominant phase for any miss; all focused tests pass; `cargo fmt` is clean; all-target/all-feature Clippy passes with warnings denied; and the feature-enabled test suites pass or any environment-only linker limitation is reproduced and documented precisely.

## Idempotence and Recovery

All source edits and tests are safe to rerun. `scripts/with-isolated-cargo-target.sh` creates and removes its own marked target directory; never create a manually named `/tmp/bifrost-*` target. If a test or build is interrupted, rerun the same helper command. Do not delete `.bifrost` caches as part of ordinary validation; use the benchmark's explicit ephemeral cache mode where available.

The transport changes are additive around the existing `PreparedToolCall` path. If a milestone fails, keep the earlier committed milestone intact and fix forward. Do not disable cancellation checks, relax tests, add lint ignores, or replace structured resolution with source scanning. Preserve unrelated worktree changes and stage explicit paths only.

The benchmark corpus is a pinned remote commit, so repeated campaigns analyze identical source. A failed clone or interrupted campaign may be rerun through the existing repository cache preparation. Raw profile traces and reports are artifacts, not source files; keep them out of commits unless a small checked-in fixture is explicitly required by a deterministic parser test.

## Artifacts and Notes

Live diagnosis on 2026-07-28:

    implementation base HEAD/origin/master: 45841f1a9e665a056380eb7c0a1b8485389cb48c
    current branch: 1228-restore-sub-five-second-latency-for-common-code-intelligence-queries
    search_symbols four-pattern warm observation: approximately 252 ms
    short-selector usage scan: approximately 35 ms, status not_found
    line-only usage scan: still running after approximately 42 s; caller terminated
    following exact source read after an earlier blocked canonical scan: blocked beyond 22 s

Recent scheduled Benchmark Actions:

    2026-07-24 run 30084696939: success, 0 regressions
    2026-07-25 run 30153610367: failure, 6 actionable regressions
    2026-07-26 run 30197412629: failure, 5 actionable regressions
    2026-07-27 run 30258351822: failure, 4 actionable regressions

Persistent measured signals from the downloaded reports:

    click-py scan_usages median: baseline 2469 ms; candidates 7474, 7780, 6318 ms
    click-py dead_code_smells median: baseline 1240 ms; candidates 6585, 6695, 5357 ms
    fastroute-php scan_usages: candidate found no call sites
    fmt-cpp get_symbol_locations: candidate found no locations

The final implementation must append focused test transcripts, final p50/p95 tables, dominant-phase evidence, and refreshed Actions run links here.

Milestone 1 focused validation:

    scripts/with-isolated-cargo-target.sh cargo test --lib issue_1228 -- --nocapture
    result: 5 passed; 0 failed; 1972 filtered out; tests finished in 0.06 s

    scripts/with-isolated-cargo-target.sh cargo test --test searchtools_service scan_usages_demotes_large_result_to_summary_within_budget -- --exact --nocapture
    result: 1 passed; 0 failed; 189 filtered out; test finished in 2.89 s

## Interfaces and Dependencies

No new crate dependency is expected. Use `crate::CancellationToken`, `src/analyzer/usages/finder.rs` source-byte admission, `src/analyzer/usages/traits.rs::UsageScanScope`, the existing bounded MCP cancellation registry, `src/profiling.rs`, and the current benchmark session/profile infrastructure.

In `src/searchtools/scan_usages.rs`, define internal equivalents of:

    #[derive(Clone)]
    pub(crate) struct ScanUsagesExecutionContext {
        pub cancellation: CancellationToken,
        pub budget: ScanUsagesBudget,
    }

    #[derive(Clone, Copy)]
    pub(crate) struct ScanUsagesBudget {
        pub max_candidate_files: usize,
        pub max_source_bytes: usize,
        pub max_callsites: usize,
    }

    #[derive(Clone, Copy, Serialize, PartialEq, Eq)]
    #[serde(rename_all = "snake_case")]
    pub enum ScanUsagesIncompleteReason {
        Cancelled,
        CandidateFiles,
        SourceBytes,
        Callsites,
        ResponseBudget,
    }

The exact names may change if an existing repository type already expresses the same concept, but one request token and one budget object must cross the service, target-resolution, candidate, provider/graph, and render boundaries. Do not pass a loose group of unrelated numeric parameters through every function.

In `src/analyzer/usages/finder.rs`, make `QueryResult` expose a completion value instead of encoding cancellation as empty success. In `src/searchtools/scan_usages.rs`, serialize `incomplete_reason` only when `complete` is false and enforce in constructors that `verified_absent` requires complete exhaustive evidence.

In `src/benchmark/mcp_session.rs`, expose request-ID-aware send, cancel, and receive operations while retaining `call_tool` as the synchronous convenience wrapper. In `src/benchmark/report.rs`, compute `p50_ms` and `p95_ms` from every non-empty measured sample vector and retain raw durations for auditability.

Plan revision note (2026-07-28 08:32Z): Created the initial self-contained plan after syncing current master, validating the issue and current source seams, probing the live plugin, reviewing recent Benchmark Actions artifacts, and separating deterministic correctness gates from the stable release wall-clock contract.

Plan revision note (2026-07-28 09:21Z): Updated the checkout state to the app-created issue branch at base `45841f1a`; recorded Milestone 1's cancellation, work-budget, incomplete-result, profiling, and regression-test implementation; documented the 64 MiB source budget and focused validation results; and removed stale detached-HEAD recovery guidance.
