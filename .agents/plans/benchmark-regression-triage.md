# Make benchmark failures distinguish latency bounds from analyzer regressions

This ExecPlan is a living document. It is maintained according to `.agents/PLANS.md` in the repository root.

## Purpose / Big Picture

The benchmark run `30427088598` reports ordinary analyzer regressions and interactive-latency failures through the same short error strings. After this work, a benchmark contributor can tell whether a scenario returned a real empty answer, stopped because its five-second interactive budget expired, or was measured before the MCP server had warmed its workspace. The interactive benchmark will warm the server outside the timed samples, while the regular compatibility benchmark will preserve bounded scan facts instead of mislabeling them as "no call sites".

The first observable proof is a focused unit test that supplies a bounded scan response and asserts that the report says it is incomplete. The second is a narrowed GitHub benchmark Action on this branch: its interactive report must not fail `search-common-symbols` merely because the first timed request performs the initial workspace build. The Action still intentionally fails if a genuinely warm request exceeds the five-second product budget.

## Progress

- [x] (2026-07-29 09:50Z) Investigated run `30427088598`, downloaded its reports and profiles, and separated normal benchmark failures from interactive failures.
- [x] (2026-07-29 09:50Z) Created `dave/benchmark-latency-regressions` from refreshed `origin/master`.
- [x] (2026-07-29 10:20Z) Mapped the benchmark/MCP cancellation seam and confirmed that ordinary scans preserve explicit bounded facts while the runner discarded them.
- [x] (2026-07-29 10:20Z) Implemented truthful bounded-result reporting, a benchmark-child request budget, and an interactive-session prewarm.
- [ ] Add focused behavior tests and complete Rust formatting, tests, clippy, and policy validation.
- [ ] Commit the milestone, open a PR, and dispatch a narrowed benchmark Action against the branch.

## Surprises & Discoveries

- Observation: The ordinary benchmark compares against `benchmark/baselines/ubuntu-latest.json` from commit `cf46d197`, before the five-second MCP request budget was introduced.
  Evidence: `google-gson` had a 7.59 second baseline `scan_usages` median, while the candidate returned a bounded incomplete response that the runner reduced to "found no call sites".
- Observation: The first interactive request performs a full lazy workspace build inside the request budget.
  Evidence: the `search-common-symbols` profile reports `WorkspaceAnalyzer::build (17203.7 ms)` and only `0.5 ms` inside `searchtools::search_symbols`.
- Observation: Queueing is not the cause of the warm scan failures.
  Evidence: both scan cases have `queue_wait` p95 of `0.1 ms`, while their execution p95 is approximately `5.67 s` and all samples are explicitly bounded incomplete.
- Observation: the full all-feature Clippy gate is currently blocked by an unrelated new warning on `origin/master`.
  Evidence: `src/analyzer/usages/get_definition/js_ts.rs:808` has a nine-argument function from `9e60fddcb`; `cargo clippy --all-targets --all-features -- -D warnings` reports `clippy::too_many_arguments` there before reporting any change in this milestone.
- Observation: the required built-in policy pack cannot complete in the active Bifrost workspace.
  Evidence: `run_policy` with only `bifrost.code-smells`, `fail_on: warning`, and evaluation date `2026-07-29` was cancelled after 5.1 seconds. Filed #1306 with the exact request and result.

## Decision Log

- Decision: Keep normal benchmark compatibility checks and the interactive product gate separate.
  Rationale: A batch comparison needs complete semantic answers, whereas interactive use must fail or return explicitly bounded partial data within five seconds. Treating a bounded answer as an ordinary empty answer loses both kinds of signal.
  Date/Author: 2026-07-29 / Codex
- Decision: Prewarm through the already initialized MCP session before collecting interactive warmups.
  Rationale: Starting a second process would test a different cache and lifecycle. The existing session must materialize its lazy workspace before the five-second latency samples begin.
  Date/Author: 2026-07-29 / Codex
- Decision: Do not fold the C++ `get_symbol_locations` empty answer into this first milestone without its raw structured response.
  Rationale: It may be a semantic lookup regression, while the other failures are independently explained by the new budget and benchmark lifecycle. A narrow follow-up repro avoids conflating those causes.
  Date/Author: 2026-07-29 / Codex
- Decision: Keep the benchmark request-budget override private to benchmark process construction and clamp it to five through sixty seconds.
  Rationale: The process spawned by `McpSession` is benchmark-owned, while the five-second interactive scan timeout remains an explicit tool-level bound. Clamping makes an accidental environment value fail safe to the ordinary five-second request budget.
  Date/Author: 2026-07-29 / Codex

## Outcomes & Retrospective

The focused runner test passed. Formatting and patch validation passed. The full Clippy command reached the project crate under one consistent rustup toolchain but is blocked by the pre-existing `too_many_arguments` lint at `src/analyzer/usages/get_definition/js_ts.rs:808`; this milestone does not alter that file. The required policy check is unreliable because the MCP policy request was cancelled, tracked in #1306. The branch Action and its artifact remain the final acceptance evidence.

## Context and Orientation

`src/benchmark/runner.rs` owns two MCP benchmark modes. `run_mcp_scenarios` sends ordinary tool scenarios through one long-lived `McpSession`; `assert_scenario_result` checks their structured responses. `run_interactive_query_scenarios` owns the release-mode latency gate and currently starts a fresh initialized session, then immediately sends its first timed warmup request. The MCP service creates its workspace lazily, so that request includes startup work.

`src/mcp_common.rs` gives admitted MCP analyzer requests a five-second `CancellationToken`. Scan tools preserve a truthful `partial` result on timeout, while many other tools return an internal timeout error. `src/searchtools/scan_usages.rs` encodes `complete` and `incomplete_reason` for every scan result. The regular runner currently only checks whether a scan has call sites, so it cannot explain when a result was intentionally bounded.

`src/relevance.rs` and `src/code_quality/dead_code_smells.rs` contain the expensive ranking and code-smell paths that timed out in Express, Click, and Dapper. Their cancellation reach must be evaluated separately; pre/post checks in `SearchToolsService` do not stop their internal work.

## Plan of Work

First, add a benchmark-only MCP request-budget override that is set by the benchmark child process. It must be parsed defensively, clamped to a conservative five-through-sixty-second range, and be long enough to let benchmark setup and complete compatibility scenarios finish. The interactive runner will still use its per-case five-second p95 assertion, so this override improves measurement fidelity without weakening the product acceptance criterion.

Next, add a deterministic prewarm request in `run_interactive_query_scenarios` after `start_initialized_session` and before any case warmup. The prewarm must perform the lazy workspace build but not add a sample to any case. A failure should be reported against every case with a clear initialization message rather than being presented as a search-symbols regression.

Then update ordinary scan assertions to inspect `structuredContent.summary.partial`, each result's `complete`, and its `incomplete_reason`. A bounded scan remains a failed compatibility scenario, but its error must name the explicit reason and never claim verified absence or zero call sites. Add a focused unit test using a minimal bounded scan payload.

Finally, trace the relevance and dead-code timeouts with the new branch Action. If the report proves they still exceed five seconds after the harness correction, add cooperative cancellation only at loops that can observe the shared token without changing ranking or smell semantics. Do not widen the first patch with the unresolved C++ location lookup.

## Concrete Steps

All commands run from `/Users/dave/.codex/worktrees/9d17/bifrost`.

1. Read `src/benchmark/runner.rs`, `src/benchmark/mcp_session.rs`, and `src/mcp_common.rs`, then add the benchmark-only budget plumbing and prewarm.
2. Add runner tests that construct MCP JSON payloads for complete and bounded scans, proving error text distinguishes the two.
3. Run the smallest focused test targets first, then `cargo fmt`, `cargo clippy --all-targets --all-features -- -D warnings`, and the repository policy pack.
4. Commit only plan and implementation files, push `dave/benchmark-latency-regressions`, open a draft PR, and dispatch the Benchmark workflow with the branch as its ref and a selected repository if the workflow exposes that input.

## Validation and Acceptance

Run the focused runner test and expect it to prove that a response containing `summary.partial: true` is reported as bounded with its reason. Run the interactive benchmark test suite and expect the new prewarm to be outside every recorded timing array.

Run `cargo fmt` and `cargo clippy --all-targets --all-features -- -D warnings` through `scripts/with-isolated-cargo-target.sh`. Run the installed `bifrost.code-smells` pack with the current UTC evaluation date and require a clean, reliable report.

The branch Action is accepted when its artifact shows an initialized server before interactive samples, no `search-common-symbols` false failure caused by a cold workspace build, and explicit bounded-scan diagnostics where a scan cannot complete. It is acceptable for genuine warm latency or semantic lookup failures to remain red; they must be named precisely in the PR.

## Idempotence and Recovery

The benchmark-only override must be absent unless the benchmark child explicitly sets it. Re-running tests or the Action is safe. The workspace must not retain benchmark target directories; use `scripts/with-isolated-cargo-target.sh` for local compilation. If an Action artifact is insufficient to classify a failure, preserve it under `/private/tmp` and create a focused reproduction instead of changing benchmark expectations.

## Artifacts and Notes

The original run is `https://github.com/BrokkAi/bifrost/actions/runs/30427088598`. Its interactive artifact identifies the primary warm scan phase as `usages::graph_find_usages` and the initial search failure as a 17.2 second lazy build. The initial milestone deliberately makes those facts visible and reproducible; it does not certify the still-unclassified C++ location result.

## Interfaces and Dependencies

At completion, `src/mcp_common.rs` will expose only an internal helper for deriving the benchmark child request budget from an explicitly named environment variable. `src/benchmark/mcp_session.rs` will set that variable when spawning the benchmark-owned Bifrost process. `src/benchmark/runner.rs` will contain a private prewarm helper returning `Result<(), String>` and a private scan-completeness assertion used by ordinary scenarios.

The public MCP JSON shape is unchanged. `scan_usages` continues to return its existing `summary.partial`, `complete`, and `incomplete_reason` fields. The new runner behavior consumes those fields rather than introducing a second representation.

Plan revised 2026-07-29: created after the run investigation to separate harness correctness from the unresolved C++ semantic lookup. Updated after implementation and validation: recorded the focused test pass, pre-existing Clippy failure, and unreliable policy check (#1306) before dispatching the branch Action.
