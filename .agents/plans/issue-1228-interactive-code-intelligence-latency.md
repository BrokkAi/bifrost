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
- [x] (2026-07-28 09:21Z) Milestone 1 complete and checkpointed as `d9bb61bf`: both scan surfaces share request cancellation and bounded candidate/source/callsite work, every bounded result carries a typed incomplete reason, five issue-specific unit/service tests and the large-response integration test pass, and the post-checkpoint review found no semantic or scope correction.
- [x] (2026-07-28 09:35Z) Milestone 2 complete and checkpointed as `fdb403f3`: every read-only tool call leaves the stdin reader for the existing four-slot bounded worker path, workspace-mutating lifecycle calls remain reader-ordered, query/policy snapshot preparation moved off the reader, lifecycle timing covers queue/execution/response-queue/writer phases, and all 14 MCP transport tests pass.
- [x] (2026-07-28 11:04Z) Milestone 3 implementation and live campaign complete: the request-ID-aware benchmark client, pinned release-mode interactive manifest, p50/p95 and bounded-incomplete reporting, heavy/light cancellation case, workflow gate, and raw lifecycle profiles are in place; all ten measured scenarios passed the 5,000 ms contract.
- [x] (2026-07-28 13:12Z) Milestone 4 complete: whole-diff security, correctness/performance, CI, architecture, and duplication reviews were applied; 26 issue-specific unit tests, 25 benchmark contract/runner tests, and the 2,041-test feature-enabled library suite pass; formatting and all-target/all-feature Clippy are clean; and the final 20-sample release gate passes all ten scenarios.
- [x] (2026-07-28 15:08Z) Milestone 5 complete: cancellable MCP Rust navigation now uses the ordinary full resolver, reference-context construction is cooperative and cache-atomic, expensive context work is syntax-gated, the direct-versus-cancellable definition/declaration parity matrix passes, all navigation and feature-enabled tests pass, and the 20-sample latency gate remains below five seconds.

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

- Observation: Merely expanding the old three-tool background allowlist would still leave expensive `query_code` and `run_policy` preparation on the stdin reader because `prepare_tool_call` eagerly captured an analyzer snapshot for those variants.
  Evidence: `SearchToolsService::prepare_query_code` and `prepare_run_policy` both call `snapshot_for_query`. Milestone 2 now prepares ordinary normalized arguments and the accepted workspace generation on the reader, then performs snapshot acquisition inside the worker through `call_tool_output_with_cancellation`; direct prepared variants remain for internal callers and focused tests.

- Observation: The existing transport boundaries were sufficient to make the fairness regression deterministic without a wall-clock timeout. A test-only worker-start hook can hold the real scan immediately before execution while the normal notification handler cancels its real token and a source lookup returns the actual `lib.rs` definition on the test thread.
  Evidence: `issue_1228_cancelled_scan_does_not_block_following_source_lookup` verifies the source body before releasing the scan barrier, then verifies the scan's `cancelled` incomplete reason and explicitly performs the same completion cleanup as the writer.

- Observation: A request deadline at the searchtool boundary was not sufficient until Rust's large per-file AST passes observed cancellation while walking nodes. The first release campaign still measured the line-only scan at 18-26 seconds after a four-second request token had expired.
  Evidence: The Rust direct/member usage passes now check the shared token before and during prepared-syntax, lexical-scope, reference-context, binding, and resolution traversal. The member scan was converted from recursion to the shared iterative tree walk, whose new `Stop` action propagates cooperative termination.

- Observation: The issue's short Rust selector can be resolved safely when its declaration location is exact. Requiring a fully-qualified name even at an exact declaration coordinate made the first benchmark case return a fast `not_found`, which would have been a vacuous latency success.
  Evidence: `resolve_scan_usages_target` now accepts `CodeUnit::short_name()` only when the precise file/line/column target matches; `issue_1228_short_selector_at_exact_location_resolves_the_declaration` preserves ordinary ambiguity behavior while pinning this exact-location contract.

- Observation: The passing release campaign legitimately used bounded time-budget responses for expensive usage scans, so a green scenario must expose that fact instead of looking indistinguishable from an exhaustive answer.
  Evidence: `ScenarioReport::bounded_incomplete_iterations`, the CLI summary, and the Actions step summary now count measured iterations that passed via an explicitly incomplete result. The gate rejects incomplete results without an approved typed reason and rejects every timed-out `verified_absent` claim.

- Observation: The July 28 scheduled benchmark retained the same four actionable regressions as July 27, with the two Click/Python latency signals worsening on the current commit.
  Evidence: Run `30349710835` reports Click `scan_usages` at 14,421 ms versus a 2,469 ms baseline and `dead_code_smells` at 13,815 ms versus 1,240 ms, plus the existing FastRoute/PHP no-callsites and fmt/C++ no-locations correctness failures.

- Observation: Ten samples were insufficient to expose a bimodal interaction between definition navigation and the usage-scan gate. In the first 20-sample campaign, an MCP definition warmup timed out while an uncancellable Rust reference-context build continued for 12.4 seconds; its background CPU work overlapped the next scenario and pushed the exact scan to an 8,704 ms p95 despite a 3,317 ms p50.
  Evidence: `run-20260728T124342Z.json` recorded definition cancellation, `RustAnalyzer::build_reference_context` at 12,170 ms, and exact-scan samples of 11,588 and 8,704 ms before the remaining samples settled around three seconds. Routing cancellable Rust navigation through bounded structured resolution made the definition p95 57.5 ms and removed the scan tail in the final full campaign.

- Observation: Serializing reference-context cache construction was not a safe performance optimization. An atomic cache experiment prevented duplicate construction but also serialized unrelated scan work and increased candidate discovery to 19.4 seconds, so it was reverted.
  Evidence: The retained experiment profile under `20260728T122307764264Z-65518-0` showed repeated 10-19 second exact scans. Bounding Rust direct/member file admission to parallel batches of four preserved cancellation checkpoints and produced a focused exact-scan p95 of 3,743 ms before the final full gate.

- Observation: This host exposed two independent validation-environment boundaries. The default `cargo clippy` lookup mixed rustup Cargo/rustc with Homebrew `cargo-clippy`/`clippy-driver`, producing an incompatible-crate error even though both reported 1.96.0; and the sandbox denied loopback binds used by three stderr-drain tests. Selecting the matching rustup toolchain made Clippy pass, and the full feature-enabled suite passed outside the network sandbox.
  Evidence: The final matched-toolchain isolated Clippy run completed with warnings denied and removed its managed target. The elevated library run completed with 2,035 passed, 0 failed, and 6 ignored.

- Observation: The Milestone 4 latency fix selected `resolve_rust_bounded` whenever navigation carried a cancellation token, while token-free navigation retained `resolve_rust`. The bounded resolver intentionally covers fewer Rust shapes, so the public MCP and direct library surfaces can disagree even when the token is never cancelled.
  Evidence: `src/analyzer/usages/get_definition/mod.rs::resolve_one` branches on `cancellation`; `src/analyzer/usages/get_definition/rust.rs::resolve_rust_bounded_in_session` handles fields, `self`, type references, and calls, while `resolve_rust_unscoped` additionally handles focused path segments, imports, macros, associated types, lexical shadowing, Cargo routing, and declaration-specific behavior.

- Observation: The full Rust resolver's main cancellation gap is eager reference-context construction, not its declaration queries. `AnalyzerRustDefinitionProvider` already routes bounded declaration lookups through `ResolutionSession`, but `RustAnalyzer::forward_reference_context_of` builds and caches every import, namespace export, glob, and re-export without observing the request token.
  Evidence: The 20-sample campaign measured `RustAnalyzer::build_reference_context` at 12,170 ms after the external request had timed out. `src/analyzer/rust/graph_support.rs::build_reference_context` has iterative import/export loops and inserts the result only after the full build, providing a natural cooperative checkpoint and no-partial-cache seam.

- Observation: Making the full reference-context builder cooperative was necessary but not sufficient for the latency contract. Eagerly requesting it at the start of the full resolver would turn an ordinary imported bare call into a three-second cancellation instead of the previous correct 60 ms resolution.
  Evidence: Full-resolver context access is now delayed until a focused use/scoped/token-tree/type shape or the final generic fallback actually needs it. The final release campaign resolves definition-by-location at 63.2 ms p95 while preserving exact direct-versus-cancellable results.

- Observation: The installed Bifrost navigation tool itself can still stall on this large Rust resolver surface.
  Evidence: A `scan_usages_by_location` request for `forward_reference_context_of` produced no result after more than 44 seconds and was terminated. Shell inspection was used only after that structured query failed; this should be tracked separately as code-intelligence tooling evidence rather than hidden inside issue #1228.

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

- Decision: Background every read-only `tools/call` through the existing bounded request registry and keep only `activate_workspace`, `refresh`, `update_paths`, and `get_active_workspace` on the reader.
  Rationale: A positive allowlist recreates head-of-line blocking whenever a tool is added or overlooked. The four lifecycle tools either mutate workspace state or are the cheap paired state read; all other advertised tools are read-only and can safely use workspace-generation suppression, bounded response queuing, and request-ID-based cancellation.
  Date/Author: 2026-07-28 / Codex

- Decision: Emit bounded-cardinality MCP timing labels by tool and phase without arguments or source text.
  Rationale: `mcp_request.queue_wait`, `execution`, `response_queue_wait`, and `writer_delivery` make a slow request attributable while tool names come from the finite server specification. Arguments and request data would leak source and explode trace cardinality; request/iteration correlation already comes from the benchmark's profile boundaries and artifact identity.
  Date/Author: 2026-07-28 / Codex

- Decision: Give public MCP usage scans a three-second cooperative execution deadline inside the five-second response contract.
  Rationale: The service needs time after analyzer interruption to classify partial evidence, render a truthful response, enqueue it, and deliver it. A deadline equal to the external budget would make a correct cooperative stop arrive too late, while deterministic work caps remain the backstop on hosts where work volume rather than time is dominant.
  Date/Author: 2026-07-28 / Codex

- Decision: Keep the interactive gate in `benchmark/interactive-latency.toml` rather than expanding the broad daily corpus manifest.
  Rationale: The release gate has a distinct two-warmup/twenty-measurement contract, raw MCP correctness oracles, absolute p95 budgets, cancellation/fairness semantics, and profile artifact policy. Separating it avoids silently changing historical daily-baseline membership and comparison semantics.
  Date/Author: 2026-07-28 / Codex

- Decision: Treat a short symbol selector as precise only when it accompanies an exact declaration location.
  Rationale: File/line/column already disambiguate the selected declaration, so demanding an FQN adds no safety there. Short-name matching without that location would weaken the public ambiguity contract and remains unsupported.
  Date/Author: 2026-07-28 / Codex

- Decision: Use twenty measured samples for the release p95 gate and retain the raw fairness light-request and cancellation distributions separately.
  Rationale: With ten samples, the nearest-rank p95 is simply the maximum and the initial green campaign missed a cross-scenario tail that appeared in a longer run. Twenty samples both exercises warm stability and makes one isolated maximum distinct from p95 while preserving every raw sample for audit.
  Date/Author: 2026-07-28 / Codex

- Decision: Route cancellable Rust navigation through the existing bounded structured resolver, and extend that resolver to follow a visible imported bare call using the import binder and analyzer declarations.
  Rationale: The ordinary resolver eagerly constructed a complete reference context for every import in the file before resolving one focused call. The bounded resolver already carries cancellation and work accounting; resolving the one visible import structurally preserves the expected definition without source-text scanning or a 12-second background task.
  Date/Author: 2026-07-28 / Codex

- Decision: Admit Rust direct/member usage work in cancellation-checked parallel batches of four.
  Rationale: Unbounded parallel admission can leave a request with a large cohort of already-running file scans when its deadline expires, while fully serial work misses the product budget. A small batch bounds cancellation lag and retained CPU without serializing the full repository.
  Date/Author: 2026-07-28 / Codex

- Decision: Use the full Rust definition resolver for both token-free and cancellable navigation, retaining the smaller bounded resolver only for internal receiver-query callers that explicitly request its reduced, work-bounded contract.
  Rationale: Public navigation parity cannot be maintained by independently extending two semantic engines. A session-aware provider already supplies cancellable and limited declaration queries to the full resolver; unifying the public entry point preserves every intentional Rust navigation feature while leaving the separately-scoped receiver-query API intact.
  Date/Author: 2026-07-28 / Codex

- Decision: Add a cancellation-aware reference-context cache API that publishes only complete contexts, and route full-resolver context access through `RustDefinitionProvider`.
  Rationale: The analyzer cache should remain shared for completed work, but a cancelled request must neither keep computing blindly nor expose a partially populated import map to later queries. A provider method lets ordinary callers retain the existing cached behavior while the cancellable navigation provider supplies `ResolutionSession::observe_cancellation` as the progress callback.
  Date/Author: 2026-07-28 / Codex

## Outcomes & Retrospective

Milestone 1 is implemented. `UsageFinder::QueryResult` now distinguishes complete, cancelled, candidate-file-bounded, and source-byte-bounded queries; cancellation is checked during source admission as well as candidate and graph work. Both public scan surfaces receive the service token and one bounded execution context. Public results retain useful statuses and hits while serializing `complete: false` plus one of `cancelled`, `candidate_files`, `source_bytes`, `callsites`, or `response_budget`. A cancelled scan is an explicit failure rather than an empty success, and bounded zero-hit scans cannot become `verified_absent`.

Milestone 2 removes the remaining stdin-reader head-of-line boundary. Read-only tool calls now share the existing maximum-four in-flight registry, cancellation map, workspace-generation suppression, fixed response queue, and writer completion cleanup. Snapshot construction for `query_code` and `run_policy` now occurs inside the worker. A held and cancelled real scan cannot prevent a following exact source body from completing, while workspace-mutating lifecycle calls remain reader-ordered. Profile traces now separate accepted-to-worker queue wait, worker execution, response-queue wait, and writer delivery for each finite tool name.

Milestone 3 productizes the latency contract. `McpSession` can send, cancel, and receive by JSON-RPC request ID while buffering out-of-order responses. The separate pinned Bifrost manifest runs nine common request cases plus one overlapping heavy-scan/light-source fairness case in release mode, with two warmups, twenty measured samples, correctness oracles, and a 5,000 ms p95 budget. Reports retain raw samples, p50/p95, profile artifacts, absolute budget outcomes, and the number of measured samples accepted as truthful bounded-incomplete responses. The scheduled workflow builds and enforces this lane independently of the historical cross-repository comparison.

The final release campaign passed every case. Warm p50/p95 results in milliseconds were: four-pattern symbol search 229/249; exact `SemanticProcedureSummary` source 6/11; exact `SearchToolsService` source 4/9; exact scan-tool source 4/7; exact symbol-search source 4/10; definition 47/58; summary 21/28; exact issue usage scan 3552/3897; line-only usage scan 3309/3901; and the fairness case 10/13. The expensive scans returned typed `time_budget` incomplete results in all twenty measured iterations rather than false verified absence. In the fairness case, the overlapped source lookup p95 was 8.9 ms and cancellation-to-heavy-completion p95 was 11.1 ms.

Milestone 4 closes the implementation with review-driven hardening: admission-time deadlines, bounded request/response channels, truthful partial-result oracles, cold-Git cancellation, cancellable navigation/source/summary checkpoints, structured dominant-phase reporting, and the Rust navigation/scan interaction found by the 20-sample campaign. The feature-enabled library suite now passes completely on this host when its loopback tests are run outside the network sandbox. The persistent Click/Python and unrelated PHP/C++ daily signals remain follow-up evidence rather than silently widening this issue's implementation scope; no completed Actions run yet contains these local changes, so causation remains unproven.

Milestone 5 closes the semantic-parity gap without surrendering the latency result. Both public Rust navigation paths now invoke the same full resolver; the cancellable path supplies a `ResolutionSession` through the provider instead of selecting the reduced receiver-query resolver. Full reference-context construction checks cancellation throughout import/export traversal and publishes only a completed cache entry. Context acquisition is lazy after structured syntax gates, so common imported calls retain the fast exact path. A 12-case fixture compares complete serialized definition and declaration batches between token-free and live-token calls while independently asserting the direct definition outcomes; an interrupted-build regression proves no partial context is cached. The final release campaign remains green, the 651-test cross-language navigation suite passes, and the unrestricted all-feature library suite passes 2,037 tests with 6 intentional ignores. No known intentional Rust navigation feature is removed by this slice.

Residual risk is now bounded and explicit: the public MCP request can still return `cancelled` or `budget_exceeded` when its documented request limits are actually reached, but an uncancelled request within those limits no longer selects different Rust semantics. The installed Bifrost usage-navigation stall observed while inspecting this work remains a separate tooling follow-up.

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

### Milestone 5: Rust navigation semantic parity under cancellation

In `src/analyzer/usages/get_definition/rust.rs`, add a cancellable full-resolution entry point that constructs a bounded `ResolutionSession`, a session-aware `AnalyzerRustDefinitionProvider`, and a query-local type cache, then invokes the same `resolve_rust` function used by token-free navigation. Keep `resolve_rust_bounded` for internal receiver-query callers, but stop selecting it from `src/analyzer/usages/get_definition/mod.rs::resolve_one`. The session-aware provider used by full navigation must report ordinary semantics rather than activating the reduced `is_bounded` branches.

In `src/analyzer/usages/rust_graph/resolver.rs`, make reference-context access a provider operation. Its default implementation will preserve the existing `RustAnalyzer::forward_reference_context_of` behavior. The session-aware analyzer provider will instead call a new cooperative API in `src/analyzer/rust/graph_support.rs`. Replace direct full-resolver calls to `forward_reference_context_of` with the provider operation so a cancelled session stops consistently no matter which Rust path, macro, type, field, or trait branch requested the context.

In `src/analyzer/rust/graph_support.rs`, implement cooperative forward reference-context construction. Check progress before and during declaration, binding, namespace-export, glob-export, re-export, and export-graph traversal. Return `None` when progress stops, and insert into `forward_reference_contexts` only after a complete context has been constructed. Existing token-free callers continue through an always-progressing wrapper and observe byte-for-byte equivalent context contents.

Add behavior-focused parity tests. A table-driven Rust fixture must pass the same batch of representative definition and declaration locations through the token-free searchtool functions and through their cancellation-aware siblings with a live, uncancelled token, then compare the complete serialized results. The matrix must include same-file and imported bare calls, aliases, scoped paths, typed receiver methods, fields, `Self`, macros, types, lexical bindings, and declaration-specific associated items; each expected direct result must also be asserted so parity cannot pass vacuously. Keep deterministic cancellation coverage proving that full-resolution work returns a `cancelled` diagnostic, and add a graph-support unit test showing a cancelled context is not cached and a subsequent uncancelled request builds and caches a complete context.

At the milestone boundary, run the focused parity, cancellation, and graph-support tests, `cargo fmt`, all-target/all-feature Clippy, the feature-enabled library suites, and the 20-sample release latency campaign. Update every living section of this plan, review the full Milestone 5 diff, and checkpoint only the milestone files on the current branch.

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

Milestone 5 is accepted when an uncancelled token produces exactly the same rendered Rust definition and declaration results as token-free navigation for the representative parity matrix; cancellation interrupts full reference-context work without caching a partial result; the existing cancellation diagnostic remains truthful; the 20-sample definition and fairness scenarios stay below five seconds; and the complete Rust navigation suite, formatting, Clippy, and feature-enabled tests pass.

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
    2026-07-28 run 30349710835: failure, 4 actionable regressions

Persistent measured signals from the downloaded reports:

    click-py scan_usages median: baseline 2469 ms; candidates 7474, 7780, 6318 ms
    click-py dead_code_smells median: baseline 1240 ms; candidates 6585, 6695, 5357 ms
    fastroute-php scan_usages: candidate found no call sites
    fmt-cpp get_symbol_locations: candidate found no locations

Latest July 28 values:

    click-py scan_usages median: 14421 ms versus 2469 ms baseline (+484%)
    click-py dead_code_smells median: 13815 ms versus 1240 ms baseline (+1014%)
    fastroute-php scan_usages: candidate still found no call sites
    fmt-cpp get_symbol_locations: candidate still found no locations

Final release benchmark:

    scripts/run-interactive-latency.sh --profile
    result: 10 passed scenarios; 0 failed; all warm p95 values below 5000 ms
    final report: benchmark/interactive-latency-output/run-20260728T130512Z.json (generated artifact, not committed)

    case                                             p50 ms    p95 ms
    search-common-symbols                              229.2     249.1
    source-semantic-summary                              6.0      11.3
    source-search-service                                3.9       9.4
    source-usage-scan                                    4.1       7.1
    source-symbol-search                                 3.7       9.7
    definition-by-location                              46.7      57.5
    summary-semantic-procedure                          20.6      28.2
    scan-semantic-procedure-exact                     3551.7    3897.0
    scan-semantic-procedure-line                      3308.7    3901.1
    heavy-scan-does-not-block-source                     9.5      13.1

    fairness light-request p95: 8.9 ms
    fairness cancellation p95: 11.1 ms
    exact and line scan dominant phase: execution[scan_usages_by_location]
    exact and line scan bounded incomplete iterations: 20 of 20 each

Milestone 3 deterministic validation:

    scripts/with-isolated-cargo-target.sh cargo test --test benchmark_manifest --test benchmark_repo_cache --test benchmark_workflow_policy --test bifrost_benchmark_run -- --nocapture
    result: 27 passed; 0 failed

    scripts/with-isolated-cargo-target.sh cargo clippy --all-targets --all-features -- -D warnings
    result: passed with warnings denied

Milestone 4 final validation:

    cargo test --lib issue_1228 --no-default-features
    result: 26 passed; 0 failed; 1972 filtered out

    cargo test --test benchmark_manifest --test benchmark_workflow_policy --test bifrost_benchmark_run
    result: 25 passed; 0 failed

    PATH=<matching rustup 1.96.0 toolchain>:<system path> scripts/with-isolated-cargo-target.sh cargo clippy --all-targets --all-features -- -D warnings
    result: passed with warnings denied; managed isolated target removed

    BIFROST_SEMANTIC_INDEX=off cargo test --features nlp,python --lib
    result: 2035 passed; 0 failed; 6 ignored (loopback tests run outside the network sandbox)

    cargo fmt --check
    result: passed

Milestone 5 semantic-parity validation:

    CARGO_TARGET_DIR=<managed retained target> cargo test --lib issue_1228 --no-default-features -- --nocapture
    result: 28 passed; 0 failed; 1972 filtered out

    CARGO_TARGET_DIR=<managed retained target> cargo test --test get_definition_test --no-default-features
    result: 651 passed; 0 failed

    PATH=<matching rustup 1.96.0 toolchain>:<system path> CARGO_TARGET_DIR=<managed retained target> cargo clippy --all-targets --all-features -- -D warnings
    result: passed with warnings denied

    BIFROST_SEMANTIC_INDEX=off CARGO_TARGET_DIR=<managed retained target> cargo test --features nlp,python --lib
    result: 2037 passed; 0 failed; 6 ignored (the three local process/pipe tests required the standard unrestricted rerun after the sandbox denied them)

    cargo fmt --check
    result: passed

Milestone 5 release benchmark:

    scripts/run-interactive-latency.sh --profile
    result: 10 passed scenarios; 0 failed; all warm p95 values below 5000 ms
    report: benchmark/interactive-latency-output/run-20260728T145934Z.json (generated artifact, not committed)

    case                                             p50 ms    p95 ms
    search-common-symbols                              250.6     270.1
    source-semantic-summary                              2.5      10.0
    source-search-service                                4.5      10.3
    source-usage-scan                                    3.8       9.5
    source-symbol-search                                 4.6       9.7
    definition-by-location                              54.9      63.2
    summary-semantic-procedure                          18.1      23.9
    scan-semantic-procedure-exact                     3339.0    3894.5
    scan-semantic-procedure-line                      3308.0    3860.8
    heavy-scan-does-not-block-source                    11.2      17.4

    fairness light-request p95: 17.4 ms
    fairness cancellation p95: 13.1 ms
    exact and line scan bounded incomplete iterations: 20 of 20 each

The focused test transcripts, final p50/p95 tables, dominant-phase evidence, and refreshed Actions run evidence are recorded above and below.

Milestone 1 focused validation:

    scripts/with-isolated-cargo-target.sh cargo test --lib issue_1228 -- --nocapture
    result: 5 passed; 0 failed; 1972 filtered out; tests finished in 0.06 s

    scripts/with-isolated-cargo-target.sh cargo test --test searchtools_service scan_usages_demotes_large_result_to_summary_within_budget -- --exact --nocapture
    result: 1 passed; 0 failed; 189 filtered out; test finished in 2.89 s

Milestone 2 focused validation:

    scripts/with-isolated-cargo-target.sh cargo test --lib issue_1228 -- --nocapture
    result after transport implementation: 7 passed; 0 failed; 1972 filtered out; tests finished in 0.06 s

    scripts/with-isolated-cargo-target.sh cargo test --lib mcp_common::uri_tests -- --nocapture
    result: 14 passed; 0 failed; 1965 filtered out; tests finished in 0.14 s

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

In `src/analyzer/usages/rust_graph/resolver.rs`, extend `RustDefinitionProvider` with a reference-context operation returning `Option<Arc<RustReferenceContext>>`. The default implementation returns the analyzer's ordinary cached context. `AnalyzerRustDefinitionProvider` overrides it so a session-aware full-navigation request calls the cooperative context builder and returns `None` after cancellation. In `src/analyzer/rust/graph_support.rs`, the cooperative builder accepts a progress callback, returns `None` on interruption, and never inserts an incomplete context into `forward_reference_contexts`.

Plan revision note (2026-07-28 08:32Z): Created the initial self-contained plan after syncing current master, validating the issue and current source seams, probing the live plugin, reviewing recent Benchmark Actions artifacts, and separating deterministic correctness gates from the stable release wall-clock contract.

Plan revision note (2026-07-28 09:21Z): Updated the checkout state to the app-created issue branch at base `45841f1a`; recorded Milestone 1's cancellation, work-budget, incomplete-result, profiling, and regression-test implementation; documented the 64 MiB source budget and focused validation results; and removed stale detached-HEAD recovery guidance.

Plan revision note (2026-07-28 09:24Z): Recorded Milestone 1 checkpoint `d9bb61bf` and its clean post-checkpoint review before beginning MCP transport work.

Plan revision note (2026-07-28 09:35Z): Recorded Milestone 2's read-only background admission, deferred snapshot preparation, deterministic scan/source fairness test, four transport timing phases, and full focused transport validation; checkpoint hash remains to be recorded after commit.

Plan revision note (2026-07-28 09:37Z): Recorded Milestone 2 checkpoint `fdb403f3` and began benchmark client/report integration.

Plan revision note (2026-07-28 11:35Z): Recorded the completed interactive benchmark implementation, exact/line scan cancellation discoveries, final ten-case release metrics, explicit bounded-incomplete reporting, clean benchmark and Clippy gates, and the July 28 scheduled regression report.

Plan revision note (2026-07-28 13:12Z): Closed Milestone 4 after whole-diff specialist review, a 20-sample campaign exposed and fixed the definition/scan overlap, structured bounded Rust import resolution preserved definition correctness, the final ten-case release gate passed, all focused and feature-enabled tests passed, and matched-toolchain all-feature Clippy completed cleanly.

Plan revision note (2026-07-28 14:06Z): Reopened the issue for Milestone 5 after identifying that the latency fix changed MCP Rust navigation to a reduced resolver. Added the full-resolver cooperative-cancellation design, direct-versus-cancellable definition/declaration parity matrix, no-partial-cache contract, and complete revalidation requirements needed to defend zero intentional semantic regressions.

Plan revision note (2026-07-28 15:08Z): Closed Milestone 5 after routing cancellable MCP Rust navigation through the full resolver, making reference-context construction cooperative and cache-atomic, delaying context work until structured syntax requires it, adding exact definition/declaration parity and no-partial-cache regressions, and passing the complete navigation, Clippy, all-feature, and 20-sample release gates.
