# Bound cold MCP initialization without duplicate analyzer builds

This ExecPlan is a living document. Maintain it in accordance with `.agents/PLANS.md`.

## Purpose / Big Picture

The first `search_symbols` or `get_summaries` request must not wait tens of seconds for a cold analyzer. Both MCP hosts must finish an interactive request within five seconds. If the complete analyzer snapshot is not ready, the host must return an accurate retry result while the original single background build continues. Warm requests must keep their current result and latency behavior.

## Progress

- [x] (2026-08-04 09:20Z) Read issue #1503, fetched `origin/master`, and merged it into the existing issue branch.
- [x] (2026-08-04 09:35Z) Mapped workspace binding, deferred analyzer construction, optional index warming, RMCP admission, and legacy-host admission.
- [ ] Add named cold-phase timing and a reproducible concurrent-host probe.
- [ ] Reproduce both hosts with a fresh process and isolated workspace cache.
- [ ] Implement bounded readiness without duplicate builds.
- [ ] Add behavior tests for concurrency, cancellation, revocation, correctness, and warm reuse.
- [ ] Run focused featureless tests, formatting, policy checks, and host comparisons.

## Surprises & Discoveries

- Observation: Both hosts wait for workspace readiness before they start the request budget.
  Evidence: `rmcp_host.rs::call_tool` and `mcp_common.rs::spawn_cancellable_tool_call_with_start_hook` call `wait_workspace_ready` without a deadline.
- Observation: The deferred analyzer build and optional query-index warming are already separate single-flight operations.
  Evidence: `SearchToolsService::pending_build` owns one join handle. `IndexWarmer` coalesces later snapshot warms.
- Observation: A current Bifrost plugin batch of concurrent symbol search and summaries took 6.0 seconds and reported unavailable Git-history ranking.
  Evidence: The 2026-08-04 tool trace in this task.

## Decision Log

- Decision: Keep one deferred analyzer build and bound only how long each interactive request waits for it.
  Rationale: Cancelling or restarting the build would duplicate work and would violate single-flight initialization.
  Date/Author: 2026-08-04 / Codex
- Decision: Use the same readiness contract in RMCP and the hand-written host.
  Rationale: `BIFROST_MCP_RMCP=on` and `off` are operator-selectable compatibility paths.
  Date/Author: 2026-08-04 / Codex

## Outcomes & Retrospective

Work is in progress. The current code has truthful complete results, but the first request can wait without a time limit.

## Context and Orientation

`crates/bifrost-mcp/src/searchtools_service.rs` owns the active workspace. A client binding starts one `bifrost-index-build` thread and stores its handle in `pending_build`. `ensure_ready` joins that handle and publishes the immutable `WorkspaceSession`. `IndexWarmer` separately warms optional query indexes after publication.

`crates/bifrost-mcp/src/rmcp_host.rs` is the RMCP host selected by `BIFROST_MCP_RMCP=on`. `crates/bifrost-mcp/src/mcp_common.rs` is the legacy host selected by `BIFROST_MCP_RMCP=off`. Both currently call `wait_workspace_ready` before they start the request budget. This excludes initialization from internal timing but does not exclude it from client wall time.

The workspace cache path can be isolated with `BIFROST_CACHE_DIR`. A fresh process plus a new temporary cache directory gives a real cold analyzer build without deleting a user cache. The test must send concurrent `search_symbols` and `get_summaries` calls to the same process.

## Plan of Work

First, add stable `BIFROST_TIMING=1` phase names around client workspace binding, analyzer construction, query-index construction, Git-history relevance work, readiness wait, and first tool execution. Extend the MCP integration harness to capture these phases from both hosts.

Second, run the same concurrent first-call probe with `BIFROST_MCP_RMCP=on` and `BIFROST_MCP_RMCP=off`. Use a new temporary `BIFROST_CACHE_DIR` for each host. Record cold and immediate warm wall times and the phase trace. Use the trace to identify the dominant phase before changing the design.

Third, replace the unbounded readiness wait with a deadline-aware wait. The request deadline starts when the host accepts the tool call. If the snapshot is still building when the bounded wait ends, return `WORKSPACE_SNAPSHOT_NOT_READY_MESSAGE`. Do not take or replace `pending_build`; the one build continues. A later call joins and publishes it. Preserve explicit client cancellation as a different result.

Fourth, add focused tests. Two concurrent first requests must observe one build. A timed-out request must not stop the build. A later request must get correct results. Workspace revocation must prevent a superseded build from publishing. Warm repeated requests must not enter the cold wait or rebuild the analyzer. Run each shared wire contract against both hosts.

## Concrete Steps

Run all commands from the repository root.

    cargo test -p brokk-bifrost-mcp --test bifrost_mcp_server <focused-test-name> -- --nocapture

Run the cold probe twice with explicit host settings and isolated cache roots:

    BIFROST_MCP_RMCP=on BIFROST_CACHE_DIR=<new-temp-dir> BIFROST_TIMING=1 <probe>
    BIFROST_MCP_RMCP=off BIFROST_CACHE_DIR=<new-temp-dir> BIFROST_TIMING=1 <probe>

After implementation, run:

    cargo fmt
    cargo test -p brokk-bifrost-mcp --test bifrost_mcp_server <focused-tests>
    cargo test -p brokk-bifrost-mcp

Do not enable `nlp`. This issue does not change semantic search.

## Validation and Acceptance

For each host, two concurrent cold requests must both return within five seconds. If the analyzer cannot finish, each response must state that the snapshot is not ready and that retry is required. The background build must continue once. A later warm retry must return the same correct symbol and summary content as the current implementation.

The timing trace must identify workspace binding, analyzer construction, query-index construction, Git-history relevance setup, readiness wait, first tool execution, and transport phases. Cancellation and root revocation tests must remain green. Warm calls must keep their current result contract and must not add a fixed delay.

## Idempotence and Recovery

The probe uses unique temporary cache directories and does not delete repository caches. It can run again safely. If a host process stops during a cold build, start a new process with a new cache directory. The single-flight state remains process-local and needs no migration.

## Artifacts and Notes

Issue #1503 reports about 50 seconds cold and less than one second warm. Current master has later transport timing from #1574, but it does not time the readiness wait because that wait happens before request admission.

## Interfaces and Dependencies

Keep `SearchToolsService` as the owner of `pending_build`. Add a deadline-aware readiness method that accepts a cancellation token or callback and an absolute `Instant`. It must distinguish ready, cancelled, and deadline-exceeded outcomes through `SearchToolsServiceError`. Both MCP hosts must call the same method.

Use the existing `profiling` module for phase output. Do not add a benchmark-only prewarm or a second initializer.

Plan update note: Created after live issue and current-master inspection showed that fixing the request admission boundary changes initialization behavior in both MCP hosts.
