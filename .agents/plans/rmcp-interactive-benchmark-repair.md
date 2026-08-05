# Repair the RMCP interactive benchmark gate

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must stay current during the work.

This document follows `.agents/PLANS.md`. A contributor must update this plan after each milestone and after each important discovery.

## Purpose / Big Picture

Bifrost must use the RMCP host by default to receive current MCP protocol support, including asynchronous protocol work. The default change remains blocked because two usage-scan cases fail the interactive benchmark. The host already returns truthful bounded results and supports cancellation. This work restores enough response time for delivery and makes the benchmark retain required transport timings when a large trace removes early stderr data.

After this change, `scripts/run-interactive-latency.sh --profile` must pass with `BIFROST_BENCHMARK_MCP_RMCP=on`. The two usage scans must finish inside five seconds. Each measured profile must report `queue_wait`, `execution`, `response_queue_wait`, and `writer_delivery`, even when its raw stderr tail is truncated. This plan does not change the default host selector. A later promotion change will use the successful benchmark evidence.

## Progress

- [x] (2026-08-05 14:55Z) Refreshed `origin`, confirmed a clean detached worktree, and created `dave/rmcp-interactive-benchmark-repair` from `origin/master` at `aef3d746c`.
- [x] (2026-08-05 14:55Z) Reproduced and inspected the prior branch benchmark evidence from GitHub Actions run `31010981510`.
- [x] (2026-08-05 14:55Z) Ran the initial `bifrost.code-smells` policy scan. It completed with 280 repository findings and no diagnostics. Eight existing findings touch planned files, but none touch planned edit locations.
- [x] (2026-08-05 14:58Z) Committed this initial ExecPlan as checkpoint `54a4b00de`.
- [x] (2026-08-05 15:07Z) Added deterministic tests for split timing lines, raw-tail truncation, request cursors, duplicate samples, and unterminated input.
- [x] (2026-08-05 15:07Z) Added bounded transport timing retention and canonical profile-artifact timing lines.
- [x] (2026-08-05 15:16Z) Restored the default usage-scan execution budget from five seconds to three seconds. Kept explicit overrides unchanged.
- [ ] Run focused formatting, unit, integration, and policy checks.
- [ ] Run the local release interactive benchmark with RMCP enabled.
- [ ] Push the branch and dispatch the GitHub Actions benchmark with profile capture and Slack disabled.
- [ ] Record local and GitHub benchmark evidence, then complete this plan.

## Surprises & Discoveries

- Observation: RMCP emits `queue_wait` before the long analyzer trace. The benchmark does not lose it at the host.
  Evidence: `crates/bifrost-mcp/src/rmcp_host.rs` emits the phase before `execute_tool`. A failed measured artifact ends with the later three phases.

- Observation: The failed measured artifact reached the 256 KiB raw stderr limit.
  Evidence: The artifact was 262,212 bytes and contained 3,468 `sql_definition_candidates` lines. It had `truncated=true`. It retained `execution`, `response_queue_wait`, and `writer_delivery`, but it did not retain the earlier `queue_wait` line.

- Observation: The two failed scans return truthful bounded partial results.
  Evidence: Run `31010981510` recorded 20 bounded incomplete iterations for each scan. The exact scan had p95 5,051.6 ms. The line scan had p95 5,077.9 ms.

- Observation: The five-second analyzer deadline cannot satisfy the five-second external response limit.
  Evidence: `SCAN_USAGES_MAX_DURATION` is five seconds. The measured requests need approximately 30 to 80 additional milliseconds for cancellation observation, rendering, queueing, and delivery.

- Observation: The repository has no named executable repository policy root.
  Evidence: `.bifrost/` contains only `policy-scope.json` and `suppressions.json`. The policy validation note in `.agents/docs/issue-1204-policy-pack-validation.md` also records no canonical repository root.

- Observation: The benchmark module tests belong to the root library, not the `bifrost` CLI binary.
  Evidence: `cargo test --bin bifrost benchmark::mcp_session::tests` ran zero tests. `cargo test -p brokk-bifrost --lib benchmark::mcp_session::tests` ran 15 tests.

- Observation: Three existing stderr-drain tests need local socket access.
  Evidence: The sandbox run failed at `TcpListener::bind` with `Operation not permitted`. The same 15-test command passed outside the socket sandbox.

- Observation: The focused analysis filter runs four scan behavior tests.
  Evidence: `cargo test -p brokk-bifrost-analysis searchtools::scan_usages::tests` passed 4 tests, including truthful partial-result guidance.

## Decision Log

- Decision: Keep RMCP and its current protocol behavior unchanged.
  Rationale: RMCP is the path to current MCP protocol support. The failures are in scan budgeting and benchmark capture, not RMCP request execution.
  Date/Author: 2026-08-05 / Codex

- Decision: Restore the three-second default scan execution budget.
  Rationale: A five-second internal budget cannot meet a five-second response contract. Three seconds leaves time for truthful cancellation, rendering, queueing, and delivery. Callers that need a longer batch scan retain `max_duration_secs` and its 300-second ceiling.
  Date/Author: 2026-08-05 / Codex

- Decision: Keep the five-second benchmark limit unchanged in this plan.
  Rationale: The user permits a later product decision if no further useful gain exists. This repair first restores the original bounded-response design. It must not hide a failed request by changing the gate.
  Date/Author: 2026-08-05 / Codex

- Decision: Retain required transport timing lines outside the raw stderr tail.
  Rationale: Increasing the raw limit only moves the failure point. Moving one RMCP timing line would be host-specific. A small separate record keeps required evidence while the diagnostic trace remains bounded.
  Date/Author: 2026-08-05 / Codex

- Decision: Do not infer a missing timing phase.
  Rationale: A value of zero would create false performance evidence. A phase that the host did not emit must still fail validation.
  Date/Author: 2026-08-05 / Codex

- Decision: Keep the RMCP default selector change outside this branch.
  Rationale: GitHub issue #1581 requires successful promotion evidence before the unset selector changes. This branch produces that evidence.
  Date/Author: 2026-08-05 / Codex

## Outcomes & Retrospective

Work is in progress. Record the final code behavior, focused test results, policy comparison, local benchmark, GitHub run, remaining limits, and lessons here.

## Context and Orientation

The repository root is `/Users/dave/.codex/worktrees/7161/bifrost`. The active branch is `dave/rmcp-interactive-benchmark-repair`. It started from `aef3d746c`.

MCP is the protocol that connects an agent client to Bifrost tools. RMCP is the Rust MCP library used by Bifrost's newer host. The legacy hand-written host remains available. GitHub issue #1581 allows RMCP to become the default only after explicit validation passes.

The interactive benchmark is a release-mode workload in `benchmark/interactive-latency.toml`. `scripts/run-interactive-latency.sh` builds the current Bifrost binary and benchmark binary. It runs nine code-intelligence cases and one fairness case against a pinned Bifrost source checkout. The workflow sets `BIFROST_BENCHMARK_MCP_RMCP=on`.

The two failing cases call `scan_usages_by_location`. They allow a bounded incomplete response. A bounded response states `complete: false`, gives an accepted `incomplete_reason`, and gives recovery guidance. This behavior is useful because a large scan can stop before it proves every usage.

`crates/bifrost-analysis/src/searchtools/scan_usages.rs` owns scan work limits. `SCAN_USAGES_MAX_DURATION` supplies the default deadline when the request has no `max_duration_secs`. `ScanUsagesExecutionContext::with_cancellation_and_max_duration` keeps an explicit caller value and clamps it to `SCAN_USAGES_MAX_DURATION_CEILING`.

`src/benchmark/mcp_session.rs` owns the benchmark MCP child process and stderr capture. `StderrTail` stores the last 256 KiB as raw diagnostic chunks. `StderrCursor` marks the first child read that belongs to one measured request. `CapturedStderr` carries the raw text and its truncation state to the artifact writer.

`src/benchmark/mcp_iteration.rs` writes one profile artifact for each warmup and measured request. `transport_phase_report` reads measured artifacts and requires all four `mcp_request` phases. The current parser scans raw text. Therefore, an early phase disappears when later analyzer timings remove its chunk.

`crates/bifrost-mcp/tests/bifrost_mcp_server.rs` already proves that both MCP hosts emit all four transport phases on a small request. The new tests must preserve that host contract and add the missing large-trace capture contract.

## Plan of Work

Milestone 1 records the design and evidence. Commit this ExecPlan alone. This checkpoint lets another contributor restart the work without the prior chat or benchmark transcript.

Milestone 2 makes transport timing capture independent of raw-tail size. Extend `CapturedStderr` with a collection of retained timing lines. Extend `StderrTail` with an incremental line collector. The collector must accept lines split across the 8 KiB child reads. It must retain only the four exact `mcp_request` phases. It must reject unrelated timing lines.

Give each retained line the sequence of the read where that line started. `capture_since` must return only lines that started at or after the request cursor. Keep a fixed line count for the retained record. Keep a small fixed limit for a partial, unterminated line. If a line exceeds that limit, discard it until its newline. Actual transport timing lines are short.

Keep `StderrTail`'s 256 KiB raw capacity unchanged. A current request produces four required timing lines, so the separate record can remain small. Old entries can leave through a bounded first-in, first-out queue. This design keeps process memory bounded even if a child writes stderr without stopping.

Update `write_profile_trace` in `src/benchmark/mcp_iteration.rs`. Write retained lines with a distinct artifact prefix. Update phase report parsing to prefer the retained lines when the artifact has them. Fall back to raw trace parsing for older artifacts. This rule avoids duplicate samples when a timing line exists in both places.

Add deterministic tests in `src/benchmark/mcp_session.rs`. Use a very small raw capacity. Write a split `queue_wait` line, write enough trace data to remove it from the raw tail, then write the later phases. Confirm the raw trace is truncated and lacks `queue_wait`. Confirm the separate timing record still has all four exact lines. Also prove that a pre-cursor line does not enter the next request and that a long unterminated line cannot grow the partial buffer without limit.

Add artifact tests in `src/benchmark/mcp_iteration.rs`. A retained timing section plus a truncated raw trace must produce one sample for each phase. A measured artifact that truly lacks `queue_wait` must still return the current error. A raw-only complete artifact must stay supported.

Milestone 3 restores scan delivery headroom. In `crates/bifrost-analysis/src/searchtools/scan_usages.rs`, change `SCAN_USAGES_MAX_DURATION` from five seconds to three seconds. Correct the comment to name the five-second response envelope. Do not change explicit caller overrides, the 300-second ceiling, cancellation classification, response schema, or deterministic count and byte limits.

Use existing deterministic scan tests to prove truthful partial results. Do not add a debug-build wall-clock assertion. Wall-clock acceptance belongs to the release benchmark.

Milestone 4 validates the implementation. Run formatting and the focused benchmark module tests. Run the analysis scan tests. Run the existing two-host wire timing test. Run featureless strict Clippy for the affected packages if the focused tests expose no failure. Use the installed Bifrost policy tool again with the same pack and date. Compare findings with the 280-finding baseline. Review every new finding in a changed file.

Run the local release benchmark with RMCP enabled and profile capture. It must report all ten cases as successful. Both scan p95 values must be below 5,000 ms. Each scan may return a truthful bounded partial. The fairness light request and cancellation measurements must remain inside their limits. Profile diagnostics must find all four transport phases.

Milestone 5 records remote branch evidence. Commit the completed implementation and validation notes. Push the branch. Dispatch `.github/workflows/benchmark.yml` with profile capture enabled, strict comparison disabled for this exploratory branch, and Slack disabled. The broad benchmark job can report unrelated corpus regressions. This plan accepts only the `interactive-latency` job as RMCP promotion evidence.

Download the `interactive-latency-<run-id>` artifact. Record the branch revision, runner system, selector, exact command, p50, p95, bounded count, fairness values, artifact name, and run URL. If the interactive job fails, inspect the measured profile before changing any limit. Update this plan and continue with the smallest supported correction.

## Concrete Steps

Run all commands from `/Users/dave/.codex/worktrees/7161/bifrost`.

Commit Milestone 1 with only this plan:

    git add .agents/plans/rmcp-interactive-benchmark-repair.md
    git commit -m "Plan RMCP interactive benchmark repair" -m "Record the two independent promotion failures, the bounded repair design, and the validation evidence needed before the RMCP default changes."

After Milestone 2 source changes, run:

    cargo fmt --all -- --check
    cargo test -p brokk-bifrost --lib benchmark::mcp_session::tests
    cargo test -p brokk-bifrost --lib benchmark::mcp_iteration::tests
    cargo test -p brokk-bifrost-mcp --test bifrost_mcp_server profiled_tool_calls_emit_all_transport_phases -- --nocapture

Expect all selected tests to pass. The wire test runs once against RMCP and once against the legacy host.

After Milestone 3, run:

    cargo test -p brokk-bifrost-analysis searchtools::scan_usages::tests
    cargo fmt --all -- --check
    git diff --check

Run task-scoped Clippy without NLP:

    scripts/with-isolated-cargo-target.sh cargo clippy -p brokk-bifrost -p brokk-bifrost-analysis -p brokk-bifrost-mcp --all-targets -- -D warnings

Run the final policy request through the installed Bifrost MCP service:

    policy_packs = ["bifrost.code-smells"]
    evaluation_date = "2026-08-05"
    fail_on = "warning"

The repository has no additional executable policy roots. The baseline is `status: finding`, 280 findings, and zero diagnostics. No new finding can point to a changed line.

Run the local release benchmark:

    BIFROST_BENCHMARK_MCP_RMCP=on scripts/run-interactive-latency.sh --profile

The report is written below `benchmark/interactive-latency-output/`. Do not commit this generated directory.

Commit the implementation milestone with explicit paths. Use a multiline message that records why raw timing evidence needs separate bounded retention and why the scan deadline is shorter than the response limit.

Push and dispatch the branch benchmark:

    git push -u origin dave/rmcp-interactive-benchmark-repair
    gh workflow run Benchmark --repo BrokkAi/bifrost --ref dave/rmcp-interactive-benchmark-repair -f repo=bifrost-self -f strict_compare=false -f profile=true -f post_to_slack=false

Find the dispatched run, wait for `interactive-latency`, and download its artifact. Do not post to Slack. Record all evidence in this plan.

## Validation and Acceptance

The transport unit test must prove that raw trace truncation can remove `queue_wait` without removing the retained timing line. The test must also prove that the report has no duplicate timing sample when raw and retained text both contain the same phase.

The measured-artifact test must continue to fail when RMCP or the legacy host does not emit a required phase. This prevents the capture repair from hiding a host regression.

The scan tests must preserve truthful incomplete results and structured recovery guidance. Explicit `max_duration_secs` requests must remain unchanged. The default budget alone changes from five seconds to three seconds.

The local release benchmark must show ten successful cases. `scan-semantic-procedure-exact` and `scan-semantic-procedure-line` must have p95 below 5,000 ms. Their 20 measured results can be bounded incomplete. All four transport phases must appear in the report. The fairness case must stay successful.

The GitHub `interactive-latency` job must pass on the branch revision and publish its artifact. A failure in the separate broad corpus job does not reject this targeted repair unless it identifies a regression caused by changed code.

Do not change the default selector, remove the legacy host, raise the latency limit, or broaden this work into analyzer optimization. If the repair cannot meet the gate, record the dominant phase and return to the user for the later timing-policy decision described in the Decision Log.

## Idempotence and Recovery

The tests use temporary directories and can run again safely. The local benchmark can run again. It reuses normal Cargo output and writes a new report below `benchmark/interactive-latency-output/`.

Do not create a manually named Cargo target in `/tmp`. Use `scripts/with-isolated-cargo-target.sh` for isolated Clippy. The helper removes its marked target after completion.

If a benchmark stops, check for a remaining `bifrost_benchmark` or benchmark child process before another run. Do not delete analyzer caches or another worktree. Remove generated benchmark output only after its report and profiles are recorded.

If the branch benchmark fails because the branch was not pushed, push the existing commits and dispatch again. Do not change the workflow selector. It is already pinned to RMCP.

## Artifacts and Notes

The prior failed promotion run is GitHub Actions run `31010981510` at commit `8ed56aeb66e5ba9e7d283783a65642085f72fdc3`. Its interactive artifact is `interactive-latency-31010981510`.

The important prior results are:

    scan-semantic-procedure-exact  p50 5033.731 ms  p95 5051.562 ms  bounded 20/20
    scan-semantic-procedure-line   p50 5041.857 ms  p95 5077.871 ms  bounded 20/20
    fairness light request         p95 2523.980 ms
    fairness cancellation          p95 15.687 ms
    profile diagnostic             missing queue_wait

The local copy of that report is `/private/tmp/rmcp-benchmark-31010981510/run-20260805T135037Z.json`. The representative truncated profile is below `/private/tmp/rmcp-benchmark-31010981510/profiles/20260805T134613714721Z-12185-0/`.

## Interfaces and Dependencies

Do not add a crate or third-party dependency.

`src/benchmark/mcp_session.rs` must keep these public benchmark interfaces compatible:

    pub struct StderrCursor {
        next_sequence: u64,
    }

    pub struct CapturedStderr {
        pub text: String,
        pub truncated: bool,
        pub transport_timings: Vec<String>,
    }

The exact private type names for retained entries can change during implementation. Each entry must include its start sequence and complete original timing line. Retention must stay bounded by constants in `mcp_session.rs`.

`src/benchmark/mcp_iteration.rs` must write retained timing lines in a distinct machine-readable form. `transport_phase_report` must prefer those retained lines and use raw trace lines only for older artifacts. Its required phase list and missing-phase error remain unchanged.

`crates/bifrost-analysis/src/searchtools/scan_usages.rs` must keep `ScanUsagesExecutionContext::with_cancellation_and_max_duration` and both public request fields unchanged. Only the default constant and its explanation change.

Revision note, 2026-08-05: Created the initial plan from the failed RMCP promotion run. The plan separates real response-budget work from bounded profile capture and keeps the selector promotion outside this branch. Recorded the first checkpoint commit before source implementation. Corrected the benchmark unit-test target and recorded the completed transport-capture and scan-budget milestones.
