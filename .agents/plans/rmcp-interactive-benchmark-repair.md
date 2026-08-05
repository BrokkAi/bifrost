# Repair the RMCP interactive benchmark gate

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must stay current during the work.

This document follows `.agents/PLANS.md`. A contributor must update this plan after each milestone and after each important discovery.

## Purpose / Big Picture

Bifrost must use the RMCP host by default to receive current MCP protocol support, including asynchronous protocol work. Two usage-scan cases first blocked that promotion. This work restored enough response time for delivery and made the benchmark retain required transport timings when a large trace removes early stderr data.

The local and Ubuntu benchmarks now pass with `BIFROST_BENCHMARK_MCP_RMCP=on`. After that evidence passed, the user authorized the promotion on this branch. An unset `BIFROST_MCP_RMCP` must now select RMCP. Explicit `off` must keep the tested hand-written rollback host. This promotion does not remove either host.

## Progress

- [x] (2026-08-05 14:55Z) Refreshed `origin`, confirmed a clean detached worktree, and created `dave/rmcp-interactive-benchmark-repair` from `origin/master` at `aef3d746c`.
- [x] (2026-08-05 14:55Z) Reproduced and inspected the prior branch benchmark evidence from GitHub Actions run `31010981510`.
- [x] (2026-08-05 14:55Z) Ran the initial `bifrost.code-smells` policy scan. It completed with 280 repository findings and no diagnostics. Eight existing findings touch planned files, but none touch planned edit locations.
- [x] (2026-08-05 14:58Z) Committed this initial ExecPlan as checkpoint `54a4b00de`.
- [x] (2026-08-05 15:07Z) Added deterministic tests for split timing lines, raw-tail truncation, request cursors, duplicate samples, and unterminated input.
- [x] (2026-08-05 15:07Z) Added bounded transport timing retention and canonical profile-artifact timing lines.
- [x] (2026-08-05 15:16Z) Restored the default usage-scan execution budget from five seconds to three seconds. Kept explicit overrides unchanged.
- [x] (2026-08-05 15:32Z) Passed formatting, diff checks, 16 stderr tests, 6 artifact tests, 4 scan tests, the two-host wire test, all-workspace all-feature Clippy, and the final policy comparison.
- [x] (2026-08-05 15:32Z) Passed the local release interactive benchmark with RMCP enabled. All 10 cases passed.
- [x] (2026-08-05 15:34Z) Pushed the branch and dispatched GitHub Actions run `31020949528` with profile capture and Slack disabled.
- [x] (2026-08-05 15:48Z) Passed the Ubuntu `interactive-latency` job, downloaded its artifact, and recorded the remote evidence.
- [x] (2026-08-05 16:10Z) Verified that issue #1581 remains open and that blocker issues #1503 and #1309 are closed.
- [x] (2026-08-05 16:18Z) Changed the unset selector to RMCP. Kept explicit `off` as the legacy rollback. Updated behavior tests, comments, benchmark coverage, and MCP documentation.
- [x] (2026-08-05 16:23Z) Passed 122 MCP unit tests, 31 MCP integration tests, 11 benchmark CLI tests, isolated doctests, formatting, full workspace all-feature Clippy, and final policy review.
- [x] (2026-08-05 16:26Z) Committed the promotion as `9ed529336`, pushed the branch, and opened ready pull request #1669.
- [x] (2026-08-05 16:57Z) Reproduced the legacy CI failure and isolated the default-host test from the lane's inherited rollback selector.
- [x] (2026-08-05 16:57Z) Passed 125 MCP unit tests, 32 MCP integration tests, matching-toolchain doctests, formatting, affected-package Clippy, and final policy review.
- [ ] Commit and push the legacy-test repair, then confirm both MCP contract lanes on pull request #1669.

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

- Observation: The default Cargo shim and Homebrew Rust have different LLVM builds for Rust 1.96.0.
  Evidence: The first isolated all-feature Clippy run failed with E0514 after one compiler built `cc` and the other compiled the analysis build script. Pinning `/opt/homebrew/bin/cargo` and `RUSTC=/opt/homebrew/bin/rustc` passed the same gate in 1 minute 42 seconds.

- Observation: The transport record works for real traces, not only the small unit fixture.
  Evidence: The local run wrote 220 profile artifacts. Fifty raw traces had `truncated=true`. All 220 artifacts contained a retained `queue_wait` line, and the report accepted all four phases.

- Observation: Restoring delivery headroom gives a large margin below the existing limit.
  Evidence: The exact scan had p50 3,097.8 ms and p95 3,308.0 ms. The line scan had p50 3,099.0 ms and p95 3,217.4 ms. Both returned 20 truthful bounded partial results.

- Observation: Three newer master commits do not touch this repair.
  Evidence: `git diff aef3d746c..origin/master` is empty for both benchmark files, `scan_usages.rs`, and the benchmark workflow. The branch remains on its validated base because this task does not authorize a rebase.

- Observation: The remote repair works when raw traces are truncated.
  Evidence: Run `31020949528` wrote 220 profile artifacts. Forty-nine raw traces had `truncated=true`. All 220 artifacts retained all four transport phases.

- Observation: The remote scan cases keep almost two seconds of delivery headroom.
  Evidence: The exact scan had p50 3,039.7 ms and p95 3,069.0 ms. The line scan had p50 3,041.2 ms and p95 3,083.3 ms. Both returned 20 truthful bounded partial results.

- Observation: The separate broad benchmark job did not run a corpus case.
  Evidence: The dispatch supplied `repo=bifrost-self`, but `benchmark/targets.toml` has no repo with that name. The broad harness stopped before analysis. The targeted interactive job uses `benchmark/interactive-latency.toml`, where `bifrost-self` is valid, and passed.

- Observation: The full MCP code suite passes with RMCP as the unset default.
  Evidence: `cargo test -p brokk-bifrost-mcp --lib --tests` passed 122 unit tests and 31 integration tests. The default 2026-07-28 discovery test and the explicit two-host tests passed.

- Observation: The normal doctest command can reuse mixed Rust 1.96 metadata.
  Evidence: The code tests passed, but the doctest compile failed with E0514 because the normal target contained rustup and Homebrew artifacts. The managed isolated target with Homebrew Cargo and rustc passed and removed itself.

- Observation: The final policy result matches the branch baseline.
  Evidence: All 12 `bifrost.code-smells` rules completed with 280 findings and zero diagnostics. Seven findings touch changed source or test files. They are existing operations outside changed lines or reviewed test-loop prompts. No promotion edit adds a finding.

- Observation: `run_policy` remains slower than the repository threshold.
  Evidence: Identical calls took 4,896 ms with an unreliable result and 11,342 ms with a complete finding result. New evidence was added to issue #1452. A later final call took 5,025 ms before warm repeats fell below the threshold.

- Observation: The default-host discovery test inherited the legacy lane selector.
  Evidence: Pull request run `31025378173` and the local reproduction both returned `Unknown method: server/discover` when the parent set `BIFROST_MCP_RMCP=off`. The child used `spawn_server`, which inherited the parent environment.

- Observation: The final policy result still matches the branch baseline after the legacy-test repair.
  Evidence: All 12 `bifrost.code-smells` rules completed with 280 findings and zero diagnostics. No finding points to `crates/bifrost-mcp/tests/bifrost_mcp_server.rs`. The calls took 9,012 ms and 5,975 ms.

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

- Decision: Keep the RMCP default selector change outside this branch. Superseded on 2026-08-05.
  Rationale: GitHub issue #1581 required successful promotion evidence before the unset selector changed. The branch first produced that evidence.
  Date/Author: 2026-08-05 / Codex

- Decision: Promote RMCP on this branch after the successful branch benchmark.
  Rationale: The user explicitly extended this branch after the local and Ubuntu gates passed. Issues #1503 and #1309 are closed. Explicit `off` keeps the tested rollback.
  Date/Author: 2026-08-05 / Codex

- Decision: Pin the Homebrew Cargo and Rust compiler for the all-feature gate.
  Rationale: The installed rustup and Homebrew compilers have the same Rust release but different LLVM builds. One installation avoids incompatible crate metadata.
  Date/Author: 2026-08-05 / Codex

- Decision: Remove the inherited selector only from the default-host discovery child.
  Rationale: This test must prove the unset process default. All other legacy-lane children must keep inheriting `off` so the rollback contract stays covered.
  Date/Author: 2026-08-05 / Codex

## Outcomes & Retrospective

The repair is complete. Bifrost now keeps transport evidence outside the raw trace cap. The three-second scan budget returns truthful partial results with approximately two seconds of external headroom. Focused tests, full all-feature Clippy, and both local and Ubuntu release benchmarks pass. The final policy scan matches the 280-finding baseline and has no diagnostics or new changed-line finding.

GitHub Actions run `31020949528` passed its targeted `interactive-latency` job on revision `7594bf75f2a871cc4573761a7fa472b1f42f41c1`. All ten cases passed. The artifact proves that all four transport phases remain present in all 220 profiles, including 49 truncated raw traces. The separate broad job failed only because the supplied `bifrost-self` selector does not exist in its different manifest. It did not test code.

This branch supplies the required RMCP promotion evidence. The user then authorized the selector change on this branch. The validated implementation now makes RMCP the unset default and retains explicit `off` for rollback. The hand-written host remains present and tested. Commit `9ed529336` is pushed. Ready pull request #1669 targets `master` and closes issue #1581.

The first pull request CI run exposed one test-isolation error. The default-host discovery test inherited `off` from the legacy matrix lane, so it tested the rollback host instead of the unset default. The repair builds the same child command, removes only that selector, and leaves every shared rollback test under the legacy host. Both selector contexts now pass locally. The complete legacy CI command passes 125 unit tests and 32 integration tests.

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

Milestone 6 promotes the validated host. Change `rmcp_host_enabled(None)` to select RMCP. Keep explicit `on` and `off` strict. Update the selector unit test. Make one 2026-07-28 discovery test start the server without a selector, so it proves the process default from end to end. Keep the two-host contract suite and explicit legacy rollback lane.

Update host-default comments and public MCP documentation. Change the benchmark environment-isolation test to prove that an ambient legacy selector cannot override the new default. Use the benchmark-facing selector to prove explicit legacy rollback. Do not remove the hand-written host.

Milestone 7 repairs the legacy CI test isolation. Keep the matrix-wide `off` selector because it is the rollback contract. Build the default-host discovery child through the shared command builder, then remove `BIFROST_MCP_RMCP` from that child only. Do not change the process environment or skip the test. Run the exact NLP-enabled legacy contract command and one RMCP-selector repetition of the default-host test.

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

    scripts/with-isolated-cargo-target.sh env RUSTC=/opt/homebrew/bin/rustc /opt/homebrew/bin/cargo clippy --workspace --all-targets --all-features -- -D warnings

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
    gh workflow run Benchmark --repo BrokkAi/bifrost --ref dave/rmcp-interactive-benchmark-repair -f strict_compare=false -f profile=true -f post_to_slack=false

Find the dispatched run, wait for `interactive-latency`, and download its artifact. Do not post to Slack. Record all evidence in this plan.

After the user authorizes promotion, run:

    cargo fmt --all -- --check
    cargo test -p brokk-bifrost-mcp mcp_common::tests::the_rmcp_host_is_default_and_the_switch_is_strict
    cargo test -p brokk-bifrost-mcp --test bifrost_mcp_server default_mcp_host_answers_2026_07_28_discovery_before_any_handshake -- --nocapture
    cargo test -p brokk-bifrost --test suite_mcp_cli bifrost_benchmark_run -- --nocapture

Run the same final policy selection. Then commit and push only the promotion files. Open one ready pull request against `master` and link issue #1581.

## Validation and Acceptance

The transport unit test must prove that raw trace truncation can remove `queue_wait` without removing the retained timing line. The test must also prove that the report has no duplicate timing sample when raw and retained text both contain the same phase.

The measured-artifact test must continue to fail when RMCP or the legacy host does not emit a required phase. This prevents the capture repair from hiding a host regression.

The scan tests must preserve truthful incomplete results and structured recovery guidance. Explicit `max_duration_secs` requests must remain unchanged. The default budget alone changes from five seconds to three seconds.

The local release benchmark must show ten successful cases. `scan-semantic-procedure-exact` and `scan-semantic-procedure-line` must have p95 below 5,000 ms. Their 20 measured results can be bounded incomplete. All four transport phases must appear in the report. The fairness case must stay successful.

The GitHub `interactive-latency` job must pass on the branch revision and publish its artifact. A failure in the separate broad corpus job does not reject this targeted repair unless it identifies a regression caused by changed code.

Do not remove the legacy host, raise the latency limit, or broaden this work into analyzer optimization. The promotion must keep `BIFROST_MCP_RMCP=off` as the rollback selector.

The legacy CI repair must pass the default-host discovery test while its parent process has `BIFROST_MCP_RMCP=off`. The full legacy command must pass all MCP unit and integration tests. The explicit RMCP parent case must also pass. No other test child can lose the matrix selector.

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

The successful local report is `benchmark/interactive-latency-output/run-20260805T153131Z.json`. It records branch revision `f1c3ffc19b1c3770392a967782f1ddfd9babce3b`.

The important local results are:

    scan-semantic-procedure-exact  p50 3097.816 ms  p95 3308.018 ms  bounded 20/20
    scan-semantic-procedure-line   p50 3098.975 ms  p95 3217.439 ms  bounded 20/20
    fairness light request         p95 28.566 ms
    fairness cancellation          p95 18.977 ms
    profile artifacts              220 total, 50 raw-truncated, 220 with retained queue_wait

The successful remote evidence is GitHub Actions run `31020949528`. The targeted `interactive-latency` job passed on Ubuntu 24.04. It tested revision `7594bf75f2a871cc4573761a7fa472b1f42f41c1` with RMCP enabled. The artifact is `interactive-latency-31020949528`.

The important remote results are:

    search-common-symbols           p50 198.450 ms   p95 920.145 ms
    scan-semantic-procedure-exact  p50 3039.652 ms  p95 3068.966 ms  bounded 20/20
    scan-semantic-procedure-line   p50 3041.190 ms  p95 3083.314 ms  bounded 20/20
    fairness light request                           p95 19.124 ms
    fairness cancellation                            p95 20.892 ms
    profile artifacts              220 total, 49 raw-truncated, all four phases in 220

The downloaded artifact is `/private/tmp/rmcp-benchmark-31020949528.wxNpCO`. The report is `run-20260805T154739Z.json`. The GitHub run is `https://github.com/BrokkAi/bifrost/actions/runs/31020949528`.

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

Revision note, 2026-08-05: Created the initial plan from the failed RMCP promotion run. The plan separates real response-budget work from bounded profile capture. Recorded the first checkpoint commit before source implementation. Corrected the benchmark unit-test target. Recorded the completed transport-capture, scan-budget, local validation, and local benchmark milestones. Added the successful Ubuntu interactive result and artifact evidence. Removed the invalid broad-manifest repo selector from the replay command. Added Milestone 6 after the user authorized promotion on this branch. Recorded the completed selector, rollback, behavior-test, Clippy, package-test, doctest, and policy gates. Recorded promotion commit `9ed529336` and ready pull request #1669. Added Milestone 7 for the legacy-lane environment-isolation repair and its validation.
