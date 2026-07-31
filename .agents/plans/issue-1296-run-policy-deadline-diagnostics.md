# Preserve canonical run_policy results at the MCP deadline

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with `.agents/PLANS.md`.

## Purpose / Big Picture

The MCP `run_policy` tool has a five-second request-wide deadline. A policy batch that reaches this deadline must remain useful: callers need a canonical schema-version-2 policy report that says the result is unreliable, distinguishes a server deadline from an explicit client cancellation, identifies the stage and policy where work stopped, and retains available work and timing data. The same contract must apply if the analyzer workspace snapshot is not ready before the deadline, rather than returning a generic JSON-RPC internal error.

After this change, a caller can invoke the built-in `bifrost.code-smells` pack and receive either a completed result within the interactive budget or a bounded `unreliable` result whose metadata explains what completed, what was active, what remained, and where the five seconds were spent. The structural-query optimization tracked by issue #1246 is deliberately outside this plan; this issue establishes a truthful bounded-execution product strategy even when a policy remains intrinsically expensive.

## Progress

- [x] (2026-07-31 06:45Z) Verified the clean issue branch, fetched current remote state, reproduced the five-second `bifrost.code-smells` deadline, and diagnosed the current cross-layer behavior.
- [x] (2026-07-31 06:45Z) Wrote this ExecPlan and fixed the implementation boundary around canonical deadline diagnostics rather than structural-query optimization.
- [ ] Add canonical deadline origin, stage timing, and policy-progress types to the schema-version-2 report model.
- [ ] Capture coordinator stage timings, per-policy elapsed work, and active/completed/pending policy identifiers.
- [ ] Convert a pre-snapshot `run_policy` deadline into a canonical unreliable report while preserving ordinary errors.
- [ ] Thread an MCP correlation identifier through `run_policy` and add end-to-end deadline regressions.
- [ ] Run formatting, focused tests, the repository policy selection, and a live `bifrost.code-smells` validation.
- [ ] Run the guided-issue specialist review, address accepted findings, and complete the retrospective.

## Surprises & Discoveries

- Observation: The original generic cancellation result is already fixed after analyzer evaluation begins.
  Evidence: Commits `84bbe356` and `0e0d3ad4` preserve a canonical incomplete report for an expired deadline and prioritize deadline state over a racing client cancellation.

- Observation: The remaining pre-snapshot path still deliberately returns an MCP internal error.
  Evidence: `SearchToolsService::ensure_ready_with_cancellation` returns `SearchToolsServiceError::internal` when a deferred workspace build is not ready, and `issue_1306_run_policy_deadline_does_not_block_on_deferred_workspace_startup` asserts that error.

- Observation: The live reproduction now exposes the expensive policy but still reaches the global deadline.
  Evidence: On 2026-07-31 at `91357eec`, `bifrost.code-smells` returned in 5.025 seconds with schema version 2 and status `unreliable`. `bifrost.performance.expensive-operation-in-nested-loop` exhausted its structural budget after scanning 1,142 files and 2,069,805 facts; later policies reported cancellation.

- Observation: Existing `BIFROST_TIMING` scopes are operational stderr diagnostics, not part of the result contract.
  Evidence: `crates/bifrost-analysis/src/profiling.rs` prints begin/end records only when the environment variable is set; the values are not retained by `PolicyReportDocument`.

## Decision Log

- Decision: Keep the five-second MCP request deadline and make bounded diagnostic output the deliberate product-level execution strategy for this issue.
  Rationale: Raising the deadline would weaken the interactive latency contract and would not resolve per-policy structural budget exhaustion. Issue #1246 owns the optimizer work required to make repeated union seed scans cheaper.
  Date/Author: 2026-07-31 / Codex

- Decision: Put semantic termination and timing information in the canonical `PolicyReportDocument`, not only in the MCP wrapper.
  Rationale: Deadline origin and available work explain why the policy result is unreliable and must remain consistent across MCP, CLI, renderers, and future hosts.
  Date/Author: 2026-07-31 / Codex

- Decision: Keep the transport correlation identifier in the MCP result wrapper.
  Rationale: A JSON-RPC request correlation value identifies transport work, not policy semantics. The canonical report should be deterministic for the same analysis inputs, while the wrapper may vary per request.
  Date/Author: 2026-07-31 / Codex

- Decision: Represent a pre-snapshot timeout as an empty canonical policy report with selected policy identifiers in execution metadata and a report-level diagnostic.
  Rationale: No analyzer snapshot means no policy was registered or evaluated, so fabricating rule descriptors or policy runs would violate report joins. The selected identifiers and terminal stage still give the caller truthful recovery information.
  Date/Author: 2026-07-31 / Codex

- Decision: Use monotonic elapsed time and integer milliseconds, with relational tests rather than exact wall-clock assertions.
  Rationale: Monotonic timing avoids clock changes, while exact elapsed values would make tests flaky.
  Date/Author: 2026-07-31 / Codex

## Outcomes & Retrospective

Implementation has not started. The current outcome is a diagnosed and reproducible contract gap with an approved cross-layer implementation boundary.

## Context and Orientation

Bifrost exposes analyzer-backed tools through an MCP server. MCP is the Model Context Protocol: clients send JSON-RPC tool calls, and the server returns structured results. `crates/bifrost-mcp/src/mcp_common.rs` admits analyzer requests and creates a `CancellationToken` whose deadline is five seconds after admission. The token can also be cancelled explicitly by a client notification.

`crates/bifrost-mcp/src/searchtools_service.rs` validates `run_policy` arguments, resolves built-in selectors into policy inputs, obtains an immutable analyzer workspace snapshot, invokes policy evaluation, and serializes `RunPolicyToolResult`. The wrapper currently contains `status`, `exit_status`, and the canonical report.

`crates/bifrost-runtime/src/code_intelligence.rs` is the typed runtime boundary between hosts such as MCP and the analysis crate. It forwards policy evaluation into `crates/bifrost-analysis/src/analyzer/policy/coordinator.rs`.

The coordinator loads policy sources, registers them, evaluates policies sequentially, applies suppressions, and builds a `PolicyReportDocument`. The document in `crates/bifrost-analysis/src/analyzer/policy/report.rs` is the canonical schema-version-2 representation used by every renderer. Each `PolicyRun` in `crates/bifrost-analysis/src/analyzer/policy/finding.rs` includes a completion state and a bounded `PolicyWorkReport` containing counts such as scanned files and fact nodes.

A deadline and an explicit cancellation have different meanings. A deadline means the server used the entire admitted interactive budget and should return a normal, incomplete result. An explicit client cancellation means the caller no longer wants the result and may remain an error. Current code distinguishes these states internally through `CancellationToken::is_timed_out`, but the public incomplete reason is only `cancelled`.

A stage is a stable phase of the request lifecycle. This plan uses bounded, explicitly enumerated stages rather than arbitrary strings: policy selection, workspace snapshot acquisition, policy registration, policy evaluation, report construction, and response serialization. A terminal stage is the stage in progress when the request became incomplete.

## Plan of Work

The first implementation milestone extends the canonical analysis model. In `crates/bifrost-analysis/src/analyzer/policy/finding.rs`, add a deadline-specific incomplete reason and a millisecond work unit. Update every exhaustive consumer, including CVSS identity labeling, so a deadline remains stable in finding and report identity. In `crates/bifrost-analysis/src/analyzer/policy/report.rs`, add a bounded execution metadata value to `PolicyReportDocument`. It must record optional termination origin, terminal stage, total elapsed milliseconds, stage timings, and bounded completed, active, and pending policy identifiers. Constructors must validate consistent states, sort deterministic identifier collections, include retained-size accounting, and permit a report with no rules or runs when a report-level diagnostic explains a pre-evaluation deadline.

The second milestone instruments coordinator work. In `crates/bifrost-analysis/src/analyzer/policy/coordinator.rs`, measure registration, individual evaluation, and report construction with `Instant`. Track policy identifiers as the sequential evaluation loop advances. When the cancellation token is timed out, use `DeadlineExceeded`; when it is explicitly cancelled before the deadline, preserve the existing cancellation error. Merge an elapsed-milliseconds metric into each evaluated policy run without discarding its existing structural work metrics. Feed batch timing and progress into the report builder, then assemble the report without consulting the expired token again.

The third milestone handles deadlines before evaluation. Refactor `SearchToolsService::prepare_run_policy_with_cancellation` so argument validation, selected identifiers, options, and selection timing are retained independently from snapshot acquisition. A timed-out snapshot acquisition must become an early `RunPolicyToolResult` with exit status 2, a schema-version-2 report, empty rule and run arrays, a snapshot-deadline diagnostic, and execution metadata containing the selected identifiers. Invalid parameters, corrupt catalogs, explicit client cancellation, and unrelated internal failures must keep their current error behavior.

The fourth milestone adds MCP transport correlation and end-to-end coverage. In `crates/bifrost-mcp/src/mcp_common.rs`, give admitted `run_policy` requests a stable server-generated correlation identifier or safely normalized JSON-RPC request identifier and pass it through the standard prepared-call path. Add it to the MCP wrapper without putting it in the canonical report. Tests must prove that deadlines both before and during evaluation return successful structured tool content rather than JSON-RPC `-32603`.

The final milestone validates the change without enabling the `nlp` feature. Format with Cargo, run focused featureless tests in the affected crates and integration suites, then use the installed policy checking skill to run `bifrost.code-smells` plus any executable repository policy roots named by the repository. A live self-workspace request must finish within five seconds or return a deadline-specific canonical unreliable report with useful stage, policy, work, and timing data. An `unreliable` ordinary policy gate remains a failed validation result and must be reported honestly.

## Concrete Steps

All commands run from `/Users/dave/.codex/worktrees/8e7f/bifrost`.

After the report-model edit, run:

    cargo fmt --all -- --check
    cargo test -p brokk-bifrost-analysis analyzer::policy

Expect the new report serialization and deadline-reason tests to pass. If the package name differs from the workspace manifest, inspect `cargo metadata --no-deps` and use the exact package name rather than guessing.

After coordinator instrumentation, rerun the analysis tests and specifically select the current deadline regressions:

    cargo test -p brokk-bifrost-analysis issue_1306

Expect the zero-timeout test to serialize `deadline_exceeded`, while an explicit cancellation before deadline remains a cancellation error.

After MCP integration, run:

    cargo test -p brokk-bifrost-mcp issue_1296
    cargo test -p brokk-bifrost-mcp issue_1306
    cargo test --test bifrost_mcp_server

Expect the new MCP tests to find normal structured content with status `unreliable`, exit status 2, schema version 2, and deadline metadata. No test should wait five real seconds; use an already-expired token or a controllable blocked workspace build.

Run final formatting and focused linting:

    cargo fmt --all -- --check
    cargo clippy -p brokk-bifrost-analysis -p brokk-bifrost-mcp --all-targets -- -D warnings

Do not enable `nlp` for this task-scoped validation. If a comprehensive pre-push gate is later explicitly required, first check disk space and use `scripts/with-isolated-cargo-target.sh` according to `AGENTS.md`.

Run the installed MCP policy selection with evaluation date `2026-07-31` and `fail_on` set to `warning`. Expect either a completed result inside the five-second budget or a canonical deadline report. If the ordinary repository gate remains `unreliable` because of issue #1246, record it as unproven rather than clean.

## Validation and Acceptance

The change is accepted when all of the following behavior is observable.

A deadline-expired policy evaluation returns a normal structured result containing `status: "unreliable"`, `exit_status: 2`, and `report.schema_version: 2`. Its execution metadata says `deadline_exceeded`, identifies the terminal stage and active policy when known, lists completed and pending identifiers within fixed bounds, and retains per-policy work plus elapsed milliseconds.

An explicit client cancellation that occurs before the deadline remains distinguishable from deadline expiry. A race after the deadline has elapsed resolves to deadline expiry, matching the token's existing precedence rule.

A deferred workspace snapshot that misses the deadline returns the same canonical unreliable contract with no fabricated rules or runs. The report identifies the snapshot stage, selected policy identifiers, and elapsed work. Invalid inputs and non-deadline failures still return their established errors.

The MCP response exposes a correlation identifier suitable for joining result diagnostics with structured timing logs. The canonical report itself remains independent of transport request identity.

Focused tests pass without `nlp`. The live `bifrost.code-smells` run either completes within five seconds or demonstrates the deliberate bounded diagnostic strategy. No implementation from issue #1246 is included.

## Idempotence and Recovery

All edits and test commands are safe to repeat. Tests use immediate expiry or controlled blocking rather than sleeping for the production deadline. Timing fields use monotonic time and bounded integer values.

If report validation rejects the pre-snapshot document, do not fabricate policy descriptors. Add a dedicated canonical constructor or builder path whose invariant is that selected policy identifiers live only in execution metadata and a report-level diagnostic explains the absence of runs.

If adding a field to schema version 2 conflicts with an existing exact-schema fixture, inspect whether the fixture represents an extensible serialized object or a frozen compatibility contract. Bifrost does not currently require backwards compatibility, but all canonical renderers must be updated together so no host silently loses deadline semantics.

If an expired cancellation token prevents report construction, separate cancellation-aware analysis from cancellation-independent assembly. Never clear or replace the token merely to hide a structured cancellation failure.

## Artifacts and Notes

The current reproduction is:

    run_policy({
      "policy_packs": ["bifrost.code-smells"],
      "evaluation_date": "2026-07-31",
      "fail_on": "warning"
    })

Observed summary:

    wall time: 5.025 seconds
    status: unreliable
    schema_version: 2
    expensive-operation-in-nested-loop:
      scanned_files: 1142
      fact_nodes: 2069805
      completion: partial_discovery
    following policies:
      completion: cancelled

This is evidence for both #1296 and the optimizer work already tracked by #1246. The implementation in this plan changes only the bounded result contract.

## Interfaces and Dependencies

Use only the Rust standard library timing types and existing policy report primitives. Do not add dependencies.

At the end of the first milestone, `PolicyIncompleteReason` must include a serialized `deadline_exceeded` variant. `PolicyWorkUnit` must support integer milliseconds. `PolicyReportDocument` must expose immutable execution metadata through a getter and serialize it in every canonical JSON result.

Define a bounded execution metadata type near `PolicyReportDocument`. It must use validated policy identifiers and an enum for stages and termination origin. It must not accept arbitrary unbounded labels. The exact constructor may evolve during implementation, but it must validate that a termination origin and terminal stage appear together and that active, completed, and pending identifiers do not overlap.

Coordinator evaluation must accept or construct an execution trace that records stage start and completion with `Instant`, but serialized values must be integer milliseconds. The trace is request-local and must not use global mutable state.

The MCP wrapper must contain the canonical `PolicyReportDocument` unchanged plus transport correlation. Do not duplicate report timing fields in the wrapper.

Revision note: Initial ExecPlan written on 2026-07-31 after live reproduction and guided diagnosis. It records the approved boundary, the remaining contract gaps, and the decision to leave structural seed reuse to issue #1246.
