# Repair cold query readiness and persisted Kotlin facts

This ExecPlan is a living document. Maintain it according to
`.agents/PLANS.md` from the repository root.

## Purpose / Big Picture

The first `query_code` request can wait for a deferred workspace build before
the current profile starts. A user sees this wait, but the profile reports only
later query work. The Exposed profile also showed a Kotlin extraction after a
scan-only prewarm. The cause is not yet proven. After this work, a profile will
show request readiness and full request time. A persisted Kotlin fact test will
prove that the next service hydrates stored facts instead of extracting them
again.

The scheduled run 31170861236 at commit
`6dc7cc58fc62ef7fc88653b64464116600466c14` showed the problem. Exposed first
request wall time was about 1.9 seconds while query profile time was about 170
milliseconds. Dapper also did real cold query work. This plan fixes visibility
and the Kotlin persistence contract first. It does not change benchmark limits
or accept cold failures as baseline values.

## Progress

- [x] (2026-08-07 11:20Z) Recorded the fresh benchmark evidence and preserved
  the narrow Gin baseline update already approved by the user.
- [x] (2026-08-07 11:20Z) Located the request preparation and deferred-build
  seam in `crates/bifrost-mcp/src/searchtools_service.rs`.
- [x] (2026-08-07 11:42Z) Read the profile type, request path, persistence
  code, and nearby tests.
- [x] (2026-08-07 11:42Z) Added request-phase timing fields and a deferred
  readiness behavior test. The focused MCP test passes.
- [x] (2026-08-07 11:47Z) Added a persisted Kotlin structural-facts workspace
  reopen test. The focused analysis test passes.
- [x] (2026-08-07 13:26Z) Ran `cargo fmt --check` and the featureless analysis
  and MCP library suites in an isolated target.
- [x] (2026-08-07 13:26Z) Ran policy discovery and attempted the required
  built-in code-smells policy request. The request was blocked by the known
  stale Java analyzer generation, not by a policy result.
- [x] (2026-08-08 06:31Z) Reran the built-in code-smells policy. The tool ran,
  but its report was unreliable because five existing rules had partial source
  discovery. The changed files did not add a reported finding.
- [x] (2026-08-08 06:05Z) Rebased the work on `origin/master` at
  `46e7bf58c` and reran the featureless analysis and MCP library suites.
- [x] (2026-08-08 06:12Z) Ran the Exposed exact query locally with the new
  timing fields. It showed that the MCP host queue wait, not service
  preparation, contains the deferred workspace build.
- [x] (2026-08-08 06:18Z) Added `transport_queue_wait` to the profile and
  benchmark report. The first profiled Exposed request now accounts for
  975.6 ms of queue wait and 109.1 ms of query execution.
- [x] (2026-08-08 06:25Z) Deferred Git blob header and attribute checks to
  requested clean paths. The Exposed first request fell from 1,086 ms to
  677 ms in the same local benchmark setup.

## Surprises & Discoveries

- Observation: The Bifrost navigation service returned stale analyzer
  generations for Rust, C#, and Java during discovery.
  Evidence: `search_symbols` and `get_summaries` returned `stale analyzer
  generation` errors on 2026-08-07. Direct source reads are used for this plan.

- Observation: `prepare_query_code` calls the snapshot path before profile
  execution. That path calls `ensure_ready`, which joins the pending workspace
  build.
  Evidence: scheduled Exposed wall time was about 1.7 seconds greater than
  profile time. The warm difference was about four milliseconds.

- Observation: Scan-only seed access bypasses the posting index. It still
  calls ordinary `structural_facts_with_outcome`, which can read or write a
  durable snapshot. Limited receiver facts are the path that intentionally
  avoids durable persistence.
  Evidence: `search/seeds.rs` calls `load_seed_facts`; `provider.rs` owns the
  durable snapshot read and write path.

- Observation: Generic TypeScript persistence coverage already proves a
  reopened `WorkspaceAnalyzer` can hydrate ordinary facts. It does not prove
  the Exposed Kotlin query or the scan-only access mode.
  Evidence: `tests/suite_persistence/structural_facts_persistence.rs`.

- Observation: A Kotlin scan-only prewarm persists the exact `Table` class
  facts. A new persisted workspace hydrates one snapshot and performs zero
  extractions.
  Evidence: `scan_only_kotlin_seed_hydrates_from_durable_facts_after_workspace_reopen`
  passed on 2026-08-07.

- Observation: The deferred workspace build begins before the service sees the
  `query_code` request. Therefore the service's `workspace_ready` field is
  near zero in a first MCP request. The MCP host queue interval contains that
  wait and must be part of the request total.
  Evidence: the local Exposed profile reported 975.6 ms of
  `transport_queue_wait`, 109.1 ms of query execution, and 1,085.1 ms total.

- Observation: JavaScript and Kotlin did not run two Git identity scans. One
  language waited for the shared identity mutex while the other read 5,329
  blob headers. The full identity scan cost 588.1 ms.
  Evidence: the timing log contains one `git_identity_scan` note and two
  overlapping `resolve_live_oids` scopes.

- Observation: A startup scan only needs index and dirty-tree data. Blob sizes
  and transform attributes only matter when an analyzer requests a clean path.
  Evidence: after deferred checks, Exposed reported a 63.1 ms identity scan,
  a 557.3 ms queue wait, and a 676.9 ms first request.

- Observation: The complete featureless library validation passed. The latest
  code-smells policy run was unreliable due partial source discovery in five
  existing rules, not due a changed-file finding.
  Evidence: `cargo test -p brokk-bifrost-analysis -p brokk-bifrost-mcp --lib`
  passed 1,707 analysis tests and 115 MCP tests. `cargo test --lib` passed 78
  tests with normal host access. `run_policy` reported partial discovery for
  nested expensive operations, file reads, parsing, serialization, and sorts.

## Decision Log

- Decision: Repair request accounting before changing an optimizer.
  Rationale: The profile does not include workspace readiness. A direct speed
  change would not show which phase improved.
  Date/Author: 2026-08-07 / Codex

- Decision: Treat Kotlin persisted facts as a behavior contract.
  Rationale: The benchmark promises scan-only prewarming. A fresh service must
  hydrate stored facts and must not extract the same facts again.
  Date/Author: 2026-08-07 / Codex

- Decision: Leave Dapper planner work for a later change.
  Rationale: Its first query does real broad hydration. It needs a focused
  candidate-selection design after request timing separates readiness cost.
  Date/Author: 2026-08-07 / Codex

- Decision: Charge MCP host queue time to the query profile.
  Rationale: it is user-visible request time and includes deferred workspace
  readiness before the service starts preparing the request.
  Date/Author: 2026-08-08 / Codex

- Decision: Validate blob identity lazily, without weakening content checks.
  Rationale: reading every repository blob header adds cold-start time for
  files and languages that the workspace does not analyze.
  Date/Author: 2026-08-08 / Codex

## Outcomes & Retrospective

The implemented profile adds `request_timings_ns` with transport queue wait,
workspace readiness, preparation, input decoding, query execution, rendering
and serialization, and total request time. The field is additive, so the
profile format remains v2. A service test proves readiness accounting. A host
handoff test proves that queue wait is included in the total. The Kotlin test
proves the scan-only durable-facts contract.

No Kotlin persistence code changed. The new test shows the benchmark symptom
does not reproduce in the durable structural-facts layer. The local Exposed
profile identified and removed the broad Git object-header scan. Dapper
candidate-planning work remains out of scope. Do not promote Exposed or Dapper
baseline values from this single local profile.

## Context and Orientation

`crates/bifrost-mcp/src/searchtools_service.rs` owns the MCP search service.
`SearchToolsService::query_code_result` parses a request, calls
`prepare_query_code`, and then executes a structural query.
`prepare_query_code` creates a workspace snapshot. `ensure_ready` waits for a
deferred workspace build when that build is still active.

A `CodeQueryProfile` is the structured result returned when a client sets
`execution_mode` to `profile`. It currently contains query execution timings,
work counters, cache layers, and result data. It must gain a request timing
section that distinguishes readiness from execution and reports full request
time.

`src/benchmark/query_code.rs` starts a separate scan-only service before its
timed service. This prewarm writes durable structural facts. The timed service
then uses a fresh process and database connection. The test creates a new
persisted workspace with an explicit scan-only access mode. It proves a durable
snapshot read, not an in-memory cache hit.

The existing modifications to `benchmark/baselines/ubuntu-latest.json` and
`benchmark/baselines/README.md` are an approved Gin-only baseline update. This
plan preserves them. It does not expand that baseline change.

## Plan of Work

First, read the query profile model and the request preparation code. Add a
small request timing value at the service boundary. Start its clock before
snapshot preparation. Record readiness after the snapshot is available. Record
execution after structural query execution. Record total after result rendering
and serialization. The MCP host must pass its accepted-to-execution queue wait
to the service profile. Use the same monotonic clock type as the existing
profile. Do not change the existing execution timing meaning.

Add tests at the service boundary. One test must start a service with a pending
deferred build and request profile mode. It must show that readiness is nonzero
and total time is at least execution time. A second test must use an already
ready service and prove the new fields remain internally consistent.

Second, trace the persisted structural facts write and read methods. Add a test
that uses a Kotlin fixture and two separate persisted analyzers. The first
analyzer runs the scan-only prewarm query. The second analyzer runs the same
exact query with profile capture. The test must require one persisted hydration
and zero extractions for the query facts. It must use the test-only explicit
access mode instead of a process-global environment variable.

Keep the profile format compatible if possible. Add fields rather than change
existing names or units. Update the benchmark parser only when it needs the new
fields for report output. Do not make a timing threshold change in this work.

## Concrete Steps

From `/Users/dave/.codex/worktrees/5cb0/bifrost`:

1. Read `CodeQueryProfile`, `query_code_result`, `prepare_query_code`,
   `ensure_ready`, and structural-facts persistence code. Record exact method
   names in this plan.
2. Update the profile model and MCP response path. Add unit or integration
   tests in the established test module or suite.
3. Create the smallest Kotlin inline project that defines and queries one
   table-like class. Run a scan-only query through the persisted service. Start
   a new service on the same project cache and run profile mode. Assert stored
   hydration and no extraction.
4. Run `cargo fmt`.
5. Run focused featureless tests for the MCP service and structural facts. Use
   `scripts/with-isolated-cargo-target.sh` when an isolated target is needed.
6. Run `cargo test --lib` only if focused tests do not cover the changed profile
   model. Do not enable `nlp`.
7. Run `run_policy` for `bifrost.code-smells` and repository policy roots.
   Treat `finding` or `unreliable` as a failed validation result.
8. If local benchmark repositories are available, run the Exposed exact query
   with `BIFROST_TIMING` and retain the profile artifact. The result must expose
   readiness, execution, and total timing.

## Validation and Acceptance

The implementation is accepted when all conditions hold:

- A profiled first request reports queue wait, readiness, execution, and total timing.
  Total is at least the sum of the measured request phases.
- A ready request reports the same fields with a small readiness value and
  correct ordering.
- A scan-only Kotlin prewarm followed by a new persisted analyzer produces a
  profile with persisted hydration and zero structural extraction.
- The focused tests, `cargo fmt --check`, JSON baseline check, and selected
  policies pass.

## Idempotence and Recovery

The tests use temporary directories or the existing persisted test cache
helpers. They can run repeatedly. Do not remove a user workspace cache. If an
isolated Cargo build fails, rerun the same helper command. It removes its own
temporary target directory.

## Artifacts and Notes

Fresh scheduled benchmark artifact:

    /private/tmp/bifrost-benchmark-31170861236/benchmark-31170861236/
    run-20260807T111857Z.json

The fresh compare reported ten entries before the approved Gin baseline update.
The work in this plan keeps the cold Dapper, Exposed, and Scala observations
visible.

Local Exposed profile before lazy identity validation:

    /private/tmp/bifrost-exposed-query-profile-queue-accounting-20260808/
    run-20260808T055813Z.json

Local Exposed profile after lazy identity validation:

    /private/tmp/bifrost-exposed-query-profile-lazy-identity-20260808/
    run-20260808T060526Z.json

## Interfaces and Dependencies

The profile response must continue to use
`crate::analyzer::structural::CodeQueryProfile`. Add a typed request timing
structure in that module. It must serialize through the existing response.

The service must retain `SearchToolsServiceError` for request preparation
failures. Do not add string parsing or source-text fallbacks. Use the
structural facts store and codec already used by the analyzer.

Plan updated on 2026-08-08: account for MCP host queue time and avoid the
repository-wide Git object-header scan during deferred workspace startup.
