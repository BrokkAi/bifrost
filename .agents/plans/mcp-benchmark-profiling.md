# Make MCP benchmark profiling safe and actionable

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This plan must be maintained in accordance with `.agents/PLANS.md` from the repository root.

## Purpose / Big Picture

The benchmark harness currently starts the Bifrost Model Context Protocol (MCP) server with a piped standard-error stream but does not read that stream while requests run. Standard error is where `BIFROST_TIMING` writes structured timing lines. Enough timing output can therefore fill the operating-system pipe and block the server before it returns its JSON-RPC response, deadlocking the benchmark. Even successful runs discard the timing output.

After this change, a developer can run `bifrost_benchmark run --profile ...` safely. The harness will continuously drain the child server's standard error, retain a bounded diagnostic tail in memory, and write profiling traces beneath the benchmark output directory. Traces will identify the repository, scenario, warmup or measured phase, and iteration. Failed MCP scenarios will include a useful retained standard-error tail. Without `--profile`, reports and normal output remain unchanged and timing instrumentation performs only the existing cheap disabled checks.

## Progress

- [x] (2026-07-13 09:55Z) Verified issue #697, fetched current refs, and confirmed the checkout is the matching feature branch at the same commit as `origin/master`.
- [x] (2026-07-13 09:55Z) Traced the MCP session, benchmark runner, CLI/report, workflow, watcher/snapshot, and definition-index code paths.
- [ ] Implement a continuously running standard-error drain with a bounded sequenced tail, explicit shutdown, and focused tests that exceed normal pipe capacity.
- [ ] Add opt-in CLI and runner profiling configuration, per-iteration trace artifacts, failure-tail reporting, compact optional report references, and the manual workflow input.
- [ ] Add disabled-by-default scopes and counters around watcher delta application, snapshot updates, definition batch/language dispatch, live-key enumeration, persisted row fetch, row resolution, dirty/nonpersisted units, and definition-index construction.
- [ ] Run formatting, focused tests, the benchmark integration suite, Clippy with all targets and features, and the full feature-enabled test suite; update this plan with evidence and outcomes.

## Surprises & Discoveries

- Observation: The issue's deadlock description exactly matches the current implementation. `McpSession::read_line` reads `ChildStderr` only when MCP stdout reaches end-of-file, and `Drop` kills the child without preserving successful-session output.
  Evidence: `src/benchmark/mcp_session.rs` stores `stderr: ChildStderr`; its EOF branch calls `read_to_string`, while no request-success path reads standard error.

- Observation: The runner creates one MCP session for a group of scenarios and runs every warmup and measured iteration through it, so raw server timing lines do not inherently identify the request that produced them.
  Evidence: `src/benchmark/runner.rs::run_mcp_scenarios` initializes one `McpSession` and maps multiple scenarios through `run_mcp_scenario`.

- Observation: The existing `BIFROST_TIMING` implementation already avoids printing when disabled, and scopes can be added without changing report schemas unless profiling itself is requested.
  Evidence: `src/profiling.rs::Scope::new` and `profiling::note` guard output with `profiling::enabled()`.

## Decision Log

- Decision: Keep the current branch and do not rebase or switch branches.
  Rationale: The repository instructions prohibit branch changes and rebases unless explicitly requested. The fetched matching feature branch and `origin/master` currently point to the same commit, so no integration is needed.
  Date/Author: 2026-07-13 / Codex

- Decision: Continuously drain standard error in a dedicated thread for every MCP session, not only in profile mode.
  Rationale: Deadlock safety must not depend on a profiling flag. When profiling is disabled the drain retains only a small bounded failure tail and does not write artifacts.
  Date/Author: 2026-07-13 / Codex

- Decision: Represent request boundaries with monotonically increasing drain cursors and write one trace artifact per scenario iteration when profiling is enabled.
  Rationale: Cursor snapshots let the runner extract only timing lines observed for a request while bounding memory. Metadata in each trace makes a reused child process understandable. If output exceeds the tail capacity, the trace will say that its beginning was truncated while the drain continues consuming all bytes.
  Date/Author: 2026-07-13 / Codex

- Decision: Add optional trace references only when `--profile` is enabled.
  Rationale: This preserves byte-for-byte report shape for ordinary scheduled benchmarks while making profile artifacts discoverable from an opt-in report.
  Date/Author: 2026-07-13 / Codex

## Outcomes & Retrospective

Implementation is in progress. The initial investigation established the unsafe pipe lifecycle and the exact instrumentation boundaries. No production behavior has changed yet.

## Context and Orientation

`src/benchmark/mcp_session.rs` launches the `bifrost` binary as an MCP child process and communicates through newline-delimited JSON-RPC on stdin and stdout. Its standard error is a separate operating-system pipe. A pipe has finite capacity; if the parent does not read while the child writes, the child eventually blocks.

`src/benchmark/runner.rs` prepares each repository, starts MCP sessions, performs warmup iterations that are not included in the benchmark median, then performs measured iterations that are. `src/benchmark/report.rs` defines the JSON artifact schema. `src/bin/bifrost_benchmark.rs` parses the `run` command and resolves output paths. `.github/workflows/benchmark.yml` invokes that command and uploads everything in `benchmark/benchmark-output`.

`src/profiling.rs` provides `scope` and `note`. When the child process has the `BIFROST_TIMING` environment variable, a scope prints a `BEGIN` line on creation and an `END` line with duration on drop. With the variable absent, it emits nothing.

The `get_definitions_by_location` MCP request first passes through `src/searchtools_service.rs`. `snapshot_for_query` applies file-watcher changes and selects the current immutable `WorkspaceAnalyzer` snapshot. `src/searchtools.rs::get_definitions_by_location` resolves file inputs and calls `src/analyzer/usages/get_definition/mod.rs::resolve_definition_batch`. Language-specific resolution may lazily request `IAnalyzer::definition_lookup_index`. For tree-sitter analyzers, `src/analyzer/tree_sitter_analyzer.rs::sql_definition_lookup_index` enumerates live files, fetches persisted candidate rows from `src/analyzer/store/mod.rs`, resolves those rows back to live `CodeUnit` declarations, adds dirty and synthetic nonpersisted units, and constructs the index.

## Plan of Work

First, replace the raw `ChildStderr` field in `McpSession` with a drain object. The drain will take ownership of the pipe immediately after spawn, run a named reader thread until end-of-file, and keep a byte-bounded deque of sequenced lines under a mutex. Snapshot methods will return the current sequence number, the retained lines since a prior sequence, whether earlier lines were evicted, and a formatted overall tail. `McpSession::Drop` will kill and wait for the child before joining the reader so the pipe reaches end-of-file. The EOF error path will use the retained tail instead of attempting a blocking late read. Focused tests will feed more data than ordinary pipe capacity through the drain and prove that reading completes, retained memory stays bounded, and the newest diagnostics survive truncation.

Second, add a `BenchmarkProfile` configuration carried by `RunRequest`. `bifrost_benchmark run --profile` will place traces in a dedicated directory beneath the already resolved benchmark output directory and pass `BIFROST_TIMING=1` only to MCP children started for that run. Around each warmup and measured tool call, the runner will take a drain cursor, execute and validate the request, then write the captured interval to a deterministic, filesystem-safe trace filename containing repository, scenario, phase, and one-based iteration. Trace content will begin with those same metadata fields and will state whether the bounded interval was truncated. Failed scenario messages will append the retained child tail. Successful profiled `ScenarioReport` values will optionally reference their trace paths; ordinary reports will omit the field entirely. The GitHub Actions workflow will expose a boolean manual `profile` input and append `--profile` only for opted-in dispatches.

Third, add profiling scopes and notes around the path needed to explain a slow definition lookup. The service will scope snapshot acquisition, watcher delta collection, full or incremental snapshot update, and the tool handler. The definition resolver will scope batch setup, per-request source/reference/tree work, definition-index acquisition, and language dispatch, with notes for batch size and selected language. The tree-sitter analyzer will scope live-key enumeration, persisted row fetch, row resolution, dirty-unit collection, nonpersisted synthetic collection, and final index construction, noting counts and the existing build counter. The store will scope the SQL candidate-row query and note key and row counts. Labels will be stable enough to compare runs and will avoid printing paths or source text.

Finally, run `cargo fmt`, focused unit tests for the drain and report behavior, `cargo test --test bifrost_benchmark_run`, and an opt-in benchmark smoke run against a small selected repository if the fixture manifest allows it. Then run `cargo clippy --all-targets --all-features -- -D warnings` and `cargo test --features nlp,python`. Update this plan after each milestone with exact evidence and checkpoint commits.

## Concrete Steps

All commands run from `/Users/dave/.codex/worktrees/195f/bifrost`.

Create and verify the drain milestone:

    cargo fmt
    cargo test benchmark::mcp_session

Expected evidence is that a test writes substantially more than 64 KiB of standard-error data, the reader reaches end-of-file without blocking, the captured byte count stays at or below its configured bound, and the final marker remains in the tail.

Verify CLI, report, and integration behavior:

    cargo test --test bifrost_benchmark_run

Expected evidence is that existing non-profile report assertions remain unchanged and new profile-mode coverage finds trace files with repository, scenario, phase, iteration, and Bifrost timing lines.

Run repository quality gates:

    cargo fmt --check
    cargo clippy --all-targets --all-features -- -D warnings
    cargo test --features nlp,python

The commands must complete successfully. Feature-enabled tests are required because the default feature set omits the NLP integration suites.

## Validation and Acceptance

The deadlock-safety acceptance test must use a controllable reader or child that writes beyond a normal standard-error pipe's capacity before a valid response can complete. The test must finish within its normal test timeout, proving the parent drains concurrently rather than at stdout EOF.

With profiling disabled, the benchmark CLI help is the only intentional visible change, existing reports deserialize and compare, and newly written reports omit profile fields. No timing lines or trace files are produced.

With `--profile`, each MCP child receives `BIFROST_TIMING`, the output directory contains per-iteration trace files, and each file names the repository, scenario, phase, and iteration. A failed request's report message contains a bounded recent standard-error tail even if earlier output was evicted. The GitHub workflow uploads these traces because they live under `benchmark/benchmark-output`.

The timing output for `get_definitions_by_location` must distinguish at least watcher/snapshot work, batch and selected language, definition-index acquisition, live key enumeration, SQL candidate fetch, row resolution, dirty and nonpersisted candidate collection, and final index construction/build count.

## Idempotence and Recovery

The implementation is additive and commands are safe to rerun. Trace filenames should be unique within a run or deliberately overwritten only for the same repository/scenario/phase/iteration tuple. The output directory is an artifact directory and may contain prior run files; tests must use temporary directories so they do not modify checked-in benchmark data.

If a child exits early, kill and wait are safe to retry conceptually: the implementation will ignore an already-exited kill error, wait for process cleanup, then join the drain after pipe closure. A poisoned capture mutex must produce a clear benchmark error or recover its inner bounded tail rather than panic in `Drop`.

## Artifacts and Notes

The motivating issue records a `serde-json-rs` `get_definition` median of roughly 34 seconds against an 11.45 millisecond baseline, but only exposes wall-clock time. The intended trace shape is concise, for example:

    repository=serde-json-rs
    scenario=get_definition
    phase=measured
    iteration=1
    truncated=false
    [bifrost-timing] BEGIN SearchToolsService::snapshot_for_query
    [bifrost-timing] END SearchToolsService::snapshot_for_query (0.2 ms)
    [bifrost-timing] BEGIN TreeSitterAnalyzer::definition_lookup_index
    ...

Exact labels may evolve during implementation, but the acceptance boundaries above must remain visible.

## Interfaces and Dependencies

No new third-party dependency is required. Use `std::thread`, `std::sync::{Arc, Mutex}`, and `std::collections::VecDeque` for the drain and bounded tail.

In `src/benchmark/mcp_session.rs`, introduce an internal drain type with operations equivalent to:

    fn spawn(stderr: ChildStderr, capacity_bytes: usize) -> Result<Self, String>;
    fn cursor(&self) -> u64;
    fn capture_since(&self, cursor: u64) -> CapturedStderr;
    fn tail(&self) -> String;
    fn join(&mut self);

`CapturedStderr` must expose retained text and a truncation flag. `McpSession` must expose request-boundary cursor and capture methods to the runner without exposing synchronization primitives.

In `src/benchmark/runner.rs`, extend `RunRequest` with optional profiling configuration that includes the trace directory. Keep the public `run_benchmark` entry point and existing benchmark semantics.

In `src/benchmark/report.rs`, add an optional profile artifact field with `#[serde(default, skip_serializing_if = "Option::is_none")]` or an optional collection with the equivalent empty omission, preserving compatibility with existing baseline JSON.

In `src/profiling.rs`, continue to use the existing environment-gated `scope` and `note` API. Do not add a logging framework or always-on counters.

Plan revision note (2026-07-13 09:55Z): Created the initial self-contained plan after live issue verification and source-path investigation. The design chooses an always-on safety drain with opt-in artifact writing so deadlock prevention is unconditional while report churn remains opt-in.
