# Make MCP benchmark profiling safe and actionable

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This plan must be maintained in accordance with `.agents/PLANS.md` from the repository root.

## Purpose / Big Picture

The benchmark harness currently starts the Bifrost Model Context Protocol (MCP) server with a piped standard-error stream but does not read that stream while requests run. Standard error is where `BIFROST_TIMING` writes structured timing lines. Enough timing output can therefore fill the operating-system pipe and block the server before it returns its JSON-RPC response, deadlocking the benchmark. Even successful runs discard the timing output.

After this change, a developer can run `bifrost_benchmark run --profile ...` safely. The harness will continuously drain the child server's standard error, retain a bounded diagnostic tail in memory, and write profiling traces beneath the benchmark output directory. Traces will identify the repository, scenario, warmup or measured phase, and iteration. Failed MCP scenarios will include a useful retained standard-error tail. Without `--profile`, reports and normal output remain unchanged and timing instrumentation performs only the existing cheap disabled checks.

## Progress

- [x] (2026-07-13 09:55Z) Verified issue #697, fetched current refs, and confirmed the checkout is the matching feature branch at the same commit as `origin/master`.
- [x] (2026-07-13 09:55Z) Traced the MCP session, benchmark runner, CLI/report, workflow, watcher/snapshot, and definition-index code paths.
- [x] (2026-07-13 10:07Z) Implemented a continuously running standard-error drain with a 256 KiB production tail, sequenced request cursors, explicit child-before-reader shutdown, poison recovery, and focused tests that push over 2 MiB through a bounded socket.
- [x] (2026-07-13 10:20Z) Added `--profile`, child-only `BIFROST_TIMING`, per-iteration traces and relative report references, bounded failure-tail context, and a manual workflow input; verified both profiled output and profile-disabled report stability with real-child integration tests.
- [x] (2026-07-13 10:26Z) Added disabled-by-default scopes and counters around watcher delta application, snapshot updates, definition batch/language dispatch, live-key enumeration, persisted row fetch, row resolution, dirty/nonpersisted units, and definition-index construction; the real-child profile test asserts every required boundary.
- [x] (2026-07-13 10:43Z) Ran formatting, focused drain tests, the complete benchmark integration suite, all-target/all-feature Clippy, and the feature-enabled library suite. All runnable gates pass: 3 drain tests, 9 benchmark integration tests, and 729 feature-enabled library tests (3 ignored). The macOS `python` feature cannot link standalone integration binaries because PyO3's `extension-module` configuration deliberately leaves Python symbols unresolved; this pre-existing packaging constraint is recorded below.
- [x] (2026-07-13 11:06Z) Completed the five-perspective guided review and resolved all six deduplicated findings: bounded transient reads, synchronized request boundaries, collision-resistant run-scoped artifacts, joined initialization diagnostics, guarded startup cleanup, and a shared component sanitizer. Two post-fix edge cases were also corrected, preserving primary child errors and attaching EOF stderr exactly once. Three specialist re-reviews approve the final diff.
- [x] (2026-07-13 11:06Z) Revalidated the review fixes: 8 focused benchmark unit tests, 5 manifest tests, all 9 benchmark integration tests, clean all-target/all-feature Clippy, and 734 feature-enabled library tests passed with 3 ignored.

## Surprises & Discoveries

- Observation: The issue's deadlock description exactly matches the current implementation. `McpSession::read_line` reads `ChildStderr` only when MCP stdout reaches end-of-file, and `Drop` kills the child without preserving successful-session output.
  Evidence: `src/benchmark/mcp_session.rs` stores `stderr: ChildStderr`; its EOF branch calls `read_to_string`, while no request-success path reads standard error.

- Observation: The runner creates one MCP session for a group of scenarios and runs every warmup and measured iteration through it, so raw server timing lines do not inherently identify the request that produced them.
  Evidence: `src/benchmark/runner.rs::run_mcp_scenarios` initializes one `McpSession` and maps multiple scenarios through `run_mcp_scenario`.

- Observation: The existing `BIFROST_TIMING` implementation already avoids printing when disabled, and scopes can be added without changing report schemas unless profiling itself is requested.
  Evidence: `src/profiling.rs::Scope::new` and `profiling::note` guard output with `profiling::enabled()`.

- Observation: `cargo test benchmark::mcp_session` builds every integration-test target before applying the name filter, which made the first focused invocation spend several minutes linking unrelated binaries.
  Evidence: Interrupting that invocation and running `cargo test --lib benchmark::mcp_session` reused the compiled library and completed with 3 passing tests in 0.41 seconds.

- Observation: Request-boundary cursor capture contains the existing nested `BIFROST_TIMING` scopes in real MCP runs without an explicit settling delay.
  Evidence: `run_subcommand_profile_writes_iteration_traces_and_report_references` found timing lines in both the warmup and measured trace immediately after each JSON-RPC response.

- Observation: The shell's default `cargo clippy` mixed rustup's Rust 1.96 compiler with a Homebrew `cargo-clippy` binary and failed before analyzing the crate.
  Evidence: Running the component explicitly as `rustup run 1.96.0 cargo-clippy clippy --all-targets --all-features -- -D warnings` completed cleanly.

- Observation: On this macOS checkout, Cargo cannot link standalone test binaries with the `python` feature because that feature enables PyO3's `extension-module` mode, which intentionally does not link libpython and therefore leaves `Py*` symbols unresolved in ordinary executables.
  Evidence: Both `cargo test --features nlp,python --tests` and an issue-focused `--test bifrost_benchmark_run` invocation fail at the linker with unresolved Python symbols. `PYO3_PYTHON=/opt/homebrew/bin/python3.13 cargo test --features nlp,python --lib` links and passes all 729 non-ignored library tests outside the sandbox. The first sandboxed run had one sidecar test fail because it could not create `~/.cache/uv`; the unrestricted rerun passed.

- Observation: Bounding only retained lines is insufficient because `BufRead::read_until` can grow its temporary line buffer without limit before retention applies.
  Evidence: Guided review found the original drain could allocate for an arbitrarily long unterminated stderr record. The final drain reads fixed 8 KiB chunks, and a focused test sends more than 2 MiB without a newline while retaining at most the configured tail.

- Observation: A stdout response does not prove that an independent stderr reader thread has consumed preceding timing writes, even when the child wrote stderr first.
  Evidence: Guided review identified that cursor-only snapshots could omit or shift timing lines. The benchmark now brackets iterations with a private MCP boundary request; the server writes and flushes a sentinel on stderr before replying, and the parent waits until the drain observes that sentinel.

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

- Decision: Make disabled `profiling::Scope` values hold no label and no start timestamp.
  Rationale: The new hot-path scopes should not allocate strings or call the clock when `BIFROST_TIMING` is absent. This also reduces overhead for all existing disabled scopes while preserving the environment-variable behavior.
  Date/Author: 2026-07-13 / Codex

- Decision: Synchronize trace capture with an internal MCP profile-boundary request instead of sleeping or polling for quiet stderr.
  Rationale: The boundary creates an explicit happens-before relationship on the child's stderr stream and remains deterministic under scheduler and pipe latency. A timeout and stream-closure state prevent the synchronization wait from hanging indefinitely.
  Date/Author: 2026-07-13 / Codex

- Decision: Put traces in a unique directory per profiled invocation and hash the raw repository name into the sanitized filename.
  Rationale: Reports from reused output directories must not point at traces overwritten by later runs, and distinct manifest names that sanitize identically must remain distinct. Normal non-profile report filenames and JSON remain unchanged.
  Date/Author: 2026-07-13 / Codex

## Outcomes & Retrospective

The implementation, guided review, and validation milestones are complete. Every MCP child now has its standard error consumed from the moment it is spawned in fixed-size chunks, so neither a full pipe nor an unterminated record can defeat the memory bound. Opted-in runs enable child timing and preserve one synchronized, metadata-rich trace per warmup or measured iteration in a unique run directory under the uploaded output directory, while ordinary report JSON and filenames remain unchanged. Traces expose every requested definition-path boundary and count, and disabled scopes avoid both label allocation and clock reads.

The focused and full benchmark suites pass, Clippy is clean across all targets and features, and all 734 active feature-enabled library tests pass. The only unavailable gate is linking standalone macOS test binaries with the existing PyO3 `extension-module` feature; this is independent of the benchmark changes and reproduces for the focused integration target itself. No dependencies were added, three specialist re-reviews approve the final fixes, no reports change without explicit profiling, and the implementation is ready to publish from the current branch.

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
    cargo test --lib benchmark::mcp_session

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

Plan revision note (2026-07-13 10:07Z): Recorded completion and focused-test evidence for the safe drain milestone, plus the discovery that unit-test filters require `--lib` here to avoid linking all integration targets.

Plan revision note (2026-07-13 10:20Z): Recorded the completed profile artifact milestone and real-child evidence for trace association and disabled-report compatibility.

Plan revision note (2026-07-13 10:26Z): Recorded completion of the get-definition instrumentation milestone and the decision to eliminate disabled-scope allocation and clock work.

Plan revision note (2026-07-13 10:43Z): Recorded final validation evidence, including the clean explicit-toolchain Clippy run, the passing 729-test feature-enabled library suite, and the pre-existing macOS PyO3 standalone-test linker limitation.

Plan revision note (2026-07-13 11:06Z): Recorded guided-review findings, the synchronized fixed-size drain and artifact-identity follow-up, post-fix specialist approvals, and final validation evidence.
