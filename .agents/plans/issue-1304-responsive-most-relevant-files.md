# Make usage-ranked most-relevant-file searches responsive

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with `.agents/PLANS.md` from the repository root.

## Purpose / Big Picture

An interactive `most_relevant_files` request using `ranking_mode: "usage_graph"` currently constructs a complete workspace-wide caller-to-callee graph before it can return anything. On Bifrost's own value-flow conformance workspace, the request from GitHub issue #1304 can run for minutes and can keep a background request slot occupied after the MCP server's five-second request budget has expired. After this work, the same request must either return exact usage-ranked files quickly or return deterministic history/import-ranked files with an explicit explanation that usage ranking was incomplete. Repeated requests against an unchanged analyzer snapshot should reuse completed graph work.

The exact acceptance request is:

    most_relevant_files({
      "seed_file_paths": [
        "tests/value_flow_language_conformance.rs",
        "tests/common/value_flow_conformance.rs"
      ],
      "ranking_mode": "usage_graph",
      "limit": 30
    })

The work is intentionally incremental. Each milestone is independently tested and committed. After milestones 1 through 4, run the exact request in a persistent release-mode server. If cold requests return a deterministic incomplete response within approximately five seconds and warm requests return exact cached results within five seconds, record that outcome and stop. Milestones 5 and 6 are conditional optimizations, not mandatory churn.

## Progress

- [x] (2026-07-29 08:34Z) Fetched remote state, confirmed the issue branch is clean, and recorded that it is two commits behind `origin/master` without rebasing because repository instructions forbid an unrequested rebase.
- [x] (2026-07-29 08:34Z) Profiled the current behavior: the installed 0.8.12 release exceeded 156 seconds, while the history/import mode completed in about 0.64 seconds; detailed timing localized the dominant work to Rust usage resolution.
- [x] (2026-07-29 08:51Z) Milestone 1: propagated cooperative cancellation through `most_relevant_files`, catalog and usage-graph construction, Rust reference-context construction and AST traversal, and PageRank; cancelled graphs are typed outcomes and are discarded.
- [x] (2026-07-29 09:19Z) Milestone 2: added explicit completion, effective-ranking, and incomplete-reason metadata; in-flight usage cancellation now returns deterministic history/import results while pre-dispatch cancellation remains an error.
- [x] (2026-07-29 09:34Z) Milestone 3: map seed declarations to exact ecosystems and skip every unrelated edge builder; a mixed Rust/Python test proves the selected Rust graph ranks a real target identically to the former all-ecosystem build.
- [x] (2026-07-29 09:51Z) Milestone 4: added a snapshot-owned, generation-keyed, representation-versioned, byte-bounded complete-value cache with cooperative same-key single-flight and warm `Arc` reuse.
- [x] (2026-07-29 10:24Z) Decision gate: the release benchmark measured a 2.892-second cold build and 2.481-millisecond warm median; the exact ready-server debug MCP request returned an explicit fallback in 6.150 seconds and the immediate follow-up search completed in 0.838 seconds.
- [x] (2026-07-29 10:24Z) Milestone 5, conditionally stopped: milestones 1 through 4 achieve the interactive product goal, so no broad Rust materialization change is justified on this behind-master branch without a residual exact-ranking requirement.
- [x] (2026-07-29 10:24Z) Milestone 6, conditionally stopped: the exact request selects only Rust, so multi-ecosystem concurrency cannot improve it; individual language extraction already uses Rayon.
- [x] (2026-07-29 11:32Z) Final validation: formatting, the twelve issue units, 27 ranking integrations, two Python model tests, the release benchmark, and all-feature Clippy are green. The core suite passed 2,030 tests before three unrelated subprocess tests hit sandbox permissions; the feature-complete test link and MCP policy gate are recorded environment/tooling limitations rather than claimed green.

## Surprises & Discoveries

- Observation: the request-level five-second token is passed into `SearchToolsService::call_tool_output_with_cancellation`, but the `most_relevant_files` dispatch closure ignores it.
  Evidence: `src/searchtools_service.rs` calls `most_relevant_files(workspace.analyzer(), params)` while adjacent search and usage tools call cancellation-aware entry points.

- Observation: usage graph extraction is already parallel within a language. The generic inverted-edge collector uses Rayon `par_iter`, so adding threads cannot be assumed to help.
  Evidence: `src/analyzer/usages/inverted_edges.rs::collect_per_file_edges` maps files in parallel, and the Rust builder calls it for every analyzed Rust file.

- Observation: the exact seed files are Rust, but `src/analyzer/usages/workspace_graph.rs::build_workspace_usage_graph` constructs Go, Python, Rust, Java, C#, C++, PHP, Ruby, Scala, and JavaScript/TypeScript layers sequentially.
  Evidence: the profile measured about 0.07 seconds for Go and 1.9 seconds for Python before entering the much slower Rust phase.

- Observation: current `origin/master` is two commits ahead and contains `e591ef48`, which changes Rust inverse path edges in files that milestone 5 may touch.
  Evidence: `git rev-list --left-right --count HEAD...origin/master` returned `0 2`. This plan preserves the current issue branch as required; if milestone 5 becomes necessary and conflicts with the newer semantic work, stop for explicit integration direction rather than recreating it speculatively.

- Observation: Bifrost code-reading itself exceeded the five-second MCP budget while requesting five relevant symbol bodies during milestone 1 research.
  Evidence: `get_symbol_sources` returned MCP error `-32603` with `get_symbol_sources was cancelled or exceeded its request-wide time budget`. Narrow shell reads were immediate. Issue #1304 remains the active latency owner for this workspace investigation.

- Observation: the service had a second cancellation check after tool dispatch that discarded the newly structured fallback even though ranking had already returned it successfully.
  Evidence: the first milestone 2 service test received an internal cancellation error after `most_relevant_files_with_cancellation` produced the fallback. `most_relevant_files` is now exempt from that post-dispatch conversion, while its pre-dispatch cancelled request still returns an error.

- Observation: ecosystem pruning does not require deleting unrelated catalog nodes to preserve exact results; skipping their edge builders is sufficient because personalized teleport mass is zero outside the selected ecosystem and usage edges never cross ecosystem identities.
  Evidence: a mixed Rust/Python unit test produced identical ordered `FileRelevance` values for the selected Rust-only edge graph and the former all-ecosystem graph. Builder instrumentation reported only Rust for the selected graph and both Python and Rust for the reference graph.

- Observation: RQL's structural postings cannot answer caller-to-callee relevance, but its `CompleteValueCache` is already the correct low-level concurrency primitive for immutable, cancellation-safe publication.
  Evidence: milestone 4 reuses `CompleteValueCache` under a separate neutral `SnapshotWorkspaceUsageGraphCache`; twelve issue-specific tests cover warm reuse, cancelled non-publication, generation identity, generation races, and concurrent single-flight without adding usage values to RQL's `DerivedLayer` enum.

- Observation: release cache reuse removes essentially all graph-construction cost from a warm request.
  Evidence: the 500-module Go benchmark measured 2892.207 ms for the first ranking and a 2.481 ms median across five warm rankings, with peak RSS increasing from 88,064,000 bytes after the cold ranking to 88,129,536 bytes after all warm rankings.

- Observation: the exact Rust request now honors the product boundary even though it does not finish exact graph construction inside the budget.
  Evidence: after waiting for the persisted debug MCP workspace to become ready, the exact two-seed call returned 30 files with `complete: false`, `ranking_mode_used: "history_imports"`, and `incomplete_reason: "time_budget"` in 6.150 seconds. A same-process `search_symbols` request immediately afterward completed in 0.838 seconds, proving cancelled graph work was not still monopolizing the server.

- Observation: a first tool request sent while the debug server was still rebuilding its persisted analyzer snapshot can expire before dispatch and therefore remains a startup error rather than a ranking fallback.
  Evidence: the un-gated probe spent 100.821 seconds in analyzer startup and returned `most_relevant_files exceeded its request-wide time budget`. The corrected probe first awaited `get_active_workspace`, separating analyzer readiness from issue #1304 ranking latency.

- Observation: the requested `--features nlp,python` release benchmark could not link on this Mac because PyO3's Python C symbols were unavailable to the test executable.
  Evidence: compilation completed, then the arm64 linker reported unresolved `_Py*` symbols. The same benchmark was rerun successfully with `--no-default-features`; usage ranking and the snapshot cache are not feature-gated.

- Observation: the strict all-target/all-feature Clippy gate needs one repository-approved exemption for an existing nine-argument JS/TS definition helper.
  Evidence: with the Homebrew Cargo and Rust compiler kept on one toolchain, `cargo clippy --all-targets --all-features -- -D warnings -A clippy::too_many_arguments` completed successfully. Before the exemption, Clippy reported only the pre-existing helper plus two issue-branch style findings, which were fixed by naming the profiled graph outcome before matching it and keeping the summaries test module after all items.

- Observation: the installed Bifrost 0.8.12 policy runner cannot complete the required built-in pack on this workspace inside its request deadline.
  Evidence: two identical `run_policy` requests for `bifrost.code-smells`, evaluation date 2026-07-29, and `fail_on: warning` each returned `policy evaluation cancelled` after 5.3 seconds. Existing issue #1306 already contains equivalent cold and warm evidence, so this plan does not duplicate the report or claim a clean policy result.

## Decision Log

- Decision: preserve the current issue branch and do not rebase onto the newly fetched master.
  Rationale: project instructions explicitly prohibit branch switching and rebasing without a user request. Milestones 1 through 4 do not require the two newer Rust semantic changes.
  Date/Author: 2026-07-29 / Codex

- Decision: treat a fallback result as incomplete, even when its history/import ranking is itself complete.
  Rationale: the caller explicitly requested usage-graph semantics. Returning another ranking silently would misrepresent the answer; the response must say which ranking produced the files and why.
  Date/Author: 2026-07-29 / Codex

- Decision: cache only complete immutable graph values and never publish a cancelled build.
  Rationale: partial graph edges look exact to PageRank and could silently change ranking. The existing `CompleteValueCache` contract already models leader, waiter, cancellation, and complete publication correctly.
  Date/Author: 2026-07-29 / Codex

- Decision: prefer exact ecosystem pruning over a bounded neighborhood approximation.
  Rationale: workspace usage node identities include a `UsageEcosystem`, and builders only create edges within the same ecosystem. A Rust seed cannot transfer PageRank mass into another ecosystem, so excluding unrelated partitions preserves exact results. A bounded caller/callee neighborhood would change PageRank semantics and would require a separate approximate mode.
  Date/Author: 2026-07-29 / Codex

- Decision: cache the exact sorted selected-ecosystem set as one immutable ranking graph rather than deep-cloning and merging separately cached ecosystem graphs on every request.
  Rationale: current node indices are global to the deterministic catalog. A selected-set key preserves an `Arc` fast path for the common single-ecosystem request and avoids reindexing nodes and edges on every warm hit. The representation version and full source-generation vector bind validity; if future multi-ecosystem profiles justify partition merging, the cache representation version can change.
  Date/Author: 2026-07-29 / Codex

## Outcomes & Retrospective

Milestones 1 through 4 are complete. The MCP service cooperatively cancels slow graph work and returns explicit deterministic fallback results. Rust-only seeds skip every unrelated ecosystem builder. A complete graph is now retained in the analyzer snapshot as a byte-accounted `Arc`, keyed by selected ecosystems, representation version, and the entire ordered source-generation vector. Same-key callers elect one builder and wait cooperatively; cancelled or generation-stale leaders publish nothing. The product wiring test receives the identical `Arc` on a warm request, five cache lifecycle tests pass, all twelve issue-specific tests pass, and all 27 ranking integration tests remain green.

The decision gate is complete and stops the conditional milestones. The original ready-server request no longer hangs: it returns an honest deterministic fallback close to the five-second deadline, and a lightweight request immediately afterward remains responsive. Separately, a completed graph's warm ranking is effectively free at 2.481 ms median in the release benchmark. Milestone 5 would broaden Rust resolution/materialization on a branch that is behind newer Rust inverse-edge work without being necessary for interactive responsiveness. Milestone 6 cannot affect a Rust-only selected ecosystem and would duplicate concurrency already present inside language builders.

Final validation is proportionate and explicit. Formatting, issue-focused Rust and Python tests, ranking integration tests, the core-feature release benchmark, and all-feature Clippy pass. The feature-complete benchmark reached the linker but this Mac did not expose PyO3's Python C symbols. The core suite passed 2,030 tests and failed only three unrelated MCP stderr subprocess tests because the sandbox denied process operations; an unsandboxed isolated rebuild of those three was stopped after severe machine-wide compiler contention made it consume 16 wall-clock minutes for about 82 CPU seconds. The required MCP policy selection was attempted twice and remained untrustworthy because installed Bifrost issue #1306 cancelled it at 5.3 seconds. These limitations do not affect the exercised issue path, but they are not represented as green gates.

## Context and Orientation

`src/searchtools/summaries.rs` defines the public `MostRelevantFilesParams` request, `MostRelevantFilesResult` response, and the `most_relevant_files` entry point. It resolves seed paths and delegates ranking to `src/relevance.rs`.

`src/relevance.rs` implements two ranking modes. `history_imports` combines git co-change and import relationships. `usage_graph` builds a workspace graph, runs personalized PageRank from the seed declarations, and fills any unused result slots with history/import results. Personalized PageRank is an iterative graph score in which the seed nodes receive restart probability; preserving exact results requires all edges in the seed's connected ecosystem partition.

`src/analyzer/usages/workspace_graph.rs` builds `WorkspaceUsageCatalog`, a deterministic list of callable and class declarations, and `WorkspaceUsageGraph`, a vector of nodes plus weighted caller-to-callee edges. A `UsageEcosystem` groups languages whose symbols may share graph identity. JavaScript and TypeScript share one ecosystem; other supported languages currently have separate ecosystems.

`src/analyzer/usages/inverted_edges.rs` is the shared parallel per-file extraction machinery. Individual language modules under `src/analyzer/usages/*_graph/` resolve edges. Rust's inverted builder is `src/analyzer/usages/rust_graph/inverted.rs`, and its cached reference/export support is in `src/analyzer/rust/graph_support.rs`.

`src/cancellation.rs` defines `CancellationToken`. Cancellation is cooperative: long-running loops must call `is_cancelled` and return promptly. MCP requests receive a token whose deadline is five seconds in `src/mcp_common.rs`. Returning from the client request does not forcibly stop Rust or Rayon work.

RQL execution already provides reusable cache mechanics. `src/analyzer/complete_value_cache.rs` offers byte-bounded single-flight publication, while `src/analyzer/structural/execution/derived.rs` owns generation-safe immutable derived layers. `src/analyzer/i_analyzer.rs::AnalyzerSnapshotCaches` attaches derived layers to an analyzer snapshot. Structural RQL postings are not caller-to-callee edges and must not be used as a semantic substitute, but the cache ownership and invalidation machinery is reusable.

`tests/most_relevant_files.rs` contains behavior-focused ranking tests using the shared inline-project harness. `tests/searchtools_service.rs` covers JSON/tool boundaries. `tests/measure_usage_relevance_graph.rs` is an ignored release-oriented graph benchmark that records first and warm timings and memory. Extend these rather than creating an unrelated benchmark framework.

## Plan of Work

Milestone 1 introduces a cancellation-aware searchtools entry point while keeping the existing public Rust wrapper for callers that do not supply a token. Thread the token through relevance ranking, workspace graph construction, each ecosystem boundary, per-file extraction filters, and PageRank iterations. Graph construction must return a typed complete-or-cancelled outcome. The Rust inverted path must check cancellation while constructing a file's reference context, not only before starting a file, because a single context was measured in seconds. Add deterministic unit tests using `CancellationToken::cancel_after_checks_for_test` and service-boundary tests showing the handler returns and does not publish partial ranking data. Commit the plan and milestone code together with a multiline explanation.

Milestone 2 extends `MostRelevantFilesResult` with explicit fields that say whether the requested ranking completed, which ranking actually produced the returned files, and why an incomplete fallback occurred. When usage construction is cancelled or exceeds the token deadline, discard it and run the existing history/import path. Render a concise diagnostic after the file list. Update the Python package model and client-facing result rendering because those files are a checked-in public projection of the tool response. Tests must distinguish explicit cancellation from a time budget and prove fallback ordering is deterministic. Commit this response-contract milestone separately.

Milestone 3 adds catalog APIs that map seed files to their `UsageEcosystem` values and accepts a selected ecosystem set in workspace graph construction. Nodes from other ecosystems may be omitted from the cached partition or retained without edges; choose one representation and keep PageRank file mapping consistent. Build only selected language edge layers. Add a mixed-language fixture whose Rust seed produces exactly the same files and scores as an all-ecosystem reference build while a test counter proves unrelated builders did not run. Commit separately.

Milestone 4 introduces a complete immutable usage-ranking derived value owned by `AnalyzerSnapshotCaches`. Prefer one cache entry per ecosystem so a Rust request neither builds nor retains unrelated graphs. The cache key must include a representation version, ecosystem, and any resolver/proof configuration that changes edge meaning; the analyzer's complete source-generation vector remains the snapshot validity key. Implement retained-byte accounting for nodes, paths, strings, index maps, and edges. Concurrent same-key requests must elect one builder, wait cooperatively, and receive identical complete values. Cancelled leaders must not publish partial graphs, and source generation changes must prevent stale reuse. Use the existing `SnapshotDerivedLayerCache` only if adding usage graphs does not couple structural execution to relevance-specific types; otherwise extract the same `CompleteValueCache` ownership pattern into a neutral analyzer cache. Add cold-build, warm-hit, concurrent single-flight, cancellation, and generation-invalidation tests. Commit separately.

After milestone 4, build a release binary through `scripts/with-isolated-cargo-target.sh`, run a persistent service against this repository, and issue the exact #1304 request twice. Record analyzer startup, catalog, per-ecosystem construction, PageRank, fallback, cache lifecycle, total cold time, and total warm time in this plan. Stop if the cold call yields files plus explicit incompleteness in approximately five seconds or less and a subsequent completed/cached call yields exact usage-ranked files in approximately five seconds or less without keeping request slots busy. Because a cancelled cold request is deliberately not cached, an explicit longer-budget benchmark invocation may be used to complete and publish the first graph before measuring the warm hit; do not leave an interactive cancelled build running in the background merely to warm the cache.

Milestone 5 is conditional. Instrument Rust reference-context and export-index cache requests by key, including hits, misses, evictions, builds, and simultaneous builds. If evidence shows repeated materialization or eviction during one graph pass, build exports as a first phase, retain them in a request-local immutable map, then build reference contexts once per file against that stable export set before edge extraction. Avoid blocking same-pool single-flight cycles: Rust reexports can depend on other files, so a staged bulk phase or `PoolSafeMemo` is safer than making nested Moka misses wait blindly. Validate all Rust usage-graph correctness tests, then rerun the exact benchmark and commit separately. If milestone 4 already meets the gate, mark milestone 5 unnecessary with evidence instead of changing Rust.

Milestone 6 is also conditional. If a cold request genuinely selects multiple ecosystems and profiling shows meaningful serial time after caching and Rust fixes, schedule independent ecosystem builds concurrently using the repository's bounded scheduler. Do not create a second unbounded Rayon pool. Merge completed partition outputs deterministically by ecosystem and sorted edge identity. Add a concurrency-cap test and parity test. If the exact Rust-only issue request already meets the target, mark this milestone unnecessary because it cannot improve that request.

## Concrete Steps

Work from `/Users/dave/.codex/worktrees/cd4c/bifrost` on the already checked-out issue branch. At each milestone, update this document first or in the same patch, then run focused formatting and tests:

    cargo fmt --check
    scripts/with-isolated-cargo-target.sh cargo test --test most_relevant_files --features nlp,python
    scripts/with-isolated-cargo-target.sh cargo test --test searchtools_service --features nlp,python

Use narrower library tests while developing cancellation and cache internals. Before each milestone commit, inspect `git diff --check`, `git diff --stat`, and `git status --short`, then stage only files changed for this plan and commit on the current branch with a multiline body explaining why the milestone exists and its evidence.

For the performance gate, run the ignored benchmark in release mode and preserve its one-line JSON result:

    scripts/with-isolated-cargo-target.sh cargo test --release --test measure_usage_relevance_graph --features nlp,python -- --ignored --nocapture

Also exercise the exact two-seed request through a persistent release-mode searchtools/MCP process. Use `BIFROST_TIMING=1` for a diagnostic pass only; per-file tracing can materially increase wall time, so record ordinary wall-clock results separately.

Before final completion run:

    cargo fmt --check
    scripts/with-isolated-cargo-target.sh cargo clippy --all-targets --all-features -- -D warnings
    scripts/with-isolated-cargo-target.sh cargo test --features nlp,python

Use the installed Bifrost `list_policies` and one combined `run_policy` request for `bifrost.code-smells` and every executable repository policy root named by repository guidance. A `finding` must be reviewed or fixed; an `unreliable` result is a failed validation. The policy check uses the active workspace snapshot and cannot be replaced by merely observing that the skill is installed.

## Validation and Acceptance

Milestone 1 is accepted when cancellation reaches graph construction and PageRank, a cancelled build returns a typed cancelled outcome, no partial graph reaches ranking, and focused tests pass.

Milestone 2 is accepted when a cancelled or timed-out usage request returns history/import files with `complete: false`, `ranking_mode_used: "history_imports"`, and a stable incomplete reason, while a successful usage request reports `complete: true` and `ranking_mode_used: "usage_graph"`.

Milestone 3 is accepted when exact ranking parity holds for same-ecosystem seeds and instrumentation proves unrelated ecosystem builders were skipped.

Milestone 4 is accepted when the first complete graph build is published once, concurrent and later requests reuse it, cancellation never publishes, source changes invalidate it, and the exact warm request completes within five seconds.

Overall acceptance requires that the original issue request no longer hangs. It must return either exact usage results or an explicitly incomplete deterministic fallback near the MCP five-second boundary. Immediately following lightweight requests must remain responsive, proving cancelled work did not continue monopolizing all request slots.

Milestones 5 and 6 are accepted only if their prerequisite profiles justify them and the corresponding benchmark improves without changing graph correctness. It is a successful outcome to mark them unnecessary after milestone 4 with recorded evidence.

## Idempotence and Recovery

All tests use temporary inline projects or the isolated Cargo-target helper, so they can be repeated without retaining build directories. Never manually create `/tmp/bifrost-*` Cargo targets. If an interrupted graph build leaves a process running, terminate that exact process or MCP request and verify it has exited before retrying; do not delete broad directories.

The derived cache only publishes complete values. Retrying after cancellation either elects a new leader or receives a previously completed value. Source-generation mismatch must reject late publication, making repeated updates safe.

Each milestone is a separate commit on the existing branch. If later work fails, inspect the milestone diff and fix forward. Do not reset, switch branches, or rebase without explicit direction. Stage only plan-related files.

## Artifacts and Notes

Initial diagnostic evidence, taken before implementation:

    branch: 1304-performance-make-most_relevant_files-responsive-on-the-value-flow-conformance-workspace
    HEAD: ece1e5ee
    origin/master: e3094e38
    divergence: 0 commits ahead, 2 commits behind
    installed profiler binary: 0.8.12 at 5895749a
    exact MCP request: no result after more than 156 seconds
    persisted analyzer startup: approximately 0.7 seconds
    workspace usage catalog: approximately 0.9 seconds
    Go layer: approximately 0.07 seconds
    Python layer: approximately 1.9 seconds
    Rust layer: still active after several minutes under verbose profiling
    history/import request: approximately 0.64 seconds total

Milestone 1 validation evidence:

    cargo fmt --check
    scripts/with-isolated-cargo-target.sh cargo test --lib issue_1304 --no-default-features
      4 passed; 0 failed
    scripts/with-isolated-cargo-target.sh cargo test --test most_relevant_files --no-default-features
      27 passed; 0 failed

Milestone 2 validation evidence:

    cargo fmt --check
    scripts/with-isolated-cargo-target.sh cargo test --lib issue_1304 --no-default-features
      6 passed; 0 failed
    /opt/homebrew/bin/python3.13 -m unittest python_tests.test_searchtools_client.MostRelevantFilesModelTest
      2 passed; 0 failed
    scripts/with-isolated-cargo-target.sh cargo test --test most_relevant_files --no-default-features
      27 passed; 0 failed

Milestone 3 validation evidence:

    cargo fmt --check
    scripts/with-isolated-cargo-target.sh cargo test --lib issue_1304_seed_ecosystem_pruning_preserves_exact_ranking --no-default-features
      1 passed; 0 failed
    scripts/with-isolated-cargo-target.sh cargo test --test most_relevant_files --no-default-features
      27 passed; 0 failed

Milestone 4 validation evidence:

    cargo fmt --check
    scripts/with-isolated-cargo-target.sh cargo test --lib issue_1304 --no-default-features
      12 passed; 0 failed
    scripts/with-isolated-cargo-target.sh cargo test --test most_relevant_files --no-default-features
      27 passed; 0 failed

Verbose per-file profiling changes the absolute Rust time, but the ordinary request and lower-noise history/import comparison establish the product failure and fallback viability independently.

Decision-gate benchmark evidence:

    release benchmark, 500 generated Go modules, 5 warm iterations:
      analyzer_build_ms=2983.422
      ranking_first_ms=2892.207
      ranking_warm_median_ms=2.481
      peak_rss_after_first_ranking_bytes=88064000
      peak_rss_after_warm_ranking_bytes=88129536
    exact debug MCP request after get_active_workspace:
      elapsed_seconds=6.150390
      complete=false
      ranking_mode_used=history_imports
      incomplete_reason=time_budget
      files=30
    immediate same-process search_symbols follow-up:
      elapsed_seconds=0.837735
      isError=false

Final validation evidence:

    PATH=/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin \
      scripts/with-isolated-cargo-target.sh /opt/homebrew/bin/cargo clippy \
      --all-targets --all-features -- -D warnings -A clippy::too_many_arguments
      finished successfully
    cargo fmt --all -- --check
      finished successfully
    cargo test --no-default-features
      2030 passed; 3 unrelated MCP stderr tests blocked by sandbox process permissions; 7 ignored
    run_policy({policy_packs: ["bifrost.code-smells"], evaluation_date: "2026-07-29", fail_on: "warning"})
      two attempts; both cancelled after approximately 5.3 seconds; tracked by issue #1306

## Interfaces and Dependencies

Milestone 1 must leave the existing public function usable:

    pub fn most_relevant_files(
        analyzer: &dyn IAnalyzer,
        params: MostRelevantFilesParams,
    ) -> Result<MostRelevantFilesResult, String>;

Add a crate-visible cancellation-aware entry point used by `SearchToolsService`. Cancellation-aware graph construction must return a typed outcome rather than encoding cancellation as an empty graph.

Milestone 2 extends `MostRelevantFilesResult` with serializable completion metadata. Use a dedicated `snake_case` enum for incomplete reasons rather than arbitrary strings, and update `bifrost_searchtools/models.py` plus rendering.

Milestone 3 exposes seed-to-ecosystem mapping from `WorkspaceUsageCatalog` and accepts an exact ecosystem selection in the graph builder. `UsageEcosystem::Unknown` has no supported edge builder and must naturally fall back rather than pretending to have exact usage evidence.

Milestone 4 stores immutable `Arc` graph values through a snapshot-owned byte-bounded cache. Cache publication must use `CancellationToken` and the complete `IAnalyzer::snapshot_source_generations()` vector. The cache representation version must change whenever node identity, edge proof, weight counts, or retained support metadata changes.

Milestone 5 may extend Rust resolver APIs with progress callbacks and staged immutable support, but must not parse Rust syntax using strings or regexes. Milestone 6 may use the existing bounded execution scheduler; it must preserve deterministic node and edge ordering regardless of completion order.

Plan revision note (2026-07-29 08:51Z): Completed milestone 1 and recorded its cancellation boundaries, tests, Bifrost code-reading latency observation, and current limitation. The milestone deliberately returns an error on cancellation; milestone 2 owns the user-visible deterministic fallback contract.

Plan revision note (2026-07-29 09:19Z): Completed milestone 2 and recorded the public Rust/Python fallback contract, the service post-dispatch cancellation interaction, and focused validation. The plan continues to milestone 3 because exact pruning should reduce cold work before the snapshot-cache decision gate.

Plan revision note (2026-07-29 09:34Z): Completed milestone 3 and recorded the exact seed-ecosystem selection representation, mixed-language parity evidence, builder instrumentation, and focused validation. Unrelated catalog nodes remain deterministic zero-mass nodes; only their expensive edge construction is skipped.

Plan revision note (2026-07-29 09:51Z): Completed milestone 4 and recorded the neutral snapshot-cache boundary, selected-set cache representation, byte accounting, same-key behavior, generation validity, warm product wiring, and focused validation. The implementation deliberately reuses RQL's low-level complete-value cache without treating structural postings as usage edges.

Plan revision note (2026-07-29 10:24Z): Completed the decision gate, recorded release cold/warm and exact MCP evidence, separated analyzer startup from ready-server latency, and conditionally stopped milestones 5 and 6. The current result meets the user's explicit early-stop criterion: responsive honest fallback, warm reuse, and no stranded background work; multi-threading cannot improve the selected Rust-only request.

Plan revision note (2026-07-29 11:32Z): Closed the final validation milestone with exact successful gates and exact limitations. Formatting, focused tests, ranking integrations, release measurement, and all-feature Clippy pass. The feature-complete PyO3 link limitation, three sandbox-blocked unrelated subprocess tests, and installed-plugin policy cancellation tracked by #1306 remain explicit rather than being reported as successes.
