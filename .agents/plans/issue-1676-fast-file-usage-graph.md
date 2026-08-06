# Use a fast file graph for usage-based relevance

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with `.agents/PLANS.md`.

## Purpose / Big Picture

After this change, `most_relevant_files` will use a coarse file-level graph when a caller selects `ranking_mode: "usage_graph"`. A cold request will not build the exact class-and-function usage graph. It will build structured file dependency edges from Bifrost's batched import facts and run personalized PageRank directly on file nodes. Callers that need the old exact ranking can select `ranking_mode: "usage_graph_exact"`. The public `usage_graph` tool will remain exact and unchanged.

The result is observable with the `most_relevant_files` MCP tool and the `most_relevant_files` helper binary. On the Bifrost workspace, a cold `usage_graph` request should complete within five seconds. A repeated request on the same analyzer generation should complete within 100 milliseconds. Focused tests will prove that the default usage mode follows file edges, that exact mode still uses declaration-level weights, and that cancellation never returns or caches a partial graph.

## Progress

- [x] (2026-08-05T19:53:45Z) Inspected the issue branch, fetched `origin`, checked upstream overlap, and mapped the exact graph, PageRank, cache, and import-analysis seams.
- [x] (2026-08-05T19:53:45Z) Selected an explicit `usage_graph_exact` ranking mode instead of a Boolean `fast` flag.
- [x] (2026-08-05T20:45:00Z) Added the coarse file graph, dense ranking representation, graph-kind cache identity, and focused Java and Rust tests.
- [x] (2026-08-05T20:45:00Z) Routed `usage_graph` to the coarse graph and retained the old path as `usage_graph_exact` across Rust, MCP, CLI, and Python surfaces.
- [x] (2026-08-05T20:45:00Z) Measured and optimized the Bifrost request. The real MCP replay took 406 ms cold and 25 ms warm.
- [x] (2026-08-05T21:11:57Z) Ran formatting, focused Rust and Python tests, workspace Clippy, the repository policy pack, and the featureless workspace test gate. Two unrelated tutorial gold tests remain broken on the branch.

## Surprises & Discoveries

- Observation: `history_imports` already runs personalized PageRank over a two-hop import graph, but git results take priority.
  Evidence: `crates/bifrost-analysis/src/relevance.rs::most_relevant_project_files_with_half_life` appends `related_files_by_imports` after git ranking.

- Observation: the analyzer already exposes one batched import read across all language delegates.
  Evidence: `MultiAnalyzer::import_infos_for_files` groups files by language and uses each provider's bulk reader when available.

- Observation: a shared helper already resolves direct imported files without losing files that declare no symbols.
  Evidence: `crates/bifrost-analysis/src/analyzer/capabilities.rs::resolve_imported_files_from_infos` prefers file-level resolution and otherwise projects resolved declarations to their source files.

- Observation: the current exact cache is single-flight and generation-safe.
  Evidence: `SnapshotWorkspaceUsageGraphCache` uses `CompleteValueCache` and rejects cancelled or stale builds.

- Observation: the branch is 16 commits behind `origin/master`, but upstream does not change the relevance, workspace graph, cache, or public ranking files.
  Evidence: `git diff --stat HEAD..origin/master` showed only a receiver-query file split inside the wider usages directory.

- Observation: projecting Rust imports through exact declaration lookup still exceeded the five-second MCP budget.
  Evidence: phase timing stopped inside `file_usage_graph.resolve_relations` after files took 155 ms and import facts took 222 ms.

- Observation: the full Rust Cargo route index is also too heavy for this coarse graph because it prepares syntax for the workspace.
  Evidence: the first coarse Rust resolver still exceeded five seconds when it called `RustAnalyzer::cargo_routes`.

- Observation: a manifest-name index gives the cross-crate identity needed by the coarse graph without Cargo route or declaration construction.
  Evidence: the Bifrost graph phase fell to 278 ms. The full MCP request took 406 ms cold and 25 ms warm.

- Observation: the installed Homebrew Clippy driver is not compatible with the active Rustup compiler, even though both report Rust 1.96.0.
  Evidence: the default command failed with E0514. Putting the Rustup toolchain first in `PATH` made workspace Clippy pass.

- Observation: the full featureless gate has two pre-existing tutorial gold failures on this branch.
  Evidence: `code_query_tutorials::java_tutorial` and `code_query_tutorials::receiver_traversal_tutorial` expect output without current receiver site identities. This change does not modify tutorial, receiver-query, or documentation files. The other 396 cross-language tests passed.

## Decision Log

- Decision: keep `usage_graph` as the fast user-facing value and add `usage_graph_exact` for the old behavior.
  Rationale: the user asked for the PageRank usage graph to use the fast graph by default. An enum names semantics more clearly than a mode-type Boolean flag.
  Date/Author: 2026-08-05 / Codex

- Decision: define the first coarse graph from structured direct file imports.
  Rationale: imports give a complete, low-cost file relation across supported languages. The analyzer already batches and caches these facts. This avoids regular expressions, token-tree recovery, receiver inference, and exact symbol authorization.
  Date/Author: 2026-08-05 / Codex

- Decision: give each direct file edge one `other` reference count in the first implementation.
  Rationale: import facts do not prove calls, member access, or type use. Marking them as another kind would claim evidence that the coarse graph does not have.
  Date/Author: 2026-08-05 / Codex

- Decision: reuse the generation-safe usage-graph cache with a graph-kind discriminator.
  Rationale: fast and exact graphs must not collide, and concurrent requests must share one build. The current complete-value cache already provides the required behavior.
  Date/Author: 2026-08-05 / Codex

- Decision: resolve Rust file imports with structured path segments, path-derived package names, and crate names from nearby Cargo manifests.
  Rationale: this data identifies coarse module files without exact declarations, syntax-wide Cargo route construction, file scans, or text parsing of Rust source.
  Date/Author: 2026-08-05 / Codex

## Outcomes & Retrospective

The implementation and validation are complete. The real issue #1504 MCP replay now completes in 406 ms on the first graph build and 25 ms on a cache hit. The measured cold graph work is 278 ms, PageRank is 3 ms, and file aggregation is 3 ms. The exact ranking remains available as `usage_graph_exact`, and the public `usage_graph` tool remains unchanged.

Formatting, focused Rust tests, the Python client test, and workspace Clippy pass. The combined `bifrost.code-smells` policy run completed all 12 policies without an unreliable result. It reports 282 existing repository findings and no findings in the new fast graph code. The policy scan found two unnecessary sorts in the new Rust import resolver. Their removal preserved deterministic order and passed the focused tests and Clippy.

The full featureless workspace test progressed through all changed components. It stopped in the unrelated tutorial gold suite with two failures and 396 passes. A temporary-storage suite first failed because the validation `PATH` omitted `/usr/sbin/lsof`; all 304 active tests passed after the path correction.

## Context and Orientation

`crates/bifrost-analysis/src/relevance.rs` owns `MostRelevantFilesRankingMode`, builds or acquires ranking graphs, runs personalized PageRank, aggregates scores, and fills missing results from history and imports. The current `UsageGraph` branch calls the exact graph builder.

`crates/bifrost-analysis/src/analyzer/usages/workspace_graph.rs` defines the exact declaration catalog and graph. Nodes represent classes or callables. Per-language inverted resolvers produce exact weighted edges. `WorkspaceUsageRankingGraph` adds a map from each file to its declaration node IDs.

`crates/bifrost-analysis/src/analyzer/usages/workspace_graph_cache.rs` caches one complete ranking graph per analyzer source generation and ecosystem selection. A source generation changes after an analyzer update. The cache is single-flight, which means one caller builds a missing value while concurrent callers wait for it.

`crates/bifrost-analysis/src/analyzer/capabilities.rs` defines `ImportAnalysisProvider`. Its `import_infos_for_files` method reads import facts in bulk. `resolve_imported_files_from_infos` maps those facts to direct project files. `MultiAnalyzer` routes both operations to the correct language analyzer.

`crates/bifrost-analysis/src/searchtools/summaries.rs`, `crates/bifrost-mcp`, `src/bin/most_relevant_files.rs`, `bifrost_searchtools/client.py`, and `bifrost_searchtools/models.py` carry the public ranking-mode values. The result payload already reports `ranking_mode_used`.

A coarse file graph has one node per analyzed source file in the selected ecosystem. An edge from file A to file B means A directly imports B through structured analyzer facts. A personalized PageRank starts probability mass at the seed files and follows these directed edges. An exact usage graph has declaration nodes and resolved reference edges. It remains available through `usage_graph_exact` and the public `usage_graph` tool.

## Plan of Work

First add file-graph types and construction in a focused module under `crates/bifrost-analysis/src/analyzer/usages/`. The builder will collect analyzed files in selected ecosystems, sort and deduplicate them, bulk-read import facts through the analyzer's `ImportAnalysisProvider`, resolve direct target files with `resolve_imported_files_from_infos`, and aggregate duplicate file pairs. It will check cancellation during each phase. It will omit self-edges and targets outside the selected ecosystem set. The resulting graph will use dense file IDs and compact `UsageReferenceCounts` with one `other` count per direct relation.

Then generalize the ranking cache key with a graph-kind enum. The two values will be coarse file and exact symbol. Preserve the current generation and ecosystem fields. Adapt the cached value to a ranking graph representation that can expose file nodes and weighted outgoing edges without making exact graph APIs depend on the coarse representation.

Next route `MostRelevantFilesRankingMode::UsageGraph` to the file builder. Add `MostRelevantFilesRankingMode::UsageGraphExact` and route it to the old declaration builder. Both modes will use the current PageRank kernel and history/import fill. Update MCP schemas, helper parsing, Python types, tests, and user-facing descriptions. Do not add a Boolean flag.

Finally run the exact Bifrost replay from issue #1504 through both modes. Record graph construction, PageRank, aggregation, cache state, and total wall time. If the coarse graph exceeds five seconds, profile the import phases and correct the measured bottleneck. Do not weaken the relation with text scanning. Run the required policy selection after source changes.

## Concrete Steps

Work from `/Users/dave/.codex/worktrees/0cb9/bifrost` on the existing issue branch.

After the graph milestone, run:

    cargo fmt --all -- --check
    BIFROST_SEMANTIC_INDEX=off cargo test file_usage_graph --lib
    BIFROST_SEMANTIC_INDEX=off cargo test relevance::tests --lib

After public routing, run:

    BIFROST_SEMANTIC_INDEX=off cargo test --test most_relevant_files
    BIFROST_SEMANTIC_INDEX=off cargo test most_relevant_files_schema --workspace
    uv run --python 3.12 -- python -m unittest python_tests.test_searchtools_client

Measure the two modes with the helper binary. Build the binary once and exclude compilation from request timing:

    BIFROST_SEMANTIC_INDEX=off cargo build --bin most_relevant_files
    BIFROST_SEMANTIC_INDEX=off BIFROST_TIMING=1 target/debug/most_relevant_files --root . --ranking-mode usage_graph crates/bifrost-analysis/src/analyzer/structural/search/witness_projection.rs crates/bifrost-analysis/src/analyzer/policy/taint_policy.rs tests/suite_bench_policy/taint_policy_adapter.rs
    BIFROST_SEMANTIC_INDEX=off BIFROST_TIMING=1 target/debug/most_relevant_files --root . --ranking-mode usage_graph_exact crates/bifrost-analysis/src/analyzer/structural/search/witness_projection.rs crates/bifrost-analysis/src/analyzer/policy/taint_policy.rs tests/suite_bench_policy/taint_policy_adapter.rs

Before completion, run:

    cargo fmt --all -- --check
    cargo clippy --workspace --all-targets -- -D warnings
    BIFROST_SEMANTIC_INDEX=off cargo test --workspace

Do not enable `nlp` for this non-NLP change. If an isolated Cargo target is necessary, use `scripts/with-isolated-cargo-target.sh`.

## Validation and Acceptance

The `usage_graph` mode must use only the coarse file graph. A test analyzer whose exact graph would choose a different file must prove the routing. The `usage_graph_exact` mode must preserve the previous exact ordering on existing fixtures. Omitting `ranking_mode` must still select `history_imports`.

File-graph tests must prove direct edge direction, duplicate aggregation, deterministic node order, self-edge removal, selected-ecosystem filtering, cancellation, and imports whose target has no declaration. The test setup should use the existing small analyzer harnesses rather than hand-written temporary projects when practical.

The MCP schema, Rust JSON, helper CLI, and Python client must accept exactly `history_imports`, `usage_graph`, and `usage_graph_exact`. The public `usage_graph` tool and its models must not change.

A cold Bifrost `usage_graph` ranking should complete within five seconds. A second call on the same analyzer generation should complete within 100 milliseconds. Cancellation must not cache or return a partial graph. Concurrent cache tests must prove that one fast graph build runs.

Formatting, focused tests, workspace Clippy, the applicable featureless tests, and the combined repository policy selection must pass. A policy result with findings requires review and correction. An unreliable policy result fails validation.

## Idempotence and Recovery

All builders are read-only and generation keyed. Re-running a request can only reuse or replace a complete cached graph. A cancelled or stale build is never inserted. If a public-surface test fails after adding the enum value, update every schema and client list together. Do not accept aliases that hide a missing surface update.

The branch is behind `origin/master`. Repository rules prohibit rebasing without an explicit instruction. Keep changes on the current branch. Before a later push, compare overlap again and ask for rebase authority if needed.

## Artifacts and Notes

Current Bifrost measurements at `1ee1da9642e489a4bdad209336845d1d67b5f1ac` are 68.934 seconds for a cold exact graph, 121.950 seconds after one source edit, 37 to 42 milliseconds warm, and 3.939 seconds for `history_imports`. PR #182 measured the original lighter Rust graph at 0.6 seconds on 323 Tauri files. PR #1534 reduced current exact Rust construction to about 71.7 seconds but left lexical and macro resolution as the long tail.

The branch tracks `origin/1676-most_relevant_files-usage-graph-ranking-takes-over-one-minute` and is 16 commits behind `origin/master`. The upstream commits only split RQL and receiver-query modules for the files relevant to this plan.

## Interfaces and Dependencies

Extend the public enum in `crates/bifrost-analysis/src/relevance.rs`:

    pub enum MostRelevantFilesRankingMode {
        HistoryImports,
        UsageGraph,
        UsageGraphExact,
    }

Add an internal cache discriminator in `crates/bifrost-analysis/src/analyzer/usages/workspace_graph_cache.rs`:

    pub(crate) enum WorkspaceUsageGraphKind {
        File,
        Exact,
    }

Add an internal file graph under `crates/bifrost-analysis/src/analyzer/usages/file_usage_graph.rs`. Its stable interface will accept `&dyn IAnalyzer`, a selected `BTreeSet<UsageEcosystem>`, and a `CancellationToken`. It will return either one complete dense file graph or cancellation. It will use `ImportAnalysisProvider`, `resolve_imported_files_from_infos`, `UsageReferenceCounts`, and existing hash collections. No new crate or third-party dependency is required.

Revision note 2026-08-05T19:53:45Z: Created the implementation plan after issue #1676 approval, code navigation, upstream overlap review, and selection of the existing batched import-analysis seam.

Revision note 2026-08-05T20:45:00Z: Recorded implementation, the persisted-analyzer Rust bottleneck, the manifest-name index decision, and cold and warm MCP evidence.

Revision note 2026-08-05T21:11:57Z: Recorded focused validation, policy cleanup, workspace Clippy, the corrected temporary-storage run, and the unrelated tutorial gold failures.
