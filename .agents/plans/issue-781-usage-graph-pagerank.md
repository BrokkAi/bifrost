# Rank relevant files with the whole-program usage graph

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with `.agents/PLANS.md`.

## Purpose / Big Picture

After this change, callers of `most_relevant_files` can opt into a `usage_graph` mode that follows Bifrost's resolved caller-to-callee graph instead of relying only on git co-change history and imports. Repeated resolved reference sites influence the rank, declaration scores roll up to files, and the existing relevance pipeline fills any remaining result slots. Omitting the mode preserves today's behavior and latency.

The behavior is observable through the MCP tool, the `most_relevant_files` helper binary, and the Python client. A small inline project in `tests/most_relevant_files.rs` will show a genuinely called dependency outranking an import-only neighbor when `ranking_mode` is `usage_graph`.

## Progress

- [x] (2026-07-15T08:43:07Z) Confirmed the issue branch was clean, fetched origin, and rebased it onto `origin/master` at `3aee987b`.
- [x] (2026-07-15T08:49:00Z) Extracted the import-specific PageRank loop into a reusable weighted dense-ID kernel and proved focused unit and import-ranking parity tests pass.
- [x] (2026-07-15T09:24:00Z) Added an exact-identity, weight-only workspace usage graph with shared node catalog and completeness metadata.
- [ ] Add opt-in usage-primary file ranking and public Rust, MCP, CLI, and Python surfaces.
- [ ] Add behavior, identity, schema, client, and performance coverage.
- [ ] Run formatting, Clippy, focused tests, and the full `nlp,python` test gate.
- [ ] Complete guided post-implementation review and address material findings.

## Surprises & Discoveries

- Observation: `related_files_by_imports` owns the only PageRank loop and divides outgoing mass by edge count, while the inverted usage engine already has `UsageEdgeWeights` with distinct call-site counts.
  Evidence: `src/relevance.rs::related_files_by_imports` and `src/analyzer/usages/inverted_edges.rs::UsageEdgeWeights`.

- Observation: the public usage graph groups JS/TS nodes with file scope, but the ordinary edge wrapper returns string keys. The existing scoped JS/TS edge builder retains `UsageNodeKey`, so ranking must use that path rather than reconstructing identity from public edges.
  Evidence: `src/searchtools.rs::usage_graph` and `src/analyzer/usages/js_ts_graph.rs::build_jsts_scoped_usage_edges`.

- Observation: making each inverted language scan generic over its final output preserves one AST walk while allowing the public graph to retain call sites and relevance to consume compact weights directly.
  Evidence: `UsageEdgeBuildOutput` in `src/analyzer/usages/inverted_edges.rs` and the language-specific `build_*_edges` adapters.

## Decision Log

- Decision: expose `history_imports` and `usage_graph` ranking modes, with `history_imports` as the default.
  Rationale: whole-workspace usage resolution is materially more expensive and semantic search already depends on current relevance behavior.
  Date/Author: 2026-07-15 / User and Codex

- Decision: personalized rank flows only from caller to callee, and declaration scores are summed into file scores.
  Rationale: this matches the existing import direction and preserves PageRank mass when multiple important declarations share a file.
  Date/Author: 2026-07-15 / User and Codex

- Decision: keep symbol scores and completeness metadata internal, and do not add a permanent workspace-graph cache.
  Rationale: issue #781 is a file-ranking capability; compact retained storage and generation-safe caching remain in #748.
  Date/Author: 2026-07-15 / User and Codex

## Outcomes & Retrospective

The weighted-PageRank and exact workspace-graph milestones are complete; usage-primary ranking and public surfaces remain.

Milestone 1 outcome 2026-07-15T08:49:00Z: `weighted_page_rank` now supports unit or weighted arcs, explicit personalized teleportation, uniform global teleportation, and personalized dangling-mass redistribution. The import adapter supplies unit weights and all 22 `most_relevant_files` integration tests remain green.

Milestone 2 outcome 2026-07-15T09:24:00Z: every language's inverted resolver can now finalize the same per-file scan into either call-site edges or compact weights. `WorkspaceUsageCatalog` owns ecosystem-qualified and JS/TS file-qualified identity, deterministic primary declarations, declaration-file membership, and completeness metadata. The public `usage_graph` reuses this catalog without changing its wire result.

## Context and Orientation

`most_relevant_files` is declared in `src/searchtools.rs`, dispatched by `src/searchtools_service.rs`, and described to MCP clients in `src/mcp_extended.rs`. Its implementation resolves seed files and calls `src/relevance.rs`, where git relevance is emitted first and a personalized PageRank over a two-hop import graph fills remaining slots.

The whole-workspace usage graph is also assembled in `src/searchtools.rs`. It enumerates non-synthetic class and callable declarations, invokes one inverted resolver per language ecosystem, and renders weighted caller-to-callee edges with call-site locations. Shared inverted mechanics live in `src/analyzer/usages/inverted_edges.rs`. Package-scoped languages use fully qualified names as node keys; JavaScript and TypeScript require the defining file as part of identity because two modules may export the same bare name.

A teleport vector is the probability mass PageRank returns to when following edges restarts. For personalized ranking, seed-file weights are divided evenly among eligible declarations in each file. A dangling node is a node with no outgoing edge; its rank is redistributed through the same teleport vector. A truncated callee is one whose inbound call sites exceeded the usage guardrail; its missing inbound edges make its centrality incomplete, so its own symbol score must not promote a file.

## Plan of Work

First extract a dense weighted PageRank helper in `src/relevance.rs`. It accepts outgoing `(node_index, weight)` arcs and a teleport vector, normalizes both transitions and teleport mass, retains the current damping and convergence constants, and supports uniform teleportation when the caller supplies an empty vector. Adapt the import graph to use unit-weight arcs and prove its result order is unchanged.

Next add `src/analyzer/usages/workspace_graph.rs`. Move the ecosystem classification there and define exact workspace node identity, deterministic primary declaration metadata, the set of declaration files used for seed mapping, weighted edges, and truncated/unproven inbound metadata. Extend the inverted resolver boundary so per-language scans can finalize directly into `UsageEdgeWeights`; JS/TS must use its file-aware scoped builder. Refactor public `usage_graph` to share the node catalog but retain its existing site-bearing JSON shape.

Then add `MostRelevantFilesRankingMode` and `related_files_by_usage`. Usage mode builds the compact graph, distributes seed mass over declarations, runs caller-to-callee PageRank, sums complete symbol scores into primary files, excludes seed files, and appends these results before the unchanged relevance pipeline fills the limit. If no seed maps or the graph has no useful edges, the existing pipeline supplies the complete result.

Finally expose the mode through MCP, CLI, and Python, explicitly pin semantic search to `history_imports`, add behavior and identity tests, and capture profiling scopes for graph construction, PageRank, and aggregation. Each completed milestone receives a multiline checkpoint commit containing only its files.

## Concrete Steps

Work from `/Users/dave/.codex/worktrees/5e5c/bifrost`.

After the PageRank milestone, run:

    cargo fmt --all -- --check
    BIFROST_SEMANTIC_INDEX=off cargo test relevance::tests
    BIFROST_SEMANTIC_INDEX=off cargo test --test most_relevant_files

After the graph milestone, run the relevant inverted-edge unit tests and:

    BIFROST_SEMANTIC_INDEX=off cargo test --test usage_graph_identity_test

After the public-surface milestone, run focused MCP and Python tests, then profile an opt-in call:

    BIFROST_SEMANTIC_INDEX=off BIFROST_TIMING=1 cargo run --bin most_relevant_files -- --root . --ranking-mode usage_graph src/searchtools.rs

Before completion, run:

    cargo fmt --all -- --check
    cargo clippy --all-targets --all-features -- -D warnings
    BIFROST_SEMANTIC_INDEX=off cargo test --features nlp,python

Do not create manually named Cargo target directories. If an isolated target becomes necessary, use `scripts/with-isolated-cargo-target.sh`.

## Validation and Acceptance

The default mode must return the same ordered results as before. Usage mode must rank an actually called dependency ahead of an import-only neighbor, respect distinct reference-site weights, never flow rank backward from callee to caller, combine multiple seed weights deterministically, and sum multiple declaration scores in one file. It must fill short results without duplicates, fall back completely for unmapped seeds, avoid promoting truncated callees, and preserve JS/TS file identity plus cross-language ecosystem identity.

The MCP schema and Python client must serialize the two mode strings exactly. Semantic search must explicitly select `history_imports`. Formatting, warnings-as-errors Clippy, focused tests, and the full feature-enabled test suite must pass. Profiling evidence must separate compact graph construction, PageRank, aggregation, and total tool time; a material regression against #754 blocks completion.

## Idempotence and Recovery

All source changes are repeatable and guarded by tests. The new mode is opt-in, so an incomplete usage implementation must never alter default results. If a language-specific weight-only adapter fails, fix the shared finalization seam or that structured resolver; do not add text scanning. If profiling exposes unacceptable graph cost, record the evidence and optimize construction rather than adding an unvalidated permanent cache.

## Artifacts and Notes

Keep checkpoint test transcripts and the final profiling breakdown in this section as milestones complete. Post the final timing comparison to issue #781 and cross-reference #754 if it uses that benchmark's corpus.

Milestone 1 evidence:

    cargo test weighted_page_rank --lib
    test result: ok. 3 passed; 0 failed

    cargo test --test most_relevant_files
    test result: ok. 22 passed; 0 failed

Milestone 2 evidence:

    cargo check --lib
    Finished successfully; temporary dead-code warnings remain until milestone 3 consumes the compact graph.

    cargo test --test usage_graph_identity_test --test usage_graph_test
    test result: ok. 5 passed; 0 failed
    test result: ok. 16 passed; 0 failed

## Interfaces and Dependencies

The public Rust request gains:

    #[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum MostRelevantFilesRankingMode {
        #[default]
        HistoryImports,
        UsageGraph,
    }

    pub struct MostRelevantFilesParams {
        pub seed_file_paths: Vec<String>,
        pub seed_weights: Option<Vec<f64>>,
        pub recency_half_life: Option<f64>,
        pub ranking_mode: MostRelevantFilesRankingMode,
        pub limit: usize,
    }

The Python client exposes the same two values through a string enum. The result payload remains unchanged. No new third-party dependency is required.

Revision note 2026-07-15T08:43:07Z: Created the implementation ExecPlan from the approved issue #781 design before source changes.

Revision note 2026-07-15T08:49:00Z: Recorded the completed weighted-PageRank milestone and its focused validation evidence.

Revision note 2026-07-15T09:24:00Z: Recorded the shared exact-identity catalog, direct weight finalization, and public usage-graph parity evidence.
