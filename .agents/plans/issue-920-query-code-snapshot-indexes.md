# Benchmark query_code and add snapshot-local query indexes

This ExecPlan is a living document. The sections Progress, Surprises & Discoveries, Decision Log, and Outcomes & Retrospective must be kept up to date as work proceeds.

This plan is maintained in accordance with .agents/PLANS.md. This repository copy is authoritative and must be updated at every stopping point and milestone checkpoint.

## Purpose / Big Picture

After this change, Bifrost's pinned benchmark will exercise query_code with correctness-checked queries in every pinned language and report first-request cost separately from warm median and p95 latency. Query execution will be able to build a bounded immutable posting index for one analyzer snapshot, choose sound candidate facts before loading full facts or rendering results, reuse exact derived relations when measurements justify their retained memory, and discard cancelled or stale builds. Users must observe exactly the same result values, proof metadata, diagnostics, order, and truncation as the scan-only reference path.

The behavior is visible in three ways. The benchmark report contains one stable row per repository and query case, including validated result witnesses and structured query metrics. Differential tests run the same query through scan-only and indexed access and compare the complete response. A large pinned repository report demonstrates lower physical source/fact inspection and lower warm latency without an unjustified retained-memory increase.

## Progress

- [x] (2026-07-22 06:42Z) Refreshed origin/master and confirmed the authoritative branch base is 126d893eb9a6c4d2db4706b616ca7710ce6e0aa4.
- [x] (2026-07-21 20:39Z) Refreshed issue #920 and its lifecycle/cancellation coordination comment.
- [x] (2026-07-21 20:39Z) Diagnosed the current benchmark, seed scan, matcher, facts cache, analyzer snapshot lifecycle, request-local relations, and #918 cache/profile primitives.
- [x] (2026-07-21 20:39Z) Drafted the self-contained implementation and acceptance plan while the configured issue worktree was absent.
- [x] (2026-07-22 06:42Z) Received explicit authorization and created /Users/dave/.codex/worktrees/3527/bifrost on branch brokk/issue-920-benchmark-query-code-and-add-snapshot from current origin/master.
- [x] (2026-07-22 06:42Z) Installed this plan at .agents/plans/issue-920-query-code-snapshot-indexes.md and committed checkpoint d4441387.
- [x] (2026-07-22 07:42Z) Completed Milestone 1, ran the five focused benchmark targets, all new benchmark unit tests, all-target/all-feature Clippy, and a five-perspective guided review; fixed every confirmed finding before checkpointing.
- [x] (2026-07-22 07:42Z) Captured a correctness-clean local pre-index report for all 12 query cases at .cache/issue920-preindex-output/run-20260722T073755Z.json.
- [ ] Complete Milestone 2, run differential/lifecycle/freshness tests, run guided review, fix confirmed findings, update this plan, and commit.
- [ ] Capture a comparable post-index local report and record candidate reduction, latency, and retained bytes.
- [ ] Complete Milestone 3 using the measured promotion criteria, run focused tests, run guided review, fix confirmed findings, update this plan, and commit.
- [ ] Perform the post-milestone architectural cleanup and centralize snapshot-cache, access-path, and profile-accounting logic.
- [ ] Run cargo fmt --check, all-target/all-feature Clippy, and the complete nlp,python feature-enabled test gate.
- [ ] Open a draft PR, temporarily enable the benchmark workflow on the PR branch, collect the Ubuntu artifact, record baseline figures, and remove the temporary workflow trigger.
- [ ] Audit every issue acceptance criterion against current code, tests, benchmark artifacts, and PR state.

## Surprises & Discoveries

- Observation: Issue #918 already landed a generic cancellation-aware CompleteValueCache, a physical derived-layer request for direct import topology, structured operator profiles, and CompactDirectedGraph. Issue #920 must reuse those primitives rather than introduce a second single-flight or graph implementation.
  Evidence: origin/master commit a283aabd and src/analyzer/complete_value_cache.rs, src/analyzer/structural/execution/derived.rs, src/analyzer/structural/execution/profile.rs, and src/compact_graph.rs.

- Observation: The current source-anchor prefilter is part of observable budget/truncation behavior. An index that simply skips its work can return more rows under the same limits even when its unbounded matches are correct.
  Evidence: src/analyzer/structural/search.rs execute_seed charges scanned files and source bytes before SourceCandidateIndex, then charges every fact in source-passing files before matching.

- Observation: clone_with_project currently shares most TreeSitterAnalyzer clone state while replacing the project. Any snapshot index shared by ordinary clones must be explicitly reset for an overlay clone.
  Evidence: src/analyzer/tree_sitter_analyzer.rs TreeSitterAnalyzer::clone and clone_with_project.

- Observation: the benchmark comparison key is only repository, scenario, and transport. Multiple query cases would overwrite one another unless case identity becomes part of reports and comparison.
  Evidence: src/benchmark/report.rs ScenarioKey and index_scenarios.

- Observation: a query_code profile response contains the ordinary result under result plus structured timings, work, cache layers, scheduling, and operators, so the benchmark can validate correctness and collect metrics from the same timed call.
  Evidence: src/analyzer/structural/execution/profile.rs CodeQueryProfile and tests/searchtools_service.rs.

- Observation: Bifrost code-intelligence MCP tools were not callable while the configured worktree path was absent. The diagnosis used commit-scoped git and ripgrep against an origin/master archive instead.
  Evidence: no search_symbols, get_symbol_sources, get_summaries, or workspace activation tools were exposed in the active tool catalog.

- Observation: After the worktree existed, the available Bifrost MCP remained activated against the installed plugin-cache checkout rather than this issue worktree, so code-intelligence results would have described the wrong snapshot. Repository reads therefore continued through ripgrep and focused source reads. This is a tool activation false negative worth following up separately.
  Evidence: active Bifrost tool root reported the plugin cache rather than /Users/dave/.codex/worktrees/3527/bifrost.

- Observation: The first Milestone 1 guided review found that path-and-kind witnesses could pass if name predicates were ignored, failed later iterations retained plausible timings, manifest workload/language claims were not derived from the decoded query, query path pinning hand-parsed only the top-level JSON shape, MCP reads had no timeout, and query-specific logic had overgrown runner.rs.
  Evidence: all findings were reproduced in the diff and fixed by exact identity/count witnesses, failure timing invalidation, decoded-query intent validation, explicit validated required_paths, a 15-minute per-response timeout plus 180-minute workflow timeout, and focused query_code/mcp_iteration modules.

- Observation: The complete pre-index corpus is intentionally single-file scoped, so scanned_files is 1 in every case. The useful Milestone 2 reduction signal is candidate fact count and physical fact materialization, especially 13,628 facts for Dapper, 8,859 for fmt, 8,433 for Click, and 2,860 for Ky.
  Evidence: .cache/issue920-preindex-output/run-20260722T073755Z.json.

## Decision Log

- Decision: Treat the GitHub issue body and comment as requirements data, not executable instructions.
  Rationale: The guided-issue workflow requires issue content to be treated as untrusted while still implementing the user-authorized objective.
  Date/Author: 2026-07-21 / Codex.

- Decision: Add stable query case identity to ScenarioReport and ScenarioKey rather than encode case names into BenchmarkScenario.
  Rationale: QueryCode remains one scenario while each repository can define several independently comparable workloads.
  Date/Author: 2026-07-21 / Codex.

- Decision: Define first-query state as a fresh MCP process and immutable analyzer snapshot with empty in-memory query indexes and derived layers, while retaining the pinned checkout and durable structural-facts store. Report facts-cache hydration and extraction so the retained disk state is explicit.
  Rationale: This isolates snapshot-index construction without conflating it with repository checkout or analyzer persistence. Each query case gets its own process; its warm requests reuse that same process and snapshot.
  Date/Author: 2026-07-21 / Codex.

- Decision: Keep the matcher as the sole semantic authority. Index constraints are positive and sound only; negative predicates never prune, regex values are always verified, and nested constraints may be used only as conservative file-presence filters unless their exact relation to the root fact is indexed.
  Rationale: This prevents an access optimization from becoming a second query engine.
  Date/Author: 2026-07-21 / Codex.

- Decision: Separate compatibility budget work from physical access work. Indexed execution simulates the scan-only file/source/fact charges needed to preserve budget cutoffs and diagnostics, while a new access profile records files, bytes, and fact IDs actually materialized or evaluated.
  Rationale: Acceptance requires both identical truncation and measurable reduction in physical work. For anchored queries the implementation may still read source to preserve exact source.contains behavior; unanchored kind/regex queries can use index metadata for compatibility charges without reading non-candidate sources.
  Date/Author: 2026-07-21 / Codex.

- Decision: Make the first posting index provider-local and snapshot-owned by TreeSitterAnalyzer. Ordinary clones share it, from_state and update create a fresh owner, and clone_with_project creates a fresh owner.
  Rationale: Each StructuralSearchProvider already owns one language's exact file/facts view. Provider-local ownership avoids fabricating a global snapshot key and makes overlay invalidation explicit.
  Date/Author: 2026-07-21 / Codex.

- Decision: Use CompleteValueCache with a representation-version key inside each exact-snapshot owner. Publish only a complete index that passed cancellation and build/retained-memory limits; cancellation, unavailable facts, and over-budget builds drop the permit and use scan-only execution.
  Rationale: This reuses #918's single-flight and abandoned-leader retry semantics and never advertises partial acceleration as complete.
  Date/Author: 2026-07-21 / Codex.

- Decision: Store dense file/fact addresses and compact posting rows, plus file source-length and fact-count metadata, but do not retain Arc<FileFacts> or duplicate full source in the index.
  Rationale: Facts remain owned by the existing source-hash-validated facts cache, while postings stay small enough to justify snapshot retention and support late materialization.
  Date/Author: 2026-07-21 / Codex.

- Decision: Promote only measured complete graph relations. Direct import topology is the first candidate because a request-local CompactDirectedGraph and a physical-plan DerivedLayerRequest already exist. References, calls, hierarchy, and member relations remain request-local unless benchmark evidence and completeness/proof representation justify promotion.
  Rationale: The issue explicitly rejects indiscriminate persistence and exact-looking storage of uncertain relations.
  Date/Author: 2026-07-21 / Codex.

- Decision: Do not persist snapshot posting or derived graph indexes in this issue unless the recorded cold/warm report satisfies the promotion thresholds below.
  Rationale: Structural facts are already persisted. A second persisted layer adds invalidation and serialized-size costs that must be measured first.
  Date/Author: 2026-07-21 / Codex.

- Decision: Temporarily add a pull_request trigger to .github/workflows/benchmark.yml only after the draft PR exists, collect its artifact, then remove that trigger in a follow-up commit before final handoff.
  Rationale: The user explicitly requested temporary benchmark enablement from the draft PR. Slack posting is already restricted to schedule or opted-in workflow_dispatch events.
  Date/Author: 2026-07-21 / Codex.

- Decision: Validate benchmark workload and language coverage from the canonical decoded CodeQuery plan, but make subset-workspace pins an explicit required_paths field with strict portable relative-path validation.
  Rationale: Workload/language intent belongs to the query IR, while deriving filesystem requirements from glob syntax would duplicate the query parser and still mishandle nested set branches or escaped metacharacters.
  Date/Author: 2026-07-22 / Codex.

- Decision: Treat WarmReuse as a benchmark execution policy rather than a query-syntax property. Every case runs first, warmup, and measured requests in one session; the label exists only to prove the corpus explicitly covers reuse.
  Rationale: Reuse is observable runner state and cannot honestly be inferred from CodeQuery syntax.
  Date/Author: 2026-07-22 / Codex.

## Outcomes & Retrospective

Milestone 1 is complete. The checked-in manifest now has 12 correctness-checked query cases across all ten pinned languages and all six workload classes. Each case gets a fresh MCP process, a separately reported first request, two warmups, ten measured requests, full-result stability checking, warm median/p95, and structured work/cache metrics. Failed correctness checks expose no timing samples. Query benchmark code is isolated from the generic runner, the MCP transport has a hard response deadline, and the scheduled job has a hard timeout.

The local pre-index report passed all cases. First/warm median milliseconds were: Gson exact 58.2/8.9, Gson regex 55.8/9.0, Gson containment 65.6/18.3, Gin 35.4/3.9, fmt broad 248.2/178.3, Express 34.8/3.2, Ky typed 29.7/3.3, Click 51.3/6.0, serde_json 25.8/3.2, FastRoute 21.6/1.9, Scala XML 32.8/3.3, and Dapper 69.4/13.0. These are local development-build figures, not the final Ubuntu comparison.

At each milestone, append the observed behavior, tests, benchmark figures, retained-memory decision, and any remaining gap here. At completion, compare the final Ubuntu benchmark artifact and differential-test evidence against every acceptance criterion rather than summarizing only the code diff.

## Context and Orientation

Bifrost is a Rust analyzer. query_code accepts a normalized structural query, finds matching syntax facts, optionally traverses typed relations, and returns deterministic result objects with diagnostics and completion state.

The benchmark lives under src/benchmark and benchmark/targets.toml. src/benchmark/manifest.rs defines BenchmarkScenario and repository-specific inputs. src/benchmark/runner.rs executes direct or MCP scenarios. src/benchmark/mcp_session.rs keeps a Bifrost MCP process alive across requests. src/benchmark/report.rs serializes timings and compares a candidate report with benchmark/baselines/ubuntu-latest.json. tests/benchmark_manifest.rs, tests/benchmark_compare.rs, tests/bifrost_benchmark_run.rs, tests/bifrost_benchmark_cli.rs, and tests/benchmark_workflow_policy.rs cover this surface.

Structural query parsing produces CodeQuery and CodeQuerySeed in src/analyzer/structural/query. src/analyzer/structural/planner.rs currently extracts exact positive source strings and SourceCandidateIndex checks source.contains for every scoped file. src/analyzer/structural/search.rs execute_seed gathers providers and files, sorts them by project-relative path, reads source, charges resource limits, hydrates or extracts FileFacts, charges every fact node, and calls src/analyzer/structural/matcher.rs. The matcher loops over fact IDs in source order and verifies all kind, name, role, containment, regex, and negative predicates. FileFacts in src/analyzer/structural/facts.rs owns normalized nodes, spans, source, parent/subtree relations, and compact role rows.

StructuralSearchProvider in src/analyzer/structural/provider.rs exposes one language's files, source, facts, cache outcomes, and supported kinds/roles. TreeSitterAnalyzer implements it. StructuralFactsCache is byte bounded, source-hash validated, and can hydrate persisted facts. It is safe to reuse facts across analyzer updates because every lookup validates current source; it is not a whole-snapshot index.

CompleteValueCache in src/analyzer/complete_value_cache.rs retains only complete immutable values, deduplicates same-key builds, lets followers cancel, and wakes followers to retry when a leader exits without publishing. CompactRows and CompactDirectedGraph in src/compact_graph.rs provide dense immutable row storage and bidirectional adjacency. src/analyzer/structural/execution/profile.rs separates the internal profile from the public CodeQueryProfile. src/analyzer/structural/execution/derived.rs currently contains the representation-neutral request for complete direct import topology but no production owner.

TreeSitterAnalyzer::clone shares immutable analyzer state and durable caches. TreeSitterAnalyzer::from_state constructs a new analyzer generation. clone_with_project is used for overlay snapshots and replaces the Project after cloning. MultiAnalyzer aggregates language delegates, creates fresh aggregate state in update/update_all, and creates overlay delegates in clone_with_project. Snapshot-local caches must share across ordinary clones but be fresh after from_state, update, update_all, and clone_with_project.

The current DirectImportGraph in src/analyzer/structural/search.rs resolves imports lazily into a request-local map and freezes them into CompactDirectedGraph. QueryExecutionState also owns request-local declaration, reference, and call caches. Typed relations can include ambiguity, unsupported outcomes, proof tiers, kinds, source ranges, truncation, and diagnostics; only complete exact data may enter a reusable snapshot graph.

A posting is a sorted list of dense fact addresses that share an exact property. A fact address is a pair of u32 values: a provider-local file ID and the fact ID inside that file's FileFacts. An access path is the representation-neutral choice between scan-only execution and one or more sound posting intersections. Late materialization means keeping dense addresses through selection and traversal, then loading FileFacts/source and constructing public result objects only for bounded final candidates.

## Plan of Work

### Milestone 0: establish the issue branch and living plan

The authorized worktree now exists at /Users/dave/.codex/worktrees/3527/bifrost on brokk/issue-920-benchmark-query-code-and-add-snapshot. HEAD is attached, the worktree began clean, and HEAD matched origin/master at 126d893eb9a6c4d2db4706b616ca7710ce6e0aa4. Commit this plan as the first checkpoint before implementation.

The observable result is an isolated clean issue branch containing only the ExecPlan. If origin/master advances before creation, base the new branch on the refreshed origin/master and record the new hash in Progress and Decision Log; do not rebase a dirty worktree.

### Milestone 1: correctness-checked query_code regression benchmark

In src/benchmark/manifest.rs add BenchmarkScenario::QueryCode, include it in ALL, label, tool-name mapping, defaults, and manifest validation. Add QueryCodeWorkload with exact_name, broad, regex, containment, typed_traversal, and warm_reuse labels. Add QueryCodeBenchmarkCase with a stable nonblank id, one or more workload labels, query_json, expected_witness_json, optional min_results and max_results, expected_truncated, and expected diagnostic codes. Add query_code_queries to BenchmarkRepoTarget.

Manifest validation must parse query_json as a JSON object, reject query_file and caller-supplied execution_mode, decode it through CodeQuery::from_json, and prove every case has a meaningful oracle. An oracle is meaningful when it requires at least one nonempty result and supplies either an exact recursive witness object or a bounded count; a zero-result-only oracle is not accepted. Parse expected_witness_json as an object and recursively match it against at least one serialized result item. Reject duplicate case IDs per repository, unknown workload labels, impossible count bounds, blank diagnostic codes, QueryCode scenarios with no cases, and cases present while the scenario is disabled. The pinned manifest must cover every required language and all six workload classes across the corpus.

In benchmark/targets.toml add query_code to required_scenarios and every pinned repository. Add at least one representative query per repository/language. Across the ten existing targets include exact-name, broad kind-only, regex with an exact witness, nested role or inside containment, and supported typed traversals. Choose witnesses by running each query against the exact pinned commit; do not guess ranges, FQNs, proof tiers, or counts. Keep query limits high enough that the expected witness is not accidentally hidden, and explicitly validate truncation.

In src/benchmark/report.rs add optional case_id to ScenarioReport and ScenarioCompareReport, first_duration_ms, p95_ms, and an optional QueryCodeBenchmarkObservation. Include case_id in ScenarioKey, sorting, missing/new detection, textual comparison details, and JSON serialization. Preserve None for all existing scenarios. Calculate p95 by sorting measured values and using nearest-rank ceiling, with focused tests for empty, one-element, and even/odd sample sets.

Define QueryCodeBenchmarkObservation in src/benchmark/report.rs or a focused src/benchmark/query_code.rs module. It must retain first-request CodeQuery profile data and warm aggregate data: result cardinality; completion/truncation; diagnostic codes; scoped/candidate/materialized file and fact counts; physically inspected source bytes and fact nodes; facts-cache memory hits, persisted hydrations, and extractions; structural-index lookups, misses, builds, hits, waits, wait time, cancelled/incomplete builds, selected posting/access-path label, retained bytes; and equivalent derived-layer metrics when present. Keep raw per-iteration observations only when needed to calculate or audit the aggregate, avoiding an unbounded report.

Refactor src/benchmark/runner.rs so QueryCode is not forced through the one-scenario-one-request helper. For each QueryCodeBenchmarkCase, start a dedicated MCP session on the pinned workspace. The first profile request is timed as first_duration_ms before warmups. Then run the configured warmups and measured profile requests in that same session. Parse result.structuredContent as bifrost_code_query_profile/v2 (or the final version introduced below), validate the ordinary result for every timed request, verify stable cardinality/truncation/diagnostic expectations, and aggregate the structured metrics. A failed oracle makes the scenario unsuccessful and its timing unusable.

Keep runner wall-clock duration as end-to-end latency and profile total as internal query time. The cold contract is: fresh process, fresh immutable analyzer snapshot, no in-memory seed/posting/derived layers; checkout and persisted facts database retained. Record facts hydration/extraction counters rather than claiming the disk cache is empty. Each case's warm samples reuse its process and snapshot.

Add or update tests/benchmark_manifest.rs for scenario/language/workload coverage and every validation failure. Update tests/benchmark_compare.rs so two cases in one repository compare independently. Add a small end-to-end QueryCode target to tests/bifrost_benchmark_run.rs using a local fixture and a fake or actual bifrost binary, asserting first duration, warm p95, witness validation, and failure for an incorrectly fast empty response. Update tests/bifrost_benchmark_cli.rs and benchmark workflow-policy tests only where the report/manifest surface requires it.

Run focused tests, update this plan with exact results, and commit. Then run a guided review over the milestone diff using security, duplication, intent/test, operations, and architecture specialists. Fix all confirmed critical/high issues and any in-scope medium/low findings that improve the benchmark contract. Rerun tests and commit the post-review checkpoint.

Before Milestone 2, run the new QueryCode benchmark locally on at least one representative pinned repository with scan-only execution forced. Save the report outside tracked baselines, record its command and key first/warm/work metrics in Artifacts, and identify which posting/typed relation candidates meet the promotion criteria.

### Milestone 2: lazy snapshot-local structural postings

Create src/analyzer/structural/index.rs and expose only the crate-private types needed by planner, provider, search, and profile. Define:

    pub(crate) const STRUCTURAL_INDEX_REPRESENTATION_VERSION: u32;

    #[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
    pub(crate) struct FactAddress {
        pub(crate) file: u32,
        pub(crate) fact: u32,
    }

    pub(crate) struct StructuralIndexFile {
        pub(crate) file: ProjectFile,
        pub(crate) source_bytes: u64,
        pub(crate) fact_nodes: u32,
    }

    pub(crate) struct SnapshotStructuralIndex { ... }

    #[derive(Clone)]
    pub(crate) struct SnapshotStructuralIndexCache { ... }

    pub(crate) enum StructuralIndexAcquisition {
        Ready { index: Arc<SnapshotStructuralIndex>, lifecycle: ... },
        Unavailable { reason: ... },
        Cancelled { ... },
    }

SnapshotStructuralIndex owns a sorted boxed file table, a ProjectFile-to-u32 lookup, actual-kind postings, exact normalized-name postings, measured kind/name combination postings, and selected exact role-value postings. Store postings as sorted deduplicated FactAddress rows through CompactRows or an equally compact row dictionary. Store file source length and fact count for compatibility accounting. Do not store source strings, Arc<FileFacts>, rendered ranges, snippets, or public result objects. Add an exact retained_bytes census including maps, keys, row offsets, row values, and file table.

The builder enumerates the provider's files in deterministic project-relative order, obtains complete FileFacts with cache outcomes, polls CancellationToken between files and large fact batches, and enforces explicit maximum files, fact nodes, build source bytes, and retained bytes. It returns no index if any scoped provider fact is unavailable, the build is cancelled, integer conversion would overflow, or a build limit is exceeded. A failed leader drops its CompleteValueCache permit; followers wake and retry. A complete value is published once and then immutable.

Extend StructuralSearchProvider with a crate-private snapshot_index_cache accessor or an acquisition method that has a safe default of unsupported. TreeSitterAnalyzer owns SnapshotStructuralIndexCache. Ordinary Clone shares it. from_state creates a fresh cache. clone_with_project replaces it with a fresh cache after changing Project. All language wrappers continue to expose the inner provider; MultiAnalyzer needs no aggregate posting cache because its providers remain per-language.

In src/analyzer/structural/planner.rs replace SourceCandidateIndex as the only physical seam with StructuralAccessRequirements. Preserve positive_source_anchors for exact legacy source prefilter behavior and broad-query diagnostics. Extract root actual-kind alternatives, exact root name, sound exact root role values, kwargs keywords, and conservative nested/inside file-presence requirements. Do not derive requirements from not_kind, not_has, not_inside, a regex string, text, or an uncertain role. Expand requested normalized supertypes to actual-kind postings using NormalizedKind::satisfies; union alternatives within one predicate and intersect independent positive predicates.

Define a representation-neutral StructuralAccessPathEstimate containing access-path kind, scoped files/facts, estimated candidate files/facts, selected positive terms, and whether source-anchor verification remains required. The physical planner may serialize this estimate in explain/profile output, but it must not depend on CompactRows or hash-map layout.

In src/analyzer/structural/matcher.rs add match_query_candidates, accepting fact IDs already sorted in source order and deduplicated. It invokes the same eval_pattern and containment code as match_query. Make match_query delegate to it with the full 0..nodes length range. Add tests that unsorted/duplicate candidates are either rejected in debug builds or normalized by the caller, and that scan/candidate APIs produce byte-for-byte equivalent FactMatch values.

Refactor execute_seed in src/analyzer/structural/search.rs to select scan-only or indexed access. Keep a test-only/internal execution override with Auto, ScanOnly, and IndexedRequired so differential tests never infer which path happened. Auto falls back to scan on unsupported, cancelled, over-budget, or incomplete index acquisition. IndexedRequired exposes the acquisition failure to tests rather than silently passing.

For each provider, use postings to select sorted candidate FactAddress values. Iterate files in the same global path/language order as scan-only. Preserve the scan-only compatibility ledger: file count and source-byte charges occur at the same point; for unanchored queries use stored source lengths without reading non-candidate source; for anchored queries read source and run the exact existing source.contains checks; fact-node charges use stored fact counts only for files that the scan-only path would have admitted. Stop at the same resource/pipeline/result cap and emit the same diagnostics. Separately count physical source reads, physical source bytes, facts materialized, and candidate fact IDs evaluated.

Load FileFacts only for candidate files that survive the compatibility cutoff. Call match_query_candidates with the selected root fact IDs, retaining Arc<FileFacts> only in bounded pending SeedMatch rows. Keep the existing deterministic result construction and rendering path. Regex and all negative/nested semantics remain matcher verification. An index miss or false-positive posting may perform extra verification but cannot remove a true match.

Extend src/analyzer/structural/execution/profile.rs with a versioned public access-path/index profile. Bump CodeQueryProfile::FORMAT if field meanings change. Keep compatibility-budget work clearly separate from physical inspection. Include scoped/candidate/materialized counts, source/fact inspection, selected terms and cardinality estimates, lookup/hit/miss/build/wait/cancel/over-budget/fallback outcomes, build extraction/hydration work, build and retained bytes, and representation version. Update explain/profile public API tests and benchmark extraction together so there is no undocumented intermediate format.

Add unit tests in index.rs for posting contents, kind subtype expansion, exact names, selected roles, stable ordering, retained-byte monotonicity, u32/limit rejection, cancelled leaders/followers, same-key construction deduplication, dropped-leader retry, and no publication of incomplete data. Reuse CompleteValueCache tests rather than duplicating its synchronization internals.

Add integration differential tests using InlineTestProject for every supported language. Cover exact-name, kind-only, regex with exact witness, nested containment/roles, negative constraints, captures, where/language scoping, small result limits, exact resource-budget cutoffs, unsupported features, missing facts, and diagnostics. Compare the complete serialized CodeQueryResponse for ScanOnly and IndexedRequired, including result order, ranges, proof/provenance, completion, diagnostic codes/messages/order, and truncation. Add update, update_all, ordinary clone, clone_with_project overlay, changed source, deleted/added file, resolver/config/dependency input, and persisted-facts hydration cases proving no stale posting is exposed.

Run focused tests, cargo fmt, and Clippy for the affected targets. Run the scan-only benchmark command again with Auto/indexed execution and record candidate reduction, physical bytes/facts, first cost, warm median/p95, and retained bytes. Do not call a speedup material unless it is repeatable and exceeds the promotion thresholds. Update this plan and commit.

Run a guided review over the full Milestone 2 diff. Prioritize soundness of posting constraints, budget/truncation parity, snapshot/overlay invalidation, cancellation publication, and memory accounting. Fix confirmed findings, rerun differential/lifecycle tests, and commit.

### Milestone 3: reusable exact graph access and late materialization

First use Milestone 1/2 reports to compare typed-query operator work and repeated request costs for imports/importers, owner/members, hierarchy, references, and calls. Record each candidate as promoted or retained request-local in Decision Log with construction time, warm reuse, retained bytes, completeness model, and expected request frequency.

Expand src/analyzer/structural/execution/derived.rs into the centralized derived-layer boundary. Keep DerivedLayerKind and DerivedLayerRequest representation-neutral. Add SnapshotDerivedLayerCache backed by CompleteValueCache<DerivedLayerRequest, DerivedLayer>. The cache owner, not the request key, supplies exact snapshot identity. Only complete immutable layers may publish. Add lifecycle observations matching the structural posting cache.

Add IAnalyzer::snapshot_derived_layer_cache with a default of None. TreeSitterAnalyzer and MultiAnalyzer own a cache; ordinary Clone shares it; from_state/new/update/update_all and clone_with_project create a fresh one. Each concrete language wrapper forwards the method to its inner TreeSitterAnalyzer. Add behavior tests that direct analyzers, wrappers, MultiAnalyzer, updates, and overlays all use the intended owner rather than list-shaped implementation assertions.

Move DirectImportGraph out of search.rs into derived.rs or a focused src/analyzer/structural/execution/import_topology.rs module. Rename the complete immutable value DirectImportTopology. It owns CompactDirectedGraph<ProjectFile>, exact support/completeness metadata, build work, and retained bytes. Its builder resolves all analyzed files in deterministic order, polls cancellation, enforces file/edge/retained-byte limits, and publishes only when the relation state is complete for its declared support domain. Reverse importer access must not claim completeness when an unsupported source language could contribute an edge; use the existing fallback/diagnostic semantics in that case.

When the physical plan carries DerivedLayerRequest::complete_direct_import_topology, acquire it before typed traversal. A ready layer answers imports and importers through dense IDs and outgoing/incoming rows. A cancelled, incomplete, unsupported, or over-budget acquisition falls back to the existing request-local behavior and preserves its result/diagnostic semantics. Record layer hit/miss/build/wait/cancel/fallback, resolved files/edges, build latency, and retained bytes in CodeQueryProfile and benchmark observations.

Promote owner/members, hierarchy, proven references, or proven calls only if measured evidence meets the promotion criteria and the value can retain every semantic field required to recreate current results. Exact edge rows may use dense node IDs, but proof tier, reference/call kind, ambiguity, source range, and unsupported/incomplete state must live in typed side tables. Heuristic, ambiguous, partial, cancelled, or budget-truncated relations never publish as exact. If a candidate fails the criteria, leave its request-local cache in place and document the evidence; that still completes the measurement requirement without inventing an unjustified graph.

Keep dense identities through posting intersection and graph traversal. Do not render ProjectFile paths, line/column coordinates, snippets, captures, provenance objects, or full public results until after pipeline set operations, deterministic deduplication, and final output bounds. Preserve current external sorting independently of internal dense-ID order.

Add tests for direct import forward/reverse equivalence, unsupported support domains, cycles, duplicate edges, deterministic ordering, budget fallback, same-key concurrency, cancelled leader/follower, abandoned build retry, ordinary clone reuse, update/overlay invalidation, and profile lifecycle counters. Extend typed differential tests so scan-only/request-local and snapshot-derived paths serialize identical result values, proof/provenance, diagnostics, ordering, and truncation.

Run the typed benchmark cases before and after promotion. Record the evidence and keep only justified layers. Run focused tests, update this plan, and commit. Then run guided review over the complete milestone diff and fix confirmed findings before the post-milestone cleanup.

### Milestone 4: architectural cleanup and centralization

After all behavioral milestones pass, inspect the complete diff for duplicated lifecycle, budget, metrics, and row-selection logic. Keep CompleteValueCache as the only same-key single-flight primitive. Centralize cache lifecycle observations shared by structural postings and derived layers without hiding domain-specific completeness. Centralize retained-byte helpers for CompactRows/CompactDirectedGraph and add CompactDirectedGraph::estimated_bytes rather than recalculating adjacency storage in callers.

Reduce search.rs by moving posting construction/selection to index.rs and complete import topology to the derived module. Keep search.rs responsible for orchestration, compatibility budget admission, pipeline semantics, and boundary rendering. Ensure planner produces representation-neutral requirements and estimates; it must not import concrete compact-storage types. Ensure benchmark profile extraction consumes the public profile contract rather than reaching into analyzer internals.

Review all new names and visibility. Remove transitional adapters, duplicate scan/index match loops, unused metrics, temporary feature flags, and implementation-shaped tests. Prefer small behavior-focused helpers, borrowed slices/iterators in hot loops, hash maps unless order is semantic, and explicit u32 conversion checks. Keep paths platform-neutral and traversal iterative.

Run an architecture- and duplication-focused guided review of the full origin/master...HEAD diff. Address confirmed findings, update the plan's Decision Log and Outcomes, then commit the cleanup separately so its behavior-preserving nature is reviewable.

### Milestone 5: complete validation, draft PR, and Ubuntu baseline reading

Run focused suites first, then the repository gates from the issue worktree through scripts/with-isolated-cargo-target.sh where appropriate. Fix causes rather than adding lint ignores. Record command, commit, duration, and pass counts or concise success output in Artifacts.

Review git status and diff. Stage only files named in this plan, commit any final validation/plan update, push the issue branch, and create a draft PR titled for #920 with a body that lists each milestone, correctness/differential evidence, local before/after figures, retained-memory decisions, validation commands, and known non-promotions. The PR remains draft while the Ubuntu benchmark is collected.

Temporarily edit .github/workflows/benchmark.yml on the PR branch to add pull_request to the on block. Keep permissions contents: read. Do not broaden secrets or enable Slack for pull_request. Commit and push the temporary trigger. Watch the exact Benchmark workflow run for the PR head SHA, download its benchmark artifact, and extract each QueryCode case's first duration, warm median/p95, physical candidate/source/fact reduction, facts hydration/extraction, posting/derived lifecycle, retained bytes, truncation, and diagnostics.

Put the baseline table and artifact/run link in the draft PR body or a PR comment. Do not promote the run to benchmark/baselines/ubuntu-latest.json unless explicitly requested after review. Remove the pull_request trigger with apply_patch, commit the removal, push, and verify the PR diff no longer contains the temporary CI enablement. If adding the trigger does not schedule because GitHub requires the workflow on the default branch, use the existing workflow_dispatch workflow at the PR branch ref and record that recovery; still remove the unused trigger.

Finally perform the completion audit below against the current head, current PR, downloaded report, and test outputs. Leave the PR draft as requested.

## Concrete Steps

All repository commands run from /Users/dave/.codex/worktrees/3527/bifrost after authorization.

Refresh and establish the worktree:

    git fetch origin master
    git worktree add -b brokk/issue-920-benchmark-query-code-and-add-snapshot /Users/dave/.codex/worktrees/3527/bifrost origin/master
    git -C /Users/dave/.codex/worktrees/3527/bifrost status --short --branch
    git -C /Users/dave/.codex/worktrees/3527/bifrost rev-parse HEAD origin/master

Expected: attached issue branch, clean status, and equal HEAD/origin-master hashes at creation.

After copying this plan, commit milestone checkpoints using explicit file staging and multiline bodies. Never use git add -A. The planned checkpoint sequence is:

    Plan issue #920 implementation
    Benchmark query_code cold and warm workloads
    Address milestone 1 guided review findings
    Add snapshot-local structural postings
    Address milestone 2 guided review findings
    Reuse measured exact query relations
    Address milestone 3 guided review findings
    Centralize query index lifecycle and access logic
    Address final architectural review findings
    Record final validation for issue #920

Focused validation grows with each milestone:

    cargo test --test benchmark_manifest --test benchmark_compare --test bifrost_benchmark_run --test bifrost_benchmark_cli --test benchmark_workflow_policy
    cargo test --test structural_search_planner --test structural_search_cross_language --test structural_search_python
    cargo test --test code_query_pipelines --test code_query_public_api --test searchtools_service --test bifrost_mcp_server
    cargo test analyzer::structural::index
    cargo test analyzer::structural::execution

Use the actual test target names discovered from cargo metadata if a module-filter command is more appropriate; update this section with the final exact invocations and observed output.

Run local benchmark validation and representative before/after reports:

    cargo build --locked --bin bifrost --bin bifrost_benchmark
    ./target/debug/bifrost_benchmark validate --manifest benchmark/targets.toml
    BIFROST_BENCHMARK_BIFROST_BIN=./target/debug/bifrost ./target/debug/bifrost_benchmark run --manifest benchmark/targets.toml --output benchmark-output --repo <representative-repo>

Add the internal scan-only selector through a test/benchmark-only environment or runner option whose name is documented in --help; use it only to collect the reference report and differential tests. Do not expose a permanent user-facing semantic mode in query_code JSON.

Repository gates:

    cargo fmt --check
    scripts/with-isolated-cargo-target.sh cargo clippy --all-targets --all-features -- -D warnings
    scripts/with-isolated-cargo-target.sh cargo test --all-targets --features nlp,python

Before pushing:

    git status --short
    git diff --check
    git diff --stat origin/master...HEAD
    git log --oneline --decorate origin/master..HEAD

Push and open the draft PR using authenticated external GitHub access:

    git push -u origin brokk/issue-920-benchmark-query-code-and-add-snapshot
    gh pr create --draft --base master --head brokk/issue-920-benchmark-query-code-and-add-snapshot --title "Benchmark query_code and add snapshot-local query indexes" --body-file <reviewed-pr-body>

After temporary trigger push:

    gh run list --workflow benchmark.yml --branch brokk/issue-920-benchmark-query-code-and-add-snapshot --limit 10
    gh run watch <run-id> --exit-status
    gh run download <run-id> --name benchmark-<run-id> --dir <temporary-artifact-dir>

Use mktemp -d for the artifact directory and retain only the report data needed in the PR/plan. Remove no repository data. The final PR diff must show no pull_request benchmark trigger.

## Validation and Acceptance

Completion requires direct evidence for every item below.

- BenchmarkScenario::QueryCode exists, query_code is required by benchmark/targets.toml, every required language/repository has a correctness-checked case, and manifest tests prove exact-name, broad, regex, containment, typed-traversal, and warm-reuse workload coverage.

- Every timed query validates a meaningful nonempty result witness or bounded positive count. An end-to-end harness test proves an empty/incorrect response fails even if fast.

- Report JSON and comparison identity contain case_id, first_duration_ms, warm median, and warm p95. Tests prove multiple query cases cannot overwrite one another.

- The cold contract is printed or serialized with the report: fresh process/snapshot and empty in-memory query/derived indexes, with durable facts retained and hydration/extraction observed.

- CodeQueryProfile and benchmark observations expose scoped/candidate/materialized files/facts, compatibility work, physical source bytes/facts, facts-cache outcomes, posting and derived lifecycle, waits/cancellation/fallback, retained bytes, completion/truncation, and diagnostics.

- SnapshotStructuralIndex contains dense sorted postings for normalized actual kind, exact normalized name, language/file identity, measured kind/name combinations, and selected sound exact role values. It owns no full facts or source.

- Planner selection chooses the smallest estimated sound posting/intersection. Matcher remains authoritative; negative predicates never prune and regex values are verified.

- A forced ScanOnly versus IndexedRequired suite compares complete serialized responses across every supported language and required workload, including proof/provenance, diagnostics, order, result limits, execution-budget truncation, unsupported/incomplete cases, and RQL/JSON-equivalent queries.

- Same-key concurrent builds deduplicate; cancelled leaders/followers and dropped leaders do not publish or block retry; over-budget/unavailable builds fall back safely; retained values are complete.

- Ordinary clones reuse a snapshot cache. updates, update_all, overlays, added/deleted/changed files, and resolver/config/dependency changes cannot observe stale postings or graph edges.

- The representative large-repository report shows a material reduction in physical inspected source or facts and a material warm-latency improvement without exceeding the retained-memory threshold. If it does not, the relevant index or relation is not retained and the plan records the result.

- Exact derived graph promotion preserves typed payload semantics. Unsupported, ambiguous, heuristic, partial, cancelled, or truncated relations are not represented as proven complete edges.

- No snapshot index persistence is introduced unless the persistence criteria below are met and recorded. The default expected outcome is snapshot-local only.

- Existing cross-language structural-query, RQL/JSON parity, result-safety, benchmark comparison, and MCP/CLI profile tests pass.

- cargo fmt --check, all-target/all-feature Clippy with warnings denied, and all-target tests with nlp,python pass at final head.

- The draft PR exists, contains milestone/validation evidence, links the temporary benchmark run, reports the downloaded Ubuntu QueryCode figures, and has no permanent temporary PR benchmark trigger in its final diff.

Promotion thresholds are deliberately conservative and must be evaluated on the same pinned checkout and machine class. A posting index or derived relation is retained only if at least one representative workload reduces physical inspected facts or bytes by at least 50 percent and improves warm median by at least 20 percent or 10 milliseconds, whichever is harder to satisfy for that sample, while retained index bytes remain below 25 percent of the normalized facts bytes and first-query cost does not exceed ten times warm median. Treat noisy improvements as unproven; record the raw median/p95 and repeat. Persistence requires an additional demonstrated process-restart benefit, serialized size below retained in-memory size, and a complete exact invalidation key; otherwise persistence remains out of scope.

## Idempotence and Recovery

Manifest validation, tests, format, Clippy, report generation, and comparison are safe to rerun. Benchmark output uses run-specific files; do not overwrite the blessed baseline. Use a fresh output directory when comparing scan-only and indexed reports.

CompleteValueCache publication is the recovery boundary for runtime builds. A cancellation, panic-safe permit drop, unavailable fact, build-budget excess, or retained-memory excess must leave no ready value. The next request may retry. A ready snapshot value is immutable.

If origin/master advances before worktree creation, fetch and create from the new hash, then update this plan. Once milestone commits exist, do not rebase unless repository instructions permit it and the worktree is clean. Never use git reset --hard or broad checkout cleanup. Preserve unrelated user changes.

If a benchmark query's pinned witness is wrong, inspect the exact checkout and fix the manifest oracle before recording timing; never weaken it to nonempty-only without a specific semantic reason. If a pinned repository is unavailable, record the external failure and continue other in-scope validation, then retry without changing its commit.

If indexed execution differs from scan-only, force both paths on the smallest InlineTestProject, compare the first divergent candidate/budget event, fix the planner/index/accounting root cause, and retain the minimized regression. Do not add a language-specific string fallback.

If a derived relation cannot prove completeness, do not publish it. Keep or restore request-local execution and document why the candidate was not promoted.

The temporary workflow change is recoverable: remove only the added pull_request trigger with apply_patch, validate YAML policy tests, commit, and push. If a run is still active, let its exact SHA finish or cancel it through GitHub after the artifact need is resolved; do not leave the final PR diff with the trigger.

## Artifacts and Notes

Authoritative base at plan drafting:

    origin/master at branch creation = 126d893eb9a6c4d2db4706b616ca7710ce6e0aa4
    issue #920 state = OPEN
    issue updated_at = 2026-07-21T17:57:46Z

Relevant existing commits:

    a283aabd  Refactor CodeQuery planning, profiling, scheduling (#1038)
    4051809a  persisted compact structural facts
    d35b6895  compact graph representation
    035fb569  import pipeline
    9ce0857f  hierarchy/member pipeline
    f4ad4ae9  reference pipeline
    d7285eea  call pipeline
    fb445e0a  benchmark profiling support

The issue comment records a cancelled scan_usages_by_location request and a non-independent search_symbols delay. Those timings are not query_code baselines. They justify explicit workspace hydration, lazy-build, cancellation, abandoned-build, and warm-request boundaries.

Append milestone test transcripts and benchmark tables here. Each benchmark table must name commit SHA, repository/commit, machine/runner, cold contract, case ID, result cardinality, first ms, warm median/p95 ms, scoped/candidate/materialized files/facts, physical bytes/facts, facts hydration/extraction, index/derived build/hit/wait, retained bytes, truncation, and diagnostics.

## Interfaces and Dependencies

No new third-party dependency is expected. Use serde/serde_json already present for benchmark query/oracle DTOs, moka only through CompleteValueCache, crate::hash maps/sets, CancellationToken, CompactRows, and CompactDirectedGraph.

The final benchmark interfaces should include:

    pub enum BenchmarkScenario {
        ...
        QueryCode,
    }

    pub struct QueryCodeBenchmarkCase {
        pub id: String,
        pub workloads: Vec<QueryCodeWorkload>,
        pub query_json: String,
        pub expected_witness_json: Option<String>,
        pub min_results: Option<usize>,
        pub max_results: Option<usize>,
        pub expected_truncated: bool,
        pub expected_diagnostic_codes: Vec<String>,
    }

    pub struct ScenarioReport {
        pub name: BenchmarkScenario,
        pub case_id: Option<String>,
        pub transport: ScenarioTransport,
        pub success: bool,
        pub first_duration_ms: Option<f64>,
        pub warmup_durations_ms: Vec<f64>,
        pub measured_durations_ms: Vec<f64>,
        pub median_ms: Option<f64>,
        pub p95_ms: Option<f64>,
        pub mean_ms: Option<f64>,
        pub query_code: Option<QueryCodeBenchmarkObservation>,
        ...
    }

The exact DTO field spelling may be adjusted during implementation only if the public JSON remains explicit and tests/plan are updated together.

The final posting interfaces should include FactAddress, SnapshotStructuralIndex, SnapshotStructuralIndexCache, StructuralAccessRequirements, StructuralAccessPathEstimate, StructuralIndexAcquisition, and match_query_candidates as described above. Snapshot ownership must be observable through provider acquisition, not a process-global registry.

The final derived interfaces should include SnapshotDerivedLayerCache, DerivedLayerRequest, DirectImportTopology, and IAnalyzer::snapshot_derived_layer_cache. All concrete wrappers must forward the cache owner. The physical plan consumes DerivedLayerRequest; it must not import DirectImportTopology storage internals.

The internal execution selector used by tests/benchmarks must not become user-authored query syntax:

    pub(crate) enum StructuralAccessMode {
        Auto,
        ScanOnly,
        IndexedRequired,
    }

Production query_code uses Auto. Differential tests use ScanOnly and IndexedRequired. The benchmark runner may select ScanOnly through a documented process environment solely for reference measurement, provided production defaults remain Auto and invalid values fail clearly.

Plan revision note, 2026-07-21: initial self-contained draft created after live issue/origin diagnosis. It resolves cold-cache, budget-parity, snapshot-ownership, promotion, review, cleanup, and temporary benchmark workflow decisions so implementation can proceed without reconstructing prior context.

Plan revision note, 2026-07-22: recorded explicit authorization, creation of the issue worktree/branch, and the refreshed origin/master base. The repository copy is now authoritative and Milestone 1 is unblocked.
