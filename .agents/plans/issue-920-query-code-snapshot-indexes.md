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
- [x] (2026-07-22 09:55Z) Completed Milestone 2 implementation and its three-specialist guided review; fixed construction peak-memory, finalization/selection cancellation, duplicate retained-byte accounting, scoped-versus-admitted telemetry, narrow-scope build cost, live-overlay freshness, and cold-ratio findings.
- [x] (2026-07-22 10:16Z) Captured paired clean-commit Dapper scan-only and Auto reports at commit 4c480b6d; the workspace query reduced warm median from 107.4 ms to 26.0 ms, examined facts from 49,181 to 27, and retained 1,979,756 bytes (16.2% of normalized-facts bytes).
- [x] (2026-07-22 11:04Z) Implemented the measured direct-import topology, snapshot ownership/lifecycle telemetry, typed differential/lifecycle tests, and Ky/Express importer benchmark cases; captured paired scan-only/Auto evidence on both pinned repositories.
- [x] (2026-07-22 11:32Z) Ran the Milestone 3 five-perspective guided review. It confirmed eager first-use Auto admission, duplicated failed-build fallback work, incomplete MultiAnalyzer generation identity, fixed-budget ownership, construction-memory, live-overlay replay, parser strictness, and cleanup findings.
- [x] (2026-07-22 12:19Z) Resolved every confirmed Milestone 3 review finding: request-scoped Auto admission, partial-work fallback reuse, all-delegate generation identity, configured budget ownership, conservative construction preflight, post-replay generation rejection, strict benchmark parsing, and derived-layer-specific public telemetry all pass focused validation and all-target/all-feature Clippy.
- [x] (2026-07-22 12:36Z) Completed Milestone 3 with clean-commit Gson evidence: 262 files/1,005 import edges, 112 exact results, warm median 335.5 to 263.2 ms, first/warm 2.16x, zero warm import resolution, and 20,262 retained bytes (0.44% of the persisted structural-facts payload).
- [x] (2026-07-22 12:50Z) Centralized request-wide retained-value accounting behind a typed census and removed the per-file clone of bulk import facts; all-target/all-feature checking plus focused census and topology tests pass before the final architecture-review fixes.
- [x] (2026-07-22 14:04Z) Completed the post-milestone architecture and benchmark guided review, fixed every confirmed lifecycle, budget, generation, identity, subset, and oracle finding, and centralized snapshot-cache/access-path state behind opaque provider and request-session APIs.
- [x] (2026-07-22 14:04Z) Passed cargo fmt --check, all-target/all-feature Clippy, the complete macOS-configured `cargo test --all-targets --features nlp,python` gate, and all 56 maturin/Python API tests.
- [x] (2026-07-22 14:52Z) Rebased cleanly onto current origin/master `433bc4a2`, rebuilt identity-matched binaries at `b4469d20`, and repeated formatting, Clippy, the complete Rust matrix, and all 56 Python tests successfully. Three final-head Gson scan/Auto pairs preserved correctness and topology hits but produced only 15.23%, 8.15%, and 2.07% warm-median improvements, so the local latency promotion is now explicitly unproven pending the required Ubuntu artifact.
- [x] (2026-07-22 15:40Z) Opened draft PR #1078, captured the authorized PR-event artifact, rejected its synthetic merge-commit identity as non-final, and captured exact-branch Ubuntu Auto run 29932651323 plus scan-only run 29933850688 at `e5057b97`; both covered 10 repositories and 16 correct QueryCode cases with no scenario failures.
- [x] (2026-07-22 15:51Z) Applied the Ubuntu decision: production Auto no longer acquires `DirectImportTopology`, while the forced differential path remains tested. Fixed the discovered cold-contract gap by priming durable structural facts in an untimed scan-only process before starting the fresh measured process; focused structural, benchmark, comparison, manifest, CLI, and end-to-end suites pass.
- [x] (2026-07-22 16:21Z) Committed the Ubuntu-driven correction at `b7409455`, captured corrected exact-head Auto run 29935713091 and scan-only run 29936770096, recorded the final figures, removed the temporary workflow trigger and dispatch selector, and restored the two passing workflow-policy tests.
- [x] (2026-07-22 18:04Z) Rebased the complete 17-commit series onto origin/master `1584751d`, preserving master's structural-search module split across `search/{mod,results,expansions,tests}.rs`. The rebased branch passed formatting, warnings-denied all-target/all-feature Clippy, the complete feature-enabled Rust gate, all 56 Python tests, and final-head service, selector, cross-language, planner, and VS Code suites.
- [x] (2026-07-22 18:04Z) Audited every issue acceptance criterion against current code, differential/lifecycle tests, the corrected exact-head Ubuntu artifacts, and draft PR #1078. The PR is mergeable, temporary workflow controls are absent, production retains only the posting index justified by the Dapper result, and the stale VS Code profile-v1 assertion discovered by CI now verifies the v2 contract locally.
- [x] (2026-07-22 18:19Z) Addressed all platform-specific feedback from CI run 29945261659 without lint suppressions: summary helper re-exports now exist only for their `nlp`/test consumers, and the benchmark test's `json` macro import is Unix-gated with its only callers. Featureless and all-feature Clippy, the affected no-feature summary unit test, and all ten benchmark-run integration tests pass locally; the macOS host cannot complete an MSVC cross-build because `lib.exe` is unavailable, so the refreshed Windows jobs remain the final cross-target verification.
- [x] (2026-07-22 21:10Z) Removed the repository-root issue scratch `.cache`, added the root-only ignore rule, rebased through origin/master `1c07b8ad`, and fixed the benchmark-discovered Scala companion self-type regression with an inline test and an exact `scala-xml` reproduction. The final master delta after measurement changed only the unrelated MCP property-fuzzer plan.
- [x] (2026-07-22 21:10Z) Captured the final-head full Ubuntu artifact from run 29956839833: 10 repositories, 92 successful scenarios, 16 clean QueryCode cases, and no subset markers. Added the ordinary 50 ms absolute noise arm to the 10x cold/warm gate after five clean full runs straddled the ratio boundary by only 1-11 ms; the original eager-build regression still exceeds the combined gate by 91 ms.

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

- Observation: Automatically freezing every `Project` attached to an analyzer made snapshot postings safe but broke the LSP's intentionally live didOpen/didChange overlay. The correct validity boundary is the overlay's monotonic generation, including set, clear, clear-all, and rejected-overlay removal; immutable analyzer generations continue to use generation zero and a fresh cache owner on update.
  Evidence: the first attempted fix failed 6 of 188 `bifrost_lsp_server` tests; generation-keyed cache acquisition then passed all 188 plus `mutable_overlay_generation_invalidates_cached_postings`.

- Observation: Building the Dapper posting index on the first production `Auto` request produced a 348.3 ms first request and 25.7 ms warm median, a 13.53x ratio that failed the plan's 10x retention gate even though warm execution improved materially. Recording one viable scan before building on reuse moved construction into the first warmup and produced 207.2/25.2 ms, or 8.24x, while retaining the build profile as `warmup_transition`.
  Evidence: dirty-tree development reports `.cache/.cache/issue920-dapper-auto-selection-v5/run-20260722T094553Z.json` and `.cache/.cache/issue920-dapper-auto-reuse-v6/run-20260722T094849Z.json`; both must be superseded by a clean-commit report before citation outside this plan.

- Observation: A ratio-only 10x cold/warm check is unstable at the promotion boundary even when the measured access path and result are unchanged. Five clean full Ubuntu runs measured the Dapper workspace case at 9.612x, 9.863x, 10.033x, 9.166x, and 10.323x; the two threshold crossings exceeded the 10x budget by only 1.3 ms and 11.0 ms. The original eager first-use build exceeded that budget by about 91 ms.
  Evidence: Actions runs 29935713091, 29951261998, 29954592246, 29955662059, and 29956839833 plus `query_code_cold_to_warm_ratio_ignores_sub_floor_boundary_jitter`.

- Observation: `scoped_fact_nodes` cannot be counted on a scan-only path without materializing files that exact source anchors excluded. The profile now reports zero when that total is unavailable and separately records `admitted_fact_nodes`, the compatibility-budget denominator available on both scan and indexed paths.
  Evidence: the Dapper scan admitted 49,181 facts after source filtering while the complete indexed scope contained 85,325 facts.

- Observation: The benchmark session intentionally strips the server's internal `BIFROST_QUERY_CODE_ACCESS_MODE`; scan-only benchmark evidence must use the runner contract `BIFROST_BENCHMARK_QUERY_CODE_ACCESS=scan_only`.
  Evidence: the first Ky report under `.cache/issue920-ky-derived-scan` was not scan-only and is invalid; `.cache/issue920-ky-derived-scan-v2/run-20260722T110052Z.json` records the valid scan reference.

- Observation: Express's importer workload meets every conservative derived-layer gate, while Ky demonstrates why the absolute latency arm matters. Express improved warm median by 10.792 ms (66.2%), retained 7,093 bytes, and kept first/warm at 9.10x. Ky improved 52.3% but only 5.69 ms, so it does not independently justify promotion.
  Evidence: `.cache/issue920-express-derived-{scan,auto}` and `.cache/issue920-ky-derived-{scan-v2,auto}` reports.

- Observation: The complete direct-import topology is tiny relative to the already-persisted structural facts but should remain snapshot-local. Express retained 7,093 bytes versus 2,259,214 serialized structural-facts payload bytes (0.31%); no restart-benefit or serialization/invalidation evidence exists for a second persisted layer.
  Evidence: `.cache/issue920/express-js/.brokk/bifrost_cache.db` read-only payload census and the paired Express reports.

- Observation: Auto admission must count complete query requests, not sibling branches inside one composed query. Otherwise two identical import branches turn a one-off request into an eager whole-workspace build and reproduce the cold-start regression the admission policy was designed to avoid.
  Evidence: `deferred_derived_builds` is request-local, while `SnapshotDerivedLayerCache` records one reuse opportunity per generation; the tiny ignored benchmark now proves cold topology `2 misses / 0 builds / 2 fallbacks`, followed by one build and then hits.

- Observation: A failed retained-topology build can preserve exact work for the request-local fallback because both paths use the same `RequestLocalDirectImportGraph`. Charging only the additional fallback work keeps file/edge limits honest and avoids resolving the same imports twice in one request.
  Evidence: `late_topology_edge_limit_reuses_partial_work_for_fallback` matches the scan response and keeps aggregate resolved files/edges within the public request limits.

- Observation: A workspace-wide derived layer cannot use only `MultiAnalyzer::project()` as its source identity; a mutable overlay on any non-primary delegate can change import edges. The cache identity is now the ordered generation vector of every delegate, while update, update_all, and clone-with-project still allocate fresh owners.
  Evidence: `multi_analyzer_tracks_every_delegate_overlay_generation` mutates the TypeScript delegate while Java remains first and observes a rebuild rather than a stale hit.

- Observation: Rebuilding only `bifrost_benchmark` can silently execute an older sibling `target/debug/bifrost` server. The first attempted clean reports showed eager first-request topology builds even though the in-process tests proved request-scoped deferral; rebuilding both binaries restored the expected first fallback and warmup build.
  Evidence: the stale-server Express/Ky reports under `issue920-*-derived-clean-{scan,auto}` and `issue920-express-derived-clean-auto-r2` are invalid and must not be cited. The valid v3/Gson reports were collected only after `cargo build --bin bifrost --bin bifrost_benchmark`.

- Observation: Moving Auto construction into the first warmup exposed a benchmark aggregation gap: `warmup_transition` recognized posting-index builds but discarded derived-layer builds. The benchmark now recognizes both transition families and preserves the complete direct-import build profile.
  Evidence: `warmup_transition_keeps_posting_and_derived_layer_builds` passes, and the clean Gson Auto report records the 262-file/1,005-edge topology build under `warmup_transition` rather than mislabeling it as first or warm work.

- Observation: Express remains a useful small-path corroboration but is too fast for the stricter absolute latency arm to be stable: repeated final-code runs moved its scan warm median between 12.9 and 15.7 ms while Auto stayed near 4.7-4.8 ms. The larger pinned Gson importer case gives decisive promotion evidence without relying on local timing noise.
  Evidence: valid Express v3 reports and the clean Gson pair at `da8862e8`; Gson improves by 72.297 ms while preserving 112 results.

- Observation: The final guided review found stale-generation windows outside the cache primitives themselves: overlay removal incremented its generation after releasing the write lock, posting selection was not revalidated after replay, and partial import fallbacks retained request work without binding it to every delegate generation. The access path now holds mutation and generation publication atomically, carries the full generation vector through selection, and discards request-local rows when that vector changes.
  Evidence: synchronized overlay-reader, post-selection generation-drift, and multi-delegate import-fallback regressions pass in the complete test gate.

- Observation: A benchmark report can be internally correct yet attributed to the wrong source checkout when `bifrost_benchmark` executes a stale sibling `bifrost` binary. Build identity therefore has to be an explicit protocol handshake, not a convention in the runbook.
  Evidence: `BIFROST_BUILD_IDENTITY` is embedded from the binary-affecting checkout state, exposed by CLI and MCP initialization, and rejected by runner tests when missing or stale.

- Observation: Subset benchmark mode cannot produce comparable query_code numbers because its query oracles describe the pinned complete workspace, and an empty JSON witness can vacuously match any result. Subset runs now mark query_code skipped and comparison rejects subset reports; manifest witnesses require a stable nonempty path identity or a positive bounded result count.
  Evidence: subset integration, vacuous-witness rejection, and fake fast-empty MCP-server tests pass.

- Observation: The latest-base scan path is substantially faster than it was at the Milestone 3 checkpoint, and the final-head Gson latency advantage did not repeat the earlier 21.55% result even though the physical lifecycle remained exact. Across three paired runs, scan/Auto warm medians were 192.889/163.505, 189.118/173.696, and 186.967/183.096 ms. Every Auto run built the complete 262-file/1,005-edge topology during warmup and then reported complete hits, zero warm import resolution, 1,005 replayed edges, 112 exact results, no truncation, and no diagnostics.
  Evidence: `.cache/issue920-final-gson-{scan,auto}{,-r2,-r3}` at `b4469d20a5aa1518687f34532b72204d15491343`.

- Observation: A `pull_request` workflow run checks out GitHub's synthetic merge commit even though the Actions run metadata reports the PR head SHA. The build-identity handshake correctly exposed this distinction: PR run 29931038596 reported `681a31b6`, while branch-ref dispatch runs 29932651323 and 29933850688 both reported exact head `e5057b97`.
  Evidence: downloaded artifacts under `/private/tmp/bifrost-920-run-QJK6HK`, `/private/tmp/bifrost-920-auto-wKbZGA`, and `/private/tmp/bifrost-920-scan-ftWxof`.

- Observation: The exact-head Ubuntu pair decisively rejects snapshot retention of `DirectImportTopology`. For `gson-class-importers`, scan-only warm median/p95 was 137.641/140.233 ms while Auto was 240.602/242.950 ms, a 102.962 ms (74.8%) regression despite identical 112-result responses, a complete 262-file/1,005-edge hit, 20,262 retained bytes, no truncation, and no diagnostics.
  Evidence: runs 29932651323 and 29933850688 at `e5057b97ec243d4a08aaef06df5118ceabf92081`.

- Observation: The Ubuntu Auto report also exposed that the serialized cold contract was not actually established. Dapper's first measured workspace query extracted 53 structural-facts files, while the later scan run hydrated 54 persisted files; runner-cache history, rather than the declared state, controlled first-request cost. An untimed scan-only priming process now materializes the durable facts, exits, and leaves a fresh measured process with empty memory but deterministic persisted hydration.
  Evidence: run 29932651323 recorded Dapper first `persisted_hydrations=1/extractions=53`; the corrected local report `.cache/issue920-final-primed-dapper-auto/run-20260722T155105Z.json` records `54/0`, a 9.59x first/warm ratio, and the end-to-end benchmark test asserts hydration without extraction.

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

- Decision: Key each provider-local posting value by representation version plus `Project::analysis_generation`, and verify the generation before publication and selection. Do not freeze live projects automatically.
  Rationale: LSP overlays must remain mutable, while a monotonic generation prevents an old positive or negative posting from serving after an in-place edit. The owner still changes on ordinary analyzer update/update_all/clone-with-project boundaries.
  Date/Author: 2026-07-22 / Codex.

- Decision: Production `Auto` scans the first viable query request, records reuse interest for that exact source-generation vector, and builds on a later viable request. Sibling branches in the same request share the deferral decision. `IndexedRequired` still builds immediately for deterministic differential tests.
  Rationale: This avoids imposing whole-workspace construction on one-shot queries and satisfies the measured first-to-warm retention gate. The benchmark preserves the transition's build work instead of hiding it in discarded warmup observations.
  Date/Author: 2026-07-22 / Codex.

- Decision: Select the smallest scoped posting by exact cardinality, materialize only that term, and filter it against later postings. Keep term cardinalities representation-neutral in the public profile.
  Rationale: The original eager implementation copied every broad posting plus intersections into request-local vectors and had unbounded cancellation gaps. Cardinality-first filtering bounds temporary selection memory and explains the physical choice.
  Date/Author: 2026-07-22 / Codex.

- Decision: Treat WarmReuse as a benchmark execution policy rather than a query-syntax property. Every case runs first, warmup, and measured requests in one session; the label exists only to prove the corpus explicitly covers reuse.
  Rationale: Reuse is observable runner state and cannot honestly be inferred from CodeQuery syntax.
  Date/Author: 2026-07-22 / Codex.

- Decision: Superseded by exact Ubuntu evidence: provisionally promote only `DirectImportTopology` as a snapshot-local derived relation. The checkpoint representative was `gson-class-importers`: warm median fell from 335.459 ms to 263.162 ms, warm import resolution fell from 262 files/1,005 edges to zero, retained memory was 20,262 bytes, and first/warm was 2.16x. Express and Ky were smaller corroborating cases.
  Rationale: Gson passes the 50% physical-work, stricter 20%-or-10-ms latency, 25% retained-memory, and 10x cold/warm gates decisively on the same pinned checkout and machine; the checked-in case makes that evidence reproducible in scheduled runs.
  Date/Author: 2026-07-22 / Codex.

- Decision: Keep owner/member, hierarchy, reference, and call relations request-local. Their current payloads include proof tier, ambiguity, site or call kind, source range, typed endpoints, and partial/unsupported state that a bare dense graph cannot reproduce; no retained-byte or cross-request benchmark passed the promotion gate.
  Rationale: Promotion must preserve the complete public typed payload and exactness state, not only endpoint connectivity. These relations are also more shape-specific and less consistently reused than import topology.
  Date/Author: 2026-07-22 / Codex.

- Decision: Treat the final-head local result as superseding the earlier local confidence claim, but keep `DirectImportTopology` provisionally through the already-required Ubuntu measurement. If the same pinned Ubuntu workload also misses the promotion threshold, remove the retained relation before final handoff rather than citing the older favorable sample.
  Rationale: The topology's correctness, work elimination, and memory bound remain proven, but the plan explicitly requires repeatable latency evidence on the same machine class and forbids retaining a relation on noisy improvement alone.
  Date/Author: 2026-07-22 / Codex.

- Decision: Do not retain `DirectImportTopology` in production Auto. Keep its forced `IndexedRequired` and test-only Auto-admission paths for exact differential and lifecycle coverage, but make normal execution use the request-local import graph. This supersedes the provisional promotion decisions above.
  Rationale: Exact-head Ubuntu Auto regressed the representative Gson warm median by 74.8% versus scan-only, far outside every promotion threshold. Correctness and compactness do not justify retaining a slower relation.
  Date/Author: 2026-07-22 / Codex.

- Decision: Keep structural postings memory-only and leave direct-import topology unselected in production for issue #920.
  Rationale: Posting indexes demonstrate material warm benefit and bounded memory, but no retained layer has demonstrated the additional restart benefit, serialized-size reduction, and durable invalidation key required for persistence. Existing structural facts remain the sole persisted substrate.
  Date/Author: 2026-07-22 / Codex.

- Decision: Establish the benchmark cold contract by running the same correctness-checked query once in an untimed forced-scan process, shutting it down, and only then starting the fresh measured process.
  Rationale: This deterministically retains durable structural facts while emptying all process-local facts, postings, derived layers, and analyzer state. Merely reusing the checkout allowed CI cache history to decide whether first-request work was hydration or extraction.
  Date/Author: 2026-07-22 / Codex.

- Decision: Use branch-ref `workflow_dispatch` for final performance attribution after the authorized PR trigger demonstrates the PR path.
  Rationale: GitHub's PR event checks out a synthetic merge commit. The embedded build identity makes that visible, while branch-ref dispatch produces an artifact whose binary and report identity exactly match the named branch SHA.
  Date/Author: 2026-07-22 / Codex.

- Decision: Account request-wide retained snapshot values through a profile-owned census keyed by both semantic value kind and Arc identity.
  Rationale: Parallel seed branches share retained values, so summing per-branch bytes double-counts memory; including the semantic kind prevents unrelated cached value types from colliding if they have the same allocator address.
  Date/Author: 2026-07-22 / Codex.

- Decision: Make Auto posting admission request-scoped through one `QueryStructuralIndexSession`, and publish reuse observation only after a successful generation-stable request.
  Rationale: Branch-local observations can make a single composed request eagerly build, while failed or stale requests must not train later requests to retain an index.
  Date/Author: 2026-07-22 / Codex.

- Decision: Cache deterministic structural and derived-layer rejections at their honest scope, hand a leader's rejection to current followers, and retain incomparable budget rejections as a Pareto frontier.
  Rationale: Rebuilding an impossible value wastes the same bounded work, but a tighter file budget and a tighter edge budget are not interchangeable and must not suppress a later viable request.
  Date/Author: 2026-07-22 / Codex.

- Decision: Bind benchmark execution to the exact source identity of both local binaries and refuse full-report comparison after `--max-files` subset execution.
  Rationale: Performance evidence is only auditable when the measured server matches the claimed checkout and the candidate and baseline represent the same complete workload.
  Date/Author: 2026-07-22 / Codex.

- Decision: Enforce the 10x QueryCode cold/warm retention limit with the comparator's existing 50 ms absolute timing floor. A candidate is a cold-retention regression only when its first request exceeds both 10x the warm median and that 10x budget by at least 50 ms.
  Rationale: This preserves rejection of the measured eager-build regression while preventing 1-11 ms runner noise from making an otherwise identical full report alternate between pass and fail. It also aligns the invariant with every other benchmark timing comparison's dual-arm policy.
  Date/Author: 2026-07-22 / Codex.

## Outcomes & Retrospective

Milestone 1 is complete. The checked-in manifest now has 16 correctness-checked query cases across all ten pinned languages and all six workload classes, including the representative Gson, Express, and Ky importer workloads added during derived-relation measurement. Each case gets a fresh MCP process, a separately reported first request, two warmups, ten measured requests, full-result stability checking, warm median/p95, and structured work/cache metrics. Failed correctness checks expose no timing samples. Query benchmark code is isolated from the generic runner, the MCP transport has a hard response deadline, and the scheduled job has a hard timeout.

The local pre-index report passed all cases. First/warm median milliseconds were: Gson exact 58.2/8.9, Gson regex 55.8/9.0, Gson containment 65.6/18.3, Gin 35.4/3.9, fmt broad 248.2/178.3, Express 34.8/3.2, Ky typed 29.7/3.3, Click 51.3/6.0, serde_json 25.8/3.2, FastRoute 21.6/1.9, Scala XML 32.8/3.3, and Dapper 69.4/13.0. These are local development-build figures, not the final Ubuntu comparison.

Milestone 2 is implementation- and guided-review-complete. The posting index retains dense `(file_id, fact_id)` rows for kind, name, selective kind/name, exact callee/module role values, kwarg keywords, and compact source-trigram filters; facts and sources remain in their existing caches. Construction preflights fixed allocations, enforces a conservative peak estimate, polls cancellation through source, fact, finalization, census, and selection loops, and publishes only under an unchanged source generation. Forced scan/index tests cover every structural language, RQL/JSON equivalence, nested captures/negation, file/source/fact/pipeline/result cutoffs, update/update_all, add/delete, clones, and mutable overlays. The complete LSP suite remains green.

The clean-commit Dapper pair at `4c480b6d3707d4b380423026ecd0bb8caf6aa9c2` satisfies the Milestone 2 promotion gates. For `workspace-exact-sql-mapper-class`, scan-only first/warm median/p95 was 217.6/107.4/245.1 ms and Auto was 208.9/26.0/26.8 ms, a 4.13x warm-median improvement with an 8.04x first-to-warm ratio. Indexed warm execution reduced candidate/examined facts from 49,181 to 27, materialized facts from 49,181 to 24,269, and inspected source bytes from 1,159,390 to 917,649. The transition warmup built over 157 files and 85,325 facts in 210.9 ms; the retained index was 1,979,756 bytes versus 12,215,566 normalized-facts bytes, or 16.2%. Both paths returned the same 27 results without truncation or diagnostics.

Milestone 3 measurement is complete. `DirectImportTopology` retains compact outgoing/incoming file IDs plus explicit source-support bits, is owned by an analyzer snapshot, and preserves scan-only values, proof/provenance, order, diagnostics, and truncation in forced differential tests. Its clean checkpoint pair passed every threshold, but three final-head local repeats failed to reproduce the required latency gain and the exact-head Ubuntu pair showed a 74.8% warm regression. Production Auto therefore no longer acquires or retains it; the forced path remains for exactness and lifecycle regression coverage. Owner/member, hierarchy, reference, and call relations also remain request-local because their complete typed payload and performance case did not justify promotion.

The post-milestone guided review and final acceptance audit are complete. Cache rejection handoff, atomic overlay generations, request-scoped posting admission, post-replay generation validation, bounded allocation preflight, generation-bound import fallback, Pareto-scoped rejection caching, and opaque provider ownership close the lifecycle and architecture gaps found by the reviewers. Benchmark evidence is protected by a checkout build-identity handshake, strict cache-layer decoding, non-vacuous witnesses, subset-report exclusion, and an environment-variance-independent cold/warm invariant. The initial exact-head Ubuntu artifact exposed one remaining benchmark-contract defect—durable facts were described but not primed—and the failed topology promotion. The corrected exact-head pair proves deterministic hydration, no topology retention, and a posting-index representative that clears every promotion gate. Temporary workflow controls are removed, the branch is rebased onto current master, and the draft PR contains the implementation and validation evidence.

The final-head baseline artifact is `run-20260722T210340Z.json` from Actions run 29956839833 at `3ed81cc526df464b6b9430da0ffa81cc07e03f59`. Its harness passed all 92 scenarios and all 16 QueryCode oracles. The dual-arm comparator accepts the report against itself and still rejects the original 13.53x eager-build sample; the blessed baseline now includes the latest-master Rust timing level rather than carrying a pre-rebase floor into scheduled strict runs.

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

Milestone 2 focused validation before checkpoint:

    cargo clippy --all-targets --all-features -- -D warnings
    # pass
    cargo test --test structural_search_planner --test structural_search_cross_language --test structural_search_python
    # 20 + 27 + 14 pass
    cargo test --test bifrost_lsp_server
    # 188 pass
    cargo test analyzer::structural::index --lib
    # 10 pass after review hardening
    cargo test indexed_ --lib
    # 10 pass, including all-language differential and RQL/JSON parity
    cargo test --test code_query_pipelines --test code_query_public_api
    # 73 + 5 pass
    cargo test --test bifrost_mcp_server --test bifrost_tool_cli --test searchtools_service
    # 20 + 26 + 167 pass, 1 intentionally ignored; rerun outside the sandbox because the linked primary-worktree cache path is read-only there
    BIFROST_CACHE_DIR=<fresh temporary directory> scripts/test_python.sh
    # 56 pass; isolation proved two earlier persisted-store hydration failures came from shared stale cache state, without modifying the primary worktree cache
    cargo fmt --check
    git diff --check
    # pass

Milestone 2 clean local benchmark pair:

    implementation commit = 4c480b6d3707d4b380423026ecd0bb8caf6aa9c2
    repository = DapperLib/Dapper at 72a54c475f75e18cb93cba0809d00a5e6e49efd9
    machine = local Apple arm64 development build
    cold contract = fresh MCP process and analyzer snapshot; empty in-memory query indexes and derived layers; pinned checkout and durable structural-facts store retained; Auto records one viable use before building on reuse
    scan report = .cache/issue920-dapper-clean-scan/run-20260722T101518Z.json
    auto report = .cache/issue920-dapper-clean-auto/run-20260722T101527Z.json
    case = workspace-exact-sql-mapper-class; result cardinality = 27; truncated = false; diagnostics = []
    scan first/median/p95 = 217.6/107.4/245.1 ms
    auto first/median/p95 = 208.9/26.0/26.8 ms; first/median = 8.04x
    scan scoped/admitted/candidate/materialized/examined facts = unavailable/49,181/49,181/49,181/49,181
    auto scoped/admitted/candidate/materialized/examined facts = 85,325/49,181/27/24,269/27
    scan/auto inspected source bytes = 1,159,390/917,649
    transition build = 157 files; 85,325 facts; 12,215,566 normalized-facts bytes; 210.9 ms; no wait/cancel/fallback
    warm index lifecycle = 1 ready lookup; 1 lookup; 1 hit; no miss/build/wait/cancel/fallback
    retained posting bytes = 1,979,756, or 16.2% of normalized-facts bytes

Milestone 3 local typed benchmark pairs (dirty implementation tree, local Apple arm64 development build):

    Ky repository = sindresorhus/ky pinned by benchmark/targets.toml
    case = ky-class-importers; result cardinality = 1; truncated = false; diagnostics = []
    valid scan report = .cache/issue920-ky-derived-scan-v2/run-20260722T110052Z.json
    auto report = .cache/issue920-ky-derived-auto/run-20260722T110001Z.json
    scan first/median/p95 = 46.993/10.875/21.531 ms
    auto first/median/p95 = 37.628/5.184/5.577 ms; warm improvement = 52.3% and 5.691 ms; first/median = 7.26x
    scan warm import work = 52 files / 111 edges; auto warm import work = 0 / 0
    topology build = 52 files / 111 edges / 3.987 ms; retained = 2,876 bytes
    invalid report not to cite = .cache/issue920-ky-derived-scan/run-20260722T105936Z.json

    Express repository = expressjs/express pinned by benchmark/targets.toml
    case = try-render-importers; result cardinality = 1; truncated = false; diagnostics = []
    scan report = .cache/issue920-express-derived-scan/run-20260722T110324Z.json
    auto report = .cache/issue920-express-derived-auto/run-20260722T110359Z.json
    scan first/median/p95 = 68.769/16.306/23.886 ms
    auto first/median/p95 = 50.173/5.514/5.806 ms; warm improvement = 66.2% and 10.792 ms; first/median = 9.10x
    scan first and warm import work = 141 files / 92 edges; auto warm import work = 0 / 0
    topology build = 141 files / 92 edges / 11.089 ms; retained = 7,093 bytes
    persisted structural-facts payload census = 2,259,214 bytes; topology/payload = 0.31%

Milestone 3 focused validation before guided-review fixes:

    cargo test analyzer::structural::execution --lib
    # 21 pass, 2 intentionally ignored
    cargo test --test code_query_pipelines --test code_query_public_api
    # 73 + 5 pass
    cargo test --test benchmark_manifest --test benchmark_compare --test benchmark_workflow_policy --test bifrost_benchmark_cli --test bifrost_benchmark_run
    # 9 + 9 + 2 + 3 + 9 pass
    BIFROST_CACHE_DIR=<fresh temporary directory> scripts/test_python.sh
    # 56 pass
    cargo clippy --all-targets --all-features -- -D warnings
    # pass
    BIFROST_CODE_QUERY_BENCH_SMALL_FILES=2 BIFROST_CODE_QUERY_BENCH_LARGE_FILES=3 BIFROST_CODE_QUERY_BENCH_ITERATIONS=1 cargo test --lib code_query_execution_profile_measurement -- --ignored --nocapture
    # 1 pass after updating the cold-versus-warm snapshot lifecycle contract

Milestone 3 guided-review fix validation:

    cargo check --all-targets --all-features
    cargo clippy --all-targets --all-features -- -D warnings
    # pass
    cargo test topology --lib
    # 11 pass, including Auto admission, partial fallback reuse, lifecycle, and topology memory preflight
    cargo test multi_analyzer_tracks_every_delegate_overlay_generation --lib
    cargo test multi_workspace_derived_cache_uses_configured_budget_share --lib
    # 1 + 1 pass
    cargo test profile_parser --lib
    cargo test public_profile_projects_stable_metrics_and_omits_internal_evidence --lib
    # 4 + 1 pass; missing derived-layer fields are rejected and generic cache layers omit derived-only counters
    cargo test derived --lib
    # 16 pass
    uv run --python 3.12 --with maturin python -m unittest python_tests.test_searchtools_client
    # 56 pass; the direct-import layer decodes to CodeQueryDerivedLayerCacheCounters
    BIFROST_CODE_QUERY_BENCH_SMALL_FILES=2 BIFROST_CODE_QUERY_BENCH_LARGE_FILES=3 BIFROST_CODE_QUERY_BENCH_ITERATIONS=1 cargo test --lib code_query_execution_profile_measurement -- --ignored --nocapture
    # 1 pass with cold deferred fallback, first-reuse build, and later-hit assertions

Milestone 3 final clean representative pair:

    implementation commit = da8862e8be52f6b2ba8a6bbbb6ee9d3a98b0b6e6
    repository = google/gson at ed2397502708ebaba53643e5c3d60e0974d7045f
    machine = local Apple arm64 development build
    case = gson-class-importers; result cardinality = 112; truncated = false; diagnostics = []
    scan report = .cache/issue920-gson-derived-clean-scan/run-20260722T123348Z.json
    auto report = .cache/issue920-gson-derived-clean-auto/run-20260722T123357Z.json
    scan first/median/p95 = 878.521/335.459/539.716 ms
    auto first/median/p95 = 567.408/263.162/353.730 ms; warm improvement = 21.55% and 72.297 ms; first/median = 2.16x
    scan first and warm import work = 262 files / 1,005 edges
    auto first admission = 1 miss / 0 builds / 1 fallback; work = 262 files / 1,005 edges
    auto warmup transition = 1 miss / 1 complete build / 0 fallbacks; build = 262 files / 1,005 edges / 31.299 ms
    auto warm = 1 complete hit / 0 import files / 0 import edges; replayed topology payload = 1,005 edges
    retained topology bytes = 20,262
    persisted structural-facts payload census = 4,648,408 bytes across 262 snapshots; topology/payload = 0.44%

Post-milestone architecture and benchmark validation before rebase:

    cargo fmt --check
    cargo clippy --all-targets --all-features -- -D warnings
    # pass
    RUSTFLAGS='-C link-arg=-undefined -C link-arg=dynamic_lookup' cargo test --all-targets --features nlp,python
    # pass; macOS linker flags match .github/workflows/ci.yml
    bash scripts/test_python.sh
    # 56 pass
    cargo test --lib complete_value_cache
    cargo test --lib derived
    cargo test --lib index
    cargo test --lib structural::search
    cargo test --test benchmark_manifest --test benchmark_compare --test bifrost_benchmark_run
    # all pass, including rejection handoff, generation drift, subset, build identity, strict parser, and fake-empty oracle regressions

Final-head validation and repeatability audit after rebasing onto `433bc4a2`:

    final implementation commit before this plan-only checkpoint = b4469d20a5aa1518687f34532b72204d15491343
    ./target/debug/bifrost --build-identity
    git rev-parse HEAD
    # both b4469d20a5aa1518687f34532b72204d15491343
    cargo fmt --check
    cargo clippy --all-targets --all-features -- -D warnings
    RUSTFLAGS='-C link-arg=-undefined -C link-arg=dynamic_lookup' cargo test --all-targets --features nlp,python
    bash scripts/test_python.sh
    # all pass; Python 56/56

    paired Gson importer reports:
      .cache/issue920-final-gson-scan/run-20260722T144807Z.json
      .cache/issue920-final-gson-auto/run-20260722T144815Z.json
      .cache/issue920-final-gson-scan-r2/run-20260722T144842Z.json
      .cache/issue920-final-gson-auto-r2/run-20260722T144851Z.json
      .cache/issue920-final-gson-scan-r3/run-20260722T144901Z.json
      .cache/issue920-final-gson-auto-r3/run-20260722T144909Z.json
    scan/Auto warm median pairs = 192.889/163.505, 189.118/173.696, 186.967/183.096 ms
    warm improvements = 15.23%, 8.15%, 2.07%; final-head local latency promotion is unproven
    all Auto warm profiles = 112 results, complete topology hit, 0 import files/edges resolved, 1,005 edges replayed, 20,262 retained bytes, no truncation or diagnostics

Initial exact-head Ubuntu pair and decision artifact:

    implementation/workflow commit = e5057b97ec243d4a08aaef06df5118ceabf92081
    Auto run = https://github.com/BrokkAi/bifrost/actions/runs/29932651323
    scan-only run = https://github.com/BrokkAi/bifrost/actions/runs/29933850688
    machine = separate GitHub ubuntu-latest runners; same exact source SHA and pinned target commits
    reports = /private/tmp/bifrost-920-auto-wKbZGA/run-20260722T153113Z.json and /private/tmp/bifrost-920-scan-ftWxof/run-20260722T153939Z.json
    both reports = 10 repositories, 16 successful QueryCode cases, no truncation or unexpected diagnostics
    Gson gson-class-importers scan first/median/p95 = 402.682/137.641/140.233 ms
    Gson gson-class-importers Auto first/median/p95 = 705.617/240.602/242.950 ms
    Auto topology = complete 262-file/1,005-edge build and hit; retained = 20,262 bytes; result cardinality = 112
    decision = reject production DirectImportTopology retention; Auto warm regressed 102.962 ms (74.8%)
    Dapper workspace Auto first/median/p95 = 818.470/49.400/50.098 ms; ratio = 16.57x
    Dapper Auto first facts = 1 persisted hydration / 53 extractions; scan first facts = 54 hydrations / 0 extractions
    contract finding = separate-run cache history controlled first-request extraction, so these first/cold ratios are not final evidence

Local validation after topology non-retention and deterministic facts priming (dirty implementation tree, Apple arm64 development build):

    Dapper scan report = .cache/issue920-final-primed-dapper-scan/run-20260722T155127Z.json
    Dapper Auto report = .cache/issue920-final-primed-dapper-auto/run-20260722T155105Z.json
    Dapper workspace scan first/median/p95 = 205.8/100.0/102.9 ms
    Dapper workspace Auto first/median/p95 = 253.6/26.4/26.7 ms; first/median = 9.59x
    Dapper Auto first facts = 54 persisted hydrations / 0 extractions
    Dapper warm facts = 49,181 scan to 27 Auto; retained posting bytes = 1,975,945 of 13,250,062 build-facts bytes (14.9%); results = 27; no truncation/diagnostics
    Gson scan report = .cache/issue920-final-no-derived-gson-scan/run-20260722T155131Z.json
    Gson Auto report = .cache/issue920-final-no-derived-gson-auto/run-20260722T155057Z.json
    Gson importer scan/Auto warm median = 178.4/181.2 ms; both use request-local 262-file/1,005-edge resolution
    Gson Auto topology lifecycle and retained bytes = all zero; results = 112; no truncation/diagnostics
    focused tests = 67 structural search + 7 QueryCode parser + 10 end-to-end benchmark + 13 compare + 10 manifest + 3 CLI, all pass

Final corrected exact-head Ubuntu pair:

    implementation commit = b74094554a0613ea57e0850353be3d8aa6cd5a5e
    Auto run = https://github.com/BrokkAi/bifrost/actions/runs/29935713091
    scan-only run = https://github.com/BrokkAi/bifrost/actions/runs/29936770096
    Auto report = /private/tmp/bifrost-920-final-auto-hIa3zx/run-20260722T160829Z.json
    scan report = /private/tmp/bifrost-920-final-scan-Kmn8sd/run-20260722T161929Z.json
    both reports = exact embedded SHA, 10 repositories, 16 successful QueryCode cases, 69 first persisted hydrations, 0 first extractions, no cold ratio above 10x
    Dapper workspace scan first/median/p95 = 357.492/182.850/184.623 ms
    Dapper workspace Auto first/median/p95 = 456.401/47.482/48.118 ms; first/median = 9.612x
    Dapper warm improvement = 135.369 ms and 74.03%; examined facts = 49,181 to 27; inspected source bytes = 1,159,390 to 917,649
    Dapper retained posting bytes = 1,975,945 of 12,215,566 build-facts bytes, or 16.18%; result cardinality = 27; no truncation/diagnostics
    production topology activity across every Auto QueryCode phase = zero; Gson importer used request-local 262-file/1,005-edge resolution and returned 112 exact results
    Auto maximum first/warm ratio across the complete corpus = 9.612x
    workflow policy after removing temporary trigger and selector = 2 passed

Invalid local timing artifacts that must not be cited:

    .cache/issue920-ky-derived-clean-auto and .cache/.cache/issue920-ky-derived-clean-scan
    .cache/issue920-express-derived-clean-{scan,auto,auto-r2,scan-r2}
    # These used a stale target/debug/bifrost even though the benchmark runner itself was rebuilt.

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

The final experimental derived interfaces include SnapshotDerivedLayerCache, DerivedLayerRequest, DirectImportTopology, and IAnalyzer::snapshot_derived_layer_cache. All concrete wrappers forward the cache owner. The physical plan consumes DerivedLayerRequest rather than storage internals, but production Auto does not acquire this failed-promotion relation; only IndexedRequired and the test-only admission mode exercise it.

The internal execution selector used by tests/benchmarks must not become user-authored query syntax:

    pub(crate) enum StructuralAccessMode {
        Auto,
        ScanOnly,
        IndexedRequired,
        #[cfg(test)]
        DerivedAutoForTest,
    }

Production query_code uses Auto, which may retain measured structural postings but always keeps imports request-local. Differential tests use ScanOnly and IndexedRequired; derived-layer lifecycle tests additionally use DerivedAutoForTest. The benchmark runner may select ScanOnly through a documented process environment solely for reference measurement, provided production defaults remain Auto and invalid values fail clearly.

Plan revision note, 2026-07-21: initial self-contained draft created after live issue/origin diagnosis. It resolves cold-cache, budget-parity, snapshot-ownership, promotion, review, cleanup, and temporary benchmark workflow decisions so implementation can proceed without reconstructing prior context.

Plan revision note, 2026-07-22: recorded explicit authorization, creation of the issue worktree/branch, and the refreshed origin/master base. The repository copy is now authoritative and Milestone 1 is unblocked.
