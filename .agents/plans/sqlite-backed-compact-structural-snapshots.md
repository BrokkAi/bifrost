# SQLite-backed compact structural snapshots

This ExecPlan is a living document. Keep `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` current as implementation and measurements proceed.

This plan follows `.agents/PLANS.md` and is self-contained for a contributor starting from this checkout.

## Purpose / Big Picture

Bifrost currently extracts normalized structural facts by parsing a file with tree-sitter the first time a structural query touches it. The resulting hot representation is compact and fast: normalized nodes live in a flat arena and semantic roles live in contiguous CSR-style rows. The process-local Moka cache is byte-bounded, however, so facts are discarded at process exit and may be re-extracted after eviction. Meanwhile, the persisted analyzer already stores parsed per-blob facts in `.brokk/bifrost_cache.db`.

This experiment will test a hybrid representation: persist a versioned, packed structural-facts snapshot per Git blob and analyzer language in SQLite, then hydrate that snapshot into the existing in-memory node arena and compact role rows on demand. SQLite supplies durable, content-addressed cold storage and existing cache eviction; the in-memory CSR representation remains the hot traversal format. The observable goal is to eliminate tree-sitter parsing and normalization on a warm persisted workspace while preserving query results and bounded hot memory. The experiment must measure cold write cost, warm hydration speed, database growth, retained heap, RSS, and hot query speed before deciding whether to promote the approach.

A successful implementation can be demonstrated by running an ignored release benchmark twice against the same generated Git workspace. On the baseline, both process lifetimes parse and normalize every requested file. On the candidate, the first lifetime writes snapshots and the second performs zero structural extractions, restores identical fact and role counts, and answers the same role-heavy query. Focused tests must also prove content invalidation, analyzer-generation invalidation, overlay safety, corruption recovery, and cascade/accounting behavior.

## Progress

- [x] (2026-07-15T17:36:49Z) Created and synchronized `experiment-sqlite-backed-compact-graph-snapshots` from `origin/master` at `fce80f1664df0564fc4bef99115439c08bc82f9e`.
- [x] (2026-07-15T18:27:31Z) Fetched and rebased the four experiment checkpoints onto current `origin/master` at `e0cff896`, then restored the in-progress reliability and benchmark edits.
- [x] (2026-07-15T17:36:49Z) Traced the structural-facts cache, persisted analyzer context, blob identity, schema migrations, analyzer epochs, cache GC accounting, compact rows, and the existing memory benchmark.
- [x] (2026-07-15T17:47:00Z) Added an implementation-independent persisted-reopen benchmark, smoke-tested it, preserved the optimized baseline executable, and recorded three 200-file baseline runs.
- [x] (2026-07-15T18:03:00Z) Added snapshot semantic version 1, a packed explicit-code wire DTO, checked compact-row construction, source-aware validation, and round-trip/corruption tests.
- [x] (2026-07-15T18:18:00Z) Added migration 0007 plus current-generation/complete-parent snapshot reads and writes, version replacement, cascade deletion, legacy cost repair, and snapshot-aware row/payload accounting.
- [x] (2026-07-15T18:42:00Z) Integrated best-effort persisted hydration before extraction and write-through snapshots after extraction, with separate counters, in-memory bypass, exact-source identities, and LSP-style overlay isolation tests.
- [x] (2026-07-15T18:27:31Z) Added and exercised focused coverage for warm reopen, content changes, TypeScript/TSX storage keys, generation changes, corruption repair, in-memory bypass, overlay isolation, snapshot cascade, replacement accounting, and legacy cost repair.
- [x] (2026-07-15T18:27:31Z) Ran alternating optimized baseline/candidate measurements at 200 x 50 and 400 x 100, repeated the larger pair in reverse order, and isolated hot CSR reads with a direct role scan.
- [x] (2026-07-15T18:27:31Z) Assessed import, hierarchy, and usage graph lifecycles and recorded the promote/keep-hot/discard matrix in `.agents/docs/sqlite-backed-compact-graph-applicability.md`.
- [ ] Run formatting, focused suites, all-target/all-feature Clippy, and the full `nlp,python` test gate; perform a final diff and design audit.

## Surprises & Discoveries

- Observation: the default structural-facts Moka cache is already bounded to one eighth of the analyzer memo budget, about 32 MiB under the default 256 MiB configuration. The earlier 1+ GiB retained-facts benchmark deliberately used a 2 GiB cache. Therefore SQLite backing is primarily a cold-start and re-extraction optimization, not a replacement for the resident-memory cap.
  Evidence: `TreeSitterAnalyzer::build_structural_cache` and `AnalyzerConfig::memo_cache_budget_bytes`; `tests/measure_structural_facts_memory.rs` explicitly supplies a 2 GiB budget.

- Observation: TypeScript uses distinct persisted language keys for `.ts` and `.tsx`, so the snapshot key must use `LanguageAdapter::storage_language_key_for_file`, not merely the public language label.
  Evidence: the TypeScript adapter's storage-language override and existing blob storage paths.

- Observation: the analyzer epoch fingerprints the crate version, grammar, bundled query files, and language salt, but it does not automatically fingerprint Rust structural normalization rules. A separate explicit structural snapshot semantic version is required even if the binary encoding remains readable.
  Evidence: `src/analyzer/store/epoch.rs`.

- Observation: adding a child table changes more than the schema. Parsed-blob logical-row and payload-byte costs are precomputed for GC, stale-generation reclamation, and capacity admission. Snapshot insertion and deletion must update those formulas and the `blob_payload_costs` materialization.
  Evidence: mutation-cost and cascade-cost SQL in `src/analyzer/store.rs` and migration `0006-analyzer-blob-payload-costs.sql`.

- Observation: on the 200-file baseline, the reopened analyzer builds in about 13 ms because ordinary parsed facts are already persisted, but structural materialization still reparses all 200 files and takes a 142-144 ms range. This cleanly isolates the additional work the snapshot is intended to remove.
  Evidence: three release runs from the preserved `fce80f16` benchmark executable recorded below.

- Observation: the role-heavy query in the second analyzer lifetime was consistently slower than in the first lifetime (about 32 ms versus 5 ms) even though fact/role counts, retained bytes, and extraction counts matched. The persistence candidate must be compared in the same lifecycle positions rather than treating the cold-lifetime query as its baseline.
  Evidence: all baseline and candidate runs reproduced the lifecycle gap. The direct CSR scan later isolated the hydrated representation and showed parity, so the remaining difference is in surrounding reopened provider/source lifecycle.

- Observation: bincode's free `serialize`/`deserialize` functions use a legacy fixed-width configuration that permits trailing bytes, while `DefaultOptions` uses varints and rejects trailing bytes. The snapshot boundary explicitly selects varints, a payload-size read limit, and trailing-byte rejection rather than inheriting either implicit configuration.
  Evidence: bincode 1.3.3 configuration documentation and the corruption tests in `structural::facts`.

- Observation: hydrated facts retain less allocator slack than freshly extracted facts because decoded node and role vectors are allocated at their exact persisted lengths. In the 20-file smoke fixture, estimated retained bytes fell from 530,120 after extraction to 378,920 after hydration while fact and role counts remained exact.
  Evidence: the first successful candidate smoke run recorded below.

- Observation: constructing a persisted workspace directly around an `OverlayProject` does not exercise the same state transition as the LSP. The production request path clones the already-built workspace with an overlay snapshot; testing that actual path proved separate source identities and preserved the disk snapshot.
  Evidence: `WorkspaceAnalyzer::clone_with_project` use in `src/lsp/server.rs` and `request_overlay_snapshot_cannot_replace_committed_structural_facts` in `src/analyzer/workspace.rs`.

- Observation: deferred snapshot upserts occasionally persisted 199 of 200 files while the warm analyzer extracted the missing file. The transaction reads existing snapshot/accounting rows before writing, so a concurrent WAL writer can invalidate a deferred read snapshot and make the upgrade fail with `SQLITE_BUSY_SNAPSHOT`. Acquiring an immediate writer transaction before those reads eliminated the gap in five consecutive 200-file runs and six 400-file runs.
  Evidence: exact snapshot-row and warm-extraction counts from the optimized candidate runs; `AnalyzerStore::upsert_structural_facts_snapshot` now starts `TransactionBehavior::Immediate`.

- Observation: the repeatable 6.7-7.9% larger 400-file reopened role-heavy query median does not come from the hydrated CSR representation. A direct scan of every role row and target measured 0.822 ms for freshly extracted facts versus 0.804 ms for hydrated facts, about 2.2% faster and effectively parity.
  Evidence: three 21-iteration candidate runs; the direct scan was added to benchmark format v2.

- Observation: a separate 2 MiB non-mmap SQLite snapshot reader lowered the benchmark's cumulative cold-plus-warm peak by roughly 15 MiB, but made cold and hydration materialization 5-10% slower and did not improve the hot query. The experiment was reverted.
  Evidence: isolated-reader candidate runs at 400 files x 100 calls compared with the shared-connection candidate.

## Decision Log

- Decision: persist one packed snapshot BLOB per `(blob_oid, storage_language_key, structural_snapshot_version)` rather than one SQL row per node or edge.
  Rationale: structural matching needs complete per-file arenas and contiguous role rows. Row-per-edge storage adds SQLite row/index overhead and many calls while offering no useful selective SQL query. A packed value preserves the hot layout and minimizes database overhead.
  Date: 2026-07-15.

- Decision: reconstruct `source` and `line_starts` during hydration instead of duplicating source text inside the snapshot.
  Rationale: the current file content is already available and its validated Git/blob identity keys the row. Byte spans and compact arrays are the durable payload; line starts are cheap to recompute.
  Date: 2026-07-15.

- Decision: use a stable, explicit wire DTO rather than bincode-serializing domain structs directly.
  Rationale: Rust enum order, `usize`, struct padding, and future domain refactors are not a durable storage contract. The wire format will use checked `u32` offsets/IDs and explicit `u8` codes for kinds and roles, wrapped by a semantic version in the SQL key.
  Date: 2026-07-15.

- Decision: treat persisted snapshots as rebuildable cache data. Read, decode, or write failures must fall back to ordinary extraction; corrupt data must never panic or fail a query.
  Rationale: `.brokk/bifrost_cache.db` is a cache. Correctness must not depend on optional optimization state.
  Date: 2026-07-15.

- Decision: keep the existing in-memory `CompactRows` representation as the query engine format.
  Rationale: SQLite is optimized for persistence and capacity management, while structural queries repeatedly traverse complete rows. The experiment is explicitly hybrid, not SQL-driven graph traversal.
  Date: 2026-07-15.

- Decision: derive the snapshot OID directly from the exact source bytes passed to structural normalization rather than resolving and re-reading a live path.
  Rationale: the content hash is the persisted blob identity and cannot race with a concurrent disk or overlay change. The store only accepts the snapshot if a complete parsed parent exists for that OID, language key, and generation. This is stronger than resolving a path and then assuming it still represents the already-read source.
  Date: 2026-07-15.

- Decision: acquire an immediate SQLite transaction for snapshot replacement.
  Rationale: snapshot replacement reads both the existing snapshot payload and cached blob cost before writing. Reserving the writer slot first avoids WAL read-snapshot upgrade races without changing the best-effort cache semantics.
  Date: 2026-07-15.

- Decision: promote the hybrid only for structural facts; retain compact imports and hierarchy as rebuildable in-memory views, and discard final usage-graph persistence.
  Rationale: structural normalization is expensive, content-addressed, immutable, and repeated across process lifetimes. Import graphs are seed/query/workspace views over already persisted raw facts, the hierarchy CSR rebuild is sub-millisecond, and usage resolution/catalog construction has richer semantic identity while final adjacency compaction previously failed to improve end-to-end metrics.
  Date: 2026-07-15.

## Outcomes & Retrospective

The hybrid is promoted for structural facts. A warm persisted analyzer performs zero tree-sitter structural extractions, reproduces exact fact and role counts, and reduces reopened materialization by 69.0% at 200 x 50 and 73.2% at 400 x 100. The first lifetime pays 16.8-21.1% for serialization and SQLite writes, and the database grows about 37-38%. Hydration constructs exact-capacity arrays, reducing the retained facts estimate about 20% relative to fresh extraction.

Hot CSR reads are at parity: the 400-file direct role scan was 0.822 ms freshly extracted and 0.804 ms hydrated. The larger end-to-end reopened query remained 6.7-7.9% slower depending on run order, so follow-up performance work should inspect provider/source lifecycle rather than change the compact representation or query SQLite directly. Cumulative-process RSS is explicitly non-decisive because the harness reuses one process and `getrusage` includes allocator and SQLite mmap history.

The reusable conclusion is narrower than a universal persisted graph. Structural facts meet the stable content identity, expensive reconstruction, immutable snapshot, and repeated-row-read criteria. Import and hierarchy relations should keep their already-promoted compact hot layouts but rebuild from raw SQLite facts; usage persistence should target a future measured stable resolver intermediate, not the final calibrated graph. The detailed matrix is in `.agents/docs/sqlite-backed-compact-graph-applicability.md`.

The implementation remains rebuildable cache state with public APIs unchanged. A corrupt, missing, stale, or unsupported snapshot falls back to correct extraction and best-effort repair. The remaining acceptance work is the full repository validation and final diff audit.

## Context and Orientation

`src/analyzer/structural/provider.rs` defines `StructuralSearchProvider` and owns `StructuralFactsCache`. A `TreeSitterAnalyzer<A>` implementation reads current source and calls `extract_file_facts` on a cache miss. `structural_extraction_count` counts parse-and-normalize runs and is therefore the most direct correctness metric for persisted hydration.

`src/analyzer/structural/facts.rs` defines `FileFacts`, `NormalizedNode`, `RoleTarget`, and `Span`. Nodes form a pre-order arena addressed by `u32`; roles are grouped by source fact in `crate::compact_graph::CompactRows<RoleTarget>`. `src/analyzer/structural/extract.rs` constructs this representation from a tree-sitter parse. `FileFacts::estimated_bytes` feeds the Moka weigher.

`src/analyzer/tree_sitter_analyzer.rs` owns both `AnalyzerStoreContext` and the structural cache. `resolve_live_oid_for_file` obtains the content identity while respecting overlays, liveness, live filesystem paths, and Git index state. `LanguageAdapter::storage_language_key_for_file` supplies the exact persisted language key. These existing methods should be exposed through narrow crate-private helpers rather than reimplementing identity logic in the structural module.

`src/analyzer/store.rs` and its submodules implement the SQLite store. The root `blobs(blob_oid, lang)` row is generation-scoped; child tables cascade when a blob is removed. `src/cache_db.rs` owns ordered migrations, now through version 7. Migration 0006 added `blob_payload_costs`, which avoids repeatedly summing all child payloads; migration 0007 adds structural snapshots. Snapshot writes preserve this accounting, and fallback cost SQL includes snapshots for legacy or repaired rows.

`tests/measure_structural_facts_memory.rs` is the retained-hot-memory benchmark from the compact graph work. This experiment adds a separate persisted-reopen benchmark because the existing fixture uses a non-Git `TestProject` and intentionally retains every `Arc<FileFacts>` in a single process. The new harness will initialize and commit a deterministic Git workspace, open it through `WorkspaceAnalyzer::build_persisted`, materialize structural facts, drop the workspace, reopen it, materialize again, and query SQLite directly for snapshot size when the candidate table exists.

The prior representation experiments and their measurements are recorded in `.agents/plans/issue-748-compact-graph-experiments.md`. They established that compact structural roles, import CSR/CSC, and hierarchy reverse CSR are valuable hot representations, while compacting the final usage weighted adjacency did not materially improve end-to-end memory or latency.

## Plan of Work

Milestone 1 establishes measurement before implementation. Add `tests/measure_structural_facts_persistence.rs`, an ignored integration benchmark with environment-controlled file count, calls per file, iterations, and parallelism. Generate TypeScript sources, initialize a Git repository, commit them while excluding `.brokk`, and use a large structural cache so both lifetimes retain comparable facts. Report build and materialization times for cold and reopened analyzers, extraction counts, fact/role counts, estimated retained bytes, role-heavy query medians, peak RSS checkpoints, database file size, and conditional snapshot row/payload totals. Emit one versioned JSON record. Compile and run this benchmark in release mode at a small smoke scale and at a representative scale. Preserve the baseline executable or results so the baseline and candidate can be alternated after implementation. Commit the plan, benchmark, and recorded baseline as the first checkpoint.

Milestone 2 defines a durable, validated serialization boundary. Add a crate-private version constant and packed DTOs close to `FileFacts`. Convert domain values to explicit integer codes and checked `u32` byte offsets. Store normalized node rows, role offsets, and role targets; omit source and line-start data. Decode against the supplied source and reject unknown codes, oversized files, invalid UTF-8 boundaries, invalid spans, non-monotonic offsets, mismatched row counts, out-of-range node IDs, invalid parents, and invalid subtree bounds. Add a checked compact-row constructor so corrupted persistence cannot trigger assertions. Round-trip representative extracted facts and exercise malformed payloads. Commit this independently before SQLite integration.

Milestone 3 adds SQLite persistence and accounting. Create migration `migrations/cache/0007-structural-fact-snapshots.sql` with a cascading foreign key to the parsed blob identity and a primary key that includes snapshot version. Bump and test the migration registry. Add generation-aware `AnalyzerStore` methods to fetch and upsert the packed payload. Reads must only return rows for a current, complete blob. Writes must be atomic, update or repair `blob_payload_costs`, and correctly account for replacement size. Update stored-cascade and fallback-cost SQL to include the optional child row and bytes. Tests must cover migration, read/write/replacement, stale generations, cascade deletion, and logical/payload cost changes. Commit the storage layer before provider integration.

Milestone 4 integrates the hybrid path. Give `TreeSitterAnalyzer` narrow helpers that resolve current blob identity and storage language. On an in-memory Moka miss, attempt to fetch and decode a current snapshot. Count hydration separately from extraction so tests and benchmarks distinguish them. If absent or invalid, parse and normalize normally, encode the result when possible, and best-effort upsert it. Never persist an overlay under an unrelated Git identity; rely on the live-OID resolver's source-derived identity and only write when the parsed blob root exists for that identity/language/generation. In-memory analyzer stores should behave as before without avoidable serialization. Preserve the source-hash validation on the hot cache. Add analyzer-level tests for warm reopen, unchanged results, source edits, overlays, corruption recovery, and languages with distinct storage keys. Commit once focused tests pass.

Milestone 5 measures and decides. Run optimized baseline and candidate executables in alternating process order at at least two deterministic fixture sizes. Record raw JSON and medians for cold build/materialization, warm build/hydration, hot query, extraction/hydration counts, database growth, retained bytes, and RSS. The promotion bar is exact output parity and zero reopened extraction for snapshot-backed files, with a substantial warm materialization improvement and tolerable first-run write/database overhead. If per-file SQLite transactions dominate cold cost, investigate a bounded batch writer or a store transaction API, then repeat measurements; do not hide a poor result behind microbenchmarks.

Finally, audit other graph families. Imports already persist raw `import_details`; their PageRank graph is a seed-induced two-hop view and the RQL graph is query-local, budgeted, and diagnostic-bearing, so persist a derived graph only if measured construction cost warrants a stable cache key. Hierarchy raw supertype/child relationships are already persisted while the reverse CSR is a lazy exact-identity workspace view; measure its build share before proposing another snapshot. Usage ranking depends on resolver/catalog state and the prior final-adjacency experiment saved less than 1 MiB without end-to-end benefit, so consider persistence only at an expensive stable intermediate. Record a promote/defer/discard matrix with evidence rather than generalizing the structural result automatically.

## Concrete Steps

Run commands from `/Users/dave/.codex/worktrees/1d60/bifrost`.

1. Format and smoke-test the new baseline harness:

       cargo fmt --all -- --check
       BIFROST_STRUCTURAL_PERSIST_BENCH_FILES=20 BIFROST_STRUCTURAL_PERSIST_BENCH_CALLS_PER_FILE=10 BIFROST_SEMANTIC_INDEX=off cargo test --release --test measure_structural_facts_persistence -- --ignored --nocapture

2. Record the representative baseline and preserve the executable or raw JSON under `/private/tmp` for post-change alternating runs:

       BIFROST_STRUCTURAL_PERSIST_BENCH_FILES=200 BIFROST_STRUCTURAL_PERSIST_BENCH_CALLS_PER_FILE=50 BIFROST_STRUCTURAL_PERSIST_BENCH_ITERATIONS=7 BIFROST_SEMANTIC_INDEX=off cargo test --release --test measure_structural_facts_persistence -- --ignored --nocapture

3. During implementation, run the smallest relevant unit/integration suites after each milestone. The expected commands will include:

       cargo test compact_graph
       cargo test structural::facts
       cargo test --test analyzer_persistence structural
       cargo test cache_db
       cargo test analyzer::store

4. Run candidate benchmarks in fresh processes, alternating with the preserved baseline binary and using identical environment variables. Capture every JSON line and summarize medians in this plan.

5. Before the final checkpoint, run the repository gates:

       cargo fmt --all -- --check
       scripts/with-isolated-cargo-target.sh cargo clippy --all-targets --all-features -- -D warnings
       scripts/with-isolated-cargo-target.sh cargo test --features nlp,python

## Validation and Acceptance

Correctness is accepted when structural query outputs and fact/role counts match extraction, reopened persisted analyzers report zero extractions for valid snapshots, and invalidation tests prove that changed content or semantics cannot reuse stale data. Corrupt and unknown-version rows must trigger safe re-extraction. Overlay content must never poison the committed blob's row. Snapshot rows must disappear with their parent blob and must be represented in both logical-row and payload-byte accounting.

Performance is accepted only from optimized, fresh-process A/B runs. Report medians and raw ranges, not a single favorable run. Warm materialization should improve materially because parsing is eliminated. Hot role-query time and retained facts size should remain at parity because both paths converge on the same `FileFacts` representation. First-run regression, snapshot payload size, total DB growth, and write amplification must be explicit. If the result is workload-dependent, leave the mechanism experimental or disabled by default and state the threshold.

The broader design is accepted when the final plan contains an evidence-backed table for structural facts, imports, hierarchy, and usage graphs. Each row must name the stable persisted identity, reconstruction cost, lifecycle, hot representation, and promote/defer/discard outcome.

## Idempotence and Recovery

The benchmark creates a fresh temporary Git workspace unless an explicit path is supplied, so reruns are independent. Persistence writes use upsert semantics and are safe to repeat. Migration 0007 is transactional through the existing migration runner. If a snapshot is corrupt or from an unknown version, the provider ignores it and extracts correct facts. A successful write deletes other semantic versions for that blob before storing the current version, preventing rebuildable rows from accumulating.

If a benchmark or test is interrupted, rerun it. Use `scripts/with-isolated-cargo-target.sh` for isolated full gates so temporary targets are removed. Do not manually create named Cargo target directories. Check `git status --short` before each checkpoint and stage only files belonging to the milestone.

## Artifacts and Notes

The optimized baseline executable is preserved at `/private/tmp/bifrost-structural-persist-baseline-fce80f16`. It was built from `fce80f1664df0564fc4bef99115439c08bc82f9e`. Each run used 200 generated TypeScript files, 50 calls per file, seven query iterations, one analyzer worker, and semantic indexing disabled.

Baseline raw summary, in run order:

| Run | cold build ms | cold materialize ms | cold query ms | warm build ms | warm materialize ms | warm query ms | cold/warm extractions | DB MiB | peak RSS cold/warm MiB |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 265.058 | 127.592 | 5.183 | 12.908 | 144.122 | 31.925 | 200 / 200 | 10.9 | 84.2 / 90.7 |
| 2 | 264.713 | 128.949 | 5.329 | 13.002 | 143.159 | 32.268 | 200 / 200 | 10.9 | 83.6 / 89.8 |
| 3 | 263.453 | 127.532 | 5.358 | 12.873 | 142.370 | 32.565 | 200 / 200 | 11.0 | 84.1 / 90.4 |
| median | 264.713 | 127.592 | 5.329 | 12.908 | 143.159 | 32.268 | 200 / 200 | 10.9 | 84.1 / 90.4 |

All runs produced exactly 142,200 normalized facts, 70,000 semantic roles, and 22,603,600 estimated retained bytes in both lifetimes. The baseline has zero snapshot rows and bytes. The small 20-file smoke run also passed and extracted 20 files in each lifetime.

The first candidate smoke run used 20 files x 10 calls. Cold extraction wrote 20 snapshots in 5.392 ms; reopened materialization hydrated all 20 with zero extractions in 2.265 ms. Facts and roles remained 3,020 and 1,400. Snapshot payload was 66,060 bytes, total database size grew from the baseline smoke's 417,792 bytes to 516,096 bytes, and estimated retained facts fell from 530,120 cold bytes to 378,920 hydrated bytes. Representative alternating results follow.

Representative 200-file A/B used 50 calls per file, seven query iterations, one analyzer worker, and alternating fresh processes. The baseline medians below are from three paired runs under the same thermal conditions; the candidate is the median of five runs after the immediate-transaction reliability fix.

| Variant | cold build ms | cold materialize ms | cold query ms | warm build ms | warm materialize ms | warm query ms | warm extractions | snapshot payload MiB | retained warm MiB | DB MiB |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| baseline | 273.937 | 132.621 | 5.488 | 12.823 | 140.420 | 33.407 | 200 | 0 | 21.6 | 10.9 |
| hybrid | 272.971 | 154.946 | 7.029 | 13.053 | 43.573 | 33.831 | 0 | 3.67 | 17.3 | 14.9-15.0 |

At this scale the hybrid makes reopened materialization 69.0% faster, makes cold materialization 16.8% slower, leaves the lifecycle-matched warm query within 1.3%, reduces estimated retained facts 19.9%, and grows the database about 37%.

Representative 400-file A/B used 100 calls per file. Three baseline-then-candidate pairs produced these medians:

| Variant | cold build ms | cold materialize ms | cold query ms | warm build ms | warm materialize ms | warm query ms | warm extractions | snapshot payload MiB | retained warm MiB | DB MiB |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| baseline | 980.470 | 519.783 | 77.161 | 30.342 | 539.081 | 104.570 | 400 | 0 | 86.2 | 42.2 |
| hybrid | 977.801 | 629.273 | 84.656 | 30.451 | 144.334 | 111.590 | 0 | 15.50 | 68.7 | 58.1 |

At this scale the hybrid makes reopened materialization 73.2% faster, makes cold materialization 21.1% slower, reduces retained facts 20.3%, and grows the database 37.7%. A three-pair reverse-order check measured 102.10 ms baseline versus 110.13 ms hybrid for the warm role-heavy query, confirming a 7.9% lifecycle-level difference. Three 21-iteration representation-only scans measured 0.822 ms freshly extracted versus 0.804 ms hydrated, so the compact rows themselves remain at parity.

Peak RSS values are retained only as diagnostic context. At 400 files, the baseline cumulative cold/warm high-water medians were 236.4/245.1 MiB and the hybrid values were 249.2/273.8 MiB. Because the same process performs both lifetimes and `getrusage` never decreases, those values combine cold allocator state, SQLite mmap, and warm values; they are not a fresh-process retained-memory comparison.

Reliability check: before the immediate transaction, two of the first three representative runs wrote 199/200 rows and performed one warm extraction. After the change, five consecutive 200-file runs and six consecutive 400-file runs wrote the exact expected row count and performed zero warm extractions.

The current-source post-rebase v2 smoke run again produced 20/20 snapshots, zero warm extractions, exact 3,020 facts and 1,400 roles, and 66,060 payload bytes. Benchmark format v2 adds `direct_role_scan_median_ms`; preserved baseline binaries remain format v1 and print the checkout's runtime HEAD, so provenance must use the preserved-binary filename and recorded build commit rather than that JSON field alone.

Keep transient executables and bulky raw logs in `/private/tmp`; keep durable conclusions in this plan. If a reusable operator/developer note is needed, place it under `.agents/docs/`, not public `docs/`.

## Interfaces and Dependencies

The experiment should leave the public API unchanged. Expected crate-private interfaces are:

- `FileFacts::encode_snapshot() -> Result<Vec<u8>, StructuralSnapshotError>` and `FileFacts::decode_snapshot(source: String, payload: &[u8]) -> Result<FileFacts, StructuralSnapshotError>`, or equivalently named free functions in `structural::facts`.
- `CompactRows::try_from_parts(offsets: Vec<usize or u32>, values: Vec<T>) -> Result<CompactRows<T>, ...>` for untrusted decoded rows, while trusted builders retain the concise constructor.
- `AnalyzerStore::load_structural_facts_snapshot(...)` and `AnalyzerStore::upsert_structural_facts_snapshot(...)`, keyed by blob OID, exact storage language key, current generation, and semantic version.
- A hydration counter alongside `structural_extraction_count`, kept crate/test-facing unless external diagnostics demonstrate value.
- Narrow `TreeSitterAnalyzer` helpers for current persisted blob identity and exact storage language key, reusing `resolve_live_oid_for_file` rather than duplicating its rules.

Use the existing `bincode` dependency for the packed DTO envelope unless measurements demonstrate unacceptable overhead. Use existing `rusqlite`, cache DB migration, and `AnalyzerStoreContext` infrastructure. Do not introduce a graph database or SQL traversal layer.
