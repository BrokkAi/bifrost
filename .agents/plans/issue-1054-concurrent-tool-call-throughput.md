# Uncap concurrent tool-call throughput (issue #1054)

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. This document must be maintained in accordance with `.agents/PLANS.md` at the repository root.

## Purpose / Big Picture

Concurrent tool calls against one workspace cap at ~3 cores on a 24-core box (measured by the MCP property fuzzer at `--jobs 24`: ~240-300% sustained CPU, workers parked in `Mutex::lock_contended`). Any parallel client load — multiple MCP clients, the fuzzer's probe pool, future parallel query scheduling — serializes. After this change, read-only tool calls scale with cores: the fuzzer's `--jobs 24` probe phase should sustain a large multiple of 3 cores and per-call p50 latency under concurrency should drop correspondingly (baseline table in the issue: get_symbol_sources p50 745ms, search_symbols p50 6.5s, scan p50 50s — all inflated by lock-wait).

The cap is a stack of five serializers, ranked by measured impact. This plan removes them in impact order, each independently verifiable:

1. One SQLite connection behind one Mutex for the whole workspace (~60 lock sites), with statement prepare/finalize churn inside the critical section.
2. An exclusive `session.write()` on every call — including read-only tools — whose no-change path only `mem::take`s an already-empty watcher delta.
3. A per-call stat storm: every touched file is `fs::metadata`-validated per call (and `analyzed_live_files` stats every workspace path per scan call), even though the production file watcher already knows exactly which paths changed.
4. Tiny shared `Mutex<BoundedFileCache>` caches (128/32 entries) with an O(n) `VecDeque::retain` on every insert, plus handlers that re-read files from disk that the analyzer already holds in memory.
5. `search_symbols` spawning a `git rev-list` subprocess and re-discovering the git repository on every call.

## Progress

- [x] (2026-07-22) M1 — Store read-connection pool + single-writer routing + statement hygiene. `ReaderPool` (readonly WAL connections, lazy checkout, transient over-capacity burst, capacity = available_parallelism) inside `AnalyzerStore`; 44 pure-read methods routed off the writer mutex; ephemeral workspaces moved to delete-on-drop temp-file DBs (with a single-connection fallback path); statement cache 64 on every connection; `read_unit_rows`/`contains_parsed_blob_conn`/`parsed_blob_keys_conn` on `prepare_cached`; ALL 14 `_bulk` IN-list readers plus the cascade-cost VALUES query padded to fixed arity ladders with NULLs (root-cause generalization of the plan's two named sites). Measured at jobs=24 on the baseline repo (cold index, comparable load): CPU 267%→687%, wall 5:02→2:59, get_symbol_sources p50 719ms→60ms (12x), get_definitions p50 1.8s→369ms, scan p50 51.3s→29.4s; get_summaries (n=77) and search_symbols (n=19) regressed modestly — both sit behind the M4 projection-cache and M5 git-subprocess serializers, next in line. Peak RSS 1.4GB→3.0GB (per-connection page caches + real concurrency). Note: `analyzer_persistence` has a PRE-EXISTING load-correlated flake in the warm-* test family (fails 1-3 tests under heavy box load with or without M1; stash-controlled repetition proved independence) — tracked separately.
- [x] (2026-07-22) M2 — Session read-first locking: has_pending peek, read-lock no-change path, staleness pass reads outside locks. Measured: wall 5:02→42.4s cumulative at jobs=24.
- [x] (2026-07-22) M3 — Liveness stat-validation memoized per snapshot instance (write-once validated flag at snapshot build; invalidation = the pre-existing generation-bump snapshot rebuild, verified for watcher and Manual flows). Zero additional fs::metadata across query contexts, proven by a new stat counter; aggregate wall unchanged on the lookup-dominated benchmark (the remaining stat cost was small there; the win concentrates in scan-heavy/slow-mount workloads).
- [x] (2026-07-22) M4 — Stamped lazy-LRU (O(1) touch + bounded compaction), caps 128→1024/32→128, all 8 handler disk-read sites routed through indexed_source.
- [x] (2026-07-22) M5 — Recent-commit OID list cached per repo keyed by peeled HEAD OID (rev-list spawned only on HEAD movement), discover-root cached per workspace, hoisted HEAD-tree peel; per-cache fill counter keeps the cache-hit test deterministic under parallel execution.
- [x] (2026-07-22) Final: clean canonical measurement on a quiet box at final HEAD (fresh index, same config): jobs=24 wall 5:02→42.5s (267%→1523% CPU), p50 sources 719→26ms, defs 1809→105ms, summaries 450→359ms, scan 51.3s→14.5s, search 4106→2438ms — every tool better than baseline, the M1-era summaries/search regressions erased. jobs=1 wall 14:04→4:00, p50 sources 15→8ms, defs 273→31ms, scan 3166→1727ms — the uncontended case improved 3.5x too. All milestones pushed.

## Surprises & Discoveries

- Observation: the store was *designed* for concurrent access and one concurrent second connection already runs in production.
  Evidence: WAL is already enabled with `synchronous=NORMAL`, 64MB cache, 256MB mmap (`src/cache_db.rs:150-203`); the origin plan (`ANALYZER_SQLITE_STORE_EXECPLAN.md`) states writes are `INSERT OR IGNORE` on content-addressed immutable rows so "concurrent processes on the shared DB are safe under WAL", and the GC coordinator already opens its own `AnalyzerStore::open_persistent` on a background thread (`src/analyzer/store/gc.rs:14`). The `Mutex<Connection>` was a simplicity default, not a correctness requirement.
- Observation: the stack capture's `sqlite3_finalize` signature is explained — the hottest per-file read path bypasses the statement cache entirely.
  Evidence: `read_unit_rows` uses plain `conn.prepare` (`src/analyzer/store/mod.rs:5002`) while candidate-row paths use `prepare_cached`; the per-connection statement cache is left at rusqlite's default 16 slots (no `set_prepared_statement_cache_capacity` call anywhere); `format!`-spliced predicates (~a dozen shapes) and variable-arity `IN (…)` lists (`read_unit_rows_bulk`, chunk sizes up to 900) fragment the cache key space far past 16.
- Observation: the exclusive per-call session write lock does nothing on the no-change path.
  Evidence: `snapshot_for_query` → `apply_watcher_delta` (`src/searchtools_service.rs:1456-1467`, `1537-1573`) locks the session exclusively, then `ProjectChangeWatcher::take_changed_files` (`src/project_watcher.rs:69-78`) locks the watcher's own `Arc<Mutex<PendingChanges>>` and `mem::take`s two empty collections; the session snapshot `Arc` is untouched. The change signal lives entirely behind the watcher's mutex and can be peeked without the session lock.
- Observation: liveness stat-validation re-runs per call despite two existing invalidation signals.
  Evidence: `LiveSnapshot::validated_oid_for_path` calls `FileStat::from_path` (= `fs::metadata`) per path per call (`src/analyzer/store/liveness.rs:322-329, 461-466`); `analyzed_live_files` does it for every live path per scan call (`src/analyzer/tree_sitter_analyzer.rs:3453-3509`). Yet `LivePathMap` already maintains a generation counter bumped on every mutation (`liveness.rs:220, 272, 284`) and the production-default `ProjectChangeWatcher` already reports exactly which files changed. Liveness never touches the SQLite connection, so this workstream is independent of M1.
- Observation: the fuzzer's probe executor is the ready-made concurrency benchmark.
  Evidence: `execute_probes` (`src/mcp_property_fuzzer/service_probes.rs:981-1042`) drives one shared in-process `SearchToolsService` from `--jobs` scoped threads with per-call `elapsed_ms`; profiling scopes (`profiling::scope`) already wrap `apply_watcher_delta`, snapshot updates, summary projection, and relevance; per-analyzer `AtomicUsize` counters (`sql_definitions_query_count`, `workspace_path_scan_count`, …) count the work M1/M3 remove.

## Decision Log

- Decision: single-writer + N-reader connections, hand-rolled checkout pool inside `AnalyzerStore`; no new dependency (no r2d2/deadpool).
  Rationale: the writer keeps the existing `conn: Mutex<Connection>` untouched (all ~20 write paths unchanged, GC claim atomicity preserved); readers are only ever SELECT + the read-only generation check, which maps exactly onto WAL snapshot semantics. A checkout pool is ~50 lines against the existing `open_persistent`/`configure_connection` factory. Reader connections are opened with `SQLITE_OPEN_READ_ONLY`, making "reads cannot write" a compile-enforced invariant of the new API.
  Date/Author: 2026-07-22 / Claude
- Decision: ephemeral/non-git workspaces move from `Connection::open_in_memory()` to a delete-on-drop temp *file* DB so the reader pool works there too.
  Rationale: in-memory SQLite DBs are per-connection (a reader pool would see empty DBs), and shared-cache in-memory mode has table-level locking that is worse than WAL. A temp file with WAL runs at page-cache speed and keeps one code path for pooling everywhere — including the fuzzer's ephemeral mode, which is where the 3-core measurement was taken. Fallback if temp-file lifecycle proves awkward on any platform: keep in-memory single-connection (pool size 0, reads fall back to the writer connection) and accept that ephemeral workspaces don't scale — record it if taken.
  Date/Author: 2026-07-22 / Claude
- Decision: transient reparse-on-read keeps writing through the existing writer connection; no write queue in this plan.
  Rationale: dirty-file reparse is rare in steady state, WAL writers do not block readers, and `INSERT OR IGNORE` on content-addressed rows makes duplicate concurrent persists harmless. A queue adds ordering machinery with no measured need; revisit only if post-M1 profiling still shows writer contention.
  Date/Author: 2026-07-22 / Claude
- Decision: fix variable-arity `IN` lists by padding to a small set of fixed chunk arities with NULL parameters (NULL never matches `IN`), not by adopting the `rusqlite` carray/vtab feature.
  Rationale: fixed arities make the SQL string set finite so `prepare_cached` actually caches; NULL padding is semantics-preserving and dependency-free.
  Date/Author: 2026-07-22 / Claude

## Outcomes & Retrospective

The plan achieved its purpose and then some. Five milestones landed as five commits, each measured. Canonical before/after at final HEAD (quiet box, fresh index, 2,555 probe calls):

    jobs=24: wall 5:02 -> 42.5s, CPU 267% -> 1523%; p50 sources 719->26ms, defs 1809->105ms, summaries 450->359ms, scan 51.3s->14.5s, search 4106->2438ms
    jobs=1 : wall 14:04 -> 4:00, CPU ~101% -> 109%; p50 sources 15->8ms, defs 273->31ms, summaries 146->53ms, scan 3166->1727ms, search 1120->778ms

Every tool improved at both concurrency levels; the transient M1-era summaries/search regressions were exactly the M4/M5 serializers and disappeared when those landed. Lessons: (1) the stack-of-serializers model held — each milestone exposed the next bottleneck, and per-milestone measurement caught the two intermediate regressions immediately; (2) two latent correctness bugs surfaced by the new concurrency were fixed en route (the #1099 GC-vs-warm-build race; a test asserting absolute values of a process-global counter); (3) the biggest design leverage came from reusing existing machinery — WAL was already on, the generation counter already existed, the watcher already knew what changed — the milestones mostly connected what was there. Remaining headroom: scan_usages (14.5s p50 under load) is now the outlier and would be the target of any follow-up; parallel query scheduling (gated off in issue-918 because of the old contention) can be revisited.

Baseline captured (2026-07-22, pre-M1 HEAD, local git-initialized copy of oh-my-openagent, fuzzer probe phase `--invariants I2,I3,I5 --max-service-symbols 300 --max-scan-probes 20 --cache-mode persisted`, 2,555 calls; note: moderate background load from concurrent agent builds, treat as indicative — a clean re-run happens before/after M1 integration):

    jobs=1  : 101% CPU, wall 14:04 | p50 sources 15ms, defs 273ms, summaries 146ms, scan 3.2s, search 1.1s
    jobs=24 : 267% CPU, wall  5:02 | p50 sources 719ms (48x), defs 1.8s (6.6x), summaries 450ms, scan 51.3s (16x), search 4.1s

24x workers bought only 2.8x throughput; under load calls spend ~95% of wall time lock-waiting. Matches the issue's production table shape.

## Context and Orientation

All paths relative to the repository root. Key architecture (verified 2026-07-22):

The per-workspace SQLite DB is `.brokk/bifrost_cache.db`, opened once via `open_unified_connection` (`src/cache_db.rs:84`, WAL + pragma block at `:150-203`, migrations v9) and held as `AnalyzerStore { conn: Mutex<Connection> }` (`src/analyzer/store/mod.rs:183`), shared by every analyzer clone through `AnalyzerStoreContext { store: Arc<AnalyzerStore>, … }` (`src/analyzer/tree_sitter_analyzer.rs:67-74`). All languages in a `MultiAnalyzer` share the one store. Non-git workspaces use `Connection::open_in_memory()` (`store/mod.rs:552`).

Read paths wrap SELECTs in a transaction only to run `require_generation_map` — a read-only staleness check against `analysis_epochs` that on mismatch returns `StoreError::stale_generation`, causing fallback to transient parse (`store/mod.rs:5372-5407`). Hot read families: `declaration_candidate_rows_*` / `definition_lookup_order_*` (symbol lookup), `read_unit_rows`/`read_unit_rows_bulk` (hydration), `search_candidate_rows_*` (search). Writes during steady-state reads: `parse_and_store_transient` when a read hits a dirty file (`tree_sitter_analyzer.rs:3395-3447`) and the `reclaim_stale_generations_conn` tail on each write path.

The service layer: `SearchToolsService.session: RwLock<Option<WorkspaceSession>>`; every tool call runs `snapshot_for_query` → exclusive `write_session()` → `apply_watcher_delta` → clones `Arc<WorkspaceAnalyzer>` + `Arc<WorkspaceRoot>` (`src/searchtools_service.rs:145-173, 1456-1467, 1537-1573`). `get_symbol_sources` takes the write lock a second time for staleness revalidation, reading candidate files from disk under it (`:1483-1491, 273-292`). The stdio MCP server itself is serial; concurrency comes from in-process multi-threaded clients (the fuzzer) and rayon fan-out inside calls.

Liveness: `LivePathMap` (in-memory, generation-counted) → `LiveSnapshot::validated_oid_for_path` stats each path on every call; the per-call `QueryReadCache` (fresh per query context) memoizes within a call only. The production-default `SessionWatcher::Active(ProjectChangeWatcher)` accumulates changed paths in `Arc<Mutex<PendingChanges>>`; `UpdateStrategy::Manual` (fuzzer, differential) has no watcher.

Shared caches: `transient_file_states` (cap 128) and `summary_file_projections` (cap 32), both `Arc<Mutex<BoundedFileCache>>` with `order.retain(..)` on every insert (`tree_sitter_analyzer.rs:865`). Handlers re-read files from disk via `ProjectFile::read_to_string` (raw `fs::read_to_string`) in `src/searchtools/{definitions.rs:79, scan_usages.rs:447,821,1159,1167,2312, navigation.rs:438, summaries.rs:459}` even though `TreeSitterAnalyzer::file_source`/`indexed_source` serve the hydrated in-memory copy.

relevance: `most_important_project_files` (`src/relevance.rs:344`) runs `Repository::discover` + spawns `git rev-list -n 1000` per call (`:1110-1124, 1171-1199`); only the per-commit change cache (moka, keyed by immutable commit OID) is reused across calls.

## Plan of Work

### M1 — Store: reader pool, read-only connections, statement hygiene

In `src/analyzer/store/mod.rs`, add a reader pool to `AnalyzerStore`: a small hand-rolled checkout structure (e.g. `readers: Mutex<Vec<Connection>>` + a capacity bound of `available_parallelism()`, lazily opened via the existing `open_persistent` path with `SQLITE_OPEN_READ_ONLY` and the same `configure_connection` pragmas minus write-side ones; checkout pops or opens, checkin pushes back). Introduce `fn read_conn(&self) -> ReaderGuard` used by the pure-read methods; the writer keeps `self.conn` untouched. Convert the read-method families (`declaration_candidate_rows_*`, `definition_lookup_order_*`, `declaration_member_rows_*`, `read_unit_rows*`, `search_candidate_rows_*`, `hydrate_file_state*`, `summary_file_projection`, `contains_parsed_blob*`, `missing_blobs`, …) to the reader guard; the generation-check transaction pattern carries over per reader connection unchanged (WAL gives each reader tx a consistent snapshot, which is precisely what the tx exists for).

Ephemeral/non-git: replace `Connection::open_in_memory()` with a delete-on-drop temp-file DB (created under the workspace's temp area or `std::env::temp_dir()`, removed in `Drop`; OS-agnostic paths per repo rules) so pooling works uniformly. Keep a graceful single-connection fallback if the readonly open of a temp DB races its creation.

Statement hygiene, same milestone: call `set_prepared_statement_cache_capacity(64)` (or the measured shape count + headroom) on every connection at configure time; convert the remaining hot plain `prepare` sites to `prepare_cached` (start with `read_unit_rows`, `contains_parsed_blob_conn`); replace variable-arity `IN (…)` construction in `read_unit_rows_bulk` and `stored_blob_cascade_costs_sql` with fixed chunk arities padded with NULLs.

Acceptance: all store/analyzer suites green; a new concurrent smoke test (N threads hammering `definitions()`/hydration against one store) passes under `cargo test`; the fuzzer's `sql_definitions_query_count`-style counters unchanged (same work, different lock).

### M2 — Session: read-first locking

In `src/searchtools_service.rs`: give `ProjectChangeWatcher` a cheap `has_pending()` (locks `PendingChanges`, checks both `requires_full_refresh` and `files.is_empty()`). `snapshot_for_query` becomes: peek `has_pending()` (no session lock); if false → `read_session()` and clone the two `Arc`s; if true → `write_session()` → `apply_watcher_delta` as today. The race (events landing between peek and clone) is the same call-boundary consistency the current code has — events that arrive after `apply_watcher_delta` already miss the current call. Apply the same pattern to `get_symbol_sources`' staleness revalidation: compute `stale_symbol_source_files` from a read-locked snapshot (moving the disk reads outside any lock), take the write lock only when the stale set is non-empty.

Acceptance: existing watcher/session suites green (grep for watcher tests around `searchtools_service`); a regression test proving a watcher-reported change is still picked up by the next call; under Manual strategy behavior is unchanged.

### M3 — Watcher-driven liveness validation

In `src/analyzer/store/liveness.rs`: memoize stat-validation on `PathState` (e.g. `validated_at: AtomicU64` stamped with the map's generation, or a validated flag cleared on invalidation). `validated_oid_for_path` returns the cached OID without `fs::metadata` when the stamp matches the current generation. Plumb invalidation: when the session applies a watcher delta (M2's write path), forward the changed paths to `live_paths` so their stamps clear (full-refresh clears all); Manual-strategy updates already rebuild/replace map entries, which bumps the generation naturally. `analyzed_live_files`' full-workspace sweep then collapses to memoized lookups after the first call.

Risk note (record in Decision Log when implementing): watcher event loss is already modeled as `requires_full_refresh`, which must clear all stamps; environments with the watcher Disabled but files changing out-of-band were already broken today only at the same window (they rely on explicit update calls), so semantics do not regress — but verify the differential/fuzzer Manual flows still see updates after their explicit `update_files` calls.

Acceptance: liveness unit tests for stamp/invalidation; watcher end-to-end test (touch file → next call re-validates); measure `workspace_path_scan_count`/stat counts drop across repeated scan calls.

### M4 — Cache hygiene and in-memory source reuse

`BoundedFileCache` (`tree_sitter_analyzer.rs:855+`): make LRU touch O(1) — allow duplicate keys in `order`, lazily discard stale entries during eviction (classic lazy LRU), or switch to a last-touch counter map; raise caps (`transient_file_states` 128 → 1024, `summary_file_projections` 32 → 128) with a Decision Log note on memory tradeoff. Route the handler disk reads listed in Context through `analyzer.file_source(file)`/`indexed_source` instead of `ProjectFile::read_to_string` (each call site names the analyzer already).

Acceptance: suites green; eviction unit test for the lazy-LRU correctness (capacity respected, most-recent survives).

### M5 — relevance: HEAD-keyed git state reuse

In `src/relevance.rs`: cache the ordered recent-commit OID list per repo keyed by the peeled HEAD OID (peeling HEAD via libgit2 is cheap and subprocess-free): on each call, peel HEAD; if unchanged, reuse the cached list — no `git rev-list` spawn; else refill and replace. Cache the discovered repo root per workspace root so `Repository::discover`'s walk happens once (opening by known path per call is fine). The existing moka commit cache stays.

Acceptance: relevance/most_relevant_files suites green; repeated `search_symbols` calls show no `rev-list` spawn (observable via the profiling scope timings; optionally a counter).

### Final — measurement and landing

Baseline before M1 lands, then after each milestone: run the MCP property fuzzer probe phase on one mid-size persisted-mode repo with `--jobs 1` and `--jobs 24`, comparing aggregate probe wall time, per-tool `elapsed_ms` p50/mean, and sustained CPU (the issue's table is the reference shape). Record numbers in this plan. Then the usual gates: `cargo fmt`, `cargo clippy --all-targets --all-features -- -D warnings`, affected suites with `--features nlp,python`, merge `origin/master`, push.

## Interfaces and Dependencies

No new crate dependencies. New/changed surfaces, all internal: `AnalyzerStore::read_conn()` + reader-pool internals and the readonly-connection factory in `src/cache_db.rs`; `ProjectChangeWatcher::has_pending()`; a stat-validation stamp on `liveness::PathState` + an invalidation entry point called from the session's delta application; `BoundedFileCache` touch/evict internals. Public tool behavior is unchanged throughout — this plan is observable only as latency/throughput and identical responses.
