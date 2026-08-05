# Restore lightweight semantic active-tree hydration

This ExecPlan is a living document. Keep `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` current. Maintain this file according to `.agents/PLANS.md`.

## Purpose / Big Picture

Bifrost currently hashes every tracked source file before semantic search becomes ready. It then selects cached chunks by blob OID alone. A shared database can contain the same blob at many paths, so this query reads rows outside the active worktree. After this change, clean tracked files use their Git index OIDs without content reads. Each Bifrost session records its exact `(path, OID)` membership in temporary SQLite tables. BM25 statistics remain exact for that worktree. Compressed vectors remain in the shared database and stream from disk during a query.

## Progress

- [x] (2026-08-05) Reconstructed the original Git-index cache contract and identified the exact-byte helper regression.
- [x] (2026-08-05) Measured Kafka against the shared CodeScale cache. OID-only loading selected 300,374 chunks. The exact active relation selected 141,319 chunks.
- [x] (2026-08-05) Proved the proposed temporary SQLite design on the 25 GB cache. It built 6,875 files, 141,319 occurrences, 70,234 vectors, and exact FTS in 1.88 seconds.
- [x] (2026-08-05) Restored semantic Git identity without changing analyzer identity.
- [x] (2026-08-05) Moved active membership, vectors, and BM25 to a read-only-main, temporary-writable SQLite session.
- [x] (2026-08-05) Added exact-membership, independent-session, watcher, connection-mode, and query-plan tests.
- [x] (2026-08-05) Profiled warm Kafka. Active construction now takes 2.19 seconds and materializes zero files.
- [x] (2026-08-05) Ran workspace all-target, all-feature Clippy with warnings denied. It passes.
- [x] (2026-08-05) Ran the featureless gate on the larger disk. 11,756 test executions passed across two runs. Two unrelated tests failed and reproduced outside this change.
- [ ] Commit, push, and rerun the 20-task CodeScale semantic arm.

## Surprises & Discoveries

- Observation: Commit `0e7c9300` changed semantic search from clean index OIDs to exact working-file hashes. The analyzer needs exact bytes for ranges, but semantic search does not share that identity contract.
  Evidence: `crates/bifrost-core/src/gitblob.rs::resolve_index_entry_oid` always calls `Oid::hash_file`.

- Observation: The persistent schema is already correct. `semantic_files` uses `(blob_oid, rel_path)` as its primary key. `semantic_file_chunks` uses the same prefix.
  Evidence: `crates/bifrost-core/migrations/cache/0014-semantic-file-documents.sql` needs no change.

- Observation: SQLite chooses the correct active-first plan after `ANALYZE temp.active_files`.
  Evidence: Kafka reports `SCAN active` followed by `SEARCH chunks USING PRIMARY KEY (blob_oid=? AND rel_path=?)`.

- Observation: A long-lived libgit2 repository can retain an old in-memory index after an external `git add`.
  Evidence: The staged-file test saw the old OID until `Index::read(true)` refreshed the index.

- Observation: The old OID-only store helper was also used by four persistence tests.
  Evidence: The integration suite failed to compile after its removal. The tests now use exact `(OID, path)` materialization checks.

- Observation: An `ORDER BY` on the occurrence insert reversed the useful join order on the large cache.
  Evidence: Kafka spent 25.77 seconds on occurrences with the sort and 0.28 seconds without it. No caller uses occurrence row order.

- Observation: The standard pre-push gate cannot use the nearly full worktree disk for its featureless test links.
  Evidence: The gate failed with `No space left on device` at 2.7 GB free. Its isolated Clippy target was correctly placed on the larger home disk.

- Observation: The featureless gate has two failures outside semantic indexing.
  Evidence: The piped REPL prints its complete result and `bye`, then fails to exit before 30 seconds. It reproduces alone with `BIFROST_SEMANTIC_INDEX=off`. A later run failed `source_and_class_jars_share_declaration_ids_and_keep_distinct_origins`. The two gate runs passed 5,371 and 6,385 tests before fail-fast stopped them.

## Decision Log

- Decision: Keep the persistent schema at version 14.
  Rationale: Existing keys and indexes support exact active joins. Session membership does not belong in shared persistent state.
  Date/Author: 2026-08-05 / Codex and user.

- Decision: Keep analyzer identities exact-byte-based. Add a semantic-specific resolver that uses index OIDs for clean tracked files.
  Rationale: Analyzer byte ranges require exact working bytes. Semantic cache reuse requires cheap Git identities.
  Date/Author: 2026-08-05 / Codex and user.

- Decision: Hash clean paths with active `filter`, `ident`, or `working-tree-encoding` attributes.
  Rationale: These attributes can change semantic content. Ordinary line-ending conversion is canonicalized to LF.
  Date/Author: 2026-08-05 / Codex and user.

- Decision: Do not change `function_document_v1` or rewarm for line-ending normalization.
  Rationale: Existing rows are unpublished local LF materializations. They already match the canonical output.
  Date/Author: 2026-08-05 / Codex and user.

- Decision: Use a read-only main SQLite connection with a writable temporary schema for active state.
  Rationale: It prevents accidental persistent writes and lets SQLite build exact FTS without copying token text through Rust.
  Date/Author: 2026-08-05 / Codex.

## Outcomes & Retrospective

The implementation now keeps all active worktree state in one temporary SQLite schema. The persistent schema remains at version 14. The NLP library passes 58 tests. The semantic-search module passes 10 integration tests. The persistence suite passes 109 tests. Workspace all-feature Clippy passes with warnings denied. Warm Kafka resolves 6,051 semantic paths to 141,319 exact occurrences and 70,234 vectors. Identity resolution takes 0.77 seconds. Active SQLite and Rust construction takes 2.19 seconds. CodeScale evaluation remains in progress.

## Context and Orientation

`crates/bifrost-nlp/src/gitcache.rs` resolves semantic file identities. It currently delegates to the analyzer-oriented exact-byte helper in `crates/bifrost-core/src/gitblob.rs`. `crates/bifrost-nlp/src/store.rs` owns the persistent semantic writer connection. `crates/bifrost-nlp/src/active_index.rs` builds worktree-local vector resolution and BM25 state. `crates/bifrost-nlp/src/indexer.rs` resolves identities, materializes missing files, and publishes the active index. `crates/bifrost-nlp/src/query.rs` streams vectors and combines retrieval signals.

The shared persistent cache stores reusable facts. A session-local active relation stores which cached facts belong to one worktree. The active relation must remain connection-local because different branches and worktrees share one database.

## Plan of Work

First, implement semantic identity in `gitcache.rs`. Build one index map and one worktree-status set for a full build. Use the index OID for a tracked path with no worktree change. Hash dirty, untracked, conflicted, or content-filtered paths. Keep targeted updates proportional to changed paths. Normalize semantic source line endings to LF before document hashing and BM25 tokenization.

Second, add a core SQLite opener that uses read-only flags for the main database but permits writes to the temporary schema. Remove active tables from `SemanticStore`. Make missing-file checks join exact requested `(OID, path)` pairs through batched `VALUES` clauses.

Third, make `ActiveIndex` own the active SQLite connection. Create temporary `active_files`, `active_occurrences`, `active_vectors`, and `bm25_idx` tables. Populate exact occurrences through both OID and path. Run `ANALYZE` on temporary membership tables. Insert FTS tokens with `INSERT ... SELECT` inside SQLite. Load only compact occurrence metadata into Rust. Keep compressed vectors in the persistent table and stream them through the active connection.

Fourth, update watcher changes in one temporary transaction. Remove old FTS rows and occurrence rows. Change path membership. Insert exact new rows. Update only touched vector hashes and Rust occurrence projections.

Finally, add timings for identity resolution and each active-index stage. Validate behavior, run the full repository gate, profile warm Kafka and the 20 shovel-ready tasks, then rerun the semantic evaluation arm.

## Concrete Steps

Run commands from `/mnt/optane/bifrost-nlp`. Use `apply_patch` for edits. Do not use a manually named Cargo target in `/tmp`.

Focused validation:

    uv run --python 3.12 -- cargo test -p brokk-bifrost-core cache_db::tests
    uv run --python 3.12 -- cargo test -p brokk-bifrost-nlp
    BIFROST_SEMANTIC_INDEX=off uv run --python 3.12 -- cargo test --test suite_semantic --features nlp,python
    BIFROST_SEMANTIC_INDEX=off uv run --python 3.12 -- cargo test --test suite_persistence --features nlp,python

Pre-push validation:

    df -h /mnt/optane
    scripts/pre-push-gate.sh
    uv run --python 3.12 -- cargo test --features nlp,python

The pre-push script runs formatting, featureless tests, doctests, and workspace-wide all-feature Clippy. It uses the repository-managed isolated target.

## Validation and Acceptance

Tests must prove clean and staged tracked paths use index OIDs. Dirty, untracked, conflicted, `ident`, and arbitrary filtered paths must use working-byte hashes. CRLF and LF semantic documents must match. Existing analyzer CRLF tests must continue to use exact-byte OIDs.

Two active connections against one database must return only their own paths, vectors, and BM25 results. A decoy path with the same OID must not enter the active corpus. Persistent writes through the active connection must fail. Temporary writes must succeed.

An `EXPLAIN QUERY PLAN` test must show an active-file scan followed by primary-key chunk lookups. Kafka must report 141,319 occurrences and 70,234 vectors. The current analyzer includes 6,051 semantic paths. Warm active construction should complete in less than five seconds on an idle host.

All 20 warm CodeScale profiles must materialize zero files. Semantic activation after analyzer construction must remain below 30 seconds per task. The evaluation uses concurrency 20 and a 1,800 second task timeout. Stop and reduce concurrency if the run causes sustained swap activity.

## Idempotence and Recovery

The change does not migrate or delete persistent data. Temporary active tables disappear when their connection closes. A failed active build leaves the shared cache unchanged. Repeating profiles and tests is safe. Keep the previous CodeScale result directory. Write the corrected run to a new directory.

## Artifacts and Notes

The prototype used `/mnt/T9/repo-clones/.codescale-cache-dw10/bifrost_cache.v14.db`. Its exact Kafka build took 1.88 seconds and 116,268 KiB maximum RSS. The prior OID-only query selected about 2.13 times too many chunk rows.

## Interfaces and Dependencies

`brokk-bifrost-core` adds one SQLite connection helper. It has no new dependency. The helper opens the main file read-only, configures the normal reader cache, and leaves `query_only` disabled so TEMP writes work.

`ActiveIndex` becomes the owner of active vector scanning and active BM25 state. `SemanticStore` remains the persistent materialization writer. The public `semantic_search` tool request and response do not change.

Plan revision note (2026-08-05): Created from the measured CodeScale regression and the approved no-migration design.

Plan revision note (2026-08-05): Recorded the completed implementation and focused validation. Added the stale libgit2 index finding.

Plan revision note (2026-08-05): Recorded the warm Kafka profile, the costly sort, and the low-disk gate recovery.

Plan revision note (2026-08-05): Recorded final Clippy success and the two reproduced featureless gate failures outside semantic indexing.
