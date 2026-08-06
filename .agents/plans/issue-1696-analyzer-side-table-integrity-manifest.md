# Generalize analyzer side-table integrity metadata

This ExecPlan is a living document. Keep `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` current.

Maintain this document according to `.agents/PLANS.md`.

## Purpose / Big Picture

Bifrost stores parsed analyzer facts in typed SQLite tables. The shared `blob_meta` row also has one count column for each optional language-specific table. That design makes all cached files pay for columns that most languages never use. It also missed newer tables, so deletion of Scala exports or materialization records can pass the integrity check.

After this change, common counts stay in `blob_meta`. Optional analyzer facts use a sparse manifest row only when a blob has such facts. Stable numeric fact identifiers let new analyzers add integrity coverage without another `blob_meta` column. Tests show that all supported optional tables detect missing rows and that old version 15 caches migrate without data loss.

## Progress

- [x] (2026-08-06 10:20Z) Inspected the worktree, current remote head, schema, write paths, read paths, and integrity tests.
- [x] (2026-08-06 10:45Z) Measured the current version 15 cache and a sparse manifest prototype.
- [x] (2026-08-06 12:05Z) Added migration 0016 and migration-preservation tests.
- [x] (2026-08-06 12:20Z) Replaced language-specific Rust count fields with the sparse manifest.
- [x] (2026-08-06 12:35Z) Added round-trip and corruption tests for all optional fact types.
- [x] (2026-08-06 12:50Z) Measured storage and metadata-read behavior after the implementation.
- [x] (2026-08-06 14:25Z) Ran focused tests, formatting, clippy, and repository policy checks. All 51 core cache tests and 78 analyzer store tests pass.
- [x] (2026-08-06 14:20Z) Completed five specialist reviews and corrected all migration, performance, test, and architecture findings.

## Surprises & Discoveries

- Observation: The current integrity condition checks C++ template metadata, Ruby dispatch modes, and Scala traits. It does not check Scala exports or materialization records.
  Evidence: `PARSED_BLOB_INTEGRITY_CONDITION` in `crates/bifrost-analysis/src/analyzer/store/mod.rs` has only the first three optional tables.

- Observation: On the available cache, removing three integer columns saves two 4 KiB pages after repacking. A five-kind sparse manifest uses three pages.
  Evidence: The prototype had 100 manifest rows, 5,575 payload bytes, and 12,288 allocated bytes. The rebuilt `blob_meta` saved 8,192 allocated bytes.

- Observation: The first migration can use only SQLite SQL. A compact encoded blob would need custom decode functions for SQL integrity checks and for migration from existing rows.
  Evidence: `crates/bifrost-core/src/cache_db.rs` applies raw migration files through `execute_batch` and `rusqlite_migration`.

- Observation: The migrated representative cache uses 8,192 fewer allocated bytes for `blob_meta` plus optional metadata, before file reclamation.
  Evidence: `blob_meta` changed from 159,744 to 139,264 bytes. The new manifest uses 12,288 bytes. The database page count stayed 128,020 and the freelist increased from 63,984 to 64,006.

- Observation: The final joined metadata projection adds less than one microsecond to a synthetic point metadata read.
  Evidence: Three 200,000-read runs took 0.20, 0.20, and 0.21 seconds on version 15. Version 16 took 0.34, 0.36, and 0.36 seconds. The mean increase is approximately 0.75 microseconds per read. Version 16 also counts materialization rows that version 15 omitted.

- Observation: Scala export facts do not also create language-neutral materialization records.
  Evidence: The corruption test found zero materialization rows for the Scala export fixture. A TypeScript export fixture supplies this fact family.

## Decision Log

- Decision: Use a sparse relational manifest, not a generic fact table or an encoded blob.
  Rationale: Facts remain in typed tables. The manifest holds only nonzero expected row counts. SQLite can migrate and validate it without application-specific functions.
  Date/Author: 2026-08-06 / Codex

- Decision: Assign stable numeric identifiers to C++ template metadata, Ruby dispatch modes, Scala traits, Scala exports, and materialization records.
  Rationale: Numeric identifiers are compact and do not couple the schema to Rust enum names. Existing identifiers never change.
  Date/Author: 2026-08-06 / Codex

- Decision: Keep common side-table counts inline in `blob_meta`.
  Rationale: These counts occur for many languages and serve hot cost and hydration queries. Moving all counts would add joins and rows without meeting issue #1696.
  Date/Author: 2026-08-06 / Codex

- Decision: Treat the change as schema generalization, not a promise of immediate file reduction.
  Rationale: The current sample has a small net allocation increase. Sparse metadata prevents every future optional fact type from adding a zero column to every blob.
  Date/Author: 2026-08-06 / Codex

- Decision: Make the manifest a child of `blob_meta`, and allow all positive fact identifiers.
  Rationale: Metadata deletion must remove its manifest. New fact identifiers must not require a schema constraint change. The current reader rejects unknown identifiers.
  Date/Author: 2026-08-06 / Codex

- Decision: Generate integrity and hydration SQL from one analyzer fact descriptor registry.
  Rationale: One registry keeps the stable identifier, typed table, result order, and dense in-memory slot aligned.
  Date/Author: 2026-08-06 / Codex

## Outcomes & Retrospective

The implementation is complete. Version 16 replaces three language-specific `blob_meta` columns with a sparse manifest. It adds integrity coverage for Scala exports and materialization records. Migration, round-trip, corruption, formatting, and clippy checks pass. Five specialist reviews have no remaining findings. The policy pack completed reliably. Its changed-file findings have stable pre-existing IDs and do not touch this change.

## Context and Orientation

The cache schema starts in `crates/bifrost-core/migrations/cache/0001-current-baseline.sql`. Later numbered files update it. `crates/bifrost-core/src/cache_db.rs` lists every migration and gives the cache file a schema version.

`blob_meta` has one row for each parsed content object and language. A side table stores repeated facts, such as ranges or Scala exports. An integrity count is the expected row count for one side table. During cache reads, Bifrost compares expected and actual counts. A mismatch makes the parsed blob incomplete and causes safe reconstruction.

The main persistence code is `crates/bifrost-analysis/src/analyzer/store/mod.rs`. `PersistedSideTableCounts` carries expected counts. `PARSED_BLOB_INTEGRITY_CONDITION` validates persisted rows. Point and bulk hydration then compare loaded row counts with metadata.

The new `blob_optional_fact_manifest` table stores `(blob_oid, lang, fact_kind, row_count)`. It has no row when an optional count is zero. `fact_kind` is a stable integer. The typed fact tables remain unchanged.

## Plan of Work

First, add migration 0016. Create the sparse manifest with a foreign key to `blobs`. Copy each nonzero C++, Ruby, and Scala-trait count from `blob_meta`. Derive Scala-export and materialization counts from their typed tables. Rebuild `blob_meta` without its three language-specific columns. Preserve its primary key, checks, foreign key, and `WITHOUT ROWID, STRICT` properties.

Update `crates/bifrost-core/src/cache_db.rs` to register migration 0016 and set the current version to 16. Extend migration tests with populated version 15 data. Verify that every optional count becomes the correct manifest row, zero counts create no row, common metadata stays unchanged, and foreign-key validation passes.

Next, define one Rust optional-fact registry near `PersistedSideTableCounts`. Give each optional type its stable identifier and expected count. Write only nonzero manifest rows. Read the manifest for point and bulk hydration. Remove C++, Ruby, and Scala-specific fields from `blob_meta` SQL and Rust raw-row structures.

Update `PARSED_BLOB_INTEGRITY_CONDITION` so each required optional typed table compares its actual count with `COALESCE` of the matching manifest count and zero. This must cover all five identifiers. Keep `PARSED_BLOB_COMPLETE_CONDITION` as the cheap marker check. Full presence checks and post-hydration comparisons remain the corruption boundary.

Update logical-row cost queries to sum optional manifest counts and include materialization records. Do not count the manifest rows as analyzer fact rows unless the existing mutation-cost contract counts all physical rows; inspect and preserve that contract through tests.

Add behavior tests. Round-trip C++, Ruby, Scala, and a language with no optional facts. Delete one row from each optional table in separate cases and verify `contains_parsed_blob` rejects the blob. Add direct cases for Scala exports and materialization records. Test that a zero optional count creates no manifest row.

Finally, measure the migrated schema. Record page and payload changes on a representative copy. Measure focused point and bulk hydration tests or benchmarks before and after. Run formatting, focused featureless tests, and the configured policy pack. Then run the guided specialist review and correct accepted findings.

## Concrete Steps

Run all commands from `/Users/dave/.codex/worktrees/7e8a/bifrost`.

Inspect status before each milestone:

    git status --short --branch

Run focused core migration tests after migration work. Select exact test names from `cargo test -p brokk-bifrost-core -- --list`, then run the migration module or named tests.

Run focused analyzer persistence tests after store work. Select the package and test binary from `Cargo.toml` and `cargo test --workspace -- --list`, then run only store and persistence tests first.

Format all Rust changes:

    cargo fmt --all

Run the featureless affected test suites. Do not enable `nlp` because this change does not affect semantic search.

Run the policy source `bifrost.code-smells` against the active workspace. Treat a finding as work to review. Treat an unreliable result as a failed check.

## Validation and Acceptance

Migration acceptance requires a populated version 15 database to reach version 16. The old C++, Ruby, and Scala count columns must no longer exist. The new manifest must contain exact nonzero counts for all five fact kinds. Common metadata and fact rows must remain equal.

Persistence acceptance requires successful round trips for C++, Ruby, Scala, and an unrelated language. A language with no optional facts must have no optional manifest row. Deleting one row from any supported optional typed table must make `contains_parsed_blob` return false. This includes `scala_exports` and `materialization_records`.

All focused tests, formatting, and policy checks must pass. The final report must state measured storage and hydration effects. It must not claim a disk reduction if the measurement does not show one.

## Idempotence and Recovery

Migration tests use temporary or in-memory databases and are safe to repeat. The real cache is rebuildable and version-keyed, but development must not edit the user's cache in place. Use a copied database for measurements.

If migration 0016 fails during development, correct the SQL and recreate the temporary test database. Never edit migrations 0001 through 0015 because released caches depend on their exact order.

If a store write fails its post-write integrity check, the surrounding SQLite transaction rolls back. Do not add partial recovery code.

## Artifacts and Notes

Baseline and final measurement evidence from the current cache:

    manifest rows: 100
    manifest payload: 5575 bytes
    manifest allocation: 12288 bytes
    rebuilt blob_meta allocation saved: 8192 bytes
    migrated blob_meta allocation: 139264 bytes
    version 16 manifest allocation: 12288 bytes
    version 15 point metadata reads, 200000: 0.20, 0.20, 0.21 seconds
    version 16 point metadata reads, 200000: 0.34, 0.36, 0.36 seconds
    mean added time per point read: approximately 0.75 microseconds

This evidence guides the design. It is not the final measurement.

## Interfaces and Dependencies

Migration 0016 must define:

    blob_optional_fact_manifest(
        blob_oid TEXT,
        lang TEXT,
        fact_kind INTEGER,
        row_count INTEGER
    )

The primary key is `(blob_oid, lang, fact_kind)`. `row_count` must be greater than zero. A foreign key to `blobs(blob_oid, lang)` must delete manifest rows with their blob.

The Rust store must define stable identifiers for these values and must never reuse them:

    1 = C++ template metadata
    2 = Ruby method dispatch mode
    3 = Scala trait
    4 = Scala export
    5 = materialization record

Use existing `rusqlite`, store transaction, hydration, and error types. Add no dependency.

Plan revision note: Created on 2026-08-06 after live schema inspection and a sparse-manifest storage prototype. Updated at completion with final tests, review corrections, storage results, point-read timings, and design decisions.
