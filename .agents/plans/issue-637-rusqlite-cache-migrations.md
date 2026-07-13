# Move the unified cache to rusqlite migrations

This ExecPlan is a living document. Maintain it according to `.agents/PLANS.md` from the repository root.

## Purpose / Big Picture

The SQLite cache currently compares three handwritten version fields and recreates data when an old version is opened. After this change, a Bifrost update can append a reviewed SQL migration and preserve compatible cache rows. A fresh cache starts from the current schema, while an existing current cache is marked as the baseline without rebuilding it. The behavior is visible through the cache-db unit tests: a seeded old-style cache keeps its analyzer and semantic rows, and a future database version is rejected without mutation.

## Progress

- [x] (2026-07-13) Rebased the issue worktree onto `origin/master` and inspected the cache schema, callers, tests, and the compatible `rusqlite_migration` 1.3.1 source.
- [x] Extract the current unified schema into baseline SQL and replace handwritten schema-version branching with the migration runner.
- [x] Add adoption, rebuild, atomicity, locking, and future-version tests.
- [x] Run formatting, focused tests, full Rust/NLP tests, and clippy; record the Python-extension test-link limitation below.

## Surprises & Discoveries

- Observation: `rusqlite_migration` 1.3.1 depends on exactly `rusqlite` 0.32.1 and applies its full migration set in one transaction.
  Evidence: its manifest pins `rusqlite = "0.32.1"`; `Migrations::to_latest` calls `Connection::transaction`, executes every pending `M::up`, then writes `PRAGMA user_version` before commit.
- Observation: Bifrost does not currently read or write `PRAGMA user_version`.
  Evidence: repository search found no `user_version` references outside this implementation work.
- Observation: `rusqlite_migration` 1.3.1 exposes `Migrations::new(Vec<M>)`, not a slice constructor.
  Evidence: its public API has `new` and `to_latest`, but no `from_slice`; the embedded cache registry is therefore a `Lazy<Migrations<'static>>` containing the append-only `M::up(include_str!(...))` entries.
- Observation: the macOS `cargo test --features nlp,python` command cannot link this project's PyO3 extension-module configuration.
  Evidence: PyO3's `extension-module` feature intentionally leaves Python symbols unresolved; Cargo's test build links the `cdylib` as a standalone dylib and fails on those `_Py*` symbols. The all-feature Clippy build passes, and the complete Rust/NLP suite passes when the extension feature is omitted.

## Decision Log

- Decision: use `rusqlite_migration = "=1.3.1"` instead of a local ledger.
  Rationale: it matches the existing SQLite driver exactly, runs SQL migrations atomically, uses the SQLite header rather than another metadata table, and rejects unknown newer versions.
  Date/Author: 2026-07-13 / Codex and user-approved plan.
- Decision: migration 1 is the current schema, not a historical conversion.
  Rationale: existing cache state values `1/1/10` identify the supported pre-migration baseline. Any other pre-migration schema is rebuildable and will be recreated.
  Date/Author: 2026-07-13 / user.
- Decision: migration files are append-only and have no down SQL.
  Rationale: the cache is derived data; downgrades must leave a newer cache untouched rather than attempt lossy reversal.
  Date/Author: 2026-07-13 / Codex and user-approved plan.
- Decision: preserve the `cache_state` version tuple only as baseline-adoption evidence, not as a live migration ledger.
  Rationale: a current pre-migration cache has no `user_version`; its known `1/1/10` tuple, integrity check, and table inventory prove it can safely receive migration version 1 without data loss.
  Date/Author: 2026-07-13 / Codex and user-approved plan.

## Outcomes & Retrospective

Implemented on 2026-07-13. `migrations/cache/0001-current-baseline.sql` is the complete current schema and initializes the unchanged `cache_state` row. `src/cache_db.rs` now embeds it in a pinned `rusqlite_migration` registry and lets the crate own ordered `user_version` updates and future-version rejection.

The narrow bridge adopts only an intact current cache: `quick_check`, the `1/1/10` state tuple, and the exact required table inventory must validate before it sets `user_version = 1` in an immediate transaction. Any incomplete or unknown pre-migration cache is rebuilt; a database ahead of migration 1 is left unchanged and rejected by the runner. The new focused tests cover fresh migration, adoption with semantic/analyzer data, incomplete and unrecognized version-0 caches, incomplete version-1 rebuilds, a forward second migration, atomic rollback on invalid migration SQL, lock/retry behavior, future-version rejection, and no legacy-cache deletion during adoption.

Validation passed: `cargo fmt`; `cargo test cache_db --lib` (16 passed); `BIFROST_SEMANTIC_INDEX=off cargo test --features nlp --test unified_cache` (4 passed); `cargo clippy --all-targets --all-features -- -D warnings` under a consistent Homebrew Rust toolchain; and the full `BIFROST_SEMANTIC_INDEX=off cargo test --features nlp` suite with an isolated UV cache (exit 0). `cargo test --features nlp,python` reaches a known macOS PyO3 extension-module linker failure before running tests; it is unrelated to this migration change and is documented above.

## Context and Orientation

`src/cache_db.rs` opens the unified SQLite file, configures each connection, and owns its schema today. Its `cache_state` table has historical global, semantic, and analyzer version fields plus cache-GC and semantic-index metadata. `src/analyzer/store/mod.rs` and `src/nlp/store.rs` open this same database. The cache is rebuildable: persisted rows accelerate startup but are never the source of truth for a workspace.

A migration is an ordered SQL change that SQLite runs exactly once. `rusqlite_migration` stores only the number of completed migrations in SQLite's `user_version` header. `migrations/cache/0001-current-baseline.sql` will therefore be the complete schema that current Bifrost creates today. Future changes append `M::up` entries and never modify an already-shipped migration.

## Plan of Work

Add the pinned migration dependency and move the exact current DDL and initial `cache_state` row from Rust strings into the baseline SQL file. Define the embedded lazy migration registry in `src/cache_db.rs` with `include_str!`; validate it in tests and call `to_latest` after any baseline preparation.

When a connection has migration version zero and user tables, validate `PRAGMA quick_check`, the existing `cache_state` tuple `1/1/10`, and the exact baseline table inventory. Mark a valid database as version one in a short immediate transaction, preserving all rows. Rebuild every other pre-migration database by atomically dropping its user tables and resetting `user_version` to zero, then let the migration runner create migration one. For a database whose `user_version` is ahead of the embedded list, let the runner return its error without changing the cache.

Delete the obsolete global/pre-release/namespace version code and its selective namespace recreation. Leave the historical version columns in migration one unchanged so baseline adoption remains compatible; no runtime code will use them after this change. Keep the existing legacy-file cleanup condition so adopting an existing unified database cannot remove legacy files.

## Concrete Steps

Work from `/Users/dave/.codex/worktrees/855b/bifrost`.

1. Add the dependency, baseline SQL, and migration bridge. Run `cargo test cache_db --lib` and expect the cache-db unit tests to pass.
2. Add behavior tests using in-memory and temporary file databases. Run `cargo test cache_db --lib` again and expect adoption, rollback, lock-release retry, rebuild, and future-version tests to pass.
3. Run `cargo fmt`, `cargo test --test unified_cache`, `cargo test --features nlp,python`, and `cargo clippy --all-targets --all-features -- -D warnings`. Record concise results here.

## Validation and Acceptance

Acceptance is a cache opened from the current pre-migration schema retaining a seeded `semantic_blobs` and `blobs` row while receiving `user_version = 1`; a corrupt or incomplete pre-migration cache being recreated; a failing migration leaving neither its new table nor a bumped user version; a lock error becoming successful after the lock is released; and an ahead database reporting an error while preserving its rows. The full test suite with `nlp,python` features and clippy must pass.

## Idempotence and Recovery

Opening an already-migrated cache is a no-op. A failed or interrupted `to_latest` transaction rolls back automatically, so opening again safely retries. A known baseline is marked only after validation. An unknown pre-migration cache is intentionally recreated because the cache is derived data. A future migration version is never rebuilt or downgraded by this binary.

## Artifacts and Notes

The implementation adds one Cargo dependency and one baseline SQL file. No external migration executable, async runtime, second SQLite driver, or data-backup workflow is introduced.

## Interfaces and Dependencies

`cache_db::migrate(&mut rusqlite::Connection) -> Result<()>` remains the entry point used by persistent and in-memory stores. Internally it uses `rusqlite_migration::{M, Migrations}` and an embedded static lazy migration registry. No public API changes are expected.

Plan created on 2026-07-13 because issue #637 is a persistent-storage refactor requiring a restartable implementation record.
