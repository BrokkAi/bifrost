# Serialize same-process cache initialization by canonical path

This ExecPlan is a living document. The sections `Progress`, `Surprises &
Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must remain current
while work proceeds.

This document must be maintained in accordance with
[.agents/PLANS.md](/mnt/optane/bifrost-fird/.agents/PLANS.md).

## Purpose / Big Picture

Issue #1173 reports that many threads opening the same fresh Bifrost cache can
race through persistent SQLite pragma setup and schema migration. SQLite still
protects the database, but peers can exhaust the five-second busy window while
the first opener performs a slow migration. After this change, openers in one
process serialize only for the same canonical cache path; different cache paths
remain independent, and cross-process correctness continues to come from
SQLite's transactional locks.

The behavior is observable by running the existing 16-opener regression under
load: every opener must see the current schema, WAL journal mode, incremental
auto-vacuum, and enabled foreign keys without a `database is locked` error.

## Progress

- [x] (2026-07-25) Reproduced the failure in the complete all-feature gate:
  15 of 16 openers returned a SQLite lock error or exhausted auto-vacuum
  initialization after roughly five seconds.
- [x] (2026-07-25) Searched the open tracker, found no matching owner, and
  created and assigned issue #1173 to `jbellis` before implementation.
- [x] (2026-07-25) Delegated implementation ownership of `src/cache_db.rs` to
  Oldskool while root owns this plan and final review.
- [x] (2026-07-25) Implemented and reviewed a
  `Weak<Mutex<()>>` registry. The global map lock is released before any
  filesystem or SQLite work; dead path cells are pruned opportunistically;
  poison paths return `Result` errors; and direct tests prove canonical
  same-path sharing plus independent-path separation.
- [x] (2026-07-25) Oldskool passed the same-path/independent-path unit tests and
  the existing 16-opener end-to-end regression.
- [x] (2026-07-26) Passed the focused 16-opener regression, formatting,
  `git diff --check`, and all-target/all-feature Clippy with warnings denied.
  A final Oldskool read-only review found no actionable correctness,
  lock-order, portability, or coverage issue.
- [ ] Pass the complete `cargo test --features nlp,python` gate after merging
  the current `origin/master` schema migration.
- [ ] Commit, synchronize, publish to `origin/master`, and close #1173.

## Surprises & Discoveries

- Observation: The migration logic is transactionally correct but its
  same-process admission control is timing-sensitive.
  Evidence: The same test passed in earlier complete runs, then failed under
  host load with one successful opener and fifteen lock failures while the
  five-second initialization deadline expired.

- Observation: Persistent pragma configuration runs before the migration
  transaction.
  Evidence: `open_unified_connection` installs the busy timeout, calls
  `configure_connection_after_busy_timeout` for auto-vacuum and WAL, queries
  initialization state, and only then calls `migrate`.

- Observation: A standard per-path mutex is sufficient; no custom condition
  variable or timing hook is necessary.
  Evidence: The weak registry can return an `Arc<Mutex<()>>`; retaining that
  `Arc` beside its ordinary guard covers the entire open sequence. Direct
  `Arc::ptr_eq` tests establish the lock-cell identity contract deterministically.

- Observation: This linked worktree's primary checkout cache moved to schema
  version 12 while the current branch still expected version 11.
  Evidence: The complete gate passed the library target and then several CLI
  integration children correctly rejected
  `/home/jonathan/Projects/bifrost/.brokk/bifrost_cache.db` as
  `DatabaseTooFarAhead`. The affected MCP target passed 28/28 against
  repository-local test cache state. This is integration drift, not a #1173
  failure; current `origin/master` must be merged before the final gate.

## Decision Log

- Decision: Serialize the complete persistent initialization and migration
  sequence by canonical database path inside the process.
  Rationale: Locking only the migration leaves auto-vacuum and WAL setup racing.
  A single global mutex would unnecessarily couple independent workspaces.
  Canonical path identity is already established by `prepare_cache_db_path`
  before persistent setup begins.
  Date/Author: 2026-07-25 / Codex

- Decision: Preserve SQLite busy handling and transactional migration locks.
  Rationale: The in-process lock cannot coordinate separate Bifrost processes,
  so it is an admission optimization and determinism guarantee, not a
  replacement for database-level correctness.
  Date/Author: 2026-07-25 / Codex

## Outcomes & Retrospective

The implementation is complete and focused tests pass. It adds a bounded,
path-local critical section with no permanent strong references to unused path
locks and no behavior change for already initialized caches. Repository-wide
publication gates and pushed-head proof remain.

## Context and Orientation

`src/cache_db.rs` owns the shared SQLite connection setup. The public
`open_unified_connection` function validates the caller's path, creates and
canonicalizes its parent directory, opens the database, installs a five-second
busy timeout, configures persistent auto-vacuum and WAL pragmas, checks whether
the unified cache was initialized, runs the schema migration, and deletes
obsolete cache files after a first successful initialization.

A path-local lock registry maps a canonical database path to a lock shared by
openers for that exact file. It must not keep one global mutex held during
SQLite work; the registry mutex is held only long enough to obtain a per-path
lock. A weak reference permits entries to become reclaimable after the last
opener releases its strong reference.

## Plan of Work

In `src/cache_db.rs`, add a process-global registry protected by a short-held
mutex. Resolve or insert an atomically shared mutex for the canonical database
path returned by `prepare_cache_db_path`. Acquire that path mutex before
opening/configuring/migrating the connection, and hold it through the
first-initialization legacy-file cleanup decision. Handle a poisoned registry
or path mutex explicitly without panicking at a public API boundary.

Strengthen the existing concurrent fresh-opener test so it continues to prove
the full schema and pragma contract. Add a behavior-focused independent-path
test only if it can deterministically prove that one path's held initialization
guard does not block a second path without adding sleeps or timing-sensitive
assertions.

## Concrete Steps

Work from `/mnt/optane/bifrost-fird`.

Run the focused regression outside the restrictive sandbox at reduced
priority:

    nice -n 10 cargo test --features nlp,python \
      cache_db::tests::concurrent_fresh_cache_openers_serialize_schema_migration \
      -- --exact

Run formatting and the repository gates:

    cargo fmt --all -- --check
    nice -n 10 cargo clippy --all-targets --all-features -- -D warnings
    BIFROST_SEMANTIC_INDEX=off nice -n 10 \
      cargo test --features nlp,python

The focused regression must report one passed test. The complete gate must
finish with no failed harness.

## Validation and Acceptance

Acceptance requires all 16 same-path openers to return `Ok(())` and observe the
current migration version, valid schema, foreign keys enabled, WAL journal
mode, and incremental auto-vacuum. Review must show that different canonical
paths resolve different lock objects and that the registry mutex is never held
across filesystem or SQLite work. Existing symlink rejection and canonical
parent handling must remain before the database is trusted.

## Idempotence and Recovery

The tests use temporary directories and are safe to repeat. The lock registry
is process-local and contains no persistent state. If the implementation causes
a regression, remove only the path-lock acquisition and its tests; SQLite
transactional locking remains the prior safe fallback.

## Artifacts and Notes

The failing full-gate result had one successful opener, multiple direct
`database is locked` errors, and multiple auto-vacuum retry timeouts between
5.28 and 5.63 seconds. This timing distribution is the evidence that a correct
winner existed but peers exhausted admission time before observing its result.

Revision note (2026-07-25): Created this plan after the final #1165 publication
gate exposed a reproducible same-process cache initialization race under load.

Revision note (2026-07-25): Updated after implementation review to record the
accepted weak standard-mutex registry and deterministic lock-identity tests.

Revision note (2026-07-26): Recorded the completed focused, formatting, Clippy,
and delegated review gates. Per direct user instruction, all later Cargo and
Bifrost work runs normally outside the sandbox at niceness 10 rather than
creating isolated Cargo targets under `/tmp`.

## Interfaces and Dependencies

Use only the standard library synchronization types already available to the
crate: `Arc`, `Weak`, `Mutex`, and `OnceLock`, plus `HashMap<PathBuf, ...>`.
Do not add a dependency or change the public signature:

    pub fn open_unified_connection(db_path: &Path) -> Result<Connection>

The lock identity must use the safe canonical database path produced by
`prepare_cache_db_path`, not the caller's unresolved spelling.
