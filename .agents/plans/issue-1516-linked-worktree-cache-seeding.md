# Seed client-bound linked-worktree caches safely

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. Maintain this document in accordance with `.agents/PLANS.md`.

## Purpose / Big Picture

Issue #1516 addresses the long cold declaration-index build seen when Codex, Claude, or another MCP client starts Bifrost in a newly created linked Git worktree. After this change, an exact-root client binding may initialize its new worktree-local `.bifrost/cache/bifrost_cache.db` from a consistent snapshot of the primary checkout's compatible cache. Bifrost will still write only beneath the client-authorized worktree, reconcile the snapshot against the linked worktree's actual files, and fall back to an ordinary cold build whenever seeding is unavailable or unsafe.

The behavior is observable through tests that warm a primary checkout, bind a linked worktree, and prove the complete primary analyzer state is copied before changed files are reconciled. The tests also prove that symbols absent from the linked worktree cannot leak from the primary cache.

## Progress

- [x] (2026-08-03) Measured the opportunity: 1,304 of 1,322 blob/language identities in the active worktree cache also existed in the primary cache, while the first broad code-intelligence lookup exceeded 30 seconds and a warm targeted lookup took 346 ms.
- [x] (2026-08-03) Created tracking issue #1516 and linked it to cold-initialization issue #1503.
- [x] (2026-08-03) Inspected client-root binding, cache path selection, SQLite initialization, Git primary-root discovery, and existing linked-worktree tests.
- [x] (2026-08-03) Added an atomic, non-overwriting SQLite online-backup seed primitive with live-WAL, incompatible-source, existing-destination, and concurrent-publisher coverage.
- [x] (2026-08-03) Seeded only exact linked-worktree roots during client binding, reconciled changed/deleted files before readiness, excluded nested roots, and retained cold-build fallback for corrupt sources.
- [x] (2026-08-03) Passed 48 cache tests, four client-root tests, formatting, diff checks, strict featureless workspace Clippy, and the post-rebase all-target/all-feature Clippy gate; ran and reviewed the complete repository policy selection.

## Surprises & Discoveries

- Observation: Ordinary analyzer cache discovery already collapses linked worktrees to the primary checkout, but client-root MCP binding deliberately bypasses that behavior.
  Evidence: `crates/bifrost-analysis/src/gitblob.rs::cache_db_path` uses `primary_repo_root`, while `crates/bifrost-mcp/src/searchtools_service.rs::client_cache_db_path` always places the database beneath the exact client root.

- Observation: The two live databases had 1,304 matching blob/language identities but no matching blob/language/generation triples.
  Evidence: Analyzer generation numbers are database-local even when the stored analysis epoch hashes match. Seeding must copy the complete compatible database rather than selectively copying blob rows without remapping generations.

- Observation: Both source and destination databases may use SQLite write-ahead logging, whose committed state can reside in `-wal` rather than the main database file.
  Evidence: `open_readonly_connection` explicitly documents read-only WAL snapshots. A filesystem copy of only `bifrost_cache.db` is therefore not a consistent seed mechanism.

- Observation: On macOS, temporary directories can be spelled through `/var` while their canonical path is under `/private/var`; SQLite's `NOFOLLOW` open rejects the non-canonical ancestor alias even though the database itself is not a symlink.
  Evidence: The first live-WAL seed test failed on the read-only source open until the already-validated source path was canonicalized before opening. Destination test reads require the same canonical spelling.

- Observation: The installed rustup and Homebrew Rust 1.96 builds share a release and commit hash but use LLVM 22.1.2 and 22.1.6 respectively, producing incompatible crate metadata when mixed.
  Evidence: Both the shared and initially isolated Clippy runs failed with E0514. Pinning Cargo, rustc, and rustdoc to `/opt/homebrew/bin` made the isolated workspace gate pass.

## Decision Log

- Decision: Use SQLite's online backup API to produce a complete destination snapshot in a temporary file, then publish it atomically without overwriting an existing destination.
  Rationale: The backup API reads a consistent committed snapshot including WAL state and tolerates an active source writer. Same-directory atomic publication keeps partial databases invisible and lets concurrent seeders race safely.
  Date/Author: 2026-08-03 / Codex

- Decision: Seed only when the client root exactly equals the linked repository's work directory; do not seed nested roots, primary checkouts, non-Git roots, or roots with an existing destination database.
  Rationale: A primary cache represents the full repository. Restricting the optimization to the exact linked-worktree root preserves the client authorization boundary and avoids importing repository-wide path state into a narrower client scope.
  Date/Author: 2026-08-03 / Codex

- Decision: Treat every seed error as an optimization miss at the MCP binding layer, log a concise diagnostic, and continue with the ordinary cold build.
  Rationale: The cache is rebuildable and code intelligence must remain available when the source is missing, busy, incompatible, corrupt, or unreadable. The low-level seed helper still returns precise errors for direct tests and diagnostics.
  Date/Author: 2026-08-03 / Codex

- Decision: Keep changes uncommitted while this checkout remains detached.
  Rationale: Repository instructions forbid creating or switching branches without explicit user direction, and committing on a detached HEAD would leave an unreferenced checkpoint rather than a useful milestone commit.
  Date/Author: 2026-08-03 / Codex

## Outcomes & Retrospective

The implementation now initializes a missing exact linked-worktree cache from the primary checkout with SQLite's online backup API, validates both source and staged schemas, synchronizes the staged file, and publishes it without clobbering a concurrent destination. MCP binding then runs its normal persisted-workspace reconciliation before the session becomes ready. Primary-only symbols are removed, changed declarations reflect linked-worktree bytes, unchanged declarations remain available from the copied analyzer state, nested roots do not seed, and a corrupt primary cache falls back to a successful cold build.

Validation passed: all 48 `cache_db` tests, all four `client_roots_tests`, `cargo fmt --all -- --check`, `git diff --check`, and strict featureless `cargo clippy --workspace --all-targets -- -D warnings` through the isolated-target helper with one consistent Homebrew toolchain. After rebasing onto `origin/master` at `04c7104ed`, both focused suites passed again and strict `cargo clippy --workspace --all-targets --all-features -- -D warnings` completed in the isolated target. The rebased Bifrost `bifrost.code-smells` selection completed reliably in 4.5 seconds with no diagnostics or incomplete rules. Its repository-wide warning baseline contains 285 findings; the only two whose files overlap this change are pre-existing sleep-in-loop notes at `searchtools_service.rs:4257` and `searchtools_service.rs:5154`, both outside every changed hunk. There are no canonical repository-defined policy roots.

## Context and Orientation

`crates/bifrost-mcp/src/searchtools_service.rs` owns MCP workspace binding. `SearchToolsService::bind_client_workspace` canonicalizes the client-authorized directory, computes `client_cache_db_path`, then starts `build_persisted_workspace_at` on a background thread. The session becomes usable only after this build completes and its query indexes are warmed.

`crates/bifrost-analysis/src/cache_db.rs` owns the unified SQLite cache's safe path checks, connection setup, migrations, schema validation, and WAL configuration. A SQLite online backup copies a transactionally consistent view from one connection to another even while the source has an active writer. The new helper belongs here because it must reuse those path and schema invariants rather than reproducing them in the MCP crate.

`crates/bifrost-analysis/src/gitblob.rs` discovers Git repositories and resolves a linked worktree's primary checkout through `Repository::commondir`. `primary_repo_root` returns the checkout owning the common Git object database. Client-root code may use that result only after proving the authorized root equals the linked repository's own work directory.

The cache stores parsed analyzer data by exact Git-style blob object ID, language, and database-local analyzer generation. Workspace construction compares current working-tree file bytes with these identities and synchronizes path-to-symbol rows before returning a ready analyzer. That reconciliation is the boundary that prevents stale primary-only paths from appearing in linked-worktree results.

## Plan of Work

First, enable rusqlite's `backup` feature for `crates/bifrost-analysis`. In `crates/bifrost-analysis/src/cache_db.rs`, add a small public seed outcome enum and a function that returns immediately when the destination exists, rejects unsafe source or destination paths, requires a current and internally consistent source schema, prepares the destination cache directory, backs the source into a same-directory temporary SQLite file, validates the snapshot, closes all SQLite handles, synchronizes the staged file, and publishes it with `persist_noclobber`. A concurrent winner must produce an `AlreadyPresent` outcome rather than an error or overwrite.

Add direct cache tests for a live WAL source, an existing destination, an incompatible source, and concurrent publication. The live-WAL test must insert recognizable data through an open writer, seed without checkpointing or closing that writer, and read the recognizable row from the destination.

Second, add a helper in `crates/bifrost-mcp/src/searchtools_service.rs` that discovers a repository from the canonical client root, requires `repo.is_worktree()`, requires the canonical Git work directory to equal the authorized root, resolves the primary checkout, constructs its generated cache path without honoring a client destination override, and attempts the low-level seed only when source and destination differ. Call this helper inside the existing background build closure immediately before `build_persisted_workspace_at`. Successful, skipped, and failed seed attempts should emit concise stderr diagnostics without exposing source contents.

Extend `client_roots_tests`. Warm a primary cache with at least one unchanged symbol, create a linked worktree, change one file and remove a primary-only file in the linked worktree, then bind the exact linked root. Assert the destination database remains local, the unchanged symbol is available, the changed symbol reflects linked-worktree bytes, and the removed symbol is absent. The live-WAL test must prove recognizable persisted state came from the seed, while the MCP test proves ordinary reconciliation consumes that seed without stale path leakage. Add a nested-root regression that proves no repository-wide seed is copied into a narrower client root.

Finally, run focused cache and MCP tests, format the workspace, run a featureless workspace Clippy gate because this change does not involve NLP, run `bifrost.code-smells` plus repository policy roots in one policy request, inspect all findings, and review the final diff against `origin/master`.

## Concrete Steps

Run all commands from `/Users/dave/.codex/worktrees/16b9/bifrost`.

After the low-level helper:

    cargo test -p brokk-bifrost-analysis cache_db::tests::seed

Expect every new seed test to pass, including the live-WAL and no-overwrite cases.

After MCP integration:

    cargo test -p brokk-bifrost-mcp client_roots_tests

Expect the original exact-root boundary test and the new seed/reconciliation tests to pass.

Final focused validation:

    cargo fmt --all -- --check
    cargo test -p brokk-bifrost-analysis cache_db::tests
    cargo test -p brokk-bifrost-mcp client_roots_tests
    scripts/with-isolated-cargo-target.sh env RUSTC=/opt/homebrew/bin/rustc RUSTDOC=/opt/homebrew/bin/rustdoc /opt/homebrew/bin/cargo clippy --workspace --all-targets -- -D warnings
    git diff --check

Do not enable `nlp` for this task-scoped validation. If the isolated Clippy build is too expensive or blocked by the environment, record the exact limitation and retain the focused compile/test evidence.

## Validation and Acceptance

Acceptance requires a live primary SQLite writer in WAL mode to remain open while a complete worktree-local snapshot is created and validated. An existing destination must remain byte-for-byte untouched. Concurrent seed attempts must leave one valid published database and no persistent staging files.

The MCP behavior test must create a real linked Git worktree and prove the destination exists only under that authorized worktree. Recognizable persisted primary state and unchanged declarations must arrive through the seed. A changed file must return the linked-worktree declaration, and a file absent from the linked worktree must not appear in search results. A nested client root must perform a cold local build without importing the primary database.

Any source discovery, validation, backup, or publication failure must still allow `ensure_ready` and ordinary analyzer queries to succeed through a cold build. The final implementation must preserve Windows-compatible `Path` handling and avoid source-text parsing or path string splitting.

## Idempotence and Recovery

Tests use disposable repositories and caches and are safe to repeat. The production seed operation is attempted only before a destination exists, uses a temporary file in the destination directory, and publishes with no-clobber semantics. Dropping the temporary path removes failed staging state. If seeding fails, no cleanup or deletion of the source is allowed; ordinary cache initialization builds the destination forward.

No schema migration is introduced. A source on an older or newer migration version is skipped rather than modified. The existing destination open path remains responsible for migrations after a successful compatible snapshot.

## Artifacts and Notes

Tracking issue: https://github.com/BrokkAi/bifrost/issues/1516

Related cold-initialization issue: https://github.com/BrokkAi/bifrost/issues/1503

Measured live overlap before implementation:

    primary blobs: 1321
    worktree blobs: 1322
    matching blob/language identities: 1304

The generation IDs differed because each cold database assigned its own monotonically increasing values, while every language's epoch hash matched.

## Interfaces and Dependencies

`crates/bifrost-analysis` must enable rusqlite feature `backup` without adding a new crate.

`crates/bifrost-analysis/src/cache_db.rs` should expose an outcome type equivalent to:

    pub enum CacheSeedOutcome {
        Seeded,
        AlreadyPresent,
        IncompatibleSource,
    }

and a fallible operation equivalent to:

    pub fn seed_unified_cache(source: &Path, destination: &Path) -> Result<CacheSeedOutcome>

Exact names may change if nearby conventions suggest a clearer API, but the distinction between successful seed, harmless skip, and actual failure must remain explicit.

`crates/bifrost-mcp/src/searchtools_service.rs` should keep the source-discovery helper private. It must accept the canonical client root and destination path, prove exact linked-worktree scope structurally through libgit2, and invoke `cache_db::seed_unified_cache`. No environment-variable mutation, filesystem copying, SQLite sidecar copying, regex, or string-based Git path parsing is permitted.

Plan revision note (2026-08-03): Created after issue #1516 was approved and filed, recording the measured cache overlap, exact-root authorization constraint, whole-database generation requirement, online-backup design, and detached-checkout limitation.

Plan revision note (2026-08-03): Closed after implementation and final validation. Recorded live-WAL backup, exact-root and cold-fallback behavior, the macOS canonical-path requirement, the mixed-toolchain Clippy workaround, and the reviewed pre-existing repository policy findings.

Plan revision note (2026-08-03): Refreshed after rebasing onto `origin/master` at `04c7104ed`, rerunning both focused suites and the complete all-feature Clippy gate, and reviewing the updated reliable policy report.
