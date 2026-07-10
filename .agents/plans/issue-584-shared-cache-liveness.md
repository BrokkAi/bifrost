# Extract shared cache and liveness plumbing for issue #584

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept current as work proceeds. Maintain this document in accordance with `.agents/PLANS.md`.

## Purpose / Big Picture

Issue #584 is the second prerequisite extracted from the combined SQLite analyzer work in PR #447. After this change, Bifrost has one shared implementation for Git blob identity, primary-repository cache paths, cache database setup, garbage-collection liveness, and live path snapshots. The semantic index becomes the first active consumer of the unified cache file, while the analyzer continues to use its current resident `AnalyzerState` and existing optional `.bifrost/analyzer.db` baseline.

The observable proof is that linked worktrees resolve the same `.brokk/bifrost_cache.db`, live file identities always reflect exact working-tree bytes, overlays override disk/index identities without becoming stale filesystem facts, Windows ordinary and verbatim roots compare equally, and ordinary analyzer construction does not create or query the unified database.

## Progress

- [x] (2026-07-10) Verified issue #583 landed as commit `69b4aa7` and rebased the existing #584 branch onto current `origin/master`.
- [x] (2026-07-10) Inspected issue #584, current semantic cache and analyzer behavior, and the reviewed PR #447 donor implementation.
- [x] (2026-07-10) Milestone 1: added shared path normalization, Git blob identity, and inert analyzer liveness; 4 Git, 9 liveness, and 1 cross-platform path test pass locally, with Windows-only disk/UNC cases compiled by the Windows matrix.
- [x] (2026-07-10) Milestone 2: added the unified semantic cache schema and shared semantic GC driver without analyzer tables or activation; 6 cache DB, 2 GC, 6 semantic store, and 8 semantic integration tests pass.
- [x] (2026-07-10) Milestone 3: ran focused regressions, formatting, strict no-CUDA clippy, diff checks, and the guided review; fixed all valid in-scope correctness, migration, security, API-surface, and duplication findings.
- [x] (2026-07-10) Review follow-up: preserved exact-byte OIDs from clean CRLF/filter checkouts during GC, made legacy cleanup safe for arbitrary paths and live legacy writers, and centralized worktree liveness/path-normalization helpers.
- [x] (2026-07-10) CI follow-up: feature-gated semantic cache/GC and NLP-only Git helpers so strict no-NLP builds do not reject inactive plumbing as dead code.

## Surprises & Discoveries

- Observation: The current semantic cache reuses the index OID for a stat-clean file, but tree-sitter and semantic materialization read working-tree bytes. On CRLF checkouts those byte streams can differ even when Git considers the path clean.
  Evidence: donor commit `e53d1928` changed the shared resolver to hash every live file from disk so cache identity and parsed bytes agree.

- Observation: The donor's `cache_db.rs` and `cache_gc.rs` include analyzer tables and `AnalyzerStore` calls that are explicitly out of scope for #584.
  Evidence: issue #584 requires reusable plumbing while the final PR #447 remains responsible for analyzer rows, persistence, hydration, and SQL-backed queries.

- Observation: `ProjectFile` already has lexical normalization, but it preserves Windows verbatim prefixes and project constructors retain canonicalized roots verbatim.
  Evidence: donor commits `6cabd484` and `360915ef` normalized both `ProjectFile` and constructor roots after Windows canonicalization.

- Observation: macOS temporary directories may be spelled through `/var` by the test harness and `/private/var` by `git worktree list --porcelain`.
  Evidence: the first linked-worktree root assertion failed until worktree roots were canonicalized before lexical normalization; the cache-path equality itself already passed.

- Observation: the liveness API is intentionally not consumed by production analyzer code in #584, so a private module otherwise triggers dead-code warnings under strict clippy.
  Evidence: the semantic integration build reported every liveness type as unused. A compile-only function-pointer contract now exercises the crate-internal interface in normal builds without runtime wiring or lint suppression; the function is optimized away and will be removed when the final analyzer store becomes the real consumer.

- Observation: stat-only index fingerprints can miss a same-size index rewrite on filesystems with coarse modification times, and removing tracked filesystem refresh entries leaves a memoized live snapshot stale after an unstaged edit.
  Evidence: guided review identified both seams. `current_index_fingerprint` now hashes the index bytes, and `refreshing_tracked_filesystem_entry_replaces_memoized_identity` proves a refreshed tracked path replaces the old snapshot identity.

- Observation: the machine's default `cargo clippy-no-cuda` mixes Rustup's compiler with Homebrew's `clippy-driver`, whose LLVM patch versions differ.
  Evidence: the ordinary command failed before crate analysis; running the same Cargo alias with the Rustup toolchain first in `PATH` and an isolated `/private/tmp/bifrost-clippy-9251` target completed with no warnings.

- Observation: a time-based GC check cannot require positive registry growth because deleting refs can make cached rows unreachable without inserting any new rows.
  Evidence: the guided review found the early `growth <= 0` return; `elapsed_interval_sweeps_without_registry_growth` now proves elapsed-interval GC removes such a row.

- Observation: reachability from Git refs is insufficient once cache keys use literal working-tree bytes: a clean CRLF checkout has a different blob OID from Git's LF-normalized object.
  Evidence: `forced_gc_preserves_clean_crlf_working_tree_identity` proves shared GC retains the working-byte OID, and `worktree_live_oids` centralizes that root calculation for every linked worktree.

- Observation: the Android target compiles without `nlp` and promotes warnings to errors, while the new shared cache module was compiled even though its only active consumer is NLP.
  Evidence: CI run `29093927597` failed on dead-code errors from `cache_db` and NLP-only Git helpers. Gating those helpers while retaining liveness' exact-byte resolver makes strict no-NLP clippy pass.

## Decision Log

- Decision: Implement on `/Users/dave/.codex/worktrees/9251/bifrost`; use `/Users/dave/.codex/worktrees/42d7/bifrost` only as read-only donor material.
  Rationale: the 9251 branch starts at merged #583/master, while 42d7 still carries the combined PR #447 branch.
  Date/Author: 2026-07-10 / Codex.

- Decision: Move semantic storage to namespaced `semantic_*` tables in `.brokk/bifrost_cache.db`, with `analyzer_schema_version = 0` and no analyzer tables.
  Rationale: this establishes the collision-free shared database boundary without activating the future analyzer backend.
  Date/Author: 2026-07-10 / Codex.

- Decision: Keep `src/nlp/gitcache.rs` as a public compatibility facade over crate-internal shared Git helpers.
  Rationale: current callers and downstream code retain their API while analyzer/cache infrastructure can reuse one implementation.
  Date/Author: 2026-07-10 / Codex.

- Decision: Place inert live-path types in `src/analyzer/store/liveness.rs`, with `src/analyzer/store/mod.rs` containing only that module.
  Rationale: this preserves the donor/final-backend seam without adding an `AnalyzerStore` or changing runtime analyzer behavior.
  Date/Author: 2026-07-10 / Codex.

- Decision: Extract a semantic-only shared GC driver now and leave analyzer sweeping for the final backend PR.
  Rationale: claim/throttle and Git reachability belong to shared cache plumbing, but referencing analyzer rows or `AnalyzerStore` would violate #584.
  Date/Author: 2026-07-10 / Codex.

- Decision: Refuse a unified cache whose analyzer schema version is nonzero instead of rewriting it, while allowing future versions to store a nonzero value by constraining the column only to nonnegative integers.
  Rationale: an older #584 binary must not destructively downgrade a future analyzer cache. When analyzer version remains zero, a rebuildable schema mismatch may atomically replace all user tables so stale donor/analyzer-shaped tables cannot survive under reset metadata.
  Date/Author: 2026-07-10 / Codex.

- Decision: Preserve only the pre-#584 public functions in `nlp::gitcache`; keep primary-root, cache-path, full-index, single-path, and worktree-HEAD helpers crate-internal.
  Rationale: the compatibility facade must not accidentally publish the new implementation seams that the final backend may need to evolve.
  Date/Author: 2026-07-10 / Codex.

- Decision: Hold and revalidate a no-follow cache-directory handle around SQLite initialization, and delete the legacy semantic files only after the first successful unified-cache initialization.
  Rationale: directory identity checks catch replacement races before or during initialization, while deferred best-effort cleanup keeps the legacy warm cache intact if initialization fails. Cleanup is keyed to the absence of initialized `cache_state`, not pre-open file existence, so an interrupted first creation can recover without one process deleting a concurrent creator's valid database.
  Date/Author: 2026-07-10 / Codex.

- Decision: Keep cache schemas rebuildable and breaking before v1.0, while retaining correctness protections for active working-tree identities and arbitrary cache paths.
  Rationale: compatibility migration machinery is unnecessary for derived data at this stage, but GC must not immediately evict an active clean CRLF/filter-transformed file and opening a custom cache path must not delete a sibling legacy file.
  Date/Author: 2026-07-10 / Codex.

- Decision: Compile semantic cache setup and Git cache/GC helpers only with the `nlp` feature; retain the exact-byte index/file resolvers needed by inert analyzer liveness in the base build.
  Rationale: this matches the active consumer boundary, eliminates no-NLP dead-code failures, and does not attach liveness to an analyzer database backend.
  Date/Author: 2026-07-10 / Codex.

## Outcomes & Retrospective

The issue #584 plumbing is complete in three checkpoint commits. Git identity now follows exact working-tree bytes across clean LF, clean CRLF, dirty, untracked, bulk, targeted, full-index, and single-path resolution. Primary and linked worktrees share one cache path; reachable refs, detached worktree HEADs, and every worktree's dirty content remain GC roots.

The active semantic cache now uses `.brokk/bifrost_cache.db`, semantic-prefixed tables, and shared `cache_state`. Analyzer version zero is reserved without creating analyzer tables or attaching any liveness/store type to analyzer construction or queries. Future nonzero analyzer schemas are refused without mutation by this older plumbing. First-open legacy cleanup occurs only after successful initialization, and cache paths reject symlinks plus directory replacement.

The guided review covered security, operations, duplication, architecture, and senior correctness. It found and prompted fixes for tracked-file snapshot refresh, same-size index invalidation, no-growth interval GC, future-schema downgrade safety, cleanup ordering, directory replacement, duplicated validation logic, and an overbroad compatibility re-export. The synthetic compile-only liveness contract remains intentionally temporary because strict clippy must type-check the inert crate-private API before the final backend supplies a real consumer.

Final evidence is: no-NLP liveness 10 and strict all-target clippy pass; Git tests 4 passed; path normalization 1 locally plus Windows-only disk/UNC cases in the Windows matrix; cache DB 12; cache GC 4; semantic store 6; analyzer parity/no-backend activation 8; semantic integration 8. `cargo fmt --all`, strict `cargo clippy-no-cuda` with the corrected Rustup toolchain path, and `git diff --check` all pass. No analyzer SQLite backend was activated.

## Context and Orientation

`src/nlp/gitcache.rs` currently owns repository discovery, working-tree blob IDs, Git object reachability, and linked-worktree enumeration. A Git blob ID is the content hash Git assigns to a file's exact bytes. The semantic index uses these IDs as cache keys.

`src/nlp/store.rs` currently owns both semantic data access and SQLite connection/schema setup for `.brokk/semantic_cache.db`. `src/nlp/indexer.rs` also owns semantic garbage-collection orchestration. This plan separates the shared parts into `src/gitblob.rs`, `src/cache_db.rs`, and `src/cache_gc.rs`, while keeping semantic row access in `src/nlp/store.rs`.

`src/analyzer/model.rs` defines `ProjectFile`, the normalized `(project root, relative path)` identity used throughout analyzer state. `src/analyzer/project.rs` constructs project roots. `src/analyzer/store/liveness.rs` will provide filesystem/Git-derived snapshots and explicit overlay entries, but no current analyzer constructor or query will use it in this issue.

An overlay is source text held in memory that shadows the file on disk. Overlay entries must carry the blob ID of their in-memory bytes and must not be invalidated by disk metadata. Filesystem entries, in contrast, capture metadata and are rejected when the path changes after snapshot creation.

## Plan of Work

Milestone 1 centralizes path normalization and Git/live-path identity. Move the lexical normalization trait into a crate-internal path module, add Windows disk/UNC prefix equivalence, apply it after project/cache canonicalization, extract Git helpers from NLP, and retain the NLP re-export. Add `analyzer::store::liveness` from the donor without any `AnalyzerStore` or runtime wiring. Tests cover LF, CRLF, dirty/untracked files, linked worktrees, overlay precedence, and stale snapshots. Format, run the focused library tests, update this plan, and commit the milestone.

Milestone 2 adds `cache_db` with safe connection configuration, semantic-prefixed schema, shared cache state, reserved analyzer schema version zero, legacy semantic-cache cleanup, and symlink rejection. Adapt `SemanticStore` to the shared connection/schema and add its DB path accessor. Move semantic GC claim/throttle/reachability into `cache_gc`, explicitly omitting analyzer dependencies. Adapt the semantic indexer and tests, run focused cache and semantic suites, update this plan, and commit the milestone.

Milestone 3 proves the scope boundary. Add or retain a regression that ordinary analyzer construction creates no `.brokk/bifrost_cache.db` and leaves resident query parity intact. Run all focused suites, `cargo fmt --all`, `cargo clippy-no-cuda`, and `git diff --check`. Review the branch against `origin/master` with the guided-review specialists, fix valid in-scope findings, update this plan's outcomes, and commit only the reviewed files. Do not push or open a PR.

## Concrete Steps

All commands run from `/Users/dave/.codex/worktrees/9251/bifrost`.

Milestone 1 validation:

    cargo fmt --all
    cargo test --lib gitblob::tests
    cargo test --lib analyzer::store::liveness::tests
    cargo test --lib path_normalization::tests

Milestone 2 validation:

    cargo test --lib cache_db::tests
    cargo test --features nlp --lib cache_gc::tests
    cargo test --features nlp --lib nlp::store::tests
    BIFROST_SEMANTIC_INDEX=off cargo test --features nlp --test semantic_search

Final validation:

    BIFROST_SEMANTIC_INDEX=off cargo test --test analyzer_query_parity
    BIFROST_SEMANTIC_INDEX=off cargo test --features nlp --test semantic_search
    cargo fmt --all
    /usr/bin/env PATH=/Users/dave/.rustup/toolchains/1.96.0-aarch64-apple-darwin/bin:/opt/homebrew/bin:/usr/bin:/bin CARGO_TARGET_DIR=/private/tmp/bifrost-clippy-9251 cargo clippy-no-cuda
    git diff --check
    git status --short

Expected results are zero test failures, zero clippy warnings, and no whitespace errors. Stage only files changed for each milestone and commit on the current branch. Do not push.

## Validation and Acceptance

The Git tests must prove all path-resolution APIs hash exact working-tree bytes. A clean LF path matches its index blob. A clean CRLF checkout intentionally differs from the normalized LF index blob and matches the CRLF bytes read by the analyzer. Dirty tracked and untracked files match their current bytes.

Linked-worktree tests must prove primary and linked roots resolve the same unified DB path and that reachability includes detached linked-worktree HEADs plus dirty/untracked content from every worktree.

Liveness tests must prove an edited path invalidates an old filesystem snapshot, an untracked entry appears through the explicit filesystem overlay until the index owns it, an in-memory overlay overrides a tracked index entry, and forked/replaced `LivePathMap` snapshots remain isolated.

Cache tests must prove semantic-prefixed tables exist, analyzer tables do not, `analyzer_schema_version` remains zero, legacy semantic files are removed only when creating the unified DB, and symlinked cache paths are rejected before deletion or SQLite open.

Analyzer regressions must prove normal construction and queries remain resident and do not create the unified database. No SQL analyzer parity, hydration, reconciliation, or persisted query test belongs in this issue.

## Idempotence and Recovery

Formatting, tests, clippy, and cache tests use temporary directories and are safe to repeat. The cache is rebuildable: a schema mismatch may recreate the whole unified database only while analyzer version is zero; a nonzero analyzer version is rejected without mutation so an older binary cannot damage a future backend. If a milestone fails, leave its edits visible, update `Progress` with completed and remaining work, and fix forward. Never reset unrelated user changes. The donor worktree remains read-only.

## Artifacts and Notes

The authoritative donor seams are `src/gitblob.rs`, `src/analyzer/store/liveness.rs`, `src/cache_db.rs`, `src/cache_gc.rs`, and the semantic adaptations in PR #447. Copy concepts, not the combined backend: exclude donor analyzer schema creation, `AnalyzerStore`, `query.rs`, hydration, reconciliation, and `TreeSitterAnalyzer` store contexts.

## Interfaces and Dependencies

`src/gitblob.rs` provides repository discovery, primary-root/cache-path resolution, exact-byte bulk/targeted/full/single-path OIDs, blob reads, worktree roots/HEADs, reachable Bloom construction, and uncommitted OIDs. `src/nlp/gitcache.rs` preserves the previous public functions through explicit wrappers. New primary-root, cache-path, full-index, single-path, and worktree-HEAD helpers remain crate-internal.

`src/cache_db.rs` provides the unified DB filename, safe connection setup, semantic schema lifecycle, shared cache state, and current time. The analyzer namespace is represented only by version zero.

`src/cache_gc.rs` provides semantic-only forced and opportunistic GC outcomes. It uses shared Git liveness and cache-state claims but has no analyzer import.

`src/analyzer/store/liveness.rs` provides crate-internal `Liveness`, `LivePathMap`, `LiveSnapshot`, `LivePathEntry`, and `LivePathValidation`. These types accept explicit filesystem or overlay identities and remain unused by production analyzer paths in #584.

`growable-bloom-filter` remains available for shared reachability, while the current cache/GC consumer is feature-gated with NLP. The base build retains only the exact-byte Git helpers required by inert analyzer liveness. No other dependency changes are required.

Plan revision note (2026-07-10): recorded post-review CRLF GC liveness, safe legacy cleanup, worktree-liveness centralization, direct path-normalization imports, no-NLP CI feature gating, updated validation counts, and the rebuildable-cache compatibility policy.

CI repair note (2026-07-10): rebasing onto current `master` exposed Windows-only raw-versus-verbatim root comparisons. Absolute project lookup, multi-root lookup, overlays, and watcher events now normalize at their shared input boundaries; formatter, watcher, and scoped-project assertions validate the normalized-root contract. Legacy cache cleanup closes its successful exclusive SQLite claim before removal so Windows can unlink the rebuildable legacy files. Focused cache/path tests, strict full/no-NLP clippy with the Rustup toolchain, formatting, and whitespace validation passed. The broad local library run had four unrelated sandbox-sensitive subprocess/sidecar timeouts.
