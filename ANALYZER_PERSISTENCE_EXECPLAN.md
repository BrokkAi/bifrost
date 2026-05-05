# Analyzer Persistence And Startup Reconcile

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document follows `.agent/PLANS.md` from the repository root. It is self-contained so a new contributor can resume the work with only this file and the current tree.

## Purpose / Big Picture

Starting Bifrost currently rebuilds each tree-sitter analyzer from source files, even when the workspace has not changed. After this change, each language analyzer can load clean per-file analysis from an on-disk cache, compare the current files against stored staleness keys, reparse only dirty files, and rebuild the immutable in-memory `AnalyzerState` from the merged payloads. A user can observe the behavior by constructing an analyzer twice over the same temporary project and seeing that the second analyzer still returns definitions after the source file is removed only when the cache is correctly invalidated; tests also verify that unchanged files are hydrated and changed/deleted files are reconciled.

## Progress

- [x] (2026-05-05 00:00Z) Read GitHub issue #1 and confirmed the missing pieces: disk persistence, staleness keys, analysis epoch, schema/version handling, startup reconcile, and persisted symbol rows.
- [x] (2026-05-05 00:10Z) Inspected `src/analyzer/tree_sitter_analyzer.rs`, `src/analyzer/model.rs`, `src/analyzer/project.rs`, and `src/analyzer/config.rs` to find the narrowest integration point.
- [x] (2026-05-05 00:20Z) Added `AnalyzerPersistenceConfig` to `AnalyzerConfig`, including enable/disable, explicit cache directory, and analysis epoch settings.
- [x] (2026-05-05 00:35Z) Added `src/analyzer/persistence.rs` with a schema-versioned JSON document, per-file staleness keys, serialized per-file payloads, and persisted symbol rows.
- [x] (2026-05-05 00:45Z) Wired `TreeSitterAnalyzer::build_state` through startup reconcile: clean files hydrate from cache, dirty or new files parse, deleted files drop out, and the merged payload is saved.
- [x] (2026-05-05 00:55Z) Added focused Rust tests proving hydration, dirty-file reanalysis, deletion removal, epoch invalidation, and corrupt-cache recovery.
- [x] (2026-05-05 01:05Z) Ran formatting, targeted tests, and full `cargo test`, then updated this plan with outcomes.

## Surprises & Discoveries

- Observation: `FileState` already contains all per-file payloads needed to rebuild the global indexes, and `TreeSitterAnalyzer::index_state` already accepts a complete per-file map.
  Evidence: `AnalyzerState` stores `files: HashMap<ProjectFile, FileState>` and `index_state(files, project, adapter)` builds `definitions`, `children`, `module_children`, `ranges`, `raw_supertypes`, `signatures`, and `classes_by_package`.
- Observation: `ProjectFile` and `CodeUnit` are Arc-backed and do not derive serde traits, so persistence needs a DTO layer rather than deriving serialization on the main identity types.
  Evidence: `src/analyzer/model.rs` defines `ProjectFile(Arc<ProjectFileInner>)` and `CodeUnit(Arc<CodeUnitInner>)`.
- Observation: Some tests intentionally compare two analyzer builds with different parallelism and should not share a persistence cache.
  Evidence: `cargo test --test java_parallel_and_cache` initially failed because the second analyzer hydrated the first analyzer's cache instead of exercising its own parallel parse path. The test now disables persistence explicitly.
- Observation: Default cache placement must not create untracked `target/` directories inside fixture roots.
  Evidence: A fixture-root Java analyzer generated `tests/fixtures/testcode-java/target/bifrost-analyzer-cache/java.json`; the default cache path now uses the nearest enclosing Git root's `target/bifrost-analyzer-cache/<project-hash>` when a Git root exists.

## Decision Log

- Decision: Implement the first persistence layer as JSON files under `target/bifrost-analyzer-cache` instead of adding SQLite in this change.
  Rationale: The repo already depends on `serde_json`, the per-file analyzer payload is private Rust data, and the first high-value behavior is startup reconcile and payload hydration. The stored format still includes schema version, analysis epoch, staleness keys, and symbol rows so it can migrate to SQLite/FTS later without changing analyzer semantics.
  Date/Author: 2026-05-05 / Codex.
- Decision: Keep the serving path immutable by hydrating `FileState` values and then rebuilding `AnalyzerState` with the existing `index_state` function.
  Rationale: This preserves the current query behavior and avoids introducing mutable disk access into `definitions`, `direct_children`, `ranges`, and source rendering.
  Date/Author: 2026-05-05 / Codex.
- Decision: Put default caches under the nearest enclosing Git root's `target/bifrost-analyzer-cache/<project-hash>` instead of always using `<project-root>/target`.
  Rationale: Real repositories still get a stable ignored cache under `target`, while fixture subdirectories inside this repository do not accumulate untracked cache files.
  Date/Author: 2026-05-05 / Codex.
- Decision: Disable persistence explicitly in `tests/java_parallel_and_cache.rs`.
  Rationale: That test is about comparing independent sequential and parallel parse results. Sharing a cache would bypass the second parse and make the test stop measuring the behavior named in the test.
  Date/Author: 2026-05-05 / Codex.

## Outcomes & Retrospective

Implemented the first cache-backed startup reconcile path. The analyzer now persists per-file payloads and symbol rows, reuses clean cached payloads on construction, reparses dirty files, removes deleted files, invalidates rows by analysis epoch, and falls back safely from corrupt cache documents. The long-term SQLite/FTS storage substrate remains future work, but the cache boundary and reconcile semantics are now present and tested.

## Context and Orientation

`src/analyzer/tree_sitter_analyzer.rs` is the generic analyzer used by language adapters such as Rust, Java, Python, and TypeScript. A `FileState` is the parsed data for one source file: source text, declarations, imports, ranges, children, signatures, and test-detection state. An `AnalyzerState` is the immutable in-memory snapshot used by query methods; it owns all `FileState` values and global lookup maps such as `definitions`.

`TreeSitterAnalyzer::build_state` currently enumerates every analyzable file for a language and passes all of them to `analyze_files`. That is the cold-start cost. The new path should first try to load clean `FileState` values from disk, compute dirty files by comparing stored and current staleness keys, parse only dirty files, remove deleted entries, then call `index_state`.

A staleness key is cheap metadata used to decide whether a cached row still describes the source file. This implementation stores file size, modified time in nanoseconds since the Unix epoch, a source hash, and an analysis epoch. The analysis epoch is a number that is bumped when parser queries or analyzer heuristics change in a way that makes old cache rows logically stale even if the file did not change.

## Plan of Work

First, extend `AnalyzerConfig` with an `AnalyzerPersistenceConfig` that defaults to enabled and writes under `target/bifrost-analyzer-cache/<project-hash>` at the nearest enclosing Git root when one exists. If no enclosing Git root exists, use the project root's `target/bifrost-analyzer-cache/<project-hash>`. The config allows tests and callers to disable persistence, override the cache directory, or override the analysis epoch.

Second, add `src/analyzer/persistence.rs`. It should define a JSON cache document with a schema version, language, analysis epoch, per-file entries, and persisted symbol rows. It should serialize Arc-backed `ProjectFile` and `CodeUnit` values through plain data-transfer structs. It should expose methods to load clean files for a current analyzable-file set and save the merged file map.

Third, wire `TreeSitterAnalyzer::build_state` so that cold construction and `update_all` perform startup reconcile. If the cache cannot be loaded, has the wrong schema, has a wrong language, or contains invalid JSON, the analyzer should fall back to parsing all current analyzable files and then overwrite the cache with a fresh document.

Fourth, add tests in a new file under `tests/` using `RustAnalyzer` and temporary projects. The tests should prove that a second analyzer can hydrate unchanged data from cache, that changed files are reanalyzed, that deleted files disappear, that a bumped epoch forces reanalysis, and that corrupt cache content does not break analyzer construction.

## Concrete Steps

Run all commands from `/Users/ryansvihla/.codex/worktrees/9f71/bifrost`.

After editing, run:

    cargo fmt
    cargo test --test analyzer_persistence
    cargo test --test rust_analyzer_update_test

If those pass, run the broader analyzer tests that are most likely to be affected:

    cargo test --test rust_analyzer_parity rust_updates_add_and_remove_definitions
    cargo test --test java_parallel_and_cache
    cargo test

## Validation and Acceptance

Acceptance is behavioral. A test should create a temporary Rust project with `lib.rs`, construct `RustAnalyzer` with persistence enabled and an explicit temp cache directory, then construct a second analyzer over the same project and assert that `get_definitions("foo")` still returns the cached function without needing to change source. A companion test should modify `lib.rs`, construct another analyzer, and assert that the new definition is visible. Another test should remove `lib.rs`, construct another analyzer, and assert that the old definition is gone. A corrupt cache file should be ignored and replaced, not surfaced as an analyzer error.

## Idempotence and Recovery

The cache lives under a generated directory and can be deleted safely. If a cache write fails, analyzer construction still returns a working in-memory analyzer based on parsed source files. If a cache read fails or a document has the wrong schema, the analyzer parses current files and overwrites the cache on the next save. Tests use temporary directories for explicit persistence checks, and the default cache path avoids writing untracked files under checked-in fixture directories.

## Artifacts and Notes

The GitHub issue recommends SQLite plus FTS5 as the long-term substrate. This first implementation deliberately stores symbol rows in the JSON document but still serves symbol queries from the rebuilt in-memory `definitions` map. That keeps the first merge small while preserving the data boundary needed for a later SQLite migration.

## Interfaces and Dependencies

In `src/analyzer/config.rs`, define:

    pub struct AnalyzerPersistenceConfig {
        pub enabled: bool,
        pub cache_dir: Option<PathBuf>,
        pub analysis_epoch: u64,
    }

In `src/analyzer/persistence.rs`, define an internal `AnalyzerDiskCache` with methods similar to:

    pub(crate) fn new(root: &Path, language: Language, config: &AnalyzerPersistenceConfig) -> Option<Self>;
    pub(crate) fn load_clean_files(&self, current_files: &[ProjectFile]) -> CacheLoadResult;
    pub(crate) fn save(&self, files: &HashMap<ProjectFile, FileState>, adapter: &dyn CacheSymbolNormalizer);

The implementation should not add new runtime dependencies beyond existing `serde` and `serde_json` for this first slice.

Revision note: Created the plan after diagnosing issue #1 so the implementation can proceed with a documented first persistence slice and an explicit rationale for using JSON before SQLite.

Revision note: Updated after implementation and validation to record the JSON cache, Git-root cache placement, Java test opt-out, and passing targeted and full test commands.
