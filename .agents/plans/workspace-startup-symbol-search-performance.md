# Make warm workspace startup and symbol search fast

This ExecPlan is a living document. Keep `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` current while work proceeds.

Maintain this document as required by `.agents/PLANS.md`.

## Purpose / Big Picture

A warm Bifrost workspace must become usable almost immediately. A normal symbol search must complete in less than one second. Today, a warm Apache Camel workspace takes 9.73 seconds to become ready in a debug build. Its first no-match `search_symbols` call takes 24.04 seconds. Bifrost needlessly reads and hashes clean tracked files during setup. It also reads every declaration for a language from a shared SQLite cache during each symbol search.

After this work, Bifrost will use Git index object IDs for clean tracked files. It will hash only dirty and untracked files. It will keep one exact active-tree mapping for each live workspace. Symbol search will use that mapping and storage-side literal filtering before it creates Rust rows. Broad regular-expression searches will scan only the active workspace.

## Progress

- [x] (2026-08-05) Profiled warm Apache Camel setup and a no-match symbol search.
- [x] (2026-08-05) Identified per-file tracked-content hashing in analyzer liveness.
- [x] (2026-08-05) Identified whole-cache declaration enumeration in symbol search.
- [ ] Add focused timing and work-count instrumentation for setup and search stages.
- [ ] Replace analyzer startup point hashing with one Git-index and dirty-tree identity snapshot.
- [ ] Reuse one shared workspace file listing for language detection and analyzer enumeration.
- [ ] Measure and remove unnecessary semantic-pack activation work.
- [ ] Add an exact SQLite active-workspace identity design that supports concurrent workspaces.
- [ ] Restrict symbol candidate reads to the active workspace and add mandatory-literal filtering.
- [ ] Validate correctness, concurrency, cache reuse, and measured performance.
- [ ] Run required formatting, tests, clippy, and repository policies when available.
- [ ] Commit and push the completed change to the current branch when the user requests a push.

## Surprises & Discoveries

- Observation: Warm setup still reads and hashes every analyzable tracked file.
  Evidence: `TreeSitterAnalyzer::resolve_live_oids` calls `file.exists()` and `Liveness::oid_for_path`. The latter canonicalizes, checks, reads, and hashes the file.

- Observation: The service option that trusts a filesystem generation does not prevent startup hashing.
  Evidence: `build_persisted_for_service` changes `LivePathMap` validation only. `resolve_live_oids` still uses the point-resolution path.

- Observation: Workspace file discovery occurs more than once.
  Evidence: `FilesystemProject::with_cached_listing` calls `FilesystemProject::new`, which calls `detect_languages`. That function performs its own complete workspace collection before the cached listing serves analyzer enumeration.

- Observation: A no-match search reads the complete shared declaration corpus for each active language.
  Evidence: `search_candidate_name_rows_for_langs` filters `code_units` by language and completeness only. It returns text OIDs and names to Rust before active-tree and pattern filtering.

- Observation: The shared CodeScale database has 1,234,140 Java declarations. Apache Camel uses 331,439 declarations from its tracked blob object IDs.
  Evidence: Direct read-only SQLite counts and a temporary join against `git ls-files -s` produced these values.

- Observation: Debug Apache Camel timings are 9.73 seconds for setup and 24.04 seconds for a no-match search.
  Evidence: `BIFROST_TIMING=1` reported 5.38 seconds for `WorkspaceAnalyzer::build`, 4.35 seconds for semantic-pack activation, and 24.029 seconds for `search_symbols.resolve`.

## Decision Log

- Decision: Correct the identity design instead of adding eager router startup.
  Rationale: Eager startup hides latency but does not remove repeated file hashing or whole-cache scans. It also increases startup contention.
  Date/Author: 2026-08-05 / Codex

- Decision: Treat a Git index entry as the content identity for a clean tracked path.
  Rationale: Git already stores the exact blob object ID. Reading the file again cannot improve this identity. Dirty and untracked paths still require working-tree hashing.
  Date/Author: 2026-08-05 / Codex

- Decision: Store exact active identities as workspace, generation, relative path, language, and blob object ID.
  Rationale: The cache can share immutable blob analysis across branches and worktrees. Queries still need an exact, concurrent workspace view. A language-global generation cannot represent two live workspaces safely.
  Date/Author: 2026-08-05 / Codex

- Decision: Keep complete regular-expression semantics.
  Rationale: Storage filtering can use a mandatory literal when one exists. A pattern without one must still scan the active workspace, not the global cache.
  Date/Author: 2026-08-05 / Codex

## Outcomes & Retrospective

Profiling and design are complete. Implementation remains.

## Context and Orientation

The Bifrost repository is `/mnt/optane/bifrost-nlp`. `crates/bifrost-core/src/analyzer/project.rs` discovers workspace files. `crates/bifrost-analysis/src/analyzer/store/liveness.rs` maps workspace paths to Git blob object IDs. `crates/bifrost-analysis/src/analyzer/tree_sitter_analyzer.rs` reconciles those identities with cached parsed blobs. `crates/bifrost-analysis/src/analyzer/store/mod.rs` owns the SQLite schema and queries. `crates/bifrost-analysis/src/searchtools/navigation.rs` implements `search_symbols`.

A blob object ID is Git's content hash for one file. An active-tree identity states that one relative path in one live workspace currently has one blob object ID. Immutable analyzer records remain keyed by blob object ID and language. Active-tree records select which immutable records belong to one workspace.

The existing semantic cache has a suitable Git identity method in `crates/bifrost-nlp/src/gitcache.rs`: it obtains clean tracked identities from the index and hashes dirty or untracked paths. The analyzer layer cannot depend on the NLP crate. Move or reproduce the general identity operation in the analysis or core layer without adding an NLP dependency to `brokk-bifrost-analysis`.

## Plan of Work

First, add timing scopes and work counts around project collection, live identity resolution, missing-blob lookup, cached-state hydration, path-symbol synchronization, semantic-pack catalog setup, semantic-pack resolution, and symbol candidate storage reads. Keep instrumentation behind `BIFROST_TIMING`.

Second, replace `Liveness::oid_for_path` startup use with a bulk snapshot. Read the Git index once. Obtain dirty and untracked paths once with a Git index-to-worktree diff. Use index object IDs for clean tracked paths. Hash only dirty, untracked, overlay, or content-transform paths. Preserve staged-file behavior: the index object ID is authoritative for a clean staged path only when it matches the bytes that Bifrost analyzes. Add behavior tests for clean, dirty, staged, untracked, deleted, renamed, linked-worktree, and content-transform cases.

Third, make `FilesystemProject::with_cached_listing` fill or read its supplied `WorkspaceFileListingCache` before language detection. Detect languages from that listing. Let analyzer enumeration filter a shared `Arc` listing without cloning the complete ordered set for every language. Preserve ignore behavior and the Git-index union.

Fourth, profile semantic-pack activation with the new scopes. Do not activate an empty overlay through expensive analyzer work. Cache immutable embedded catalog bootstrap data process-wide when safe. Keep workspace model discovery workspace-specific.

Fifth, add active-workspace tables to the analyzer database. Use a stable workspace key that distinguishes concurrent worktrees. Store a generation row for each workspace and exact path rows for that generation. Publish a new generation transactionally after identity construction. Keep old active generations until no live process needs them or until bounded garbage collection can prove they are stale. Add indexes for workspace, generation, language, blob object ID, and relative path. Do not duplicate immutable code-unit data.

Sixth, change symbol candidate queries. Join `code_units` to the selected active-workspace identities before returning rows. For pattern batches with a mandatory literal, apply a storage predicate to `short_name`, `identifier`, persisted qualified names, and the content qualifier. Hydrate full candidate data only for matched keys. For patterns without a mandatory literal, enumerate the compact active name projection only. Preserve cancellation and complete-result reporting.

Finally, run correctness and timing validation. Compare result sets before and after the change on focused fixtures. Start one rmcp server with two workspaces that use one database. Run concurrent searches and refreshes. Confirm that each result stays in its selected workspace. Measure Apache Camel after a fully warm prebuild.

## Concrete Steps

Work from `/mnt/optane/bifrost-nlp`. Use `apply_patch` for edits. Do not create build targets in `/tmp`. Use normal Cargo targets when possible. Use `scripts/with-isolated-cargo-target.sh` only when isolation is necessary.

Run focused tests after each milestone. Use the shared inline-project harness for new small analyzer tests. Put new integration test modules under an existing `tests/<suite>/` directory and add them to that suite's `main.rs`.

For the final warm measurement, set `BIFROST_TIMING=1`, disable semantic indexing, use the existing CodeScale cache, and query Apache Camel. Do not trigger model embedding or a cold repository prewarm.

## Validation and Acceptance

A clean tracked workspace startup must report zero working-file content hashes. Dirty and untracked fixtures must report exactly the paths that require hashing. A staged-content fixture must analyze the correct visible bytes.

Two concurrent named workspaces that share a database must retain separate active generations. A refresh in one must not change the other workspace's symbol results.

Exact, qualified, substring, multi-pattern, and regular-expression symbol searches must return the same results as the reference implementation. A no-match literal query must not enumerate the global language corpus.

On the warm Apache Camel corpus, setup should approach one second and a normal no-match literal search should complete below one second. Record exact debug and release timings. If a remaining stage exceeds one second, profile and correct it before completion.

Run focused test binaries during development. Before completion, run:

    cargo fmt
    cargo test --workspace
    uv run --python 3.12 -- cargo test --features nlp,python
    cargo clippy --workspace --all-targets --all-features -- -D warnings

Check disk space before the NLP build. Do not run another NLP build when a sibling worktree already runs one.

The repository instructions require one `bifrost.code-smells` policy run plus each executable repository policy root. Run it only if the `bifrost-policy-checking` skill and its `run_policy` tool are installed. Report that validation as unavailable when the tool is not installed.

## Idempotence and Recovery

Schema migration must be transactional and version-keyed. A failed migration must leave the old database readable by the old binary. The current cache file naming already includes the schema version. Increase the schema version when the table contract changes so Bifrost creates a new file instead of modifying the large existing cache in place.

Warm measurements are read-mostly but can publish active generations. They are safe to repeat. Remove temporary profile files after extracting results.

## Artifacts and Notes

The baseline debug timing is:

    workspace binding                              0.3 ms
    WorkspaceAnalyzer::build                    5377.7 ms
    configured semantic-pack activation         4354.9 ms
    complete analyzer construction              9732.6 ms
    search_symbols.resolve                     24029.0 ms
    remaining search work                          6.5 ms

The flat CPU profile showed SQLite B-tree traversal, SQLite VM work, memory comparison, Git OID text parsing, path hashing, and allocation. GPU work did not appear. Semantic indexing was disabled.

## Interfaces and Dependencies

Expose one bulk Git identity operation in a layer available to `brokk-bifrost-analysis`. It must return exact relative paths, blob object IDs, and whether each identity came from the Git index or working bytes. It must not add `hf-hub`, `tokenizers`, or `fastrq` to analysis or core.

Extend `AnalyzerStore` with transactional active-workspace publication and active candidate queries. Keep SQLite access inside the store. Callers must not construct SQL fragments from model input.

Extend `SearchSymbolPatternBatch` with safe mandatory-literal information derived from the compiled pattern. An absent literal means no storage literal filter. It must never remove a valid regular-expression match.

Revision note: 2026-08-05. Created this plan after profiling showed that lazy multi-workspace startup exposed older identity and global-search costs. The user approved all six remediation items.
