# Prepare analyzer queries for a future storage backend

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept current as work proceeds. Maintain this document in accordance with `.agents/PLANS.md`.

## Purpose / Big Picture

Issue #583 is the first prerequisite extracted from the combined SQLite analyzer work in PR #447. After this change, analyzer consumers use query contracts that can return values produced outside the resident in-memory state, while current construction, updates, persistence, and user-visible analysis behavior remain unchanged. The observable proof is that the owned query primitives and their convenience aliases return the same Java, Python, and multi-language results, and the existing definition, usage, LSP, and SearchTools tests remain green.

This issue does not add a database, cache schema, Git blob liveness, a persisted query backend, or backend selection. The local worktree at `/Users/dave/.codex/worktrees/42d7/bifrost` is reference material only.

## Progress

- [x] (2026-07-10) Verified the existing issue branch is clean and rebased on latest `origin/master`.
- [x] (2026-07-10) Inspected issue #583, the current analyzer contracts, and the donor implementation seams.
- [x] (2026-07-10) Converted the storage-sensitive analyzer query primitives to owned result types and centralized all convenience aliases on those primitives.
- [x] (2026-07-10) Added the crate-internal storage-adapter contract and path-sensitive language overrides without activating it.
- [x] (2026-07-10) Added and passed focused parity coverage for owned queries and adapter semantics.
- [x] (2026-07-10) Ran final formatting, non-CUDA all-target clippy, focused behavioral tests, and diff checks.
- [x] (2026-07-10) Recorded final outcomes and checkpoint commits on the existing branch without pushing.

## Surprises & Discoveries

- Observation: The donor branch combines roughly two hundred files of analyzer, SQLite, cache, liveness, and test work, but the owned-query seam is concentrated in `IAnalyzer`, `TreeSitterAnalyzer`, `MultiAnalyzer`, language delegates, and their direct callers.
  Evidence: The donor history separates `M4b: owned IAnalyzer primitives` from the earlier SQL-backed query commits and later cache/liveness work.

- Observation: Current `IAnalyzer` exposes both borrowed primitives and owned `get_*`/`*_of` wrappers. Keeping the wrappers as default aliases avoids unnecessary test churn while still ensuring all future backends implement one primitive query path.
  Evidence: `src/analyzer/i_analyzer.rs` currently clones borrowed primitive results in each wrapper, while several language analyzers redundantly override both layers.

- Observation: `ImportAnalysisProvider::import_info_of` is not part of the storage-sensitive query seam and can remain borrowed in this issue.
  Evidence: Converting it created unrelated churn in import resolvers, while the approved interface list only requires `IAnalyzer` imports to become owned.

- Observation: Rust's public-bound lints require the companion trait and `FileState` to be lexically public because `TreeSitterAnalyzer` is public, even though both live in a crate-private module and the trait is re-exported only as `pub(crate)`.
  Evidence: More restrictive declarations produced `private_bounds`/private-interface warnings during `cargo check`; the current module boundary keeps the contract crate-internal without lint suppression.

- Observation: This machine has matching-version Rust and Clippy installations built against different LLVM patch releases, so the repository alias initially rejected dependency metadata even in a separate target directory.
  Evidence: Homebrew `clippy-driver` reported LLVM 22.1.6 while the selected Rust toolchain reported LLVM 22.1.2. Running the alias with the Rustup toolchain directory first in `PATH` and an isolated `CARGO_TARGET_DIR` completed successfully.

## Decision Log

- Decision: Keep `TreeSitterAnalyzer` backed by the current `AnalyzerState` and clone only at the owned query boundary.
  Rationale: This prepares consumers for non-resident results without introducing or activating a backend in issue #583.
  Date/Author: 2026-07-10 / Codex.

- Decision: Preserve the existing convenience methods as default forwarding aliases and remove every concrete language and multi-analyzer override.
  Rationale: The final storage backend can implement each owned primitive once, and parity tests prove the aliases reach that exact primitive path without behavior changes.
  Date/Author: 2026-07-10 / Codex.

- Decision: Put storage-specific language hooks in a crate-internal companion trait rather than expanding the public parsing-oriented `LanguageAdapter` API.
  Rationale: The future backend needs path-independent storage semantics, but external language-adapter implementers do not need internal `FileState` hydration details.
  Date/Author: 2026-07-10 / Codex.

- Decision: Keep existing analyzer persistence and `search_definitions_persisted` unchanged.
  Rationale: Replacing or activating persistence belongs to the final SQLite integration, not this prerequisite.
  Date/Author: 2026-07-10 / Codex.

- Decision: Keep `ImportAnalysisProvider::import_info_of` borrowed.
  Rationale: It is outside the approved `IAnalyzer` API migration and does not need to support a future storage query in #583.
  Date/Author: 2026-07-10 / Codex.

## Outcomes & Retrospective

Implementation and validation are complete. `IAnalyzer`, `TreeSitterAnalyzer`, every language delegate, and `MultiAnalyzer` now expose owned storage-sensitive query results; `all_declarations_with_primary_ranges` provides the future bulk range seam; and all convenience aliases are centralized defaults. The storage adapter remains inert and has no database, liveness, cache, or backend-selection dependency.

The focused validation passed 4 storage-adapter unit tests, 7 query-parity tests (including the shared harness tests), 158 LSP tests, 397 definition tests, 17 multi-analyzer tests, 104 SearchTools tests with one pre-existing expensive smoke test ignored, and 5 usage-identity tests. `cargo clippy-no-cuda` passed all non-CUDA targets with warnings denied, `cargo fmt --all` completed, and `git diff --check` reported no errors.

Checkpoint `7200eecf` records the owned query and adapter implementation plus its primary parity coverage. A final validation checkpoint accompanies this completed ExecPlan and the all-target ownership-boundary fixes. No changes were made to dependencies, analyzer persistence, `search_definitions_persisted`, backend activation, cache/liveness code, or SQLite store modules.

## Context and Orientation

`src/analyzer/i_analyzer.rs` defines `IAnalyzer`, the shared query interface used by analyzers, usage resolution, LSP handlers, SearchTools, and code-quality features. Its storage-sensitive primitives currently yield references borrowed from resident `AnalyzerState`, and default `get_*` helpers clone those references into owned values.

`src/analyzer/tree_sitter_analyzer.rs` owns the generic tree-sitter implementation. `FileState` stores per-file declarations, imports, ranges, signatures, hierarchy edges, test metadata, source, and parse errors. `AnalyzerState` combines file states into workspace indexes. This issue keeps both structures and the existing build/update path.

Concrete language analyzers under `src/analyzer/<language>/` wrap `TreeSitterAnalyzer` and implement `IAnalyzer`. `src/analyzer/multi_analyzer.rs` combines those analyzers. These delegates must change their primitive signatures but must not gain any SQL or cache dependency.

A “storage adapter” in this plan means a crate-internal language contract that separates content-derived data, which may eventually be stored once per content blob, from path-derived data, which must be reconstructed for the live file path. The contract is inert in this issue: no current build or query path invokes a database.

## Plan of Work

First, change `IAnalyzer` primitives to return owned values. `top_level_declarations` returns `Vec<CodeUnit>`, `analyzed_files` returns `Vec<ProjectFile>`, `all_declarations` yields owned `CodeUnit`s, `declarations` returns `BTreeSet<CodeUnit>`, `definitions` yields owned `CodeUnit`s, and children/import/range/signature queries return owned vectors. Add `all_declarations_with_primary_ranges` with a correct default implementation. Keep existing convenience aliases, but make them forward to the owned primitives without another clone layer.

Next, adapt `TreeSitterAnalyzer`, `MultiAnalyzer`, and each concrete language delegate. The in-memory implementation clones collections from immutable state. Callers that use primitive iterators must stop calling `.cloned()` and must borrow owned loop variables when passing them to another query. Do not import donor memoization, SQL query helpers, store contexts, or liveness types.

Then add a crate-internal storage-adapter trait beside `LanguageAdapter`. Defaults preserve content qualifiers and test flags, exclude only file-scope units, use the analyzer language label as the storage key, and perform no hydration synthesis. Override the contract only where the donor proved path dependence: Python, Rust, and Go recompute path-dependent package/module names; JavaScript and TypeScript separate source-derived and path-derived test detection and synthesize path-derived module units; TypeScript distinguishes TypeScript and TSX parser keys. The trait remains unused in production for this issue and is covered directly by unit tests.

Finally, add an inline-project integration test that exercises Java, Python, and `MultiAnalyzer` queries through both the owned primitives and convenience aliases. Assert real declarations, definitions, children, imports, ranges, signatures, and primary ranges. Run focused definition, usage, LSP, and SearchTools suites, then formatting, non-CUDA clippy, and diff checks.

## Concrete Steps

All commands run from `/Users/dave/.codex/worktrees/0326/bifrost`.

Before editing, synchronize the existing branch:

    git fetch
    git rebase origin/master

After implementing query contracts and their direct callers, format and compile:

    cargo fmt
    cargo clippy-no-cuda

Run adapter and query parity tests with semantic indexing disabled:

    BIFROST_SEMANTIC_INDEX=off cargo test --lib storage_adapter_
    BIFROST_SEMANTIC_INDEX=off cargo test --test analyzer_query_parity --test multi_analyzer_test --test get_definition_test --test usage_graph_identity_test --test searchtools_service --test bifrost_lsp_server

Finish with repository hygiene checks:

    git diff --check
    git status --short

Expected results are zero test failures, zero clippy warnings, and no whitespace errors. Stage and commit only files changed for each verified milestone; do not push or open a pull request.

## Validation and Acceptance

The new parity test must demonstrate that owned primitive queries and the retained aliases report identical Java, Python, and combined analyzer results. It must also show the expected semantic content: top-level and nested declarations, definitions by FQ name, direct children, imports, non-empty ranges, signatures where present, and primary-range pairs.

Adapter unit tests must show that default hooks are identity/no-op operations, Python/Rust/Go qualifiers reconstruct from a live file path, JavaScript/TypeScript reconstruct path-derived module/test state, and `.ts` versus `.tsx` receive distinct parser storage keys. These tests must not open or inspect a database.

Existing focused tests must prove unchanged definition lookup, usage graph identity, LSP behavior, multi-language routing, and SearchTools behavior. `cargo clippy-no-cuda` must compile all non-CUDA targets without warnings.

## Idempotence and Recovery

Formatting, tests, clippy, and diff checks are safe to repeat. The new storage-adapter contract is inert, so a failing adapter test cannot change runtime state. If a mechanical owned-value migration fails to compile, use the compiler errors to update only direct consumers; do not import donor store code as a shortcut. Existing user changes must not be reset or swept into a checkpoint commit.

## Artifacts and Notes

The authoritative donor seam is the API shape in `/Users/dave/.codex/worktrees/42d7/bifrost`, especially the owned-query changes associated with donor commit `23ea77d0`. Store/query files and later liveness/cache commits are explicitly excluded.

## Interfaces and Dependencies

No dependency changes are allowed. At completion, `IAnalyzer` exposes owned query primitives and `all_declarations_with_primary_ranges`. The exact collection types are `Vec`, `BTreeSet`, and boxed owned iterators as appropriate. Existing convenience aliases remain callable and delegate to those primitives.

The crate-internal storage-adapter trait supplies storage language keys, qualifier storage/hydration, persistable-unit filtering, stored/hydrated test metadata, and hydrated synthetic-unit reconstruction. It uses existing analyzer model types only and has no database or Git dependency.
