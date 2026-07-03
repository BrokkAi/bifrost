# Refactor analyzer state to borrowed views and hash collections

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document follows `.agent/PLANS.md`. It is self-contained and describes how to change the Rust analyzer API so callers borrow immutable analyzer state instead of repeatedly cloning sorted collections.

## Purpose / Big Picture

The current Rust port exposes many immutable analyzer collections as owned `Vec`, `BTreeMap`, or `BTreeSet` values. A profile of a running `generate.py` workload showed substantial native CPU in comparison-heavy sorted collections, including `ProjectFile` path comparisons and `CodeUnit` ordering. After this change, analyzer callers will iterate borrowed state directly and the analyzer will use `HashMap` and `HashSet` for internal lookup/uniqueness when no semantic sorting is required. This should reduce clone and comparison overhead while preserving semantic behavior. Any caller that truly needs deterministic order must sort explicitly at the point where it renders or asserts an ordered output.

## Progress

- [x] (2026-04-23T07:22:28Z) Read `.agent/PLANS.md` and current trait/state layout.
- [x] (2026-04-23T07:22:28Z) Recorded the implementation strategy and API shape in this ExecPlan.
- [x] (2026-04-23T07:26:50Z) Converted `IAnalyzer` and `ImportAnalysisProvider` to include borrowed state-view methods while keeping owned adapter methods for compatibility.
- [x] (2026-04-23T07:26:50Z) Updated `TreeSitterAnalyzer`, language analyzer wrappers, `MultiAnalyzer`, `WorkspaceAnalyzer`, and the searchtools test helper to compile against the borrowed-view API.
- [x] (2026-04-23T08:05:12Z) Replaced internal analyzer state maps/sets and language capability caches with `HashMap`/`HashSet` where order is not semantic.
- [x] (2026-04-23T08:05:12Z) Migrated hot internal callers in analyzer helpers, searchtools, summary, and relevance to borrowed iterator/slice APIs.
- [x] (2026-04-23T08:05:12Z) Ran formatting and validation; updated tests that require deterministic comparison to sort/collect at the assertion boundary.

## Surprises & Discoveries

- Observation: `IAnalyzer` is used as a trait object in boundary code such as searchtools and summary, so borrowed iterators must be object-safe.
  Evidence: `src/searchtools.rs` accepts `&dyn IAnalyzer`; `src/summary.rs` accepts analyzer trait references.

- Observation: The borrowed-view compatibility layer compiles and passes the library test suite before changing storage types.
  Evidence: `cargo check` finished successfully; `cargo test --lib` reported `27 passed; 0 failed; 36 ignored`.

- Observation: The storage and capability cache conversion compiles without any analyzer-order regressions in the local suites.
  Evidence: `cargo check`, `cargo fmt --check`, `cargo test --lib`, `cargo test --test model_handle_semantics`, and focused import/hierarchy integration tests all passed.

- Observation: The `most_relevant_files` integration binary compiles and its local tests pass, but Brokk-reference cases cannot run in this checkout.
  Evidence: `cargo test --test most_relevant_files` failed only in reference invocations with `ClassNotFoundException: ai.brokk.tools.MostRelevantFilesCli` or missing Gradle task `:app:runMostRelevantFiles`.

## Decision Log

- Decision: Use `Box<dyn Iterator<Item = &T> + '_>` for borrowed iterator trait methods.
  Rationale: It preserves `dyn IAnalyzer` object safety. Returning `impl Iterator` or generic associated iterator types would force a broader dispatch redesign.
  Date/Author: 2026-04-23 / Codex.

- Decision: Preserve deterministic order only when caller analysis proves an order-sensitive contract.
  Rationale: The user explicitly clarified that Python/MCP JSON order may change unless explicitly guaranteed, and tests/rendering paths that require order should own the sort.
  Date/Author: 2026-04-23 / Codex.

- Decision: Keep owned returns for computed text and computed result sets in the first implementation pass.
  Rationale: Source blocks and skeletons are derived strings, not stored state. Import/reference/hierarchy/search result sets are computed outputs and can be optimized separately after the state-view refactor lands.
  Date/Author: 2026-04-23 / Codex.

- Decision: Change set-valued capability results and their caches to `HashSet`, while sorting only at tests or ranking/rendering code that has an explicit deterministic need.
  Rationale: Import/reference/relevant-import/direct-descendant APIs express uniqueness, not sorted order. Tests that compared against `BTreeSet` now collect into `BTreeSet` at the assertion boundary.
  Date/Author: 2026-04-23 / Codex.

## Outcomes & Retrospective

Milestone outcome 2026-04-23: The analyzer trait now has borrowed-view accessors and implementations delegate through them. Existing owned `get_*` methods remain as compatibility adapters so callers can be migrated incrementally.

Milestone outcome 2026-04-23: `TreeSitterAnalyzer` now stores file/index state in hash maps and hash sets where no ordering contract exists. Language analyzer import/reference/type-hierarchy caches also use hash sets for uniqueness. Searchtools, summary, relevance, Java/Python/JS/TS/Go/Rust/C++ import resolution, and shared analyzer helpers iterate borrowed analyzer state directly and clone only when they need owned return values.

Validation outcome 2026-04-23: `cargo fmt --check`, `cargo check`, `cargo test --lib`, `cargo test --test model_handle_semantics`, `cargo test --tests --no-run`, and focused import/hierarchy integration tests passed. `cargo test --test most_relevant_files` was attempted; non-reference tests passed, while reference parity tests failed because the Java Brokk reference CLI/task is unavailable in this workspace.

## Context and Orientation

The core trait is `IAnalyzer` in `src/analyzer/i_analyzer.rs`. It is implemented by `TreeSitterAnalyzer` in `src/analyzer/tree_sitter_analyzer.rs`, by per-language wrappers such as `src/analyzer/java_analyzer.rs`, and by `MultiAnalyzer` in `src/analyzer/multi_analyzer.rs`. The tree-sitter analyzer stores immutable indexed state in `AnalyzerState`, currently behind `Arc<AnalyzerState>`. Refresh/update creates a new analyzer state rather than mutating the old state in place.

The word "borrowed view" means a method returns references to data already stored inside the analyzer, for example `&CodeUnit` or `&[Range]`, rather than cloning the data into a new owned collection. The word "boundary" means an API that must materialize owned values for serialization or rendered output, such as MCP JSON responses or generated source text.

## Plan of Work

First, change `IAnalyzer` and `ImportAnalysisProvider` signatures for state-backed accessors. The final trait must include borrowed methods named `top_level_declarations`, `analyzed_files`, `declarations`, `definitions`, `direct_children`, `import_statements`, `ranges`, and `signatures`. Implementations should return boxed iterators or slices. Existing owned-style callers should be updated to clone only where ownership is required.

Second, update `TreeSitterAnalyzer` and the per-language wrappers. `TreeSitterAnalyzer` should expose borrowed views directly from `AnalyzerState` and `FileState`. Wrappers should delegate to `inner` and return borrowed views, not cloned collections. `MultiAnalyzer` must combine multiple delegates with boxed iterators; where the target language is known, it should delegate directly. When it must aggregate across languages, use `Vec<&T>` or chained boxed iterators internally without cloning unless returning a computed owned result.

Third, replace sorted storage with hash storage where sorting is not semantic. In `TreeSitterAnalyzer`, convert `AnalyzerState.files`, `definitions`, `children`, `module_children`, `ranges`, `raw_supertypes`, `signatures`, and `classes_by_package` to `HashMap`; convert `type_aliases`, `ParsedFile.type_identifiers`, and `ParsedFile.type_aliases` to `HashSet`. Keep `Vec` for inherently ordered data such as top-level declarations, imports, import statements, source ranges, and child lists. Convert caches in language analyzers from `BTreeMap`/`BTreeSet` to hash maps/sets only when they are lookup or membership caches. If a rendered output or test relies on order, sort in that caller.

Fourth, run validation. Fix compiler errors mechanically, then address test failures by deciding whether the failing path has a semantic ordering contract. If it does, sort at that caller. If it does not, relax the assertion or adapt it to compare sets.

## Concrete Steps

From `/home/jonathan/Projects/bifrost`, use these commands during implementation:

    cargo fmt --check
    cargo check
    cargo test --lib
    cargo test --test model_handle_semantics

If the external Brokk reference runner is present, also run:

    cargo test --test most_relevant_files

If `cargo fmt --check` reports only formatting, run `cargo fmt` and repeat `cargo fmt --check`.

## Validation and Acceptance

The refactor is accepted when `cargo check`, `cargo test --lib`, and focused analyzer tests pass, and the code no longer clones stored analyzer collections merely to iterate them. The observable behavior is that normal analyzer operations still pass tests while internal accessors use borrowed views and hash collections. Performance validation is to profile `generate.py` again with `perf` and confirm that `ProjectFile::cmp`, `std::path::compare_components`, and clone-heavy accessor paths are materially reduced from the previous sample.

## Idempotence and Recovery

The refactor is safe to repeat because it is source-only. If a step fails, use `git diff` to inspect partial edits and continue fixing compiler errors. Do not reset or discard user changes. If a specific hash conversion causes a semantic ordering failure, revert only that conversion or add explicit sorting at the ordering-sensitive caller.

## Artifacts and Notes

The prior profile artifacts were:

    /tmp/bifrost-generate-3956946.perf.data
    /tmp/bifrost-generate-3956946-dwarf.perf.data

Those showed `_native.abi3.so` dominating sampled CPU and path comparisons visible under `TreeSitterAnalyzer::file_state` and `package_name_of`.

## Interfaces and Dependencies

At the end of this work, `IAnalyzer` in `src/analyzer/i_analyzer.rs` should include object-safe borrowed accessors with signatures equivalent to:

    fn top_level_declarations<'a>(&'a self, file: &ProjectFile) -> Box<dyn Iterator<Item = &'a CodeUnit> + 'a>;
    fn analyzed_files<'a>(&'a self) -> Box<dyn Iterator<Item = &'a ProjectFile> + 'a>;
    fn declarations<'a>(&'a self, file: &ProjectFile) -> Box<dyn Iterator<Item = &'a CodeUnit> + 'a>;
    fn definitions<'a>(&'a self, fq_name: &str) -> Box<dyn Iterator<Item = &'a CodeUnit> + 'a>;
    fn direct_children<'a>(&'a self, code_unit: &CodeUnit) -> Box<dyn Iterator<Item = &'a CodeUnit> + 'a>;
    fn import_statements<'a>(&'a self, file: &ProjectFile) -> &'a [String];
    fn ranges<'a>(&'a self, code_unit: &CodeUnit) -> &'a [Range];
    fn signatures<'a>(&'a self, code_unit: &CodeUnit) -> &'a [String];

`ImportAnalysisProvider` in `src/analyzer/capabilities.rs` should include:

    fn import_info_of<'a>(&'a self, file: &ProjectFile) -> &'a [ImportInfo];

Owned methods that compute new values may remain owned.

Revision note 2026-04-23: Initial ExecPlan created before implementation to satisfy repository instructions for significant refactors.
