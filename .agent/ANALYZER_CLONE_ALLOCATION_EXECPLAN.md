# Reduce analyzer clone and allocation pressure

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This plan follows `.agent/PLANS.md` in this repository.

## Purpose / Big Picture

Large Java repositories currently spend substantial native analyzer time and memory on cloning and moving `CodeUnit` and `ProjectFile` values. A `CodeUnit` is the analyzer's value for a class, method, field, or module; a `ProjectFile` is the analyzer's value for a root-relative file path. Both values are used as ordered map/set keys and returned through the public `IAnalyzer` API. This change reduces repeated allocation while keeping the public API shape stable, so Python searchtools calls continue to work while high-parallelism context gathering uses less memory and does less copying.

The observable outcome is that existing Rust and Python tests pass unchanged, Java wildcard import resolution produces the same results, and perf samples show less time in `CodeUnit::clone`, `Vec::clone`, and allocation/copy paths.

## Progress

- [x] (2026-04-23) Confirmed the same-root searchtools registry idea is out of scope because this workload has only one `SearchToolsClient` per root.
- [x] (2026-04-23) Identified the hot model types: `src/analyzer/model.rs` defines deep-cloned `ProjectFile` and `CodeUnit`; `src/analyzer/tree_sitter_analyzer.rs` stores and clones them through `BTreeMap` and `BTreeSet`; `src/analyzer/java_analyzer.rs` scans all declarations for wildcard imports.
- [x] (2026-04-23) Rewrote allocation-heavy comparisons and searches: `CodeUnit::cmp` compares borrowed fields, tree-sitter search scans indexed definitions, refresh uses metrics, and Java wildcard imports use an indexed package/class lookup.
- [x] (2026-04-23) Converted `ProjectFile` and `CodeUnit` to public handles over private `Arc` inner structs while preserving semantic equality, ordering, hashing, and accessors.
- [x] (2026-04-23) Added focused regression tests in `tests/model_handle_semantics.rs` for `ProjectFile`, `CodeUnit`, and Java wildcard imports.
- [x] (2026-04-23) Ran focused validation: `cargo test --test model_handle_semantics`, `cargo test --test java_parallel_and_cache`, `cargo test --test searchtools_service`, `cargo test --test java_imports_and_hierarchy`, `cargo test --test java_search_parity`, and `cargo test --test java_update_parity` all passed.
- [x] (2026-04-23) Ran full Rust validation. All ordinary analyzer/searchtools tests reached by `cargo test` passed, but `tests/most_relevant_files.rs` reference-parity cases failed because the environment lacks `ai.brokk.tools.MostRelevantFilesCli` and Gradle task `:app:runMostRelevantFiles`.
- [x] (2026-04-23) Ran Python client validation with `uv run python -m unittest python_tests/test_searchtools_client.py`; all 5 tests passed.

## Surprises & Discoveries

- Observation: `CodeUnit::cmp` currently constructs two `fq_name()` strings and clones `source` and `signature` for each comparison.
  Evidence: `src/analyzer/model.rs` implements `Ord` with tuple construction from `self.fq_name()`, `self.source.clone()`, and `self.signature.clone()`.
- Observation: Java wildcard imports currently call `self.inner.get_all_declarations()` inside each wildcard import loop.
  Evidence: `src/analyzer/java_analyzer.rs::resolve_imports_uncached` scans all declarations for each `package.*` import.
- Observation: A test-only `SummaryElement` initializer was stale and omitted `symbol` and `kind`.
  Evidence: compiling integration tests failed in `src/searchtools.rs` until the initializer included those fields.
- Observation: Making `CodeUnit::Ord` consistent with `Eq` exposed a package-summary bug where package module parents hid real class declarations.
  Evidence: `summarize_symbols_renders_brokk_style_package_headers` returned an empty summary until `summary_root_units` treated module parents as grouping context rather than roots that suppress children.
- Observation: Full `cargo test` depends on external Brokk Java/Gradle reference tooling not present in this checkout.
  Evidence: `tests/most_relevant_files.rs` failed with `ClassNotFoundException: ai.brokk.tools.MostRelevantFilesCli` and missing Gradle task `:app:runMostRelevantFiles`; unrelated analyzer and searchtools tests passed before those failures.

## Decision Log

- Decision: Do not add a same-root searchtools registry or shared PyO3 session in this change.
  Rationale: The workload has only one `SearchToolsClient` per root, so a registry would add concurrency and lifecycle complexity without reducing this workload's analyzer count.
  Date/Author: 2026-04-23 / Codex.
- Decision: Prefer `ProjectFile(Arc<ProjectFileInner>)` and `CodeUnit(Arc<CodeUnitInner>)` over `Arc<CodeUnit>` collection elements or per-field `Arc`s.
  Rationale: The public API can still return `CodeUnit` and `ProjectFile` by value, while clones share the whole immutable payload. Using `Arc<CodeUnit>` throughout would force a much larger API and collection rewrite; using `Arc` only inside fields would still copy a larger struct and perform several atomic increments per clone.
  Date/Author: 2026-04-23 / Codex.

## Outcomes & Retrospective

The clone/allocation refactor is implemented. `ProjectFile` and `CodeUnit` are cheap Arc-backed handles, search and refresh avoid broad declaration clones, Java wildcard imports use an indexed package lookup, and focused Rust plus Python validation pass. Full `cargo test` is blocked only by external most-relevant-files reference tooling absent from this environment.

## Context and Orientation

The main files are `src/analyzer/model.rs`, `src/analyzer/tree_sitter_analyzer.rs`, and `src/analyzer/java_analyzer.rs`. `model.rs` defines the value types used throughout the analyzer. `tree_sitter_analyzer.rs` parses files, builds an immutable `AnalyzerState`, and implements `IAnalyzer`. `java_analyzer.rs` wraps the generic tree-sitter analyzer with Java-specific import and hierarchy logic and owns memo caches.

`IAnalyzer` is the public Rust trait for analyzer operations. It returns owned values such as `Vec<CodeUnit>` and `BTreeSet<ProjectFile>`. This plan keeps those signatures unchanged.

## Plan of Work

First, remove allocation-heavy operations that do not require representation changes. Rewrite `CodeUnit::cmp` to compare borrowed fields directly. Change `TreeSitterAnalyzer::search_definitions` to scan the already-indexed definitions map and clone only matches. Add direct analyzer metrics so refresh and metrics code do not clone all declarations only to count them. Add a Java package/class index so wildcard import resolution looks up classes by package instead of scanning all declarations.

Second, change `ProjectFile` and `CodeUnit` into small public handle structs wrapping private `Arc` inner structs. Preserve constructors, accessors, display, ordering, hashing, and equality semantics. Pointer identity must never determine equality or order.

Third, update cache weight estimates and add focused tests for ordering, hashing, wildcard import resolution, and search stability. Then run the focused and full test suites.

## Concrete Steps

From `/home/jonathan/Projects/bifrost`, edit the files above. After each milestone, run focused tests before continuing:

    cargo test java_parallel_and_cache
    cargo test searchtools_service

At the end, run:

    cargo test
    uv run python -m unittest python_tests/test_searchtools_client.py

## Validation and Acceptance

Acceptance requires all existing tests to pass. New regression tests must prove `CodeUnit` and `ProjectFile` ordering/hashing stay semantic after the `Arc` conversion, and Java wildcard imports return the same declarations as before. Performance acceptance is measured separately on the large Ghidra workload by comparing RSS, swap, analyzer build time, and perf samples for `CodeUnit::clone`, `Vec::clone`, BTree iteration, and Java import resolution.

## Idempotence and Recovery

The code changes are ordinary source edits and tests are safe to rerun. If a representation change breaks broad tests, keep the no-allocation comparison/search changes and repair the handle conversion in small steps rather than reverting unrelated user changes.

## Artifacts and Notes

This plan intentionally excludes searchtools registries, reusable native sessions, and borrowed-return `IAnalyzer` APIs. Those can be revisited after measuring this lower-risk pass.

## Interfaces and Dependencies

No new dependencies are required. `std::sync::Arc` is sufficient. The public `CodeUnit` and `ProjectFile` constructors and accessors remain available with the same names and return types.
