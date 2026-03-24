# Port Brokk Java Analyzer To Rust

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with `.agent/PLANS.md`.

## Purpose / Big Picture

After this change, this repository will contain a Rust library that reproduces the in-memory behavior of Brokk's Java analyzer while using a Rust-native concurrent snapshot pipeline. A user will be able to load the copied Brokk Java fixtures, ask for declarations, source, skeletons, imports, and type hierarchy information, and then update the analyzer after file edits. The proof will be translated Rust tests that exercise the same behaviors as Brokk's Java test suite and keep passing under both sequential and parallel analyzer construction.

## Progress

- [x] (2026-03-24T21:05Z) Read `.agent/PLANS.md`, `analyzer.txt`, and the Brokk analyzer sources and tests under `../brokk`.
- [x] (2026-03-24T21:05Z) Fixed the v1 scope to `JavaAnalyzer + TreeSitterAnalyzer + IAnalyzer`, single-threaded, in-memory snapshots with update support, and no persisted state I/O or `MultiAnalyzer`.
- [x] (2026-03-24T21:05Z) Decided to vendor Brokk's `treesitter/` query files and `testcode-*` fixture directories unchanged.
- [x] (2026-03-24T21:19Z) Initialized the Rust crate and copied the Brokk resource trees into `resources/treesitter/` and `tests/fixtures/`.
- [x] (2026-03-24T21:19Z) Created the first Rust API scaffold for the analyzer model, project abstraction, capability traits, and public module structure.
- [x] (2026-03-24T21:19Z) Added the initial Cargo dependencies and verified that the scaffold compiles with `cargo check` on Rust `1.93.1`.
- [x] (2026-03-24T21:19Z) Replaced the placeholder `TreeSitterAnalyzer` with a single-threaded parse/index core that loads Java files, builds declaration/range indexes, tracks imports, and supports snapshot-style updates.
- [x] (2026-03-24T21:19Z) Added the first Rust smoke tests covering fixture parsing and explicit file updates; `cargo test --test java_analyzer_smoke` now passes.
- [x] (2026-03-24T21:19Z) Implemented the first Java semantic layer: import resolution with explicit-over-wildcard precedence, same-package referencing detection, raw-supertype extraction, and direct/transitive hierarchy traversal. `cargo test --test java_imports_and_hierarchy` passes.
- [x] (2026-03-24T21:19Z) Implemented a first rendering layer for class/function source extraction and recursive skeleton/header reconstruction. `cargo test --test java_source_and_skeleton` passes against the copied Java fixtures.
- [x] (2026-03-24T21:19Z) Implemented lexical scope lookup and access-expression filtering for constructor/method parameters, locals, enhanced-for variables, catch parameters, try-with-resources variables, and lambda parameters. `cargo test --test java_scope_analysis` passes.
- [x] (2026-03-24T21:19Z) Added package-module code units and implicit-constructor synthesis for classes only, with explicit constructors suppressing synthesis. `cargo test --test java_modules_and_constructors` passes.
- [x] (2026-03-24T21:19Z) Implemented comment-aware source extraction that includes immediately preceding Javadocs/comments without pulling in unrelated code from the same line. `cargo test --test java_comment_source` passes.
- [x] (2026-03-24T21:19Z) Added regression coverage for duplicate overload preservation and multi-step updates. `cargo test --test java_update_regressions` passes.
- [x] (2026-03-24T21:19Z) Added canonical callable-signature normalization coverage, including varargs. `cargo test --test java_signature_normalization` passes.
- [x] (2026-03-24T21:49Z) Closed another Java parity slice: Java-style call-receiver extraction, generic/location/anonymous-name normalization for lookups, lambda code-unit attachment to overloads, module child merging across `package-info.java`, and relevant-import selection. `cargo test --test java_parity_edges` passes.
- [x] (2026-03-24T21:51Z) Added another fixture-driven translation pass covering top-level declarations, direct class children, line-range `enclosing_code_unit` behavior, and `could_import_file` Java edge cases. `cargo test --test java_fixture_parity` passes.
- [x] (2026-03-24T21:51Z) Added declaration-inventory parity coverage for fixture-wide class enumeration, packaged-file declarations, and nested-class `short_name`/`identifier` semantics. `cargo test --test java_declarations_parity` passes.
- [x] (2026-03-24T21:52Z) Added import-detail parity coverage for import-info structure, mixed/static import resolution, circular import stability, relevant-import filtering for fully qualified types, and Java type-identifier extraction. `cargo test --test java_import_detail_parity` passes.
- [x] (2026-03-24T21:53Z) Aligned Java search behavior with Brokk's case-insensitive matching and added focused search parity tests for basic patterns, regex patterns, nested classes, and missing results. `cargo test --test java_search_parity` passes.
- [x] (2026-03-24T21:54Z) Cleaned up the current implementation to satisfy the plan's validation gate. `cargo test`, `cargo fmt --check`, and `cargo clippy --all-targets --all-features -- -D warnings` all pass.
- [x] (2026-03-24T21:57Z) Finished the remaining Java search/enclosure edge cases by adding `autocomplete_definitions`, treating record components as implicit field declarations, and rejecting empty byte ranges in `enclosing_code_unit`. `cargo test`, `cargo fmt --check`, and `cargo clippy --all-targets --all-features -- -D warnings` all pass.
- [x] (2026-03-24T22:24Z) Finished the remaining Java analyzer parity slice by translating the outstanding lambda, update, interface-constant, multi-declarator field, literal-initializer, final-varargs, comment-filtering, and method-parameter cases from Brokk's `Java*Analyzer*Test` files. This required fixing direct field-initializer lambda discovery, switching lambda `$anon$line:col` names to Brokk's zero-based coordinates, filtering anonymous structures from search, and rendering per-declarator field skeletons with literal-only initializer preservation. `cargo test`, `cargo fmt --check`, and `cargo clippy --all-targets --all-features -- -D warnings` now pass again.
- [x] (2026-03-24T23:02Z) Added a `summarize` utility plus reusable summary rendering helpers so full-path filenames and FQCNs can be rendered through the Rust analyzer using Brokk-style file/codeunit skeleton summaries. Added CLI coverage for absolute-path and FQCN resolution, and verified the fixture invocation `cargo run --quiet --bin summarize -- --root tests/fixtures/testcode-java A`.
- [x] (2026-03-24T21:49Z) The current Rust suite passes with `cargo test`.
- [x] (2026-03-24T23:41Z) Replaced the remaining sequential build/update flow with one Rayon-backed file-shard pipeline shared by initial build, `update`, and `update_all`. Files are now parsed exactly once per snapshot and reduced deterministically into immutable analyzer state.
- [x] (2026-03-24T23:41Z) Added `AnalyzerConfig` so callers can choose build parallelism and an approximate memo-cache RAM budget. The `summarize` progress hook now works with the thread-safe completion-based build callback used by the parallel pipeline.
- [x] (2026-03-24T23:41Z) Added bounded `moka` memo caches for Java import resolution, reverse referencing-file lookups, relevant imports, and direct hierarchy queries. Added focused regression coverage for sequential-vs-parallel parity and tiny-budget cache correctness. `cargo test`, `cargo fmt --check`, and `cargo clippy --all-targets --all-features -- -D warnings` all pass again.

## Surprises & Discoveries

- Observation: the user-visible Java analyzer surface is broader than declaration extraction.
  Evidence: `JavaAnalyzerTest`, `JavaImportTest`, `JavaTypeHierarchyTest`, and the update tests all exercise source reconstruction, local shadowing, access-expression filtering, import relevance, type hierarchy traversal, and snapshot updates.

- Observation: the Brokk resource corpus is already organized for direct reuse and spans more languages than Java.
  Evidence: `../brokk/app/src/main/resources/treesitter/` contains `java`, `go`, `cpp`, `javascript`, `typescript`, `python`, `rust`, `php`, `scala`, and `c_sharp`; `../brokk/app/src/test/resources/` contains matching `testcode-*` trees.

- Observation: the current environment had Rust toolchains installed through `1.93`, but `stable` was still on `1.84.0`.
  Evidence: `rustup show` reported `stable` active on `1.84.0`; `rustup run 1.93 rustc --version` reported `1.93.1`. The default toolchain has now been switched to `1.93`.

- Observation: a useful early split is to keep the generic engine responsible for parsing, indexing, ranges, and snapshot updates while pushing language semantics into `JavaAnalyzer`.
  Evidence: the generic state now compiles cleanly with declaration/import indexing, but features such as import resolution precedence and local shadowing still depend on Java-specific name resolution rules.

- Observation: a tiny Rust smoke suite is enough to catch snapshot-wrapper bugs immediately.
  Evidence: the first update smoke test failed until `JavaAnalyzer::update` and `JavaAnalyzer::update_all` stopped returning `self.clone()` and started wrapping the updated inner analyzer.

- Observation: the current import-resolution rules can already cover the key Brokk precedence cases without a full query-driven name resolver.
  Evidence: explicit imports beat wildcard imports, wildcard ambiguity is deterministic by import order, and same-package references are recoverable by matching extracted type identifiers; `cargo test --test java_imports_and_hierarchy` passes 7 tests.

- Observation: the existing declaration ranges plus lightweight stored signatures are enough to reconstruct the basic Java skeletons covered by the copied fixture tests.
  Evidence: `cargo test --test java_source_and_skeleton` passes for overloaded method source extraction, nested-class source slices, recursive class skeletons, and header-only skeletons.

- Observation: the lexical-scope cases exercised by the Java tests are coverable with a direct upward Tree-sitter walk plus a few node-specific checks.
  Evidence: `cargo test --test java_scope_analysis` passes for constructor parameters, local variables, enhanced-for variables, try-with-resources variables, lambda parameters, and field-vs-local access filtering.

- Observation: package modules and implicit constructors fit cleanly into the existing parsed-file model without broad engine changes.
  Evidence: a module code unit can be inserted as another top-level declaration with children pointing at the file's top-level classes, and synthetic constructors can be added as child function code units without source ranges; `cargo test --test java_modules_and_constructors` passes.

- Observation: comment-aware source extraction did not require storing comment ranges in analyzer state; a backward source scan from the declaration start was enough for the exercised cases.
  Evidence: `cargo test --test java_comment_source` passes for class Javadocs, method Javadocs, inner-class indentation preservation, and the inline-comment edge case.

- Observation: synthetic constructors should be resolvable but should not contribute a normal callable signature in overload-sensitive regression tests.
  Evidence: the duplicate-overload regression passed only after synthetic constructors stopped carrying a concrete `"()"` signature.

- Observation: package modules need cross-file merging semantics even though `CodeUnit` identity still includes the source file.
  Evidence: `package-info.java` and ordinary package members each create a module-shaped declaration for the same package; Brokk-style child traversal only matches expectations after module definitions are deduplicated for lookup and their child lists are merged by package FQN.

- Observation: Brokk's Java name normalization rules matter outside declaration indexing because tests query definitions with generics, location suffixes, and anonymous suffixes attached.
  Evidence: the new parity tests only passed after Java lookup normalization stripped generic type arguments, trailing `:line[:col]` suffixes, and trailing numeric anonymous-class suffixes like `$1`.

- Observation: several remaining Brokk Java tests translate directly into Rust assertions over the existing public API without exposing new engine gaps.
  Evidence: the new fixture-driven parity tests for top-level declarations, direct children, enclosing-by-lines, and `could_import_file` all passed immediately once translated.

- Observation: the current Rust `CodeUnit` naming and declaration indexing already line up with Brokk for the broader fixture inventory cases.
  Evidence: the translated declaration-parity tests for all Java fixture classes, packaged-file declarations, and nested-class identifiers passed without code changes.

- Observation: the Java import helper surface is mostly aligned now; the remaining import test work is translation-heavy rather than implementation-heavy.
  Evidence: the translated import-detail tests for import-info parsing, mixed import resolution, circular import stability, relevant-import filtering, and qualified type extraction all passed without code changes.

- Observation: search behavior was one of the last real semantic mismatches rather than a missing test translation.
  Evidence: the translated search tests required an implementation change so `search_definitions` compiles case-insensitive regexes, after which the new search parity suite passed.

- Observation: the remaining uncovered search regressions clustered around record declarations and autocomplete rather than general indexing.
  Evidence: once record components were emitted as field code units and `autocomplete_definitions` was added to the Rust `IAnalyzer` surface, the remaining translated Java search/enclosure tests passed without further engine redesign.

- Observation: Brokk's lambda naming depends on Tree-sitter's raw zero-based row/column and on whether the nearest enclosing owner is a callable or a class-like declaration.
  Evidence: the translated `JavaLambdaAnalyzerTest` only passed after direct field-initializer lambdas were traversed explicitly, `$anon$line:col` used zero-based coordinates, and class-owned lambdas were nested as `Class.Class$anon$...` while method-owned lambdas remained `Class.method$anon$...`.

- Observation: Brokk's field skeleton behavior is per-declarator, not per-field-declaration string splitting.
  Evidence: the translated interface-constant and initializer tests failed until Rust rebuilt each field signature from the declaration prefix, type node, declarator name, and only literal/boolean/null initializer nodes.

- Observation: the existing analyzer API was already sufficient to reproduce Brokk-style summary rendering without adding a separate context-manager layer.
  Evidence: the new `summarize` utility only needed `getTopLevelDeclarations`, `getDefinitions`, `getSkeleton`, and direct-ancestor traversal to render file and codeunit summaries with Brokk-like package grouping and ancestor sections.

- Observation: Rust can keep one shared concurrent architecture for both initial build and updates without adopting Java's shared mutable map model.
  Evidence: the new `TreeSitterAnalyzer` pipeline parses files into fully owned per-file shards in parallel, then rebuilds global indexes deterministically from those shards for both `new` and `update`.

- Observation: most of the Java-side cache wins translate cleanly as bounded memo caches over an immutable snapshot instead of mutable bidirectional caches intertwined with core analyzer state.
  Evidence: import resolution, referencing-file lookup, relevant-import filtering, and direct hierarchy queries now use weighted `moka` caches while definitions, children, ranges, imports, and raw supertypes remain eagerly materialized in immutable analyzer state.

## Decision Log

- Decision: preserve Brokk's Java-like API names in Rust for v1 instead of inventing an idiomatic-Rust-first surface.
  Rationale: that keeps the translated tests direct and reduces semantic drift from the reference implementation.
  Date/Author: 2026-03-24 / Codex + user

- Decision: vendor Brokk's `.scm` Tree-sitter queries and `testcode-*` fixtures unchanged.
  Rationale: the user explicitly requested direct reuse, and it removes a large source of accidental differences from the port.
  Date/Author: 2026-03-24 / Codex + user

- Decision: start with a stable Rust public surface before implementing parsing internals.
  Rationale: the engine work spans declarations, imports, type hierarchy, and update semantics; locking the public types first reduces churn while the internals are built out.
  Date/Author: 2026-03-24 / Codex

- Decision: build the first real parser/index layer by walking the Java syntax tree directly rather than reproducing Brokk's query-driven extraction immediately.
  Rationale: it gets the single-threaded engine and snapshot model in place quickly. The vendored `.scm` files remain in the repository and can be integrated later where query-driven extraction materially improves parity.
  Date/Author: 2026-03-24 / Codex

- Decision: persist raw supertypes and extracted type identifiers in the generic analyzer state and resolve them in `JavaAnalyzer`.
  Rationale: the generic state should own parsed facts, while Java-specific precedence rules decide how those facts become imports, ancestors, descendants, and same-package references.
  Date/Author: 2026-03-24 / Codex

- Decision: persist rendered declaration signatures in the generic analyzer state and build skeletons recursively from those signatures plus ordered child relationships.
  Rationale: it avoids reparsing on every request and keeps the first source/skeleton milestone simple while still matching the fixture-backed Java tests.
  Date/Author: 2026-03-24 / Codex

- Decision: implement the first scope-analysis pass in `JavaAnalyzer` by reparsing the current source text on demand instead of storing full per-file syntax trees in analyzer state.
  Rationale: it keeps the snapshot state simpler for v1 while still providing correct local-scope answers for the exercised tests.
  Date/Author: 2026-03-24 / Codex

- Decision: represent package declarations as `CodeUnitType::Module` values whose fully qualified name is the package name, and attach top-level classes as their direct children.
  Rationale: this matches the Brokk tests for top-level declarations and package-module child traversal while preserving the existing `CodeUnit` model.
  Date/Author: 2026-03-24 / Codex

- Decision: implement comment-aware extraction in the shared source path with a backward textual scan rather than extending `Range` with explicit comment offsets.
  Rationale: it was sufficient for the current Java acceptance cases and avoided widening the range/state model before more languages exist in the Rust port.
  Date/Author: 2026-03-24 / Codex

- Decision: keep module merging as a lookup/child-aggregation behavior in the shared engine instead of changing `CodeUnit` equality semantics globally.
  Rationale: Brokk parity required packages to behave like one logical module across files, but changing `CodeUnit` identity would have risked broader regressions in the Rust port's declaration model.
  Date/Author: 2026-03-24 / Codex

- Decision: synthesize Java lambda code units during callable parsing and attach them to the nearest enclosing callable using Brokk-style `$anon$line:col` names.
  Rationale: this is the smallest change that satisfies the overload/lambda attachment regressions without reintroducing the full query-driven Brokk extraction pipeline.
  Date/Author: 2026-03-24 / Codex

- Decision: make `search_definitions` case-insensitive in the shared engine.
  Rationale: Brokk's Java search semantics are case-insensitive, and the Rust port already routes search through the generic regex-based matcher.
  Date/Author: 2026-03-24 / Codex

- Decision: add `autocomplete_definitions` as a default Rust `IAnalyzer` method and keep its behavior generic.
  Rationale: Brokk exposes autocomplete at the interface level, and the remaining Java search tests only needed the shared substring/fuzzy ordering behavior rather than a Java-only override.
  Date/Author: 2026-03-24 / Codex

- Decision: treat the remaining `Java*Analyzer*Test` translation work as behavior-equivalent acceptance rather than a line-for-line reproduction of internal helper tests.
  Rationale: tests like query-caching internals are implementation-specific in Brokk's query-driven engine, while the Rust port keeps the same user-visible analyzer semantics with a simpler single-threaded traversal-based core.
  Date/Author: 2026-03-24 / Codex + user

- Decision: parallelize analyzer construction and updates with per-file shards plus a deterministic reduce instead of Java-style concurrent shared map mutation.
  Rationale: it preserves one concurrent pipeline for both build and update, avoids GC-shaped shared mutable graphs, and keeps published analyzer snapshots lock-free for reads.
  Date/Author: 2026-03-24 / Codex + user

- Decision: keep hot structural facts eager in `AnalyzerState` and use narrow weighted memo caches only for expensive derived Java queries.
  Rationale: Rust's immutable snapshot model makes definitions, children, ranges, imports, and raw supertypes cheap to read eagerly, while `moka` provides a practical approximate-RAM budget for second-order queries such as resolved imports and hierarchy lookups.
  Date/Author: 2026-03-24 / Codex + user

## Outcomes & Retrospective

The repository now has the crate scaffold, the copied Brokk resource corpus, the public Rust API layer, a concurrent parse/index core built around immutable snapshots, Java semantics for imports, hierarchy, source/skeleton rendering, lexical scope analysis, package modules, implicit constructors, comment-aware extraction, Java call-receiver heuristics, normalized-name lookups, Brokk-style lambda discovery/naming, relevant-import selection, fixture top-level/member parity coverage, declaration-inventory parity coverage, import-detail parity coverage, case-insensitive search parity, autocomplete parity, record-component field support, interface-constant and field-initializer parity, bounded memo caches for expensive Java queries, and duplicate/update regressions. For the scoped v1 port, the translated Rust suite now covers the full intended `Java*Analyzer*Test` surface except the explicitly excluded serialization round-trip case and `JavascriptAnalyzerTest`.

The repository also now has a `summarize` CLI utility that resolves either absolute file paths under the project root or Java FQCN targets and prints Brokk-style skeleton summaries using the Rust analyzer implementation. This gives the port a direct command-line path for exercising file summaries and symbol summaries outside the translated test harness.

## Context and Orientation

This repository started essentially empty. The reference implementation lives in `../brokk/app/src/main/java/ai/brokk/analyzer/`. The reference tests live in `../brokk/app/src/test/java/ai/brokk/analyzer/`. The Tree-sitter query files now copied into this repository live under `resources/treesitter/`, and the test fixture directories now copied into this repository live under `tests/fixtures/`.

In Brokk terminology, a `CodeUnit` is a named declaration such as a class, function, field, or module statement. A `ProjectFile` is a file identified relative to a project root so two paths can be compared safely. A "snapshot" analyzer means updates return a new analyzer value rather than mutating the previous one in place. A "skeleton" is the summarized code shape for a declaration rather than its full source text.

The Rust crate root is `src/lib.rs`. The analyzer module tree is under `src/analyzer/`. The intent is to expose a Rust equivalent of Brokk's `IAnalyzer`, `TreeSitterAnalyzer`, `JavaAnalyzer`, `ImportAnalysisProvider`, and `TypeHierarchyProvider`, while keeping the published analyzer state immutable and allowing build/update work to run concurrently.

## Plan of Work

The first code milestone creates the crate structure and public types in `src/analyzer/`. `src/analyzer/model.rs` defines the core value types such as `CodeUnit`, `ProjectFile`, `Range`, `ImportInfo`, `DeclarationInfo`, `Language`, and `CodeBaseMetrics`. `src/analyzer/project.rs` defines the `Project` trait and a lightweight `TestProject` implementation used by future Rust tests. `src/analyzer/capabilities.rs` and `src/analyzer/i_analyzer.rs` define the analyzer capability traits and the main analyzer API. `src/analyzer/tree_sitter_analyzer.rs` and `src/analyzer/java_analyzer.rs` begin as placeholders with the public names and constructor flow that later milestones will fill in.

The second milestone will replace those placeholders with a real Tree-sitter-backed engine. That engine will parse Java files serially, load the vendored `.scm` queries from `resources/treesitter/java/`, build symbol indexes and file metadata, and expose snapshot updates. Once the generic engine exists, `src/analyzer/java_analyzer.rs` will add Java-specific package resolution, import resolution, source extraction, access-expression filtering, local declaration lookup, and type hierarchy logic.

The third milestone will translate selected Brokk Java tests into Rust integration tests under `tests/`. Those tests will read the vendored fixtures directly from `tests/fixtures/` and create temporary projects for update scenarios. The translated tests are the acceptance gate for the port.

## Concrete Steps

Work from `/home/jonathan/Projects/bifrost`.

The scaffold and vendoring steps have already been run:

    cargo init --lib --name brokk_analyzer .
    mkdir -p resources tests/fixtures
    cp -R ../brokk/app/src/main/resources/treesitter resources/
    cp -R ../brokk/app/src/test/resources/testcode-* tests/fixtures/

The current scaffold has also been compiled successfully:

    cargo check

The next implementation step is to edit:

    Cargo.toml
    src/lib.rs
    src/analyzer/mod.rs
    src/analyzer/model.rs
    src/analyzer/project.rs
    src/analyzer/source_content.rs
    src/analyzer/capabilities.rs
    src/analyzer/i_analyzer.rs
    src/analyzer/tree_sitter_analyzer.rs
    src/analyzer/java_analyzer.rs

After the parsing pipeline exists, add Rust tests under:

    tests/java_analyzer/

## Validation and Acceptance

The change is complete only when the Rust test suite demonstrates the same observable behaviors covered by the selected Brokk Java tests. At a minimum, the following commands must pass from `/home/jonathan/Projects/bifrost`:

    cargo test
    cargo fmt --check
    cargo clippy --all-targets --all-features -- -D warnings

Acceptance is behavioral rather than structural. The analyzer must be able to load the copied Java fixtures, return matching declarations and skeletons, resolve imports and type hierarchy relationships, and produce a fresh snapshot after file updates.

## Idempotence and Recovery

The vendoring step is safe to repeat by deleting the copied resource directories and copying them again from `../brokk`. The Rust crate scaffold is additive. If the parser implementation breaks later milestones, keep the public types stable and rework the engine internals without editing the vendored resources. Any translated test that proves too broad may be split into smaller Rust tests as long as the original behavior is preserved and the split is recorded in this plan.

## Artifacts and Notes

Important reference paths:

    ../brokk/app/src/main/java/ai/brokk/analyzer/IAnalyzer.java
    ../brokk/app/src/main/java/ai/brokk/analyzer/TreeSitterAnalyzer.java
    ../brokk/app/src/main/java/ai/brokk/analyzer/JavaAnalyzer.java
    ../brokk/app/src/main/java/ai/brokk/analyzer/CodeUnit.java
    ../brokk/app/src/main/java/ai/brokk/analyzer/ProjectFile.java
    ../brokk/app/src/main/java/ai/brokk/analyzer/ImportInfo.java
    ../brokk/app/src/main/java/ai/brokk/analyzer/ImportAnalysisProvider.java
    ../brokk/app/src/main/java/ai/brokk/analyzer/TypeHierarchyProvider.java
    ../brokk/app/src/test/java/ai/brokk/analyzer/JavaAnalyzerTest.java
    ../brokk/app/src/test/java/ai/brokk/analyzer/imports/JavaImportTest.java
    ../brokk/app/src/test/java/ai/brokk/analyzer/types/JavaTypeHierarchyTest.java
    ../brokk/app/src/test/java/ai/brokk/analyzer/update/JavaAnalyzerUpdateTest.java

## Interfaces and Dependencies

The crate must export these public items from `src/lib.rs` and `src/analyzer/mod.rs`:

    pub trait IAnalyzer
    pub struct TreeSitterAnalyzer<A>
    pub struct JavaAnalyzer
    pub trait ImportAnalysisProvider
    pub trait TypeHierarchyProvider
    pub struct ProjectFile
    pub struct CodeUnit
    pub enum CodeUnitType
    pub struct ImportInfo
    pub struct Range
    pub struct DeclarationInfo
    pub trait Project
    pub struct TestProject

The implementation will use Rust's `tree-sitter` and `tree-sitter-java` crates together with the vendored `.scm` query files under `resources/treesitter/`. Directory traversal will use `walkdir`. Temporary directories and fixture-heavy tests will use `tempfile`.

Revision note: this initial checked-in ExecPlan records the final v1 scope, the vendored-resource decision, and the completion of the crate/resource scaffold so later work can restart from the working tree alone.
