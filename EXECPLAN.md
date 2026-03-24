# Port Brokk Java Analyzer To Rust

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with `.agent/PLANS.md`.

## Purpose / Big Picture

After this change, this repository will contain a Rust library that reproduces the single-threaded, in-memory behavior of Brokk's Java analyzer. A user will be able to load the copied Brokk Java fixtures, ask for declarations, source, skeletons, imports, and type hierarchy information, and then update the analyzer after file edits. The proof will be translated Rust tests that exercise the same behaviors as Brokk's Java test suite.

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
- [ ] Complete the remaining Java-specific semantics: skeleton rendering, comment-aware source extraction, access-expression filtering, nearest declaration lookup, and broader update/regression parity.
- [ ] Translate the selected Java tests into Rust integration tests and make them pass.
- [ ] Run the Rust test suite and commit each milestone as a logical unit.

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

## Outcomes & Retrospective

The repository now has the crate scaffold, the copied Brokk resource corpus, the public Rust API layer, a single-threaded parse/index core, and a first Java semantic layer for imports and hierarchy. The major remaining gap is semantic parity for skeleton/source rendering, local declaration and access-expression logic, and the broader translated acceptance suite.

## Context and Orientation

This repository started essentially empty. The reference implementation lives in `../brokk/app/src/main/java/ai/brokk/analyzer/`. The reference tests live in `../brokk/app/src/test/java/ai/brokk/analyzer/`. The Tree-sitter query files now copied into this repository live under `resources/treesitter/`, and the test fixture directories now copied into this repository live under `tests/fixtures/`.

In Brokk terminology, a `CodeUnit` is a named declaration such as a class, function, field, or module statement. A `ProjectFile` is a file identified relative to a project root so two paths can be compared safely. A "snapshot" analyzer means updates return a new analyzer value rather than mutating the previous one in place. A "skeleton" is the summarized code shape for a declaration rather than its full source text.

The Rust crate root is `src/lib.rs`. The analyzer module tree is under `src/analyzer/`. The intent is to expose a Rust equivalent of Brokk's `IAnalyzer`, `TreeSitterAnalyzer`, `JavaAnalyzer`, `ImportAnalysisProvider`, and `TypeHierarchyProvider`, while keeping the implementation single-threaded in v1.

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
