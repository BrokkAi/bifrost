# Align Bifrost Import and Hierarchy Capability Plumbing with Brokk

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with `.agent/PLANS.md`.

## Purpose / Big Picture

After this change, Bifrost will keep the same public capability model it already exposes for import graph analysis and type hierarchy analysis, but the common behavior in those features will live in shared code instead of being reimplemented in multiple language analyzers. A contributor should be able to inspect the capability layer and understand which languages support Brokk-equivalent features, which parts are truly language-specific, and which parts are generic plumbing.

The user-visible proof is behavioral parity. Running the import and hierarchy test suites should continue to show that import graph support exists for Java, Python, Go, JavaScript, TypeScript, Rust, and C++, and that type hierarchy support exists for Java and Python. The new common helpers should not change those results.

## Progress

- [x] (2026-03-30 18:11Z) Read `.agent/PLANS.md`, inspected Bifrost and Brokk capability support, and confirmed parity-first scope.
- [x] (2026-03-30 18:11Z) Identified the duplicated behaviors worth centralizing: generic reverse-import scans and generic descendant scans.
- [x] (2026-03-30 18:20Z) Implemented shared capability helpers in `src/analyzer/capabilities.rs` and re-exported them for internal analyzer use.
- [x] (2026-03-30 18:20Z) Refactored Go, Python, JavaScript, TypeScript, and Rust reverse-import scans to use the shared helper while preserving per-analyzer caches.
- [x] (2026-03-30 18:20Z) Refactored Java and Python direct-descendant computation to use the shared hierarchy helper, and reused the shared import-based portion of Java reverse-import logic without removing its same-package augmentation.
- [x] (2026-03-30 18:20Z) Added `tests/analyzer_capability_parity.rs` to codify the Brokk-equivalent support matrix.
- [x] (2026-03-30 18:20Z) Ran the focused import and hierarchy suites; all selected tests passed.
- [x] (2026-03-30 18:20Z) Updated this ExecPlan with the implementation outcomes and final discoveries.

## Surprises & Discoveries

- Observation: Bifrost already matches Brokk’s language matrix for the feature area under discussion.
  Evidence: Both repos support import graph analysis for Java, Python, Go, JavaScript/TypeScript, Rust, and C++, and both support type hierarchy only for Java and Python.

- Observation: Java cannot fully use a naive shared `referencing_files_of` implementation because its reverse-import logic also includes same-package implicit references.
  Evidence: `src/analyzer/java_analyzer.rs` adds same-package files by scanning type identifiers after the initial import-based pass.

- Observation: C++ cannot safely switch to a declaration-based shared `referencing_files_of` implementation because its current logic intentionally treats quoted includes as file references even when no declarations resolve from the included file.
  Evidence: `src/analyzer/cpp_analyzer.rs` matches include paths and file names directly rather than only checking `imported_code_units_of`.

- Observation: The shared helper boundary worked cleanly for Go, Python, JavaScript, TypeScript, Rust, Java descendant scans, and the import-based portion of Java reverse-import logic without changing test behavior.
  Evidence: `cargo test --test analyzer_capability_parity --test multi_analyzer_capability_test --test multi_analyzer_import_test --test java_imports_and_hierarchy --test python_type_hierarchy_test --test go_import_test --test javascript_import_test --test typescript_import_test --test rust_import_test --test cpp_analyzer_test` exited successfully.

## Decision Log

- Decision: Keep Bifrost’s public capability surface unchanged in this refactor.
  Rationale: The goal is parity-first cleanup, not a Brokk-style public API migration.
  Date/Author: 2026-03-30 / Codex

- Decision: Centralize only the behavior that is semantically identical across analyzers, not every implementation shape that merely looks similar.
  Rationale: Java and C++ each have behavior beyond the generic reverse-import scan, so forcing them into the shared path would silently lose supported cases.
  Date/Author: 2026-03-30 / Codex

## Outcomes & Retrospective

The refactor achieved the intended DRY improvement without changing the public capability surface. Shared internal helpers now own the generic “reverse import via resolved imported code units” scan and the generic “direct descendants via direct ancestors” scan. The language-specific analyzers still own the places where semantics diverge from the generic rule.

The parity matrix is now explicit in tests. This is the main protection against accidental capability drift. The focused suites stayed green, which is the proof that the refactor did not change supported behavior in the targeted feature area.

Remaining follow-on work, if desired, should be treated as separate tasks. The main candidates are broader analyzer-surface alignment with Brokk, cache-sharing cleanup across wrappers, or new capability rollout for languages that neither repo currently supports in this area.

## Context and Orientation

The relevant public traits live in `src/analyzer/capabilities.rs`. `ImportAnalysisProvider` is the capability for semantic import resolution. `TypeHierarchyProvider` is the capability for direct and transitive ancestor/descendant traversal. `MultiAnalyzer` in `src/analyzer/multi_analyzer.rs` routes these capabilities across per-language analyzers.

The per-language analyzers wrap `TreeSitterAnalyzer` and add language-specific import or hierarchy logic. The duplicated code in scope is not the parsing logic itself. The duplicated code is the repeated scan of “all analyzed files that import a target file” and the repeated scan of “all analyzed class declarations whose direct ancestors include a target class.”

Brokk provides the comparison target for this work. The parity target is feature-level parity in the specific area discussed above, not wholesale replication of Brokk’s `TreeSitterAnalyzer` runtime model.

## Plan of Work

First, add shared internal helper functions to `src/analyzer/capabilities.rs`. One helper will compute referencing files given an analyzer, an `ImportAnalysisProvider`, and a target file. It will iterate analyzed files, skip the target file, ask the provider for `imported_code_units_of(candidate)`, and retain candidates that import code units whose source file is the target. The helper will return a `BTreeSet<ProjectFile>` for deterministic behavior.

Add a second shared helper to compute direct descendants given an analyzer, a `TypeHierarchyProvider`, and a target code unit. It will scan `analyzer.get_all_declarations()`, keep only class code units other than the target, compute direct ancestors with the provider, and retain candidates whose ancestor set contains the target by fully-qualified name.

Next, refactor the analyzers whose semantics already match the generic reverse-import scan. These are Python, Go, JavaScript, TypeScript, and Rust. In each file, keep the existing memoization behavior, but replace the duplicated file scan with the shared helper.

Do not replace Java’s or C++’s `referencing_files_of` implementations wholesale. For Java, use the helper only for the initial import-based result if that meaningfully simplifies the code, then keep the same-package augmentation exactly as it exists today. For C++, leave `referencing_files_of` language-specific.

Refactor Java and Python `get_direct_descendants` to delegate their scan to the shared hierarchy helper while keeping their language-specific `get_direct_ancestors` logic intact.

Finally, add tests that codify the parity matrix and verify capability presence and absence at the direct-analyzer and `MultiAnalyzer` levels. Run the focused import and hierarchy suites plus the new capability tests, then update this ExecPlan with the result.

## Concrete Steps

From `/home/jonathan/Projects/bifrost`:

1. Edit `src/analyzer/capabilities.rs` to add the shared internal helper functions for reverse-import scans and direct-descendant scans.
2. Edit `src/analyzer/go_analyzer.rs`, `src/analyzer/javascript_analyzer.rs`, `src/analyzer/typescript_analyzer.rs`, `src/analyzer/rust_analyzer.rs`, and `src/analyzer/python_analyzer.rs` to use the shared reverse-import helper.
3. Edit `src/analyzer/java_analyzer.rs` only enough to reuse the shared descendant helper and, optionally, the generic import-based portion of `referencing_files_of` without changing its same-package augmentation.
4. Add or update tests so the expected capability matrix is explicit.
5. Run the focused Rust test commands listed below.

Expected commands:

    cargo test --test multi_analyzer_capability_test
    cargo test --test multi_analyzer_import_test
    cargo test --test java_imports_and_hierarchy
    cargo test --test python_type_hierarchy_test
    cargo test --test go_import_test
    cargo test --test javascript_import_test
    cargo test --test typescript_import_test
    cargo test --test rust_import_test
    cargo test --test cpp_analyzer_test

## Validation and Acceptance

Acceptance is behavioral:

1. The focused import and hierarchy tests pass without changing their expected results.
2. The new capability-matrix test proves that Bifrost exposes import graph support for Java, Python, Go, JavaScript, TypeScript, Rust, and C++, and hierarchy support for Java and Python only.
3. `MultiAnalyzer` still exposes import and hierarchy capabilities only when at least one delegate supports them.
4. Update-driven tests still pass, showing that analyzer-specific memo caches remain valid after the refactor.

## Idempotence and Recovery

The code edits are additive refactors and can be retried safely. If a helper extraction changes behavior unexpectedly, revert the specific analyzer to its previous local implementation while keeping the helper in place for analyzers whose semantics match it. Do not broaden the shared helper to cover Java or C++ behavior by guesswork; preserve their language-specific logic if a regression appears.

## Artifacts and Notes

The most important artifact for this change is the parity matrix captured in tests. If implementation uncovers a missing language-level parity case relative to Brokk, record it here with the failing test name and the chosen resolution.

## Interfaces and Dependencies

In `src/analyzer/capabilities.rs`, define internal helper functions with signatures equivalent to:

    pub(crate) fn referencing_files_via_imports<A, P>(
        analyzer: &A,
        provider: &P,
        file: &ProjectFile,
    ) -> BTreeSet<ProjectFile>
    where
        A: IAnalyzer,
        P: ImportAnalysisProvider

    pub(crate) fn direct_descendants_via_ancestors<A, P>(
        analyzer: &A,
        provider: &P,
        code_unit: &CodeUnit,
    ) -> BTreeSet<CodeUnit>
    where
        A: IAnalyzer,
        P: TypeHierarchyProvider

These helpers are internal. They exist to remove duplicated scans while preserving the current public trait methods.

Change note: created the initial ExecPlan before code edits and recorded the discovered Java/C++ exceptions so the implementation does not accidentally simplify away supported behavior.

Change note: updated the ExecPlan after implementation to record the final helper boundaries, test evidence, and the fact that the parity matrix is now enforced by a dedicated regression test.
