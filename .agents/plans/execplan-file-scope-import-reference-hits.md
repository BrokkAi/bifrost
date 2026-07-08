# File-Scope Code Units for Import Reference Hits

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document follows `.agents/PLANS.md` from the repository root.

## Purpose / Big Picture

Bifrost already separates usage hits by surface: call graph and search relevance should ignore import bindings, while LSP `textDocument/references` should include the import line that brings a symbol into a file. This works for Python and JavaScript/TypeScript because those analyzers have module code units covering the whole file. Java, Rust, PHP, and Scala often place imports above every class or function declaration, so the current non-optional `UsageHit.enclosing` invariant causes import hits to be dropped.

After this change, every parsed source file has a synthetic file-scope code unit that spans the whole file. Imports above declarations can use that scope as their enclosing owner, LSP references can report import binding lines consistently, and external usage surfaces remain import-free.

## Progress

- [x] (2026-07-01T12:44:56Z) Created the ExecPlan before code edits and recorded the intended model decision.
- [x] (2026-07-01T12:58:00Z) Added and persisted `CodeUnitType::FileScope`, including epoch invalidation.
- [x] (2026-07-01T12:58:00Z) Added full-file synthetic scopes to parsed file state through the common analyzer build path.
- [x] (2026-07-01T12:58:00Z) Added import-kind hit paths for Java, Rust, PHP, and Scala precise import bindings.
- [x] (2026-07-01T13:18:00Z) Added declaration, usage surface, LSP import-hit, and persistence tests.
- [x] (2026-07-01T13:26:00Z) Ran targeted tests, `cargo fmt --check`, and `cargo clippy-no-cuda`.
- [x] (2026-07-01T13:55:00Z) Address guided-review findings: hide file scopes from public/search symbol surfaces, make import hits clause-specific, and add regression coverage.

## Surprises & Discoveries

- Observation: File scopes must not leak through normal top-level declaration APIs.
  Evidence: The Scala usage graph initially lost a same-package member hit because package discovery saw the synthetic file scope first; filtering file scopes from `top_level_declarations()` and skipping them in Scala package lookup restored the existing suite.

- Observation: File scopes also leak through lower-level declaration/search APIs if they are indexed like semantic declarations.
  Evidence: `cargo test --test ruby_analyzer_test empty_file_yields_no_declarations` fails because `get_declarations(empty.rb)` now returns the synthetic file scope.

## Decision Log

- Decision: Use synthetic file-scope code units rather than optional `UsageHit.enclosing`.
  Rationale: A usage hit always has a source context; the missing model element is file scope, not nullable ownership. Keeping `enclosing` non-optional avoids spreading special cases through LSP, call hierarchy, relevance, and persistence consumers.
  Date/Author: 2026-07-01 / Codex

- Decision: Keep Go and C# import-hit behavior out of scope except for file-scope ownership.
  Rationale: Go and C# imports are commonly package or namespace scoped rather than per-symbol bindings, so emitting precise per-symbol import hits there needs separate language-specific design.
  Date/Author: 2026-07-01 / Codex

- Decision: Keep synthetic file scopes out of normal top-level declaration iteration.
  Rationale: File scopes are structural owners for ranges, not semantic declarations. Existing package/import logic expects top-level declarations to be language declarations such as packages, modules, classes, or functions.
  Date/Author: 2026-07-01 / Codex

## Outcomes & Retrospective

- Implemented synthetic file-scope code units, import-kind hits for Java/Rust/PHP/Scala, persistence mapping and epoch invalidation, and tests for LSP references, usage-surface filtering, enclosing ownership, and persistence. The focused suites and `cargo clippy-no-cuda` passed.
- Guided-review follow-up kept file scopes structural while filtering them from public declarations, in-memory definition search, metrics, and LSP caps. Rust/PHP/Scala import-hit emission now avoids same-name aliased import false positives, and the focused suites plus `cargo clippy-no-cuda` passed.

## Context and Orientation

`CodeUnit` is Bifrost's declaration-like unit: class, function, field, module, or macro. `UsageHit` currently stores a non-optional `enclosing: CodeUnit`. `TreeSitterAnalyzer::enclosing_code_unit` chooses the smallest declaration range that contains a source range, so a full-file synthetic code unit can own top-level import syntax without stealing ordinary references from narrower class or function declarations.

The main implementation points are `src/analyzer/model.rs` for `CodeUnitType`, `src/analyzer/tree_sitter_analyzer.rs` for parsed file state and enclosing lookup, `src/analyzer/persistence/*` for persisted analyzer state, and the per-language usage graph hit/extractor modules under `src/analyzer/usages`.

## Plan of Work

First, add `CodeUnitType::FileScope` and a `CodeUnit::file_scope(ProjectFile)` helper that returns a synthetic unit with an empty package and the relative file path as its short name. Update every exhaustive match over `CodeUnitType`, including persistence kind conversion and UI symbol-kind formatting, so file scopes compile and remain hidden by existing synthetic filters.

Second, add a central `ParsedFile` helper that inserts the synthetic file-scope unit into `declarations`, `top_level_declarations`, and `ranges`, with one range covering the whole source. Call this helper from the common build path after language parsing so every analyzer gets a file scope uniformly. Do not add file scopes to `definition_lookup_units`.

Third, add import-hit recording for Java, Rust, PHP, and Scala only where the language scanner already identifies a structured import binding node that resolves to the target symbol. Mark these hits with `UsageHitKind::Import`. Do not use source-text regexes or mini parsers to find imports.

Fourth, update persistence invalidation. Add `FileScope` to `code_unit_kind_str` and `parse_kind`. Bump the per-language epoch salt for every language whose parsed output now includes file scopes, because existing rows lack this synthetic owner even though their payload wire shape is unchanged.

Finally, add tests that prove LSP references include import lines, external usage surfaces still exclude them, file scopes own top-level imports, narrow declarations still own ordinary references, and persistence round-trips file scopes without exposing them through persisted search.

## Concrete Steps

Run commands from the repository root `/Users/dave/.codex/worktrees/12f3/bifrost`.

Use targeted tests while developing:

    cargo test --test cross_language_import_hits
    cargo test --test analyzer_persistence

Before finishing, run:

    cargo fmt --check
    cargo clippy-no-cuda

On macOS or other non-CUDA environments, do not run `cargo clippy --all-targets --all-features -- -D warnings`; it enables CUDA-backed features.

## Validation and Acceptance

The change is accepted when `tests/cross_language_import_hits.rs` shows Java, Rust, PHP, and Scala LSP references include the import binding line for an imported target symbol, and usage surface tests show `all_hits()` excludes those import hits while `all_hits_including_imports()` includes them.

The declaration model is accepted when a range on an import token resolves to `CodeUnitType::FileScope`, while a range inside a class or function still resolves to that narrower class or function.

The persistence change is accepted when a persisted analyzer can round-trip a file-scope unit, persisted search does not expose synthetic file scopes as ordinary symbols, and the new `FileScope` kind maps through the persisted symbol kind conversion.

## Idempotence and Recovery

The implementation is additive and safe to retry. If a test run writes build artifacts under `target/`, leave them alone. If persistence tests create temporary analyzer databases, they should stay under test temp directories and be cleaned by the test harness.

## Artifacts and Notes

Issue `#388` describes the root cause: import hits are dropped in languages whose imports live outside every currently emitted code unit. The intended behavior is LSP-visible import hits with call graph and `scan_usages` surfaces remaining import-free.

## Interfaces and Dependencies

At completion, `src/analyzer/model.rs` must expose:

    CodeUnitType::FileScope
    CodeUnit::file_scope(source: ProjectFile) -> CodeUnit

`src/analyzer/tree_sitter_analyzer.rs` must have a central parsed-file operation that registers a full-file range for the file-scope unit without adding it to definition lookup units.

`src/analyzer/persistence/reconcile.rs` must map `FileScope` to and from the stable on-disk kind string `FileScope`.
