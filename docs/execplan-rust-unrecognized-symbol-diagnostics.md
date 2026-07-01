# Add high-confidence Rust unrecognized-symbol diagnostics

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document follows `.agent/PLANS.md` in this repository. It is self-contained so a future contributor can continue the implementation without relying on prior chat context.

## Purpose / Big Picture

Bifrost already reports syntax diagnostics from tree-sitter and semantic unresolved-symbol diagnostics for some languages. After this change, Rust users opening a crate-local Rust file in an LSP client can also see an error when Bifrost can prove a type, value, or free function reference is unknown. The feature is intentionally conservative: when Rust macros, cfg gates, external crates, glob imports, trait methods, or type inference might explain a name, Bifrost emits no semantic diagnostic.

The observable outcome is an LSP diagnostic with source `bifrost-rust` and code `rust_unrecognized_symbol` for a clear missing Rust reference such as `MissingType` in a local type annotation, while malformed files still report only `bifrost-tree-sitter` parse diagnostics.

## Progress

- [x] (2026-07-01 12:36Z) Created this ExecPlan after reading `.agent/PLANS.md`, inspecting the existing LSP diagnostic hook, and confirming Rust has no `semantic_diagnostics` override yet.
- [x] (2026-07-01 12:42Z) Added `src/analyzer/rust/diagnostics.rs` and wired `RustAnalyzer::semantic_diagnostics` to the collector.
- [x] (2026-07-01 12:44Z) Added analyzer tests for unknown references, known local/import/module references, conservative suppression cases, malformed files, and diagnostic caps; added LSP pull, parse-only, and publish diagnostics tests.
- [x] (2026-07-01 12:48Z) Ran focused tests, formatting, and no-CUDA clippy validation successfully.
- [x] (2026-07-01 13:10Z) Addressed guided-review findings by removing per-identifier Rust reparsing, recognizing Rust type aliases as type declarations, isolating nested item scopes, pre-seeding block-local item declarations, handling trait method generics, preventing item generic leakage, and reusing existing parser/node helpers.

## Surprises & Discoveries

- Observation: No LSP handler change is needed for Rust semantic diagnostics.
  Evidence: `src/lsp/handlers/diagnostic.rs` already calls `workspace.analyzer().semantic_diagnostics(...)` after parse diagnostics are empty and maps analyzer diagnostics to ordinary LSP errors.

- Observation: Rust already has reusable structured resolution helpers for imports and module paths.
  Evidence: `src/analyzer/rust/graph_support.rs` exposes `RustAnalyzer::reference_context_of`, `resolve_imported_export_from_binder`, and `resolve_module_files`; `src/analyzer/rust/lexical_scope.rs` exposes `visible_import_binder_at`.

- Observation: Parameter type annotations need explicit scanning even though parameter patterns are not reference positions.
  Evidence: The first `cargo test rust_semantic_diagnostics --lib` run reported only `missing_value` and `missing_function`, not `MissingType`. The collector now skips the parameter pattern but scans the parameter `type` field.

- Observation: Import visibility must be computed from the already-parsed tree, not by calling a parse-backed helper for each identifier.
  Evidence: Guided review found that `visible_import_binder_at` reparsed the whole file per checked reference. The collector now caches structured `use` bindings from the first parse and filters them by byte offset.

- Observation: Rust item scopes differ from closures.
  Evidence: Guided review found that nested `function_item` nodes inherited outer local bindings even though Rust item functions cannot capture local variables. The collector now enters isolated scopes for item functions and signatures while closures keep normal capture behavior.

## Decision Log

- Decision: Implement this as `src/analyzer/rust/diagnostics.rs` instead of adding a shared unresolved-symbol framework.
  Rationale: The issue is Rust-specific and the confidence rules depend on Rust syntax, imports, modules, macros, and external-crate boundaries. A generic layer would either be underpowered or too broad for this first slice.
  Date/Author: 2026-07-01 / Codex

- Decision: Suppress semantic diagnostics whenever tree-sitter reports parse errors.
  Rationale: The existing LSP diagnostic contract already treats parse diagnostics as higher priority. The issue requires the reference shape to be trustworthy before reporting an unresolved semantic error.
  Date/Author: 2026-07-01 / Codex

- Decision: Report only simple bare references and rooted crate-local paths in the first slice; suppress member/method resolution unless the owner is structurally known in a later enhancement.
  Rationale: Trait methods, inherent methods, deref, field access, and type inference require richer Rust semantics than Bifrost currently indexes with high confidence. Suppressing these avoids false positives.
  Date/Author: 2026-07-01 / Codex

- Decision: Use separate type and value scope bindings in the Rust diagnostic pass.
  Rationale: Rust type parameters should suppress type-reference diagnostics but not value-reference diagnostics, and local values should not suppress missing type diagnostics. Keeping the binding kind in the scope stack avoids cross-namespace false negatives.
  Date/Author: 2026-07-01 / Codex

## Outcomes & Retrospective

The implementation adds Rust semantic diagnostics to both pull and publish LSP diagnostics through the existing analyzer hook. It reports clear unresolved Rust type/value/free-function references and suppresses malformed files, local bindings, known declarations, Rust type aliases, imports, crate-local module paths, primitives/prelude-safe names, macros, attributes, cfg-gated items, external paths, and glob-import uncertainty.

The work intentionally does not implement rustc name resolution, macro expansion, Cargo feature evaluation, external crate metadata, or trait/member/type-inference diagnostics. Those remain out of scope to keep the first Rust diagnostics slice high-confidence.

## Context and Orientation

The LSP diagnostic entry point is `src/lsp/handlers/diagnostic.rs`. It reads the document, builds tree-sitter parse diagnostics, and only if that list is empty asks the active analyzer for semantic diagnostics through `IAnalyzer::semantic_diagnostics`.

The analyzer trait is defined in `src/analyzer/i_analyzer.rs`. Languages that support semantic diagnostics override the default empty implementation. Existing examples are `src/analyzer/go/diagnostics.rs`, `src/analyzer/python/diagnostics.rs`, and `src/analyzer/php/diagnostics.rs`.

The Rust analyzer lives under `src/analyzer/rust/`. `src/analyzer/rust/mod.rs` defines `RustAnalyzer` and its `IAnalyzer` implementation. `src/analyzer/rust/imports.rs` parses `use` declarations into structured `ImportInfo` values. `src/analyzer/rust/lexical_scope.rs` can compute imports visible at a byte position and local shadowing. `src/analyzer/rust/graph_support.rs` builds crate-local reference contexts and resolves import binders to indexed declarations.

A semantic diagnostic is the internal analyzer result type in `src/analyzer/model.rs`. It carries a byte range, a source string, a diagnostic code, and a message. The LSP layer converts it to an LSP diagnostic range using the document text.

## Plan of Work

Add a new private module `src/analyzer/rust/diagnostics.rs`. It should parse Rust with `tree_sitter_rust`, suppress files with parse errors, skip very large files, and walk the named AST nodes iteratively. It should maintain a stack of lexical bindings for function bodies, closures, blocks, patterns, and type parameters. It should emit `RustSemanticDiagnostic` only for clear unresolved references.

Update `src/analyzer/rust/mod.rs` to declare the module and override `semantic_diagnostics` in the `IAnalyzer for RustAnalyzer` impl by delegating to `diagnostics::collect_rust_semantic_diagnostics(self, file, source)` and converting results to `SemanticDiagnostic`.

The collector must use structured AST relationships rather than regex or ad hoc Rust parsing. It may inspect tree-sitter node kinds, fields, parent/child relationships, and existing analyzer structures. It should consider a name known when it is a local binding, a same-file or crate-local declaration, a visible import, a resolved alias, a rooted `crate`/`self`/`super` path, a primitive type, or a common prelude item. It should suppress names in declaration, import, macro, attribute, lifetime, label, field, and uncertain member contexts.

Add crate-internal tests in the new diagnostics module. Use small inline projects and instantiate `RustAnalyzer` directly so the tests can assert private diagnostic kind/source fields. Add LSP tests in `tests/bifrost_lsp_server.rs` near the existing Go/Python/PHP semantic diagnostics tests.

## Concrete Steps

Run all commands from `/Users/dave/.codex/worktrees/5a06/bifrost`.

First, create the diagnostics module and wire it into the analyzer. Then run:

    cargo test rust_semantic_diagnostics --lib

After analyzer tests pass, add the LSP tests and run:

    cargo test --test bifrost_lsp_server rust_semantic_diagnostics --features nlp

Finally run:

    cargo fmt --check
    cargo clippy-no-cuda

If formatting fails, run `cargo fmt` and repeat `cargo fmt --check`.

Actual validation run on 2026-07-01:

    cargo test rust_semantic_diagnostics --lib
    result before review fixes: ok. 5 passed; 0 failed
    result after review fixes: ok. 6 passed; 0 failed

    cargo test --test bifrost_lsp_server rust_semantic_diagnostics --features nlp
    result: ok. 3 passed; 0 failed

    cargo fmt --check
    result: passed

    cargo clippy-no-cuda
    result: passed

## Validation and Acceptance

The analyzer tests should prove that `MissingType` or `missing_value` in clear Rust reference positions creates one `rust_unrecognized_symbol` diagnostic, and that known local bindings, imports, type aliases, module-relative paths, primitives, prelude-safe names, macros, attributes, labels, lifetimes, cfg-gated code, external-looking paths, and malformed files create no Rust semantic diagnostics. They should also prove nested item functions do not capture outer locals, block-local functions are visible before declaration, trait method generics are recognized, and generic parameters from one item do not leak into sibling items.

The LSP pull diagnostic test should start the Bifrost LSP server on a temporary Rust project, request `textDocument/diagnostic`, and observe at least one item with `source` equal to `bifrost-rust`, `code` equal to `rust_unrecognized_symbol`, and a message containing the missing symbol. The malformed Rust LSP test should observe `bifrost-tree-sitter` diagnostics and no `bifrost-rust` diagnostics. The publish diagnostic test should save a Rust file with an unresolved name and observe the same semantic diagnostic through `textDocument/publishDiagnostics`.

## Idempotence and Recovery

All edits are source and test additions. The collector is deterministic and bounded by file size and diagnostic count. If a test exposes a false positive, prefer suppressing that syntax shape over adding speculative inference. If a high-confidence false negative appears, add structured handling using tree-sitter nodes or existing analyzer indexes, not regex, string splitting, or manual delimiter parsing.

## Artifacts and Notes

Expected successful focused test output will look like this in abbreviated form:

    test result: ok. ... rust_semantic_diagnostics ...

The exact number of tests may change as regressions are added, but all focused Rust semantic diagnostic tests must pass before this plan is considered complete.

The completed implementation produced these focused summaries:

    running 5 tests
    test result: ok. 5 passed; 0 failed; 411 filtered out

After guided-review fixes:

    running 6 tests
    test result: ok. 6 passed; 0 failed; 411 filtered out

    running 3 tests
    test result: ok. 3 passed; 0 failed; 140 filtered out

## Interfaces and Dependencies

Define this private diagnostic type in `src/analyzer/rust/diagnostics.rs`:

    pub(crate) struct RustSemanticDiagnostic {
        pub(crate) range: Range,
        pub(crate) kind: &'static str,
        pub(crate) message: String,
    }

Define these private constants:

    pub(crate) const RUST_UNRECOGNIZED_SYMBOL: &str = "rust_unrecognized_symbol";
    pub(crate) const RUST_SEMANTIC_DIAGNOSTIC_SOURCE: &str = "bifrost-rust";

Expose this private collector:

    pub(crate) fn collect_rust_semantic_diagnostics(
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
        source: &str,
    ) -> Vec<RustSemanticDiagnostic>

No public API changes and no new external dependencies are required.

Revision note, 2026-07-01: Created the initial ExecPlan before implementation to record the Rust-only scope, the diagnostic interface, and the validation bundle.

Revision note, 2026-07-01: Updated the plan after implementation to record the completed collector, LSP coverage, validation commands, and the parameter-type scanning discovery.

Revision note, 2026-07-01: Updated after guided review to record the import-cache refactor, type/value scope split, Rust type-alias handling, item-scope corrections, and added regressions.
