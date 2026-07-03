# Add high-confidence Go unrecognized-symbol diagnostics

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document follows `.agent/PLANS.md` from the repository root.

## Purpose / Big Picture

After this change, the LSP server reports semantic diagnostics for Go references that Bifrost can prove are unresolved. A user opening a Go file in an editor will still see syntax errors from tree-sitter, and will additionally see a diagnostic for clear mistakes such as a misspelled local identifier or a missing member on an indexed workspace package. The first slice is deliberately conservative: when structured Go facts are incomplete, Bifrost emits nothing rather than guessing.

## Progress

- [x] (2026-06-30 21:20Z) Created this ExecPlan and mapped the implementation to `src/analyzer/go`, `src/lsp/handlers/diagnostic.rs`, and Go/LSP tests.
- [x] (2026-06-30 10:21Z) Added the Go semantic diagnostic collector and analyzer-facing API.
- [x] (2026-06-30 10:21Z) Wired Go semantic diagnostics into LSP pull and push diagnostics without changing parse-error behavior.
- [x] (2026-06-30 10:21Z) Added analyzer and LSP regression tests for positive diagnostics and conservative non-emission.
- [x] (2026-06-30 10:27Z) Ran formatting, targeted analyzer/LSP tests, `cargo clippy-no-cuda`, and `git diff --check`.
- [x] (2026-06-30 11:35Z) Fixed guided-review findings for bounded diagnostic output, shared Go import namespace resolution, selector traversal, field handling, LSP diagnostic abstraction, and LSP test duplication.

## Surprises & Discoveries

- Observation: The existing diagnostic handler only reports parser errors and is already shared by pull diagnostics and `publishDiagnostics`.
  Evidence: `src/lsp/handlers/diagnostic.rs` has one `collect` path used by both LSP flows.
- Observation: Existing Go definition/type/usage code already models package identity, import aliases, dot imports, lexical locals, package members, and receiver fields/methods.
  Evidence: `src/analyzer/usages/get_definition/go.rs` and `src/analyzer/usages/go_graph/reference.rs` contain the structured resolution logic this feature must mirror or reuse.
- Observation: `GoAnalyzer` delegates nearest-declaration lookup to the generic tree-sitter analyzer, whose default implementation currently returns `None`.
  Evidence: The collector keeps its own ordered lexical scope stack for Go parameters, short declarations, range clauses, value declarations, type parameters, and variadic parameters.

## Decision Log

- Decision: Add an analyzer-owned Go collector and keep LSP conversion thin.
  Rationale: The confidence policy depends on Go semantics, not LSP protocol details; this keeps language logic close to the Go analyzer.
  Date/Author: 2026-06-30 / Codex.
- Decision: Suppress semantic diagnostics for files with parse errors.
  Rationale: The issue requires the file to be parsed cleanly enough that reference shape is trustworthy, and parse diagnostics remain independently visible.
  Date/Author: 2026-06-30 / Codex.
- Decision: Diagnose only bare identifiers and package-qualified selectors whose receiver is a resolved import package in this first slice.
  Rationale: These cases are high-confidence with the existing index. Local receiver selectors are used for suppression of known fields/methods, but unresolved local receiver members are not diagnosed unless the receiver type is proven and the member lookup is unambiguous.
  Date/Author: 2026-06-30 / Codex.
- Decision: Track lexical declarations with an ordered explicit traversal stack instead of using a file-wide local-name prepass.
  Rationale: File-wide suppression hid real unresolved identifiers across functions. Ordered scopes preserve the high-confidence policy while avoiding recursive tree walking in the LSP path.
  Date/Author: 2026-06-30 / Codex.
- Decision: Reuse the Go graph namespace resolver for diagnostics and memoize package-clause names on `GoAnalyzer`.
  Rationale: Import semantics must stay aligned with usage resolution, and diagnostics must not reread and reparse imported package files on every LSP request.
  Date/Author: 2026-06-30 / Codex.
- Decision: Add a crate-level semantic diagnostic hook on `IAnalyzer`.
  Rationale: LSP diagnostics should convert language-neutral analyzer diagnostics instead of owning Go-specific semantic branches.
  Date/Author: 2026-06-30 / Codex.

## Outcomes & Retrospective

The implementation adds Go semantic diagnostics to both pull and push LSP diagnostics. Analyzer tests cover unknown locals, unknown workspace package members, nested selectors, relative workspace imports, known names, import forms, predeclared names, locals, generic and variadic declarations, struct field names and field types, diagnostic caps, external imports, and malformed-file suppression. LSP tests cover pull diagnostics, publish diagnostics, and parse-error-only behavior for malformed Go. Final validation passed with `cargo test go_semantic_diagnostics --lib`, the targeted `bifrost_lsp_server` diagnostics tests under `--features nlp`, `cargo fmt`, `cargo clippy-no-cuda`, and `git diff --check`.

## Context and Orientation

The LSP diagnostic entry point is `src/lsp/handlers/diagnostic.rs`. Its `collect` function maps a document URI to a `ProjectFile`, reads the source, gets cached parse errors from `WorkspaceAnalyzer`, and returns LSP `Diagnostic` values. The server calls this same function for pull diagnostics and for `textDocument/publishDiagnostics`, so adding Go semantic diagnostics there affects both paths.

Go analyzer code lives in `src/analyzer/go`. The existing `GoAnalyzer` wraps `TreeSitterAnalyzer<GoAdapter>` and exposes declarations, imports, parse errors, and a `DefinitionLookupIndex` through `IAnalyzer`. Go package names are canonicalized in `src/analyzer/go/packages.rs`, and top-level declarations are collected in `src/analyzer/go/declarations.rs`.

The existing structured Go resolution code lives mostly under `src/analyzer/usages`. It is not an LSP diagnostics subsystem, but it contains important helpers and behavior to mirror: `get_definition/go.rs` resolves package members and local receiver selectors, while `go_graph/reference.rs` tracks lexical shadows. Do not add regex or source-text mini-parsers for Go syntax. Use tree-sitter nodes and analyzer indexes.

## Plan of Work

Create `src/analyzer/go/diagnostics.rs` with an internal result type `GoSemanticDiagnostic` containing a `Range`, a stable kind string, and a message. Expose a public crate-internal function `collect_go_semantic_diagnostics(analyzer: &dyn IAnalyzer, file: &ProjectFile, source: &str) -> Vec<GoSemanticDiagnostic>`.

The collector will parse the file with tree-sitter Go and immediately return no semantic diagnostics if tree-sitter reports `ERROR` or `MISSING` nodes. It will walk the named AST iteratively, track lexical scopes for parameters and local declarations, and consider only true reference nodes. It will ignore declarations, import paths, package clauses, labels, blank identifiers, predeclared identifiers, and builtins. For bare identifiers, it will suppress diagnostics when the name is a local binding, same-package declaration, imported package alias, dot-imported workspace declaration, or predeclared Go name; otherwise it will emit an unrecognized-symbol diagnostic. For selectors, it will diagnose unknown members only when the qualifier is a resolved workspace import package and the package has indexed declarations but not the requested member. For local receiver selectors, it will use proven receiver type facts to suppress known fields and methods, but suppress rather than diagnose when the receiver cannot be resolved confidently.

Update `src/analyzer/go/mod.rs` to expose the new diagnostics module within the crate. Update `src/lsp/handlers/diagnostic.rs` so the existing parse-error list is still returned, and Go semantic diagnostics are appended only when `language == Language::Go`. Convert analyzer byte ranges to LSP ranges with `byte_range_to_lsp_range`, set severity to error, source to `bifrost-go`, and code to the diagnostic kind.

Add focused analyzer tests in a Go test file using `InlineTestProject`. Add LSP integration tests in `tests/bifrost_lsp_server.rs` for pull and publish diagnostics. Keep all fixtures inline and small.

## Concrete Steps

From `/Users/dave/.codex/worktrees/4bf5/bifrost`, run:

    cargo test --test go_analyzer_test go_semantic_diagnostics
    cargo test --test bifrost_lsp_server go_semantic_diagnostics --features nlp
    cargo fmt
    cargo clippy-no-cuda
    git diff --check

Expected success means all targeted tests pass, formatting makes no further semantic changes, clippy reports no warnings, and `git diff --check` prints no whitespace errors.

## Validation and Acceptance

A Go file containing `func Run() { missingValue }` should produce a `bifrost-go` diagnostic with kind `go_unrecognized_symbol` for `missingValue`.

A Go file importing an indexed workspace package and calling an absent package member, such as `store.Missing()`, should produce a `bifrost-go` diagnostic with kind `go_unrecognized_package_member` when `store` resolves to a workspace package and that package has other indexed declarations.

No semantic diagnostic should be emitted for known declarations, imported package symbols, import aliases, dot imports, blank imports, predeclared identifiers, builtins, local variables, labels, declaration names, package clauses, known fields, known methods, external imports, unresolved receiver types, or malformed Go syntax.

Existing Java parse-error diagnostics must still be reported by `textDocument/diagnostic`, and malformed Go syntax must still report tree-sitter parse diagnostics even when semantic diagnostics are suppressed.

## Idempotence and Recovery

All changes are normal source edits and can be repeated safely. If a test fails after a partial implementation, rerun the targeted command after fixing the relevant collector or LSP conversion. If a semantic test fails due to a false positive, prefer suppressing diagnostics for that syntax shape over widening the diagnostic pass.

## Artifacts and Notes

No artifacts yet.

## Interfaces and Dependencies

In `src/analyzer/go/diagnostics.rs`, define:

    pub(crate) struct GoSemanticDiagnostic {
        pub(crate) range: Range,
        pub(crate) kind: &'static str,
        pub(crate) message: String,
    }

    pub(crate) fn collect_go_semantic_diagnostics(
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
        source: &str,
    ) -> Vec<GoSemanticDiagnostic>

The implementation should depend only on existing crate modules, `tree_sitter_go`, tree-sitter nodes, and analyzer indexes already built by `GoAnalyzer`. It must not invoke `go list`, download modules, or add a new public protocol shape.
