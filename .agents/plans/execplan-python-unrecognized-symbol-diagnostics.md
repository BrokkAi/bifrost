# Add high-confidence Python unrecognized-symbol diagnostics

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document follows `.agent/PLANS.md` from the repository root.

## Purpose / Big Picture

After this change, the LSP server reports semantic diagnostics for Python names that Bifrost can prove are unresolved from project-local, structured facts. A user opening a Python file in an editor will still see tree-sitter syntax errors, and on clean files will additionally see an error for a clear misspelling such as `missing_value` inside a function. Python's dynamic features make broad unknown-symbol diagnostics risky, so this first slice emits only for simple bare-name references and suppresses anything involving attributes, unresolved imports, wildcard imports, dynamic import patterns, or malformed syntax.

## Progress

- [x] (2026-06-30 20:45Z) Created this ExecPlan and mapped the work to the Python analyzer semantic diagnostic hook, the shared LSP diagnostic path, and focused analyzer/LSP tests.
- [x] (2026-06-30 21:06Z) Added the Python semantic diagnostic collector and wired it through `PythonAnalyzer::semantic_diagnostics`.
- [x] (2026-06-30 21:13Z) Added analyzer and LSP regression tests for positive diagnostics and conservative non-emission.
- [x] (2026-06-30 21:18Z) Ran targeted tests, formatting, and `cargo clippy-no-cuda`; whitespace validation remains.
- [x] (2026-06-30 21:26Z) Tightened function traversal to include Python type annotations and reran targeted tests plus `cargo clippy-no-cuda`.
- [x] (2026-06-30 21:27Z) Ran final `git diff --check`.
- [x] (2026-06-30 22:05Z) Addressed guided-review findings for builtin exceptions, attribute receivers, comprehension scopes, parameter annotations/defaults, match patterns, and shared Go/Python diagnostic utilities.

## Surprises & Discoveries

- Observation: The shared LSP diagnostic path already converts crate-internal `SemanticDiagnostic` values after parse diagnostics.
  Evidence: `src/lsp/handlers/diagnostic.rs` calls `workspace.analyzer().semantic_diagnostics(&project_file, &content)` only when the parse diagnostic list is empty.
- Observation: The current branch already contains the Go semantic diagnostic infrastructure, including `SemanticDiagnostic`, LSP conversion, and caps for large files and diagnostic volume.
  Evidence: `src/analyzer/go/diagnostics.rs` defines `MAX_GO_SEMANTIC_DIAGNOSTICS` and `GO_SEMANTIC_DIAGNOSTIC_SOURCE`; `src/analyzer/i_analyzer.rs` has a default `semantic_diagnostics` hook.
- Observation: The tree-sitter Python `except` alias was not exposed through the initially guessed `alias` field in the test fixture.
  Evidence: `cargo test python_semantic_diagnostics --lib` initially reported a false `python_unrecognized_symbol` diagnostic for `exc` in `except Exception as exc`; the implementation now collects identifier descendants under `except_clause` to seed the alias from AST nodes.
- Observation: Function annotations are outside the body node and were skipped by a body-only traversal.
  Evidence: The added `python_semantic_diagnostics_report_unknown_type_references` regression initially returned no diagnostics for `-> MissingType`; function traversal now scans parameters, annotations, and body inside the function scope.
- Observation: Guided review found several common Python syntax shapes where high-confidence behavior could drift without explicit handling.
  Evidence: Added regressions for builtin exceptions, parameter annotations/defaults, unresolved attribute receivers, comprehension scope isolation, and match pattern uncertainty; `cargo test python_semantic_diagnostics --lib` now runs 13 focused tests.

## Decision Log

- Decision: Keep Python diagnostics analyzer-owned and reuse the existing `SemanticDiagnostic` LSP conversion.
  Rationale: Python confidence rules depend on language semantics and analyzer indexes, while LSP should stay a protocol adapter.
  Date/Author: 2026-06-30 / Codex.
- Decision: Suppress semantic diagnostics for files with parse errors and for files with unresolved wildcard imports or module-level dynamic hooks.
  Rationale: The issue requires high confidence. These constructs make absence unknowable, so no diagnostic is better than a false positive.
  Date/Author: 2026-06-30 / Codex.
- Decision: Treat virtualenv, `.venv`, `site-packages`, and `uv` dependency discovery as out of scope.
  Rationale: Issue #362 lists virtualenv/site-packages discovery as a non-goal for this first slice; unresolved external imports should suppress, not trigger dependency indexing.
  Date/Author: 2026-06-30 / Codex.
- Decision: Suppress semantic diagnostics for `match_statement` in this slice instead of modeling all pattern bindings.
  Rationale: Python match patterns bind names through several pattern node shapes. Suppressing the whole construct preserves the high-confidence contract until structured pattern binding is added deliberately.
  Date/Author: 2026-06-30 / Codex.
- Decision: Extract only language-neutral diagnostic helpers shared with Go.
  Rationale: `ScopeStack`, node identity/text/range helpers are mechanical and were duplicated; Python import, parameter, comprehension, match, and dynamic suppression semantics remain language-specific.
  Date/Author: 2026-06-30 / Codex.

## Outcomes & Retrospective

The implementation now reports Python semantic diagnostics for high-confidence unresolved bare names through both pull and push LSP diagnostics. Analyzer tests cover unknown locals, unknown type annotations, parameter annotations/defaults, builtin exceptions, known locals/imports/builtins, relative imports, project re-exports, unresolved import suppression, dynamic construct suppression, attribute receiver/member policy, comprehension scoping, match-pattern suppression, malformed-file suppression, and diagnostic caps. LSP tests cover pull diagnostics, publish diagnostics on save, and parse-error-only behavior for malformed Python.

Validation completed so far:

    cargo test python_semantic_diagnostics --lib
    cargo test --test bifrost_lsp_server python_semantic_diagnostics --features nlp
    cargo fmt
    cargo clippy-no-cuda

## Context and Orientation

The LSP diagnostic entry point is `src/lsp/handlers/diagnostic.rs`. It maps a document URI to a project file, reads source, asks the active workspace analyzer for parse errors, and converts those errors to LSP diagnostics with source `bifrost-tree-sitter`. On this branch, that same path also asks the analyzer for semantic diagnostics when there are no parse diagnostics, then converts those to LSP diagnostics. This means adding Python semantic diagnostics to `PythonAnalyzer` affects both pull diagnostics (`textDocument/diagnostic`) and push diagnostics (`textDocument/publishDiagnostics`).

Python analyzer code lives under `src/analyzer/python`. `PythonAnalyzer` wraps a generic tree-sitter analyzer, exposes declarations and imports through `IAnalyzer`, and already has helpers for Python import binding, re-export resolution, relative imports, module code units, and module names. A semantic diagnostic is a crate-internal value with a byte `Range`, a source string, a kind string, and a message; LSP conversion happens outside the Python analyzer.

## Plan of Work

Create `src/analyzer/python/diagnostics.rs`. The collector parses clean Python source with tree-sitter, skips files above a fixed byte limit, returns no diagnostics when parse errors exist, and walks the syntax tree iteratively. It records lexical names as scopes are entered and treats function parameters, assignment targets, loop targets, `with/as` aliases, exception aliases, named expressions, function declarations, class declarations, and import bindings as visible names. It emits only for bare `identifier` nodes that are true references and are not known in any local scope, same-file declaration, indexed project-local declaration, resolved import, or Python built-in set.

The collector must suppress rather than diagnose when confidence is low. It should return no diagnostics for a file with unresolved wildcard imports, module-level `__getattr__`, `globals()`, `locals()`, `__import__`, or `importlib.import_module`. It should not emit for attribute references such as `obj.missing`; attribute/member diagnostics are a future feature.

Update `src/analyzer/python/mod.rs` to declare the diagnostics module, import `SemanticDiagnostic`, and implement `semantic_diagnostics` by mapping the Python collector into `SemanticDiagnostic` values. Do not change the LSP diagnostic protocol shape.

Add focused analyzer tests in the new diagnostics module. Add LSP integration tests in `tests/bifrost_lsp_server.rs` using the existing `LspTestServer` helper.

## Concrete Steps

From `/Users/dave/.codex/worktrees/b70c/bifrost`, run:

    cargo test python_semantic_diagnostics --lib
    cargo test --test bifrost_lsp_server python_semantic_diagnostics --features nlp
    cargo fmt
    cargo clippy-no-cuda
    git diff --check

Expected success means all targeted Python diagnostics tests pass, formatting completes, clippy reports no warnings, and `git diff --check` reports no whitespace errors.

## Validation and Acceptance

A Python file containing `def run():\n    missing_value\n` should produce one LSP diagnostic with source `bifrost-python`, code `python_unrecognized_symbol`, and a message containing `missing_value`.

No semantic diagnostic should be emitted for known locals, parameters, same-file declarations, project imports, relative imports, project re-exports, builtins, external imports, unresolved wildcard imports, dynamic import constructs, module-level `__getattr__`, attribute accesses, or malformed Python syntax. Malformed Python should continue to report `bifrost-tree-sitter` parse diagnostics only.

## Idempotence and Recovery

All edits are normal source and test changes and can be repeated safely. If tests fail after a partial implementation, rerun the focused command after fixing the collector or test fixture. If a false positive appears, prefer adding a conservative suppression for that syntax shape over widening the diagnostic pass.

## Artifacts and Notes

Validation transcript:

    cargo test python_semantic_diagnostics --lib
    test result: ok. 13 passed; 0 failed; 0 ignored; 0 measured; 370 filtered out

    cargo test --test bifrost_lsp_server python_semantic_diagnostics --features nlp
    test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 119 filtered out

    cargo clippy-no-cuda
    Finished `dev` profile [unoptimized + debuginfo] target(s)

    git diff --check
    no output

## Interfaces and Dependencies

In `src/analyzer/python/diagnostics.rs`, define:

    pub(crate) const PYTHON_UNRECOGNIZED_SYMBOL: &str = "python_unrecognized_symbol";
    pub(crate) const PYTHON_SEMANTIC_DIAGNOSTIC_SOURCE: &str = "bifrost-python";

    pub(crate) struct PythonSemanticDiagnostic {
        pub(crate) range: Range,
        pub(crate) kind: &'static str,
        pub(crate) message: String,
    }

    pub(crate) fn collect_python_semantic_diagnostics(
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
        source: &str,
    ) -> Vec<PythonSemanticDiagnostic>

The implementation depends only on existing crate modules, tree-sitter Python, existing analyzer indexes, and Python analyzer import/export helpers. It must not invoke Python, `uv`, pyright, mypy, or inspect virtualenv/site-packages.

## Revision Notes

- 2026-06-30: Initial ExecPlan created before implementation to make the intended conservative Python diagnostic slice self-contained.
- 2026-06-30: Updated after implementation and targeted validation to record the collector design, test evidence, and the exception-alias AST discovery.
- 2026-06-30: Updated after adding annotation traversal so type references participate in the high-confidence bare-name diagnostic policy.
- 2026-06-30: Updated after guided-review fixes to record the conservative match handling, shared utility extraction, and expanded regression coverage.
