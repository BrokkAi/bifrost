# Add high-confidence PHP unrecognized-symbol diagnostics

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document follows `.agent/PLANS.md` from the repository root.

## Purpose / Big Picture

After this change, Bifrost's LSP server reports semantic diagnostics for PHP references that the analyzer can prove are unresolved. A user opening a PHP file will still see tree-sitter syntax diagnostics for malformed code, and cleanly parsed files will additionally get diagnostics for clear mistakes such as a misspelled namespaced type, function, constant, or member on a structurally known receiver.

The first slice is deliberately conservative. PHP supports dynamic class names, function names, member names, magic methods, magic properties, and vendor autoload behavior that Bifrost does not fully model. When one of those dynamic or external boundaries appears, the diagnostic pass emits nothing rather than guessing.

## Progress

- [x] (2026-07-01 09:10Z) Created this ExecPlan and mapped the work to `src/analyzer/php`, `src/lsp/handlers/diagnostic.rs`, analyzer tests, and LSP tests.
- [x] (2026-07-01 09:34Z) Added `src/analyzer/php/diagnostics.rs` and wired it through `PhpAnalyzer::semantic_diagnostics`.
- [x] (2026-07-01 09:34Z) Added analyzer tests for unresolved names, alias suppression, Composer PSR-4 project classes, dynamic suppression, malformed suppression, external boundaries, and known receiver member handling.
- [x] (2026-07-01 09:34Z) Added LSP tests for PHP pull diagnostics, publish diagnostics on save, and parse-only behavior for malformed PHP.
- [x] (2026-07-01 09:34Z) Ran targeted validation, formatting, `cargo clippy-no-cuda`, and `git diff --check`.
- [x] (2026-07-01 10:25Z) Addressed guided-review findings for PHP global fallback, magic member boundaries, trait-provided members, nested local scopes, dynamic class names, and missing static receiver types.

## Surprises & Discoveries

- Observation: The existing LSP diagnostic handler already calls `IAnalyzer::semantic_diagnostics` only after parse diagnostics are empty.
  Evidence: `src/lsp/handlers/diagnostic.rs` builds parse diagnostics first, then extends with analyzer semantic diagnostics only when that list is empty.
- Observation: PHP get-definition and usage-graph code already model most reference shapes needed for this feature.
  Evidence: `src/analyzer/usages/get_definition/php.rs` resolves types, functions, constants, static members, and typed instance receivers using `PhpFileContext` and the definition index.
- Observation: The existing PHP alias parser still uses source-text parsing internally, but the new diagnostic collector can avoid adding new mini-parsers by walking tree-sitter nodes for reference collection.
  Evidence: `src/analyzer/php/aliases.rs` handles `use` declarations, while the planned collector will inspect AST node kinds and fields for all new reference sites.
- Observation: PHP tree-sitter represents variable names with named children that can look like bare `name` nodes during a generic walk.
  Evidence: The first `cargo test php_semantic_diagnostics --lib` run falsely diagnosed `$service`, `$this`, and namespace declaration names as constants until `is_bare_constant_reference` excluded `variable_name`, `namespace_name`, and declaration contexts.
- Observation: Unqualified PHP functions and constants are not high-confidence unresolved references because PHP can fall back to global functions/constants from a namespace.
  Evidence: Guided review flagged namespaced `str_replace(...)` as a false positive; the collector now suppresses unqualified function and constant diagnostics.

## Decision Log

- Decision: Add an analyzer-owned PHP collector and keep LSP conversion generic.
  Rationale: The confidence policy depends on PHP semantics, while the LSP layer already knows how to render language-neutral `SemanticDiagnostic` values.
  Date/Author: 2026-07-01 / Codex.
- Decision: Suppress semantic diagnostics for malformed PHP files.
  Rationale: The issue requires reference shapes to be trustworthy, and the existing diagnostic path already reports parse errors independently.
  Date/Author: 2026-07-01 / Codex.
- Decision: Diagnose only workspace-bounded unresolved names and structurally known members.
  Rationale: Missing external vendor symbols, magic PHP members, and dynamic names are common enough that absence from the index is not proof of a bug.
  Date/Author: 2026-07-01 / Codex.
- Decision: Suppress dynamic PHP shapes locally instead of suppressing a whole file when dynamic constructs appear.
  Rationale: A file can contain a dynamic call and still have an unrelated high-confidence unresolved type or function reference elsewhere.
  Date/Author: 2026-07-01 / Codex.
- Decision: Suppress member diagnostics for owners with magic member handlers or trait uses.
  Rationale: `__call`, `__callStatic`, `__get`, and trait methods can make an apparently absent member valid even when the flattened member is not directly indexed on the class.
  Date/Author: 2026-07-01 / Codex.

## Outcomes & Retrospective

The implementation adds PHP semantic diagnostics to both pull and publish LSP diagnostics through the existing analyzer hook. The collector reports workspace-bounded unresolved PHP types, qualified functions, qualified constants, missing static receiver types, and members on structurally known receivers, while suppressing malformed files, dynamic PHP constructs, unqualified function/constant names, external vendor boundaries, imported aliases, Composer PSR-4 project classes, built-in scalar types, common PHP built-in functions/constants, magic members, trait-use owners, nested-scope binding leaks, and known inherited members. Focused analyzer tests, LSP tests, PHP get-definition regressions, formatting, clippy, and whitespace checks passed.

## Context and Orientation

The LSP diagnostic entry point is `src/lsp/handlers/diagnostic.rs`. It maps a document URI to a `ProjectFile`, reads the source, reports tree-sitter parse errors, and calls `workspace.analyzer().semantic_diagnostics(...)` only if there are no parse errors. Go and Python already use this hook through `src/analyzer/go/diagnostics.rs` and `src/analyzer/python/diagnostics.rs`.

The PHP analyzer lives in `src/analyzer/php`. `src/analyzer/php/mod.rs` defines `PhpAnalyzer`, exposes PHP namespace and `use` alias helpers, and implements the `IAnalyzer` trait. `src/analyzer/php/composer.rs` models Composer PSR-4 roots for indexed project declarations. `src/analyzer/usages/get_definition/php.rs` and `src/analyzer/usages/php_graph` contain structured PHP resolution behavior that the collector should mirror or reuse.

A semantic diagnostic is a language-neutral analyzer result with a byte `Range`, source string, kind string, and message. The LSP layer converts those byte ranges to protocol ranges and sets severity to error.

## Plan of Work

Create `src/analyzer/php/diagnostics.rs`. Define a crate-internal `PhpSemanticDiagnostic` and constants `PHP_UNRECOGNIZED_SYMBOL`, `PHP_UNRECOGNIZED_MEMBER`, and `PHP_SEMANTIC_DIAGNOSTIC_SOURCE`. The collector function `collect_php_semantic_diagnostics(analyzer: &dyn IAnalyzer, file: &ProjectFile, source: &str) -> Vec<PhpSemanticDiagnostic>` should parse PHP with tree-sitter, suppress files with parse errors, bound file size and diagnostic count, and walk named AST nodes iteratively.

The collector should recognize only structured reference positions: `object_creation_expression`, `named_type`, `instanceof` type operands, `function_call_expression` with a literal `name` or `qualified_name`, bare constant references, `class_constant_access_expression`, `scoped_call_expression`, `scoped_property_access_expression`, `member_call_expression`, and `member_access_expression`. It should ignore declarations, `namespace_use_declaration`, comments, strings, variables, variable variables, dynamic member names, dynamic function names, and any syntax shape where the owner cannot be proven.

Update `src/analyzer/php/mod.rs` to add the module and implement `semantic_diagnostics` by delegating to the collector and converting into `SemanticDiagnostic`.

Add crate-internal analyzer tests to cover unknown namespaced type/function/constant references, imported alias suppression, Composer PSR-4 suppression for indexed project classes, malformed-file suppression, dynamic construct suppression, and known `self`, `static`, and `parent` member behavior. These tests use `TestProject` because the diagnostic kind and source fields are crate-internal. Add LSP tests to verify pull diagnostics, publish diagnostics on save, and parse-only behavior for malformed PHP.

## Concrete Steps

Work from `/Users/dave/.codex/worktrees/02d5/bifrost`.

Run these commands after implementation:

    cargo test php_semantic_diagnostics --lib
    cargo test --test bifrost_lsp_server php_semantic_diagnostics --features nlp
    cargo test --test get_definition_test php_
    cargo fmt
    cargo clippy-no-cuda
    git diff --check

## Validation and Acceptance

A PHP file containing an unresolved type such as `private MissingType $value;` in an indexed namespace should produce one `bifrost-php` diagnostic with code `php_unrecognized_symbol`.

A PHP file containing qualified unresolved names such as `\App\missing_function();` or `\App\MISSING_CONSTANT` in an indexed namespace should produce `bifrost-php` diagnostics with code `php_unrecognized_symbol`. Unqualified function and constant names should be suppressed because PHP namespace fallback makes them uncertain.

A PHP file importing or referencing an indexed project class through Composer PSR-4 roots should produce no semantic diagnostic. A malformed PHP file should produce tree-sitter diagnostics and no `bifrost-php` diagnostics.

Member diagnostics should appear only when the receiver owner is known from `$this`, `self`, `static`, `parent`, a typed parameter, or an assignment from `new KnownType()`. Dynamic method, property, class, and function references should produce no diagnostics.

## Idempotence and Recovery

All changes are source edits and test additions. Re-running the implementation steps is safe. If a diagnostic test fails due to a false positive, prefer suppressing that syntax shape over expanding inference. If a test fails due to a false negative in a high-confidence shape, inspect the tree-sitter node kind and add structured handling for that shape without introducing regex or delimiter parsing.

## Artifacts and Notes

Targeted validation completed so far:

    cargo test php_semantic_diagnostics --lib
    result: 10 passed; 0 failed

    cargo test --test bifrost_lsp_server php_semantic_diagnostics --features nlp
    result: 3 passed; 0 failed

    cargo test --test get_definition_test php_
    result: 16 passed; 0 failed

    cargo fmt
    result: completed with no output

    cargo clippy-no-cuda
    result: finished successfully

    git diff --check
    result: completed with no output

## Interfaces and Dependencies

In `src/analyzer/php/diagnostics.rs`, define:

    pub(crate) struct PhpSemanticDiagnostic {
        pub(crate) range: Range,
        pub(crate) kind: &'static str,
        pub(crate) message: String,
    }

    pub(crate) fn collect_php_semantic_diagnostics(
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
        source: &str,
    ) -> Vec<PhpSemanticDiagnostic>

The implementation should depend on existing crate modules, tree-sitter nodes, `tree_sitter_php`, `PhpAnalyzer`, `PhpFileContext`, `resolve_php_type`, `resolve_php_function`, `resolve_php_constant`, and the already-built `DefinitionLookupIndex`. It must not invoke Composer, scan `vendor`, download packages, or add a new LSP protocol shape.

Revision note, 2026-07-01: Initial ExecPlan created because issue #360 is a cross-cutting analyzer and LSP feature.

Revision note, 2026-07-01: Updated progress, discoveries, decisions, test-fixture rationale, and validation artifacts after implementing the PHP diagnostics collector and focused tests.
