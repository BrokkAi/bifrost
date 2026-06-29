# Tighten LSP Type-Definition Cursor Contexts

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document follows `.agent/PLANS.md` from the repository root. Any contributor who changes this work must update this file so it remains self-contained and accurate.

## Purpose / Big Picture

Bifrost advertises the LSP `textDocument/typeDefinition` capability for supported documents. That capability is document-wide, so editors such as VS Code can offer "Go to Type Definition" even when the cursor is on a function name or another callable symbol that is not a type-bearing expression. Before this plan, some of those requests could do too much analysis and either look like they were hanging or return a misleading return type.

After this work, Bifrost still advertises `typeDefinitionProvider`, but the handler returns a prompt JSON `null` result for cursor positions that are not semantically appropriate for type-definition lookup. Users can see the behavior by running the focused LSP integration tests and by trying "Go to Type Definition" on a script-level function name in VS Code: the request completes without navigation instead of appearing stuck.

## Progress

- [x] (2026-06-29 14:00Z) Confirmed the worktree is on `323-tighten-lsp-type-definition-cursor-contexts`, clean, and aligned with `origin/master` after `git fetch`.
- [x] (2026-06-29 14:05Z) Added this ExecPlan as the living source of truth for issue `#323`.
- [x] (2026-06-29 14:12Z) Added baseline LSP regressions for inappropriate TypeScript/JavaScript cursor contexts.
- [x] (2026-06-29 14:18Z) Tightened JS/TS type lookup cursor semantics and ran focused validation.
- [x] (2026-06-29 14:30Z) Ran guided review for the JS/TS milestone and addressed the accepted short-circuit ordering finding.
- [ ] Tighten Java and C# cursor semantics, add regressions, and run focused validation.
- [ ] Run guided review for the JVM/.NET milestone and address accepted findings.
- [ ] Tighten Rust, Go, and Scala cursor semantics, add regressions, and run focused validation.
- [ ] Run guided review for the Rust/Go/Scala milestone and address accepted findings.
- [ ] Run final focused tests, formatting, non-CUDA clippy, and final guided review.

## Surprises & Discoveries

- Observation: This branch currently has no local implementation commits; `HEAD`, `origin/master`, and `origin/323-tighten-lsp-type-definition-cursor-contexts` all resolve to the same commit at kickoff.
  Evidence: `git rev-parse HEAD origin/master origin/323-tighten-lsp-type-definition-cursor-contexts` printed `a4a7a717b05379ed9098290d8b1be39001eb3c4e` for all three refs.

- Observation: The LSP handler already has one useful choke point for this work.
  Evidence: `src/lsp/handlers/type_definition.rs` reads overlay-aware document text, accepts selected class declarations through `selected_type_declaration`, and otherwise calls `get_type::resolve_type_batch` from `resolve_type_target`.

- Observation: TypeScript currently treats function and method declaration names as type-bearing by returning their explicit return type.
  Evidence: `src/analyzer/usages/get_type/js_ts.rs` has `declaration_type_node_for_reference`, which returns the `return_type` field for `function_declaration`, `method_definition`, and `method_signature` when the selected name matches.

- Observation: The initial TypeScript regressions reproduced issue `#323` while existing positive and null cases stayed green.
  Evidence: Before changing resolver code, `cargo test --test bifrost_lsp_server type_definition --features nlp` ran 6 filtered tests; the new TypeScript function-name and method-name tests failed by returning the `Widget` interface location, while the JavaScript unsupported callable, unresolved JavaScript value, Rust explicit local type, and TypeScript overlay tests passed.

- Observation: A tree-sitter parent/name-field check is enough to prevent JS/TS callable declaration names from being treated as return-type lookup targets.
  Evidence: After adding `is_callable_declaration_name` in `src/analyzer/usages/get_type/js_ts.rs`, `cargo test --test bifrost_lsp_server type_definition --features nlp` passed 6/6 filtered tests.

- Observation: The first JS/TS review checkpoint found the initial short-circuit was placed after import-binder construction, which was correct but not as cheap as it should be.
  Evidence: `is_callable_declaration_name` now runs immediately after `smallest_named_node_covering` succeeds and before `compute_jsts_import_binder`; the focused type-definition tests and `cargo fmt --check` pass after this change.

## Decision Log

- Decision: Keep `typeDefinitionProvider` advertised globally.
  Rationale: LSP capabilities are document-wide and the issue explicitly requires preserving useful behavior for variables, fields, parameters, type expressions, and open-document overlays.
  Date/Author: 2026-06-29 / Codex

- Decision: Put cursor-context short-circuiting in analyzer-owned type lookup rather than in the LSP handler.
  Rationale: The handler should not contain per-language syntax tables. Existing type lookup functions already parse source with tree-sitter and own language semantics.
  Date/Author: 2026-06-29 / Codex

- Decision: Use `TypeLookupStatus::NoType` with a specific diagnostic kind for inappropriate symbols instead of adding a new outcome type.
  Rationale: The LSP handler already turns empty type results into `null`. A diagnostic kind gives tests and tools a structured reason without changing the public LSP response shape.
  Date/Author: 2026-06-29 / Codex

## Outcomes & Retrospective

No implementation milestone is complete yet. The current expected outcome is a focused branch that keeps positive type-definition behavior while making inappropriate callable-symbol requests complete with `null`.

Milestone 1 and the JS/TS resolver slice are implemented. TypeScript function and method declaration names now return `null` from LSP typeDefinition instead of navigating to their return type, and the JavaScript unsupported callable case remains a normal `null` response.

JS/TS guided-review outcome: one tactical finding was accepted and fixed. Inappropriate TypeScript declaration-name requests now short-circuit before import-binder and alias setup. No remaining blocker is known for this milestone.

## Context and Orientation

`textDocument/typeDefinition` is routed in `src/lsp/server.rs` to `src/lsp/handlers/type_definition.rs`. The handler reads the current file from disk or from the LSP open-document overlay, converts the LSP position to a byte offset, checks whether the cursor selects a type declaration name, and then delegates expression and identifier lookup to `crate::analyzer::usages::get_type`.

`get_type` is a shared analyzer API under `src/analyzer/usages/get_type/`. It accepts a `TypeLookupRequest`, resolves the source cursor to a `ResolvedReferenceSite`, parses the file with tree-sitter for supported languages, and returns a `TypeLookupOutcome`. A `TypeLookupOutcome` has a `status`, an optional resolved reference site, zero or more type definitions, and structured diagnostics. The LSP handler only returns locations when at least one type definition is present; otherwise it returns `None`, which serializes as JSON `null`.

An inappropriate symbol context means the cursor is on syntax that is a declaration name or callable identity rather than on a type expression, variable, field, parameter, receiver object, or expression whose type Bifrost can prove. For example, the `build` token in `function build(): Widget` is inappropriate for `typeDefinition`; normal definition or call-hierarchy navigation is the right feature there. The `Widget` token in the return type and a `value` variable declared as `Widget` remain appropriate.

Do not solve this by disabling `typeDefinitionProvider`, by adding regexes, by splitting source text to infer syntax, or by adding handler-level per-language node-kind tables. Cursor classification must come from tree-sitter nodes, existing analyzer declaration ranges, import binders, or resolver helpers that already operate on parsed syntax.

## Plan of Work

First, add LSP integration tests in `tests/bifrost_lsp_server.rs` near the existing type-definition tests. Use small temporary projects and `position_after` to target the cursor on the exact declaration or callable token. The tests should assert `response["result"].is_null()` for inappropriate contexts and should preserve the existing positive tests for explicit local types and open-document overlays.

Second, tighten JS/TS in `src/analyzer/usages/get_type/js_ts.rs`. Add a language-local helper that recognizes selected function or method declaration names from tree-sitter nodes and returns `no_type("inappropriate_symbol_context", ...)` before `declaration_type_node_for_reference` can treat return types as the type-definition result. Preserve type-reference lookup, declaration-name lookup for parameters/variables/properties, local binding lookup, receiver lookup, and call-expression return-type lookup only when the selected node is the expression, not the callable declaration identity.

Third, tighten Java and C#. Java logic lives in `src/analyzer/usages/get_definition/java.rs` behind `java_type_lookup_fqn`; C# logic lives in `src/analyzer/usages/get_definition/csharp.rs` behind `csharp_type_lookup_resolution`. For both, function or method declaration names must return no type instead of their return type, while parameter names, local variables, fields, receiver objects, and explicit type nodes continue to work.

Fourth, tighten Rust, Go, and Scala. Rust logic lives in `src/analyzer/usages/get_type/rust.rs` and uses `rust_type_lookup_expression`. Go logic lives in `src/analyzer/usages/get_definition/go.rs` behind `go_type_lookup_resolution` and must preserve interface method owner behavior used by `textDocument/implementation`. Scala logic lives in `src/analyzer/usages/get_definition/scala.rs` behind `scala_type_lookup_fqn`. Each language should reject selected callable-symbol identities using parsed node relationships rather than source text probes.

After each milestone, update this document's living sections, run focused validation, run `brokk:brokk-guided-review` in uncommitted-changes mode for the milestone diff, and address accepted findings before moving on.

## Concrete Steps

Work from the repository root:

    cd /Users/dave/.codex/worktrees/b4f5/bifrost

At kickoff, refresh remote refs and confirm the current branch:

    git fetch
    git status --short --branch
    git rev-parse HEAD origin/master origin/323-tighten-lsp-type-definition-cursor-contexts

During implementation, run the focused LSP type-definition tests after each code milestone:

    cargo test --test bifrost_lsp_server type_definition --features nlp

When a milestone changes language-specific resolver helpers, also run the relevant focused tests if they exist and are practical:

    cargo test --test usages_js_ts_graph_test --features nlp
    cargo test --test usages_java_graph_test --features nlp
    cargo test --test usages_csharp_graph_test --features nlp
    cargo test --test usages_rust_graph_test --features nlp
    cargo test --test usages_go_graph_test --features nlp
    cargo test --test usages_scala_graph_test --features nlp

Run formatting before review checkpoints:

    cargo fmt --check

At the final quality gate on this macOS worktree, run:

    cargo test --test bifrost_lsp_server type_definition --features nlp
    cargo fmt --check
    cargo clippy-no-cuda

## Validation and Acceptance

The primary acceptance behavior is LSP-level. Requests on inappropriate callable-symbol positions return a response whose `result` is JSON `null`. The response must arrive as a normal LSP response; the tests must not depend on cancellation or client-side timeout.

Positive behavior must remain green. A request on a Rust explicit local type still resolves to the model file. A request on a TypeScript open-document overlay annotation still resolves to the imported interface. A request on an unresolved JavaScript value still returns `null`. The initialize response still advertises `typeDefinitionProvider: true`.

The focused validation command is:

    cargo test --test bifrost_lsp_server type_definition --features nlp

Expected final result: all type-definition tests pass, including the new inappropriate-context regressions and existing positive tests.

## Idempotence and Recovery

The changes are additive and can be rerun safely. Tests use temporary directories and do not require persistent workspace state. If a milestone test fails after a partial edit, keep the failing code in place, update this ExecPlan with the discovery, and fix forward rather than reverting unrelated user changes.

Do not create or switch branches. Stage only files changed for this work, and commit between ExecPlan milestones as required by `AGENTS.md`. Do not push or open a pull request unless explicitly asked.

## Artifacts and Notes

The JSON shape for an inappropriate cursor response should be:

    {
      "jsonrpc": "2.0",
      "id": 2,
      "result": null
    }

The TypeScript regression source should include a concrete return type, for example:

    interface Widget {}
    function build(): Widget { return {} as Widget; }

Putting the cursor on `build` should return `null`. Putting the cursor on `Widget` in the return type remains a valid type-definition request.

## Interfaces and Dependencies

No public LSP capability changes are allowed. `src/lsp/capabilities.rs` must keep:

    type_definition_provider: Some(TypeDefinitionProviderCapability::Simple(true))

No new external dependencies are needed. Any helper added to `get_type` or `get_definition` must use existing tree-sitter `Node` APIs, existing analyzer indexes, and existing `no_type`/diagnostic outcome construction.

At the end of this work, `TypeLookupOutcome` still carries:

    status: TypeLookupStatus
    reference: Option<ResolvedReferenceSite>
    types: Vec<TypeLookupType>
    diagnostics: Vec<TypeLookupDiagnostic>

Inappropriate contexts should use:

    TypeLookupStatus::NoType
    diagnostic kind: "inappropriate_symbol_context"

## Revision Notes

2026-06-29 / Codex: Created this ExecPlan from issue `#323` and the implementation plan requested by the user. The document records the existing handler and resolver seams and the no-mini-parser constraint before code changes begin.
