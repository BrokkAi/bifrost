# Tighten LSP Type Hierarchy and Implementation Cursor Contexts

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document follows `.agent/PLANS.md` from the repository root. Any contributor who changes this work must update this file so it remains self-contained and accurate.

## Purpose / Big Picture

Bifrost advertises the LSP `typeHierarchyProvider` and `implementationProvider` capabilities so editors can offer type hierarchy and implementation navigation in supported source files. Before this work, `textDocument/prepareTypeHierarchy` could accept unrelated cursor positions inside a class or type body by walking from the enclosing code unit to the nearest surrounding type. `textDocument/implementation` also reused the broad type-definition target resolver, which is useful for "go to type definition" but too permissive for implementation navigation.

After this work, both providers remain advertised, but they return a normal JSON `null` response for cursor positions that are not valid type or implementation targets. Users can see the behavior by running the focused LSP integration tests. Requests on type declarations and valid type references still work; requests on method names, ordinary functions, locals, literals, fields, and unsupported value contexts complete without misleading navigation.

## Progress

- [x] (2026-06-29 11:11Z) Confirmed the worktree is clean on `332-tighten-lsp-type-hierarchy-and-implementation-cursor-contexts`, aligned with its upstream, and at `cc45d8f`.
- [x] (2026-06-29 11:20Z) Added this ExecPlan as the living source of truth for issue `#332`.
- [x] (2026-06-29 11:27Z) Ran Milestone 0 baseline focused LSP tests for existing type hierarchy and implementation positives.
- [x] (2026-06-29 11:30Z) Prepared the ExecPlan-only Milestone 0 checkpoint for commit.
- [x] (2026-06-29 12:20Z) Milestone 1 implementation: added shared resolver target classification, tightened type hierarchy and implementation eligibility, and added Java/C#/Scala cursor-context regressions.
- [x] (2026-06-29 12:28Z) Ran Milestone 1 focused validation: type hierarchy, implementation, and type definition LSP slices passed.
- [x] (2026-06-29 13:15Z) Ran and resolved Milestone 1 guided review on the uncommitted diff.
- [ ] Milestone 2: implement TypeScript/JavaScript and Rust cursor-context regressions.
- [x] (2026-06-29 13:45Z) Milestone 3: added Go implementation/type-hierarchy value-context regressions, completed guided review, fixed accepted test findings, and reran focused validation.
- [ ] Milestone 4: run the final focused LSP sweep, formatting, non-CUDA clippy, final guided review, and final cleanup.

## Surprises & Discoveries

- Observation: The branch already exists and is not detached at kickoff.
  Evidence: `git status --short --branch` printed `## 332-tighten-lsp-type-hierarchy-and-implementation-cursor-contexts...origin/332-tighten-lsp-type-hierarchy-and-implementation-cursor-contexts`.

- Observation: The branch is current with its upstream after refreshing remote refs.
  Evidence: `git rev-list --left-right --count HEAD...@{upstream}` printed `0 0`.

- Observation: There is an instruction conflict around rebasing at kickoff.
  Evidence: The worktree instructions say to run `git fetch && git rebase` when starting on a new worktree, while the project-doc section says not to rebase unless explicitly asked. This plan records the conflict and follows the project-doc override by fetching but not rebasing.

- Observation: `prepareTypeHierarchy` currently has the exact broad promotion behavior described by issue `#332`.
  Evidence: `src/lsp/handlers/type_hierarchy.rs::prepare` calls `analyzer.enclosing_code_unit`, then `nearest_type_unit`, which climbs parents until it finds a class-like code unit.

- Observation: `implementation` currently shares the broad type-definition target resolver.
  Evidence: `src/lsp/handlers/type_definition.rs::implementation` calls `resolve_type_target`, the same helper used by `typeDefinition`, then maps resolved type targets to descendants.

- Observation: Existing positive type hierarchy and Go implementation behavior is green before production code changes.
  Evidence: `cargo test --test bifrost_lsp_server type_hierarchy --features nlp` passed 9 filtered tests, and `cargo test --test bifrost_lsp_server implementation --features nlp` passed 3 filtered tests.

- Observation: Scala return type syntax was not classified as an explicit type position.
  Evidence: The new `bifrost_lsp_server_type_hierarchy_filters_java_csharp_scala_value_contexts` regression initially returned `null` for the cursor on `Widget` in `def build(): Widget`; adding `return_type` to `scala_is_type_position` made the test pass.

- Observation: The old Go implementation-from-local positive is now intentionally invalid under issue `#332`.
  Evidence: After implementation eligibility started rejecting `ValueExpression` targets, `bifrost_lsp_server_implementation_returns_go_interface_descendants` returned `null` when invoked on a local variable of interface type, while Go interface declaration and interface method implementation tests still passed.

- Observation: Guided review found the initial target-kind classification was incomplete.
  Evidence: Reviewers noted that Rust and TypeScript declared type references still used the default `ValueExpression` helper. The fix marked TypeScript declared type resolution with `type_reference_outcome`, added Rust explicit type-node resolution through `rust_resolve_type_node_fqn`, and added TS/Rust LSP type-reference regressions.

- Observation: Guided review found the first target-kind enum leaked a Go-specific name into generic code.
  Evidence: `TypeLookupTargetKind::GoInterfaceMethodOwner` was replaced with language-neutral `TypeLookupTargetKind::MemberOwner`, while the existing `go_interface_method_owner` diagnostic remains the analyzer-owned way to recover the selected method name.

- Observation: The Milestone 3 review found that the first Go local-variable case targeted the type annotation, not the local identifier.
  Evidence: The case used `position_after(source, "local W")`, which lands inside `Worker` in `var local Worker`; the fix changed it to `position_after(source, "var local")` and reused one shared null-case table for implementation and hierarchy assertions.

## Decision Log

- Decision: Keep `typeHierarchyProvider` and `implementationProvider` advertised globally.
  Rationale: LSP capabilities are document-wide and issue `#332` explicitly asks to preserve advertised capabilities while returning `null` for invalid cursor contexts.
  Date/Author: 2026-06-29 / Codex

- Decision: Use an ExecPlan with milestone commits and guided-review checkpoints.
  Rationale: The behavior spans multiple language-specific type lookup paths, so small reviewable slices reduce the risk of weakening valid type-definition behavior while tightening type hierarchy and implementation.
  Date/Author: 2026-06-29 / Codex

- Decision: Fetch remote refs but do not rebase at kickoff.
  Rationale: `git fetch` satisfies the freshness check. The project-doc section explicitly says not to rebase unless asked, so no rebase was run.
  Date/Author: 2026-06-29 / Codex

- Decision: Preserve broad `textDocument/typeDefinition` behavior.
  Rationale: Type definition may legitimately resolve the type of a value expression, such as a local variable or receiver. Type hierarchy and implementation have narrower target semantics and should opt into stricter eligibility.
  Date/Author: 2026-06-29 / Codex

- Decision: Add `TypeLookupTargetKind` to `TypeLookupOutcome`.
  Rationale: The LSP handlers need to distinguish type-syntax results from value-expression results without adding language-specific syntax tables in handler code. The classification is produced by analyzer-owned tree-sitter resolvers.
  Date/Author: 2026-06-29 / Codex

- Decision: Treat Go implementation from a local interface-typed variable as an invalid value context.
  Rationale: Issue `#332` asks implementation to reject locals and ordinary value contexts while preserving type/interface declarations and Go interface method owner lookup. The existing declaration and interface-method tests continue to cover the preserved positives.
  Date/Author: 2026-06-29 / Codex

- Decision: Keep C# Milestone 1 coverage to negative cursor contexts for hierarchy.
  Rationale: The C# hierarchy handler currently returns `null` for the attempted type-reference fixture. Rather than keep a weak `array or null` assertion, the milestone validates C# method/local rejection and leaves positive C# type-reference hierarchy coverage out of this slice.
  Date/Author: 2026-06-29 / Codex

## Outcomes & Retrospective

Milestone 0 baseline validation is complete. The branch is clean and current with its upstream. This document records the implementation scope, repository orientation, validation plan, and review checkpoint policy before production code changes begin. Existing positive type hierarchy and Go implementation LSP tests pass before production code changes.

Milestone 1 implementation and guided-review resolution are complete. The shared `TypeLookupTargetKind` classification now lets `typeDefinition` keep broad behavior while `prepareTypeHierarchy` and `implementation` reject value-expression targets. Java, C#, and Scala regressions cover method/function names and locals returning `null`; Java, Scala, TypeScript, and Rust cover valid type-reference hierarchy behavior where supported, and TypeScript covers implementation from a type reference. The review-accepted fixes removed the Go-specific target-kind name from the generic enum and completed TypeScript/Rust type-reference classification. Focused validation passed after review fixes:

    cargo test --test bifrost_lsp_server type_hierarchy --features nlp
    result: 10 passed; 0 failed

    cargo test --test bifrost_lsp_server implementation --features nlp
    result: 5 passed; 0 failed

    cargo test --test bifrost_lsp_server type_definition --features nlp
    result: 11 passed; 0 failed

Milestone 3 is complete. The new Go regression proves ordinary functions, non-interface methods, struct fields, and local variables return `null` for both `textDocument/implementation` and `textDocument/prepareTypeHierarchy`, while the existing Go interface declaration and interface-method positives remain green. Guided review found one duplicated case-table cleanup and one real cursor-target bug; both were fixed. Validation passed:

    cargo test --test bifrost_lsp_server bifrost_lsp_server_go_type_or_implementation_rejects_value_contexts --features nlp
    result: 1 passed; 0 failed

    cargo test --test bifrost_lsp_server implementation --features nlp
    result: 6 passed; 0 failed

## Context and Orientation

`textDocument/prepareTypeHierarchy`, `typeHierarchy/supertypes`, and `typeHierarchy/subtypes` are routed in `src/lsp/server.rs` to `src/lsp/handlers/type_hierarchy.rs`. The `prepare` handler reads the current document from disk or the LSP open-document overlay, converts the LSP position to a byte offset, and builds a `TypeHierarchyItem` for a type `CodeUnit`. A `CodeUnit` is the analyzer's declaration model from `src/analyzer/model.rs`; class-like units include classes, interfaces, structs, traits, and similar declarations represented by `CodeUnit::is_class()`.

`textDocument/typeDefinition` and `textDocument/implementation` are routed to `src/lsp/handlers/type_definition.rs`. `typeDefinition` returns locations for type definitions that describe the selected expression or identifier. `implementation` uses type hierarchy relations to return descendants of a selected type, or method implementations for valid method-owner cases such as Go interface methods.

The shared analyzer type lookup API lives under `src/analyzer/usages/get_type/`. It accepts a `TypeLookupRequest`, resolves the source cursor to a `ResolvedReferenceSite`, parses the file with tree-sitter for supported languages, and returns a `TypeLookupOutcome`. A `TypeLookupOutcome` currently has a `status`, an optional resolved reference site, zero or more type definitions, and structured diagnostics.

A valid type hierarchy target means the cursor is on a type declaration selection range or on parsed type syntax that names a supported type. A valid implementation target means the cursor is on a type/interface declaration, a supported type reference, or a known special method-owner case such as a Go interface method. A value expression means a local variable, ordinary function call, receiver/member expression, field, literal, or arbitrary identifier whose type can be useful for `typeDefinition` but should not seed type hierarchy or implementation.

Do not solve this by disabling LSP providers, by adding regexes, by splitting source text to infer syntax, or by adding language-kind tables in LSP handlers. Cursor classification must come from tree-sitter nodes, existing analyzer declaration ranges, import binders, or resolver helpers that already operate on parsed syntax.

## Plan of Work

Milestone 0 creates this ExecPlan, runs the current focused positive tests for type hierarchy and implementation, then commits only this document. This establishes a resumable plan before production code changes.

Milestone 1 introduces structured target classification in `src/analyzer/usages/get_type/mod.rs` and wires the shared LSP resolver to respect stricter eligibility for type hierarchy and implementation without changing `typeDefinition`. The classification should distinguish at least type references from value expressions, and it should preserve the existing Go interface-method owner diagnostic path. Java, C#, and Scala should be updated first because their type lookup helpers already have explicit inappropriate callable declaration handling from the neighboring type-definition work. Add LSP regressions proving method/function names and locals return `null` for type hierarchy or implementation while type declarations and valid type references still work.

Milestone 2 extends the same structured classification to TypeScript/JavaScript and Rust. TypeScript type references and annotations should be classified as valid type references, while ordinary values, calls, locals, and callable declaration identities should not seed type hierarchy or implementation. JavaScript should stay unsupported for declared type lookup unless existing structured behavior already proves a positive path. Rust explicit type syntax should be valid, while expression-derived lookup should remain available only to `typeDefinition`.

Milestone 3 handles Go and implementation-specific behavior. Go interface declarations and Go interface method implementation lookup must continue to work. Ordinary Go functions, non-interface methods, locals, fields, and value contexts should return `null` for implementation and should not prepare type hierarchy. Existing Go structural interface hierarchy tests must stay green.

Milestone 4 performs the full focused LSP sweep and cleanup. Run the type hierarchy, implementation, type definition, and neighboring call hierarchy tests, then run formatting and the non-CUDA clippy gate. Run a final guided review on the accumulated branch diff, fix accepted findings, update this plan's outcomes, and commit final cleanup.

After each implementation milestone, update this document's living sections, run focused validation, run `brokk:brokk-guided-review` in uncommitted-changes mode for that milestone diff, address accepted findings, rerun focused validation, and commit only files changed for the milestone.

## Concrete Steps

Work from the repository root:

    cd /Users/dave/.codex/worktrees/351c/bifrost

At kickoff, refresh remote refs and confirm branch state:

    git fetch origin
    git status --short --branch
    git rev-list --left-right --count HEAD...@{upstream}

Run Milestone 0 baseline validation:

    cargo test --test bifrost_lsp_server type_hierarchy --features nlp
    cargo test --test bifrost_lsp_server implementation --features nlp

During implementation milestones, run the focused LSP tests most relevant to the slice:

    cargo test --test bifrost_lsp_server type_hierarchy --features nlp
    cargo test --test bifrost_lsp_server implementation --features nlp
    cargo test --test bifrost_lsp_server type_definition --features nlp

At the final quality gate on this macOS worktree, run:

    cargo test --test bifrost_lsp_server type_hierarchy --features nlp
    cargo test --test bifrost_lsp_server implementation --features nlp
    cargo test --test bifrost_lsp_server type_definition --features nlp
    cargo test --test bifrost_lsp_server call_hierarchy --features nlp
    cargo fmt
    cargo clippy-no-cuda

## Validation and Acceptance

The primary acceptance behavior is LSP-level. Invalid cursor positions return a normal response whose `result` is JSON `null`. The response must not depend on client timeout, server error, or cancellation.

Positive behavior must remain green. `typeHierarchyProvider` and `implementationProvider` must still be advertised by the initialize response. `prepareTypeHierarchy` must still work on type declarations and valid type references. `typeHierarchy/supertypes` and `typeHierarchy/subtypes` must still return existing Java, Python, JavaScript, TypeScript, PHP, C++, Scala, Rust, and Go structural interface results. `textDocument/implementation` must still return descendants for valid type/interface contexts, including Go interface declaration and Go interface method implementation lookup.

Invalid behavior must be covered by focused LSP regressions. `prepareTypeHierarchy` should return `null` on method names, function names, locals, literals, and arbitrary identifiers inside a type body. `textDocument/implementation` should return `null` on ordinary functions, non-interface methods, locals, fields, and unsupported value contexts.

## Idempotence and Recovery

The changes are additive and can be rerun safely. Tests use temporary directories and do not require persistent workspace state. If a milestone test fails after a partial edit, keep the failing code in place, update this ExecPlan with the discovery, and fix forward rather than reverting unrelated user changes.

Stage only files changed for this work, and commit between ExecPlan milestones as requested. Do not push or open a pull request unless explicitly asked.

## Artifacts and Notes

The JSON shape for an invalid cursor response should be:

    {
      "jsonrpc": "2.0",
      "id": 2,
      "result": null
    }

A Java type hierarchy negative fixture should include a class with a method and local:

    class Widget {}
    class Service {
        Widget build() {
            Widget local = new Widget();
            return local;
        }
    }

Putting the cursor on `Service` should prepare type hierarchy for `Service`. Putting the cursor on `Widget` in the return type should prepare hierarchy for `Widget` if the language's type lookup supports that reference. Putting the cursor on `build` or `local` should return `null`.

A Go implementation positive fixture should keep the interface method case:

    type Runner interface { Run() error }
    type Worker struct{}
    func (Worker) Run() error { return nil }

Putting the cursor on `Runner` should return the `Worker` type implementation. Putting the cursor on the interface method `Run` should return `Worker.Run`. Putting the cursor on an ordinary non-interface function or local should return `null`.

## Interfaces and Dependencies

No public LSP capability changes are allowed. `src/lsp/capabilities.rs` must keep both:

    type_hierarchy_provider: Some(TypeHierarchyServerCapability::Simple(true))
    implementation_provider: Some(ImplementationProviderCapability::Simple(true))

No new external dependencies are needed. Any helper added to `get_type`, `get_definition`, or LSP handlers must use existing tree-sitter `Node` APIs, existing analyzer indexes, existing LSP range utilities, and existing diagnostic outcome construction.

At the end of the implementation, `TypeLookupOutcome` should carry enough structured classification for LSP handlers to distinguish broad type-definition targets from narrower type hierarchy and implementation targets. The exact type name may change during implementation, but the semantics must remain explicit and analyzer-owned rather than encoded as handler-level language tables.

## Revision Notes

2026-06-29 / Codex: Created this ExecPlan from issue `#332` and the milestone implementation plan requested by the user. The document records the current handler seams, branch state, no-rebase decision, and review checkpoint protocol before production code changes begin.
