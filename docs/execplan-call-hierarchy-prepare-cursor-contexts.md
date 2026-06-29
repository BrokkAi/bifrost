# Tighten LSP Call Hierarchy Prepare Cursor Contexts

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document follows `.agent/PLANS.md` from the repository root. Any contributor who changes this work must update this file so it remains self-contained and accurate.

## Purpose / Big Picture

Bifrost advertises the LSP `textDocument/prepareCallHierarchy` capability so editors can offer call hierarchy actions in supported source files. Before this work, the prepare handler accepted any cursor position inside a callable body by finding the enclosing code unit and promoting it to the nearest function or class. That made right-clicking on a local variable, type reference, field access, or unrelated identifier inside a function misleadingly prepare call hierarchy for the enclosing callable.

After this work, Bifrost still advertises `callHierarchyProvider`, but `textDocument/prepareCallHierarchy` returns a prompt JSON `null` unless the cursor is on a semantically valid call-hierarchy target: a callable declaration identity or a call expression/reference that the analyzer can resolve to a callable declaration. Users can see the behavior by running the focused LSP call hierarchy tests. Invalid cursor positions should complete normally with `result: null`; valid declaration and call-reference positions should still prepare a `CallHierarchyItem`.

## Progress

- [x] (2026-06-29 15:45Z) Confirmed the worktree is clean on `331-tighten-lsp-call-hierarchy-prepare-cursor-contexts`; `HEAD`, `origin/master`, and `origin/331-tighten-lsp-call-hierarchy-prepare-cursor-contexts` all resolve to `fbfe670bf3dc4f73af991b6ff55a9d2d3fc65a18`.
- [x] (2026-06-29 15:48Z) Added this ExecPlan as the living source of truth for issue `#331`.
- [ ] Milestone 1: shared prepare gate plus Java proof.
- [ ] Milestone 2: JS/TS and Rust coverage.
- [ ] Milestone 3: Go, C#, C++, Scala, Python, PHP, and Ruby declaration-scope documentation.
- [ ] Milestone 4: final quality gate and final guided review.

## Surprises & Discoveries

- Observation: The prepare bug is isolated to `src/lsp/handlers/call_hierarchy.rs`.
  Evidence: `prepare` currently reads the document, computes a cursor byte range, calls `analyzer.enclosing_code_unit`, and immediately promotes that enclosing unit through `nearest_call_hierarchy_unit`.

- Observation: Existing call hierarchy relation code already has structured call-site filtering.
  Evidence: `incoming_calls` filters `UsageHit`s through `is_call_usage_hit`, which delegates to `is_call_reference_range`; `outgoing_calls` collects `call_reference_ranges` and resolves them with `resolve_definition_batch_with_source`.

- Observation: There is an instruction conflict around rebasing at kickoff.
  Evidence: The worktree instructions say to run `git fetch && git rebase` when starting on a new worktree, while the project-doc section says not to rebase unless explicitly asked. This plan records the conflict and follows the project-doc override by fetching but not rebasing.

## Decision Log

- Decision: Keep `callHierarchyProvider` advertised globally.
  Rationale: The issue explicitly requires preserving the advertised capability and narrowing prepare eligibility instead of hiding the feature from clients.
  Date/Author: 2026-06-29 / Codex

- Decision: Tighten `prepareCallHierarchy` in the LSP handler by reusing analyzer-owned structured helpers.
  Rationale: The handler already owns LSP request shaping and item creation, while `call_reference_ranges`, `is_call_reference_range`, and definition lookup already encode language-specific call/reference semantics without regex or text mini-parsers.
  Date/Author: 2026-06-29 / Codex

- Decision: Fetch remote refs but do not rebase at kickoff.
  Rationale: `git fetch` is required by the worktree instructions and verified that local refs are aligned. The project-doc section explicitly says not to rebase unless asked, so no rebase was run.
  Date/Author: 2026-06-29 / Codex

## Outcomes & Retrospective

No implementation milestones are complete yet. This ExecPlan records the intended behavior, current handler seam, and validation workflow before code changes begin.

## Context and Orientation

`textDocument/prepareCallHierarchy` is routed in `src/lsp/server.rs` to `src/lsp/handlers/call_hierarchy.rs`. The handler reads the current document from disk or the LSP open-document overlay, converts the LSP position to a byte offset, and builds a `CallHierarchyItem` for a `CodeUnit`. A `CodeUnit` is the analyzer's declaration model from `src/analyzer/model.rs`; its kind can be `Class`, `Function`, `Field`, `Module`, or `Macro`.

Call hierarchy prepare is different from relation computation. Prepare decides whether the cursor position is an eligible starting point and returns zero or one `CallHierarchyItem`. Incoming and outgoing relation handlers then use that item to compute callers and callees. This issue is about the prepare eligibility gate only; incoming/outgoing behavior such as overload identity, constructor calls, nested-call filtering, and non-call type-reference filtering must remain intact.

A callable declaration identity means the cursor is on the name/selection range of a class, constructor, method, function, or other non-synthetic `CodeUnitType::Class` or `CodeUnitType::Function` that `is_call_hierarchy_unit` already accepts. A call reference means a source token that is syntactically part of a call expression, such as `target` in `target()` or `Service` in `new Service()`, and whose definition lookup resolves to an accepted callable declaration.

Do not solve this by disabling `callHierarchyProvider`, by treating every identifier inside a function as eligible, by adding regexes, or by splitting source text to infer syntax. Cursor classification must come from analyzer declaration ranges, LSP symbol selection ranges, tree-sitter call-reference helpers, or definition lookup.

## Plan of Work

First, update `src/lsp/handlers/call_hierarchy.rs`. Replace the current `enclosing_code_unit` promotion in `prepare` with a helper that attempts declaration-name eligibility first and call-reference eligibility second. Declaration eligibility should find the nearest accepted call-hierarchy unit but only return it when the cursor byte range overlaps the item's LSP selection range converted from analyzer data. Call-reference eligibility should use `is_call_reference_range` for the selected token, then call `resolve_definition_batch_with_source` for that token range and accept only `DefinitionLookupStatus::Resolved` outcomes whose resolved definitions can be promoted with `nearest_call_hierarchy_unit`.

Second, add null-capable LSP test helpers in `tests/bifrost_lsp_server.rs`. The existing `prepare_call_hierarchy` helper assumes a one-item array, so add a companion that returns the raw response result and lets tests assert `is_null()`.

Third, implement milestone tests. Milestone 1 proves Java behavior for local variables, type references, valid method declarations, valid method calls, and non-call field access. Milestone 2 extends the same behavior to JavaScript, TypeScript, and Rust. Milestone 3 extends coverage to Go, C#, C++, Scala, Python, and PHP where definition lookup can prove call targets. Ruby call-reference prepare remains unsupported because Ruby definition lookup currently reports unsupported language; Ruby declaration-name prepare may remain allowed when analyzer declarations prove the cursor is on a callable declaration name.

After each implementation milestone, update this document's living sections, run focused validation, run `brokk:brokk-guided-review` in uncommitted-changes mode for that milestone diff, address accepted findings, rerun focused validation, and commit only files changed for the milestone.

## Concrete Steps

Work from the repository root:

    cd /Users/dave/.codex/worktrees/6831/bifrost

At kickoff, refresh remote refs and confirm branch state:

    git fetch
    git status --short --branch
    git rev-parse HEAD origin/master origin/331-tighten-lsp-call-hierarchy-prepare-cursor-contexts

During implementation, run the focused LSP call hierarchy tests after each code milestone:

    cargo test --test bifrost_lsp_server call_hierarchy --features nlp

When resolver behavior is touched directly, also run the relevant focused resolver or usage tests if practical.

Run formatting before review checkpoints:

    cargo fmt --check

At the final quality gate on this macOS worktree, run:

    cargo test --test bifrost_lsp_server call_hierarchy --features nlp
    cargo fmt --check
    cargo clippy-no-cuda

## Validation and Acceptance

The primary acceptance behavior is LSP-level. Requests on invalid cursor positions return a normal response whose `result` is JSON `null`. The response must not depend on client timeout, server error, or cancellation.

Positive behavior must remain green. A request on a callable declaration name still returns a single `CallHierarchyItem`. A request on a call expression whose target resolves to an accepted callable still returns the callee item. Existing incoming/outgoing call hierarchy tests for overload identity, constructor calls, nested function/type filtering, and non-call type-reference filtering must still pass. The initialize response must still advertise `callHierarchyProvider: true`.

The focused validation command is:

    cargo test --test bifrost_lsp_server call_hierarchy --features nlp

Expected final result: all call hierarchy tests pass, including the new prepare null regressions and existing relation tests.

## Idempotence and Recovery

The changes are additive and can be rerun safely. Tests use temporary directories and do not require persistent workspace state. If a milestone test fails after a partial edit, keep the failing code in place, update this ExecPlan with the discovery, and fix forward rather than reverting unrelated user changes.

Do not create or switch branches. Stage only files changed for this work, and commit between ExecPlan milestones as required by the requested workflow. Do not push or open a pull request unless explicitly asked.

## Artifacts and Notes

The JSON shape for an invalid cursor response should be:

    {
      "jsonrpc": "2.0",
      "id": 2,
      "result": null
    }

The Java local-variable regression source should include a valid method with both a local variable and a call:

    class Service { static void target() {} }
    class Caller {
        void helper() {
            int local = 1;
            Service.target();
        }
    }

Putting the cursor on `local` should return `null`. Putting the cursor on `helper` should prepare `helper`. Putting the cursor on `target` in `Service.target()` should prepare `target`.

## Interfaces and Dependencies

No public LSP capability changes are allowed. The initialize result must continue to include:

    "callHierarchyProvider": true

No new external dependencies are needed. Any helper added to call hierarchy prepare must use existing analyzer APIs and existing tree-sitter-backed helper functions. The prepare helper should continue to return `Option<Vec<CallHierarchyItem>>` so unsupported files, invalid URIs, and invalid cursor contexts serialize through the existing LSP response path as `null`.

## Revision Notes

2026-06-29 / Codex: Created this ExecPlan from issue `#331` and the implementation plan requested by the user. The document records the current prepare bug, the no-mini-parser constraint, the branch/rebase decision, and the milestone review workflow before code changes begin.
