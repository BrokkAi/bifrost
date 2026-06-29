# Tighten LSP Call Hierarchy Prepare Cursor Contexts

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document follows `.agent/PLANS.md` from the repository root. Any contributor who changes this work must update this file so it remains self-contained and accurate.

## Purpose / Big Picture

Bifrost advertises the LSP `textDocument/prepareCallHierarchy` capability so editors can offer call hierarchy actions in supported source files. Before this work, the prepare handler accepted any cursor position inside a callable body by finding the enclosing code unit and promoting it to the nearest function or class. That made right-clicking on a local variable, type reference, field access, or unrelated identifier inside a function misleadingly prepare call hierarchy for the enclosing callable.

After this work, Bifrost still advertises `callHierarchyProvider`, but `textDocument/prepareCallHierarchy` returns a prompt JSON `null` unless the cursor is on a semantically valid call-hierarchy target: a callable declaration identity or a call expression/reference that the analyzer can resolve to a callable declaration. Users can see the behavior by running the focused LSP call hierarchy tests. Invalid cursor positions should complete normally with `result: null`; valid declaration and call-reference positions should still prepare a `CallHierarchyItem`.

## Progress

- [x] (2026-06-29 15:45Z) Confirmed the worktree is clean on `331-tighten-lsp-call-hierarchy-prepare-cursor-contexts`; `HEAD`, `origin/master`, and `origin/331-tighten-lsp-call-hierarchy-prepare-cursor-contexts` all resolve to `fbfe670bf3dc4f73af991b6ff55a9d2d3fc65a18`.
- [x] (2026-06-29 15:48Z) Added this ExecPlan as the living source of truth for issue `#331`.
- [x] (2026-06-29 16:25Z) Implemented Milestone 1 shared prepare gate and Java proof, ran focused validation, completed guided review, accepted two low-risk review fixes, and reran validation.
- [x] (2026-06-29 16:45Z) Added Milestone 2 JS/TS and Rust prepare coverage, ran focused validation, and completed a manual guided-review fallback because the agent pool was at its thread limit.
- [x] (2026-06-29 17:05Z) Added Milestone 3 coverage for Go, C#, C++, Scala, Python, PHP, and Ruby declaration-only behavior, ran focused validation, and completed manual guided review.
- [x] (2026-06-29 17:20Z) Ran the final quality gate, reviewed the accumulated branch diff, and recorded completion.

## Surprises & Discoveries

- Observation: The prepare bug is isolated to `src/lsp/handlers/call_hierarchy.rs`.
  Evidence: `prepare` currently reads the document, computes a cursor byte range, calls `analyzer.enclosing_code_unit`, and immediately promotes that enclosing unit through `nearest_call_hierarchy_unit`.

- Observation: Existing call hierarchy relation code already has structured call-site filtering.
  Evidence: `incoming_calls` filters `UsageHit`s through `is_call_usage_hit`, which delegates to `is_call_reference_range`; `outgoing_calls` collects `call_reference_ranges` and resolves them with `resolve_definition_batch_with_source`.

- Observation: There is an instruction conflict around rebasing at kickoff.
  Evidence: The worktree instructions say to run `git fetch && git rebase` when starting on a new worktree, while the project-doc section says not to rebase unless explicitly asked. This plan records the conflict and follows the project-doc override by fetching but not rebasing.

- Observation: Consolidating the Java prepare regressions requires cursor positions inside identifier tokens, not after them.
  Evidence: A consolidated test initially failed because the positive call-reference request placed the LSP cursor after `target`, making `cursor_byte_range` cover `(` and returning `null`. Moving the cursor inside `target` made the focused call hierarchy tests pass.

- Observation: The shared prepare gate currently parses a call-reference source once to prove call syntax and again through definition lookup to resolve the target.
  Evidence: Guided review flagged the double parse in `is_call_reference_range` plus `resolve_definition_batch_with_source`. The review did not find a correctness bug, and the larger parse-sharing API is left for a later cleanup rather than weakening this milestone with a broad source-size fallback.

- Observation: Milestone 2 did not require production-code changes.
  Evidence: Adding JS/TS and Rust LSP prepare regressions passed against the shared Milestone 1 handler with `cargo test --test bifrost_lsp_server call_hierarchy --features nlp`.

- Observation: Remaining-language call-reference coverage also passed through the shared handler once cursors were placed inside identifier tokens.
  Evidence: Go, C#, C++, Scala, Python, and PHP declaration/call-reference positives plus local-variable negatives passed in `bifrost_lsp_server_call_hierarchy_prepare_filters_remaining_language_contexts`; Ruby declaration prepare passed while Ruby call-reference prepare returned `null`.

- Observation: The final branch diff is limited to the intended implementation, tests, and ExecPlan.
  Evidence: `git diff --stat origin/master...HEAD` listed only `docs/execplan-call-hierarchy-prepare-cursor-contexts.md`, `src/lsp/handlers/call_hierarchy.rs`, and `tests/bifrost_lsp_server.rs`; `git diff --check origin/master...HEAD` produced no output.

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

- Decision: Use one shared LSP position comparator for containment and sorting.
  Rationale: Guided review found that the new containment helper duplicated position ordering already present in range sorting. A shared comparator prevents future drift in LSP position boundary semantics.
  Date/Author: 2026-06-29 / Codex

- Decision: Combine the Java prepare regressions into one server session.
  Rationale: Guided review found unnecessary LSP server startup churn across four closely related single-file Java cases. A single test still verifies local-variable, type-reference, call-reference, and field-access behavior while reducing process/indexing overhead.
  Date/Author: 2026-06-29 / Codex

## Outcomes & Retrospective

Milestone 1 is complete. `prepareCallHierarchy` now uses a shared prepare target helper that accepts callable declaration selection ranges and structured call references that resolve to callable declarations. Java LSP regressions prove local variables, type references, and field accesses return `null`, while a method declaration and call reference still prepare call hierarchy items. Existing Java relation tests for incoming/outgoing calls, overload identity, constructor calls, nested filtering, and non-call type-reference filtering remain green.

Milestone 1 guided-review outcome: security, senior-dev, and architecture reviewers found no blocking issues. Duplication review found repeated LSP position comparison logic, which was fixed with a shared comparator. DevOps review found test process churn, which was fixed by consolidating Java prepare contexts into one LSP server session. DevOps also noted double parsing on call-reference prepare; this is recorded as a future structured parse-sharing cleanup because the current behavior is correct and a broad size fallback would reject valid large-file prepare requests.

Validation completed for Milestone 1:

    cargo test --test bifrost_lsp_server call_hierarchy --features nlp
    result: 7 passed; 0 failed

    cargo fmt --check
    result: passed

Milestone 2 is complete. TypeScript coverage now proves function declarations, direct function calls, constructor calls, local variables, and type references go through the intended prepare outcomes. JavaScript coverage proves method declaration names still prepare. Rust coverage proves free function declarations and function calls prepare, while locals and type references return `null`.

Milestone 2 guided-review outcome: spawning reviewer agents failed because the session had reached its agent thread limit, so the review was completed manually against the test-only diff using the same security, duplication, senior-dev, devops, and architecture lenses. No actionable findings were found.

Validation completed for Milestone 2:

    cargo test --test bifrost_lsp_server call_hierarchy_prepare --features nlp
    result: 3 passed; 0 failed

    cargo test --test bifrost_lsp_server call_hierarchy --features nlp
    result: 9 passed; 0 failed

    cargo fmt --check
    result: passed

Milestone 3 is complete. Go, C#, C++, Scala, Python, and PHP now have LSP prepare coverage proving callable declarations and resolvable call references prepare call hierarchy items while local variables return `null`. Ruby has declaration-name coverage and an explicit `null` assertion for call-reference prepare, matching the current unsupported Ruby definition-lookup boundary.

Milestone 3 guided-review outcome: the review was completed manually against the test-only diff because new reviewer agents were still unavailable. No actionable security, duplication, correctness, devops, or architecture findings were found. The single large integration test is intentional: it avoids spawning one LSP server per language while still making every language-specific assertion explicit.

Validation completed for Milestone 3:

    cargo test --test bifrost_lsp_server call_hierarchy_prepare --features nlp
    result: 4 passed; 0 failed

    cargo test --test bifrost_lsp_server call_hierarchy --features nlp
    result: 10 passed; 0 failed

    cargo fmt --check
    result: passed

Milestone 4 is complete. The final quality gate passed, and the accumulated branch diff was reviewed manually because the agent pool was still unavailable for new reviewer batches. The final review found no unresolved findings. The branch contains four implementation/checkpoint commits before this final ExecPlan update: the initial plan, the Java/shared-handler slice, the JS/TS/Rust coverage slice, and the remaining-language coverage slice.

Final validation completed:

    cargo test --test bifrost_lsp_server call_hierarchy --features nlp
    result: 10 passed; 0 failed

    cargo fmt --check
    result: passed

    cargo clippy-no-cuda
    result: passed

    git diff --check origin/master...HEAD
    result: passed

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

2026-06-29 / Codex: Updated this ExecPlan after Milestone 1 implementation and guided review. The document now records the accepted review fixes, focused validation results, and the deferred parse-sharing cleanup concern.

2026-06-29 / Codex: Updated this ExecPlan after Milestone 2 test coverage. The document now records that JS/TS and Rust behavior passed with the shared handler and that the review checkpoint used the manual fallback path after the agent pool reached its thread limit.

2026-06-29 / Codex: Updated this ExecPlan after Milestone 3 coverage. The document now records the remaining-language test outcomes, including Ruby's declaration-only boundary.

2026-06-29 / Codex: Updated this ExecPlan after the final quality gate and accumulated-diff review. The document now records final validation and completion.
