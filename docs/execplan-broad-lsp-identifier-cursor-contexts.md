# Tighten Broad LSP Identifier Cursor Contexts

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document follows `.agent/PLANS.md` from the repository root. Any contributor who changes this work must update this file so it remains self-contained and accurate. This plan also follows the repository `AGENTS.md` expectations: keep the branch already checked out, do not create or switch branches, avoid parser-replacing text heuristics, prefer structured analyzer data, run focused validation before expensive checks, run guided review at milestone checkpoints, and commit directly on the current branch between milestones.

## Purpose / Big Picture

Bifrost advertises broad LSP editor features such as "Go to Definition", "Find References", "Document Highlight", and "Hover". These features are useful on many declarations and references, but they become confusing when a user right-clicks a word in a comment, a string literal, a keyword, an unresolved local, or another token that is not a meaningful analyzer target. Before this work, the handlers for those broad endpoints can treat any raw identifier-like text under the cursor as a global symbol name and search the workspace for matching declarations.

After this work, Bifrost will still advertise the same LSP capabilities, but inappropriate cursor contexts will return prompt `null` or empty results instead of navigating to or scanning usages for unrelated workspace symbols. A user can see the result by running the focused LSP tests and by opening a file that contains both `// target` and `void target() {}`: requesting definition, hover, references, or document highlights on the comment word `target` should complete normally with no result, while requesting those features on the real method name or a real reference should still work.

## Progress

- [x] (2026-06-29 12:53Z) Created this ExecPlan from the issue `#333` audit and recorded the required guided-review, AGENTS.md audit, validation, and milestone-commit workflow.
- [x] (2026-06-29 13:02Z) Confirmed branch/upstream state after kickoff fetch and recorded exact commit IDs in `Surprises & Discoveries`.
- [x] (2026-06-29 13:06Z) Milestone 1 complete: added independent invalid-context LSP regressions without production-code changes, ran focused tests to prove the bug, ran guided review on the test-only diff, addressed accepted review findings, and prepared the milestone commit.
- [ ] Milestone 2: introduce a shared structured cursor-target resolver for broad identifier endpoints, wire `definition` and `hover`, validate, run guided review and AGENTS.md audit, update this plan, and commit.
- [ ] Milestone 3: wire `references` and `documentHighlight` to the shared resolver while preserving declaration/reference behavior and overlay awareness, validate, run guided review and AGENTS.md audit, update this plan, and commit.
- [ ] Milestone 4: broaden regressions across comments, literals, keywords, unresolved locals, ambiguous short names, and open-document overlays; run final quality gate, final guided review, update this plan, and commit.

## Surprises & Discoveries

- Observation: At audit kickoff, the relevant broad handlers all used raw identifier extraction plus global short-name lookup rather than structured cursor-context resolution.
  Evidence: `src/lsp/handlers/definition.rs`, `src/lsp/handlers/references.rs`, `src/lsp/handlers/document_highlight.rs`, and `src/lsp/handlers/hover.rs` call `identifier_at_offset` or `identifier_span_at_offset`, then call `resolve_identifier_candidates` or `resolve_first_identifier_candidate` from `src/lsp/handlers/util.rs`.

- Observation: The branch is already named for issue `#333` and has upstream tracking.
  Evidence: `git status --short --branch` printed `## 333-audit-broad-lsp-identifier-endpoints-for-inappropriate-cursor-contexts...origin/333-audit-broad-lsp-identifier-endpoints-for-inappropriate-cursor-contexts`.

- Observation: The project has recent LSP cursor-context ExecPlans that use the same milestone pattern requested here.
  Evidence: `docs/execplan-type-definition-cursor-contexts.md` and `docs/execplan-call-hierarchy-prepare-cursor-contexts.md` both keep provider advertisements unchanged, add LSP regressions, run focused tests, run guided-review checkpoints, and commit between milestones.

- Observation: `origin/master` advanced after the initial plan commit, while the issue branch upstream stayed at the prior master commit.
  Evidence: After `git fetch`, `git rev-parse HEAD origin/master origin/333-audit-broad-lsp-identifier-endpoints-for-inappropriate-cursor-contexts` printed `7a842496243f92952cab6fe8fefc13791a37e080`, `e3fc1367b41c22ede25934798349d0e3cc443fea`, and `f1e2cd37fc80877a09578fe685043e3de92ed8c3`. Per project instructions, no rebase was run.

- Observation: The first Milestone 1 regression shape was too broad.
  Evidence: Guided review found that one combined test name matched all four endpoint filters but failed at the first definition assertion, so `hover`, `references`, and `document_highlight` filter failures did not independently prove those endpoints. The review also found that the expected-failing assertion ran before LSP shutdown.

- Observation: The revised Milestone 1 tests independently reproduce the issue for all four broad endpoints before production changes.
  Evidence: `cargo test --test bifrost_lsp_server definition --features nlp` failed only `bifrost_lsp_server_definition_ignores_comment_token` because `// target` returned the real method definition. `cargo test --test bifrost_lsp_server hover --features nlp` failed only `bifrost_lsp_server_hover_ignores_comment_token` because the comment token returned a Java hover for `void target()`. `cargo test --test bifrost_lsp_server references --features nlp` failed only `bifrost_lsp_server_references_ignore_comment_token` because the comment token returned declaration and call-reference locations. `cargo test --test bifrost_lsp_server document_highlight --features nlp` failed only `bifrost_lsp_server_document_highlight_ignores_comment_token` because the comment token returned declaration and read highlights.

## Decision Log

- Decision: Keep all provider advertisements unchanged.
  Rationale: Issue `#333` explicitly asks to preserve the current capabilities and only change request behavior for inappropriate cursor contexts.
  Date/Author: 2026-06-29 / Codex

- Decision: Build a shared structured cursor-target resolver for the broad identifier endpoints instead of adding endpoint-local filters.
  Rationale: The failure mode is shared by definition, references, documentHighlight, and hover. A common resolver keeps comment/literal/keyword/unresolved-local behavior consistent and avoids duplicating language-specific checks in each handler.
  Date/Author: 2026-06-29 / Codex

- Decision: Use existing tree-sitter-backed analyzer helpers, declaration selection ranges, and definition/type lookup infrastructure rather than regexes or source-text mini parsers.
  Rationale: `AGENTS.md` explicitly forbids replacing parser support with string splitting, regexes, or delimiter scanning. This work is about cursor semantics, so structured syntax and analyzer ranges must be the source of truth.
  Date/Author: 2026-06-29 / Codex

- Decision: Run `brokk:brokk-guided-review` after each implementation milestone and audit findings against AGENTS.md before committing.
  Rationale: The user requested guided-review checkpoints, AGENTS.md compliance auditing, and commits between milestones. Review findings must be evaluated against the repository's structured-analysis design constraints before accepting fixes.
  Date/Author: 2026-06-29 / Codex

## Outcomes & Retrospective

No implementation milestone is complete yet. This initial plan converts the issue audit into an executable workflow and records the expected review, validation, and commit cadence before code changes begin.

Milestone 1 is complete. The test-only regressions now prove that a comment token matching a real method name can resolve through each broad endpoint: definition, hover, references, and documentHighlight. Each regression also exercises valid declaration behavior first so future fixes must preserve useful broad endpoint behavior. The focused failures are expected until Milestones 2 and 3 replace the raw string-based cursor path.

Milestone 1 guided-review outcome: security found no issues. DevOps, senior-dev, and architecture all flagged that the original combined regression did not independently prove each endpoint and could mislead focused milestone validation. DevOps also flagged that the expected-failing assertion could panic before LSP shutdown. Duplication review flagged that the new generic request helper should be reused by existing typeDefinition and implementation helpers. All findings were accepted and fixed: the regression is split into four endpoint-specific tests, each test collects responses then calls `shutdown_lsp` before asserting the expected failure, and existing position-based helpers now delegate to `text_document_position_response`.

## Context and Orientation

The Language Server Protocol, or LSP, is the protocol editors use to ask a language server for features such as go-to-definition, references, hover text, and document highlights. In this repository, LSP requests are handled under `src/lsp/handlers/`. The four broad endpoints in scope are:

`src/lsp/handlers/definition.rs`, which handles `textDocument/definition` and returns declaration locations.

`src/lsp/handlers/references.rs`, which handles `textDocument/references` and returns locations where a symbol is used.

`src/lsp/handlers/document_highlight.rs`, which handles `textDocument/documentHighlight` and returns ranges to highlight in the current file.

`src/lsp/handlers/hover.rs`, which handles `textDocument/hover` and returns a skeleton or signature snippet for the symbol under the cursor.

All four handlers currently read the requested document through `read_document_for_uri` from `src/lsp/handlers/util.rs`. That is important because `read_document_for_uri` uses the project abstraction and therefore respects LSP open-document overlays, meaning unsaved editor content can drive request behavior. This overlay-aware behavior must remain intact.

The current shared helper `resolve_identifier_candidates` in `src/lsp/handlers/util.rs` accepts only a bare identifier string. It first tries `analyzer.get_definitions(identifier)` and then falls back to `analyzer.search_definitions` with a word-boundary pattern. This string-only API cannot distinguish a real symbol reference from the same text inside a comment or literal.

The repository already has more structured cursor-resolution patterns. `src/symbol_rename.rs` resolves rename targets from an exact file and byte offset before scanning usages. `src/lsp/handlers/call_hierarchy.rs` accepts callable declaration selections and structured call references, not arbitrary words inside a function body. `src/lsp/handlers/type_target.rs` uses analyzer-owned type lookup and eligibility filters for type-definition, type-hierarchy, and implementation. This plan should reuse that style.

The implementation must not use regexes, string splitting, or delimiter scanning to decide whether the cursor is on a real symbol. A structured cursor target means a target proven from one of these sources: a declaration selection range from analyzer data, a tree-sitter node that language-specific definition lookup accepts as a real reference, an import binder, or an existing resolver helper that already works from parsed syntax.

## Plan of Work

Milestone 1 adds regression tests first. Add tests in `tests/bifrost_lsp_server.rs` near the existing broad endpoint tests. Use small temporary projects and the existing LSP test helpers where possible. The first fixture should include a declaration and the same word in a comment, for example `class CommentTargets { // target` followed by `void target() {}`. Assert that definition and hover on the comment token return JSON `null`, that references on the comment token returns `null` or an empty array, and that documentHighlight on the comment token returns `null` or an empty array. Also assert that the same endpoint on the real declaration or a real reference still returns a useful result. Run focused tests before changing production code so the failures prove the current bug.

Milestone 2 introduces a shared structured resolver for broad symbol targets. The likely home is `src/lsp/handlers/util.rs` or a new small module under `src/lsp/handlers/` if the type grows too large. The resolver should accept the workspace analyzer, project, URI, LSP position, and an option that says whether declarations are allowed. It should read overlay-aware content, compute the byte offset, identify the selected token range, and then prove that the cursor is either on a real declaration selection or on a structured reference that definition lookup resolves. For declaration selection, use analyzer ranges plus `identifier_selection_range` or `lsp_symbol_parts` style selection logic. For references, prefer `resolve_definition_batch_with_source` from `src/analyzer/usages/get_definition/mod.rs` so language-specific resolvers validate the syntax node before returning candidates. Wire `definition` and `hover` through this resolver first because they only need resolved declaration candidates and direct response formatting.

Milestone 3 wires `references` and `documentHighlight` through the same resolver. These endpoints must not call `UsageFinder` unless the cursor target has already been proven meaningful. Preserve `params.context.include_declaration` for references. Preserve documentHighlight's current-file filter and its declaration highlight behavior, but only after the cursor target is valid. This milestone must explicitly verify that a comment token with the same name as a same-file method does not produce a declaration highlight.

Milestone 4 broadens coverage and finalizes quality. Add invalid-context coverage for literals, keywords, unresolved locals that share a short name with a workspace declaration, ambiguous short names from different packages or files, and didOpen/didChange overlays changing which identifier is selected. Keep tests focused and avoid large reusable fixture directories unless a case genuinely needs them. Run the final validation bundle and a final guided review over the accumulated branch diff.

After every milestone, update `Progress`, `Surprises & Discoveries`, `Decision Log`, `Outcomes & Retrospective`, and `Revision Notes`. Then run `brokk:brokk-guided-review` in uncommitted-changes mode for the milestone diff. If reviewer agents are unavailable, perform the documented manual fallback with the same five lenses: security, duplication, senior-dev intent, devops, and architecture. Audit every accepted finding against AGENTS.md before editing; reject recommendations that add regex/text-search fallbacks, parser-replacing mini parsers, broad fallback behavior, unnecessary cloning in hot paths, or unrelated scope. Once validation and review findings are resolved, stage only the milestone files and commit directly on the current branch.

## Concrete Steps

Work from the repository root:

    cd /Users/dave/.codex/worktrees/556b/bifrost

At kickoff, refresh remote refs and confirm the current branch and base state:

    git fetch
    git status --short --branch
    git rev-parse HEAD origin/master origin/333-audit-broad-lsp-identifier-endpoints-for-inappropriate-cursor-contexts

Milestone 1 test-first commands:

    cargo test --test bifrost_lsp_server definition --features nlp
    cargo test --test bifrost_lsp_server hover --features nlp
    cargo test --test bifrost_lsp_server references --features nlp
    cargo test --test bifrost_lsp_server document_highlight --features nlp
    cargo fmt --check

Milestones 2 and 3 focused validation commands:

    cargo test --test bifrost_lsp_server definition --features nlp
    cargo test --test bifrost_lsp_server hover --features nlp
    cargo test --test bifrost_lsp_server references --features nlp
    cargo test --test bifrost_lsp_server document_highlight --features nlp
    cargo fmt --check

If a milestone touches definition lookup resolver behavior outside the LSP handlers, also run the relevant focused usage or definition tests for the language touched. For example:

    cargo test --test get_definition_test --features nlp
    cargo test --test usages_java_graph_test --features nlp
    cargo test --test usages_js_ts_graph_test --features nlp

At each guided-review checkpoint, gather the uncommitted milestone diff:

    git diff
    git diff --staged

Run `brokk:brokk-guided-review` in uncommitted-changes mode. Include this scoping instruction in the review prompt: only report issues introduced or worsened by the milestone diff, and also check whether the diff violates AGENTS.md constraints such as adding regex or text-search fallbacks, parser-replacing mini parsers, broad fallback behavior, or unrelated refactors. Walk findings, queue or apply accepted fixes, rerun focused validation, update this plan, then commit only the files changed for the milestone.

Commit commands must stage explicit files only. For example, after Milestone 1:

    git status --short
    git add docs/execplan-broad-lsp-identifier-cursor-contexts.md tests/bifrost_lsp_server.rs
    git commit -m "Add broad LSP cursor-context regression plan and tests"

At the final quality gate on this macOS worktree, avoid `--all-features` because it enables CUDA-dependent `nlp-gpu`. Run:

    cargo test --test bifrost_lsp_server definition --features nlp
    cargo test --test bifrost_lsp_server hover --features nlp
    cargo test --test bifrost_lsp_server references --features nlp
    cargo test --test bifrost_lsp_server document_highlight --features nlp
    cargo fmt --check
    cargo clippy-no-cuda
    git diff --check origin/master...HEAD

## Validation and Acceptance

The primary acceptance behavior is LSP-level. Invalid cursor positions must return a normal LSP response with JSON `null` or an empty array, depending on the endpoint's existing response shape. The server must not hang, perform a misleading workspace-wide usage scan, or return a declaration just because the selected word matches a symbol somewhere else.

For `textDocument/definition`, a comment token such as `target` in `// target` must return `result: null`. A real declaration or real reference to `target` must still return the declaration location.

For `textDocument/hover`, the same comment token must return `result: null`. A real declaration or real reference must still return markdown hover content with the existing language fence and skeleton behavior.

For `textDocument/references`, the same comment token must return `null` or an empty array and must not call into workspace usage scanning for an unrelated declaration. A real declaration or real reference must still return usage locations and must still respect `includeDeclaration`.

For `textDocument/documentHighlight`, the same comment token must return `null` or an empty array. It must not add the same-file declaration highlight for a method with the same name unless the cursor target is valid. Valid declaration and reference positions must still return current-file highlights only.

Overlay behavior must remain intact. If didOpen or didChange changes the document text under the cursor, the selected identifier and response body must come from the overlay rather than stale disk content.

Provider advertisements must remain unchanged. The initialize response must still advertise `definitionProvider`, `referencesProvider`, `documentHighlightProvider`, and `hoverProvider` as it does before this work.

## Idempotence and Recovery

The tests should use temporary directories and can be run repeatedly. If a focused test fails before production changes in Milestone 1, keep that failing test because it is evidence of the bug. If a later implementation leaves tests failing, update this plan with the failure and fix forward rather than reverting unrelated user changes.

Do not create or switch branches. Do not rebase unless the user explicitly asks; if worktree instructions and project instructions conflict, follow the project instruction that says not to rebase unless asked. Stage only files changed for this work. Do not use `git add -A`. Commit between milestones as required by this plan and the user's request. Do not push or open a pull request unless explicitly asked.

If `brokk:brokk-guided-review` cannot spawn agents because the agent pool is unavailable, perform the manual fallback described in the skill: review the milestone diff sequentially through the security, duplication, senior-dev, devops, and architecture lenses, then record the fallback and any findings in this plan before committing.

## Artifacts and Notes

The simplest Java repro source for the first regression should look like this:

    class CommentTargets {
        // target
        void target() {}
        void caller() {
            target();
        }
    }

For a request on the comment token `target`, the desired response shape for definition and hover is:

    {
      "jsonrpc": "2.0",
      "id": 2,
      "result": null
    }

For references and documentHighlight, either `result: null` or `result: []` is acceptable if it matches the handler's existing convention for no meaningful target. The important behavior is that the request completes promptly and does not report the real method or its usages from the comment position.

## Interfaces and Dependencies

No new external dependencies are needed. Use existing modules and APIs:

`crate::lsp::handlers::util::read_document_for_uri` must remain the document-reading entry point so overlays work.

`crate::lsp::conversion::position_to_byte_offset` must remain the LSP-position-to-byte-offset conversion entry point.

`crate::analyzer::usages::get_definition::DefinitionLookupRequest` and `resolve_definition_batch_with_source` should be used for structured reference resolution when possible.

`crate::lsp::handlers::util::identifier_selection_range` or the document-symbol selection-range logic should be used for declaration-name selection checks.

`crate::analyzer::usages::UsageFinder` must only run after the cursor target is proven meaningful.

The shared resolver should expose a small internal API that lets endpoint handlers request candidates without knowing language-specific syntax. A concrete shape can be adjusted during implementation, but it should carry at least the selected file, overlay content, line starts, selected byte range, selected identifier text, and resolved `CodeUnit` candidates. It should not expose a string-only global lookup as the main success path.

## Revision Notes

2026-06-29 / Codex: Created this ExecPlan from the issue `#333` audit and the user's requested workflow. The plan records the broad LSP handler failure mode, the no-mini-parser constraint from AGENTS.md, the guided-review checkpoints, and the requirement to commit between milestones before code changes begin.

2026-06-29 / Codex: Updated this ExecPlan after adding the Milestone 1 test-only regression. The document now records refreshed branch evidence and the focused failing LSP commands that prove the current broad handlers resolve comment tokens through global identifier lookup.

2026-06-29 / Codex: Updated this ExecPlan after guided review of the Milestone 1 test-only diff. The document now records the accepted review findings, the split endpoint-specific regressions, teardown-before-assertion shape, and revised independent focused-test failures.
