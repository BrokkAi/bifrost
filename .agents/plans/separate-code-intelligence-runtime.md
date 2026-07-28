# Separate the shared code-intelligence runtime from protocol hosts

This ExecPlan is a living document. It must be maintained according to `.agents/PLANS.md` from the repository root.

## Purpose / Big Picture

Bifrost currently exposes the same code-intelligence operations through two protocol hosts: the Model Context Protocol (MCP) server used by agents and the Language Server Protocol (LSP) server used by editors. The hosts should translate their protocol messages, but query execution, policy evaluation, cancellation, and workspace access should have one clear owner. After this change, the two hosts call a shared code-intelligence runtime for their overlapping RQL query and RQL policy operations. A developer can verify this by running the MCP and LSP integration tests and observing identical query/policy behavior through each protocol.

This is deliberately the first extraction, not a new Cargo workspace. The current CI time is dominated by the full cross-platform test suite, so splitting packages before the interface is proven would add dependency churn without improving an interactive request. The extracted module will be a stable internal dependency boundary that can later become a standalone crate without changing the MCP or LSP public protocol.

## Progress

- [x] (2026-07-28 19:45 SAST) Created branch `dave/separate-code-intelligence-runtime` from `origin/master` and mapped the existing MCP service and LSP request paths.
- [x] (2026-07-28 20:05 SAST) Created and self-assigned GitHub issue #1260 to track this staged extraction.
- [x] (2026-07-28 20:10 SAST) Defined `CodeIntelligenceRuntime` and migrated the direct MCP and LSP RQL query/policy execution calls.
- [ ] Add direct runtime coverage plus MCP and LSP regression coverage, run the policy gate and Rust validation, then perform review.
- [ ] Commit the finished refactor, push the branch, and open a ready-for-review pull request.

## Surprises & Discoveries

- Observation: `SearchToolsService` already owns MCP workspace lifecycle, snapshot freshness, watcher updates, and output rendering, while LSP owns editor overlays and request workers.
  Evidence: `src/searchtools_service.rs` stores a `WorkspaceSession`; `src/lsp/server.rs` stores an `OverlayProject` in `ServerState`.

- Observation: both hosts already execute the same RQL concepts but call lower-level analyzer/policy functions separately.
  Evidence: `SearchToolsService::query_code_result_for_snapshot` invokes structural execution with a registration lease, while `lsp::server::handle_run_rql_query_request` invokes structural execution directly; analogous policy calls are separate.

## Decision Log

- Decision: Extract a shared internal `code_intelligence` runtime module before creating additional Cargo packages, tracked by GitHub issue #1260.
  Rationale: This proves a real dependency direction and preserves current behavior before introducing packaging, feature, and publishing complexity.
  Date/Author: 2026-07-28 / Codex

- Decision: Cover RQL query execution and RQL policy evaluation in this slice; leave LSP document overlays, formatting, diagnostics, MCP JSON-RPC framing, and MCP watcher lifecycle in their protocol hosts.
  Rationale: These two operations have equivalent analyzer semantics and existing end-to-end tests, whereas overlays and protocol framing are necessarily host-specific.
  Date/Author: 2026-07-28 / Codex

## Outcomes & Retrospective

Implementation has not begun. At completion, record the public behavior preserved, the shared API introduced, validation evidence, and the remaining extraction work needed before a multi-crate split.

## Context and Orientation

`src/lib.rs` is the crate root. It currently exposes both analyzer modules and protocol hosts. `src/searchtools_service.rs` implements `SearchToolsService`, the stateful in-process service behind MCP and Python calls. It owns a current analyzer snapshot, filesystem watcher handling, and tool argument decoding. `src/mcp_extended.rs` starts the extended MCP stdio server but does not contain analyzer logic.

`src/lsp/server.rs` owns the LSP stdio event loop and `ServerState`. It must retain ownership of open-document overlays because editor text can differ from the file on disk. The LSP handlers `handle_run_rql_query_request` and `handle_run_rql_policy_request` currently call structural-query and policy functions directly after the LSP layer has decoded the request and created a cancellable worker.

A code-intelligence runtime in this plan is an in-process API that receives an existing `WorkspaceAnalyzer` plus an optional `CancellationToken`. It performs analyzer work but does not read JSON-RPC messages, render MCP text, mutate LSP overlays, or own background watchers. A protocol host remains responsible for those concerns.

## Plan of Work

First, create `src/code_intelligence.rs` and declare it from `src/lib.rs`. Define `CodeIntelligenceRuntime<'a>` to borrow a `WorkspaceAnalyzer` and optionally a cancellation token. Give it typed methods for executing a parsed `CodeQuery` and for evaluating RQL policy inputs/source. Keep method inputs typed rather than accepting protocol JSON. The structural-query method must preserve the existing execution limits and cancellation behavior. The policy methods must preserve the caller-supplied policy root, source identity or inputs, evaluation options, and optional cancellation token.

Next, migrate `src/searchtools_service.rs`. Its MCP-specific responsibilities remain: decode and validate `serde_json::Value`, obtain a consistent `WorkspaceQueryScope`, coordinate typestate registration leases, finish snapshot accounting, and render a `ToolOutput`. Replace its direct structural-query and policy evaluator calls with the shared runtime after it has prepared the typed request. The registration-lease path belongs in the runtime API because it affects query semantics rather than MCP rendering.

Then migrate `src/lsp/server.rs`. Keep parsing LSP params, URI/path validation, progress reporting, worker ownership, response formatting, and cancellation-to-LSP-error translation in the server. Replace direct structural-query and policy evaluator calls inside the worker closures with `CodeIntelligenceRuntime`. The runtime must be constructed from the worker's `WorkspaceAnalyzer`, preserving the LSP overlay-aware project held by that analyzer.

Add a behavior-focused test in the new runtime module or an existing focused integration suite that executes a simple RQL query with a shared runtime over an inline project. Keep the established MCP and LSP integration tests as end-to-end proof that protocol responses stay stable. Add a regression assertion where necessary to prove cancellation is passed through, rather than merely testing the new type's constructor.

Finally, update this plan with actual evidence, run formatting, the targeted runtime/MCP/LSP tests, the repository policy gate, and the required all-feature Clippy command. Review the diff for dependency direction: `code_intelligence` may depend on analyzer and cancellation modules, but it must not depend on `lsp`, `mcp_*`, MCP rendering, or JSON-RPC types. Commit the implementation and plan together with a multiline message, push the branch, and open a non-draft PR explaining that this is an internal extraction that enables a future workspace split.

## Concrete Steps

Work from `/Users/dave/.codex/worktrees/5d4b/bifrost`.

1. Inspect the current direct execution calls with:

       rg -n 'execute_workspace_request|evaluate_policy_(source|inputs)_with_analyzer' src/searchtools_service.rs src/lsp/server.rs

2. Add the runtime module, migrate both hosts, and format it with:

       cargo fmt --all

3. Run focused behavior tests in isolated targets:

       RUSTC=/opt/homebrew/bin/rustc scripts/with-isolated-cargo-target.sh cargo test --test bifrost_lsp_server run_rql --quiet
       RUSTC=/opt/homebrew/bin/rustc scripts/with-isolated-cargo-target.sh cargo test --test bifrost_mcp_server run_policy --quiet

   The focused tests must pass with no output-contract changes other than intentionally added runtime coverage.

4. Run the project policy selection through the installed policy-checking skill when available, using the `bifrost.code-smells` pack and each executable repository policy root. Treat a `finding` or `unreliable` status as a validation failure to investigate before shipping.

5. Run the Rust gate:

       RUSTC=/opt/homebrew/bin/rustc scripts/with-isolated-cargo-target.sh cargo clippy --all-targets --all-features -- -D warnings

6. Check the finished diff, commit only files changed for this refactor, push `dave/separate-code-intelligence-runtime`, and create a ready-for-review PR.

## Validation and Acceptance

Acceptance is behavioral. An LSP `bifrost/runRqlQuery` request against an editor workspace must return the same structural matches as before and still honour cancellation. MCP `query_code` and `run_policy` calls must retain their current structured results and exit/status semantics. The shared runtime must be the sole caller of the low-level RQL query/policy execution functions for those paths, proven by source search and review. The targeted integration tests, policy gate, formatter, and all-feature Clippy gate must pass.

## Idempotence and Recovery

The module extraction is additive until callers are migrated, so an interrupted edit can be resumed by completing the migration before deleting imports. The isolated Cargo helper removes its target directory on exit; do not set a manual `CARGO_TARGET_DIR`. If a rebase is required before publishing, replay the extraction without changing observable protocol behavior. Do not remove LSP overlays or MCP watcher state as part of this plan.

## Artifacts and Notes

Expected focused test evidence resembles:

    running 1 test
    .
    test result: ok. 1 passed; 0 failed

The key review invariant is dependency direction:

    lsp/server.rs  ─┐
                    ├─> code_intelligence.rs ─> analyzer + policy engine
    searchtools_service.rs ─┘

Neither the runtime nor analyzer modules may import `lsp`, `mcp_extended`, or MCP rendering code.

## Interfaces and Dependencies

In `src/code_intelligence.rs`, define a public internal-facing API with this shape, adapting exact result names from the existing analyzer modules:

    pub struct CodeIntelligenceRuntime<'a> {
        workspace: &'a WorkspaceAnalyzer,
        cancellation: Option<&'a CancellationToken>,
    }

    impl<'a> CodeIntelligenceRuntime<'a> {
        pub fn new(
            workspace: &'a WorkspaceAnalyzer,
            cancellation: Option<&'a CancellationToken>,
        ) -> Self;

        pub fn execute_query(
            &self,
            query: &CodeQuery,
            limits: CodeQueryExecutionLimits,
        ) -> CodeQueryResponse;

        // Provide typed policy-input and policy-source methods matching the
        // existing evaluator inputs; do not accept JSON or protocol objects.
    }

If preserving the MCP typestate registration lease requires an additional typed query-context argument, make that context a runtime type defined in `code_intelligence.rs`. It must not expose an MCP-specific name or renderer.

Revision note (2026-07-28): created after source inspection. The plan explicitly limits this PR to a tested internal runtime extraction, so a later Cargo workspace split has an API to move rather than a speculative package boundary.

Revision note (2026-07-28): issue #1260 was created and self-assigned before implementation continued. The first implementation slice routes the existing typed RQL query and policy calls through `CodeIntelligenceRuntime`; validation is still in progress.
