# Add cancellable LSP reference requests with request-scoped progress

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with `.agents/PLANS.md` from the repository root.

## Purpose / Big Picture

Bifrost currently handles almost every Language Server Protocol (LSP) request synchronously on the thread that reads client messages. If a references search takes a long time, the server cannot read the client's `$/cancelRequest` notification until the search has already finished. Formatting is the sole exception because it has a formatter-specific worker and cancellation registry.

After this work, `textDocument/references` will run on a bounded worker while the main LSP loop remains responsive. A client can cancel an active references request and receive the LSP `RequestCancelled` error code `-32800`. When the request includes a client-owned `workDoneToken`, Bifrost will send an indeterminate begin/report/end sequence on `$/progress`; requests without a token will emit no request progress. The worker registry and cancellation token will be reusable by later issue #578 milestones, but this plan deliberately does not migrate workspace symbols, diagnostics, hierarchy, semantic tokens, or partial-result streaming.

The behavior is observable through the integration tests in `tests/bifrost_lsp_server.rs`: initialization advertises reference work-done progress, an ordinary references request still returns the same locations, a token-bearing request produces the expected progress lifecycle, and a canceled active request receives `-32800`. Unit tests prove bounded worker cleanup and analyzer-loop cancellation without timing-dependent sleeps.

## Progress

- [x] (2026-07-10 09:38Z) Rebased the existing `578-extend-lsp-cancellation-and-request-progress` branch onto current `origin/master` and confirmed the worktree is clean.
- [x] (2026-07-10 09:38Z) Re-read `.agents/PLANS.md`, the issue plan, current LSP dispatch, formatting cancellation, progress support, reference handling, and usage-finder architecture.
- [ ] Add the crate-private cooperative cancellation token and propagate it through the default usage candidate providers and every language query loop used by references.
- [ ] Add the bounded LSP request-worker registry, request-scoped progress reporter, and asynchronous references dispatch.
- [ ] Add deterministic unit/integration coverage and update the public LSP documentation.
- [ ] Run formatting, focused tests, `cargo clippy-no-cuda`, and the full test suite.
- [ ] Run specialist reviews, address actionable findings, and record final outcomes.

## Surprises & Discoveries

- Observation: The issue branch's remote ref still pointed at `37879e30`, while `origin/master` had advanced to `a1e952e0` with runtime LSP configuration support.
  Evidence: `git rebase origin/master` advanced the current branch to `a1e952e0`; `ServerState` now owns `runtime_configuration` and calls `register_runtime_configuration` before entering the main loop.

- Observation: The Bifrost code-intelligence MCP tool surface was not exposed in this Codex session.
  Evidence: the available tool list contained no `search_symbols`, `scan_usages`, `get_symbol_sources`, or related Bifrost MCP tools, so investigation used the skill's documented `rg` and direct-source fallback.

- Observation: `lsp-types` 0.97 already models client-supplied `workDoneToken` on `ReferenceParams` and supports the work-done begin/report/end payloads needed by this milestone.
  Evidence: the local dependency sources define `ReferenceParams.work_done_progress_params` and `WorkDoneProgress::{Begin,Report,End}`. No dependency update is required.

## Decision Log

- Decision: Implement the references-first milestone rather than all handlers named by issue #578.
  Rationale: References exercises the deepest required cancellation seam through candidate discovery and every language usage resolver. Proving the shared infrastructure here keeps the first change reviewable and leaves request-specific progress/streaming policy to later milestones.
  Date/Author: 2026-07-10 / Codex

- Decision: Keep existing public Rust `UsageFinder` and `CandidateFileProvider` APIs unchanged.
  Rationale: Cancellation is currently an LSP execution concern. A crate-private `UsageFinder::with_cancellation` path and cancellation stored in internal default providers can stop the real work without forcing every external/custom provider to adopt a new public type.
  Date/Author: 2026-07-10 / Codex

- Decision: Keep references partial results disabled in this milestone.
  Rationale: The current handler globally sorts and deduplicates locations. Returning chunks before that normalization cannot yet guarantee complete, append-only partial results, while LSP permits a server to ignore `partialResultToken` and return the full result normally.
  Date/Author: 2026-07-10 / Codex

- Decision: Bound cancellable read-only request workers to two active jobs.
  Rationale: Usage search may itself use Rayon and can consume substantial CPU and file I/O. Two concurrent searches preserve responsiveness without allowing an editor to create unbounded native threads. Excess requests receive LSP `ServerCancelled` (`-32802`).
  Date/Author: 2026-07-10 / Codex

- Decision: Use request-time clones of `WorkspaceAnalyzer` and `Arc<OverlayProject>` in workers.
  Rationale: These types are sendable and cloneable, avoid borrowing mutable `ServerState`, and preserve the same request-start snapshot semantics as the old synchronous dispatch while later editor notifications continue on the main loop.
  Date/Author: 2026-07-10 / Codex

## Outcomes & Retrospective

Implementation has not started. On completion, summarize the supported behavior, validation results, remaining issue #578 handlers, and any review-driven design changes here.

## Context and Orientation

`src/lsp/server.rs` owns the stdio connection, initializes `ServerState`, reads JSON-RPC messages, dispatches LSP requests, and sends responses. Its `main_loop` processes one message at a time. `handle_request` currently invokes `references::handle` directly, so the loop cannot read cancellation notifications during a search. Formatting takes a different path: it prepares immutable input, registers a `FormatterCancellation`, spawns a thread, and maps cancellation to `ErrorCode::RequestCanceled`.

`src/lsp/handlers/references.rs` resolves the code symbol under the cursor, calls `usage_hits_for_candidates`, maps usage hits to LSP locations, optionally adds declarations, then sorts and deduplicates the complete location list. `src/lsp/handlers/usage_hits.rs` is the small adapter into `UsageFinder`.

`src/analyzer/usages/finder.rs` selects candidate files and dispatches to a language-specific structured usage graph. `src/analyzer/usages/candidates.rs` contains the import-graph provider and a Rayon-backed text-search candidate fallback. `src/analyzer/usages/traits.rs` defines `UsageScanScope`, which already travels through the language query resolvers and is therefore the right internal carrier for a cooperative token. The language graph implementations scan files and structured analyzer indices; they must check cancellation at file or batch boundaries. Cancellation must not become a `FuzzyResult` failure because it is not a semantic usage-analysis outcome.

A cooperative cancellation token is a cloneable handle containing an atomic boolean. Calling `cancel` sets the boolean; long-running code periodically calls `is_cancelled` and returns early. It does not forcibly terminate threads. Therefore shutdown correctness depends on placing checkpoints in every potentially long file-scanning loop and joining worker handles after cancellation.

Client-initiated work-done progress differs from Bifrost's existing startup progress. Startup asks the client to create a server-owned token using `window/workDoneProgress/create`. A references request already supplies its own optional `workDoneToken`; Bifrost must use that token directly and only until it sends the request response. The advertised `referencesProvider` must become an options object with `workDoneProgress: true` so clients know Bifrost will honor such tokens.

## Plan of Work

First, add a crate-private cancellation module containing `CancellationToken`. The default constructor creates a live, not-canceled token. Clones share one atomic flag. Add `cancel` and `is_cancelled`; do not expose this module from the public crate API.

Teach `UsageFinder` to accept a token through a crate-private builder while keeping `new`, `query`, `find_usages`, the public provider trait, and all external callers source-compatible. Store the token in the finder. Construct the default import-graph and text-search providers with the same token, and store it in `UsageScanScope`. Check it before and after candidate discovery, filtering/truncation, and graph dispatch. Candidate providers should stop at their existing file-loop boundaries; the Rayon closure must test the flag before file I/O and before recording a match. An early-aborted internal search may construct an empty intermediate result because the LSP handler will check the same token and discard it.

Add cancellation checks at file/batch boundaries in the JS/TS, Python, PHP, Rust, Java, C#, C++, Go, Scala, and Ruby query implementations. Where a strategy delegates a whole file set to an extractor helper, pass the shared token or a cancellation predicate into that helper so cancellation can stop between files rather than only after the whole helper returns. Do not change usage proof rules, candidate limits, structured resolver behavior, or public result shapes.

Next, add a request-scoped LSP context for references. It owns the shared cancellation token and an optional work-done reporter backed by the cloned connection sender. The reporter sends `WorkDoneProgress::Begin` with title `Finding references`, `cancellable: true`, message `Resolving symbol`, and no percentage. The handler reports `Searching workspace` immediately before usage search and `Preparing locations` before mapping/sorting results. The worker sends one `End` with `References ready`, `Cancelled`, or `Failed` before its JSON-RPC response. With no token, every reporter method is a no-op. Progress send failures are logged and do not replace the request result; if the connection is closed, the final response send will fail consistently as well.

Refactor references dispatch so parameter extraction stays on the main thread. Invalid parameters still produce an immediate `InvalidParams` response. For valid parameters, capture the request id, method, cloned analyzer, cloned overlay, connection sender, client work-done token, and a fresh cancellation token. Register and spawn the worker through `RequestJobs`.

`RequestJobs` will use an atomic active count and a mutex-protected map from `RequestId` to a token plus `JoinHandle`. Acquisition is capped at two active workers. A full registry returns `ServerCancelled` without starting progress. The message loop reaps finished handles before acting on each new message so cancellation received after a response is harmless. `$/cancelRequest` calls both `RequestJobs::cancel` and the existing formatter registry. Server teardown cancels all request tokens, drains the map, joins every handle, then performs the existing formatter cancellation/wait and connection shutdown.

The reference handler will return a typed crate-private cancellation result. It checks the token before cursor resolution, after target resolution, before and after usage search, during hit conversion and declaration inclusion, and before/after sort and dedup. If canceled, the worker emits the progress end and returns `ErrorCode::RequestCanceled` with a concise message. A cancellation racing after the final check may harmlessly arrive after a successful response, consistent with cooperative cancellation semantics.

Update `src/lsp/capabilities.rs` to advertise `ReferencesOptions { work_done_progress: Some(true) }`. Update the public LSP documentation to state that references supports cooperative cancellation and request-scoped work-done progress, while broader handler cancellation and partial results remain follow-up work.

Finally, add deterministic tests. Worker-registry unit tests will use barriers or channels to hold a fake worker until its token is canceled, prove the two-job cap, prove unknown/completed cancellation no-ops, and prove cancel-and-join shutdown. Usage tests will pass a pre-canceled token and use counting/trap test collaborators to prove candidate/resolver loops return before file work. LSP integration tests will update the capability expectation, assert progress ordering and token identity, assert no progress without a token, preserve existing reference locations, and cover harmless late/unsupported cancellation. Do not add production sleeps or environment-variable test hooks.

## Concrete Steps

Run all commands from `/Users/dave/.codex/worktrees/7d57/bifrost`.

1. Add the cancellation module and usage-search checkpoints. Format and run the focused usage tests:

       cargo fmt
       cargo test --test usages_finder_fallback_test

2. Add request workers, reference progress, cancellation mapping, and capability advertisement. Run the server unit and focused integration tests:

       cargo test --lib lsp::server::tests
       cargo test --test bifrost_lsp_server bifrost_lsp_server_references
       cargo test --test bifrost_lsp_server bifrost_lsp_server_formatting_cancel_stops_active_formatter -- --exact

3. Update documentation and run the full local CI-equivalent checks for this macOS host:

       cargo fmt
       cargo clippy-no-cuda
       cargo test

The focused tests should report zero failures. The reference progress test should observe begin, one or more report notifications, end, and then the response. A canceled active job should return error code `-32800`. The existing formatter-cancellation test must continue to pass.

## Validation and Acceptance

Initialization returns `referencesProvider` as an object whose `workDoneProgress` field is `true`.

A references request without `workDoneToken` returns the same sorted, deduplicated locations as before and emits no request-scoped `$/progress` notification.

A references request with `workDoneToken: "reference-progress"` emits only notifications using that exact token, in the order begin, zero or more reports, end. The end notification is sent before the JSON-RPC response.

When the client cancels an active references request by id, the main loop processes the cancellation while the worker is running, structured usage work observes the shared flag at a bounded checkpoint, and the worker returns error code `-32800`. The request never remains open. Canceling an unknown, unsupported, or already-completed request changes no state visible to later requests.

When shutdown begins with active reference workers, all tokens are canceled and all handles are joined before the connection and I/O threads are dropped. Existing formatter children are still terminated and reaped by their specialized cancellation path.

All language usage graph tests and the complete Rust test suite remain green, demonstrating that the crate-private cancellation path did not alter public usage-query semantics when no cancellation token is supplied.

## Idempotence and Recovery

All code and test changes are ordinary source edits and can be reapplied safely after inspecting the current diff. The ExecPlan is append/update-in-place and must reflect actual progress after each stopping point.

If a worker test hangs, interrupt the test process, inspect which cancellation checkpoint or join path was missed, and rerun only the named unit test. Do not weaken the test with a timeout-based success condition. If a language usage test regresses, compare the uncanceled path and restore its original candidate/result semantics before adding the token check at a safer loop boundary.

If validation exposes unrelated failures, record them in `Surprises & Discoveries` and distinguish them from failures introduced by this branch. Do not hide failures with lint allowances or ignored tests.

## Artifacts and Notes

The existing baseline command passed before implementation:

    cargo test --test bifrost_lsp_server bifrost_lsp_server_formatting_cancel_stops_active_formatter -- --exact

Expected tail:

    test bifrost_lsp_server_formatting_cancel_stops_active_formatter ... ok
    test result: ok. 1 passed; 0 failed

The LSP error enum in the current `lsp-server` dependency spells the Rust variant `RequestCanceled`, while the protocol documentation and issue text often spell the concept `RequestCancelled`. The wire value is the authoritative contract: `-32800`.

## Interfaces and Dependencies

No dependency versions change.

Add a crate-private cancellation type with this conceptual interface:

    #[derive(Clone, Default)]
    pub(crate) struct CancellationToken { /* shared atomic flag */ }

    impl CancellationToken {
        pub(crate) fn cancel(&self);
        pub(crate) fn is_cancelled(&self) -> bool;
    }

Add a crate-private `UsageFinder::with_cancellation(CancellationToken) -> Self` or equivalent builder. Public `UsageFinder` methods continue to behave exactly as before by using a never-canceled default token.

Add a crate-private request context consumed by `references::handle`. Its interface exposes the token, cancellation checks, and phase reporting without exposing connection details to analyzer code.

Change the LSP capability wire shape from:

    "referencesProvider": true

to:

    "referencesProvider": { "workDoneProgress": true }

Use only the existing standard-library threading/synchronization primitives and existing `lsp-server`, `lsp-types`, Rayon, and serde dependencies.
