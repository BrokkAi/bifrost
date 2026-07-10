# Add incremental LSP text synchronization

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This plan is maintained in accordance with `.agents/PLANS.md` from the repository root.

## Purpose / Big Picture

Bifrost currently asks editors to resend an entire open document after every keystroke. After this change, the LSP server advertises incremental synchronization and can mirror small UTF-16 range edits without losing the rest of the unsaved buffer. A user can observe the result by opening a document through LSP, sending ranged `textDocument/didChange` events, and then seeing hover, completion, analyzer state, and diagnostics reflect the edited text. Whole-document replacement events remain supported for compatible clients.

## Progress

- [x] (2026-07-10 06:56Z) Confirmed the issue branch is clean, fetched its remote, and verified it is already up to date.
- [x] (2026-07-10 06:56Z) Recorded the implementation contract and validation plan in this ExecPlan.
- [x] (2026-07-10 07:00Z) Implemented the private transactional text-change applicator and nine focused unit tests.
- [x] (2026-07-10 07:09Z) Integrated document versions and incremental changes into the LSP server while preserving downstream refresh behavior.
- [x] (2026-07-10 07:09Z) Updated capability advertisement, integration coverage, and public LSP documentation.
- [x] (2026-07-10 07:25Z) Ran formatting, focused and full tests, doctests, no-CUDA clippy, and a final diff review; added a transactional rollback regression found during review.
- [x] (2026-07-10 07:28Z) Rebased all checkpoints onto current `origin/master` (`1b28944c`) and reran the ten text-sync and 160 LSP tests successfully.

## Surprises & Discoveries

- Observation: `src/lsp/conversion.rs::position_to_byte_offset` already counts UTF-16 correctly and understands LF, CRLF, and CR, but deliberately clamps invalid line positions to EOF because it serves read-only request cursors.
  Evidence: its existing unit tests pin clamping behavior, so mutation-time validation must use a separate fallible helper rather than changing query semantics.

- Observation: the current `didChange` handler keeps only the last range-less event and discards ranged events, but the complete overlay, cache invalidation, analyzer update, generation, and diagnostics pipeline already exists.
  Evidence: the focused initialization, overlay/completion, malformed-change, and conversion tests all passed before implementation.

- Observation: a single owned `String` plus recomputed line starts is sufficient to implement the protocol safely without adding a rope or text-buffer dependency.
  Evidence: `cargo test lsp::text_sync::tests --lib` passes nine cases covering ordered edits, UTF-16, line endings, clamping, and transactional rejection.

- Observation: open-document state already survives workspace-root removal, so incremental edits received while a root is absent can be retained without analyzer work and replayed when the root returns.
  Evidence: the extended `bifrost_lsp_server_replays_open_document_after_workspace_folder_readd` test passes after editing the tracked document between root removal and re-addition.

- Observation: the sandbox blocks the existing uv cache used by the voyage-sidecar lifecycle test, and this machine places Homebrew `rustdoc` and `clippy-driver` before the Rustup tools even though both report Rust 1.96.
  Evidence: the sandboxed full suite failed only when uv could not open `~/.cache/uv`; the host rerun passed every test binary. Doctests and clippy initially reported incompatible compiler metadata until run with `/Users/dave/.cargo/bin` tools and an isolated clippy target directory.

- Observation: `origin/master` advanced after the planning snapshot while the issue branch's configured upstream remained at the old base, so plain `git rebase` did not incorporate the new master commit.
  Evidence: the final graph audit found merge base `3b4d1081` and current master `1b28944c`; `git rebase origin/master` applied all four checkpoints without conflicts.

## Decision Log

- Decision: Advertise `TextDocumentSyncKind::INCREMENTAL` when the implementation lands, while continuing to accept range-less whole-document replacements after `didOpen`.
  Rationale: LSP exposes one synchronization kind, so keeping `FULL` advertised would leave conforming clients unable to exercise the new path.
  Date/Author: 2026-07-10 / user and Codex.

- Decision: Store the client document version from `didOpen` and accept only strictly newer `didChange` versions; gaps are valid.
  Rationale: incremental ranges depend on the exact preceding document state, so applying stale changes risks corrupting the server mirror.
  Date/Author: 2026-07-10 / user and Codex.

- Decision: Treat the entire content-change array as one transaction and commit downstream state once only after every change validates.
  Rationale: LSP defines each change against the intermediate state produced by earlier changes, and a later malformed range must not leave a partially updated overlay.
  Date/Author: 2026-07-10 / Codex.

- Decision: Preserve LSP's required line-end clamping for character columns past the visible line length, but reject nonexistent lines, reversed ranges, and positions inside a UTF-16 surrogate pair.
  Rationale: character overflow has defined protocol behavior, while the other positions cannot be mapped safely to Rust UTF-8 string boundaries.
  Date/Author: 2026-07-10 / user and Codex.

- Decision: Ignore deprecated `rangeLength`; the structured `range` is authoritative.
  Rationale: the LSP specification deprecates `rangeLength`, and validating two competing representations would reject otherwise valid clients.
  Date/Author: 2026-07-10 / Codex.

## Outcomes & Retrospective

Issue #575 is implemented and validated. The server advertises incremental sync, preserves whole-document changes, validates versions, applies ordered UTF-16 edits, retains out-of-root open documents, and rejects unsafe notifications without side effects. Ten pure text-sync tests pass, the 160-test LSP target passes, every full-suite unit and integration test binary passes, doctests pass with the matching Rustup `rustdoc`, formatting is clean, and the isolated no-CUDA all-target clippy run passes. No known work remains.

## Context and Orientation

`src/lsp/server.rs` is the hand-written LSP notification dispatcher. Its `DidOpenTextDocument` and `DidChangeTextDocument` arms store unsaved text in `OverlayProject`, invalidate completion data, update `WorkspaceAnalyzer`, and publish diagnostics. `ServerState::open_documents` holds complete client-owned buffers and `document_generations` protects formatting responses from racing with later edits.

`src/lsp/capabilities.rs` constructs the initialize response. It currently advertises full-document synchronization. `src/lsp/conversion.rs` converts request cursor positions but is intentionally permissive, so the new mutation-specific code belongs in a private `src/lsp/text_sync.rs` module.

An LSP position is a zero-based line and UTF-16 code-unit column. An incremental content change replaces the half-open range from `start` through, but not including, `end`. Changes in one notification are ordered: each range is interpreted against the text produced by the previous change. LF, CRLF, and CR are all line endings, and positions cannot point between the two bytes of CRLF.

## Plan of Work

First add `src/lsp/text_sync.rs`. Define a private `TextSyncError` with safe, displayable rejection reasons and `apply_content_changes(current: &str, changes: &[TextDocumentContentChangeEvent]) -> Result<String, TextSyncError>`. Clone the initial string once, apply each range-less replacement or ranged `String::replace_range` in order, and recompute line starts after every intermediate edit. The fallible UTF-16 position converter must return the visible line end for excessive character columns, reject missing line indices, and reject columns that land inside a multi-unit Unicode scalar. Validate the converted start is not after the end before replacing. Unit tests in the same module cover insertion, replacement, deletion, Unicode, all supported line endings, multiple ordered changes, mixed whole/ranged changes, invalid ranges, and ignored `rangeLength`.

Then update `src/lsp/server.rs`. Add `version: i32` to `OpenDocument` and capture it on `didOpen`. Before applying `didChange`, require an open-document entry and a strictly newer version. Empty change arrays update only the stored protocol version. Non-empty valid arrays use the pure helper against the stored text, then update the stored text/version and internal generation once. For files in the active project, write the completed buffer to `OverlayProject`, invalidate completion once, update the workspace analyzer once, and publish diagnostics once. A tracked open document temporarily outside the active roots still updates its stored text, version, and generation so a later workspace rebuild restores the latest overlay. Rejected events change none of these states.

Generalize the existing throttled malformed-change logger to accept a safe reason string and include the URI and incoming version without logging document content. Notifications do not receive JSON-RPC error responses, so rejection remains a logged no-op rather than an error propagated out of the server loop.

Finally change `src/lsp/capabilities.rs` to advertise incremental synchronization, update `tests/bifrost_lsp_server.rs` with end-to-end behavior, and update `docs/src/content/docs/lsp.md` so the public protocol list is current. The dated internal audit remains unchanged as historical context.

## Concrete Steps

All commands run from `/Users/dave/.codex/worktrees/3ba7/bifrost`.

Implement and check the pure edit layer:

    cargo test lsp::text_sync::tests --lib

Integrate the handler and run the affected end-to-end cases by exact test name while iterating, then run the entire LSP integration target:

    cargo test --features nlp --test bifrost_lsp_server

Run the full Rust suite and repository-required checks:

    cargo test --features nlp
    cargo fmt
    cargo fmt --check
    cargo clippy-no-cuda

Commit each completed milestone on the existing branch, staging only files belonging to that milestone. Do not push or open a pull request.

## Validation and Acceptance

Initialization must return `textDocumentSync.change` equal to `2`. After `didOpen`, a range-less replacement must still update hover or completion. A valid ranged edit must update the overlay and analyzer so hover, completion, and diagnostics observe the final text. Multiple changes must produce the same buffer as applying them sequentially on the client.

UTF-16 tests must distinguish one-unit BMP characters from two-unit supplementary characters. LF, CRLF, and CR edits must preserve untouched line-ending bytes, including ranges that end at the start of the following line. A character column past line end must edit at line end. A nonexistent line, reversed range, surrogate-interior position, stale version, or unknown document must leave the overlay and downstream state unchanged and must not publish diagnostics.

All commands in `Concrete Steps` must exit successfully. The LSP integration test must also run unchanged on Windows CI through the existing path/URI helpers and temporary-project harness.

## Idempotence and Recovery

The pure applicator mutates only an owned temporary string, so validation failures are retryable and cannot partially update server state. Test commands and formatting can be rerun safely. If a milestone fails, keep the ExecPlan progress entry split into completed and remaining work, fix the root cause, and rerun the smallest failing test before broader validation. Git commits are checkpoint commits on the existing issue branch; do not create or switch branches.

## Artifacts and Notes

Pre-change focused tests passed for initialize capability shape, whole-document overlay/completion refresh, malformed ranged-change rejection, and UTF-16 conversions. The synchronized starting commit is `3b4d108105a8c35235d4a78e1385096111cd4d0c`.

Final validation evidence:

    cargo test lsp::text_sync::tests --lib
    # 10 passed

    cargo test --features nlp --test bifrost_lsp_server
    # 160 passed

    cargo test --features nlp
    # every unit and integration test binary passed; the final doctest process
    # required the matching Rustup rustdoc below because PATH selected Homebrew

    RUSTDOC=/Users/dave/.cargo/bin/rustdoc cargo test --features nlp --doc
    # passed

    cargo fmt --check
    # passed

    PATH=/Users/dave/.cargo/bin:/Users/dave/.local/bin:/opt/homebrew/bin:/usr/bin:/bin \
      CARGO_TARGET_DIR=/private/tmp/bifrost-clippy-575 cargo clippy-no-cuda
    # passed

After rebasing onto `origin/master`:

    cargo test lsp::text_sync::tests --lib
    # 10 passed

    cargo test --features nlp --test bifrost_lsp_server
    # 160 passed

## Interfaces and Dependencies

The only public interface change is the LSP initialize response: `textDocumentSync.change` changes from `FULL` (`1`) to `INCREMENTAL` (`2`). No public Rust API or new dependency is needed.

The private module must expose to its parent only:

    pub(super) fn apply_content_changes(
        current: &str,
        changes: &[lsp_types::TextDocumentContentChangeEvent],
    ) -> Result<String, TextSyncError>;

`TextSyncError` must implement `Display` with document-content-free details suitable for the throttled stderr rejection log.

Plan revision note (2026-07-10 07:00Z): Marked the pure text-sync milestone complete and recorded the no-new-dependency result because its focused tests now pass.

Plan revision note (2026-07-10 07:09Z): Marked server, capability, docs, and integration work complete after the focused cases and the full LSP integration target passed.

Plan revision note (2026-07-10 07:25Z): Closed the plan after full validation and recorded the host toolchain-path workaround so later runs can reproduce the green doctest and clippy results.

Plan revision note (2026-07-10 07:28Z): Recorded the final master rebase and post-rebase focused validation so the completed plan matches the delivered branch graph.
