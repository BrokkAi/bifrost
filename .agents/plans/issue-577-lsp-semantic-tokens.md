# Add full-document LSP semantic tokens

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This plan is maintained in accordance with `.agents/PLANS.md` from the repository root.

## Purpose / Big Picture

Bifrost currently provides navigation and diagnostics through its LSP server but leaves all coloring to editor syntax highlighters. After this change, editors that support LSP semantic tokens can request `textDocument/semanticTokens/full` and receive stable coloring for analyzer-known declarations and structured references, including unsaved editor content. The feature deliberately augments ordinary syntax highlighting: it does not attempt to color keywords, literals, comments, locals, or parameters.

## Progress

- [x] (2026-07-10 09:38Z) Confirmed the issue branch and worktree are clean and aligned with their configured upstream.
- [x] (2026-07-10 09:38Z) Recorded the implementation contract, milestones, and validation requirements in this ExecPlan.
- [x] (2026-07-10 09:49Z) Implemented the semantic-token collector, stable legend, UTF-16 relative encoding, capability negotiation, and request dispatch.
- [x] (2026-07-10 09:49Z) Added four focused unit tests and four real LSP subprocess tests covering all grammar candidate predicates, multi-language symbols, overlays, Unicode, line endings, and unsupported files.
- [x] (2026-07-10 09:49Z) Updated the public LSP documentation and internal API-surface audit.
- [x] (2026-07-10 09:59Z) Ran formatting, focused and complete tests, matching-toolchain doctests, no-CUDA clippy, reviewed the final diff, and recorded validation evidence.

## Surprises & Discoveries

- Observation: The Bifrost code-intelligence skill instructions are installed, but their MCP tools are not exposed in this session.
  Evidence: tool discovery found no `search_symbols`, `get_symbol_sources`, or `scan_usages` callable, so repository exploration used the skills' documented `rg` and source-reading fallback.

- Observation: `DeclarationNameRangeContext` was the natural owner for both the parsed root and the exact source snapshot, but the resolver also needs shared ownership of that source.
  Evidence: storing the context content as `Arc<String>` lets semantic tokens reuse the same bytes with a refcount bump instead of cloning the full document before batch resolution; all existing callers continue to borrow `&str`.

- Observation: Every supported grammar exposes reference candidates through named leaf nodes called `identifier`, an `_identifier` variant, or the PHP/Ruby `name`/variable forms.
  Evidence: the table-driven unit test parses tiny Java, Go, C++, JavaScript, TypeScript, Python, Rust, PHP, Scala, C#, and Ruby sources and finds at least one candidate without source scanning.

- Observation: This machine selects Homebrew `rustdoc` after Rustup `rustc` built the dependency artifacts, even though both report Rust 1.96, so the final doctest step rejects otherwise compatible metadata.
  Evidence: every unit and integration binary passed before doctests failed with E0514; rerunning `cargo test --doc` with `RUSTDOC=/Users/dave/.cargo/bin/rustdoc` passed. The matching Rustup-first path and isolated target directory also let no-CUDA clippy pass cleanly.

## Decision Log

- Decision: The fixed token-type legend is `namespace`, `type`, `function`, `property`, `macro`, in that order, with `declaration` as the only modifier.
  Rationale: This maps one-to-one onto Bifrost's deliberately lean `CodeUnitType` taxonomy without reintroducing syntax-shaped public categories.
  Date/Author: 2026-07-10 / user and Codex.

- Decision: Emit only analyzer-known declaration names and structured references whose viable targets all map to one legend type.
  Rationale: High-confidence semantic coloring is useful without replacing the editor's syntax highlighter, and conflicting targets should not be colored by guesswork.
  Date/Author: 2026-07-10 / user and Codex.

- Decision: Advertise only full-document tokens, without result IDs, range requests, delta requests, refresh requests, or per-request progress.
  Rationale: This is the focused first milestone from issue #577; each deferred capability needs independent state and protocol behavior.
  Date/Author: 2026-07-10 / user and Codex.

- Decision: Advertise the fixed legend only when the client announces full requests, relative encoding, every legend type, and the declaration modifier.
  Rationale: Keeping one immutable server legend avoids per-client token-index state and prevents sending types or modifiers the client says it cannot consume.
  Date/Author: 2026-07-10 / Codex.

## Outcomes & Retrospective

Issue #577 is implemented and validated. Compatible LSP clients receive the stable five-type legend and can request full-document tokens for analyzer-known declarations and structured references. The handler reads unsaved overlays, returns an empty successful result for unsupported inputs, uses iterative tree-sitter candidate discovery and structured batch resolution, and emits deterministic UTF-16 relative tokens without range/delta state or lexical fallback. Four focused unit tests, four new real-server scenarios, the complete 173-test LSP target, every full-suite unit and integration binary, doctests, formatting, and no-CUDA clippy pass. No known implementation work remains.

## Context and Orientation

`src/lsp/capabilities.rs` builds the initialize response. `src/lsp/server.rs` dispatches requests. Per-feature implementations live in `src/lsp/handlers/`. All document handlers must read through `Project::read_source`; the LSP server wraps its filesystem project in `OverlayProject`, so this is how unsaved `didOpen` and `didChange` content wins over disk.

Bifrost records named declarations as `CodeUnit` values and their byte ranges through `IAnalyzer`. `src/analyzer/declaration_range.rs` reparses a file once in `DeclarationNameRangeContext` and locates the exact tree-sitter name node for a declaration. Structured reference resolution is batched by `resolve_definition_batch_with_source` in `src/analyzer/usages/get_definition/mod.rs`; it reuses one source snapshot and one parse per language during the batch.

The LSP semantic-token wire format sorts tokens by zero-based line and UTF-16 character column. Each token contains five unsigned integers: line delta from the previous token, start-column delta on the same line or absolute start on a new line, UTF-16 length, legend type index, and modifier bitset. Tokens may not overlap in this milestone, and identifier tokens never span lines.

## Plan of Work

First extend `DeclarationNameRangeContext` so it can return every name range recorded for a `CodeUnit` and expose its parsed root for a second iterative tree walk. Preserve the existing single-range method for current callers. Add `src/lsp/handlers/semantic_tokens.rs` with the fixed legend, a `CodeUnitType` mapping, language-specific tree-sitter identifier-node predicates, declaration collection, batch reference resolution, range conflict handling, UTF-16 conversion, sorting, deduplication, and relative encoding. Failure to resolve the URI, source, language, or parse must produce a successful empty result.

Then wire `SemanticTokensFullRequest` into `src/lsp/server.rs` and add semantic-token capability negotiation in `src/lsp/capabilities.rs`. Advertise only when the client supports full requests, the `relative` format, all five fixed token types, and the `declaration` modifier. The server advertises `full: true` and omits range and delta support.

Add unit tests next to the handler for mapping, declaration precedence, deterministic encoding, UTF-16, CRLF/LF, and empty results. Extend `tests/common/lsp_client.rs` with a full-document semantic-token request helper and `tests/bifrost_lsp_server.rs` with capability and end-to-end tests over a small Java, TypeScript, and Rust workspace. Use unsaved overlays and a supplementary Unicode scalar before an identifier to prove the request uses the current buffer and UTF-16 positions. Add a table-driven parse/candidate test covering each supported Bifrost language with a tiny declaration/reference source.

Finally update `docs/src/content/docs/lsp.md` and `.agents/docs/lsp-api-surface-audit.md`, format, run focused tests, run the complete LSP target and Rust suite, run no-CUDA clippy, review the diff, and keep this plan's progress and evidence current. Commit each verified milestone on the existing branch, staging only milestone files. Do not push or open a pull request.

## Concrete Steps

All commands run from `/Users/dave/.codex/worktrees/cc91/bifrost`.

During implementation, use the narrowest relevant commands first:

    cargo test lsp::handlers::semantic_tokens --lib
    cargo test --test bifrost_lsp_server semantic_tokens -- --nocapture

After focused behavior passes, run:

    cargo test --test bifrost_lsp_server
    cargo test
    cargo fmt
    cargo fmt --check
    cargo clippy-no-cuda

## Validation and Acceptance

An initialized client that advertises full semantic tokens, relative encoding, and the fixed legend must receive `semanticTokensProvider` with the exact stable type/modifier arrays, `full: true`, and no range or delta capability. Clients that cannot consume that contract must not receive the provider.

A full-document request must return analyzer-known declaration names with modifier bit zero set and resolved references with no modifier. Module, type, function, field, and macro targets must use legend indexes 0 through 4. Multiple viable targets are accepted only when all map to the same type. Declaration/reference collisions must produce one declaration token. Tokens must be ordered, non-overlapping, delta encoded, and measured in UTF-16 units.

Requests must read unsaved overlays. Unicode before or inside an identifier and LF/CRLF source must yield correct positions. Unsupported, unreadable, outside-workspace, and unparseable files must return an empty semantic-token array without a JSON-RPC error. Range, delta, result IDs, refresh, progress, keywords, literals, comments, operators, locals, and parameters remain absent.

## Idempotence and Recovery

The collector is read-only and request-local. It does not cache result IDs or mutate analyzer state, so requests and tests can be repeated safely. If a test exposes a language-specific identifier gap, add or correct the structured tree-sitter node predicate; do not add source scanning or regex fallback. Formatting and validation commands are repeatable. Checkpoint commits stay on the existing branch and stage only files changed for this issue.

## Artifacts and Notes

The synchronized starting commit is `a1e952e0`, which is also the configured remote branch and `origin/master` at the start of implementation.

Focused implementation evidence:

    cargo test lsp::handlers::semantic_tokens --lib
    # 4 passed

    cargo test --test bifrost_lsp_server semantic_tokens -- --nocapture
    # 4 passed

Final validation evidence:

    cargo test --test bifrost_lsp_server
    # 173 passed

    cargo test
    # every unit and integration binary passed; the final doctest command
    # needed the matching Rustup rustdoc below

    RUSTDOC=/Users/dave/.cargo/bin/rustdoc cargo test --doc
    # passed

    cargo fmt --check
    # passed

    PATH=/Users/dave/.cargo/bin:/Users/dave/.local/bin:/opt/homebrew/bin:/usr/bin:/bin \
      CARGO_TARGET_DIR=/private/tmp/bifrost-clippy-577 cargo clippy-no-cuda
    # passed

## Interfaces and Dependencies

No new dependency or public Rust API is required. The public interface addition is the negotiated LSP capability and `textDocument/semanticTokens/full` request.

The handler exposes within the LSP crate:

    pub(crate) fn legend() -> lsp_types::SemanticTokensLegend;

    pub fn handle(
        workspace: &WorkspaceAnalyzer,
        project: &dyn Project,
        params: &SemanticTokensParams,
    ) -> Option<SemanticTokensResult>;

`handle` always returns `Some(SemanticTokensResult::Tokens(...))`; error-like document states use an empty `data` vector. The declaration-range context gains an internal all-name-ranges operation while retaining existing behavior for current callers.

Plan revision note (2026-07-10 09:38Z): Created the self-contained implementation plan before changing production code.

Plan revision note (2026-07-10 09:49Z): Marked the core handler, integration coverage, and documentation milestones complete after focused unit and subprocess tests passed.

Plan revision note (2026-07-10 09:59Z): Closed the plan after complete LSP, full-suite, doctest, formatting, and no-CUDA clippy validation, and documented the reproducible Rustup/Homebrew toolchain workaround.
