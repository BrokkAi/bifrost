# LSP API Surface Audit

Issue: <https://github.com/BrokkAi/bifrost/issues/564>

Spec reference: LSP 3.18, <https://microsoft.github.io/language-server-protocol/specifications/lsp/3.18/specification/>

Date: 2026-07-09

## Current Bifrost LSP Surface

`src/lsp/capabilities.rs` advertises only capabilities that have handlers in
`src/lsp/server.rs`. Unsupported requests fall through to JSON-RPC
`MethodNotFound`; unsupported notifications are ignored as required by the
protocol.

Currently implemented and advertised:

- Text document synchronization with open/close, full-document `didChange`, and
  `didSave`.
- Definition, type definition, implementation, hover, signature help,
  completion, references, rename/prepareRename, document highlight, document
  symbol, formatting, folding range, workspace symbol, pull diagnostics, type
  hierarchy, and call hierarchy.
- Workspace folder changes and watched-file notifications.
- Server-initiated startup work-done progress when the client advertises
  `window.workDoneProgress`.
- Cancellation for active formatting requests.

## Candidate Matrix

| API | Current support | User value | Implementation risk | Recommendation |
| --- | --- | --- | --- | --- |
| `textDocument/didChange` incremental sync | Not advertised. Bifrost advertises `TextDocumentSyncKind::FULL`; malformed incremental-looking events are dropped with a throttled stderr warning. | Medium. Reduces payload size for large edits and can make non-conforming or limited clients less surprising. | Medium-high. Must apply ordered UTF-16 LSP ranges to local text exactly, update overlay generations, preserve Windows CRLF behavior, and avoid stale analyzer reparses. | Open a focused implementation issue. Keep full sync as the default until the range-edit path is covered by cross-platform tests. |
| `workspace/didChangeConfiguration` | Implemented by #576. Pull-capable clients use `workspace/configuration`; legacy clients can push full snapshots. Formatter rules swap live, while roots/excludes rebuild transactionally and clear departed diagnostics. | High for editor integrations. Users can update formatter commands, roots, and excludes without restarting the server. | Covered by response-ordering, rebuild, overlay, diagnostic, formatter-cancellation, and Windows handle-cleanup tests. | Keep the runtime schema limited to existing LSP settings; expose analyzer tuning only through a separately designed schema. |
| `textDocument/codeAction` | Not advertised. Unknown code-action requests return `MethodNotFound`. | Low today. Existing diagnostics are mostly parse errors and do not carry safe edits; Bifrost has no organize-import or quick-fix edit engine yet. | Medium. A low-value empty provider would train clients to call a useless path, while real fixes need diagnostic IDs and edit generation. | Do not implement now. Reconsider after diagnostics carry stable machine-readable codes with safe edits. |
| `textDocument/semanticTokens` | Full-document semantic tokens are implemented by #577 for analyzer-known declarations and structured references. The fixed legend mirrors Bifrost's high-level declaration taxonomy, and requests read unsaved overlays. | High. Editor highlighting is visible, broadly supported, and Bifrost classifies symbols from tree-sitter/analyzer structure rather than lexical tokenization. | Covered by stable-legend, multi-language, UTF-16, CRLF, overlay, and unsupported-file tests. Range/delta result state and refresh behavior remain separate work. | Keep full-document support focused on high-confidence resolved symbols. Add range or delta only with a measured client or performance need. |
| `workspace/executeCommand` | Not advertised. | Low today. There are no Bifrost LSP commands that should execute through editors rather than MCP/CLI or direct code-action edits. | Medium-high. Server-side commands need strict command registration, argument validation, and clear trust boundaries. | Explicitly decline for now. Only add with a concrete command-producing feature. |
| `textDocument/willSave` / `willSaveWaitUntil` | Not advertised. Bifrost already supports explicit formatting and `didSave` re-index/diagnostics. | Low. There is no current cache-prep operation needed before save, and formatting-on-save is normally driven by `textDocument/formatting`. | Medium. `willSaveWaitUntil` blocks the save path and must be fast, cancellation-aware, and editor-compatible. | Explicitly decline for now. Use explicit formatting and `didSave` until there is a concrete pre-save edit or cache use case. |
| Cancellation beyond formatting | `$/cancelRequest` is decoded, but only active formatting jobs are cancellable. Other requests finish normally. | Medium-high for expensive references, workspace symbol, diagnostics, hierarchy, and future semantic token requests. | Medium-high. Requires cooperative cancellation through analyzer/search code and predictable partial-result semantics. | Open a focused issue for cooperative cancellation on long-running requests, then wire per-request work-done/partial-result progress where it helps. |
| Progress beyond startup | Server-initiated startup progress is implemented. Per-request work-done progress and partial results are not implemented. | Medium. Helpful for large references/workspace symbol/diagnostic requests and future semantic tokens. | Medium. Must honor per-request `workDoneToken`/`partialResultToken` and avoid mixing final results with partial result streams. | Track with the cancellation issue unless a specific request needs independent progress first. |

## Follow-Up Issue Scope

Open these focused follow-ups:

1. Incremental `textDocument/didChange` support:
   <https://github.com/BrokkAi/bifrost/issues/575>
2. Runtime `workspace/didChangeConfiguration` support (implemented):
   <https://github.com/BrokkAi/bifrost/issues/576>
3. Full-document `textDocument/semanticTokens` support:
   <https://github.com/BrokkAi/bifrost/issues/577>
4. Cooperative cancellation and per-request progress for long-running LSP
   requests: <https://github.com/BrokkAi/bifrost/issues/578>

Do not open follow-ups for `codeAction`, `executeCommand`, or
`willSave`/`willSaveWaitUntil` until there is a concrete feature that needs
them.

## Windows Considerations

- Range-edit application must preserve CRLF/LF content exactly as received from
  the client and must use LSP UTF-16 positions rather than byte offsets.
- Workspace rebuilds triggered by configuration changes should drop stale
  diagnostics and avoid keeping file handles, formatter child processes, or old
  analyzer state alive across root/exclude changes.
- Cancellation support must always reap child formatter processes and should not
  leave worker threads blocked on channels during shutdown.
