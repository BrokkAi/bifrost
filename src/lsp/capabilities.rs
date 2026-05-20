use lsp_types::{
    CompletionOptions, DiagnosticOptions, DiagnosticServerCapabilities,
    FoldingRangeProviderCapability, HoverProviderCapability, OneOf, ServerCapabilities,
    TextDocumentSyncCapability, TextDocumentSyncKind, TextDocumentSyncOptions,
    TextDocumentSyncSaveOptions, WorkDoneProgressOptions,
};

pub fn server_capabilities() -> ServerCapabilities {
    // Full-document sync: each `didChange` carries the entire buffer, which we
    // store in `OverlayProject` so request-time reads and the analyzer's
    // reparse both see the unsaved content. INCREMENTAL would require applying
    // range edits locally and is left as a follow-up.
    let text_document_sync = TextDocumentSyncOptions {
        open_close: Some(true),
        change: Some(TextDocumentSyncKind::FULL),
        will_save: None,
        will_save_wait_until: None,
        save: Some(TextDocumentSyncSaveOptions::Supported(true)),
    };

    ServerCapabilities {
        text_document_sync: Some(TextDocumentSyncCapability::Options(text_document_sync)),
        completion_provider: Some(CompletionOptions {
            // v1: client must invoke completion explicitly. We don't expose
            // trigger characters because identifier-prefix-only completion
            // isn't meaningful on `.` or `::` (we don't resolve qualified
            // names yet).
            resolve_provider: Some(false),
            ..CompletionOptions::default()
        }),
        definition_provider: Some(OneOf::Left(true)),
        document_highlight_provider: Some(OneOf::Left(true)),
        document_symbol_provider: Some(OneOf::Left(true)),
        folding_range_provider: Some(FoldingRangeProviderCapability::Simple(true)),
        hover_provider: Some(HoverProviderCapability::Simple(true)),
        references_provider: Some(OneOf::Left(true)),
        workspace_symbol_provider: Some(OneOf::Left(true)),
        diagnostic_provider: Some(DiagnosticServerCapabilities::Options(DiagnosticOptions {
            identifier: Some("bifrost-tree-sitter".to_string()),
            inter_file_dependencies: false,
            workspace_diagnostics: false,
            work_done_progress_options: WorkDoneProgressOptions::default(),
        })),
        // Per-feature capabilities are turned on as their handlers land.
        ..ServerCapabilities::default()
    }
}
