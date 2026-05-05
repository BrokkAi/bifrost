use lsp_types::{
    DiagnosticOptions, DiagnosticServerCapabilities, HoverProviderCapability, OneOf,
    ServerCapabilities, TextDocumentSyncCapability, TextDocumentSyncKind, TextDocumentSyncOptions,
    TextDocumentSyncSaveOptions, WorkDoneProgressOptions,
};

pub fn server_capabilities() -> ServerCapabilities {
    // Text sync: open/close + full-document save. Live didChange overlays are
    // intentionally out of scope for v1 — the analyzer re-reads from disk via
    // WorkspaceAnalyzer::update on save.
    let text_document_sync = TextDocumentSyncOptions {
        open_close: Some(true),
        change: Some(TextDocumentSyncKind::NONE),
        will_save: None,
        will_save_wait_until: None,
        save: Some(TextDocumentSyncSaveOptions::Supported(true)),
    };

    ServerCapabilities {
        text_document_sync: Some(TextDocumentSyncCapability::Options(text_document_sync)),
        definition_provider: Some(OneOf::Left(true)),
        document_symbol_provider: Some(OneOf::Left(true)),
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
