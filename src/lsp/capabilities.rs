use lsp_types::{
    ClientCapabilities, CompletionClientCapabilities, CompletionOptions, DiagnosticOptions,
    DiagnosticServerCapabilities, DocumentFormattingOptions, FoldingRangeProviderCapability,
    HoverProviderCapability, ImplementationProviderCapability, OneOf, RenameOptions,
    ServerCapabilities, SignatureHelpOptions, TextDocumentSyncCapability, TextDocumentSyncKind,
    TextDocumentSyncOptions, TextDocumentSyncSaveOptions, TypeDefinitionProviderCapability,
    WorkDoneProgressOptions, WorkspaceFoldersServerCapabilities,
};

pub fn server_capabilities(client_capabilities: &ClientCapabilities) -> ServerCapabilities {
    // Full-document sync: each `didChange` carries the entire buffer, which we
    // store in `OverlayProject` so request-time reads and the analyzer's
    // reparse both see the unsaved content. INCREMENTAL would require applying
    // range edits locally and is left as a follow-up.
    //
    // Non-conforming clients that ignore the advertised FULL kind and send
    // INCREMENTAL events anyway are detected by `server.rs::handle_notification`
    // (the `DidChangeTextDocument` arm) and warned about via a throttled
    // stderr line — see `maybe_log_malformed_didchange` for the contract.
    let text_document_sync = TextDocumentSyncOptions {
        open_close: Some(true),
        change: Some(TextDocumentSyncKind::FULL),
        will_save: None,
        will_save_wait_until: None,
        save: Some(TextDocumentSyncSaveOptions::Supported(true)),
    };

    ServerCapabilities {
        text_document_sync: Some(TextDocumentSyncCapability::Options(text_document_sync)),
        completion_provider: completion_provider(client_capabilities),
        signature_help_provider: Some(SignatureHelpOptions {
            // Signature help currently reparses overlay source and may perform
            // structured definition lookup, so v1 supports explicit requests
            // without advertising automatic typing triggers.
            trigger_characters: None,
            retrigger_characters: None,
            work_done_progress_options: WorkDoneProgressOptions::default(),
        }),
        definition_provider: Some(OneOf::Left(true)),
        type_definition_provider: Some(TypeDefinitionProviderCapability::Simple(true)),
        implementation_provider: Some(ImplementationProviderCapability::Simple(true)),
        document_highlight_provider: Some(OneOf::Left(true)),
        document_symbol_provider: Some(OneOf::Left(true)),
        document_formatting_provider: Some(OneOf::Right(DocumentFormattingOptions {
            work_done_progress_options: WorkDoneProgressOptions::default(),
        })),
        folding_range_provider: Some(FoldingRangeProviderCapability::Simple(true)),
        hover_provider: Some(HoverProviderCapability::Simple(true)),
        references_provider: Some(OneOf::Left(true)),
        rename_provider: Some(OneOf::Right(RenameOptions {
            prepare_provider: Some(true),
            work_done_progress_options: WorkDoneProgressOptions::default(),
        })),
        workspace_symbol_provider: Some(OneOf::Left(true)),
        diagnostic_provider: Some(DiagnosticServerCapabilities::Options(DiagnosticOptions {
            identifier: Some("bifrost-tree-sitter".to_string()),
            inter_file_dependencies: false,
            workspace_diagnostics: false,
            work_done_progress_options: WorkDoneProgressOptions::default(),
        })),
        workspace: Some(lsp_types::WorkspaceServerCapabilities {
            workspace_folders: Some(WorkspaceFoldersServerCapabilities {
                supported: Some(true),
                change_notifications: Some(OneOf::Left(true)),
            }),
            file_operations: None,
        }),
        // Per-feature capabilities are turned on as their handlers land.
        ..ServerCapabilities::default()
    }
}

fn completion_provider(client_capabilities: &ClientCapabilities) -> Option<CompletionOptions> {
    let completion = client_capabilities
        .text_document
        .as_ref()
        .and_then(|text_document| text_document.completion.as_ref())?;
    if !has_completion_sub_capability(completion) {
        return None;
    }
    Some(CompletionOptions {
        // v1: client must invoke completion explicitly. We don't expose
        // trigger characters because identifier-prefix-only completion
        // isn't meaningful on `.` or `::` (we don't resolve qualified
        // names yet).
        resolve_provider: Some(false),
        ..CompletionOptions::default()
    })
}

fn has_completion_sub_capability(completion: &CompletionClientCapabilities) -> bool {
    completion.dynamic_registration.is_some()
        || completion.completion_item.is_some()
        || completion.completion_item_kind.is_some()
        || completion.context_support.is_some()
        || completion.insert_text_mode.is_some()
        || completion.completion_list.is_some()
}
