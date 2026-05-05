use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use lsp_server::{Connection, ErrorCode, ExtractError, IoThreads, Message, Notification, Request, Response};
use lsp_types::notification::{
    DidChangeWatchedFiles, DidSaveTextDocument, Notification as LspNotificationTrait,
};
use lsp_types::request::{
    DocumentDiagnosticRequest, DocumentSymbolRequest, GotoDefinition, HoverRequest, References,
    Request as LspRequestTrait, WorkspaceSymbolRequest,
};
use lsp_types::{
    DidChangeWatchedFilesParams, DidSaveTextDocumentParams, FileChangeType, InitializeParams,
};

use crate::analyzer::{AnalyzerConfig, FilesystemProject, Project, WorkspaceAnalyzer};
use crate::lsp::capabilities::server_capabilities;
use crate::lsp::conversion::uri_to_path;
use crate::lsp::handlers::util::project_file_for_uri as resolve_project_file;
use crate::lsp::handlers::{
    definition, diagnostic, document_symbol, hover, references, workspace_symbol,
};

/// Run the LSP server over stdio. `fallback_root` is used when the client does
/// not advertise a `workspaceFolders[0]`. Returns when the client sends
/// `exit` (after the standard `shutdown` request) or the connection drops.
pub fn run_lsp_stdio_server(fallback_root: PathBuf) -> Result<(), String> {
    let (connection, io_threads) = Connection::stdio();
    run_with_connection(connection, io_threads, fallback_root)
}

pub(crate) fn run_with_connection(
    connection: Connection,
    io_threads: IoThreads,
    fallback_root: PathBuf,
) -> Result<(), String> {
    let server_capabilities = serde_json::to_value(server_capabilities())
        .map_err(|err| format!("Failed to serialize LSP server capabilities: {err}"))?;

    let init_params_value = connection
        .initialize(server_capabilities)
        .map_err(|err| format!("LSP initialize failed: {err}"))?;
    let init_params: InitializeParams = serde_json::from_value(init_params_value)
        .map_err(|err| format!("Failed to decode InitializeParams: {err}"))?;

    let workspace_root = pick_workspace_root(&init_params, fallback_root.as_path());
    let mut state = ServerState::new(workspace_root)?;

    let result = main_loop(&connection, &mut state);
    // Drop the connection before joining the IO threads so the writer thread
    // sees its sender close and exits — otherwise io_threads.join() blocks
    // forever on a still-live writer channel.
    drop(connection);
    io_threads
        .join()
        .map_err(|err| format!("LSP IO threads failed: {err}"))?;
    result
}

fn main_loop(connection: &Connection, state: &mut ServerState) -> Result<(), String> {
    for msg in &connection.receiver {
        match msg {
            Message::Request(req) => {
                if connection
                    .handle_shutdown(&req)
                    .map_err(|err| format!("LSP shutdown handling failed: {err}"))?
                {
                    return Ok(());
                }
                handle_request(connection, state, req)?;
            }
            Message::Notification(note) => handle_notification(state, note)?,
            Message::Response(_) => {
                // We do not currently send server→client requests, so any
                // inbound Response is unsolicited and safe to ignore.
            }
        }
    }
    Ok(())
}

fn handle_request(
    connection: &Connection,
    state: &mut ServerState,
    req: Request,
) -> Result<(), String> {
    let id = req.id.clone();
    let response = match req.method.as_str() {
        DocumentSymbolRequest::METHOD => decode_and_run::<DocumentSymbolRequest, _>(req, |params| {
            Ok(document_symbol::handle(
                &state.workspace,
                state.project.root(),
                &params,
            ))
        }),
        WorkspaceSymbolRequest::METHOD => decode_and_run::<WorkspaceSymbolRequest, _>(req, |params| {
            Ok(workspace_symbol::handle(&state.workspace, &params))
        }),
        GotoDefinition::METHOD => decode_and_run::<GotoDefinition, _>(req, |params| {
            Ok(definition::handle(
                &state.workspace,
                state.project.root(),
                &params,
            ))
        }),
        HoverRequest::METHOD => decode_and_run::<HoverRequest, _>(req, |params| {
            Ok(hover::handle(&state.workspace, state.project.root(), &params))
        }),
        References::METHOD => decode_and_run::<References, _>(req, |params| {
            Ok(references::handle(
                &state.workspace,
                state.project.root(),
                &params,
            ))
        }),
        DocumentDiagnosticRequest::METHOD => {
            decode_and_run::<DocumentDiagnosticRequest, _>(req, |params| {
                Ok(diagnostic::handle(state.project.root(), &params))
            })
        }
        _ => Response::new_err(
            id,
            ErrorCode::MethodNotFound as i32,
            format!("Method not implemented: {}", req.method),
        ),
    };
    connection
        .sender
        .send(Message::Response(response))
        .map_err(|err| format!("Failed to send LSP response: {err}"))
}

/// Decode the typed params for an LSP request and run `handler`, mapping any
/// failure into a JSON-RPC error response that preserves the original id.
fn decode_and_run<R, F>(req: Request, handler: F) -> Response
where
    R: lsp_types::request::Request,
    R::Params: serde::de::DeserializeOwned,
    R::Result: serde::Serialize,
    F: FnOnce(R::Params) -> Result<R::Result, String>,
{
    let id = req.id.clone();
    let method = req.method.clone();
    let params = match req.extract::<R::Params>(<R as lsp_types::request::Request>::METHOD) {
        Ok((_, params)) => params,
        Err(ExtractError::JsonError { error, .. }) => {
            return Response::new_err(
                id,
                ErrorCode::InvalidParams as i32,
                format!("Failed to decode params for {method}: {error}"),
            );
        }
        Err(ExtractError::MethodMismatch(_)) => {
            return Response::new_err(
                id,
                ErrorCode::MethodNotFound as i32,
                format!("Method not implemented: {method}"),
            );
        }
    };
    match handler(params) {
        Ok(result) => match serde_json::to_value(result) {
            Ok(value) => Response::new_ok(id, value),
            Err(err) => Response::new_err(
                id,
                ErrorCode::InternalError as i32,
                format!("Failed to serialize {method} result: {err}"),
            ),
        },
        Err(message) => Response::new_err(id, ErrorCode::InternalError as i32, message),
    }
}

fn handle_notification(state: &mut ServerState, note: Notification) -> Result<(), String> {
    match note.method.as_str() {
        DidSaveTextDocument::METHOD => {
            let params: DidSaveTextDocumentParams =
                serde_json::from_value(note.params).map_err(|err| {
                    format!("Failed to decode {} params: {err}", DidSaveTextDocument::METHOD)
                })?;
            if let Some(file) =
                resolve_project_file(state.project.root(), &params.text_document.uri)
            {
                let mut changed = BTreeSet::new();
                changed.insert(file);
                state.workspace = state.workspace.update(&changed);
            }
            Ok(())
        }
        DidChangeWatchedFiles::METHOD => {
            let params: DidChangeWatchedFilesParams =
                serde_json::from_value(note.params).map_err(|err| {
                    format!(
                        "Failed to decode {} params: {err}",
                        DidChangeWatchedFiles::METHOD
                    )
                })?;
            // Treat created/changed/deleted uniformly — the analyzer's
            // update path re-reads from disk, so it handles both new content
            // and disappearance correctly.
            let mut changed = BTreeSet::new();
            for change in params.changes {
                if matches!(
                    change.typ,
                    FileChangeType::CREATED | FileChangeType::CHANGED | FileChangeType::DELETED
                )
                    && let Some(file) = resolve_project_file(state.project.root(), &change.uri)
                {
                    changed.insert(file);
                }
            }
            if !changed.is_empty() {
                state.workspace = state.workspace.update(&changed);
            }
            Ok(())
        }
        _ => {
            // `initialized` and every unsupported notification falls through;
            // unknown notifications are spec-required to be silently ignored.
            Ok(())
        }
    }
}

pub(crate) struct ServerState {
    workspace: WorkspaceAnalyzer,
    project: Arc<dyn Project>,
}

impl ServerState {
    fn new(root: PathBuf) -> Result<Self, String> {
        let project: Arc<dyn Project> = Arc::new(
            FilesystemProject::new(&root)
                .map_err(|err| format!("Failed to initialize project root {}: {err}", root.display()))?,
        );
        let workspace = WorkspaceAnalyzer::build(Arc::clone(&project), AnalyzerConfig::default());
        Ok(Self { workspace, project })
    }
}

fn pick_workspace_root(params: &InitializeParams, fallback: &Path) -> PathBuf {
    if let Some(folders) = &params.workspace_folders
        && let Some(first) = folders.first()
        && let Some(path) = uri_to_path(&first.uri)
    {
        return path;
    }

    // `root_uri` and the long-deprecated `root_path` are still common.
    #[allow(deprecated)]
    if let Some(uri) = &params.root_uri
        && let Some(path) = uri_to_path(uri)
    {
        return path;
    }
    #[allow(deprecated)]
    if let Some(root_path) = &params.root_path {
        return PathBuf::from(root_path);
    }

    fallback.to_path_buf()
}
