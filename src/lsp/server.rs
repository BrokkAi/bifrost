use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use lsp_server::{
    Connection, ErrorCode, ExtractError, IoThreads, Message, Notification, Request, Response,
};
use lsp_types::notification::{
    DidChangeTextDocument, DidChangeWatchedFiles, DidCloseTextDocument, DidOpenTextDocument,
    DidSaveTextDocument, Notification as LspNotificationTrait, PublishDiagnostics,
};
use lsp_types::request::{
    Completion, DocumentDiagnosticRequest, DocumentHighlightRequest, DocumentSymbolRequest,
    FoldingRangeRequest, GotoDefinition, HoverRequest, References, Request as LspRequestTrait,
    TypeHierarchyPrepare, TypeHierarchySubtypes, TypeHierarchySupertypes, WorkspaceSymbolRequest,
};
use lsp_types::{
    DidChangeTextDocumentParams, DidChangeWatchedFilesParams, DidCloseTextDocumentParams,
    DidOpenTextDocumentParams, DidSaveTextDocumentParams, FileChangeType, InitializeParams,
    PublishDiagnosticsParams, Uri,
};

use crate::analyzer::{
    AnalyzerConfig, FilesystemProject, OverlayProject, Project, WorkspaceAnalyzer,
};
use crate::lsp::capabilities::server_capabilities;
use crate::lsp::conversion::uri_to_path;
use crate::lsp::handlers::util::project_file_for_uri as resolve_project_file;
use crate::lsp::handlers::{
    completion, definition, diagnostic, document_highlight, document_symbol, folding_range, hover,
    references, type_hierarchy, workspace_symbol,
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
    let server_capabilities = server_capabilities_json()?;

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

fn server_capabilities_json() -> Result<serde_json::Value, String> {
    let mut capabilities = serde_json::to_value(server_capabilities())
        .map_err(|err| format!("Failed to serialize LSP server capabilities: {err}"))?;
    if let Some(object) = capabilities.as_object_mut() {
        // lsp-types 0.97 has the type-hierarchy request/response types but no
        // ServerCapabilities field for this standard 3.17+ capability.
        object.insert(
            "typeHierarchyProvider".to_string(),
            serde_json::Value::Bool(true),
        );
    }
    Ok(capabilities)
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
            Message::Notification(note) => handle_notification(connection, state, note)?,
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
        DocumentSymbolRequest::METHOD => {
            decode_and_run::<DocumentSymbolRequest, _>(req, |params| {
                Ok(document_symbol::handle(
                    &state.workspace,
                    state.project(),
                    &params,
                ))
            })
        }
        FoldingRangeRequest::METHOD => decode_and_run::<FoldingRangeRequest, _>(req, |params| {
            Ok(folding_range::handle(
                &state.workspace,
                state.project(),
                &params,
            ))
        }),
        WorkspaceSymbolRequest::METHOD => {
            decode_and_run::<WorkspaceSymbolRequest, _>(req, |params| {
                Ok(workspace_symbol::handle(&state.workspace, &params))
            })
        }
        GotoDefinition::METHOD => decode_and_run::<GotoDefinition, _>(req, |params| {
            Ok(definition::handle(
                &state.workspace,
                state.project(),
                &params,
            ))
        }),
        HoverRequest::METHOD => decode_and_run::<HoverRequest, _>(req, |params| {
            Ok(hover::handle(&state.workspace, state.project(), &params))
        }),
        Completion::METHOD => decode_and_run::<Completion, _>(req, |params| {
            // Borrow the overlay field directly (not via `state.project()`) so
            // it disjoint-borrows from `&mut state.completion_cache`.
            Ok(completion::handle(
                &mut state.completion_cache,
                &state.workspace,
                state.overlay.as_ref(),
                &params,
            ))
        }),
        References::METHOD => decode_and_run::<References, _>(req, |params| {
            Ok(references::handle(
                &state.workspace,
                state.project(),
                &params,
            ))
        }),
        DocumentHighlightRequest::METHOD => {
            decode_and_run::<DocumentHighlightRequest, _>(req, |params| {
                Ok(document_highlight::handle(
                    &state.workspace,
                    state.project(),
                    &params,
                ))
            })
        }
        DocumentDiagnosticRequest::METHOD => {
            decode_and_run::<DocumentDiagnosticRequest, _>(req, |params| {
                Ok(diagnostic::handle(
                    &state.workspace,
                    state.project(),
                    &params,
                ))
            })
        }
        TypeHierarchyPrepare::METHOD => decode_and_run::<TypeHierarchyPrepare, _>(req, |params| {
            Ok(type_hierarchy::prepare(
                &state.workspace,
                state.project(),
                &params,
            ))
        }),
        TypeHierarchySupertypes::METHOD => {
            decode_and_run::<TypeHierarchySupertypes, _>(req, |params| {
                Ok(type_hierarchy::supertypes(
                    &state.workspace,
                    state.project(),
                    &params,
                ))
            })
        }
        TypeHierarchySubtypes::METHOD => {
            decode_and_run::<TypeHierarchySubtypes, _>(req, |params| {
                Ok(type_hierarchy::subtypes(
                    &state.workspace,
                    state.project(),
                    &params,
                ))
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

fn handle_notification(
    connection: &Connection,
    state: &mut ServerState,
    note: Notification,
) -> Result<(), String> {
    match note.method.as_str() {
        DidOpenTextDocument::METHOD => {
            let params: DidOpenTextDocumentParams =
                serde_json::from_value(note.params).map_err(|err| {
                    format!(
                        "Failed to decode {} params: {err}",
                        DidOpenTextDocument::METHOD
                    )
                })?;
            if let Some(file) =
                resolve_project_file(state.project().root(), &params.text_document.uri)
            {
                state
                    .overlay
                    .set(file.abs_path(), params.text_document.text);
                state.completion_cache.invalidate(&file.abs_path());
                let mut changed = BTreeSet::new();
                changed.insert(file);
                state.workspace = state.workspace.update(&changed);
                publish_diagnostics(
                    connection,
                    &state.workspace,
                    state.project(),
                    &params.text_document.uri,
                )?;
            }
            Ok(())
        }
        DidChangeTextDocument::METHOD => {
            let params: DidChangeTextDocumentParams =
                serde_json::from_value(note.params).map_err(|err| {
                    format!(
                        "Failed to decode {} params: {err}",
                        DidChangeTextDocument::METHOD
                    )
                })?;
            // With TextDocumentSyncKind::FULL each event has `range = None`
            // and `text` = full document. We capability-advertise FULL, but
            // tolerate non-conforming clients by taking the *last* event
            // that looks full-document — anything else, drop the
            // notification rather than apply a malformed partial edit.
            let uri = params.text_document.uri;
            let n_changes = params.content_changes.len();
            let full_text = params
                .content_changes
                .into_iter()
                .rev()
                .find(|change| change.range.is_none())
                .map(|change| change.text);
            if let Some(file) = resolve_project_file(state.project().root(), &uri) {
                match full_text {
                    Some(text) => {
                        state.overlay.set(file.abs_path(), text);
                        state.completion_cache.invalidate(&file.abs_path());
                        let mut changed = BTreeSet::new();
                        changed.insert(file);
                        state.workspace = state.workspace.update(&changed);
                        publish_diagnostics(connection, &state.workspace, state.project(), &uri)?;
                    }
                    None if n_changes > 0 => {
                        // Non-conforming client: it sent events but none was
                        // full-document. Drop the notification (we have no
                        // way to apply incremental ranges) but warn so the
                        // user can debug "edits aren't reflected" instead of
                        // silently diverging from the buffer.
                        state.maybe_log_malformed_didchange(&uri, n_changes);
                    }
                    None => {
                        // Empty content_changes — spec-permitted no-op. Stay
                        // silent.
                    }
                }
            }
            Ok(())
        }
        DidCloseTextDocument::METHOD => {
            let params: DidCloseTextDocumentParams =
                serde_json::from_value(note.params).map_err(|err| {
                    format!(
                        "Failed to decode {} params: {err}",
                        DidCloseTextDocument::METHOD
                    )
                })?;
            if let Some(file) =
                resolve_project_file(state.project().root(), &params.text_document.uri)
            {
                // Only reparse if we actually had an overlay — close without a
                // prior open is a spec-permitted nop (e.g. some clients send it
                // for files the server never opened).
                if state.overlay.clear(&file.abs_path()) {
                    state.completion_cache.invalidate(&file.abs_path());
                    let mut changed = BTreeSet::new();
                    changed.insert(file);
                    state.workspace = state.workspace.update(&changed);
                    publish_diagnostics(
                        connection,
                        &state.workspace,
                        state.project(),
                        &params.text_document.uri,
                    )?;
                }
            }
            Ok(())
        }
        DidSaveTextDocument::METHOD => {
            let params: DidSaveTextDocumentParams =
                serde_json::from_value(note.params).map_err(|err| {
                    format!(
                        "Failed to decode {} params: {err}",
                        DidSaveTextDocument::METHOD
                    )
                })?;
            if let Some(file) =
                resolve_project_file(state.project().root(), &params.text_document.uri)
            {
                // Drop completion's mtime-cached content first — the save just
                // bumped the file's mtime, but we want the next completion
                // request to refresh from disk even if the editor's mtime is
                // older than our cached one (which happens with editors that
                // write atomically via rename + stat-preserving copy).
                state.completion_cache.invalidate(&file.abs_path());
                let mut changed = BTreeSet::new();
                changed.insert(file);
                state.workspace = state.workspace.update(&changed);
                // Push diagnostics for clients that don't poll the pull-model
                // textDocument/diagnostic endpoint. Clients that DO poll just
                // receive the same items twice, which is benign. Skip when
                // the URI is outside the project — otherwise we'd publish an
                // empty array for a URI we never published for, and a few
                // clients (e.g. some Sublime LSP frontends) create empty
                // diagnostic state for any URI the server publishes for.
                publish_diagnostics(
                    connection,
                    &state.workspace,
                    state.project(),
                    &params.text_document.uri,
                )?;
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
                ) && let Some(file) = resolve_project_file(state.project().root(), &change.uri)
                {
                    state.completion_cache.invalidate(&file.abs_path());
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

/// Send a `textDocument/publishDiagnostics` notification with the current
/// parse-error report for `uri`. We always send — even when the diagnostic
/// list is empty — so clients clear stale diagnostics from a previous save.
fn publish_diagnostics(
    connection: &Connection,
    workspace: &WorkspaceAnalyzer,
    project: &dyn Project,
    uri: &Uri,
) -> Result<(), String> {
    let diagnostics = diagnostic::collect(workspace, project, uri);
    let params = PublishDiagnosticsParams {
        uri: uri.clone(),
        diagnostics,
        version: None,
    };
    let note = Notification::new(PublishDiagnostics::METHOD.to_string(), params);
    connection
        .sender
        .send(Message::Notification(note))
        .map_err(|err| format!("Failed to send publishDiagnostics: {err}"))
}

pub(crate) struct ServerState {
    workspace: WorkspaceAnalyzer,
    /// The `OverlayProject` is shared with the analyzer (via `Arc<dyn Project>`
    /// inside `WorkspaceAnalyzer`) and with request-time read paths in
    /// `handlers::util::read_document_for_uri`. did{Open,Change,Close}
    /// notifications mutate the overlay store in-place; analyzer reparses and
    /// LSP reads observe the new content on the next call.
    overlay: Arc<OverlayProject>,
    /// Owned by `textDocument/completion`. Lives on `ServerState` because the
    /// handler is invoked per-keystroke and benefits from mtime-checked
    /// caching of file content + line offsets. Other handlers (hover,
    /// definition, references) fire far less often, so they continue to
    /// re-read on every request without sharing this cache.
    completion_cache: completion::CompletionCache,
    /// Last instant we logged a malformed `didChange` for a given URI. Used
    /// to throttle the warning to one line per URI per
    /// [`MALFORMED_DIDCHANGE_LOG_THROTTLE`] — a misbehaving client sending
    /// incremental events per keystroke would otherwise flood stderr.
    malformed_didchange_log: Mutex<HashMap<String, Instant>>,
}

/// Minimum interval between stderr lines reporting a malformed `didChange`
/// for the same URI. Mirrors the cadence of `OVERLAY_REJECTION_LOG_THROTTLE`
/// in the analyzer layer.
const MALFORMED_DIDCHANGE_LOG_THROTTLE: Duration = Duration::from_secs(60);

/// Soft cap on the malformed-didChange throttle map. Same rationale as
/// `OVERLAY_REJECTION_LOG_MAX_ENTRIES`: a sloppy or hostile client could
/// otherwise send a stream of distinct URIs and grow the map without bound.
const MALFORMED_DIDCHANGE_LOG_MAX_ENTRIES: usize = 256;

impl ServerState {
    fn new(root: PathBuf) -> Result<Self, String> {
        let filesystem: Arc<dyn Project> =
            Arc::new(FilesystemProject::new(&root).map_err(|err| {
                format!(
                    "Failed to initialize project root {}: {err}",
                    root.display()
                )
            })?);
        let overlay = Arc::new(OverlayProject::new(filesystem));
        let workspace = WorkspaceAnalyzer::build(
            Arc::clone(&overlay) as Arc<dyn Project>,
            AnalyzerConfig::default(),
        );
        Ok(Self {
            workspace,
            overlay,
            completion_cache: completion::CompletionCache::new(),
            malformed_didchange_log: Mutex::new(HashMap::new()),
        })
    }

    pub(crate) fn project(&self) -> &dyn Project {
        self.overlay.as_ref()
    }

    /// Emit a single stderr warning for `uri` if we haven't logged one
    /// within [`MALFORMED_DIDCHANGE_LOG_THROTTLE`]. The throttle map is
    /// bounded; entries older than the throttle window are pruned when it
    /// fills.
    fn maybe_log_malformed_didchange(&self, uri: &Uri, n_changes: usize) {
        let now = Instant::now();
        let should_log = {
            let mut log = self
                .malformed_didchange_log
                .lock()
                .expect("malformed didChange log poisoned");
            let key = uri.as_str();
            let recent = log
                .get(key)
                .map(|last| now.duration_since(*last) < MALFORMED_DIDCHANGE_LOG_THROTTLE)
                .unwrap_or(false);
            if recent {
                false
            } else {
                if log.len() >= MALFORMED_DIDCHANGE_LOG_MAX_ENTRIES {
                    log.retain(|_, last| {
                        now.duration_since(*last) < MALFORMED_DIDCHANGE_LOG_THROTTLE
                    });
                    if log.len() >= MALFORMED_DIDCHANGE_LOG_MAX_ENTRIES {
                        log.clear();
                    }
                }
                log.insert(key.to_string(), now);
                true
            }
        };
        if should_log {
            eprintln!(
                "[bifrost-lsp] dropping didChange for {}: {n_changes} content_change events but none was a full-document replacement (server advertises TextDocumentSyncKind::FULL)",
                uri.as_str(),
            );
        }
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
