use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use lsp_server::{
    Connection, ErrorCode, ExtractError, IoThreads, Message, Notification, Request, RequestId,
    Response,
};
use lsp_types::notification::{
    DidChangeTextDocument, DidChangeWatchedFiles, DidCloseTextDocument, DidOpenTextDocument,
    DidSaveTextDocument, Notification as LspNotificationTrait, Progress, PublishDiagnostics,
};
use lsp_types::request::{
    CallHierarchyIncomingCalls, CallHierarchyOutgoingCalls, CallHierarchyPrepare, Completion,
    DocumentDiagnosticRequest, DocumentHighlightRequest, DocumentSymbolRequest,
    FoldingRangeRequest, GotoDefinition, HoverRequest, References, Request as LspRequestTrait,
    TypeHierarchyPrepare, TypeHierarchySubtypes, TypeHierarchySupertypes, WorkDoneProgressCreate,
    WorkspaceSymbolRequest,
};
use lsp_types::{
    DidChangeTextDocumentParams, DidChangeWatchedFilesParams, DidCloseTextDocumentParams,
    DidOpenTextDocumentParams, DidSaveTextDocumentParams, FileChangeType, InitializeParams,
    ProgressParams, ProgressParamsValue, ProgressToken, PublishDiagnosticsParams, Uri,
    WorkDoneProgress, WorkDoneProgressBegin, WorkDoneProgressCreateParams, WorkDoneProgressEnd,
    WorkDoneProgressReport,
};

use crate::analyzer::persistence::{AnalyzerStorage, default_db_path};
use crate::analyzer::{
    AnalyzerConfig, BuildProgressEvent, BuildProgressPhase, FilesystemProject, MultiRootProject,
    OverlayProject, Project, WorkspaceAnalyzer,
};
use crate::lsp::capabilities::server_capabilities;
use crate::lsp::conversion::uri_to_path;
use crate::lsp::handlers::util::{
    project_file_for_uri as resolve_project_file,
    project_file_for_uri_allow_missing as resolve_project_file_allow_missing,
};
use crate::lsp::handlers::{
    call_hierarchy, completion, definition, diagnostic, document_highlight, document_symbol,
    folding_range, hover, references, type_hierarchy, workspace_symbol,
};

/// Run the LSP server over stdio. `fallback_root` is used when the client does
/// not advertise usable workspace folders or legacy root params. Returns when
/// the client sends `exit` (after the standard `shutdown` request) or the
/// connection drops.
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
    let supports_work_done_progress = raw_client_supports_work_done_progress(&init_params_value);
    let init_params: InitializeParams = serde_json::from_value(init_params_value)
        .map_err(|err| format!("Failed to decode InitializeParams: {err}"))?;

    let workspace_roots = collect_workspace_roots(&init_params, fallback_root.as_path());
    let progress = if supports_work_done_progress {
        StartupProgress::create(&connection, "bifrost-startup-index".to_string())?
    } else {
        None
    };

    if let Some(progress) = progress.as_ref() {
        progress.begin("Indexing workspace")?;
    }

    let state_result = ServerState::new(workspace_roots, progress.as_ref());
    if let Some(progress) = progress.as_ref() {
        let message = if state_result.is_ok() {
            "Indexing complete"
        } else {
            "Indexing failed"
        };
        progress.end(message)?;
    }
    let mut state = state_result?;

    let result = main_loop(&connection, &mut state);
    drop(progress);
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
        object.insert(
            "callHierarchyProvider".to_string(),
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

fn raw_client_supports_work_done_progress(params: &serde_json::Value) -> bool {
    params
        .pointer("/capabilities/window/workDoneProgress")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
}

struct StartupProgress {
    token: ProgressToken,
    send_message: Arc<dyn Fn(Message) -> Result<(), String> + Send + Sync>,
    state: Arc<Mutex<StartupProgressState>>,
}

#[derive(Default)]
struct StartupProgressState {
    last_parse_report_by_language: HashMap<crate::analyzer::Language, usize>,
}

impl StartupProgress {
    fn create(connection: &Connection, token: String) -> Result<Option<Self>, String> {
        let request_id = RequestId::from("bifrost-startup-progress-create".to_string());
        let token = ProgressToken::String(token);
        let request = Request::new(
            request_id.clone(),
            WorkDoneProgressCreate::METHOD.to_string(),
            WorkDoneProgressCreateParams {
                token: token.clone(),
            },
        );
        connection
            .sender
            .send(Message::Request(request))
            .map_err(|err| format!("Failed to request work-done progress token: {err}"))?;
        if !Self::wait_for_create_response(connection, &request_id)? {
            return Ok(None);
        }
        let sender = connection.sender.clone();
        Ok(Some(Self {
            token,
            send_message: Arc::new(move |message| {
                sender
                    .send(message)
                    .map_err(|err| format!("Failed to send LSP progress message: {err}"))
            }),
            state: Arc::new(Mutex::new(StartupProgressState::default())),
        }))
    }

    fn wait_for_create_response(
        connection: &Connection,
        request_id: &RequestId,
    ) -> Result<bool, String> {
        loop {
            match connection.receiver.recv_timeout(Duration::from_secs(5)) {
                Ok(Message::Response(response)) if response.id == *request_id => {
                    return Ok(response.error.is_none());
                }
                Ok(Message::Response(_)) => continue,
                Ok(Message::Notification(note)) if note.method == "initialized" => continue,
                Ok(message) => {
                    return Err(format!(
                        "Unexpected LSP message before startup progress token response: {message:?}"
                    ));
                }
                Err(_) => return Ok(false),
            }
        }
    }

    fn clone_for_callback(&self) -> Self {
        Self {
            token: self.token.clone(),
            send_message: Arc::clone(&self.send_message),
            state: Arc::clone(&self.state),
        }
    }

    fn begin(&self, title: &str) -> Result<(), String> {
        self.send(WorkDoneProgress::Begin(WorkDoneProgressBegin {
            title: title.to_string(),
            cancellable: Some(false),
            message: Some("Preparing workspace index".to_string()),
            percentage: Some(0),
        }))
    }

    fn report_analyzer_event(&self, event: BuildProgressEvent) {
        let should_report = {
            let mut state = self.state.lock().expect("startup progress state poisoned");
            should_report_progress_event(&mut state, &event)
        };
        if !should_report {
            return;
        }
        let _ = self.send(WorkDoneProgress::Report(WorkDoneProgressReport {
            cancellable: Some(false),
            message: Some(progress_message_for_event(&event)),
            percentage: None,
        }));
    }

    fn end(&self, message: &str) -> Result<(), String> {
        self.send(WorkDoneProgress::End(WorkDoneProgressEnd {
            message: Some(message.to_string()),
        }))
    }

    fn send(&self, value: WorkDoneProgress) -> Result<(), String> {
        let note = Notification::new(
            Progress::METHOD.to_string(),
            ProgressParams {
                token: self.token.clone(),
                value: ProgressParamsValue::WorkDone(value),
            },
        );
        (self.send_message)(Message::Notification(note))
    }
}

fn progress_message_for_event(event: &BuildProgressEvent) -> String {
    match event.phase {
        BuildProgressPhase::Enumerate => {
            format!("Found {} {:?} file(s)", event.total, event.language)
        }
        BuildProgressPhase::Reconcile => format!(
            "Reconciled {:?}: {} cached of {} file(s)",
            event.language, event.completed, event.total
        ),
        BuildProgressPhase::Parse => format!(
            "Parsed {:?} files: {} of {}",
            event.language, event.completed, event.total
        ),
        BuildProgressPhase::Persist => {
            format!("Updated {:?} index cache", event.language)
        }
        BuildProgressPhase::Index => format!("Indexed {:?} declarations", event.language),
    }
}

fn should_report_progress_event(
    state: &mut StartupProgressState,
    event: &BuildProgressEvent,
) -> bool {
    const PARSE_REPORT_INTERVAL: usize = 50;
    match event.phase {
        BuildProgressPhase::Parse => {
            if event.completed == 1 || event.completed >= event.total {
                state
                    .last_parse_report_by_language
                    .insert(event.language, event.completed);
                return true;
            }
            let last = state
                .last_parse_report_by_language
                .get(&event.language)
                .copied()
                .unwrap_or(0);
            if event.completed.saturating_sub(last) >= PARSE_REPORT_INTERVAL {
                state
                    .last_parse_report_by_language
                    .insert(event.language, event.completed);
                true
            } else {
                false
            }
        }
        _ => true,
    }
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
        CallHierarchyPrepare::METHOD => decode_and_run::<CallHierarchyPrepare, _>(req, |params| {
            Ok(call_hierarchy::prepare(
                &state.workspace,
                state.project(),
                &params,
            ))
        }),
        CallHierarchyIncomingCalls::METHOD => {
            decode_and_run::<CallHierarchyIncomingCalls, _>(req, |params| {
                Ok(call_hierarchy::incoming_calls(
                    &state.workspace,
                    state.project(),
                    &params,
                ))
            })
        }
        CallHierarchyOutgoingCalls::METHOD => {
            decode_and_run::<CallHierarchyOutgoingCalls, _>(req, |params| {
                Ok(call_hierarchy::outgoing_calls(
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
            if let Some(file) = resolve_project_file(state.project(), &params.text_document.uri) {
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
            if let Some(file) = resolve_project_file(state.project(), &uri) {
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
            if let Some(file) = resolve_project_file(state.project(), &params.text_document.uri) {
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
            if let Some(file) = resolve_project_file(state.project(), &params.text_document.uri) {
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
                ) && let Some(file) =
                    resolve_project_file_allow_missing(state.project(), &change.uri)
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
    fn new(roots: Vec<PathBuf>, progress: Option<&StartupProgress>) -> Result<Self, String> {
        let project: Arc<dyn Project> = if roots.len() == 1 {
            let root = roots
                .into_iter()
                .next()
                .expect("single-root state should contain one root");
            Arc::new(FilesystemProject::new(&root).map_err(|err| {
                format!(
                    "Failed to initialize project root {}: {err}",
                    root.display()
                )
            })?)
        } else {
            Arc::new(
                MultiRootProject::new(roots)
                    .map_err(|err| format!("Failed to initialize multi-root project: {err}"))?,
            )
        };
        let overlay = Arc::new(OverlayProject::new(project));
        let project = Arc::clone(&overlay) as Arc<dyn Project>;
        let workspace = build_workspace_for_lsp(project, progress);
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

fn build_workspace_for_lsp(
    project: Arc<dyn Project>,
    progress: Option<&StartupProgress>,
) -> WorkspaceAnalyzer {
    let config = AnalyzerConfig::default();
    match progress {
        Some(progress) => {
            let progress = progress.clone_for_callback();
            let Some(persistence_root) = project.persistence_root() else {
                return WorkspaceAnalyzer::build(project, config);
            };
            match AnalyzerStorage::open(default_db_path(persistence_root))
                .ok()
                .map(Arc::new)
            {
                Some(storage) => WorkspaceAnalyzer::build_with_storage_and_progress(
                    project,
                    config,
                    storage,
                    move |event| progress.report_analyzer_event(event),
                ),
                None => WorkspaceAnalyzer::build(project, config),
            }
        }
        None => WorkspaceAnalyzer::build(project, config),
    }
}

fn collect_workspace_roots(params: &InitializeParams, fallback: &Path) -> Vec<PathBuf> {
    if let Some(folders) = &params.workspace_folders {
        let roots: Vec<PathBuf> = folders
            .iter()
            .filter_map(|folder| workspace_folder_path(&folder.uri))
            .collect();
        if !roots.is_empty() {
            return roots;
        }
    }

    // `root_uri` and the long-deprecated `root_path` are still common, and
    // remain the fallback when no usable startup workspace folders were sent.
    #[allow(deprecated)]
    if let Some(uri) = &params.root_uri
        && let Some(path) = uri_to_path(uri)
    {
        return vec![path];
    }
    #[allow(deprecated)]
    if let Some(root_path) = &params.root_path {
        return vec![PathBuf::from(root_path)];
    }

    vec![fallback.to_path_buf()]
}

fn workspace_folder_path(uri: &Uri) -> Option<PathBuf> {
    let Some(path) = uri_to_path(uri) else {
        eprintln!(
            "[bifrost-lsp] ignoring non-file workspace folder URI: {}",
            uri.as_str()
        );
        return None;
    };
    match path.canonicalize() {
        Ok(path) if path.is_dir() => Some(path),
        Ok(path) => {
            eprintln!(
                "[bifrost-lsp] ignoring workspace folder that is not a directory: {}",
                path.display()
            );
            None
        }
        Err(err) => {
            eprintln!(
                "[bifrost-lsp] ignoring unavailable workspace folder {}: {err}",
                path.display()
            );
            None
        }
    }
}
