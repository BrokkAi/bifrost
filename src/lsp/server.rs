use std::cell::RefCell;
use std::collections::{BTreeSet, HashMap};
use std::io;
use std::panic;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Once};
use std::thread;
use std::time::{Duration, Instant};

use lsp_server::{
    Connection, ErrorCode, ExtractError, IoThreads, Message, Notification, Request, RequestId,
    Response,
};
use lsp_types::notification::{
    Cancel, DidChangeTextDocument, DidChangeWatchedFiles, DidChangeWorkspaceFolders,
    DidCloseTextDocument, DidOpenTextDocument, DidSaveTextDocument,
    Notification as LspNotificationTrait, Progress, PublishDiagnostics,
};
use lsp_types::request::{
    CallHierarchyIncomingCalls, CallHierarchyOutgoingCalls, CallHierarchyPrepare, Completion,
    DocumentDiagnosticRequest, DocumentHighlightRequest, DocumentSymbolRequest,
    FoldingRangeRequest, Formatting, GotoDefinition, GotoImplementation, GotoTypeDefinition,
    HoverRequest, PrepareRenameRequest, References, Rename, Request as LspRequestTrait,
    SignatureHelpRequest, TypeHierarchyPrepare, TypeHierarchySubtypes, TypeHierarchySupertypes,
    WorkDoneProgressCreate, WorkspaceSymbolRequest,
};
use lsp_types::{
    CancelParams, DidChangeTextDocumentParams, DidChangeWatchedFilesParams,
    DidChangeWorkspaceFoldersParams, DidCloseTextDocumentParams, DidOpenTextDocumentParams,
    DidSaveTextDocumentParams, FileChangeType, InitializeParams, NumberOrString, ProgressParams,
    ProgressParamsValue, ProgressToken, PublishDiagnosticsParams, Uri, WorkDoneProgress,
    WorkDoneProgressBegin, WorkDoneProgressCreateParams, WorkDoneProgressEnd,
    WorkDoneProgressReport,
};

use crate::analyzer::{
    AnalyzerConfig, BuildProgressEvent, BuildProgressPhase, FilesystemProject, MultiRootProject,
    OverlayProject, Project, ProjectFile, WorkspaceAnalyzer,
};
use crate::lsp::capabilities::server_capabilities;
use crate::lsp::conversion::{path_to_uri_string, uri_to_path};
use crate::lsp::handlers::util::{
    project_file_for_abs_path, project_file_for_uri as resolve_project_file,
    project_file_for_uri_allow_missing as resolve_project_file_allow_missing,
};
use crate::lsp::handlers::{
    call_hierarchy, completion, definition, diagnostic, document_highlight, document_symbol,
    folding_range, formatting, hover, references, rename, signature_help, type_definition,
    type_hierarchy, workspace_symbol,
};
use crate::util::throttled_log::ThrottledLog;

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
    install_lsp_panic_hook();

    let (init_id, init_params_value) = connection
        .initialize_start()
        .map_err(|err| format!("LSP initialize failed: {err}"))?;
    let supports_work_done_progress = raw_client_supports_work_done_progress(&init_params_value);
    let init_params: InitializeParams = match serde_json::from_value(init_params_value) {
        Ok(params) => params,
        Err(err) => {
            let message = format!("Failed to decode InitializeParams: {err}");
            return finish_with_initialize_error(
                connection,
                io_threads,
                init_id,
                ErrorCode::InvalidParams as i32,
                message,
            );
        }
    };
    let server_capabilities = server_capabilities_json(&init_params)?;
    connection
        .initialize_finish(
            init_id,
            serde_json::json!({
                "capabilities": server_capabilities,
            }),
        )
        .map_err(|err| format!("LSP initialize failed: {err}"))?;

    let workspace_config = collect_workspace_config(&init_params, fallback_root.as_path())?;
    let mut pending_messages = Vec::new();
    let progress = if supports_work_done_progress {
        StartupProgress::create(
            &connection,
            "bifrost-startup-index".to_string(),
            &mut pending_messages,
        )?
    } else {
        None
    };

    if let Some(progress) = progress.as_ref() {
        progress.begin("Indexing workspace")?;
    }

    let state_result = ServerState::new(workspace_config, progress.as_ref());
    if let Some(progress) = progress.as_ref() {
        let message = if state_result.is_ok() {
            "Indexing complete"
        } else {
            "Indexing failed"
        };
        progress.end(message)?;
    }
    let mut state = state_result?;

    let result = main_loop(&connection, &mut state, pending_messages);
    state.formatting_jobs.cancel_all();
    state
        .formatting_jobs
        .wait_for_empty(FORMATTER_SHUTDOWN_GRACE);
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

fn finish_with_initialize_error(
    connection: Connection,
    io_threads: IoThreads,
    init_id: RequestId,
    code: i32,
    message: String,
) -> Result<(), String> {
    connection
        .sender
        .send(Message::Response(Response::new_err(
            init_id,
            code,
            message.clone(),
        )))
        .map_err(|send_err| format!("Failed to send LSP initialize error: {send_err}"))?;
    drop(connection);
    io_threads
        .join()
        .map_err(|err| format!("LSP IO threads failed after initialize error: {err}"))?;
    Err(message)
}

fn server_capabilities_json(params: &InitializeParams) -> Result<serde_json::Value, String> {
    let mut capabilities = serde_json::to_value(server_capabilities(&params.capabilities))
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

fn main_loop(
    connection: &Connection,
    state: &mut ServerState,
    pending_messages: Vec<Message>,
) -> Result<(), String> {
    for msg in pending_messages {
        if handle_message(connection, state, msg)? {
            return Ok(());
        }
    }
    for msg in &connection.receiver {
        if handle_message(connection, state, msg)? {
            return Ok(());
        }
    }
    Ok(())
}

fn handle_message(
    connection: &Connection,
    state: &mut ServerState,
    msg: Message,
) -> Result<bool, String> {
    let meta = LspMessageMeta::from_message(&msg);
    let _scope = LspDebugScope::enter(meta.clone());
    if lsp_debug_enabled() {
        log_lsp_message("start", &meta, None, None);
    }
    let started = Instant::now();
    let result = match msg {
        Message::Request(req) => {
            match connection
                .handle_shutdown(&req)
                .map_err(|err| format!("LSP shutdown handling failed: {err}"))
            {
                Ok(true) => Ok(true),
                Ok(false) => handle_request(connection, state, req).map(|()| false),
                Err(err) => Err(err),
            }
        }
        Message::Notification(note) => handle_notification(connection, state, note).map(|()| false),
        Message::Response(_) => {
            // We do not currently send server→client requests outside the
            // startup-progress token handshake, so any inbound Response that
            // reaches the main loop is unsolicited and safe to ignore.
            Ok(false)
        }
    };
    let elapsed = started.elapsed();
    match &result {
        Ok(_) if lsp_debug_enabled() => log_lsp_message("finish", &meta, Some(elapsed), None),
        Ok(_) if elapsed >= lsp_slow_threshold() => {
            log_lsp_message("slow", &meta, Some(elapsed), None)
        }
        Err(err) => log_lsp_message("error", &meta, Some(elapsed), Some(err.as_str())),
        Ok(_) => {}
    }
    result
}

#[derive(Clone)]
struct LspMessageMeta {
    kind: &'static str,
    method: String,
    id: Option<String>,
}

impl LspMessageMeta {
    fn from_message(message: &Message) -> Self {
        match message {
            Message::Request(req) => Self {
                kind: "request",
                method: req.method.clone(),
                id: Some(format!("{:?}", req.id)),
            },
            Message::Notification(note) => Self {
                kind: "notification",
                method: note.method.clone(),
                id: None,
            },
            Message::Response(response) => Self {
                kind: "response",
                method: "<response>".to_string(),
                id: Some(format!("{:?}", response.id)),
            },
        }
    }
}

struct LspDebugContext {
    meta: LspMessageMeta,
    started: Instant,
}

struct LspDebugScope;

thread_local! {
    static LSP_DEBUG_CONTEXT: RefCell<Option<LspDebugContext>> = const { RefCell::new(None) };
}

impl LspDebugScope {
    fn enter(meta: LspMessageMeta) -> Self {
        LSP_DEBUG_CONTEXT.with(|context| {
            *context.borrow_mut() = Some(LspDebugContext {
                meta,
                started: Instant::now(),
            });
        });
        Self
    }
}

impl Drop for LspDebugScope {
    fn drop(&mut self) {
        LSP_DEBUG_CONTEXT.with(|context| {
            *context.borrow_mut() = None;
        });
    }
}

static LSP_PANIC_HOOK: Once = Once::new();

fn install_lsp_panic_hook() {
    LSP_PANIC_HOOK.call_once(|| {
        let previous = panic::take_hook();
        panic::set_hook(Box::new(move |info| {
            LSP_DEBUG_CONTEXT.with(|context| {
                if let Some(active) = context.borrow().as_ref() {
                    log_lsp_message(
                        "panic",
                        &active.meta,
                        Some(active.started.elapsed()),
                        Some(&info.to_string()),
                    );
                } else {
                    eprintln!("[bifrost-lsp] panic outside active LSP message: {info}");
                }
            });
            previous(info);
        }));
    });
}

fn lsp_debug_enabled() -> bool {
    std::env::var("BIFROST_LSP_DEBUG")
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "on"))
        .unwrap_or(false)
}

fn lsp_slow_threshold() -> Duration {
    std::env::var("BIFROST_LSP_SLOW_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .map(Duration::from_millis)
        .unwrap_or_else(|| Duration::from_millis(2000))
}

fn log_lsp_message(
    event: &str,
    meta: &LspMessageMeta,
    elapsed: Option<Duration>,
    detail: Option<&str>,
) {
    let id = meta
        .id
        .as_deref()
        .map(|id| format!(" id={id}"))
        .unwrap_or_default();
    let elapsed = elapsed
        .map(|elapsed| format!(" elapsed_ms={}", elapsed.as_millis()))
        .unwrap_or_default();
    let detail = detail
        .map(|detail| format!(" detail={detail}"))
        .unwrap_or_default();
    eprintln!(
        "[bifrost-lsp] {event} {} method={}{}{}{}",
        meta.kind, meta.method, id, elapsed, detail
    );
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
    progress_by_language: HashMap<crate::analyzer::Language, u32>,
    expected_language_count: usize,
    last_report_percentage: u32,
}

impl StartupProgress {
    fn create(
        connection: &Connection,
        token: String,
        pending_messages: &mut Vec<Message>,
    ) -> Result<Option<Self>, String> {
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
        if !Self::wait_for_create_response(connection, &request_id, pending_messages)? {
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
        pending_messages: &mut Vec<Message>,
    ) -> Result<bool, String> {
        loop {
            match connection.receiver.recv_timeout(Duration::from_secs(5)) {
                Ok(Message::Response(response)) if response.id == *request_id => {
                    return Ok(response.error.is_none());
                }
                Ok(Message::Response(_)) => continue,
                Ok(Message::Notification(note)) if note.method == "initialized" => continue,
                Ok(message) => pending_messages.push(message),
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

    fn set_expected_language_count(&self, count: usize) {
        let mut state = self.state.lock().expect("startup progress state poisoned");
        state.expected_language_count = count;
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
        let percentage = {
            let mut state = self.state.lock().expect("startup progress state poisoned");
            if !should_report_progress_event(&mut state, &event) {
                return;
            }
            progress_percentage_for_event(&mut state, &event)
        };
        let _ = self.send(WorkDoneProgress::Report(WorkDoneProgressReport {
            cancellable: Some(false),
            message: Some(progress_message_for_event(&event)),
            percentage: Some(percentage),
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

fn progress_percentage_for_event(
    state: &mut StartupProgressState,
    event: &BuildProgressEvent,
) -> u32 {
    const PROGRESS_UNITS: u32 = 1_000;
    let language_units = progress_units_for_event(event);
    let language_progress = state
        .progress_by_language
        .entry(event.language)
        .or_default();
    *language_progress = (*language_progress).max(language_units);

    let expected_language_count = state
        .expected_language_count
        .max(state.progress_by_language.len())
        .max(1);
    let completed_units: u32 = state.progress_by_language.values().sum();
    let computed = ((completed_units as u64) * 99
        / ((expected_language_count as u64) * PROGRESS_UNITS as u64)) as u32;
    let percentage = computed.clamp(0, 99).max(state.last_report_percentage);
    state.last_report_percentage = percentage;
    percentage
}

fn progress_units_for_event(event: &BuildProgressEvent) -> u32 {
    const PROGRESS_UNITS: u32 = 1_000;
    let (phase_start, phase_end) = match event.phase {
        BuildProgressPhase::Enumerate => (0, 50),
        BuildProgressPhase::Reconcile => (50, 200),
        BuildProgressPhase::Parse => (200, 800),
        BuildProgressPhase::Persist => (800, 900),
        BuildProgressPhase::Index => (900, PROGRESS_UNITS),
    };
    let phase_span = phase_end - phase_start;
    let phase_progress = if event.total == 0 {
        1.0
    } else {
        (event.completed.min(event.total) as f64) / (event.total as f64)
    };
    phase_start + ((phase_span as f64) * phase_progress).floor() as u32
}

fn handle_request(
    connection: &Connection,
    state: &mut ServerState,
    req: Request,
) -> Result<(), String> {
    if req.method == Formatting::METHOD {
        return handle_formatting_request(connection, state, req);
    }

    let id = req.id.clone();
    let id_for_log = format!("{id:?}");
    let method = req.method.clone();
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
        GotoTypeDefinition::METHOD => decode_and_run::<GotoTypeDefinition, _>(req, |params| {
            Ok(type_definition::handle(
                &state.workspace,
                state.project(),
                &params,
            ))
        }),
        GotoImplementation::METHOD => decode_and_run::<GotoImplementation, _>(req, |params| {
            Ok(type_definition::implementation(
                &state.workspace,
                state.project(),
                &params,
            ))
        }),
        HoverRequest::METHOD => decode_and_run::<HoverRequest, _>(req, |params| {
            Ok(hover::handle(&state.workspace, state.project(), &params))
        }),
        SignatureHelpRequest::METHOD => decode_and_run::<SignatureHelpRequest, _>(req, |params| {
            Ok(signature_help::handle(
                &state.workspace,
                state.project(),
                &params,
            ))
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
        PrepareRenameRequest::METHOD => decode_and_run::<PrepareRenameRequest, _>(req, |params| {
            Ok(rename::prepare(&state.workspace, state.project(), &params))
        }),
        Rename::METHOD => decode_and_run::<Rename, _>(req, |params| {
            Ok(rename::handle(&state.workspace, state.project(), &params))
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
    if let Some(error) = response.error.as_ref() {
        eprintln!(
            "[bifrost-lsp] request error method={} id={} code={} message={}",
            method, id_for_log, error.code, error.message
        );
    }
    connection
        .sender
        .send(Message::Response(response))
        .map_err(|err| format!("Failed to send LSP response: {err}"))
}

fn handle_formatting_request(
    connection: &Connection,
    state: &ServerState,
    req: Request,
) -> Result<(), String> {
    let id = req.id.clone();
    let method = req.method.clone();
    let params = match req.extract::<lsp_types::DocumentFormattingParams>(Formatting::METHOD) {
        Ok((_, params)) => params,
        Err(ExtractError::JsonError { error, .. }) => {
            let response = Response::new_err(
                id,
                ErrorCode::InvalidParams as i32,
                format!("Failed to decode params for {method}: {error}"),
            );
            return connection
                .sender
                .send(Message::Response(response))
                .map_err(|err| format!("Failed to send LSP response: {err}"));
        }
        Err(ExtractError::MethodMismatch(_)) => {
            let response = Response::new_err(
                id,
                ErrorCode::MethodNotFound as i32,
                format!("Method not implemented: {method}"),
            );
            return connection
                .sender
                .send(Message::Response(response))
                .map_err(|err| format!("Failed to send LSP response: {err}"));
        }
    };
    let Some(slot) = state.formatting_jobs.try_acquire() else {
        let response = Response::new_err(
            id,
            ErrorCode::InternalError as i32,
            "too many concurrent formatting requests".to_string(),
        );
        return connection
            .sender
            .send(Message::Response(response))
            .map_err(|err| format!("Failed to send LSP response: {err}"));
    };
    let document_generation = state.document_generation(&params.text_document.uri);
    let document_uri = params.text_document.uri.clone();
    let rules = state.formatter_commands.clone();
    let prepared = match formatting::prepare(state.project(), &params, &rules) {
        Ok(Some(prepared)) => prepared,
        Ok(None) => {
            drop(slot);
            let response = Response::new_ok(id, serde_json::Value::Null);
            return connection
                .sender
                .send(Message::Response(response))
                .map_err(|err| format!("Failed to send LSP response: {err}"));
        }
        Err(message) => {
            drop(slot);
            let response = Response::new_err(id, ErrorCode::InternalError as i32, message);
            return connection
                .sender
                .send(Message::Response(response))
                .map_err(|err| format!("Failed to send LSP response: {err}"));
        }
    };
    let cancellation = formatting::FormatterCancellation::new();
    state
        .formatting_jobs
        .insert(id.clone(), cancellation.clone());
    let sender = connection.sender.clone();
    let generations = Arc::clone(&state.document_generations);
    let jobs = state.formatting_jobs.clone();
    thread::spawn(move || {
        let result = formatting::run_prepared_with_cancellation(prepared, &cancellation);
        let current_generation = generations
            .lock()
            .expect("document generation lock poisoned")
            .get(document_uri.as_str())
            .copied()
            .unwrap_or(0);
        let response = if current_generation != document_generation && !cancellation.is_cancelled()
        {
            Response::new_ok(id.clone(), serde_json::Value::Array(Vec::new()))
        } else {
            match result {
                Ok(edits) => match serde_json::to_value(edits) {
                    Ok(value) => Response::new_ok(id.clone(), value),
                    Err(err) => Response::new_err(
                        id.clone(),
                        ErrorCode::InternalError as i32,
                        format!("Failed to serialize {method} result: {err}"),
                    ),
                },
                Err(message) if cancellation.is_cancelled() => {
                    Response::new_err(id.clone(), ErrorCode::RequestCanceled as i32, message)
                }
                Err(message) => {
                    Response::new_err(id.clone(), ErrorCode::InternalError as i32, message)
                }
            }
        };
        if let Some(error) = response.error.as_ref() {
            eprintln!(
                "[bifrost-lsp] request error method={} id={:?} code={} message={}",
                method, id, error.code, error.message
            );
        }
        if let Err(err) = sender.send(Message::Response(response)) {
            eprintln!(
                "[bifrost-lsp] failed to send formatting response method={} id={:?}: {err}",
                method, id
            );
        }
        jobs.remove(&id);
        drop(slot);
    });
    Ok(())
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

fn request_id_from_number_or_string(id: NumberOrString) -> RequestId {
    match id {
        NumberOrString::Number(value) => RequestId::from(value),
        NumberOrString::String(value) => RequestId::from(value),
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
                state.remember_open_document(
                    params.text_document.uri.clone(),
                    file.abs_path(),
                    params.text_document.text.clone(),
                );
                state
                    .overlay
                    .set(file.abs_path(), params.text_document.text);
                state.completion_cache.invalidate(&file.abs_path());
                let mut changed = BTreeSet::new();
                changed.insert(file);
                state.workspace = state.workspace.update(&changed);
                publish_diagnostics_for_state(connection, state, &params.text_document.uri)?;
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
                        state.remember_open_document(uri.clone(), file.abs_path(), text.clone());
                        state.overlay.set(file.abs_path(), text);
                        state.completion_cache.invalidate(&file.abs_path());
                        let mut changed = BTreeSet::new();
                        changed.insert(file);
                        state.workspace = state.workspace.update(&changed);
                        publish_diagnostics_for_state(connection, state, &uri)?;
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
            } else if let Some(text) = full_text {
                state.update_open_document_text(&uri, text);
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
                state.forget_open_document(&params.text_document.uri);
                if state.overlay.clear(&file.abs_path()) {
                    state.completion_cache.invalidate(&file.abs_path());
                    let mut changed = BTreeSet::new();
                    changed.insert(file);
                    state.workspace = state.workspace.update(&changed);
                    publish_diagnostics_for_state(connection, state, &params.text_document.uri)?;
                }
            } else {
                state.forget_open_document(&params.text_document.uri);
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
                publish_diagnostics_for_state(connection, state, &params.text_document.uri)?;
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
        DidChangeWorkspaceFolders::METHOD => {
            let params: DidChangeWorkspaceFoldersParams = serde_json::from_value(note.params)
                .map_err(|err| {
                    format!(
                        "Failed to decode {} params: {err}",
                        DidChangeWorkspaceFolders::METHOD
                    )
                })?;
            let stale_diagnostics = state.apply_workspace_folder_change(params)?;
            for uri in stale_diagnostics {
                publish_empty_diagnostics(connection, &uri)?;
            }
            Ok(())
        }
        Cancel::METHOD => {
            let params: CancelParams = serde_json::from_value(note.params)
                .map_err(|err| format!("Failed to decode {} params: {err}", Cancel::METHOD))?;
            let id = request_id_from_number_or_string(params.id);
            state.formatting_jobs.cancel(&id);
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

fn publish_diagnostics_for_state(
    connection: &Connection,
    state: &mut ServerState,
    uri: &Uri,
) -> Result<(), String> {
    publish_diagnostics(connection, &state.workspace, state.project(), uri)?;
    state.remember_published_diagnostic_uri(uri);
    Ok(())
}

fn publish_empty_diagnostics(connection: &Connection, uri: &Uri) -> Result<(), String> {
    let params = PublishDiagnosticsParams {
        uri: uri.clone(),
        diagnostics: Vec::new(),
        version: None,
    };
    let note = Notification::new(PublishDiagnostics::METHOD.to_string(), params);
    connection
        .sender
        .send(Message::Notification(note))
        .map_err(|err| format!("Failed to clear publishDiagnostics: {err}"))
}

pub(crate) struct ServerState {
    active_roots: Vec<WorkspaceRoot>,
    configured_roots: bool,
    excluded_paths: Vec<PathBuf>,
    formatter_commands: Vec<formatting::FormatterCommandRule>,
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
    malformed_didchange_log: ThrottledLog<String>,
    published_diagnostic_uris: Vec<Uri>,
    open_documents: HashMap<String, OpenDocument>,
    document_generations: Arc<Mutex<HashMap<String, u64>>>,
    formatting_jobs: FormattingJobs,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct WorkspaceRoot {
    identity_uri: String,
    identity_path: PathBuf,
    analyzer_path: PathBuf,
}

#[derive(Clone, Debug, Default)]
struct LspWorkspaceConfig {
    roots: Vec<WorkspaceRoot>,
    configured_roots: bool,
    excluded_paths: Vec<PathBuf>,
    formatter_commands: Vec<formatting::FormatterCommandRule>,
}

#[derive(serde::Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct BifrostInitializationOptions {
    #[serde(default)]
    roots: Vec<String>,
    #[serde(default)]
    exclude: Vec<String>,
    #[serde(default)]
    formatter_commands: Vec<formatting::FormatterCommandRule>,
}

#[derive(Clone, Debug)]
struct OpenDocument {
    uri: Uri,
    abs_path: PathBuf,
    text: String,
}

/// Minimum interval between stderr lines reporting a malformed `didChange`
/// for the same URI. Mirrors the cadence of `OVERLAY_REJECTION_LOG_THROTTLE`
/// in the analyzer layer.
const MALFORMED_DIDCHANGE_LOG_THROTTLE: Duration = Duration::from_secs(60);

/// Soft cap on the malformed-didChange throttle map. Same rationale as
/// `OVERLAY_REJECTION_LOG_MAX_ENTRIES`: a sloppy or hostile client could
/// otherwise send a stream of distinct URIs and grow the map without bound.
const MALFORMED_DIDCHANGE_LOG_MAX_ENTRIES: usize = 256;
const MAX_CONCURRENT_FORMATTING_REQUESTS: usize = 2;
const FORMATTER_SHUTDOWN_GRACE: Duration = Duration::from_secs(2);

struct FormattingSlot {
    active: Arc<AtomicUsize>,
}

impl Drop for FormattingSlot {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::AcqRel);
    }
}

#[derive(Clone, Default)]
struct FormattingJobs {
    active: Arc<AtomicUsize>,
    jobs: Arc<Mutex<HashMap<RequestId, formatting::FormatterCancellation>>>,
}

impl FormattingJobs {
    fn try_acquire(&self) -> Option<FormattingSlot> {
        self.active
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                (active < MAX_CONCURRENT_FORMATTING_REQUESTS).then_some(active + 1)
            })
            .ok()
            .map(|_| FormattingSlot {
                active: Arc::clone(&self.active),
            })
    }

    fn insert(&self, id: RequestId, cancellation: formatting::FormatterCancellation) {
        self.jobs
            .lock()
            .expect("formatting job lock poisoned")
            .insert(id, cancellation);
    }

    fn remove(&self, id: &RequestId) {
        self.jobs
            .lock()
            .expect("formatting job lock poisoned")
            .remove(id);
    }

    fn cancel(&self, id: &RequestId) {
        let job = self
            .jobs
            .lock()
            .expect("formatting job lock poisoned")
            .get(id)
            .cloned();
        if let Some(job) = job {
            job.cancel();
        }
    }

    fn cancel_all(&self) {
        let jobs: Vec<_> = self
            .jobs
            .lock()
            .expect("formatting job lock poisoned")
            .values()
            .cloned()
            .collect();
        for job in jobs {
            job.cancel();
        }
    }

    fn wait_for_empty(&self, timeout: Duration) {
        let started = Instant::now();
        while self.active.load(Ordering::Acquire) > 0 && started.elapsed() < timeout {
            thread::sleep(Duration::from_millis(10));
        }
    }
}

impl ServerState {
    fn new(config: LspWorkspaceConfig, progress: Option<&StartupProgress>) -> Result<Self, String> {
        let LspWorkspaceConfig {
            roots,
            configured_roots,
            excluded_paths,
            formatter_commands,
        } = config;
        let (project, active_roots) = build_project_for_roots(roots, &excluded_paths)?;
        let overlay = Arc::new(OverlayProject::new(project));
        let project = Arc::clone(&overlay) as Arc<dyn Project>;
        if let Some(progress) = progress {
            progress.set_expected_language_count(project.analyzer_languages().len());
        }
        let workspace = build_workspace_for_lsp(project, progress);
        Ok(Self {
            active_roots,
            configured_roots,
            excluded_paths,
            formatter_commands,
            workspace,
            overlay,
            completion_cache: completion::CompletionCache::new(),
            malformed_didchange_log: ThrottledLog::new(
                MALFORMED_DIDCHANGE_LOG_THROTTLE,
                MALFORMED_DIDCHANGE_LOG_MAX_ENTRIES,
            ),
            published_diagnostic_uris: Vec::new(),
            open_documents: HashMap::new(),
            document_generations: Arc::new(Mutex::new(HashMap::new())),
            formatting_jobs: FormattingJobs::default(),
        })
    }

    pub(crate) fn project(&self) -> &dyn Project {
        self.overlay.as_ref()
    }

    fn apply_workspace_folder_change(
        &mut self,
        params: DidChangeWorkspaceFoldersParams,
    ) -> Result<Vec<Uri>, String> {
        if self.configured_roots {
            return Ok(Vec::new());
        }
        let mut roots = self.active_roots.clone();
        for folder in params.event.removed {
            if let Some(path) = workspace_folder_identity_path(&folder.uri) {
                let identity_uri = folder.uri.as_str();
                roots.retain(|root| {
                    root.identity_uri != identity_uri
                        && root.identity_path != path
                        && root.analyzer_path != path
                });
            }
        }
        for folder in params.event.added {
            if let Some(root) = workspace_root_for_folder(&folder) {
                roots.push(root);
            }
        }
        normalize_roots(&mut roots);
        if roots == self.active_roots {
            return Ok(Vec::new());
        }
        self.rebuild_workspace(roots)
    }

    fn rebuild_workspace(&mut self, roots: Vec<WorkspaceRoot>) -> Result<Vec<Uri>, String> {
        let previous_diagnostics = self.published_diagnostic_uris.clone();
        let (project, active_roots): (Arc<dyn Project>, Vec<WorkspaceRoot>) = if roots.is_empty() {
            (
                Arc::new(NoWorkspaceProject::new(self.project().root().to_path_buf())),
                Vec::new(),
            )
        } else {
            build_project_for_roots(roots, &self.excluded_paths)?
        };
        let overlay = Arc::new(OverlayProject::new(project));
        for document in self.open_documents.values_mut() {
            if let Some(file) = resolve_project_file(overlay.as_ref(), &document.uri)
                .or_else(|| project_file_for_abs_path(overlay.as_ref(), &document.abs_path))
            {
                document.abs_path = file.abs_path();
                overlay.set(file.abs_path(), document.text.clone());
            }
        }
        let project = Arc::clone(&overlay) as Arc<dyn Project>;
        let workspace = build_workspace_for_lsp(project, None);
        self.active_roots = active_roots;
        self.workspace = workspace;
        self.overlay = overlay;
        self.completion_cache.clear();

        let mut stale = Vec::new();
        self.published_diagnostic_uris.clear();
        for uri in previous_diagnostics {
            if uri_belongs_to_project(self.project(), &uri) {
                self.remember_published_diagnostic_uri(&uri);
            } else {
                stale.push(uri);
            }
        }
        Ok(stale)
    }

    fn remember_published_diagnostic_uri(&mut self, uri: &Uri) {
        if !self.published_diagnostic_uris.contains(uri) {
            self.published_diagnostic_uris.push(uri.clone());
        }
    }

    fn remember_open_document(&mut self, uri: Uri, abs_path: PathBuf, text: String) {
        self.bump_document_generation(&uri);
        self.open_documents.insert(
            uri.as_str().to_string(),
            OpenDocument {
                uri,
                abs_path,
                text,
            },
        );
    }

    fn update_open_document_text(&mut self, uri: &Uri, text: String) {
        self.bump_document_generation(uri);
        if let Some(document) = self.open_documents.get_mut(uri.as_str()) {
            document.text = text;
        }
    }

    fn forget_open_document(&mut self, uri: &Uri) {
        self.bump_document_generation(uri);
        self.open_documents.remove(uri.as_str());
    }

    fn bump_document_generation(&self, uri: &Uri) {
        let mut generations = self
            .document_generations
            .lock()
            .expect("document generation lock poisoned");
        let generation = generations.entry(uri.as_str().to_string()).or_insert(0);
        *generation = generation.saturating_add(1);
    }

    fn document_generation(&self, uri: &Uri) -> u64 {
        self.document_generations
            .lock()
            .expect("document generation lock poisoned")
            .get(uri.as_str())
            .copied()
            .unwrap_or(0)
    }

    /// Emit a single stderr warning for `uri` if we haven't logged one
    /// within [`MALFORMED_DIDCHANGE_LOG_THROTTLE`]. The throttle map is
    /// bounded; entries older than the throttle window are pruned when it
    /// fills.
    fn maybe_log_malformed_didchange(&self, uri: &Uri, n_changes: usize) {
        let now = Instant::now();
        if self.malformed_didchange_log.should_log(uri.as_str(), now) {
            eprintln!(
                "[bifrost-lsp] dropping didChange for {}: {n_changes} content_change events but none was a full-document replacement (server advertises TextDocumentSyncKind::FULL)",
                uri.as_str(),
            );
        }
    }
}

struct NoWorkspaceProject {
    root: PathBuf,
}

impl NoWorkspaceProject {
    fn new(root: PathBuf) -> Self {
        Self { root }
    }
}

impl Project for NoWorkspaceProject {
    fn root(&self) -> &Path {
        &self.root
    }

    fn analyzer_languages(&self) -> BTreeSet<crate::analyzer::Language> {
        BTreeSet::new()
    }

    fn all_files(&self) -> std::io::Result<BTreeSet<crate::analyzer::ProjectFile>> {
        Ok(BTreeSet::new())
    }

    fn analyzable_files(
        &self,
        _language: crate::analyzer::Language,
    ) -> std::io::Result<BTreeSet<crate::analyzer::ProjectFile>> {
        Ok(BTreeSet::new())
    }

    fn file_by_rel_path(&self, _rel_path: &Path) -> Option<crate::analyzer::ProjectFile> {
        None
    }

    fn file_by_abs_path(&self, _abs_path: &Path) -> Option<crate::analyzer::ProjectFile> {
        None
    }

    fn file_by_abs_path_allow_missing(
        &self,
        _abs_path: &Path,
    ) -> Option<crate::analyzer::ProjectFile> {
        None
    }

    fn persistence_root(&self) -> Option<&Path> {
        None
    }
}

struct ScopedProject {
    inner: Arc<dyn Project>,
    excluded_paths: Vec<PathBuf>,
}

impl ScopedProject {
    fn new(inner: Arc<dyn Project>, excluded_paths: Vec<PathBuf>) -> Self {
        Self {
            inner,
            excluded_paths,
        }
    }

    fn is_excluded_abs_path(&self, path: &Path) -> bool {
        path_is_within_any(path, &self.excluded_paths)
    }

    fn is_excluded_file(&self, file: &ProjectFile) -> bool {
        self.is_excluded_abs_path(&file.abs_path())
    }

    fn filter_files(&self, files: BTreeSet<ProjectFile>) -> BTreeSet<ProjectFile> {
        files
            .into_iter()
            .filter(|file| !self.is_excluded_file(file))
            .collect()
    }
}

impl Project for ScopedProject {
    fn root(&self) -> &Path {
        self.inner.root()
    }

    fn workspace_root_for_file(&self, file: &ProjectFile) -> PathBuf {
        self.inner.workspace_root_for_file(file)
    }

    fn analyzer_languages(&self) -> BTreeSet<crate::analyzer::Language> {
        self.all_files()
            .map(|files| {
                files
                    .iter()
                    .map(crate::analyzer::common::language_for_file)
                    .filter(|language| *language != crate::analyzer::Language::None)
                    .collect()
            })
            .unwrap_or_default()
    }

    fn all_files(&self) -> io::Result<BTreeSet<ProjectFile>> {
        self.inner.all_files().map(|files| self.filter_files(files))
    }

    fn analyzable_files(
        &self,
        language: crate::analyzer::Language,
    ) -> io::Result<BTreeSet<ProjectFile>> {
        self.inner
            .analyzable_files(language)
            .map(|files| self.filter_files(files))
    }

    fn file_by_rel_path(&self, rel_path: &Path) -> Option<ProjectFile> {
        let file = self.inner.file_by_rel_path(rel_path)?;
        (!self.is_excluded_file(&file)).then_some(file)
    }

    fn file_by_abs_path(&self, abs_path: &Path) -> Option<ProjectFile> {
        if self.is_excluded_abs_path(abs_path) {
            return None;
        }
        self.inner.file_by_abs_path(abs_path)
    }

    fn file_by_abs_path_allow_missing(&self, abs_path: &Path) -> Option<ProjectFile> {
        if self.is_excluded_abs_path(abs_path) {
            return None;
        }
        self.inner.file_by_abs_path_allow_missing(abs_path)
    }

    fn persistence_root(&self) -> Option<&Path> {
        self.inner.persistence_root()
    }

    fn is_gitignored(&self, rel_path: &Path) -> bool {
        self.inner.is_gitignored(rel_path)
    }

    fn read_source(&self, file: &ProjectFile) -> io::Result<String> {
        self.inner.read_source(file)
    }

    fn has_overlay(&self, file: &ProjectFile) -> bool {
        self.inner.has_overlay(file)
    }
}

fn build_project_for_roots(
    roots: Vec<WorkspaceRoot>,
    excluded_paths: &[PathBuf],
) -> Result<(Arc<dyn Project>, Vec<WorkspaceRoot>), String> {
    let mut roots = roots;
    normalize_roots(&mut roots);
    let analyzer_roots: Vec<PathBuf> = roots
        .iter()
        .map(|root| root.analyzer_path.clone())
        .collect();
    let project: Arc<dyn Project> = if roots.len() == 1 {
        let root = roots[0].analyzer_path.clone();
        let project = FilesystemProject::new(&root).map_err(|err| {
            format!(
                "Failed to initialize project root {}: {err}",
                root.display()
            )
        })?;
        Arc::new(project)
    } else {
        let project = MultiRootProject::new(analyzer_roots)
            .map_err(|err| format!("Failed to initialize multi-root project: {err}"))?;
        Arc::new(project)
    };
    let project = if excluded_paths.is_empty() {
        project
    } else {
        Arc::new(ScopedProject::new(project, excluded_paths.to_vec())) as Arc<dyn Project>
    };
    Ok((project, roots))
}

fn normalize_roots(roots: &mut Vec<WorkspaceRoot>) {
    roots.sort_by(|left, right| {
        left.analyzer_path
            .cmp(&right.analyzer_path)
            .then_with(|| left.identity_uri.cmp(&right.identity_uri))
            .then_with(|| left.identity_path.cmp(&right.identity_path))
    });
    roots.dedup_by(|left, right| {
        left.identity_uri == right.identity_uri
            || left.identity_path == right.identity_path
            || left.analyzer_path == right.analyzer_path
    });
}

fn workspace_root_for_folder(folder: &lsp_types::WorkspaceFolder) -> Option<WorkspaceRoot> {
    let uri = &folder.uri;
    let Some(path) = uri_to_path(uri) else {
        eprintln!(
            "[bifrost-lsp] ignoring non-file workspace folder URI: {}",
            uri.as_str()
        );
        return None;
    };
    match path.canonicalize() {
        Ok(analyzer_path) if analyzer_path.is_dir() => Some(WorkspaceRoot {
            identity_uri: uri.as_str().to_string(),
            identity_path: path,
            analyzer_path,
        }),
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

fn workspace_root_for_path(path: PathBuf) -> Result<WorkspaceRoot, String> {
    let analyzer_path = path.canonicalize().map_err(|err| {
        format!(
            "Failed to canonicalize project root {}: {err}",
            path.display()
        )
    })?;
    Ok(WorkspaceRoot {
        identity_uri: path_to_uri_string(&path),
        identity_path: path,
        analyzer_path,
    })
}

fn workspace_folder_identity_path(uri: &Uri) -> Option<PathBuf> {
    let Some(path) = uri_to_path(uri) else {
        eprintln!(
            "[bifrost-lsp] ignoring non-file workspace folder URI: {}",
            uri.as_str()
        );
        return None;
    };
    Some(path.canonicalize().unwrap_or(path))
}

fn uri_belongs_to_project(project: &dyn Project, uri: &Uri) -> bool {
    let Some(path) = uri_to_path(uri) else {
        return false;
    };
    project_file_for_abs_path(project, &path).is_some()
}

fn build_workspace_for_lsp(
    project: Arc<dyn Project>,
    progress: Option<&StartupProgress>,
) -> WorkspaceAnalyzer {
    let config = AnalyzerConfig::default();
    match progress {
        Some(progress) => {
            let progress = progress.clone_for_callback();
            WorkspaceAnalyzer::build_persisted_with_progress(project, config, move |event| {
                progress.report_analyzer_event(event)
            })
        }
        // Persist regardless of progress support. Work-done progress is a
        // UI capability (can the client render a progress bar); it has no
        // bearing on whether the analyzer cache is worth keeping. A client that
        // cannot show progress still benefits from a warm `.bifrost` cache on
        // restart, matching the MCP server, which always persists.
        None => WorkspaceAnalyzer::build_persisted(project, config),
    }
}

fn collect_workspace_config(
    params: &InitializeParams,
    fallback: &Path,
) -> Result<LspWorkspaceConfig, String> {
    let options = bifrost_initialization_options(params);
    let fallback_base = fallback
        .canonicalize()
        .unwrap_or_else(|_| fallback.to_path_buf());
    let configured_roots = !options.roots.is_empty();
    let roots = if configured_roots {
        let roots: Vec<WorkspaceRoot> = options
            .roots
            .into_iter()
            .filter_map(|root| workspace_root_for_config_path(&root, &fallback_base))
            .collect();
        if roots.is_empty() {
            return Err("bifrost.roots did not contain any usable directories".to_string());
        }
        roots
    } else {
        collect_workspace_roots(params, fallback)?
    };
    let excluded_paths = options
        .exclude
        .into_iter()
        .filter_map(|path| scoped_config_path(&path, &fallback_base))
        .map(|path| path.canonicalize().unwrap_or(path))
        .collect();
    Ok(LspWorkspaceConfig {
        roots,
        configured_roots,
        excluded_paths,
        formatter_commands: options.formatter_commands,
    })
}

fn collect_workspace_roots(
    params: &InitializeParams,
    fallback: &Path,
) -> Result<Vec<WorkspaceRoot>, String> {
    if let Some(folders) = &params.workspace_folders {
        let roots: Vec<WorkspaceRoot> = folders
            .iter()
            .filter_map(workspace_root_for_folder)
            .collect();
        if !roots.is_empty() {
            return Ok(roots);
        }
    }

    // `root_uri` and the long-deprecated `root_path` are still common, and
    // remain the fallback when no usable startup workspace folders were sent.
    #[allow(deprecated)]
    if let Some(uri) = &params.root_uri
        && let Some(path) = uri_to_path(uri)
    {
        return Ok(vec![workspace_root_for_path(path)?]);
    }
    #[allow(deprecated)]
    if let Some(root_path) = &params.root_path {
        return Ok(vec![workspace_root_for_path(PathBuf::from(root_path))?]);
    }

    Ok(vec![workspace_root_for_path(fallback.to_path_buf())?])
}

fn bifrost_initialization_options(params: &InitializeParams) -> BifrostInitializationOptions {
    let Some(value) = params.initialization_options.as_ref() else {
        return BifrostInitializationOptions::default();
    };
    let Some(object) = value.as_object() else {
        eprintln!("[bifrost-lsp] ignoring initializationOptions that is not an object");
        return BifrostInitializationOptions::default();
    };
    BifrostInitializationOptions {
        roots: optional_string_array(object, "roots"),
        exclude: optional_string_array(object, "exclude"),
        formatter_commands: match object.get("formatterCommands") {
            Some(value) => serde_json::from_value(value.clone()).unwrap_or_else(|err| {
                eprintln!(
                    "[bifrost-lsp] ignoring invalid initializationOptions.formatterCommands: {err}"
                );
                Vec::new()
            }),
            None => Vec::new(),
        },
    }
}

fn optional_string_array(
    object: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Vec<String> {
    let Some(value) = object.get(key) else {
        return Vec::new();
    };
    let Some(items) = value.as_array() else {
        eprintln!("[bifrost-lsp] ignoring initializationOptions.{key} that is not an array");
        return Vec::new();
    };
    items
        .iter()
        .enumerate()
        .filter_map(|(index, item)| {
            item.as_str().map(str::to_string).or_else(|| {
                eprintln!(
                    "[bifrost-lsp] ignoring initializationOptions.{key}[{index}] that is not a string"
                );
                None
            })
        })
        .collect()
}

fn workspace_root_for_config_path(raw: &str, base: &Path) -> Option<WorkspaceRoot> {
    let Some(path) = scoped_config_path(raw, base) else {
        eprintln!("[bifrost-lsp] ignoring empty bifrost root setting");
        return None;
    };
    match path.canonicalize() {
        Ok(analyzer_path) if analyzer_path.is_dir() => Some(WorkspaceRoot {
            identity_uri: path_to_uri_string(&path),
            identity_path: path,
            analyzer_path,
        }),
        Ok(path) => {
            eprintln!(
                "[bifrost-lsp] ignoring bifrost root that is not a directory: {}",
                path.display()
            );
            None
        }
        Err(err) => {
            eprintln!(
                "[bifrost-lsp] ignoring unavailable bifrost root {}: {err}",
                path.display()
            );
            None
        }
    }
}

fn scoped_config_path(raw: &str, base: &Path) -> Option<PathBuf> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let path = PathBuf::from(trimmed);
    let path = if path.is_absolute() {
        path
    } else {
        base.join(path)
    };
    Some(normalize_path_lexically(path))
}

fn normalize_path_lexically(path: PathBuf) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::Prefix(_) | Component::RootDir | Component::Normal(_) => {
                normalized.push(component.as_os_str());
            }
        }
    }
    normalized
}

fn path_is_within_any(path: &Path, candidates: &[PathBuf]) -> bool {
    let normalized = path
        .canonicalize()
        .unwrap_or_else(|_| normalize_path_lexically(path.to_path_buf()));
    candidates
        .iter()
        .any(|candidate| normalized == *candidate || normalized.starts_with(candidate))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn invalid_formatter_commands_do_not_discard_roots_or_exclude() {
        let params: InitializeParams = serde_json::from_value(json!({
            "processId": null,
            "rootUri": null,
            "capabilities": {},
            "initializationOptions": {
                "roots": ["service-a"],
                "exclude": ["target"],
                "formatterCommands": [{"include": ["*.rs"]}]
            }
        }))
        .unwrap();

        let options = bifrost_initialization_options(&params);
        assert_eq!(options.roots, vec!["service-a"]);
        assert_eq!(options.exclude, vec!["target"]);
        assert!(options.formatter_commands.is_empty());
    }

    #[test]
    fn scoped_project_delegates_workspace_root_for_file() {
        let temp = tempfile::tempdir().unwrap();
        let outer = temp.path().canonicalize().unwrap();
        let parent = outer.join("repo");
        let nested = parent.join("frontend");
        std::fs::create_dir_all(nested.join("src")).unwrap();
        std::fs::write(nested.join("src/app.ts"), "const x=1;").unwrap();
        let inner = Arc::new(MultiRootProject::new([parent, nested.clone()]).unwrap());
        let scoped = ScopedProject::new(inner, vec![outer.join("ignored")]);
        let file = scoped.file_by_abs_path(&nested.join("src/app.ts")).unwrap();

        assert_eq!(scoped.workspace_root_for_file(&file), nested);
    }
}
