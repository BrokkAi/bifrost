use std::cell::RefCell;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::io;
use std::panic;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Once};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use lsp_server::{
    Connection, ErrorCode, ExtractError, IoThreads, Message, Notification, Request, RequestId,
    Response,
};
use lsp_types::notification::{
    Cancel, DidChangeConfiguration, DidChangeTextDocument, DidChangeWatchedFiles,
    DidChangeWorkspaceFolders, DidCloseTextDocument, DidOpenTextDocument, DidSaveTextDocument,
    Notification as LspNotificationTrait, PublishDiagnostics,
};
use lsp_types::request::{
    CallHierarchyIncomingCalls, CallHierarchyOutgoingCalls, CallHierarchyPrepare, Completion,
    DocumentDiagnosticRequest, DocumentHighlightRequest, DocumentSymbolRequest,
    FoldingRangeRequest, Formatting, GotoDefinition, GotoImplementation, GotoTypeDefinition,
    HoverRequest, PrepareRenameRequest, References, RegisterCapability, Rename,
    Request as LspRequestTrait, SemanticTokensFullRequest, SignatureHelpRequest,
    TypeHierarchyPrepare, TypeHierarchySubtypes, TypeHierarchySupertypes, WorkDoneProgressCreate,
    WorkspaceConfiguration, WorkspaceSymbolRequest,
};
use lsp_types::{
    CancelParams, ConfigurationItem, ConfigurationParams, DidChangeConfigurationParams,
    DidChangeTextDocumentParams, DidChangeWatchedFilesParams, DidChangeWorkspaceFoldersParams,
    DidCloseTextDocumentParams, DidOpenTextDocumentParams, DidSaveTextDocumentParams,
    FileChangeType, InitializeParams, NumberOrString, ProgressToken, PublishDiagnosticsParams,
    Registration, RegistrationParams, Uri, WorkDoneProgress, WorkDoneProgressBegin,
    WorkDoneProgressCreateParams, WorkDoneProgressEnd, WorkDoneProgressReport,
};

use crate::analyzer::{
    AnalyzerConfig, BuildProgressEvent, BuildProgressPhase, FilesystemProject, MultiRootProject,
    OverlayProject, Project, ProjectFile, WorkspaceAnalyzer,
};
use crate::cancellation::CancellationToken;
use crate::lsp::capabilities::server_capabilities;
use crate::lsp::conversion::{path_to_uri_string, uri_to_path};
use crate::lsp::handlers::util::{
    project_file_for_abs_path, project_file_for_uri as resolve_project_file,
    project_file_for_uri_allow_missing as resolve_project_file_allow_missing,
};
use crate::lsp::handlers::{
    call_hierarchy, completion, definition, diagnostic, document_highlight, document_symbol,
    folding_range, formatting, hover, references, rename, semantic_tokens, signature_help,
    type_definition, type_hierarchy, workspace_symbol,
};
use crate::lsp::progress::work_done_progress_message;
use crate::lsp::request_context::{RequestCancelled, RequestContext};
use crate::lsp::text_sync::apply_content_changes;
#[cfg(test)]
use crate::path_normalization::NormalizePath;
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
    state.register_runtime_configuration(&connection)?;

    let result = main_loop(&connection, &mut state, pending_messages);
    state.request_jobs.cancel_all_and_join();
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
    state.request_jobs.reap_finished();
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
        Message::Response(response) => handle_response(connection, state, response).map(|()| false),
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

fn handle_response(
    connection: &Connection,
    state: &mut ServerState,
    response: Response,
) -> Result<(), String> {
    if response.id == runtime_configuration_registration_request_id() {
        if let Some(error) = response.error {
            eprintln!(
                "[bifrost-lsp] runtime configuration registration failed: {}",
                truncate_runtime_configuration_log(&error.message)
            );
        }
        return Ok(());
    }

    let Some(generation) = state
        .configuration_protocol
        .pending_pulls
        .remove(&response.id)
    else {
        return Ok(());
    };
    if generation != state.configuration_protocol.latest_pull_generation {
        return Ok(());
    }
    let value = match response.error {
        Some(error) => {
            eprintln!(
                "[bifrost-lsp] runtime configuration pull failed: {}",
                truncate_runtime_configuration_log(&error.message)
            );
            return Ok(());
        }
        None => match response.result {
            Some(serde_json::Value::Array(mut values)) if values.len() == 1 => values.remove(0),
            Some(serde_json::Value::Array(values)) => {
                eprintln!(
                    "[bifrost-lsp] ignoring runtime configuration response: expected one item, received {}",
                    values.len()
                );
                return Ok(());
            }
            Some(value) => {
                eprintln!(
                    "[bifrost-lsp] ignoring runtime configuration response: expected an array, received {}",
                    json_value_kind(&value)
                );
                return Ok(());
            }
            None => {
                eprintln!("[bifrost-lsp] ignoring runtime configuration response without a result");
                return Ok(());
            }
        },
    };
    apply_runtime_configuration_value(connection, state, &value)
}

const MAX_RUNTIME_CONFIGURATION_LOG_CHARS: usize = 240;

fn truncate_runtime_configuration_log(message: &str) -> String {
    let mut truncated = message
        .chars()
        .take(MAX_RUNTIME_CONFIGURATION_LOG_CHARS)
        .collect::<String>();
    if message.chars().count() > MAX_RUNTIME_CONFIGURATION_LOG_CHARS {
        truncated.push_str("...");
    }
    truncated
}

fn json_value_kind(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "boolean",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
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
        (self.send_message)(work_done_progress_message(self.token.clone(), value))
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
    if req.method == References::METHOD {
        return handle_references_request(connection, state, req);
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
        SemanticTokensFullRequest::METHOD => {
            decode_and_run::<SemanticTokensFullRequest, _>(req, |params| {
                Ok(semantic_tokens::handle(
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

fn handle_references_request(
    connection: &Connection,
    state: &ServerState,
    req: Request,
) -> Result<(), String> {
    let id = req.id.clone();
    let method = req.method.clone();
    let params = match req.extract::<lsp_types::ReferenceParams>(References::METHOD) {
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

    let Some(slot) = state.request_jobs.try_acquire() else {
        let response = Response::new_err(
            id,
            ErrorCode::ServerCancelled as i32,
            "too many concurrent cancellable requests".to_string(),
        );
        return connection
            .sender
            .send(Message::Response(response))
            .map_err(|err| format!("Failed to send LSP response: {err}"));
    };
    let Some(active_request) = state.active_request_ids.try_reserve(id.clone()) else {
        let response = Response::new_err(
            id,
            ErrorCode::InvalidRequest as i32,
            "request id is already active".to_string(),
        );
        return connection
            .sender
            .send(Message::Response(response))
            .map_err(|err| format!("Failed to send LSP response: {err}"));
    };

    let cancellation = CancellationToken::default();
    if !state.request_jobs.reserve(id.clone(), cancellation.clone()) {
        let response = Response::new_err(
            id,
            ErrorCode::InvalidRequest as i32,
            "request id is already active".to_string(),
        );
        return connection
            .sender
            .send(Message::Response(response))
            .map_err(|err| format!("Failed to send LSP response: {err}"));
    }
    let worker_cancellation = cancellation.clone();
    let project = Arc::new(state.overlay.snapshot());
    let workspace = state
        .workspace
        .clone_with_project(Arc::clone(&project) as Arc<dyn Project>);
    let sender = connection.sender.clone();
    let progress_sender = sender.clone();
    let work_done_token = params.work_done_progress_params.work_done_token.clone();
    let worker_id = id.clone();
    let worker_method = method.clone();
    let context = RequestContext::new(
        worker_cancellation.clone(),
        work_done_token,
        "Finding references",
        "Resolving symbol",
        Arc::new(move |message| {
            progress_sender
                .send(message)
                .map_err(|err| format!("Failed to send LSP progress: {err}"))
        }),
    );
    let handle = match thread::Builder::new()
        .name("bifrost-lsp-references".to_string())
        .spawn(move || {
            context.begin();
            let response = finish_reference_request(
                &worker_id,
                &worker_method,
                &context,
                &worker_cancellation,
                || references::handle(&workspace, project.as_ref(), &params, &context),
            );
            if let Some(error) = response.error.as_ref() {
                eprintln!(
                    "[bifrost-lsp] request error method={} id={:?} code={} message={}",
                    worker_method, worker_id, error.code, error.message
                );
            }
            if let Err(err) = sender.send(Message::Response(response)) {
                eprintln!(
                    "[bifrost-lsp] failed to send reference response method={} id={:?}: {err}",
                    worker_method, worker_id
                );
            }
            drop(active_request);
            drop(slot);
        }) {
        Ok(handle) => handle,
        Err(err) => {
            state.request_jobs.remove(&id);
            let response = Response::new_err(
                id,
                ErrorCode::InternalError as i32,
                format!("Failed to start reference worker: {err}"),
            );
            return connection
                .sender
                .send(Message::Response(response))
                .map_err(|send_err| format!("Failed to send LSP response: {send_err}"));
        }
    };
    state.request_jobs.start(&id, handle);
    Ok(())
}

fn finish_reference_request<T: serde::Serialize>(
    id: &RequestId,
    method: &str,
    context: &RequestContext,
    cancellation: &CancellationToken,
    run: impl FnOnce() -> Result<T, RequestCancelled>,
) -> Response {
    match panic::catch_unwind(panic::AssertUnwindSafe(run)) {
        Err(_) => {
            context.end("Failed");
            Response::new_err(
                id.clone(),
                ErrorCode::InternalError as i32,
                format!("{method} failed unexpectedly"),
            )
        }
        Ok(result) => match result {
            Err(RequestCancelled) => {
                context.end("Cancelled");
                Response::new_err(
                    id.clone(),
                    ErrorCode::RequestCanceled as i32,
                    "reference request cancelled by client".to_string(),
                )
            }
            Ok(_) if cancellation.is_cancelled() => {
                context.end("Cancelled");
                Response::new_err(
                    id.clone(),
                    ErrorCode::RequestCanceled as i32,
                    "reference request cancelled by client".to_string(),
                )
            }
            Ok(result) => match serde_json::to_value(result) {
                Ok(value) => {
                    context.end("References ready");
                    Response::new_ok(id.clone(), value)
                }
                Err(err) => {
                    context.end("Failed");
                    Response::new_err(
                        id.clone(),
                        ErrorCode::InternalError as i32,
                        format!("Failed to serialize {method} result: {err}"),
                    )
                }
            },
        },
    }
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
    let Some(active_request) = state.active_request_ids.try_reserve(id.clone()) else {
        let response = Response::new_err(
            id,
            ErrorCode::InvalidRequest as i32,
            "request id is already active".to_string(),
        );
        return connection
            .sender
            .send(Message::Response(response))
            .map_err(|err| format!("Failed to send LSP response: {err}"));
    };
    let document_generation = state.document_generation(&params.text_document.uri);
    let document_uri = params.text_document.uri.clone();
    let rules = state.runtime_configuration.formatter_commands.clone();
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
        drop(active_request);
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
        DidChangeConfiguration::METHOD => {
            if state.configuration_protocol.supports_pull {
                state.request_runtime_configuration(connection)
            } else {
                let params: DidChangeConfigurationParams = match serde_json::from_value(note.params)
                {
                    Ok(params) => params,
                    Err(err) => {
                        eprintln!(
                            "[bifrost-lsp] ignoring runtime configuration notification: {}",
                            truncate_runtime_configuration_log(&err.to_string())
                        );
                        return Ok(());
                    }
                };
                apply_runtime_configuration_value(connection, state, &params.settings)
            }
        }
        DidOpenTextDocument::METHOD => {
            let params: DidOpenTextDocumentParams =
                serde_json::from_value(note.params).map_err(|err| {
                    format!(
                        "Failed to decode {} params: {err}",
                        DidOpenTextDocument::METHOD
                    )
                })?;
            let document = params.text_document;
            if let Some(file) = resolve_project_file(state.project(), &document.uri) {
                state.remember_open_document(
                    document.uri.clone(),
                    file.abs_path(),
                    document.version,
                    document.text.clone(),
                );
                state.overlay.set(file.abs_path(), document.text);
                state.completion_cache.invalidate(&file.abs_path());
                let mut changed = BTreeSet::new();
                changed.insert(file);
                state.workspace = state.workspace.update(&changed);
                publish_diagnostics_for_state(connection, state, &document.uri)?;
            } else if let Some(abs_path) = uri_to_path(&document.uri) {
                let abs_path = abs_path
                    .canonicalize()
                    .unwrap_or_else(|_| normalize_path_lexically(abs_path));
                state.remember_open_document(
                    document.uri,
                    abs_path,
                    document.version,
                    document.text,
                );
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
            let uri = params.text_document.uri;
            let version = params.text_document.version;
            let Some(document) = state.open_documents.get(uri.as_str()) else {
                state.maybe_log_unknown_document_didchange(version);
                return Ok(());
            };
            if version <= document.version {
                state.maybe_log_rejected_didchange(
                    &uri,
                    version,
                    &format!(
                        "version must be newer than the current version {}",
                        document.version
                    ),
                );
                return Ok(());
            }

            if params.content_changes.is_empty() {
                state.update_open_document_version(&uri, version);
                return Ok(());
            }

            let updated_text = match apply_content_changes(&document.text, &params.content_changes)
            {
                Ok(text) => text,
                Err(error) => {
                    state.maybe_log_rejected_didchange(&uri, version, &error.to_string());
                    return Ok(());
                }
            };

            state.update_open_document(&uri, version, updated_text.clone());
            if let Some(file) = resolve_project_file(state.project(), &uri) {
                state.overlay.set(file.abs_path(), updated_text);
                state.completion_cache.invalidate(&file.abs_path());
                let mut changed = BTreeSet::new();
                changed.insert(file);
                state.workspace = state.workspace.update(&changed);
                publish_diagnostics_for_state(connection, state, &uri)?;
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
            state.request_jobs.cancel(&id);
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

fn apply_runtime_configuration_value(
    connection: &Connection,
    state: &mut ServerState,
    value: &serde_json::Value,
) -> Result<(), String> {
    let configuration = match parse_runtime_configuration(value, &state.configuration_base) {
        Ok(configuration) => configuration,
        Err(err) => {
            eprintln!("[bifrost-lsp] ignoring runtime configuration: {err}");
            return Ok(());
        }
    };
    let stale_diagnostics = match state.apply_runtime_configuration(configuration) {
        Ok(stale) => stale,
        Err(err) => {
            eprintln!("[bifrost-lsp] runtime configuration was not applied: {err}");
            return Ok(());
        }
    };
    for uri in stale_diagnostics {
        publish_empty_diagnostics(connection, &uri)?;
    }
    Ok(())
}

fn runtime_configuration_registration_request_id() -> RequestId {
    RequestId::from("bifrost-runtime-configuration-register".to_string())
}

pub(crate) struct ServerState {
    active_roots: Vec<WorkspaceRoot>,
    editor_roots: Vec<WorkspaceRoot>,
    configuration_base: PathBuf,
    runtime_configuration: BifrostRuntimeConfiguration,
    configuration_protocol: RuntimeConfigurationProtocol,
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
    /// Last instant we logged a rejected `didChange` for a given URI. Used
    /// to throttle the warning to one line per URI per
    /// [`REJECTED_DIDCHANGE_LOG_THROTTLE`] — a misbehaving client sending
    /// invalid events per keystroke would otherwise flood stderr.
    rejected_didchange_log: ThrottledLog<String>,
    published_diagnostic_uris: Vec<Uri>,
    open_documents: HashMap<String, OpenDocument>,
    document_generations: Arc<Mutex<HashMap<String, u64>>>,
    request_jobs: RequestJobs,
    formatting_jobs: FormattingJobs,
    active_request_ids: ActiveRequestIds,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct WorkspaceRoot {
    identity_uri: String,
    identity_path: PathBuf,
    analyzer_path: PathBuf,
}

#[derive(Clone, Debug, Default)]
struct LspWorkspaceConfig {
    editor_roots: Vec<WorkspaceRoot>,
    configuration_base: PathBuf,
    runtime_configuration: BifrostRuntimeConfiguration,
    configuration_protocol: RuntimeConfigurationProtocol,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct BifrostRuntimeConfiguration {
    configured_roots: Vec<WorkspaceRoot>,
    excluded_paths: Vec<PathBuf>,
    formatter_commands: Vec<formatting::FormatterCommandRule>,
}

#[derive(Clone, Debug, Default)]
struct RuntimeConfigurationProtocol {
    supports_pull: bool,
    supports_dynamic_registration: bool,
    registration_sent: bool,
    next_pull_generation: u64,
    latest_pull_generation: u64,
    pending_pulls: HashMap<RequestId, u64>,
}

struct PreparedWorkspaceRebuild {
    active_roots: Vec<WorkspaceRoot>,
    workspace: WorkspaceAnalyzer,
    overlay: Arc<OverlayProject>,
    open_document_paths: HashMap<String, PathBuf>,
    retained_diagnostics: Vec<Uri>,
    stale_diagnostics: Vec<Uri>,
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
    version: i32,
    text: String,
}

/// Minimum interval between stderr lines reporting a rejected `didChange`
/// for the same URI. Mirrors the cadence of `OVERLAY_REJECTION_LOG_THROTTLE`
/// in the analyzer layer.
const REJECTED_DIDCHANGE_LOG_THROTTLE: Duration = Duration::from_secs(60);

/// Soft cap on the rejected-didChange throttle map. Same rationale as
/// `OVERLAY_REJECTION_LOG_MAX_ENTRIES`: a sloppy or hostile client could
/// otherwise send a stream of distinct URIs and grow the map without bound.
const REJECTED_DIDCHANGE_LOG_MAX_ENTRIES: usize = 256;
const MAX_CONCURRENT_CANCELLABLE_REQUESTS: usize = 2;
const MAX_CONCURRENT_FORMATTING_REQUESTS: usize = 2;
const FORMATTER_SHUTDOWN_GRACE: Duration = Duration::from_secs(2);

#[derive(Clone)]
struct ConcurrencyLimiter {
    active: Arc<AtomicUsize>,
    limit: usize,
}

impl ConcurrencyLimiter {
    fn new(limit: usize) -> Self {
        Self {
            active: Arc::new(AtomicUsize::new(0)),
            limit,
        }
    }

    fn try_acquire(&self) -> Option<ConcurrencySlot> {
        self.active
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                (active < self.limit).then_some(active + 1)
            })
            .ok()
            .map(|_| ConcurrencySlot {
                active: Arc::clone(&self.active),
            })
    }

    fn active_count(&self) -> usize {
        self.active.load(Ordering::Acquire)
    }
}

struct ConcurrencySlot {
    active: Arc<AtomicUsize>,
}

#[derive(Clone, Default)]
struct ActiveRequestIds {
    ids: Arc<Mutex<HashSet<RequestId>>>,
}

impl ActiveRequestIds {
    fn try_reserve(&self, id: RequestId) -> Option<ActiveRequestReservation> {
        let mut ids = self.ids.lock().expect("active request id lock poisoned");
        ids.insert(id.clone()).then(|| ActiveRequestReservation {
            registry: self.clone(),
            id,
        })
    }

    fn release(&self, id: &RequestId) {
        self.ids
            .lock()
            .expect("active request id lock poisoned")
            .remove(id);
    }
}

struct ActiveRequestReservation {
    registry: ActiveRequestIds,
    id: RequestId,
}

impl Drop for ActiveRequestReservation {
    fn drop(&mut self) {
        self.registry.release(&self.id);
    }
}

impl Drop for ConcurrencySlot {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::AcqRel);
    }
}

struct RequestJob {
    cancellation: CancellationToken,
    handle: Option<JoinHandle<()>>,
}

struct RequestJobs {
    limiter: ConcurrencyLimiter,
    jobs: Mutex<HashMap<RequestId, RequestJob>>,
}

impl Default for RequestJobs {
    fn default() -> Self {
        Self {
            limiter: ConcurrencyLimiter::new(MAX_CONCURRENT_CANCELLABLE_REQUESTS),
            jobs: Mutex::new(HashMap::new()),
        }
    }
}

impl RequestJobs {
    fn try_acquire(&self) -> Option<ConcurrencySlot> {
        self.limiter.try_acquire()
    }

    fn reserve(&self, id: RequestId, cancellation: CancellationToken) -> bool {
        use std::collections::hash_map::Entry;

        let mut jobs = self.jobs.lock().expect("request job lock poisoned");
        match jobs.entry(id) {
            Entry::Vacant(entry) => {
                entry.insert(RequestJob {
                    cancellation,
                    handle: None,
                });
                true
            }
            Entry::Occupied(_) => false,
        }
    }

    fn start(&self, id: &RequestId, handle: JoinHandle<()>) {
        let mut jobs = self.jobs.lock().expect("request job lock poisoned");
        let job = jobs.get_mut(id).expect("request job must be reserved");
        assert!(job.handle.replace(handle).is_none());
    }

    fn remove(&self, id: &RequestId) {
        self.jobs
            .lock()
            .expect("request job lock poisoned")
            .remove(id);
    }

    fn cancel(&self, id: &RequestId) {
        let cancellation = self
            .jobs
            .lock()
            .expect("request job lock poisoned")
            .get(id)
            .map(|job| job.cancellation.clone());
        if let Some(cancellation) = cancellation {
            cancellation.cancel();
        }
    }

    fn reap_finished(&self) {
        let finished = {
            let mut jobs = self.jobs.lock().expect("request job lock poisoned");
            let ids: Vec<_> = jobs
                .iter()
                .filter(|(_, job)| job.handle.as_ref().is_some_and(JoinHandle::is_finished))
                .map(|(id, _)| id.clone())
                .collect();
            ids.into_iter()
                .filter_map(|id| jobs.remove(&id))
                .collect::<Vec<_>>()
        };
        for job in finished {
            if job.handle.is_some_and(|handle| handle.join().is_err()) {
                eprintln!("[bifrost-lsp] request worker panicked");
            }
        }
    }

    fn cancel_all_and_join(&self) {
        let jobs: Vec<_> = self
            .jobs
            .lock()
            .expect("request job lock poisoned")
            .drain()
            .map(|(_, job)| job)
            .collect();
        for job in &jobs {
            job.cancellation.cancel();
        }
        for job in jobs {
            if job.handle.is_some_and(|handle| handle.join().is_err()) {
                eprintln!("[bifrost-lsp] request worker panicked during shutdown");
            }
        }
    }
}

#[derive(Clone)]
struct FormattingJobs {
    limiter: ConcurrencyLimiter,
    jobs: Arc<Mutex<HashMap<RequestId, formatting::FormatterCancellation>>>,
}

impl Default for FormattingJobs {
    fn default() -> Self {
        Self {
            limiter: ConcurrencyLimiter::new(MAX_CONCURRENT_FORMATTING_REQUESTS),
            jobs: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl FormattingJobs {
    fn try_acquire(&self) -> Option<ConcurrencySlot> {
        self.limiter.try_acquire()
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

    fn wait_for_empty(&self, timeout: Duration) -> bool {
        let started = Instant::now();
        while self.limiter.active_count() > 0 && started.elapsed() < timeout {
            thread::sleep(Duration::from_millis(10));
        }
        self.limiter.active_count() == 0
    }
}

impl ServerState {
    fn new(config: LspWorkspaceConfig, progress: Option<&StartupProgress>) -> Result<Self, String> {
        let LspWorkspaceConfig {
            editor_roots,
            configuration_base,
            runtime_configuration,
            configuration_protocol,
        } = config;
        let roots = if runtime_configuration.configured_roots.is_empty() {
            editor_roots.clone()
        } else {
            runtime_configuration.configured_roots.clone()
        };
        let (project, active_roots) =
            build_project_for_roots(roots, &runtime_configuration.excluded_paths)?;
        let overlay = Arc::new(OverlayProject::new(project));
        let project = Arc::clone(&overlay) as Arc<dyn Project>;
        if let Some(progress) = progress {
            progress.set_expected_language_count(project.analyzer_languages().len());
        }
        let workspace = build_workspace_for_lsp(project, progress);
        Ok(Self {
            active_roots,
            editor_roots,
            configuration_base,
            runtime_configuration,
            configuration_protocol,
            workspace,
            overlay,
            completion_cache: completion::CompletionCache::new(),
            rejected_didchange_log: ThrottledLog::new(
                REJECTED_DIDCHANGE_LOG_THROTTLE,
                REJECTED_DIDCHANGE_LOG_MAX_ENTRIES,
            ),
            published_diagnostic_uris: Vec::new(),
            open_documents: HashMap::new(),
            document_generations: Arc::new(Mutex::new(HashMap::new())),
            request_jobs: RequestJobs::default(),
            formatting_jobs: FormattingJobs::default(),
            active_request_ids: ActiveRequestIds::default(),
        })
    }

    pub(crate) fn project(&self) -> &dyn Project {
        self.overlay.as_ref()
    }

    fn register_runtime_configuration(&mut self, connection: &Connection) -> Result<(), String> {
        if !self.configuration_protocol.supports_dynamic_registration
            || self.configuration_protocol.registration_sent
        {
            return Ok(());
        }
        self.configuration_protocol.registration_sent = true;
        let request = Request::new(
            runtime_configuration_registration_request_id(),
            RegisterCapability::METHOD.to_string(),
            RegistrationParams {
                registrations: vec![Registration {
                    id: "bifrost-runtime-configuration".to_string(),
                    method: DidChangeConfiguration::METHOD.to_string(),
                    register_options: Some(serde_json::json!({"section": "bifrost"})),
                }],
            },
        );
        connection
            .sender
            .send(Message::Request(request))
            .map_err(|err| format!("Failed to register runtime configuration: {err}"))
    }

    fn request_runtime_configuration(&mut self, connection: &Connection) -> Result<(), String> {
        self.configuration_protocol.next_pull_generation = self
            .configuration_protocol
            .next_pull_generation
            .saturating_add(1);
        let generation = self.configuration_protocol.next_pull_generation;
        self.configuration_protocol.latest_pull_generation = generation;
        let id = RequestId::from(format!("bifrost-runtime-configuration-{generation}"));
        let request = Request::new(
            id.clone(),
            WorkspaceConfiguration::METHOD.to_string(),
            ConfigurationParams {
                items: vec![ConfigurationItem {
                    scope_uri: None,
                    section: Some("bifrost".to_string()),
                }],
            },
        );
        connection
            .sender
            .send(Message::Request(request))
            .map_err(|err| format!("Failed to request runtime configuration: {err}"))?;
        self.configuration_protocol.pending_pulls.clear();
        self.configuration_protocol
            .pending_pulls
            .insert(id, generation);
        Ok(())
    }

    fn apply_workspace_folder_change(
        &mut self,
        params: DidChangeWorkspaceFoldersParams,
    ) -> Result<Vec<Uri>, String> {
        let mut roots = self.editor_roots.clone();
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
        if roots == self.editor_roots {
            return Ok(Vec::new());
        }
        if !self.runtime_configuration.configured_roots.is_empty() {
            self.editor_roots = roots;
            return Ok(Vec::new());
        }
        let prepared = self
            .prepare_workspace_rebuild(roots.clone(), &self.runtime_configuration.excluded_paths)?;
        let stale = self.commit_workspace_rebuild(prepared)?;
        self.editor_roots = roots;
        Ok(stale)
    }

    fn prepare_workspace_rebuild(
        &self,
        roots: Vec<WorkspaceRoot>,
        excluded_paths: &[PathBuf],
    ) -> Result<PreparedWorkspaceRebuild, String> {
        let (project, active_roots): (Arc<dyn Project>, Vec<WorkspaceRoot>) = if roots.is_empty() {
            (
                Arc::new(NoWorkspaceProject::new(self.project().root().to_path_buf())),
                Vec::new(),
            )
        } else {
            build_project_for_roots(roots, excluded_paths)?
        };
        let overlay = Arc::new(OverlayProject::new(project));
        let mut open_document_paths = HashMap::new();
        let mut replayed_files = BTreeSet::new();
        for (key, document) in &self.open_documents {
            if let Some(file) = resolve_project_file(overlay.as_ref(), &document.uri)
                .or_else(|| project_file_for_abs_path(overlay.as_ref(), &document.abs_path))
            {
                open_document_paths.insert(key.clone(), file.abs_path());
                overlay.set(file.abs_path(), document.text.clone());
                replayed_files.insert(file);
            }
        }
        let project = Arc::clone(&overlay) as Arc<dyn Project>;
        let mut workspace = build_workspace_for_lsp(project, None);
        if !replayed_files.is_empty() {
            workspace = workspace.update(&replayed_files);
        }
        let mut stale = Vec::new();
        let mut retained_diagnostics = Vec::new();
        for uri in &self.published_diagnostic_uris {
            if uri_belongs_to_project(overlay.as_ref(), uri) {
                retained_diagnostics.push(uri.clone());
            } else {
                stale.push(uri.clone());
            }
        }
        Ok(PreparedWorkspaceRebuild {
            active_roots,
            workspace,
            overlay,
            open_document_paths,
            retained_diagnostics,
            stale_diagnostics: stale,
        })
    }

    fn commit_workspace_rebuild(
        &mut self,
        prepared: PreparedWorkspaceRebuild,
    ) -> Result<Vec<Uri>, String> {
        self.formatting_jobs.cancel_all();
        if !self
            .formatting_jobs
            .wait_for_empty(FORMATTER_SHUTDOWN_GRACE)
        {
            return Err(format!(
                "formatter cleanup did not finish within {} before workspace rebuild",
                FORMATTER_SHUTDOWN_GRACE.as_secs_f64()
            ));
        }
        for (key, abs_path) in prepared.open_document_paths {
            if let Some(document) = self.open_documents.get_mut(&key) {
                document.abs_path = abs_path;
            }
        }
        self.active_roots = prepared.active_roots;
        let old_workspace = std::mem::replace(&mut self.workspace, prepared.workspace);
        let old_overlay = std::mem::replace(&mut self.overlay, prepared.overlay);
        self.completion_cache.clear();
        self.published_diagnostic_uris = prepared.retained_diagnostics;
        drop(old_workspace);
        drop(old_overlay);
        Ok(prepared.stale_diagnostics)
    }

    fn apply_runtime_configuration(
        &mut self,
        configuration: BifrostRuntimeConfiguration,
    ) -> Result<Vec<Uri>, String> {
        if configuration == self.runtime_configuration {
            return Ok(Vec::new());
        }
        let rebuild_required = configuration.configured_roots
            != self.runtime_configuration.configured_roots
            || configuration.excluded_paths != self.runtime_configuration.excluded_paths;
        if !rebuild_required {
            self.runtime_configuration = configuration;
            return Ok(Vec::new());
        }
        let roots = if configuration.configured_roots.is_empty() {
            self.editor_roots.clone()
        } else {
            configuration.configured_roots.clone()
        };
        let prepared = self.prepare_workspace_rebuild(roots, &configuration.excluded_paths)?;
        let stale = self.commit_workspace_rebuild(prepared)?;
        self.runtime_configuration = configuration;
        Ok(stale)
    }

    fn remember_published_diagnostic_uri(&mut self, uri: &Uri) {
        if !self.published_diagnostic_uris.contains(uri) {
            self.published_diagnostic_uris.push(uri.clone());
        }
    }

    fn remember_open_document(&mut self, uri: Uri, abs_path: PathBuf, version: i32, text: String) {
        self.bump_document_generation(&uri);
        self.open_documents.insert(
            uri.as_str().to_string(),
            OpenDocument {
                uri,
                abs_path,
                version,
                text,
            },
        );
    }

    fn update_open_document(&mut self, uri: &Uri, version: i32, text: String) {
        self.bump_document_generation(uri);
        if let Some(document) = self.open_documents.get_mut(uri.as_str()) {
            document.version = version;
            document.text = text;
        }
    }

    fn update_open_document_version(&mut self, uri: &Uri, version: i32) {
        if let Some(document) = self.open_documents.get_mut(uri.as_str()) {
            document.version = version;
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
    /// within [`REJECTED_DIDCHANGE_LOG_THROTTLE`]. The throttle map is
    /// bounded; entries older than the throttle window are pruned when it
    /// fills.
    fn maybe_log_rejected_didchange(&self, uri: &Uri, version: i32, reason: &str) {
        let now = Instant::now();
        if self.rejected_didchange_log.should_log(uri.as_str(), now) {
            eprintln!(
                "[bifrost-lsp] dropping didChange for {} at version {version}: {reason}",
                uri.as_str(),
            );
        }
    }

    /// Unknown documents are keyed together so a client cannot bypass the
    /// throttle by cycling through attacker-controlled URIs. Do not echo the
    /// URI because it is neither trusted nor useful without tracked state.
    fn maybe_log_unknown_document_didchange(&self, version: i32) {
        const UNKNOWN_DOCUMENT_LOG_KEY: &str = "<unknown-document>";

        let now = Instant::now();
        if self
            .rejected_didchange_log
            .should_log(UNKNOWN_DOCUMENT_LOG_KEY, now)
        {
            eprintln!(
                "[bifrost-lsp] dropping didChange for an unknown document at version {version}: document is not open"
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

fn normalize_paths(paths: &mut Vec<PathBuf>) {
    paths.sort();
    paths.dedup();
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
        // Build the analyzer regardless of progress support. Work-done progress
        // is a UI capability (can the client render a progress bar); it has no
        // bearing on whether the analyzer store should be populated.
        None => WorkspaceAnalyzer::build_persisted(project, config),
    }
}

fn collect_workspace_config(
    params: &InitializeParams,
    fallback: &Path,
) -> Result<LspWorkspaceConfig, String> {
    let BifrostInitializationOptions {
        roots,
        exclude,
        formatter_commands,
    } = bifrost_initialization_options(params);
    let configuration_base = fallback
        .canonicalize()
        .unwrap_or_else(|_| fallback.to_path_buf());
    let mut editor_roots = collect_workspace_roots(params, fallback)?;
    normalize_roots(&mut editor_roots);
    let mut configured_roots = if roots.is_empty() {
        Vec::new()
    } else {
        let roots: Vec<WorkspaceRoot> = roots
            .into_iter()
            .filter_map(|root| workspace_root_for_config_path(&root, &configuration_base))
            .collect();
        if roots.is_empty() {
            return Err("bifrost.roots did not contain any usable directories".to_string());
        }
        roots
    };
    normalize_roots(&mut configured_roots);
    let mut excluded_paths: Vec<PathBuf> = exclude
        .into_iter()
        .filter_map(|path| scoped_config_path(&path, &configuration_base))
        .map(|path| path.canonicalize().unwrap_or(path))
        .collect();
    normalize_paths(&mut excluded_paths);
    let workspace_capabilities = params.capabilities.workspace.as_ref();
    let supports_pull = workspace_capabilities
        .and_then(|workspace| workspace.configuration)
        .unwrap_or(false);
    let supports_dynamic_registration = workspace_capabilities
        .and_then(|workspace| workspace.did_change_configuration.as_ref())
        .and_then(|configuration| configuration.dynamic_registration)
        .unwrap_or(false);
    Ok(LspWorkspaceConfig {
        editor_roots,
        configuration_base,
        runtime_configuration: BifrostRuntimeConfiguration {
            configured_roots,
            excluded_paths,
            formatter_commands,
        },
        configuration_protocol: RuntimeConfigurationProtocol {
            supports_pull,
            supports_dynamic_registration,
            ..RuntimeConfigurationProtocol::default()
        },
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

fn parse_runtime_configuration(
    value: &serde_json::Value,
    base: &Path,
) -> Result<BifrostRuntimeConfiguration, String> {
    let outer = value
        .as_object()
        .ok_or_else(|| "settings must be an object".to_string())?;
    let object = match outer.get("bifrost") {
        Some(value) => value
            .as_object()
            .ok_or_else(|| "settings.bifrost must be an object".to_string())?,
        None => outer,
    };
    let roots = strict_optional_string_array(object, "roots")?;
    let exclude = strict_optional_string_array(object, "exclude")?;
    let formatter_commands: Vec<formatting::FormatterCommandRule> =
        match object.get("formatterCommands") {
            Some(value) => serde_json::from_value(value.clone())
                .map_err(|err| format!("formatterCommands is invalid: {err}"))?,
            None => Vec::new(),
        };
    for (index, rule) in formatter_commands.iter().enumerate() {
        rule.validate()
            .map_err(|err| format!("formatterCommands[{index}] is invalid: {err}"))?;
    }
    let mut configured_roots = roots
        .iter()
        .map(|root| runtime_workspace_root_for_config_path(root, base))
        .collect::<Result<Vec<_>, _>>()?;
    normalize_roots(&mut configured_roots);
    let mut excluded_paths = exclude
        .iter()
        .map(|path| {
            scoped_config_path(path, base)
                .ok_or_else(|| "exclude entries must not be empty".to_string())
                .map(|path| path.canonicalize().unwrap_or(path))
        })
        .collect::<Result<Vec<_>, _>>()?;
    normalize_paths(&mut excluded_paths);
    Ok(BifrostRuntimeConfiguration {
        configured_roots,
        excluded_paths,
        formatter_commands,
    })
}

fn strict_optional_string_array(
    object: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<Vec<String>, String> {
    let Some(value) = object.get(key) else {
        return Ok(Vec::new());
    };
    let items = value
        .as_array()
        .ok_or_else(|| format!("{key} must be an array of strings"))?;
    items
        .iter()
        .enumerate()
        .map(|(index, item)| {
            item.as_str()
                .map(str::to_string)
                .ok_or_else(|| format!("{key}[{index}] must be a string"))
        })
        .collect()
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
    match configured_workspace_root(raw, base) {
        Ok(root) => Some(root),
        Err(err) => {
            eprintln!("[bifrost-lsp] ignoring bifrost root setting: {err}");
            None
        }
    }
}

fn runtime_workspace_root_for_config_path(raw: &str, base: &Path) -> Result<WorkspaceRoot, String> {
    configured_workspace_root(raw, base)
}

fn configured_workspace_root(raw: &str, base: &Path) -> Result<WorkspaceRoot, String> {
    let path = scoped_config_path(raw, base)
        .ok_or_else(|| "roots entries must not be empty".to_string())?;
    let analyzer_path = path
        .canonicalize()
        .map_err(|err| format!("root {} is unavailable: {err}", path.display()))?;
    if !analyzer_path.is_dir() {
        return Err(format!(
            "root is not a directory: {}",
            analyzer_path.display()
        ));
    }
    Ok(WorkspaceRoot {
        identity_uri: path_to_uri_string(&path),
        identity_path: path,
        analyzer_path,
    })
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
    use std::sync::Barrier;
    use std::sync::mpsc;

    use super::*;
    use lsp_types::notification::Progress;
    use serde_json::json;

    #[test]
    fn runtime_configuration_accepts_direct_and_nested_full_snapshots() {
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path().canonicalize().unwrap();
        let source = base.join("source");
        std::fs::create_dir_all(&source).unwrap();
        let settings = json!({
            "roots": ["source"],
            "exclude": ["target", "target"],
            "formatterCommands": [{"include": ["*.rs"], "command": "rustfmt"}]
        });

        let direct = parse_runtime_configuration(&settings, &base).unwrap();
        let nested = parse_runtime_configuration(&json!({"bifrost": settings}), &base).unwrap();

        assert_eq!(direct, nested);
        assert_eq!(direct.configured_roots.len(), 1);
        assert_eq!(direct.excluded_paths, vec![base.join("target")]);
        assert_eq!(direct.formatter_commands.len(), 1);
    }

    #[test]
    fn runtime_configuration_missing_fields_clear_previous_values() {
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path().canonicalize().unwrap();

        let configuration =
            parse_runtime_configuration(&json!({"unrelatedLaunchSetting": true}), &base).unwrap();

        assert!(configuration.configured_roots.is_empty());
        assert!(configuration.excluded_paths.is_empty());
        assert!(configuration.formatter_commands.is_empty());
    }

    #[test]
    fn runtime_configuration_rejects_malformed_recognized_fields() {
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path().canonicalize().unwrap();

        let roots_error = parse_runtime_configuration(&json!({"roots": "src"}), &base)
            .expect_err("roots must be rejected atomically");
        assert!(roots_error.contains("roots must be an array"));

        let formatter_error = parse_runtime_configuration(
            &json!({"exclude": [], "formatterCommands": [{"include": ["*.rs"]}]}),
            &base,
        )
        .expect_err("invalid formatter rule must reject the snapshot");
        assert!(formatter_error.contains("formatterCommands is invalid"));
    }

    #[test]
    fn runtime_configuration_rejects_semantically_invalid_formatter_rules() {
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path().canonicalize().unwrap();
        let invalid_rules = [
            (
                json!({"formatterCommands": [{"command": "   "}]}),
                "command must not be empty",
            ),
            (
                json!({"formatterCommands": [{"command": "fmt", "language": "brainfuck"}]}),
                "unknown language",
            ),
            (
                json!({"formatterCommands": [{"command": "fmt", "include": ["["]}]}),
                "not a valid glob",
            ),
        ];

        for (settings, expected) in invalid_rules {
            let error = parse_runtime_configuration(&settings, &base)
                .expect_err("semantic formatter error must reject the whole snapshot");
            assert!(error.contains(expected), "unexpected error: {error}");
        }
    }

    #[test]
    fn workspace_config_captures_runtime_configuration_capabilities() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let params: InitializeParams = serde_json::from_value(json!({
            "processId": null,
            "rootUri": path_to_uri_string(&root),
            "capabilities": {
                "workspace": {
                    "configuration": true,
                    "didChangeConfiguration": {"dynamicRegistration": true}
                }
            }
        }))
        .unwrap();

        let config = collect_workspace_config(&params, &root).unwrap();

        assert!(config.configuration_protocol.supports_pull);
        assert!(config.configuration_protocol.supports_dynamic_registration);
    }

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

        assert_eq!(scoped.workspace_root_for_file(&file), nested.normalize());
    }

    #[test]
    fn request_jobs_cancel_registered_worker_and_ignore_unknown_ids() {
        let jobs = RequestJobs::default();
        jobs.cancel(&RequestId::from(404));

        let slot = jobs.try_acquire().expect("first request slot");
        let token = CancellationToken::default();
        let worker_token = token.clone();
        let (ready_tx, ready_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let handle = thread::spawn(move || {
            ready_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            assert!(worker_token.is_cancelled());
            drop(slot);
        });
        let id = RequestId::from(1);
        assert!(jobs.reserve(id.clone(), token));
        jobs.start(&id, handle);

        ready_rx.recv().unwrap();
        jobs.cancel(&id);
        release_tx.send(()).unwrap();
        jobs.cancel_all_and_join();

        assert_eq!(jobs.limiter.active_count(), 0);
    }

    #[test]
    fn request_jobs_bound_and_reap_completed_workers() {
        let jobs = RequestJobs::default();
        let first = jobs.try_acquire().expect("first request slot");
        let second = jobs.try_acquire().expect("second request slot");
        assert!(jobs.try_acquire().is_none());
        drop(first);
        drop(second);

        let slot = jobs.try_acquire().expect("reused request slot");
        let (done_tx, done_rx) = mpsc::channel();
        let handle = thread::spawn(move || {
            drop(slot);
            done_tx.send(()).unwrap();
        });
        let id = RequestId::from(2);
        assert!(jobs.reserve(id.clone(), CancellationToken::default()));
        jobs.start(&id, handle);
        done_rx.recv().unwrap();
        while !jobs
            .jobs
            .lock()
            .unwrap()
            .get(&id)
            .and_then(|job| job.handle.as_ref())
            .is_some_and(JoinHandle::is_finished)
        {
            thread::yield_now();
        }
        jobs.reap_finished();
        jobs.cancel(&id);

        assert!(jobs.jobs.lock().unwrap().is_empty());
        assert_eq!(jobs.limiter.active_count(), 0);
    }

    #[test]
    fn request_jobs_shutdown_cancels_and_joins_all_workers() {
        let jobs = RequestJobs::default();
        let barrier = Arc::new(Barrier::new(MAX_CONCURRENT_CANCELLABLE_REQUESTS + 1));
        for id in 0..MAX_CONCURRENT_CANCELLABLE_REQUESTS {
            let slot = jobs.try_acquire().expect("request slot");
            let token = CancellationToken::default();
            let worker_token = token.clone();
            let worker_barrier = Arc::clone(&barrier);
            let handle = thread::spawn(move || {
                worker_barrier.wait();
                while !worker_token.is_cancelled() {
                    thread::yield_now();
                }
                drop(slot);
            });
            let id = RequestId::from(id as i32);
            assert!(jobs.reserve(id.clone(), token));
            jobs.start(&id, handle);
        }

        barrier.wait();
        jobs.cancel_all_and_join();

        assert!(jobs.jobs.lock().unwrap().is_empty());
        assert_eq!(jobs.limiter.active_count(), 0);
    }

    #[test]
    fn request_jobs_reject_duplicate_active_ids_without_replacement() {
        let jobs = RequestJobs::default();
        let id = RequestId::from(7);
        let original = CancellationToken::default();

        assert!(jobs.reserve(id.clone(), original.clone()));
        assert!(!jobs.reserve(id.clone(), CancellationToken::default()));
        jobs.cancel(&id);

        assert!(original.is_cancelled());
        jobs.remove(&id);
    }

    #[test]
    fn panicking_reference_worker_ends_progress_and_returns_error() {
        let messages = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&messages);
        let cancellation = CancellationToken::default();
        let context = RequestContext::new(
            cancellation.clone(),
            Some(ProgressToken::String("panic-progress".to_string())),
            "Finding references",
            "Resolving symbol",
            Arc::new(move |message| {
                sink.lock().unwrap().push(message);
                Ok(())
            }),
        );
        context.begin();

        let response = finish_reference_request::<serde_json::Value>(
            &RequestId::from(9),
            References::METHOD,
            &context,
            &cancellation,
            || panic!("injected reference failure"),
        );

        assert_eq!(
            response.error.as_ref().map(|error| error.code),
            Some(ErrorCode::InternalError as i32)
        );
        let messages = messages.lock().unwrap();
        assert_eq!(messages.len(), 2);
        let Message::Notification(end) = &messages[1] else {
            panic!("expected progress end notification");
        };
        assert_eq!(end.method, Progress::METHOD);
        assert_eq!(end.params["token"], json!("panic-progress"));
        assert_eq!(end.params["value"]["kind"], json!("end"));
        assert_eq!(end.params["value"]["message"], json!("Failed"));
    }

    #[test]
    fn active_request_ids_are_reserved_across_async_job_kinds() {
        let ids = ActiveRequestIds::default();
        let id = RequestId::from(8);

        let reference_reservation = ids.try_reserve(id.clone()).unwrap();
        assert!(ids.try_reserve(id.clone()).is_none());
        drop(reference_reservation);

        assert!(ids.try_reserve(id).is_some());
    }
}
