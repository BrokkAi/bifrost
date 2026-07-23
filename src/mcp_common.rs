use crate::{
    SearchToolsService, SearchToolsServiceError, SearchToolsServiceErrorCode, ToolOutput,
    analyzer::policy::escape_terminal_text, searchtools_render::RenderOptions,
    tool_arguments::normalize_tool_arguments,
};
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::io::{self, BufRead, Write};
use std::path::PathBuf;

const JSONRPC_VERSION: &str = "2.0";
const PROTOCOL_VERSION: &str = "2025-11-25";
const PARSE_ERROR: i64 = -32700;
const INVALID_REQUEST: i64 = -32600;
const METHOD_NOT_FOUND: i64 = -32601;
const INVALID_PARAMS: i64 = -32602;
const INTERNAL_ERROR: i64 = -32603;
const RESOURCE_NOT_FOUND: i64 = -32002;
const GET_SUMMARIES_RESPONSE_BUDGET_BYTES: usize = 4_096;
const AGENTS_GUIDANCE_URI: &str = "bifrost://agent-guidance/agents.md";
const AGENTS_GUIDANCE_MIME_TYPE: &str = "text/markdown";
const ROOTS_REQUEST_ID_PREFIX: &str = "bifrost-roots-";
const CODEX_MCP_CLIENT_NAME: &str = "codex-mcp-client";
const CODEX_SANDBOX_STATE_META_CAPABILITY: &str = "codex/sandbox-state-meta";
const AGENTS_GUIDANCE_TEXT: &str = include_str!("../resources/agent-guidance/bifrost-agents.md");

pub(crate) const BENCHMARK_PROFILE_BOUNDARY_METHOD: &str = "bifrost/benchmark-profile-boundary";
pub(crate) const BENCHMARK_PROFILE_BOUNDARY_MARKER: &str =
    "\n\u{1e}bifrost-benchmark-profile-boundary\u{1e}\n";
pub(crate) const MCP_FILE_WATCHER_ENV: &str = "BIFROST_MCP_FILE_WATCHER";

pub const SEARCHTOOLS_INSTRUCTIONS: &str =
    "Analyzer-backed search tools for source code workspaces.";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct McpRenderOptions {
    pub render_line_numbers: bool,
}

impl Default for McpRenderOptions {
    fn default() -> Self {
        Self {
            render_line_numbers: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct McpServerSpec {
    pub instructions: &'static str,
    pub tool_names: HashSet<String>,
    pub tool_descriptors: Vec<Value>,
}

#[derive(Debug)]
struct McpConnectionState {
    accepts_client_roots: bool,
    client_supports_roots: bool,
    workspace_binding_source: WorkspaceBindingSource,
    codex_sandbox_cwd_uri: Option<String>,
    codex_sandbox_root: Option<PathBuf>,
    initialize_received: bool,
    initialized: bool,
    pending_roots_request: Option<String>,
    roots_refresh_requested: bool,
    next_request_id: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WorkspaceBindingSource {
    None,
    ExplicitRoot,
    ClientRoots,
    CodexSandboxState,
}

impl McpConnectionState {
    fn new(accepts_client_roots: bool) -> Self {
        Self {
            accepts_client_roots,
            client_supports_roots: false,
            workspace_binding_source: if accepts_client_roots {
                WorkspaceBindingSource::None
            } else {
                WorkspaceBindingSource::ExplicitRoot
            },
            codex_sandbox_cwd_uri: None,
            codex_sandbox_root: None,
            initialize_received: false,
            initialized: false,
            pending_roots_request: None,
            roots_refresh_requested: false,
            next_request_id: 1,
        }
    }

    fn roots_request(&mut self) -> Option<Value> {
        if !self.accepts_client_roots
            || !self.client_supports_roots
            || !self.initialized
            || self.pending_roots_request.is_some()
        {
            return None;
        }
        let id = format!("{ROOTS_REQUEST_ID_PREFIX}{}", self.next_request_id);
        self.next_request_id += 1;
        self.pending_roots_request = Some(id.clone());
        Some(json!({
            "jsonrpc": JSONRPC_VERSION,
            "id": id,
            "method": "roots/list",
            "params": {},
        }))
    }

    fn finish_roots_response(&mut self) -> Option<Value> {
        if std::mem::take(&mut self.roots_refresh_requested) {
            self.roots_request()
        } else {
            None
        }
    }

    fn accepts_codex_sandbox_state(&self) -> bool {
        self.accepts_client_roots && self.initialize_received && !self.client_supports_roots
    }
}

pub fn build_server_spec(
    instructions: &'static str,
    tool_descriptors: Vec<Value>,
) -> Result<McpServerSpec, String> {
    build_server_spec_with_hidden(instructions, tool_descriptors, Vec::new())
}

pub fn build_server_spec_with_hidden(
    instructions: &'static str,
    tool_descriptors: Vec<Value>,
    hidden_tool_names: Vec<String>,
) -> Result<McpServerSpec, String> {
    let mut tool_names = HashSet::with_capacity(tool_descriptors.len());
    for descriptor in &tool_descriptors {
        let Some(name) = descriptor.get("name").and_then(Value::as_str) else {
            return Err("tool descriptor missing string name".to_string());
        };
        tool_names.insert(name.to_string());
    }
    tool_names.extend(hidden_tool_names);

    Ok(McpServerSpec {
        instructions,
        tool_names,
        tool_descriptors,
    })
}

pub fn run_stdio_server(
    root: Option<PathBuf>,
    render_options: McpRenderOptions,
    spec: &McpServerSpec,
) -> Result<(), String> {
    // Explicit roots build in the background. Rootless servers answer initialize
    // without touching process cwd and bind only from a client-provided workspace.
    let accepts_client_roots = root.is_none();
    let watch_files = file_watching_enabled(std::env::var_os(MCP_FILE_WATCHER_ENV).as_deref())?;
    let service = match (root, watch_files) {
        (Some(root), true) => SearchToolsService::new_deferred(root)?,
        (Some(root), false) => SearchToolsService::new_deferred_manual(root)?,
        (None, true) => SearchToolsService::new_unbound(),
        (None, false) => SearchToolsService::new_unbound_manual(),
    };
    let mut connection = McpConnectionState::new(accepts_client_roots);

    let stdin = io::stdin();
    let mut stdout = io::stdout();
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(line) => line,
            Err(err) => return Err(format!("Failed to read MCP request: {err}")),
        };

        if line.trim().is_empty() {
            continue;
        }

        let response = match serde_json::from_str::<Value>(&line) {
            Ok(message) => {
                dispatch_message(&service, &mut connection, message, render_options, spec)
            }
            Err(err) => Some(error_response(
                Value::Null,
                PARSE_ERROR,
                format!("Invalid JSON: {err}"),
            )),
        };

        if let Some(response) = response {
            let encoded = serde_json::to_string(&response)
                .map_err(|err| format!("Failed to serialize MCP response: {err}"))?;
            writeln!(stdout, "{encoded}")
                .and_then(|_| stdout.flush())
                .map_err(|err| format!("Failed to write MCP response: {err}"))?;
        }
    }

    // Normal shutdown (stdin reached EOF): the process is about to exit, so skip
    // the service's destructor. Dropping it would walk the whole in-memory index
    // freeing millions of allocations and tear down the recursive file watcher --
    // a noticeable pause that the OS would otherwise do for free on exit. We leak
    // it deliberately: all responses are already flushed (above), and the
    // analyzer DB is durable -- every reconcile/update committed its WAL
    // transaction synchronously, so the next open recovers cleanly without the
    // checkpoint that `Drop` would run here. Error paths above return early and
    // are unaffected.
    std::mem::forget(service);
    Ok(())
}

fn file_watching_enabled(value: Option<&OsStr>) -> Result<bool, String> {
    match value {
        None => Ok(true),
        Some(value) if value == "on" => Ok(true),
        Some(value) if value == "off" => Ok(false),
        Some(value) => Err(format!(
            "{MCP_FILE_WATCHER_ENV} must be `on` or `off`, not `{}`",
            value.to_string_lossy()
        )),
    }
}

fn dispatch_message(
    service: &SearchToolsService,
    connection: &mut McpConnectionState,
    message: Value,
    render_options: McpRenderOptions,
    spec: &McpServerSpec,
) -> Option<Value> {
    let Some(object) = message.as_object() else {
        return Some(error_response(
            Value::Null,
            INVALID_REQUEST,
            "MCP message must be a JSON object".to_string(),
        ));
    };

    let jsonrpc = object
        .get("jsonrpc")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if jsonrpc != JSONRPC_VERSION {
        let id = object.get("id").cloned().unwrap_or(Value::Null);
        return Some(error_response(
            id,
            INVALID_REQUEST,
            format!("Unsupported jsonrpc version: {jsonrpc}"),
        ));
    }

    let Some(method) = object.get("method").and_then(Value::as_str) else {
        if let Some(id) = object.get("id")
            && (object.contains_key("result") || object.contains_key("error"))
        {
            return handle_response(service, connection, id, object);
        }
        let id = object.get("id").cloned().unwrap_or(Value::Null);
        return Some(error_response(
            id,
            INVALID_REQUEST,
            "Missing method".to_string(),
        ));
    };

    let params = object.get("params").cloned().unwrap_or(Value::Null);
    let id = object.get("id").cloned();

    match id {
        Some(id) => {
            if method == "initialize" {
                if connection.initialize_received {
                    return Some(error_response(
                        id,
                        INVALID_REQUEST,
                        "MCP initialize may only be sent once per connection".to_string(),
                    ));
                }
                connection.initialize_received = true;
                connection.client_supports_roots = params
                    .pointer("/capabilities/roots")
                    .is_some_and(Value::is_object);
                let client_is_codex = params.pointer("/clientInfo/name").and_then(Value::as_str)
                    == Some(CODEX_MCP_CLIENT_NAME);
                let protocol = if !connection.accepts_client_roots {
                    "explicit-root"
                } else if connection.client_supports_roots {
                    "mcp-roots"
                } else {
                    "codex-sandbox-state"
                };
                eprintln!(
                    "bifrost: MCP initialize client={} roots_supported={} workspace_protocol={protocol}",
                    if client_is_codex {
                        CODEX_MCP_CLIENT_NAME
                    } else {
                        "other"
                    },
                    connection.client_supports_roots,
                );
            }
            Some(dispatch_request(
                service,
                connection,
                id,
                method,
                params,
                render_options,
                spec,
            ))
        }
        None => handle_notification(service, connection, method, params),
    }
}

fn handle_response(
    service: &SearchToolsService,
    connection: &mut McpConnectionState,
    id: &Value,
    response: &serde_json::Map<String, Value>,
) -> Option<Value> {
    let pending_id = connection.pending_roots_request.as_deref()?;
    if id.as_str() != Some(pending_id) {
        return None;
    }
    connection.pending_roots_request = None;

    // A roots change received while this request was in flight makes its
    // response stale. The notification already revoked the active workspace;
    // discard the old list and request the current one before binding again.
    if connection.roots_refresh_requested {
        return connection.finish_roots_response();
    }

    if let Some(error) = response.get("error") {
        eprintln!("bifrost: MCP roots/list failed: {error}");
        return connection.finish_roots_response();
    }
    let Some(roots) = response
        .get("result")
        .and_then(|result| result.get("roots"))
        .and_then(Value::as_array)
    else {
        eprintln!("bifrost: MCP roots/list response is missing result.roots");
        return connection.finish_roots_response();
    };

    let mut last_error = None;
    for root in roots {
        let Some(uri) = root.get("uri").and_then(Value::as_str) else {
            last_error = Some("root entry is missing a string uri".to_string());
            continue;
        };
        let path = match client_root_to_path(uri) {
            Ok(path) => path,
            Err(error) => {
                last_error = Some(error);
                continue;
            }
        };
        match service.bind_client_workspace(path) {
            Ok(root) => {
                connection.workspace_binding_source = WorkspaceBindingSource::ClientRoots;
                connection.codex_sandbox_cwd_uri = None;
                connection.codex_sandbox_root = None;
                eprintln!(
                    "bifrost: bound MCP workspace source=roots/list root={}",
                    escape_terminal_text(root.to_string_lossy().as_ref())
                );
                return connection.finish_roots_response();
            }
            Err(error) => last_error = Some(error.to_string()),
        }
    }

    if roots.is_empty() {
        if let Err(error) = service.unbind_client_workspace() {
            eprintln!("bifrost: failed to clear revoked MCP workspace root: {error}");
        }
        connection.workspace_binding_source = WorkspaceBindingSource::None;
        connection.codex_sandbox_cwd_uri = None;
        connection.codex_sandbox_root = None;
        eprintln!("bifrost: MCP client returned no workspace roots; server remains unbound");
    } else if let Some(error) = last_error {
        if let Err(unbind_error) = service.unbind_client_workspace() {
            eprintln!("bifrost: failed to clear unusable MCP workspace roots: {unbind_error}");
        }
        connection.workspace_binding_source = WorkspaceBindingSource::None;
        connection.codex_sandbox_cwd_uri = None;
        connection.codex_sandbox_root = None;
        eprintln!("bifrost: no usable MCP workspace root: {error}");
    }
    connection.finish_roots_response()
}

fn client_root_to_path(root: &str) -> Result<PathBuf, String> {
    let native_path = PathBuf::from(root);
    if native_path.is_absolute() {
        return Ok(native_path);
    }

    file_uri_to_path(root)
}

fn file_uri_to_path(uri: &str) -> Result<PathBuf, String> {
    let parsed =
        url::Url::parse(uri).map_err(|error| format!("invalid root URI `{uri}`: {error}"))?;
    if parsed.scheme() != "file" {
        return Err(format!(
            "unsupported root URI scheme `{}`; expected file",
            parsed.scheme()
        ));
    }
    parsed
        .to_file_path()
        .map_err(|()| format!("root URI is not a local filesystem path: {uri}"))
        .and_then(|path| {
            if path.is_absolute() {
                Ok(path)
            } else {
                Err(format!("root URI is not absolute: {uri}"))
            }
        })
}

fn dispatch_request(
    service: &SearchToolsService,
    connection: &mut McpConnectionState,
    id: Value,
    method: &str,
    params: Value,
    render_options: McpRenderOptions,
    spec: &McpServerSpec,
) -> Value {
    let response = match method {
        "initialize" => Ok(initialize_result(
            spec.instructions,
            connection.accepts_codex_sandbox_state(),
        )),
        "ping" => Ok(json!({})),
        BENCHMARK_PROFILE_BOUNDARY_METHOD => write_benchmark_profile_boundary(),
        "resources/list" => Ok(list_resources_result()),
        "resources/read" => handle_resource_read(params),
        "tools/list" => Ok(list_tools_result(spec)),
        "tools/call" => handle_tool_call(service, connection, params, render_options, spec),
        _ => Err((METHOD_NOT_FOUND, format!("Unknown method: {method}"))),
    };

    match response {
        Ok(result) => success_response(id, result),
        Err((code, message)) => error_response(id, code, message),
    }
}

fn write_benchmark_profile_boundary() -> Result<Value, (i64, String)> {
    let mut stderr = io::stderr().lock();
    stderr
        .write_all(BENCHMARK_PROFILE_BOUNDARY_MARKER.as_bytes())
        .and_then(|_| stderr.flush())
        .map_err(|err| {
            (
                INTERNAL_ERROR,
                format!("Failed to write benchmark profile boundary: {err}"),
            )
        })?;
    Ok(json!({}))
}

fn handle_notification(
    service: &SearchToolsService,
    connection: &mut McpConnectionState,
    method: &str,
    _params: Value,
) -> Option<Value> {
    match method {
        "notifications/initialized" => {
            connection.initialized = true;
            connection.roots_request()
        }
        "notifications/roots/list_changed" => {
            if !connection.accepts_client_roots || !connection.client_supports_roots {
                return None;
            }
            if let Err(error) = service.unbind_client_workspace() {
                eprintln!("bifrost: failed to revoke changed MCP workspace roots: {error}");
            }
            connection.workspace_binding_source = WorkspaceBindingSource::None;
            connection.codex_sandbox_cwd_uri = None;
            connection.codex_sandbox_root = None;
            if connection.pending_roots_request.is_some() {
                connection.roots_refresh_requested = true;
                None
            } else {
                connection.roots_request()
            }
        }
        _ => None,
    }
}

fn initialize_result(instructions: &str, advertise_codex_sandbox_state: bool) -> Value {
    let mut result = json!({
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": {
            "resources": {},
            "tools": {},
        },
        "serverInfo": {
            "name": "bifrost",
            "version": env!("CARGO_PKG_VERSION"),
            "buildIdentity": crate::BIFROST_BUILD_IDENTITY,
        },
        "instructions": instructions,
    });
    if advertise_codex_sandbox_state {
        result["capabilities"]["experimental"] = json!({
            CODEX_SANDBOX_STATE_META_CAPABILITY: {},
        });
    }
    result
}

fn list_tools_result(spec: &McpServerSpec) -> Value {
    json!({
        "tools": &spec.tool_descriptors,
    })
}

fn list_resources_result() -> Value {
    json!({
        "resources": [agents_guidance_resource_descriptor()],
    })
}

fn agents_guidance_resource_descriptor() -> Value {
    json!({
        "uri": AGENTS_GUIDANCE_URI,
        "name": "bifrost-agents.md",
        "title": "Bifrost AGENTS.md guidance",
        "description": "Appendable agent instructions for Bifrost code-intelligence workflows.",
        "mimeType": AGENTS_GUIDANCE_MIME_TYPE,
        "annotations": {
            "audience": ["user", "assistant"],
            "priority": 0.8,
        },
    })
}

fn handle_resource_read(params: Value) -> Result<Value, (i64, String)> {
    let Some(object) = params.as_object() else {
        return Err((
            INVALID_PARAMS,
            "resources/read params must be an object".to_string(),
        ));
    };
    let Some(uri) = object.get("uri").and_then(Value::as_str) else {
        return Err((
            INVALID_PARAMS,
            "resources/read params missing uri".to_string(),
        ));
    };
    if uri != AGENTS_GUIDANCE_URI {
        return Err((RESOURCE_NOT_FOUND, format!("Resource not found: {uri}")));
    }
    Ok(json!({
        "contents": [
            {
                "uri": AGENTS_GUIDANCE_URI,
                "mimeType": AGENTS_GUIDANCE_MIME_TYPE,
                "text": AGENTS_GUIDANCE_TEXT,
            }
        ],
    }))
}

fn handle_tool_call(
    service: &SearchToolsService,
    connection: &mut McpConnectionState,
    params: Value,
    render_options: McpRenderOptions,
    spec: &McpServerSpec,
) -> Result<Value, (i64, String)> {
    let Some(object) = params.as_object() else {
        return Err((
            INVALID_PARAMS,
            "tools/call params must be an object".to_string(),
        ));
    };

    let Some(name) = object.get("name").and_then(Value::as_str) else {
        return Err((INVALID_PARAMS, "tools/call params missing name".to_string()));
    };

    if !spec.tool_names.contains(name) {
        return Ok(tool_error_result(format!("Unknown tool: {name}")));
    }

    reconcile_codex_sandbox_workspace(service, connection, object)?;

    let arguments = object
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));
    if connection.workspace_binding_source == WorkspaceBindingSource::None {
        return Err(unbound_workspace_error());
    }
    let Some(workspace_root) = service.active_workspace_root() else {
        return Err(unbound_workspace_error());
    };
    if name == "activate_workspace" {
        let authority = match connection.workspace_binding_source {
            WorkspaceBindingSource::ClientRoots => Some("MCP client roots"),
            WorkspaceBindingSource::CodexSandboxState => Some("Codex sandbox metadata"),
            WorkspaceBindingSource::None | WorkspaceBindingSource::ExplicitRoot => None,
        };
        if let Some(authority) = authority {
            return Ok(tool_error_result(format!(
                "activate_workspace is unavailable while the workspace is controlled by {authority}; update the client-provided workspace instead"
            )));
        }
    }
    let arguments = match normalize_tool_arguments(name, arguments, &workspace_root) {
        Ok(arguments) => arguments,
        Err(message) => return Ok(tool_error_result(message)),
    };

    let render_options = RenderOptions {
        render_line_numbers: render_options.render_line_numbers,
    };
    match service.call_tool_output(name, arguments.clone(), render_options) {
        Ok(output) => {
            let output = if name == "get_summaries" {
                fit_get_summaries_output_to_budget(service, output, render_options)
                    .map_err(|err| map_service_error(err.code, err.message))?
            } else {
                output
            };
            Ok(tool_success_result(output))
        }
        Err(err) => {
            if err.code == SearchToolsServiceErrorCode::UnknownTool {
                return Ok(tool_error_result(err.message));
            }
            Err(map_service_error(err.code, err.message))
        }
    }
}

fn reconcile_codex_sandbox_workspace(
    service: &SearchToolsService,
    connection: &mut McpConnectionState,
    params: &serde_json::Map<String, Value>,
) -> Result<(), (i64, String)> {
    if !connection.accepts_codex_sandbox_state() {
        return Ok(());
    }

    let thread_id = params
        .get("_meta")
        .and_then(|metadata| metadata.get("threadId"))
        .and_then(Value::as_str);
    let sandbox_cwd = params
        .get("_meta")
        .and_then(|metadata| metadata.get(CODEX_SANDBOX_STATE_META_CAPABILITY))
        .and_then(|sandbox_state| sandbox_state.get("sandboxCwd"))
        .and_then(Value::as_str);

    let Some(sandbox_cwd) = sandbox_cwd else {
        revoke_codex_sandbox_workspace(service, connection, thread_id, "metadata missing")?;
        log_codex_workspace_event("workspace metadata missing", thread_id);
        return Err(unbound_workspace_error());
    };

    let active_root = service.active_workspace_root();
    if connection.workspace_binding_source == WorkspaceBindingSource::CodexSandboxState
        && connection.codex_sandbox_cwd_uri.as_deref() == Some(sandbox_cwd)
        && connection.codex_sandbox_root.is_some()
        && active_root.as_ref() == connection.codex_sandbox_root.as_ref()
    {
        return Ok(());
    }

    let candidate = match file_uri_to_path(sandbox_cwd) {
        Ok(candidate) => candidate,
        Err(error) => {
            revoke_codex_sandbox_workspace(service, connection, thread_id, "metadata invalid")?;
            log_codex_workspace_event(
                &format!(
                    "rejected workspace metadata error={}",
                    escape_terminal_text(&error)
                ),
                thread_id,
            );
            return Err((
                INVALID_PARAMS,
                format!("Invalid Codex sandbox workspace metadata: {error}"),
            ));
        }
    };

    if connection.workspace_binding_source == WorkspaceBindingSource::CodexSandboxState {
        revoke_codex_sandbox_workspace(service, connection, thread_id, "metadata changed")?;
    }

    if service.active_workspace_root().is_some() {
        service
            .unbind_client_workspace()
            .map_err(|error| map_service_error(error.code, error.message))?;
        connection.workspace_binding_source = WorkspaceBindingSource::None;
        connection.codex_sandbox_cwd_uri = None;
        connection.codex_sandbox_root = None;
        log_codex_workspace_event(
            "revoked previous workspace reason=metadata changed",
            thread_id,
        );
    }

    match service.bind_client_workspace(candidate) {
        Ok(root) => {
            connection.workspace_binding_source = WorkspaceBindingSource::CodexSandboxState;
            connection.codex_sandbox_cwd_uri = Some(sandbox_cwd.to_string());
            connection.codex_sandbox_root = Some(root.clone());
            log_codex_workspace_event(
                &format!(
                    "bound MCP workspace source={CODEX_SANDBOX_STATE_META_CAPABILITY} root={}",
                    escape_terminal_text(root.to_string_lossy().as_ref())
                ),
                thread_id,
            );
            Ok(())
        }
        Err(error) => {
            connection.workspace_binding_source = WorkspaceBindingSource::None;
            connection.codex_sandbox_cwd_uri = None;
            connection.codex_sandbox_root = None;
            log_codex_workspace_event(
                &format!(
                    "failed workspace bind source={CODEX_SANDBOX_STATE_META_CAPABILITY} error={}",
                    escape_terminal_text(&error.message)
                ),
                thread_id,
            );
            Err(map_service_error(error.code, error.message))
        }
    }
}

fn revoke_codex_sandbox_workspace(
    service: &SearchToolsService,
    connection: &mut McpConnectionState,
    thread_id: Option<&str>,
    reason: &str,
) -> Result<(), (i64, String)> {
    if connection.workspace_binding_source != WorkspaceBindingSource::CodexSandboxState {
        return Ok(());
    }
    service
        .unbind_client_workspace()
        .map_err(|error| map_service_error(error.code, error.message))?;
    connection.workspace_binding_source = WorkspaceBindingSource::None;
    connection.codex_sandbox_cwd_uri = None;
    connection.codex_sandbox_root = None;
    log_codex_workspace_event(&format!("revoked MCP workspace reason={reason}"), thread_id);
    Ok(())
}

fn log_codex_workspace_event(event: &str, thread_id: Option<&str>) {
    if let Some(thread_id) = thread_id {
        eprintln!(
            "bifrost: {event} thread_id={}",
            escape_terminal_text(thread_id)
        );
    } else {
        eprintln!("bifrost: {event}");
    }
}

fn unbound_workspace_error() -> (i64, String) {
    (
        INTERNAL_ERROR,
        "Bifrost is not bound to a workspace. The MCP client must provide an approved filesystem root via roots/list or Codex sandbox-state metadata, or configure Bifrost with --root or BIFROST_WORKSPACE_ROOT."
            .to_string(),
    )
}

fn map_service_error(code: SearchToolsServiceErrorCode, message: String) -> (i64, String) {
    let jsonrpc_code = match code {
        SearchToolsServiceErrorCode::InvalidParams => INVALID_PARAMS,
        SearchToolsServiceErrorCode::UnknownTool => METHOD_NOT_FOUND,
        SearchToolsServiceErrorCode::Internal => INTERNAL_ERROR,
    };
    (jsonrpc_code, message)
}

fn fit_get_summaries_output_to_budget(
    service: &SearchToolsService,
    output: ToolOutput,
    render_options: RenderOptions,
) -> Result<ToolOutput, SearchToolsServiceError> {
    let ToolOutput::Structured {
        mut structured,
        rendered_text: base_rendered_text,
    } = output
    else {
        return Ok(output);
    };

    if let Some(object) = structured.as_object_mut() {
        object
            .entry("degraded".to_string())
            .or_insert_with(|| json!(false));
        object
            .entry("degradation".to_string())
            .or_insert(Value::Null);
    }

    let original_bytes = serialized_json_len(&structured);
    let summaries_len = structured
        .get("summaries")
        .and_then(Value::as_array)
        .map(|items| items.len())
        .unwrap_or(0);
    if original_bytes <= GET_SUMMARIES_RESPONSE_BUDGET_BYTES {
        return Ok(ToolOutput::Structured {
            structured,
            rendered_text: base_rendered_text,
        });
    }

    if summaries_len == 0 {
        mark_listing_budget_degradation(&mut structured, original_bytes);
        let budgeted = shrink_get_summaries_value_to_budget(structured);
        let rendered_text =
            render_budgeted_get_summaries_text(&budgeted, None, render_options.render_line_numbers);
        return Ok(ToolOutput::Structured {
            structured: budgeted,
            rendered_text: Some(rendered_text),
        });
    }

    let (budgeted, rendered_text) =
        degrade_get_summaries_value(service, structured, None, original_bytes, render_options)?;
    Ok(ToolOutput::Structured {
        structured: budgeted,
        rendered_text: Some(rendered_text),
    })
}

fn degrade_get_summaries_value(
    service: &SearchToolsService,
    mut structured: Value,
    compact_text: Option<String>,
    original_bytes: usize,
    render_options: RenderOptions,
) -> Result<(Value, String), SearchToolsServiceError> {
    let mut compact_text = compact_text;
    if let Some(paths) = compact_symbols_paths(&structured) {
        if serialized_json_len(&structured) > GET_SUMMARIES_RESPONSE_BUDGET_BYTES {
            let compact_output = service.call_tool_output(
                "list_symbols",
                json!({ "file_patterns": paths }),
                render_options,
            )?;
            compact_text = rendered_text_for_output(&compact_output);
            let ToolOutput::Structured {
                structured: compact_structured,
                ..
            } = compact_output
            else {
                return Err(SearchToolsServiceError {
                    code: SearchToolsServiceErrorCode::Internal,
                    message: "list_symbols returned non-structured output during MCP budgeting"
                        .to_string(),
                });
            };
            structured =
                compact_only_get_summaries_value(structured, compact_structured, original_bytes);
        }
    } else if let Some((compact_structured, rendered)) = compact_symbols_from_summaries(&structured)
    {
        compact_text = Some(rendered);
        structured =
            compact_only_get_summaries_value(structured, compact_structured, original_bytes);
    } else {
        let compact_paths = summary_paths_for_compaction(&structured);
        if !compact_paths.is_empty() {
            let compact_output = service.call_tool_output(
                "list_symbols",
                json!({ "file_patterns": compact_paths }),
                render_options,
            )?;
            compact_text = rendered_text_for_output(&compact_output);
            let ToolOutput::Structured {
                structured: compact_structured,
                ..
            } = compact_output
            else {
                return Err(SearchToolsServiceError {
                    code: SearchToolsServiceErrorCode::Internal,
                    message: "list_symbols returned non-structured output during MCP budgeting"
                        .to_string(),
                });
            };
            structured =
                compact_only_get_summaries_value(structured, compact_structured, original_bytes);
        }
    }

    let structured = shrink_get_summaries_value_to_budget(structured);
    let text = render_budgeted_get_summaries_text(
        &structured,
        compact_text,
        render_options.render_line_numbers,
    );
    Ok((structured, text))
}

fn mark_listing_budget_degradation(structured: &mut Value, original_bytes: usize) {
    let Some(object) = structured.as_object_mut() else {
        return;
    };
    object.insert("degraded".to_string(), json!(true));
    object.insert(
        "degradation".to_string(),
        json!({
            "reason": "response_budget_exceeded",
            "requested_format": "container_listing",
            "returned_format": "truncated_container_listing",
            "budget_bytes": GET_SUMMARIES_RESPONSE_BUDGET_BYTES,
            "original_bytes": original_bytes,
            "message": "The container listing exceeded the response budget and was truncated. Re-call get_summaries with a narrower directory or package target."
        }),
    );
}

fn summary_paths_for_compaction(structured: &Value) -> Vec<String> {
    structured
        .get("summaries")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|summary| {
            let label = summary.get("label")?.as_str()?;
            let path = summary.get("path")?.as_str()?;
            (label == path).then(|| path.to_string())
        })
        .collect()
}

fn compact_symbols_paths(structured: &Value) -> Option<Vec<String>> {
    let files = structured
        .get("compact_symbols")?
        .get("files")?
        .as_array()?;
    Some(
        files
            .iter()
            .filter_map(|file| file.get("path").and_then(Value::as_str).map(str::to_string))
            .collect(),
    )
}

fn compact_only_get_summaries_value(
    mut structured: Value,
    compact_structured: Value,
    original_bytes: usize,
) -> Value {
    if let Some(object) = structured.as_object_mut() {
        object.insert("summaries".to_string(), json!([]));
        object.insert("compact_symbols".to_string(), compact_structured);
        object.insert("degraded".to_string(), json!(true));
        object.insert(
            "degradation".to_string(),
            json!({
                "reason": "response_budget_exceeded",
                "requested_format": "summaries",
                "returned_format": "compact_symbols",
                "budget_bytes": GET_SUMMARIES_RESPONSE_BUDGET_BYTES,
                "original_bytes": original_bytes,
                "message": "Full summaries exceeded the response budget; returned compact declaration outlines. Re-call get_summaries with narrower targets or get_symbol_sources for exact bodies."
            }),
        );
    }
    structured
}

/// Builds the budgeted outline from the summary payload that was already
/// assembled for this request. Re-running `list_symbols` here would re-resolve
/// every parent and discard the persisted summary projection's work.
fn compact_symbols_from_summaries(structured: &Value) -> Option<(Value, String)> {
    let summaries = structured.get("summaries")?.as_array()?;
    if summaries.is_empty() {
        return None;
    }

    let mut files = Vec::with_capacity(summaries.len());
    for summary in summaries {
        let path = summary.get("path")?.as_str()?;
        if summary.get("label")?.as_str()? != path {
            return None;
        }
        let elements = summary.get("elements")?.as_array()?;
        let file = compact_file_from_summary(path, elements)?;
        files.push(file);
    }
    files.sort_by(|left, right| left["path"].as_str().cmp(&right["path"].as_str()));

    let compact = json!({
        "truncated": false,
        "total_files": files.len(),
        "files": files,
    });
    let text = render_compact_symbols_text(&compact);
    Some((compact, text))
}

fn compact_file_from_summary(path: &str, elements: &[Value]) -> Option<Value> {
    if elements.is_empty() {
        return None;
    }

    let mut parents = HashMap::new();
    for element in elements {
        let symbol = element.get("symbol")?.as_str()?;
        let parent = element
            .get("parent_symbol")
            .and_then(Value::as_str)
            .map(str::to_string);
        let is_module = element.get("kind")?.as_str()? == "module";
        parents
            .entry(symbol.to_string())
            .or_insert((parent, is_module));
    }

    let mut ordered = elements.to_vec();
    ordered.sort_by(|left, right| {
        left["start_line"]
            .as_u64()
            .cmp(&right["start_line"].as_u64())
            .then_with(|| left["end_line"].as_u64().cmp(&right["end_line"].as_u64()))
            .then_with(|| left["symbol"].as_str().cmp(&right["symbol"].as_str()))
    });

    let mut loc = 0;
    let mut lines = Vec::with_capacity(ordered.len());
    for element in ordered {
        let symbol = element.get("symbol")?.as_str()?;
        let kind = element.get("kind")?.as_str()?;
        loc = loc.max(element.get("end_line")?.as_u64()? as usize);
        if kind == "module" {
            lines.push(format!("# {symbol}"));
            continue;
        }

        let parent = element.get("parent_symbol").and_then(Value::as_str);
        let depth = compact_symbol_depth(parent, &parents);
        lines.push(format!(
            "{}- {}",
            "  ".repeat(depth),
            compact_symbol_label(symbol)
        ));
    }
    (loc > 0).then(|| json!({ "path": path, "loc": loc, "lines": lines }))
}

fn compact_symbol_depth(
    parent: Option<&str>,
    parents: &HashMap<String, (Option<String>, bool)>,
) -> usize {
    let mut depth = 0;
    let mut current = parent;
    for _ in 0..parents.len() {
        let Some(symbol) = current else {
            break;
        };
        let Some((next_parent, is_module)) = parents.get(symbol) else {
            break;
        };
        if *is_module {
            break;
        }
        depth += 1;
        current = next_parent.as_deref();
    }
    depth
}

fn compact_symbol_label(symbol: &str) -> &str {
    let mut start = 0;
    for separator in [".", "::", "->", "$", "+"] {
        if let Some(index) = symbol.rfind(separator) {
            start = start.max(index + separator.len());
        }
    }
    symbol
        .get(start..)
        .filter(|label| !label.is_empty())
        .unwrap_or(symbol)
}

fn render_compact_symbols_text(compact: &Value) -> String {
    compact
        .get("files")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|file| {
            let path = file.get("path")?.as_str()?;
            let loc = file.get("loc")?.as_u64()?;
            let lines = file
                .get("lines")?
                .as_array()?
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>();
            Some(format!("{path} ({loc} lines)\n{}", lines.join("\n")))
        })
        .collect::<Vec<_>>()
        .join("\n\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_watching_defaults_on_and_accepts_explicit_modes() {
        assert!(file_watching_enabled(None).unwrap());
        assert!(file_watching_enabled(Some(OsStr::new("on"))).unwrap());
        assert!(!file_watching_enabled(Some(OsStr::new("off"))).unwrap());

        let error = file_watching_enabled(Some(OsStr::new("disabled"))).unwrap_err();
        assert!(error.contains(MCP_FILE_WATCHER_ENV), "{error}");
        assert!(error.contains("on` or `off"), "{error}");
    }

    #[test]
    fn compact_summary_reuses_parent_aware_elements() {
        let structured = json!({
            "summaries": [{
                "label": "src/Thing.java",
                "path": "src/Thing.java",
                "elements": [
                    { "symbol": "demo", "kind": "module", "start_line": 1, "end_line": 1 },
                    { "symbol": "demo.Thing", "kind": "class", "start_line": 3, "end_line": 12 },
                    { "symbol": "demo.Thing.value", "kind": "field", "parent_symbol": "demo.Thing", "start_line": 4, "end_line": 4 },
                    { "symbol": "demo.Thing.Inner", "kind": "class", "parent_symbol": "demo.Thing", "start_line": 6, "end_line": 11 },
                    { "symbol": "demo.Thing.Inner.run", "kind": "function", "parent_symbol": "demo.Thing.Inner", "start_line": 7, "end_line": 9 }
                ]
            }]
        });

        let (compact, text) = compact_symbols_from_summaries(&structured).expect("compact summary");
        assert_eq!(
            compact["files"][0]["lines"],
            json!(["# demo", "- Thing", "  - value", "  - Inner", "    - run"])
        );
        assert_eq!(12, compact["files"][0]["loc"]);
        assert!(text.contains("src/Thing.java (12 lines)"), "{text}");
    }

    #[test]
    fn compact_summary_leaves_symbol_targets_on_the_legacy_path() {
        let structured = json!({
            "summaries": [{
                "label": "demo.Thing",
                "path": "src/Thing.java",
                "elements": [{
                    "symbol": "demo.Thing",
                    "kind": "class",
                    "start_line": 3,
                    "end_line": 12
                }]
            }]
        });

        assert!(compact_symbols_from_summaries(&structured).is_none());
    }

    #[test]
    fn oversized_container_listing_is_truncated_to_budget() {
        let entries = (0..200)
            .map(|index| {
                json!({
                    "kind": "file",
                    "name": format!("generated_file_{index:03}.rs"),
                    "path": format!("src/generated/generated_file_{index:03}.rs"),
                })
            })
            .collect::<Vec<_>>();
        let mut structured = json!({
            "summaries": [],
            "listings": [{
                "target": "src/generated",
                "kind": "directory",
                "entries": entries,
                "total_entries": 200,
                "truncated": false,
            }],
            "not_found": [],
            "ambiguous": [],
            "ambiguous_paths": [],
            "degraded": false,
            "degradation": null,
        });
        let original_bytes = serialized_json_len(&structured);

        mark_listing_budget_degradation(&mut structured, original_bytes);
        let structured = shrink_get_summaries_value_to_budget(structured);

        assert!(
            serialized_json_len(&structured) <= GET_SUMMARIES_RESPONSE_BUDGET_BYTES,
            "{}",
            serialized_json_len(&structured)
        );
        assert_eq!(true, structured["degraded"]);
        assert_eq!(true, structured["listings"][0]["truncated"]);
        assert_eq!(200, structured["listings"][0]["total_entries"]);
        assert!(
            structured["listings"][0]["entries"]
                .as_array()
                .is_some_and(|entries| entries.len() < 200)
        );
        let rendered = render_budgeted_get_summaries_text(&structured, None, true);
        assert!(rendered.contains("Directory src/generated"), "{rendered}");
        assert!(rendered.contains("of 200 entries"), "{rendered}");
    }
}

fn shrink_compact_symbols_value_to_budget(mut structured: Value) -> Value {
    loop {
        if serialized_json_len(&structured) <= GET_SUMMARIES_RESPONSE_BUDGET_BYTES {
            return structured;
        }
        let Some(files) = structured
            .get_mut("compact_symbols")
            .and_then(|value| value.get_mut("files"))
            .and_then(Value::as_array_mut)
        else {
            return structured;
        };
        if files.len() <= 1 {
            if let Some(compact) = structured
                .get_mut("compact_symbols")
                .and_then(Value::as_object_mut)
            {
                compact.insert("truncated".to_string(), json!(true));
            }
            return structured;
        }
        files.pop();
        if let Some(compact) = structured
            .get_mut("compact_symbols")
            .and_then(Value::as_object_mut)
        {
            compact.insert("truncated".to_string(), json!(true));
        }
    }
}

fn shrink_get_summaries_value_to_budget(structured: Value) -> Value {
    let mut structured = shrink_compact_symbols_value_to_budget(structured);
    loop {
        if serialized_json_len(&structured) <= GET_SUMMARIES_RESPONSE_BUDGET_BYTES {
            return structured;
        }
        let Some(listings) = structured.get_mut("listings").and_then(Value::as_array_mut) else {
            return structured;
        };
        let Some(index) = listings
            .iter()
            .enumerate()
            .filter_map(|(index, listing)| {
                let len = listing.get("entries")?.as_array()?.len();
                (len > 0).then_some((index, len))
            })
            .max_by_key(|(_, len)| *len)
            .map(|(index, _)| index)
        else {
            return structured;
        };
        let Some(listing) = listings[index].as_object_mut() else {
            return structured;
        };
        if let Some(entries) = listing.get_mut("entries").and_then(Value::as_array_mut) {
            entries.pop();
        }
        listing.insert("truncated".to_string(), json!(true));
    }
}

fn render_budgeted_get_summaries_text(
    structured: &Value,
    compact_text: Option<String>,
    render_line_numbers: bool,
) -> String {
    let note = structured
        .get("degradation")
        .and_then(|value| value.get("message"))
        .and_then(Value::as_str)
        .map(|message| format!("Note: {message}"))
        .unwrap_or_default();
    let mut blocks = Vec::new();
    if !note.is_empty() {
        blocks.push(note);
    }
    if let Some(compact_text) = compact_text.filter(|text| !text.is_empty()) {
        blocks.push(compact_text);
    }
    blocks.extend(render_container_listings_json(
        structured,
        render_line_numbers,
    ));
    if blocks.is_empty() {
        blocks.push("No matching summaries found.".to_string());
    }
    let mut text = blocks.join("\n\n");
    if text.len() > GET_SUMMARIES_RESPONSE_BUDGET_BYTES {
        let suffix = "\n\n[truncated for MCP text budget; inspect structuredContent for full compact result]";
        let keep = GET_SUMMARIES_RESPONSE_BUDGET_BYTES.saturating_sub(suffix.len());
        text.truncate(keep);
        text.push_str(suffix);
    }
    text
}

fn render_container_listings_json(structured: &Value, render_line_numbers: bool) -> Vec<String> {
    structured
        .get("listings")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|listing| {
            let target = listing.get("target")?.as_str()?;
            let label = match listing.get("kind")?.as_str()? {
                "directory" => "Directory",
                "package" => "Package",
                _ => return None,
            };
            let languages = listing
                .get("languages")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>();
            let language_suffix = if languages.is_empty() {
                String::new()
            } else {
                format!(" ({})", languages.join(", "))
            };
            let mut lines = vec![format!("{label} {target}{language_suffix}")];
            let entries = listing.get("entries")?.as_array()?;
            lines.extend(entries.iter().filter_map(|entry| {
                let kind = entry.get("kind")?.as_str()?;
                match kind {
                    "directory" => Some(format!("[directory] {}", entry.get("path")?.as_str()?)),
                    "file" => Some(format!("[file] {}", entry.get("path")?.as_str()?)),
                    "package" => {
                        let languages = entry
                            .get("languages")
                            .and_then(Value::as_array)
                            .into_iter()
                            .flatten()
                            .filter_map(Value::as_str)
                            .collect::<Vec<_>>();
                        let suffix = if languages.is_empty() {
                            String::new()
                        } else {
                            format!("; {}", languages.join(", "))
                        };
                        Some(format!(
                            "[package{suffix}] {}",
                            entry.get("qualified_name")?.as_str()?
                        ))
                    }
                    "type" => {
                        let path = entry.get("path")?.as_str()?;
                        let location = if render_line_numbers {
                            format!(
                                "{path}:{}..{}",
                                entry.get("start_line")?.as_u64()?,
                                entry.get("end_line")?.as_u64()?
                            )
                        } else {
                            path.to_string()
                        };
                        Some(format!(
                            "[type; {}] {}: {location}",
                            entry.get("language")?.as_str()?,
                            entry.get("symbol")?.as_str()?
                        ))
                    }
                    _ => None,
                }
            }));
            if entries.is_empty() {
                lines.push("(empty)".to_string());
            }
            if listing
                .get("truncated")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                lines.push(format!(
                    "[showing {} of {} entries]",
                    entries.len(),
                    listing
                        .get("total_entries")
                        .and_then(Value::as_u64)
                        .unwrap_or(entries.len() as u64)
                ));
            }
            Some(lines.join("\n"))
        })
        .collect()
}

fn rendered_text_for_output(output: &ToolOutput) -> Option<String> {
    match output {
        ToolOutput::Structured { rendered_text, .. } => rendered_text.clone(),
        ToolOutput::Text(text) => Some(text.clone()),
    }
}

fn serialized_json_len<T: Serialize>(value: &T) -> usize {
    serde_json::to_vec(value)
        .map(|bytes| bytes.len())
        .unwrap_or(usize::MAX)
}

fn tool_success_result(output: ToolOutput) -> Value {
    match output {
        ToolOutput::Text(text) => json!({
            "content": [
                {
                    "type": "text",
                    "text": text,
                }
            ],
            "isError": false,
        }),
        ToolOutput::Structured {
            structured,
            rendered_text,
        } => {
            let text = rendered_text.unwrap_or_else(|| {
                serde_json::to_string(&structured)
                    .unwrap_or_else(|_| "Failed to serialize tool result".to_string())
            });
            json!({
                "content": [
                    {
                        "type": "text",
                        "text": text,
                    }
                ],
                "structuredContent": structured,
                "isError": false,
            })
        }
    }
}

fn tool_error_result(message: String) -> Value {
    json!({
        "content": [
            {
                "type": "text",
                "text": message,
            }
        ],
        "isError": true,
    })
}

fn success_response(id: Value, result: Value) -> Value {
    json!({
        "jsonrpc": JSONRPC_VERSION,
        "id": id,
        "result": result,
    })
}

fn error_response(id: Value, code: i64, message: String) -> Value {
    json!({
        "jsonrpc": JSONRPC_VERSION,
        "id": id,
        "error": {
            "code": code,
            "message": message,
        }
    })
}

pub fn tool_descriptor(name: &str, description: &str, input_schema: Value) -> Value {
    json!({
        "name": name,
        "description": description,
        "inputSchema": input_schema,
        "annotations": {
            "readOnlyHint": true,
            "destructiveHint": false,
            "idempotentHint": true,
            "openWorldHint": false,
        }
    })
}

pub fn mutating_tool_descriptor(name: &str, description: &str, input_schema: Value) -> Value {
    json!({
        "name": name,
        "description": description,
        "inputSchema": input_schema,
        "annotations": {
            "readOnlyHint": false,
            "destructiveHint": false,
            "idempotentHint": true,
            "openWorldHint": false,
        }
    })
}

pub fn json_schema_object(required: &[&str]) -> Value {
    json!({
        "type": "object",
        "properties": {},
        "required": required,
    })
}

pub fn symbol_names_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "symbols": {
                "type": "array",
                "items": { "type": "string" },
                "description": "Fully qualified or short symbol names to resolve, or project-relative file paths/globs for file-backed symbol views."
            }
        },
        "required": ["symbols"]
    })
}

pub fn file_patterns_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "file_patterns": {
                "type": "array",
                "items": { "type": "string" },
                "description": "Project-relative file paths or glob patterns, or absolute paths/globs inside the active workspace."
            }
        },
        "required": ["file_patterns"]
    })
}

pub fn summaries_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "targets": {
                "type": "array",
                "items": { "type": "string" },
                "description": "Targets may be mixed in one call. Use a project-relative directory like an `ls`: it returns immediate child directories and git-visible files (tracked or unignored), including non-source files, without recursively flattening descendants; gitignored files are excluded. Use an OO namespace or language import/package path like a semantic `ls`: it returns direct child packages and top-level types declared in that exact package. A real filesystem directory wins if a target could mean either. Literal files, globs, and class/module symbols return ranged code summaries. Oversized ordinary summaries degrade to compact_symbols; oversized listings retain a total count and set truncated. Examples: \"src/auth\", \"com.example.auth\", \"github.com/cli/cli/v2/internal/skills/discovery\", \"src/auth/**/*.rs\", \"MyClass\"."
            }
        },
        "required": ["targets"]
    })
}

pub fn weight_knob_descriptor(
    description_prefix: &str,
    default_value: i32,
    pick_threshold: WeightThreshold,
) -> Value {
    let cmp = match pick_threshold {
        WeightThreshold::Negative => "<",
        WeightThreshold::NonPositive => "<=",
    };
    json!({
        "type": "integer",
        "description": format!(
            "{description_prefix}; values {cmp} 0 use the brokk default ({default_value})."
        )
    })
}

#[derive(Clone, Copy)]
pub enum WeightThreshold {
    Negative,
    NonPositive,
}

#[cfg(test)]
mod uri_tests {
    use super::*;

    #[test]
    fn file_uri_round_trips_native_absolute_paths() {
        let path = std::env::current_dir()
            .expect("current directory")
            .join("workspace with spaces");
        let uri = url::Url::from_file_path(&path).expect("file URI");
        assert_eq!(file_uri_to_path(uri.as_str()).unwrap(), path);
    }

    #[test]
    fn absolute_native_workspace_root_is_accepted() {
        let path = std::env::current_dir()
            .expect("current directory")
            .join("workspace with spaces");
        assert_eq!(
            client_root_to_path(path.to_str().expect("native path")).unwrap(),
            path
        );
    }

    #[test]
    fn relative_native_workspace_root_is_rejected() {
        let error = client_root_to_path("workspace").unwrap_err();
        assert!(error.contains("invalid root URI `workspace`"), "{error}");
    }

    #[test]
    fn file_uri_rejects_non_file_schemes() {
        let error = file_uri_to_path("https://example.com/workspace").unwrap_err();
        assert!(
            error.contains("unsupported root URI scheme `https`"),
            "{error}"
        );
    }

    #[test]
    fn roots_changes_during_a_request_are_coalesced() {
        let service = SearchToolsService::new_unbound();
        let mut connection = McpConnectionState::new(true);
        connection.client_supports_roots = true;
        connection.initialized = true;
        let first = connection.roots_request().expect("first roots request");

        assert!(
            handle_notification(
                &service,
                &mut connection,
                "notifications/roots/list_changed",
                Value::Null,
            )
            .is_none()
        );
        connection.pending_roots_request = None;
        let second = connection
            .finish_roots_response()
            .expect("coalesced roots request");

        assert_ne!(first["id"], second["id"]);
        assert_eq!(second["method"], "roots/list");
    }
}
