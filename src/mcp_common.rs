use crate::{
    SearchToolsService, SearchToolsServiceErrorCode, ToolOutput, searchtools_render::RenderOptions,
    tool_arguments::normalize_tool_arguments,
};
use serde_json::{Value, json};
use std::collections::HashSet;
use std::io::{self, BufRead, Write};
use std::path::PathBuf;

const JSONRPC_VERSION: &str = "2.0";
const PROTOCOL_VERSION: &str = "2025-11-25";
const PARSE_ERROR: i64 = -32700;
const INVALID_REQUEST: i64 = -32600;
const METHOD_NOT_FOUND: i64 = -32601;
const INVALID_PARAMS: i64 = -32602;
const INTERNAL_ERROR: i64 = -32603;

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
    root: PathBuf,
    render_options: McpRenderOptions,
    spec: &McpServerSpec,
) -> Result<(), String> {
    let service = SearchToolsService::new(root)?;

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
            Ok(message) => dispatch_message(&service, message, render_options, spec),
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

    Ok(())
}

fn dispatch_message(
    service: &SearchToolsService,
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
        Some(id) => Some(dispatch_request(
            service,
            id,
            method,
            params,
            render_options,
            spec,
        )),
        None => {
            handle_notification(method, params);
            None
        }
    }
}

fn dispatch_request(
    service: &SearchToolsService,
    id: Value,
    method: &str,
    params: Value,
    render_options: McpRenderOptions,
    spec: &McpServerSpec,
) -> Value {
    let response = match method {
        "initialize" => Ok(initialize_result(spec.instructions)),
        "ping" => Ok(json!({})),
        "tools/list" => Ok(list_tools_result(spec)),
        "tools/call" => handle_tool_call(service, params, render_options, spec),
        _ => Err((METHOD_NOT_FOUND, format!("Unknown method: {method}"))),
    };

    match response {
        Ok(result) => success_response(id, result),
        Err((code, message)) => error_response(id, code, message),
    }
}

fn handle_notification(method: &str, _params: Value) {
    let _ = method == "notifications/initialized";
}

fn initialize_result(instructions: &str) -> Value {
    json!({
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": {
            "tools": {},
        },
        "serverInfo": {
            "name": "bifrost",
            "version": env!("CARGO_PKG_VERSION"),
        },
        "instructions": instructions,
    })
}

fn list_tools_result(spec: &McpServerSpec) -> Value {
    json!({
        "tools": &spec.tool_descriptors,
    })
}

fn handle_tool_call(
    service: &SearchToolsService,
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

    let arguments = object
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let workspace_root = service.active_workspace_root();
    let arguments = match normalize_tool_arguments(name, arguments, &workspace_root) {
        Ok(arguments) => arguments,
        Err(message) => return Ok(tool_error_result(message)),
    };

    match service.call_tool_output(
        name,
        arguments,
        RenderOptions {
            render_line_numbers: render_options.render_line_numbers,
        },
    ) {
        Ok(output) => Ok(tool_success_result(output)),
        Err(err) => {
            if err.code == SearchToolsServiceErrorCode::UnknownTool {
                return Ok(tool_error_result(err.message));
            }
            Err(map_service_error(err.code, err.message))
        }
    }
}

fn map_service_error(code: SearchToolsServiceErrorCode, message: String) -> (i64, String) {
    let jsonrpc_code = match code {
        SearchToolsServiceErrorCode::InvalidParams => INVALID_PARAMS,
        SearchToolsServiceErrorCode::UnknownTool => METHOD_NOT_FOUND,
        SearchToolsServiceErrorCode::Internal => INTERNAL_ERROR,
    };
    (jsonrpc_code, message)
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
                "description": "Project-relative file paths, directory paths, glob patterns, class names, or absolute paths/globs inside the active workspace. File and glob targets return detailed ranged summaries; directory targets return a compact symbol inventory capped to the most relevant files. Examples: \"src/auth/**/*.rs\", \"crates/polars-core/src/frame/**/*.rs\", \"MyClass\"."
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
