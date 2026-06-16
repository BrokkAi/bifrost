use crate::{
    SearchToolsService, SearchToolsServiceError, SearchToolsServiceErrorCode, ToolOutput,
    searchtools_render::RenderOptions, tool_arguments::normalize_tool_arguments,
};
use serde::Serialize;
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
const GET_SUMMARIES_RESPONSE_BUDGET_BYTES: usize = 4_096;

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

    let render_options = RenderOptions {
        render_line_numbers: render_options.render_line_numbers,
    };
    match service.call_tool_output(name, arguments.clone(), render_options) {
        Ok(output) => {
            let output = if name == "get_summaries" {
                fit_get_summaries_output_to_budget(service, output, &arguments, render_options)
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
    arguments: &Value,
    render_options: RenderOptions,
) -> Result<ToolOutput, SearchToolsServiceError> {
    let ToolOutput::Structured {
        mut structured,
        rendered_text: base_rendered_text,
    } = output
    else {
        return Ok(output);
    };

    let mut compact_text =
        maybe_add_directory_inventory(service, &mut structured, arguments, render_options)?;

    let original_bytes = serialized_json_len(&structured);
    let summaries_len = structured
        .get("summaries")
        .and_then(Value::as_array)
        .map(|items| items.len())
        .unwrap_or(0);
    if original_bytes <= GET_SUMMARIES_RESPONSE_BUDGET_BYTES || summaries_len == 0 {
        let rendered_text =
            render_non_degraded_get_summaries_text(base_rendered_text, compact_text.take());
        return Ok(ToolOutput::Structured {
            structured,
            rendered_text: Some(rendered_text),
        });
    }

    let (budgeted, rendered_text) = degrade_get_summaries_value(
        service,
        structured,
        compact_text,
        original_bytes,
        render_options,
    )?;
    Ok(ToolOutput::Structured {
        structured: budgeted,
        rendered_text: Some(rendered_text),
    })
}

fn maybe_add_directory_inventory(
    service: &SearchToolsService,
    structured: &mut Value,
    arguments: &Value,
    render_options: RenderOptions,
) -> Result<Option<String>, SearchToolsServiceError> {
    let targets = arguments
        .get("targets")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_string))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if targets.is_empty() {
        return Ok(None);
    }

    let unresolved = unresolved_targets(&targets, structured);
    if unresolved.is_empty() {
        return Ok(None);
    }

    let compact_output = service.call_tool_output(
        "list_symbols",
        json!({ "file_patterns": unresolved }),
        render_options,
    )?;
    let compact_text = rendered_text_for_output(&compact_output);
    let ToolOutput::Structured {
        structured: compact_structured,
        ..
    } = compact_output
    else {
        return Ok(compact_text);
    };
    let has_files = compact_structured
        .get("files")
        .and_then(Value::as_array)
        .map(|files| !files.is_empty())
        .unwrap_or(false);
    if !has_files {
        return Ok(compact_text);
    }

    if let Some(object) = structured.as_object_mut() {
        object.insert("compact_symbols".to_string(), compact_structured);
        object
            .entry("degraded".to_string())
            .or_insert_with(|| json!(false));
        object
            .entry("degradation".to_string())
            .or_insert(Value::Null);
    }
    Ok(compact_text)
}

fn unresolved_targets(targets: &[String], structured: &Value) -> Vec<String> {
    let found_summary_paths: std::collections::HashSet<_> = structured
        .get("summaries")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|summary| summary.get("path").and_then(Value::as_str))
        .collect();
    let not_found: std::collections::HashSet<_> = structured
        .get("not_found")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    targets
        .iter()
        .filter(|target| {
            not_found.contains(target.as_str()) && !found_summary_paths.contains(target.as_str())
        })
        .cloned()
        .collect()
}

fn degrade_get_summaries_value(
    service: &SearchToolsService,
    mut structured: Value,
    compact_text: Option<String>,
    original_bytes: usize,
    render_options: RenderOptions,
) -> Result<(Value, String), SearchToolsServiceError> {
    let compact_paths = summary_paths_for_compaction(&structured);
    let list_output = if compact_paths.is_empty() {
        None
    } else {
        Some(service.call_tool_output(
            "list_symbols",
            json!({ "file_patterns": compact_paths }),
            render_options,
        )?)
    };
    let mut compact_text = compact_text;
    if let Some(paths) = compact_symbols_paths(&structured) {
        if serialized_json_len(&structured) > GET_SUMMARIES_RESPONSE_BUDGET_BYTES {
            let compact_output = service.call_tool_output(
                "list_symbols",
                json!({ "file_patterns": paths }),
                render_options,
            )?;
            compact_text = rendered_text_for_output(&compact_output);
            structured =
                compact_only_get_summaries_value(structured, compact_output, original_bytes)?;
        }
    } else if let Some(output) = list_output {
        compact_text = rendered_text_for_output(&output);
        structured = compact_only_get_summaries_value(structured, output, original_bytes)?;
    }

    let text = render_budgeted_get_summaries_text(&structured, compact_text);
    Ok((shrink_compact_symbols_value_to_budget(structured), text))
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
    compact_output: ToolOutput,
    original_bytes: usize,
) -> Result<Value, SearchToolsServiceError> {
    let ToolOutput::Structured {
        structured: compact_structured,
        ..
    } = compact_output
    else {
        return Err(SearchToolsServiceError {
            code: SearchToolsServiceErrorCode::Internal,
            message: "list_symbols returned non-structured output during MCP budgeting".to_string(),
        });
    };
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
    Ok(structured)
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

fn render_budgeted_get_summaries_text(structured: &Value, compact_text: Option<String>) -> String {
    let note = structured
        .get("degradation")
        .and_then(|value| value.get("message"))
        .and_then(Value::as_str)
        .map(|message| format!("Note: {message}"))
        .unwrap_or_default();
    let compact_text = compact_text.unwrap_or_else(|| "No matching summaries found.".to_string());
    let mut text = if note.is_empty() {
        compact_text
    } else {
        format!("{note}\n\n{compact_text}")
    };
    if text.len() > GET_SUMMARIES_RESPONSE_BUDGET_BYTES {
        let suffix = "\n\n[truncated for MCP text budget; inspect structuredContent for full compact result]";
        let keep = GET_SUMMARIES_RESPONSE_BUDGET_BYTES.saturating_sub(suffix.len());
        text.truncate(keep);
        text.push_str(suffix);
    }
    text
}

fn render_non_degraded_get_summaries_text(
    base_rendered_text: Option<String>,
    compact_text: Option<String>,
) -> String {
    let base = base_rendered_text.unwrap_or_else(|| "No matching summaries found.".to_string());
    match compact_text {
        Some(compact) if base == "No matching summaries found." => compact,
        Some(compact) => format!("{base}\n\n{compact}"),
        None => base,
    }
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
                "description": "Project-relative file paths, directory paths, glob patterns, class names, or absolute paths/globs inside the active workspace. File and glob targets return detailed ranged summaries when they fit the response budget; oversized results are marked degraded and return compact_symbols declaration outlines. Directory targets return compact_symbols by design. Examples: \"src/auth/**/*.rs\", \"crates/polars-core/src/frame/**/*.rs\", \"MyClass\"."
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
