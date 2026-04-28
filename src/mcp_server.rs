use crate::{SearchToolsService, SearchToolsServiceErrorCode};
use serde_json::{Value, json};
use std::io::{self, BufRead, Write};
use std::path::PathBuf;

const JSONRPC_VERSION: &str = "2.0";
const PROTOCOL_VERSION: &str = "2025-11-25";
const PARSE_ERROR: i64 = -32700;
const INVALID_REQUEST: i64 = -32600;
const METHOD_NOT_FOUND: i64 = -32601;
const INVALID_PARAMS: i64 = -32602;
const INTERNAL_ERROR: i64 = -32603;

pub fn run_searchtools_stdio_server(root: PathBuf) -> Result<(), String> {
    let mut service = SearchToolsService::new(root)?;

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
            Ok(message) => dispatch_message(&mut service, message),
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

fn dispatch_message(service: &mut SearchToolsService, message: Value) -> Option<Value> {
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
        Some(id) => Some(dispatch_request(service, id, method, params)),
        None => {
            handle_notification(method, params);
            None
        }
    }
}

fn dispatch_request(
    service: &mut SearchToolsService,
    id: Value,
    method: &str,
    params: Value,
) -> Value {
    let response = match method {
        "initialize" => Ok(initialize_result()),
        "ping" => Ok(json!({})),
        "tools/list" => Ok(list_tools_result()),
        "tools/call" => handle_tool_call(service, params),
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

fn initialize_result() -> Value {
    json!({
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": {
            "tools": {},
        },
        "serverInfo": {
            "name": "bifrost",
            "version": env!("CARGO_PKG_VERSION"),
        },
        "instructions": "Analyzer-backed search tools for source code workspaces.",
    })
}

fn list_tools_result() -> Value {
    json!({
        "tools": [
            mutating_tool_descriptor(
                "refresh",
                "Refresh the analyzer snapshot for the current workspace.",
                json_schema_object(&[]),
            ),
            mutating_tool_descriptor(
                "activate_workspace",
                "Set the active workspace for this MCP server. The path must be absolute. If it lives inside a git repository, the active workspace becomes the nearest enclosing repository root (discovery walks parents until a .git is found); otherwise the canonicalized path is used as-is. Pass a path you intend to be the project root.",
                json!({
                    "type": "object",
                    "properties": {
                        "workspace_path": {
                            "type": "string",
                            "description": "Absolute path to the desired workspace directory."
                        }
                    },
                    "required": ["workspace_path"]
                }),
            ),
            tool_descriptor(
                "get_active_workspace",
                "Return the currently active workspace root.",
                json_schema_object(&[]),
            ),
            tool_descriptor(
                "search_symbols",
                "Search indexed symbols across the current workspace.",
                json!({
                    "type": "object",
                    "properties": {
                        "patterns": {
                            "type": "array",
                            "items": { "type": "string" },
                            "description": "Search patterns to match against indexed symbol names."
                        },
                        "include_tests": {
                            "type": "boolean",
                            "default": false,
                            "description": "Whether to include symbols from detected test files."
                        },
                        "limit": {
                            "type": "integer",
                            "default": 20,
                            "minimum": 1,
                            "description": "Maximum number of files to return."
                        }
                    },
                    "required": ["patterns"]
                }),
            ),
            tool_descriptor(
                "get_symbol_locations",
                "Return file locations for indexed symbols.",
                symbol_names_schema(),
            ),
            tool_descriptor(
                "get_symbol_summaries",
                "Return ranged summaries for indexed symbols.",
                symbol_names_schema(),
            ),
            tool_descriptor(
                "get_symbol_sources",
                "Return source blocks for indexed symbols.",
                symbol_names_schema(),
            ),
            tool_descriptor(
                "get_summaries",
                "Return ranged summaries for matching files, globs, or class targets.",
                summaries_schema(),
            ),
            tool_descriptor(
                "list_symbols",
                "Return compact recursive symbol outlines for matching files.",
                file_patterns_schema(),
            ),
            tool_descriptor(
                "most_relevant_files",
                "Return related project files ranked by Git history and imports.",
                json!({
                    "type": "object",
                    "properties": {
                        "seed_files": {
                            "type": "array",
                            "items": { "type": "string" },
                            "description": "Project-relative seed files used to rank related files."
                        },
                        "limit": {
                            "type": "integer",
                            "default": 20,
                            "minimum": 0,
                            "description": "Maximum number of related files to return."
                        }
                    },
                    "required": ["seed_files"]
                }),
            ),
        ]
    })
}

fn tool_descriptor(name: &str, description: &str, input_schema: Value) -> Value {
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

fn mutating_tool_descriptor(name: &str, description: &str, input_schema: Value) -> Value {
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

fn json_schema_object(required: &[&str]) -> Value {
    json!({
        "type": "object",
        "properties": {},
        "required": required,
    })
}

fn symbol_names_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "symbols": {
                "type": "array",
                "items": { "type": "string" },
                "description": "Fully qualified or short symbol names to resolve."
            },
            "kind_filter": {
                "type": "string",
                "enum": ["any", "class", "function", "field", "module"],
                "default": "any",
                "description": "Optional symbol kind filter."
            }
        },
        "required": ["symbols"]
    })
}

fn file_patterns_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "file_patterns": {
                "type": "array",
                "items": { "type": "string" },
                "description": "Project-relative file paths or glob patterns."
            }
        },
        "required": ["file_patterns"]
    })
}

fn summaries_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "targets": {
                "type": "array",
                "items": { "type": "string" },
                "description": "Project-relative file paths, glob patterns, or class names."
            }
        },
        "required": ["targets"]
    })
}

fn handle_tool_call(
    service: &mut SearchToolsService,
    params: Value,
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

    let arguments = object
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));

    match service.call_tool_value(name, arguments) {
        Ok(structured) => Ok(tool_success_result(structured)),
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

fn tool_success_result(structured: Value) -> Value {
    let text = serde_json::to_string_pretty(&structured)
        .unwrap_or_else(|_| "Failed to pretty-print tool result".to_string());
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
