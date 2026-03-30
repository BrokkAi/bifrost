use crate::{
    AnalyzerConfig, FilesystemProject, Project, ProjectChangeWatcher, ProjectFile,
    WorkspaceAnalyzer,
    searchtools::{
        FilePatternsParams, RefreshParams, SearchSymbolsParams, SymbolNamesParams,
        get_file_summaries, get_symbol_locations, get_symbol_sources, get_symbol_summaries,
        refresh_result, search_symbols, skim_files,
    },
};
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use std::sync::Arc;

const JSONRPC_VERSION: &str = "2.0";
const PROTOCOL_VERSION: &str = "2025-11-25";
const PARSE_ERROR: i64 = -32700;
const INVALID_REQUEST: i64 = -32600;
const METHOD_NOT_FOUND: i64 = -32601;
const INVALID_PARAMS: i64 = -32602;
const INTERNAL_ERROR: i64 = -32603;

pub fn run_searchtools_stdio_server(root: PathBuf) -> Result<(), String> {
    let project: Arc<dyn Project> = Arc::new(
        FilesystemProject::new(root)
            .map_err(|err| format!("Failed to initialize project root: {err}"))?,
    );
    let mut workspace = WorkspaceAnalyzer::build(Arc::clone(&project), AnalyzerConfig::default());
    let watcher = ProjectChangeWatcher::start(project).ok();

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
            Ok(message) => dispatch_message(&mut workspace, watcher.as_ref(), message),
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
    workspace: &mut WorkspaceAnalyzer,
    watcher: Option<&ProjectChangeWatcher>,
    message: Value,
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
        Some(id) => Some(dispatch_request(workspace, watcher, id, method, params)),
        None => {
            handle_notification(method, params);
            None
        }
    }
}

fn dispatch_request(
    workspace: &mut WorkspaceAnalyzer,
    watcher: Option<&ProjectChangeWatcher>,
    id: Value,
    method: &str,
    params: Value,
) -> Value {
    let response = match method {
        "initialize" => Ok(initialize_result()),
        "ping" => Ok(json!({})),
        "tools/list" => Ok(list_tools_result()),
        "tools/call" => handle_tool_call(workspace, watcher, params),
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
            tool_descriptor(
                "refresh",
                "Refresh the analyzer snapshot for the current workspace.",
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
                "get_file_summaries",
                "Return ranged summaries for matching files.",
                file_patterns_schema(),
            ),
            tool_descriptor(
                "skim_files",
                "Return compact symbol skim output for matching files.",
                file_patterns_schema(),
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
                "description": "Glob-style project-relative file patterns."
            }
        },
        "required": ["file_patterns"]
    })
}

fn handle_tool_call(
    workspace: &mut WorkspaceAnalyzer,
    watcher: Option<&ProjectChangeWatcher>,
    params: Value,
) -> Result<Value, (i64, String)> {
    apply_watcher_delta(workspace, watcher);

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
    let structured = match name {
        "refresh" => decode_and_run::<RefreshParams, _>(arguments, |_| {
            *workspace = workspace.update_all();
            refresh_result(workspace.analyzer())
        })?,
        "search_symbols" => decode_and_run::<SearchSymbolsParams, _>(arguments, |params| {
            search_symbols(workspace.analyzer(), params)
        })?,
        "get_symbol_locations" => decode_and_run::<SymbolNamesParams, _>(arguments, |params| {
            get_symbol_locations(workspace.analyzer(), params)
        })?,
        "get_symbol_summaries" => decode_and_run::<SymbolNamesParams, _>(arguments, |params| {
            get_symbol_summaries(workspace.analyzer(), params)
        })?,
        "get_symbol_sources" => decode_and_run::<SymbolNamesParams, _>(arguments, |params| {
            get_symbol_sources(workspace.analyzer(), params)
        })?,
        "get_file_summaries" => decode_and_run::<FilePatternsParams, _>(arguments, |params| {
            get_file_summaries(workspace.analyzer(), params)
        })?,
        "skim_files" => decode_and_run::<FilePatternsParams, _>(arguments, |params| {
            skim_files(workspace.analyzer(), params)
        })?,
        _ => {
            return Ok(tool_error_result(format!("Unknown tool: {name}")));
        }
    };

    tool_success_result(structured)
}

fn apply_watcher_delta(workspace: &mut WorkspaceAnalyzer, watcher: Option<&ProjectChangeWatcher>) {
    let Some(watcher) = watcher else {
        return;
    };

    let delta = watcher.take_changed_files();
    if delta.requires_full_refresh {
        *workspace = workspace.update_all();
        return;
    }

    if delta.files.is_empty() {
        return;
    }

    let changed_files: BTreeSet<ProjectFile> = delta.files.into_iter().collect();
    *workspace = workspace.update(&changed_files);
}

fn decode_and_run<P, R>(
    arguments: Value,
    handler: impl FnOnce(P) -> R,
) -> Result<Value, (i64, String)>
where
    P: serde::de::DeserializeOwned,
    R: Serialize,
{
    let params = serde_json::from_value::<P>(arguments)
        .map_err(|err| (INVALID_PARAMS, format!("Invalid tool arguments: {err}")))?;
    serde_json::to_value(handler(params)).map_err(|err| {
        (
            INTERNAL_ERROR,
            format!("Failed to serialize tool result: {err}"),
        )
    })
}

fn tool_success_result(structured: Value) -> Result<Value, (i64, String)> {
    let pretty = serde_json::to_string_pretty(&structured).map_err(|err| {
        (
            INTERNAL_ERROR,
            format!("Failed to format tool result: {err}"),
        )
    })?;
    Ok(json!({
        "content": [{ "type": "text", "text": pretty }],
        "structuredContent": structured,
        "isError": false,
    }))
}

#[cfg(test)]
mod tests {
    use super::apply_watcher_delta;
    use crate::{Language, ProjectChangeWatcher, ProjectFile, TestProject, WorkspaceAnalyzer};
    use std::sync::Arc;

    #[test]
    fn apply_watcher_delta_updates_workspace_from_pending_files() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().to_path_buf();
        std::fs::write(root.join("lib.rs"), "fn before() {}\n").unwrap();

        let project = Arc::new(TestProject::new(root.clone(), Language::Rust));
        let mut workspace =
            WorkspaceAnalyzer::build(project.clone(), crate::AnalyzerConfig::default());
        let watcher = ProjectChangeWatcher::start(project).unwrap();

        std::fs::write(root.join("lib.rs"), "fn after() {}\n").unwrap();
        for _ in 0..50 {
            apply_watcher_delta(&mut workspace, Some(&watcher));
            if workspace.analyzer().get_definitions("after").len() == 1 {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        panic!(
            "workspace did not see watcher-driven refresh for {}",
            ProjectFile::new(root, "lib.rs").rel_path().display()
        );
    }
}

fn tool_error_result(message: String) -> Value {
    json!({
        "content": [{ "type": "text", "text": message }],
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
