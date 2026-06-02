use crate::{
    SearchToolsService, SearchToolsServiceErrorCode, ToolOutput, searchtools_render::RenderOptions,
};
use serde_json::{Value, json};
use std::collections::HashSet;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};

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
    let mut tool_names = HashSet::with_capacity(tool_descriptors.len());
    for descriptor in &tool_descriptors {
        let Some(name) = descriptor.get("name").and_then(Value::as_str) else {
            return Err("tool descriptor missing string name".to_string());
        };
        tool_names.insert(name.to_string());
    }

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
            Ok(message) => dispatch_message(&mut service, message, render_options, spec),
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
    service: &mut SearchToolsService,
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
    service: &mut SearchToolsService,
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
    service: &mut SearchToolsService,
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
    let arguments = match normalize_tool_arguments(name, arguments, service.active_workspace_root())
    {
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

fn normalize_tool_arguments(
    tool_name: &str,
    mut arguments: Value,
    workspace_root: &Path,
) -> Result<Value, String> {
    match tool_name {
        "get_summaries" => normalize_string_array_field(&mut arguments, "targets", workspace_root)?,
        "list_symbols" => {
            normalize_string_array_field(&mut arguments, "file_patterns", workspace_root)?
        }
        "most_relevant_files" => {
            normalize_string_array_field(&mut arguments, "seed_file_paths", workspace_root)?
        }
        "get_file_contents" => {
            normalize_string_array_field(&mut arguments, "file_paths", workspace_root)?
        }
        "find_filenames" => {
            normalize_string_array_field(&mut arguments, "patterns", workspace_root)?
        }
        "search_file_contents" | "jq" | "xml_skim" | "xml_select" => {
            normalize_optional_string_field(&mut arguments, "file_path", workspace_root)?
        }
        "list_files" => {
            normalize_optional_string_field(&mut arguments, "directory_path", workspace_root)?
        }
        "compute_cyclomatic_complexity"
        | "compute_cognitive_complexity"
        | "report_comment_density_for_files"
        | "report_exception_handling_smells"
        | "report_test_assertion_smells"
        | "report_structural_clone_smells"
        | "report_long_method_and_god_object_smells"
        | "report_dead_code_and_unused_abstraction_smells" => {
            normalize_string_array_field(&mut arguments, "file_paths", workspace_root)?
        }
        "get_git_log" => {
            normalize_optional_string_field(&mut arguments, "file_path", workspace_root)?
        }
        _ => {}
    }
    Ok(arguments)
}

fn normalize_string_array_field(
    arguments: &mut Value,
    field: &str,
    workspace_root: &Path,
) -> Result<(), String> {
    let Some(array) = arguments.get_mut(field).and_then(Value::as_array_mut) else {
        return Ok(());
    };

    for item in array {
        let Some(raw) = item.as_str() else {
            continue;
        };
        if let Some(normalized) = normalize_mcp_path_argument(raw, workspace_root)? {
            *item = Value::String(normalized);
        }
    }
    Ok(())
}

fn normalize_optional_string_field(
    arguments: &mut Value,
    field: &str,
    workspace_root: &Path,
) -> Result<(), String> {
    let Some(value) = arguments.get_mut(field) else {
        return Ok(());
    };
    let Some(raw) = value.as_str() else {
        return Ok(());
    };
    if let Some(normalized) = normalize_mcp_path_argument(raw, workspace_root)? {
        *value = Value::String(normalized);
    }
    Ok(())
}

fn normalize_mcp_path_argument(raw: &str, workspace_root: &Path) -> Result<Option<String>, String> {
    let trimmed = raw.trim();
    if !looks_like_absolute_path(trimmed) {
        return Ok(None);
    }

    if contains_glob_syntax(trimmed) {
        return normalize_absolute_glob(trimmed, workspace_root).map(Some);
    }

    normalize_absolute_literal_path(trimmed, workspace_root).map(Some)
}

fn normalize_absolute_literal_path(raw: &str, workspace_root: &Path) -> Result<String, String> {
    let path = Path::new(raw);
    if let Ok(canonical_path) = path.canonicalize() {
        let canonical_root = workspace_root
            .canonicalize()
            .unwrap_or_else(|_| workspace_root.to_path_buf());
        return canonical_path
            .strip_prefix(&canonical_root)
            .map(path_to_slash_string)
            .map_err(|_| outside_workspace_error(raw, workspace_root));
    }

    normalize_absolute_path_lexically(raw, workspace_root)
}

fn normalize_absolute_glob(raw: &str, workspace_root: &Path) -> Result<String, String> {
    normalize_absolute_path_lexically(raw, workspace_root)
}

fn normalize_absolute_path_lexically(raw: &str, workspace_root: &Path) -> Result<String, String> {
    let raw_norm = slash_string(raw);
    let root_norm = slash_string(&workspace_root.display().to_string());
    let root_trimmed = root_norm.trim_end_matches('/');

    let relative = if raw_norm == root_trimmed {
        ""
    } else if let Some(rest) = raw_norm.strip_prefix(&format!("{root_trimmed}/")) {
        rest
    } else {
        return Err(outside_workspace_error(raw, workspace_root));
    };

    normalize_relative_slash_path(relative)
        .map_err(|_| outside_workspace_error(raw, workspace_root))
}

fn normalize_relative_slash_path(relative: &str) -> Result<String, String> {
    let mut parts: Vec<&str> = Vec::new();
    for part in relative.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if parts.pop().is_none() {
                    return Err("path escapes active workspace".to_string());
                }
            }
            _ => parts.push(part),
        }
    }
    Ok(parts.join("/"))
}

fn looks_like_absolute_path(raw: &str) -> bool {
    Path::new(raw).is_absolute() || is_windows_absolute_path(raw)
}

fn is_windows_absolute_path(raw: &str) -> bool {
    let bytes = raw.as_bytes();
    bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'/' | b'\\')
}

fn contains_glob_syntax(raw: &str) -> bool {
    raw.contains(['*', '?', '['])
}

fn path_to_slash_string(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn slash_string(path: &str) -> String {
    path.replace('\\', "/")
}

fn outside_workspace_error(raw: &str, workspace_root: &Path) -> String {
    format!(
        "absolute path is outside active workspace: {} (workspace: {})",
        raw,
        workspace_root.display()
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
                serde_json::to_string_pretty(&structured)
                    .unwrap_or_else(|_| "Failed to pretty-print tool result".to_string())
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn normalizes_absolute_literal_paths_for_tool_fields() {
        let root = TempDir::new().expect("temp dir");
        let src = root.path().join("src");
        fs::create_dir(&src).expect("src dir");
        let file = src.join("A.java");
        fs::write(&file, "class A {}\n").expect("write file");

        let normalized = normalize_tool_arguments(
            "get_file_contents",
            json!({ "file_paths": [file.display().to_string()] }),
            root.path(),
        )
        .expect("normalize");

        assert_eq!(normalized["file_paths"][0], "src/A.java");
    }

    #[test]
    fn normalizes_absolute_globs_lexically() {
        let root = TempDir::new().expect("temp dir");
        let raw = format!("{}/src/**/*.rs", root.path().display());

        let normalized = normalize_tool_arguments(
            "list_symbols",
            json!({ "file_patterns": [raw] }),
            root.path(),
        )
        .expect("normalize");

        assert_eq!(normalized["file_patterns"][0], "src/**/*.rs");
    }

    #[test]
    fn rejects_existing_absolute_paths_outside_workspace() {
        let root = TempDir::new().expect("root dir");
        let outside = TempDir::new().expect("outside dir");
        let file = outside.path().join("secret.txt");
        fs::write(&file, "secret").expect("write outside");

        let err = normalize_tool_arguments(
            "get_file_contents",
            json!({ "file_paths": [file.display().to_string()] }),
            root.path(),
        )
        .expect_err("outside path should fail");

        assert!(err.contains("outside active workspace"), "{err}");
        assert!(err.contains(&file.display().to_string()), "{err}");
    }

    #[test]
    fn normalizes_nonexistent_absolute_paths_inside_workspace() {
        let root = TempDir::new().expect("temp dir");
        let missing = root.path().join("src").join("Missing.java");

        let normalized = normalize_tool_arguments(
            "get_file_contents",
            json!({ "file_paths": [missing.display().to_string()] }),
            root.path(),
        )
        .expect("normalize");

        assert_eq!(normalized["file_paths"][0], "src/Missing.java");
    }

    #[test]
    fn rejects_nonexistent_parent_dir_escapes() {
        let root = TempDir::new().expect("temp dir");
        let raw = format!("{}/../outside/Missing.java", root.path().display());

        let err = normalize_tool_arguments(
            "get_file_contents",
            json!({ "file_paths": [raw] }),
            root.path(),
        )
        .expect_err("escaping path should fail");

        assert!(err.contains("outside active workspace"), "{err}");
    }

    #[test]
    fn leaves_non_path_fields_untouched() {
        let root = TempDir::new().expect("temp dir");
        let absolute_looking_symbol = format!("{}/src/A.java", root.path().display());

        let normalized = normalize_tool_arguments(
            "scan_usages",
            json!({ "symbols": [absolute_looking_symbol] }),
            root.path(),
        )
        .expect("normalize");

        assert_eq!(normalized["symbols"][0], absolute_looking_symbol);
    }

    #[test]
    fn normalizes_only_path_fields_for_mixed_argument_tools() {
        let root = TempDir::new().expect("temp dir");
        let src = root.path().join("src");
        fs::create_dir(&src).expect("src dir");
        let file = src.join("lib.rs");
        fs::write(&file, "fn helper() {}\n").expect("write file");
        let fq_name = format!("{}/src/lib.rs", root.path().display());

        let normalized = normalize_tool_arguments(
            "report_dead_code_and_unused_abstraction_smells",
            json!({
                "file_paths": [file.display().to_string()],
                "fq_names": [fq_name]
            }),
            root.path(),
        )
        .expect("normalize");

        assert_eq!(normalized["file_paths"][0], "src/lib.rs");
        assert_eq!(normalized["fq_names"][0], fq_name);
    }
}
