use crate::mcp_common::{
    McpRenderOptions, file_patterns_schema, json_schema_object, mutating_tool_descriptor,
    run_stdio_server, summaries_schema, symbol_names_schema, tool_descriptor,
};
use serde_json::{Value, json};
use std::path::PathBuf;

pub fn run_core_stdio_server(
    root: PathBuf,
    render_options: McpRenderOptions,
) -> Result<(), String> {
    let spec = crate::mcp_registry::resolve_server_spec("core")?;
    run_stdio_server(root, render_options, &spec)
}

pub fn run_searchtools_stdio_server(
    root: PathBuf,
    render_options: McpRenderOptions,
) -> Result<(), String> {
    let spec = crate::mcp_registry::resolve_server_spec("searchtools")?;
    run_stdio_server(root, render_options, &spec)
}

pub(crate) fn symbol_tool_descriptors() -> Vec<Value> {
    vec![
        tool_descriptor(
            "search_symbols",
            "Find classes, functions, methods, fields, modules, and other indexed declarations by name; prefer over grep when looking for code symbols.",
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
                        "description": "Maximum number of matching symbol results to return."
                    }
                },
                "required": ["patterns"]
            }),
        ),
        tool_descriptor(
            "get_symbol_sources",
            "Read exact source blocks for known symbols after search_symbols; file paths/globs return flat top-level symbol outlines for matching files.",
            symbol_names_schema(),
        ),
        tool_descriptor(
            "get_summaries",
            "Summarize matching source files, globs, classes, or modules with line ranges. Use before repeated read_file/grep calls when you need a compact map of related code before choosing exact definitions to inspect. Example targets: [\"src/auth/**/*.rs\"], [\"crates/polars-core/src/frame/**/*.rs\"], [\"MyClass\"].",
            summaries_schema(),
        ),
        tool_descriptor(
            "list_symbols",
            "Outline declarations recursively for source files; use to understand code structure without reading entire files.",
            file_patterns_schema(),
        ),
        tool_descriptor(
            "scan_usages",
            "Find references, call sites, and related tests for known fully qualified symbols. Prefer over grep when changing existing behavior and callers may matter; use search_symbols first for partial names. Static analysis may include false positives. Graph-analysis fallbacks and resolved-symbol failures are returned with structured reasons.",
            json!({
                "type": "object",
                "properties": {
                    "symbols": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Fully qualified symbol names to find usages for."
                    },
                    "include_tests": {
                        "type": "boolean",
                        "default": false,
                        "description": "Include call sites in test files."
                    }
                },
                "required": ["symbols"]
            }),
        ),
    ]
}

pub(crate) fn workspace_tool_descriptors() -> Vec<Value> {
    vec![
        mutating_tool_descriptor(
            "refresh",
            "Force a full rebuild of the code index. Normal tool calls already apply watcher-detected file changes automatically, so use this only when you want to blow away cached analyzer state and rescan the entire workspace.",
            json_schema_object(&[]),
        ),
        mutating_tool_descriptor(
            "activate_workspace",
            "Switch the active workspace root for later tools; a workspace is already active at startup, so use this only to move to a different repo, checkout, or worktree.",
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
            "Return the current active workspace root, including after any prior workspace switch; use this to confirm which repository later tools will inspect.",
            json_schema_object(&[]),
        ),
    ]
}
