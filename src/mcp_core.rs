use crate::mcp_common::{
    McpRenderOptions, json_schema_object, mutating_tool_descriptor, run_stdio_server,
    summaries_schema, symbol_names_schema, tool_descriptor,
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
            "Find classes, functions, methods, fields, modules, and other indexed declarations by name. Use this first for broad or partial symbol discovery, then pass fully qualified results to get_symbol_sources or scan_usages.",
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
            "Read exact source blocks for known symbols after search_symbols. File paths/globs return flat top-level symbol outlines as a secondary file-backed view; use get_summaries for broader structure.",
            symbol_names_schema(),
        ),
        tool_descriptor(
            "get_summaries",
            "Summarize matching source files, globs, classes, or modules with line ranges. Use before repeated read_file/grep calls when you need a compact map of related code before choosing exact definitions to inspect. If full summaries exceed the response budget, the result is marked degraded and returns compact_symbols declaration outlines instead. Example targets: [\"src/auth/**/*.rs\"], [\"crates/polars-core/src/frame/**/*.rs\"], [\"MyClass\"].",
            summaries_schema(),
        ),
        tool_descriptor(
            "scan_usages",
            "Find references, call sites, usages, callers, and related tests for known fully qualified symbols. Prefer over grep when changing existing behavior and callers may matter; use search_symbols first for partial names. Results are tiered by volume and budget: few callers include snippets, larger results degrade to lines or per-file summaries. Narrow with paths or one symbol at a time for detail.",
            json!({
                "type": "object",
                "properties": {
                    "symbols": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Fully qualified symbol names from search_symbols are preferred; short names may resolve fuzzily or become ambiguous."
                    },
                    "include_tests": {
                        "type": "boolean",
                        "default": false,
                        "description": "Include call sites in test files."
                    },
                    "paths": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Optional project-relative file paths or glob patterns used to narrow where usages are searched. Use paths from summary-mode scan_usages output to re-call for line or snippet detail."
                    }
                },
                "required": ["symbols"]
            }),
        ),
        tool_descriptor(
            "get_definition",
            "Resolve source reference sites back to workspace definition metadata. Use when you know a file and source location and need usage-to-definition navigation without building the whole usage_graph. Results distinguish resolved definitions from no_definition, unresolvable_import_boundary, ambiguous, unsupported_language, invalid_location, and not_found states.",
            json!({
                "type": "object",
                "properties": {
                    "references": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "path": {
                                    "type": "string",
                                    "description": "Project-relative source file path containing the reference."
                                },
                                "line": {
                                    "type": "integer",
                                    "minimum": 1,
                                    "description": "1-based line containing the reference. Use with column when byte offsets are not available."
                                },
                                "column": {
                                    "type": "integer",
                                    "minimum": 1,
                                    "description": "1-based column containing the reference token."
                                },
                                "start_byte": {
                                    "type": "integer",
                                    "minimum": 0,
                                    "description": "0-based byte offset at or inside the reference token."
                                },
                                "end_byte": {
                                    "type": "integer",
                                    "minimum": 0,
                                    "description": "Optional exclusive byte end offset for a selected reference range."
                                },
                                "symbol": {
                                    "type": "string",
                                    "description": "Optional disambiguating symbol name. The location remains the primary lookup input."
                                }
                            },
                            "required": ["path"]
                        }
                    },
                    "include_tests": {
                        "type": "boolean",
                        "default": false,
                        "description": "Allow reference lookups inside detected test files."
                    }
                },
                "required": ["references"]
            }),
        ),
        tool_descriptor(
            "usage_graph",
            "Return the whole-workspace caller->callee reference graph in one call: classes and functions as nodes, resolved references as weighted edges. Use to build a code map or rank symbols by importance (e.g. PageRank) instead of issuing one scan_usages call per symbol. Edges reuse scan_usages resolution; symbols whose call sites exceed the enumeration guardrail are listed under truncated_symbols with their inbound edges omitted.",
            json!({
                "type": "object",
                "properties": {
                    "include_tests": {
                        "type": "boolean",
                        "default": false,
                        "description": "Include references that live in detected test files."
                    },
                    "paths": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Optional project-relative file paths or glob patterns used to narrow where references are searched. Omit to graph the whole workspace."
                    }
                }
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
