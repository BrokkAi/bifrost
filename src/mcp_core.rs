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
    let git_repo = crate::mcp_registry::workspace_is_git(&root);
    let spec = crate::mcp_registry::resolve_server_spec_for_render_options(
        "core",
        render_options,
        git_repo,
    )?;
    run_stdio_server(root, render_options, &spec)
}

pub fn run_searchtools_stdio_server(
    root: PathBuf,
    render_options: McpRenderOptions,
) -> Result<(), String> {
    let git_repo = crate::mcp_registry::workspace_is_git(&root);
    let spec = crate::mcp_registry::resolve_server_spec_for_render_options(
        "searchtools",
        render_options,
        git_repo,
    )?;
    run_stdio_server(root, render_options, &spec)
}

pub(crate) fn symbol_tool_descriptors(render_line_numbers: bool) -> Vec<Value> {
    let definition_descriptor = if render_line_numbers {
        get_definitions_by_location_descriptor()
    } else {
        get_definitions_by_reference_descriptor()
    };
    let scan_descriptor = if render_line_numbers {
        scan_usages_by_location_descriptor()
    } else {
        scan_usages_by_reference_descriptor()
    };
    let scan_tool_name = if render_line_numbers {
        "scan_usages_by_location"
    } else {
        "scan_usages_by_reference"
    };
    let search_symbols_description = format!(
        "Find classes, functions, methods, fields, modules, and other indexed declarations by name. Use this first for broad or partial symbol discovery, then pass fully qualified results to get_symbol_sources or {scan_tool_name}."
    );

    let mut descriptors = vec![
        tool_descriptor(
            "search_symbols",
            &search_symbols_description,
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
        scan_descriptor,
        definition_descriptor,
    ];
    if render_line_numbers {
        descriptors.push(get_type_by_location_descriptor());
    }
    descriptors.push(rename_symbol_descriptor());
    descriptors.push(tool_descriptor(
        "usage_graph",
        "Return the whole-workspace caller->callee reference graph in one call: classes and functions as nodes, resolved references as weighted edges. Use to build a code map or rank symbols by importance instead of issuing one per-symbol scan-usage call. Each edge carries its reference locations as a `sites` array of {path, line} (1-based), so you can map call sites without re-scanning; the site count equals the edge weight. Edges reuse scan-usage resolution; symbols whose call sites exceed the enumeration guardrail are listed under truncated_symbols with their inbound edges omitted.",
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
    ));
    descriptors.push(tool_descriptor(
        "analyze_commit",
        "Analyze a normal single-parent commit against its parent and return Bifrost-resolved semantic patch effects: changed files, introduced/edited/deleted/moved symbols, dependency symbols, signature/import/call-edge changes, changed test symbols, and large-callsite truncation notices.",
        json!({
            "type": "object",
            "properties": {
                "revision": {
                    "type": "string",
                    "minLength": 1,
                    "description": "Commit hash, branch, or tag resolving to a single-parent commit."
                },
                "include_tests": {
                    "type": "boolean",
                    "default": true,
                    "description": "Include symbols and call edges from detected test files."
                }
            },
            "required": ["revision"]
        }),
    ));
    descriptors
}

fn rename_symbol_descriptor() -> Value {
    tool_descriptor(
        "rename_symbol",
        "Return the safe, non-mutating edit set for renaming one resolved workspace symbol from an exact line and character column. The tool rejects ambiguous, unsupported, invalid, truncated, or low-confidence renames instead of applying changes.",
        json!({
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "minLength": 1,
                    "description": "Project-relative source file path containing the declaration or reference to rename."
                },
                "line": {
                    "type": "integer",
                    "minimum": 1,
                    "description": "1-based line containing the selected identifier."
                },
                "column": {
                    "type": "integer",
                    "minimum": 1,
                    "description": "1-based character column inside the selected identifier."
                },
                "new_name": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": crate::symbol_rename::MAX_RENAME_IDENTIFIER_BYTES,
                    "description": "Replacement identifier. It must be valid for the target symbol's language."
                }
            },
            "required": ["path", "line", "column", "new_name"]
        }),
    )
}

fn get_type_by_location_descriptor() -> Value {
    tool_descriptor(
        "get_type_by_location",
        "Resolve source reference sites to the workspace type definitions known for those expressions or identifiers from exact line/column locations.",
        location_references_schema(
            "Project-relative source file path containing the expression or identifier.",
            Some(crate::searchtools::TYPE_LOOKUP_MAX_REFERENCES),
        ),
    )
}

fn get_definitions_by_location_descriptor() -> Value {
    tool_descriptor(
        "get_definitions_by_location",
        "Resolve source reference sites back to workspace definition metadata from exact line/column locations. Use when line numbers are visible and you need usage-to-definition navigation without building the whole usage_graph.",
        location_references_schema(
            "Project-relative source file path containing the reference.",
            None,
        ),
    )
}

fn location_references_schema(path_description: &str, max_items: Option<usize>) -> Value {
    let mut references = json!({
        "type": "array",
        "items": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": path_description
                },
                "line": {
                    "type": "integer",
                    "minimum": 1,
                    "description": "1-based line containing the reference."
                },
                "column": {
                    "type": "integer",
                    "minimum": 1,
                    "description": "1-based character column containing the reference token."
                }
            },
            "required": ["path", "line"]
        }
    });
    if let Some(max_items) = max_items
        && let Some(object) = references.as_object_mut()
    {
        object.insert("maxItems".to_string(), json!(max_items));
    }
    json!({
        "type": "object",
        "properties": {
            "references": references
        },
        "required": ["references"]
    })
}

fn scan_usages_by_reference_descriptor() -> Value {
    tool_descriptor(
        "scan_usages_by_reference",
        "Find references, call sites, callers, and related tests for known workspace symbols. Use search_symbols first for partial names. Each result reports its effective scope, status, completeness, resolved declaration, and proven or unproven usage sites.",
        json!({
            "type": "object",
            "properties": {
                "symbols": {
                    "type": "array",
                    "minItems": 1,
                    "items": { "type": "string", "pattern": "\\S" },
                    "description": "Fully qualified symbols from search_symbols are preferred; short names may resolve fuzzily or become ambiguous."
                },
                "include_tests": {
                    "type": "boolean",
                    "default": false,
                    "description": "Include call sites in test files."
                },
                "paths": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Optional project-relative paths or globs used to narrow where usages are searched."
                }
            },
            "required": ["symbols"]
        }),
    )
}

fn scan_usages_by_location_descriptor() -> Value {
    tool_descriptor(
        "scan_usages_by_location",
        "Find references, call sites, callers, and related tests for declarations selected by project-relative path and 1-based line/column. The location must identify a declaration name; arbitrary lines inside a declaration body are rejected.",
        json!({
            "type": "object",
            "properties": {
                "targets": {
                    "type": "array",
                    "minItems": 1,
                    "items": {
                        "type": "object",
                        "properties": {
                            "path": {
                                "type": "string",
                                "minLength": 1,
                                "description": "Project-relative source path containing the declaration."
                            },
                            "line": {
                                "type": "integer",
                                "minimum": 1,
                                "description": "1-based line containing the declaration name."
                            },
                            "column": {
                                "type": "integer",
                                "minimum": 1,
                                "description": "Optional 1-based character column inside the declaration name."
                            }
                        },
                        "required": ["path", "line"]
                    }
                },
                "include_tests": {
                    "type": "boolean",
                    "default": false,
                    "description": "Include call sites in test files."
                },
                "paths": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Optional project-relative paths or globs used to narrow where usages are searched."
                }
            },
            "required": ["targets"]
        }),
    )
}

fn get_definitions_by_reference_descriptor() -> Value {
    tool_descriptor(
        "get_definitions_by_reference",
        "Resolve source reference sites back to workspace definition metadata from copied source context and a target token. Use when line numbers are hidden or unreliable. If repeated target occurrences in the context resolve differently, the result is ambiguous.",
        json!({
            "type": "object",
            "properties": {
                "references": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "symbol": {
                                "type": "string",
                                "description": "Fully qualified workspace symbol whose source contains the reference context."
                            },
                            "context": {
                                "type": "string",
                                "description": "Exact source text copied from the file around the reference."
                            },
                            "target": {
                                "type": "string",
                                "description": "Exact single reference token to resolve inside the context; for qualified expressions, use the member or name token rather than the whole expression."
                            }
                        },
                        "required": ["symbol", "context", "target"]
                    }
                }
            },
            "required": ["references"]
        }),
    )
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
