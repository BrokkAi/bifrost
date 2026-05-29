use crate::mcp_common::{
    McpRenderOptions, McpServerSpec, SEARCHTOOLS_INSTRUCTIONS, file_patterns_schema,
    json_schema_object, mutating_tool_descriptor, run_stdio_server, summaries_schema,
    symbol_names_schema, tool_descriptor,
};
use serde_json::{Value, json};
use std::path::PathBuf;

pub const CORE_TOOL_NAMES: &[&str] = &[
    "refresh",
    "activate_workspace",
    "get_active_workspace",
    "search_symbols",
    "get_symbol_locations",
    "get_symbol_sources",
    "get_summaries",
    "list_symbols",
    "scan_usages",
];

pub const SEARCHTOOLS_TOOL_NAMES: &[&str] = &[
    "refresh",
    "activate_workspace",
    "get_active_workspace",
    "search_symbols",
    "get_symbol_locations",
    "get_symbol_sources",
    "get_summaries",
    "list_symbols",
    "most_relevant_files",
    "scan_usages",
    "get_file_contents",
    "find_filenames",
    "find_files_containing",
    "search_file_contents",
    "list_files",
    "skim_files",
    "search_git_commit_messages",
    "get_git_log",
    "get_commit_diff",
    "jq",
    "xml_skim",
    "xml_select",
    "compute_cyclomatic_complexity",
    "compute_cognitive_complexity",
    "report_comment_density_for_code_unit",
    "report_exception_handling_smells",
    "report_comment_density_for_files",
    "analyze_git_hotspots",
    "report_test_assertion_smells",
    "report_structural_clone_smells",
    "report_long_method_and_god_object_smells",
    "report_dead_code_and_unused_abstraction_smells",
    "report_secret_like_code",
];

const CORE_SPEC: McpServerSpec = McpServerSpec {
    instructions: SEARCHTOOLS_INSTRUCTIONS,
    tool_names: CORE_TOOL_NAMES,
    tool_descriptors: core_tool_descriptors,
};

const SEARCHTOOLS_SPEC: McpServerSpec = McpServerSpec {
    instructions: SEARCHTOOLS_INSTRUCTIONS,
    tool_names: SEARCHTOOLS_TOOL_NAMES,
    tool_descriptors: searchtools_tool_descriptors,
};

pub fn run_core_stdio_server(
    root: PathBuf,
    render_options: McpRenderOptions,
) -> Result<(), String> {
    run_stdio_server(root, render_options, &CORE_SPEC)
}

pub fn run_searchtools_stdio_server(
    root: PathBuf,
    render_options: McpRenderOptions,
) -> Result<(), String> {
    run_stdio_server(root, render_options, &SEARCHTOOLS_SPEC)
}

pub(crate) fn core_tool_descriptors() -> Vec<Value> {
    vec![
        mutating_tool_descriptor(
            "refresh",
            "Update the code index after files change so symbol, usage, and workspace search results reflect the current checkout.",
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
            "get_symbol_locations",
            "Get project-relative file paths and line ranges for known symbols after search_symbols; use before opening exact definitions.",
            symbol_names_schema(),
        ),
        tool_descriptor(
            "get_symbol_sources",
            "Read exact source blocks for known symbols after search_symbols; prefer over cat when inspecting definitions.",
            symbol_names_schema(),
        ),
        tool_descriptor(
            "get_summaries",
            "Summarize matching source files, globs, or classes with line ranges; use to orient in code before reading full files.",
            summaries_schema(),
        ),
        tool_descriptor(
            "list_symbols",
            "Outline declarations recursively for source files; use to understand code structure without reading entire files.",
            file_patterns_schema(),
        ),
        tool_descriptor(
            "scan_usages",
            "Find references and call sites for known fully qualified symbols; use search_symbols first for partial names. Static analysis may include false positives. Graph-analysis fallbacks and resolved-symbol failures are returned with structured reasons.",
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

fn searchtools_tool_descriptors() -> Vec<Value> {
    let mut tools = core_tool_descriptors();
    tools.extend(crate::mcp_extended::extended_tool_descriptors());
    tools.extend(crate::mcp_slopcop::slopcop_tool_descriptors());
    tools
}
