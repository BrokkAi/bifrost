use crate::mcp_common::{McpRenderOptions, run_stdio_server, tool_descriptor};
use serde_json::{Value, json};
use std::path::PathBuf;

pub const EXTENDED_TOOL_NAMES: &[&str] = &[
    "get_symbol_locations",
    "get_symbol_ancestors",
    "find_filenames",
    "list_files",
    "most_relevant_files",
    "search_git_commit_messages",
    "get_git_log",
    "get_commit_diff",
    "jq",
    "xml_skim",
    "xml_select",
];

pub fn run_extended_stdio_server(
    root: PathBuf,
    render_options: McpRenderOptions,
) -> Result<(), String> {
    let spec = crate::mcp_registry::resolve_server_spec("extended")?;
    run_stdio_server(root, render_options, &spec)
}

pub(crate) fn extended_tool_descriptors() -> Vec<Value> {
    let pattern_schema_description = "A structural pattern object. Fields (all optional): kind (normalized kind, subtype-aware: declaration, callable, function, method, constructor, lambda, class, import, call, assignment, field_access, identifier, literal, string_literal, numeric_literal, boolean_literal, null_literal, return, throw, catch, if, loop, decorator), kind_exact (exact-kind variant), name (string for exact match or {\"regex\": ...}), text ({\"regex\": ...}), capture (label reported with each match), has / not_has (descendant patterns), and role sub-patterns valid for the declared kind: callee, receiver, args (array), kwargs (object keyed by keyword name), left, right, module, decorators (array), object, field.";
    vec![
        tool_descriptor(
            "search_ast",
            "Search code structure across languages using normalized node kinds instead of grammar-specific node names. Finds shapes like calls to a named function, assignments of literals, decorated functions, or imports of a module, with named captures and enclosing symbols. Use scan_usages instead when you already know the exact symbol; use this for structural shapes.",
            json!({
                "type": "object",
                "properties": {
                    "match": {
                        "type": "object",
                        "description": pattern_schema_description
                    },
                    "inside": {
                        "type": "object",
                        "description": "Optional containment constraint: the match must be lexically inside a node matching this pattern (same shape as match)."
                    },
                    "not_inside": {
                        "type": "object",
                        "description": "Optional negative containment: the match must NOT be inside a node matching this pattern."
                    },
                    "where": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Optional project-relative path globs limiting which files are searched."
                    },
                    "languages": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Optional language filter (e.g. \"python\"). Languages without structural support are reported in diagnostics."
                    },
                    "limit": {
                        "type": "integer",
                        "default": 100,
                        "minimum": 1,
                        "maximum": 1000,
                        "description": "Maximum number of matches to return."
                    }
                },
                "required": ["match"]
            }),
        ),
        tool_descriptor(
            "get_symbol_locations",
            "Get project-relative file paths and line ranges for known symbols after search_symbols; use before opening exact definitions.",
            crate::mcp_common::symbol_names_schema(),
        ),
        tool_descriptor(
            "get_symbol_ancestors",
            "Get nearest-parent-first ancestor class symbols for known classes after search_symbols; use when class inheritance context matters.",
            crate::mcp_common::symbol_names_schema(),
        ),
        tool_descriptor(
            "find_filenames",
            "Find files in the workspace whose path matches any of the given glob patterns. Patterns without '/' match against the file basename; patterns with '/' match against the full project-relative path. Absolute patterns inside the active workspace are converted to project-relative patterns before matching.",
            json!({
                "type": "object",
                "properties": {
                    "patterns": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Glob patterns to match against file paths."
                    },
                    "limit": {
                        "type": "integer",
                        "default": 100,
                        "minimum": 1,
                        "description": "Maximum number of matching files to return."
                    }
                },
                "required": ["patterns"]
            }),
        ),
        tool_descriptor(
            "list_files",
            "Return a recursive listing of files under a workspace-relative directory. Respects .gitignore via the project's walker.",
            json!({
                "type": "object",
                "properties": {
                    "directory_path": {
                        "type": "string",
                        "description": "Project-relative directory to list, or an absolute directory inside the active workspace. Empty string lists the workspace root."
                    },
                    "max_entries": {
                        "type": "integer",
                        "default": 500,
                        "minimum": 1,
                        "description": "Maximum number of entries to return."
                    }
                },
                "required": ["directory_path"]
            }),
        ),
        tool_descriptor(
            "most_relevant_files",
            "Given seed source files, rank related code by imports and git history; use after finding one relevant file to expand context.",
            json!({
                "type": "object",
                "properties": {
                    "seed_file_paths": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Project-relative seed files used to rank related files, or absolute paths inside the active workspace."
                    },
                    "seed_weights": {
                        "type": "array",
                        "items": { "type": "number", "exclusiveMinimum": 0.0 },
                        "description": "Optional raw per-seed weights aligned by index with seed_file_paths. When omitted, every seed uses weight 1.0."
                    },
                    "recency_half_life": {
                        "type": ["number", "null"],
                        "default": 250.0,
                        "exclusiveMinimum": 0.0,
                        "description": "Optional git recency half-life in commits. Omit for the default 250-commit exponential decay, or pass null for uniform weighting."
                    },
                    "limit": {
                        "type": "integer",
                        "default": 20,
                        "minimum": 0,
                        "description": "Maximum number of related files to return."
                    }
                },
                "required": ["seed_file_paths"]
            }),
        ),
        tool_descriptor(
            "search_git_commit_messages",
            "Regex search across the workspace's git commit messages. Returns matching commits as a sequence of <commit id=\"...\"> blocks, each containing <message> and <edited_files>.",
            json!({
                "type": "object",
                "properties": {
                    "pattern": {
                        "type": "string",
                        "description": "Regular expression to match against commit messages."
                    },
                    "limit": {
                        "type": "integer",
                        "default": 20,
                        "minimum": 1,
                        "maximum": 100,
                        "description": "Maximum number of matching commits to return (capped at 100)."
                    }
                },
                "required": ["pattern"]
            }),
        ),
        tool_descriptor(
            "get_git_log",
            "Return recent commits, optionally filtered to those that touch a given path. Output is a <git_log> wrapper containing <entry> elements with hash, author, date and the commit message body.",
            json!({
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Optional project-relative file or directory path to filter by, or an absolute path inside the active workspace."
                    },
                    "limit": {
                        "type": "integer",
                        "default": 20,
                        "minimum": 1,
                        "maximum": 100,
                        "description": "Maximum number of commits to return (capped at 100)."
                    }
                }
            }),
        ),
        tool_descriptor(
            "get_commit_diff",
            "Return the unified diff for a single commit versus its parent (or the empty tree for root commits), wrapped in a <commit_diff> element with revision, short_hash, files_total, files_included and truncated attributes. Truncated by file count and lines per file.",
            json!({
                "type": "object",
                "properties": {
                    "revision": {
                        "type": "string",
                        "description": "Commit reference (short hash, full hash, branch, tag)."
                    },
                    "max_files": {
                        "type": "integer",
                        "default": 10,
                        "minimum": 1,
                        "maximum": 100,
                        "description": "Maximum number of files to include in the diff (capped at 100)."
                    },
                    "lines_per_file": {
                        "type": "integer",
                        "default": 1000,
                        "minimum": 1,
                        "maximum": 5000,
                        "description": "Maximum number of diff lines per file (capped at 5000)."
                    }
                },
                "required": ["revision"]
            }),
        ),
        tool_descriptor(
            "jq",
            "Run a jq expression against one or more JSON files matched by a glob (or a literal path).",
            json!({
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Project-relative glob or literal path to JSON file(s), or an absolute path/glob inside the active workspace."
                    },
                    "filter": {
                        "type": "string",
                        "description": "jq filter expression."
                    },
                    "max_files": {
                        "type": "integer",
                        "default": 25,
                        "minimum": 1,
                        "description": "Maximum number of files to process."
                    },
                    "matches_per_file": {
                        "type": "integer",
                        "default": 100,
                        "minimum": 1,
                        "description": "Maximum number of filter outputs to collect per file."
                    }
                },
                "required": ["file_path", "filter"]
            }),
        ),
        tool_descriptor(
            "xml_skim",
            "Return an element-hierarchy outline (tag name, depth, attribute count) for one or more XML files. HTML is not supported in this revision; well-formed XML only.",
            json!({
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Project-relative glob or literal path to XML file(s), or an absolute path/glob inside the active workspace."
                    },
                    "max_files": {
                        "type": "integer",
                        "default": 25,
                        "minimum": 1,
                        "description": "Maximum number of files to process."
                    }
                },
                "required": ["file_path"]
            }),
        ),
        tool_descriptor(
            "xml_select",
            "Run an XPath 3.1 expression against one or more XML files. Returns matched node text, attribute value, or outer XML depending on output mode. HTML is not supported in this revision.",
            json!({
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Project-relative glob or literal path to XML file(s), or an absolute path/glob inside the active workspace."
                    },
                    "xpath": {
                        "type": "string",
                        "description": "XPath 3.1 expression."
                    },
                    "output": {
                        "type": "string",
                        "enum": ["text", "attribute", "outer-xml"],
                        "default": "text",
                        "description": "Output mode for matched nodes."
                    },
                    "attr_name": {
                        "type": "string",
                        "description": "Required when output is \"attribute\"."
                    },
                    "max_files": {
                        "type": "integer",
                        "default": 25,
                        "minimum": 1,
                        "description": "Maximum number of files to process."
                    }
                },
                "required": ["file_path", "xpath"]
            }),
        ),
    ]
}
