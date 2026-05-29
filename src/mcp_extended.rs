use crate::mcp_common::{
    McpRenderOptions, McpServerSpec, SEARCHTOOLS_INSTRUCTIONS, run_stdio_server,
    symbol_names_schema, tool_descriptor,
};
use serde_json::{Value, json};
use std::path::PathBuf;

pub const EXTENDED_TOOL_NAMES: &[&str] = &[
    "get_file_contents",
    "find_filenames",
    "find_files_containing",
    "search_file_contents",
    "list_files",
    "skim_files",
    "get_symbol_summaries",
    "most_relevant_files",
    "search_git_commit_messages",
    "get_git_log",
    "get_commit_diff",
    "jq",
    "xml_skim",
    "xml_select",
];

const EXTENDED_SPEC: McpServerSpec = McpServerSpec {
    instructions: SEARCHTOOLS_INSTRUCTIONS,
    tool_names: EXTENDED_TOOL_NAMES,
    tool_descriptors: extended_tool_descriptors,
};

pub fn run_extended_stdio_server(
    root: PathBuf,
    render_options: McpRenderOptions,
) -> Result<(), String> {
    run_stdio_server(root, render_options, &EXTENDED_SPEC)
}

pub(crate) fn extended_tool_descriptors() -> Vec<Value> {
    vec![
        tool_descriptor(
            "get_file_contents",
            "Return the raw text contents of one or more files in the workspace, given project-relative paths or absolute paths inside the active workspace.",
            json!({
                "type": "object",
                "properties": {
                    "file_paths": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Project-relative paths of files to read, or absolute paths inside the active workspace."
                    }
                },
                "required": ["file_paths"]
            }),
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
            "find_files_containing",
            "Find files whose contents match any of the given regular expressions. Binary files and files outside the workspace's gitignore-respecting walk are skipped.",
            json!({
                "type": "object",
                "properties": {
                    "patterns": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Regular expressions to match against file contents."
                    },
                    "limit": {
                        "type": "integer",
                        "default": 50,
                        "minimum": 1,
                        "description": "Maximum number of matching files to return."
                    },
                    "case_insensitive": {
                        "type": "boolean",
                        "default": false,
                        "description": "Whether to ignore case when matching."
                    }
                },
                "required": ["patterns"]
            }),
        ),
        tool_descriptor(
            "search_file_contents",
            "Search file contents with regular expressions, returning matching lines with surrounding context. Optionally restrict the search to files matching a glob or absolute glob inside the active workspace.",
            json!({
                "type": "object",
                "properties": {
                    "patterns": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Regular expressions to search for in file contents."
                    },
                    "file_path": {
                        "type": "string",
                        "description": "Optional glob to restrict the search to matching paths, or an absolute path/glob inside the active workspace."
                    },
                    "context_lines": {
                        "type": "integer",
                        "default": 2,
                        "minimum": 0,
                        "description": "Number of context lines to include before and after each match."
                    },
                    "case_insensitive": {
                        "type": "boolean",
                        "default": false,
                        "description": "Whether to ignore case when matching."
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
            "skim_files",
            "Return a top-level declaration outline (class/function/field/module) for each given file. Like list_symbols but constrained to top-level declarations only.",
            json!({
                "type": "object",
                "properties": {
                    "file_paths": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Project-relative paths of files to skim, or absolute paths inside the active workspace."
                    }
                },
                "required": ["file_paths"]
            }),
        ),
        tool_descriptor(
            "get_symbol_summaries",
            "Preview compact line-ranged summaries for known symbols after search_symbols; cheaper than reading whole files.",
            symbol_names_schema(),
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
