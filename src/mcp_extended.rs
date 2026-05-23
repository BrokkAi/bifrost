use crate::mcp_common::{
    McpRenderOptions, McpServerSpec, SEARCHTOOLS_INSTRUCTIONS, WeightThreshold, run_stdio_server,
    tool_descriptor, weight_knob_descriptor,
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
            "Return the raw text contents of one or more files in the workspace, given project-relative paths.",
            json!({
                "type": "object",
                "properties": {
                    "filenames": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Project-relative paths of files to read."
                    }
                },
                "required": ["filenames"]
            }),
        ),
        tool_descriptor(
            "find_filenames",
            "Find files in the workspace whose path matches any of the given glob patterns. Patterns without '/' match against the file basename; patterns with '/' match against the full project-relative path.",
            json!({
                "type": "object",
                "properties": {
                    "patterns": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Glob patterns to match against filenames."
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
            "Search file contents with regular expressions, returning matching lines with surrounding context. Optionally restrict the search to files matching a glob.",
            json!({
                "type": "object",
                "properties": {
                    "patterns": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Regular expressions to search for in file contents."
                    },
                    "filepath": {
                        "type": "string",
                        "description": "Optional glob to restrict the search to matching paths."
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
                        "description": "Project-relative directory to list. Empty string lists the workspace root."
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
                        "description": "Project-relative paths of files to skim."
                    }
                },
                "required": ["file_paths"]
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
                    "path": {
                        "type": "string",
                        "description": "Optional project-relative file or directory path to filter by."
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
                    "filepath": {
                        "type": "string",
                        "description": "Project-relative glob or literal path to JSON file(s)."
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
                "required": ["filepath", "filter"]
            }),
        ),
        tool_descriptor(
            "xml_skim",
            "Return an element-hierarchy outline (tag name, depth, attribute count) for one or more XML files. HTML is not supported in this revision; well-formed XML only.",
            json!({
                "type": "object",
                "properties": {
                    "filepath": {
                        "type": "string",
                        "description": "Project-relative glob or literal path to XML file(s)."
                    },
                    "max_files": {
                        "type": "integer",
                        "default": 25,
                        "minimum": 1,
                        "description": "Maximum number of files to process."
                    }
                },
                "required": ["filepath"]
            }),
        ),
        tool_descriptor(
            "xml_select",
            "Run an XPath 3.1 expression against one or more XML files. Returns matched node text, attribute value, or outer XML depending on output mode. HTML is not supported in this revision.",
            json!({
                "type": "object",
                "properties": {
                    "filepath": {
                        "type": "string",
                        "description": "Project-relative glob or literal path to XML file(s)."
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
                "required": ["filepath", "xpath"]
            }),
        ),
        tool_descriptor(
            "compute_cyclomatic_complexity",
            "Compute heuristic cyclomatic complexity per function/method in the given files; flag those exceeding a threshold. Heuristic counts a base of 1 plus each `if/while/for/switch/case/catch` keyword and each `&&`/`||`/`?` operator in the source.",
            json!({
                "type": "object",
                "properties": {
                    "file_paths": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Project-relative paths of files to analyze."
                    },
                    "threshold": {
                        "type": "integer",
                        "default": 10,
                        "description": "Flag functions whose complexity exceeds this threshold. Values <= 0 fall back to 10."
                    }
                },
                "required": ["file_paths"]
            }),
        ),
        tool_descriptor(
            "compute_cognitive_complexity",
            "Compute heuristic cognitive complexity per function/method in the given files; flag those exceeding a threshold. Walks the language's tree-sitter AST, scoring control-flow breaks by SonarSource rules (each `if`/loop/`catch`/case adds 1+nesting; sequences of `&&`/`||` count per distinct adjacent operator; labeled `break`/`continue` add 1). Output format matches the brokk-core MCP byte-for-byte.",
            json!({
                "type": "object",
                "properties": {
                    "file_paths": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Project-relative paths of files to analyze."
                    },
                    "threshold": {
                        "type": "integer",
                        "default": 15,
                        "description": "Flag functions whose cognitive complexity exceeds this threshold. Values <= 0 fall back to 15."
                    }
                },
                "required": ["file_paths"]
            }),
        ),
        tool_descriptor(
            "report_comment_density_for_code_unit",
            "Java comment density for one symbol identified by fully qualified name. Reports header vs inline comment line counts, declaration span lines, and rolled-up totals for class-like units. Output format matches the brokk-core MCP byte-for-byte.",
            json!({
                "type": "object",
                "properties": {
                    "fq_name": {
                        "type": "string",
                        "description": "Fully qualified name (e.g. com.example.MyClass or com.example.MyClass.method)."
                    },
                    "max_lines": {
                        "type": "integer",
                        "default": 120,
                        "description": "Maximum output lines; values <= 0 default to 120."
                    }
                },
                "required": ["fq_name"]
            }),
        ),
        tool_descriptor(
            "report_exception_handling_smells",
            "Detects suspicious exception handlers using weighted heuristics designed for high-recall triage. Scores generic catches and tiny / empty / comment-only / log-only handlers, then subtracts credit for richer handler bodies. Use min_score, max_findings, and the per-rule weights to tune precision/recall. Output format matches the brokk-core MCP byte-for-byte.",
            json!({
                "type": "object",
                "properties": {
                    "file_paths": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Project-relative paths of files to analyze."
                    },
                    "min_score": {
                        "type": "integer",
                        "default": 4,
                        "description": "Minimum score to include a finding; values <= 0 default to 4."
                    },
                    "max_findings": {
                        "type": "integer",
                        "default": 80,
                        "description": "Maximum findings to emit; values <= 0 default to 80."
                    },
                    "generic_throwable_weight": weight_knob_descriptor(
                        "Weight for catching Throwable", 5, WeightThreshold::Negative),
                    "generic_exception_weight": weight_knob_descriptor(
                        "Weight for catching Exception", 3, WeightThreshold::Negative),
                    "generic_runtime_exception_weight": weight_knob_descriptor(
                        "Weight for catching RuntimeException", 2, WeightThreshold::Negative),
                    "empty_body_weight": weight_knob_descriptor(
                        "Weight for empty catch bodies", 5, WeightThreshold::Negative),
                    "comment_only_body_weight": weight_knob_descriptor(
                        "Weight for comment-only catch bodies", 4, WeightThreshold::Negative),
                    "small_body_weight": weight_knob_descriptor(
                        "Weight for small catch bodies", 2, WeightThreshold::Negative),
                    "log_only_body_weight": weight_knob_descriptor(
                        "Weight for log-only catch bodies", 2, WeightThreshold::Negative),
                    "meaningful_body_credit_per_statement": weight_knob_descriptor(
                        "Score credit subtracted per catch statement in the body", 1, WeightThreshold::Negative),
                    "meaningful_body_statement_threshold": weight_knob_descriptor(
                        "Maximum statements that earn meaningful-body credit", 6, WeightThreshold::Negative),
                    "small_body_max_statements": weight_knob_descriptor(
                        "Maximum statement count considered a small body", 2, WeightThreshold::Negative)
                },
                "required": ["file_paths"]
            }),
        ),
        tool_descriptor(
            "report_comment_density_for_files",
            "Java comment density tables for the given source files: one section per file and one row per top-level declaration with own and rolled-up header / inline / span line counts. Non-Java files are skipped with a one-line placeholder. Output format matches the brokk-core MCP byte-for-byte.",
            json!({
                "type": "object",
                "properties": {
                    "file_paths": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Project-relative paths of files to analyze."
                    },
                    "max_top_level_rows": {
                        "type": "integer",
                        "default": 60,
                        "description": "Maximum declaration rows across all files; values <= 0 default to 60."
                    },
                    "max_files": {
                        "type": "integer",
                        "default": 25,
                        "description": "Maximum files to include; values <= 0 default to 25."
                    }
                },
                "required": ["file_paths"]
            }),
        ),
    ]
}
