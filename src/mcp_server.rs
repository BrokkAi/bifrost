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
            tool_descriptor(
                "scan_usages",
                "Find call sites and references for fully qualified symbol names. Use search_symbols first when you only have a partial name. Best-effort name resolution: bifrost is tree-sitter only (no scope analysis or type checker), so output may include false positives for shadowed names.",
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
                "report_long_method_and_god_object_smells",
                "Detects oversized functions, god classes, and god modules using weighted maintainability-size thresholds. Walks the declaration tree per file, rolling up function/nested-type counts and cyclomatic complexity. Tunable knobs apply when supplied; values <= 0 use brokk defaults. File-level modules (JS/TS, Python, Rust, Go, C++) get a built-in leeway multiplier. Output format matches the brokk-core MCP byte-for-byte.",
                json!({
                    "type": "object",
                    "properties": {
                        "file_paths": {
                            "type": "array",
                            "items": { "type": "string" },
                            "description": "Project-relative paths of files to analyze."
                        },
                        "max_findings": {
                            "type": "integer",
                            "default": 20,
                            "description": "Maximum findings to emit; values <= 0 default to 20."
                        },
                        "max_files": {
                            "type": "integer",
                            "default": 25,
                            "description": "Maximum files to analyze; values <= 0 default to 25."
                        },
                        "long_method_span_lines": weight_knob_descriptor(
                            "Long-function span threshold", 80, WeightThreshold::NonPositive),
                        "high_complexity_threshold": weight_knob_descriptor(
                            "Cyclomatic complexity considered high", 10, WeightThreshold::NonPositive),
                        "god_object_span_lines": weight_knob_descriptor(
                            "God-object span threshold", 300, WeightThreshold::NonPositive),
                        "god_object_direct_children": weight_knob_descriptor(
                            "Direct member count flagged as a god object", 20, WeightThreshold::NonPositive),
                        "god_object_functions": weight_knob_descriptor(
                            "Function count flagged as a god object", 15, WeightThreshold::NonPositive),
                        "helper_sprawl_functions": weight_knob_descriptor(
                            "Function count flagged as helper sprawl", 10, WeightThreshold::NonPositive),
                        "helper_sprawl_workflow_lines": weight_knob_descriptor(
                            "Workflow size that triggers helper-sprawl scoring", 60, WeightThreshold::NonPositive)
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

/// JSON schema fragment for an integer "weight knob" tunable.
/// `pick_threshold` selects the sentinel: `WeightThreshold::Negative`
/// matches `pick_weight` semantics (only `< 0` falls back to the brokk
/// default; `0` is an explicit override that disables the rule).
/// `WeightThreshold::NonPositive` matches `pick_positive` (both `0` and
/// negatives fall back; `0` is not a valid override).
fn weight_knob_descriptor(
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
enum WeightThreshold {
    /// Only `< 0` falls back to the default; `0` is honored as an
    /// explicit override. Pairs with `code_quality::pick_weight`.
    Negative,
    /// Both `0` and negatives fall back to the default. Pairs with
    /// `code_quality::pick_positive`.
    NonPositive,
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

// Convention between this function and `SearchToolsService::decode_and_run`:
//
// - If a tool handler returns a serde struct (object/array), `to_value`
//   produces a JSON object/array. We render it as pretty-printed JSON in
//   `content[0].text` AND attach the structured value as
//   `structuredContent` so MCP clients can choose either form.
//
// - If a tool handler returns a `String`, `to_value` produces
//   `Value::String`. We treat that as the canonical text representation
//   of the tool's output (the git-history tools take this path to mirror
//   brokk-core's XML-style textual output) and emit it verbatim in
//   `content[0].text`, with no `structuredContent`.
//
// The convention is checked here, at the wire boundary, rather than
// expressed in the handler signature. A future tool returning a string
// will automatically get the text-shaped envelope. If a handler returns
// something else that happens to serialize to `Value::String` (e.g. a
// newtype around `String`), that is also fine — it is treated as text.
//
// To break this convention cleanly, introduce a `ToolOutput` enum in
// `searchtools_service` and have `decode_and_run` return it, then match
// on the variant here. Until that refactor, the two layers must keep
// this comment in sync.
fn tool_success_result(structured: Value) -> Value {
    if let Value::String(text) = structured {
        return json!({
            "content": [
                {
                    "type": "text",
                    "text": text,
                }
            ],
            "isError": false,
        });
    }
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
