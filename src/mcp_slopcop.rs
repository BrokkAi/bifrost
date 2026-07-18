use crate::mcp_common::{
    McpRenderOptions, WeightThreshold, run_stdio_server, tool_descriptor, weight_knob_descriptor,
};
use serde_json::{Value, json};
use std::path::PathBuf;

pub const SLOPCOP_TOOL_NAMES: &[&str] = &[
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
    "analyze_commit",
];

pub fn run_slopcop_stdio_server(
    root: PathBuf,
    render_options: McpRenderOptions,
) -> Result<(), String> {
    let spec = crate::mcp_registry::resolve_server_spec("slopcop")?;
    run_stdio_server(root, render_options, &spec)
}

pub(crate) fn slopcop_tool_descriptors() -> Vec<Value> {
    vec![
        tool_descriptor(
            "compute_cyclomatic_complexity",
            "Compute heuristic cyclomatic complexity per function/method in the given files; flag those exceeding a threshold. Heuristic counts a base of 1 plus each `if/while/for/switch/case/catch` keyword and each `&&`/`||`/`?` operator in the source.",
            json!({
                "type": "object",
                "properties": {
                    "file_paths": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Project-relative paths of files to analyze, or absolute paths inside the active workspace."
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
                        "description": "Project-relative paths of files to analyze, or absolute paths inside the active workspace."
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
                        "description": "Project-relative paths of files to analyze, or absolute paths inside the active workspace."
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
                        "description": "Project-relative paths of files to analyze, or absolute paths inside the active workspace."
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
        tool_descriptor(
            "analyze_git_hotspots",
            "Git churn and complexity hotspots: correlates recent commit activity with cyclomatic complexity per file. Bounded to control context size: use max_files and max_commits, and an optional time window (since_days or ISO instants). Returns a compact markdown summary.",
            json!({
                "type": "object",
                "properties": {
                    "since_days": {
                        "type": "integer",
                        "default": 7,
                        "description": "Days back from now for the window start when since_iso is empty; values <= 0 default to 7."
                    },
                    "since_iso": {
                        "type": "string",
                        "description": "Optional ISO-8601 start instant; when non-blank, overrides since_days."
                    },
                    "until_iso": {
                        "type": "string",
                        "description": "Optional ISO-8601 exclusive end instant; empty means no upper bound."
                    },
                    "max_commits": {
                        "type": "integer",
                        "default": 500,
                        "description": "Maximum commits to walk; values <= 0 default to 500; hard cap 5000."
                    },
                    "max_files": {
                        "type": "integer",
                        "default": 75,
                        "description": "Maximum files to return (top by churn); values <= 0 default to 75; hard cap 500."
                    }
                }
            }),
        ),
        tool_descriptor(
            "report_test_assertion_smells",
            "Detects low-value or brittle Java test assertion smells using weighted heuristics. Uses test detection as a fast filter, then scores missing assertions, tautologies, constant-truth checks, constant-equality checks, shallow assertions, oversized literals, and anonymous test doubles. Output format matches the brokk-core MCP byte-for-byte.",
            json!({
                "type": "object",
                "properties": {
                    "file_paths": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Project-relative paths of files to analyze, or absolute paths inside the active workspace."
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
                    "no_assertion_weight": {
                        "type": "integer",
                        "description": "Weight for tests with no assertion-equivalent calls; values < 0 use the brokk default (5)."
                    },
                    "tautological_assertion_weight": {
                        "type": "integer",
                        "description": "Weight for self-comparison or tautological assertions; values < 0 use the brokk default (6)."
                    },
                    "constant_truth_weight": {
                        "type": "integer",
                        "description": "Weight for constant-truth assertions such as assertTrue(true); values < 0 use the brokk default (4)."
                    },
                    "constant_equality_weight": {
                        "type": "integer",
                        "description": "Weight for constant-equality assertions such as assertEquals(1, 1); values < 0 use the brokk default (4)."
                    },
                    "nullness_only_weight": {
                        "type": "integer",
                        "description": "Weight for nullness-only assertions; values < 0 use the brokk default (2)."
                    },
                    "shallow_assertion_only_weight": {
                        "type": "integer",
                        "description": "Weight for tests whose assertions are all shallow; values < 0 use the brokk default (2)."
                    },
                    "overspecified_literal_weight": {
                        "type": "integer",
                        "description": "Weight for exact large literals in assertions; values < 0 use the brokk default (2)."
                    },
                    "anonymous_test_double_weight": {
                        "type": "integer",
                        "description": "Weight for inline anonymous test doubles; values < 0 use the brokk default (3)."
                    },
                    "repeated_anonymous_test_double_weight": {
                        "type": "integer",
                        "description": "Weight for repeated anonymous test-double shapes in one file; values < 0 use the brokk default (5)."
                    },
                    "meaningful_assertion_credit": {
                        "type": "integer",
                        "description": "Score credit subtracted per meaningful assertion; values < 0 use the brokk default (1)."
                    },
                    "meaningful_assertion_credit_cap": {
                        "type": "integer",
                        "description": "Maximum meaningful assertions that earn credit; values < 0 use the brokk default (4)."
                    },
                    "large_literal_length_threshold": {
                        "type": "integer",
                        "description": "Literal length considered large enough to review; values < 0 use the brokk default (120)."
                    }
                },
                "required": ["file_paths"]
            }),
        ),
        tool_descriptor(
            "report_structural_clone_smells",
            "Detects suspicious structural clones using token shingles plus Java AST refinement. Uses analyzer-provided clone smells for high-recall triage. Output format matches the brokk-core MCP byte-for-byte.",
            json!({
                "type": "object",
                "properties": {
                    "file_paths": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Project-relative paths of files to analyze, or absolute paths inside the active workspace."
                    },
                    "min_score": {
                        "type": "integer",
                        "default": 60,
                        "description": "Minimum score to include a finding; values <= 0 default to the brokk clone threshold (60)."
                    },
                    "min_normalized_tokens": {
                        "type": "integer",
                        "description": "Minimum normalized token count for a clone candidate; values <= 0 use the brokk default (12)."
                    },
                    "shingle_size": {
                        "type": "integer",
                        "description": "Token shingle size; values <= 0 use the brokk default (2)."
                    },
                    "min_shared_shingles": {
                        "type": "integer",
                        "description": "Minimum shared shingles before similarity is considered; values <= 0 use the brokk default (3)."
                    },
                    "ast_similarity_percent": {
                        "type": "integer",
                        "description": "Minimum AST refinement similarity; values <= 0 use the brokk default (70)."
                    },
                    "max_findings": {
                        "type": "integer",
                        "default": 80,
                        "description": "Maximum findings to emit; values <= 0 default to 80."
                    }
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
                        "description": "Project-relative paths of files to analyze, or absolute paths inside the active workspace."
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
            "report_dead_code_and_unused_abstraction_smells",
            "Detects likely dead Rust declarations and one-call abstractions using tree-sitter-backed usage queries. The handler is intentionally conservative: ambiguous results, candidate truncation, and usage-cap guardrails are surfaced as skipped evidence instead of findings.",
            json!({
                "type": "object",
                "properties": {
                    "file_paths": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Project-relative paths of files to analyze, or absolute paths inside the active workspace."
                    },
                    "fq_names": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Optional fully qualified Rust symbols to analyze; when omitted the tool discovers candidates from file_paths."
                    },
                    "min_score": {
                        "type": "integer",
                        "default": 8,
                        "description": "Minimum score to include a finding; values <= 0 default to 8."
                    },
                    "max_findings": {
                        "type": "integer",
                        "default": 40,
                        "description": "Maximum findings to emit; values <= 0 default to 40."
                    },
                    "max_input_files": {
                        "type": "integer",
                        "default": 25,
                        "description": "Maximum existing files to scan for candidate declarations; values <= 0 default to 25."
                    },
                    "max_candidate_symbols": {
                        "type": "integer",
                        "default": 200,
                        "description": "Maximum candidate symbols to analyze; values <= 0 default to 200."
                    },
                    "max_usage_candidate_files": {
                        "type": "integer",
                        "default": 1000,
                        "description": "Maximum candidate files per symbol usage query; values <= 0 default to 1000."
                    },
                    "max_usages_per_symbol": {
                        "type": "integer",
                        "default": 100,
                        "description": "Maximum usage hits per symbol before the guardrail returns an inconclusive skip; values <= 0 default to 100."
                    }
                },
                "required": ["file_paths"]
            }),
        ),
        tool_descriptor(
            "report_secret_like_code",
            "Scans non-test text files for secret-looking strings, including current/default-branch files and git history. Findings are heuristic and redacted for downstream LLM triage. Use maxFindings/maxCommits to bound output and work.",
            json!({
                "type": "object",
                "properties": {
                    "max_findings": {
                        "type": "integer",
                        "default": 100,
                        "description": "Maximum findings to emit; values <= 0 default to 100."
                    },
                    "max_commits": {
                        "type": "integer",
                        "default": 2000,
                        "description": "Maximum commits to walk from HEAD; values <= 0 default to 2000."
                    },
                    "include_history_only": {
                        "type": "boolean",
                        "default": false,
                        "description": "Include findings that only appear in history and are not present in the current/default branch."
                    },
                    "include_low_confidence": {
                        "type": "boolean",
                        "default": false,
                        "description": "Include lower-confidence short credential-like assignments."
                    }
                }
            }),
        ),
        tool_descriptor(
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
        ),
    ]
}
