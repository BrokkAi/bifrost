use crate::mcp_common::{McpRenderOptions, run_named_stdio_server, tool_descriptor};
use serde_json::{Value, json};
use std::path::PathBuf;

pub const DIFF_TOOL_NAMES: &[&str] = &[
    "analyze_diff",
    "blast_radius",
    "cyclomatic_complexity",
    "missing_tests",
    "score_diff",
];

pub fn run_diff_stdio_server(
    root: PathBuf,
    render_options: McpRenderOptions,
) -> Result<(), String> {
    run_named_stdio_server(root, render_options, "diff")
}

pub(crate) fn diff_tool_descriptors() -> Vec<Value> {
    vec![
        tool_descriptor(
            "analyze_diff",
            "Compare Git endpoints and return changed files with insertion/deletion counts, edited/introduced/deleted/moved/resignatured symbols, import changes, dependencies and callsite truncation notices. Symbols carry is_test; edited records name both endpoints and touched old/new lines. Edited/moved records carry added_calls/removed_calls, introduced records calls, and deleted records called. Unattributed edges have no patch-symbol caller. call_edges defaults to changed_lines: resolve reference start lines changed on each side, not whole-caller relationships. Unchanged sites and import-only rebinding outside those lines are omitted. An addition needs a complete base scope; a removal needs a complete target scope. Exact selected deltas refuse ambiguous attribution and uncertain moved correspondence. changed_files retains full-file inventory and incumbent best-effort deltas, including renamed preimage comparisons. omit skips call analysis and leaves its arrays empty; import_changes remains available. call_analysis reports scope, complete/incomplete/omitted status and endpoint reasons. Completeness applies only to the requested inventory. Explicit endpoints accept commits or trees; commit resolution wins. With neither endpoint, compare the merge base of HEAD and the default branch against the live worktree (origin/HEAD selects that branch, falling back to HEAD). With target alone, compare a commit against its first parent; a tree target requires base. Labels are full commit hashes or tree:<oid>. Immutable endpoint comparisons ignore the live worktree, index and .gitattributes. Snapshot-only objects require host configuration --diff-snapshot-object-dir; the tool accepts no object-store path.",
            endpoint_schema(json!({
                "include_tests": {
                    "type": "boolean",
                    "default": true,
                    "description": "Include symbols and call edges from detected test files."
                },
                "call_edges": {
                    "type": "string",
                    "enum": ["changed_lines", "changed_files", "omit"],
                    "default": "changed_lines",
                    "description": "Call-edge inventory: selected changed reference start lines, all declarations in changed files, or omitted."
                }
            })),
        ),
        tool_descriptor(
            "blast_radius",
            "Report test file or directory scopes reached by reverse-walking Bifrost's structured direct file-dependency graph from files changed between Git endpoints. The graph includes ordinary imports and language-owned file relations such as Rust external `mod` declarations. This is file-dependency evidence, not an exhaustive test-impact claim, individual method-call graph, test-runner identifier map, or runtime coverage report. `graph_completion` describes only construction and traversal of that graph. `paths_outside_file_graph` identifies changed build, data, documentation, or other non-analyzer paths whose validation this model cannot infer. Endpoint resolution is identical to analyze_diff: with no endpoints, compare the merge base of HEAD and the default branch against the live worktree; an explicit commit target without a base still compares against its first parent. Distance zero includes changed files that themselves contain structurally detected tests; `analyzer_changed_test_paths` exposes those analyzer-owned file paths even when scopes are coalesced, but they are not runner identifiers. Changed callable symbols use `in_test_context` for contextual test-tree or structural attribution; it does not mean a callable is an individually runnable test or make its file a test scope. Removed or renamed-away dependencies use conditional base-graph recovery; removed import edges between surviving target files remain removed. Directory scopes compact exact reached test files without truncating `reached_test_file_count`.",
            endpoint_schema(json!({
                "max_scopes": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 1000,
                    "default": 100,
                    "description": "Maximum file or directory scopes to return. Exact affected-test count is preserved when directory scopes are coalesced."
                }
            })),
        ),
        tool_descriptor(
            "cyclomatic_complexity",
            "Compare heuristic cyclomatic complexity for functions introduced or patch-edited between Git endpoints. Introduced functions report only their postimage score; edited functions report before and after scores plus a signed delta, including zero-delta edits. Deleted functions and pure moves are omitted. Tests are excluded by default. Scoring is identical to compute_cyclomatic_complexity: base 1 plus `if/while/for/switch/case/catch` and `&&`/`||`/`?`. Endpoint resolution is identical to analyze_diff, including the default worktree comparison and first-parent default for an explicit commit target.",
            endpoint_schema(json!({
                "include_tests": {
                    "type": "boolean",
                    "default": false,
                    "description": "Include functions in structurally detected test code or test-tree paths."
                }
            })),
        ),
        tool_descriptor(
            "missing_tests",
            "Find introduced or behavior-changed production functions for which Bifrost can establish no structured call path from test-context code. The blast-radius file graph is used only to bound each changed file's reverse importer closure; batched exact, location-anchored usage scans then follow enclosing callers within that reduced set. A complete exhausted search appears in `missing_functions`. Cancelled, incomplete, unresolved, ambiguous, or unproven searches appear in `indeterminate_functions` and are never promoted to a confident negative. Deleted functions, pure moves, and test-context functions are omitted. This is static structured reachability, not runtime coverage. Endpoint resolution is identical to analyze_diff, including the default worktree comparison and first-parent default for an explicit commit target.",
            endpoint_schema(json!({})),
        ),
        tool_descriptor(
            "score_diff",
            "Return raw maintenance features in geometry, coordination, verification, baseline and excluded; no weights or aggregate score. geometry counts changed symbols, production/test files, directories, insertions/deletions, edit_clusters (connected changed-production-file components linked by a shared directory or target import), and mean/max directory distance. coordination reports target caller sites outside changed files per signature change, added/removed call-edge weight, unattributed_call_edge_changes and edited symbols with dispatch_extensibility: open. Call analysis retains full changed-file relationships; it does not inherit analyze_diff's changed_lines default. Incomplete full-file deltas remain incumbent best-effort; analyze_diff exposes their call_analysis status. verification counts changed production symbols with zero direct test references: symbol-level and non-transitive, not coverage. Indirectly reached symbols remain in this count. baseline reports before/after cognitive complexity of edited pairs, its delta and maximum after value for comparison, not verdicts. excluded lists binary/unparseable files; verification.unresolved_symbols lists incomplete scans. Endpoint resolution matches analyze_diff. Tests remain in scope for verification; references cover the whole target. Verification retains hot-symbol source lines; incomplete scans stay unresolved. Sessions reuse immutable target analysis and the last complete reference query; the first call may be expensive. Worktree calls reuse complete disk workspaces.",
            endpoint_schema(json!({})),
        ),
    ]
}

fn endpoint_schema(extra_properties: Value) -> Value {
    let mut properties = serde_json::Map::from_iter([
        (
            "base".to_string(),
            json!({
                "type": "string",
                "minLength": 1,
                "description": "Commit-ish or tree-ish before endpoint. Defaults to the first parent of an explicit commit target; with an implicit worktree target, defaults to the merge base of HEAD and the default branch, falling back to HEAD."
            }),
        ),
        (
            "target".to_string(),
            json!({
                "type": "string",
                "minLength": 1,
                "description": "Commit-ish or tree-ish after endpoint. Omit for the live worktree. A tree-only target requires an explicit base."
            }),
        ),
    ]);
    let extra = extra_properties
        .as_object()
        .expect("diff descriptor extra properties are an object");
    properties.extend(extra.clone());
    json!({
        "type": "object",
        "properties": properties,
    })
}
