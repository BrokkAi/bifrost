use crate::mcp_common::{McpRenderOptions, run_stdio_server, tool_descriptor};
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
    let spec = crate::mcp_registry::resolve_server_spec("diff")?;
    run_stdio_server(Some(root), render_options, &spec, None)
}

pub(crate) fn diff_tool_descriptors() -> Vec<Value> {
    vec![
        tool_descriptor(
            "analyze_diff",
            "Diff two endpoints and return Bifrost-resolved semantic patch effects: changed files with `git diff --numstat` insertion/deletion counts, symbols edited (one record naming the symbol at both endpoints, with the old and new lines each hunk touched), introduced, deleted, moved or resignatured, dependency symbols, import changes, and large-callsite truncation notices. Every reported symbol carries `is_test`. Call-edge changes arrive already attributed to the symbol that makes the calls: an edited or moved record carries `added_calls` and `removed_calls`, an introduced record carries `calls`, and a deleted record carries `called`; `unattributed_call_edge_changes` holds only the edges whose caller is no patch symbol. A move that renames a symbol is not itself a call-edge change, because the preimage graph is compared under the postimage names. An explicit endpoint accepts a commit-ish or tree-ish; commit resolution wins when a spelling can resolve to either. Omit both parameters to compare the merge base of HEAD and the default branch against the live working tree; the default branch comes from origin/HEAD, with HEAD as the fallback when that symbolic ref is unavailable. With `target` alone, a commit compares against its first parent; a tree-only target is rejected because a tree has no parent, so provide `base`. Endpoint labels report a full commit hash or `tree:<full-oid>`. When both endpoints are immutable commits or trees, comparison ignores the live working tree, index, and `.gitattributes`. Objects available only in a snapshot store require the host to launch Bifrost with `--diff-snapshot-object-dir`; this tool never accepts an object-store filesystem path argument.",
            endpoint_schema(json!({
                "include_tests": {
                    "type": "boolean",
                    "default": true,
                    "description": "Include symbols and call edges from detected test files."
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
            "Score how hard a revision range makes future maintenance, as a deterministic vector of raw named features. Four groups plus `excluded`; NO weights and NO single score -- no validated weighting exists, so a consumer combines these itself. `geometry`: counts of symbols edited/introduced/deleted/moved/resignatured, production and test files changed, distinct directories, insertions/deletions, `edit_clusters` (connected components over changed production files, where two connect when they share a directory or one imports the other in the target revision), and mean/max pairwise directory distance (components up plus down between those files' directories). `coordination`: external caller sites per signature change (reference sites in the target revision lying in files this diff did not touch), added and removed call-edge weight, `unattributed_call_edge_changes` as an opacity signal, and edited symbols whose signature metadata publishes `dispatch_extensibility: open`. `verification`: changed production symbols with zero direct test reference -- SYMBOL-LEVEL AND NON-TRANSITIVE, meaning no reference site for that exact symbol lies in a test file or test region. A symbol a test reaches only through an intermediate is still reported here; this is not coverage. `baseline`: cognitive complexity over the before and after sides of the edited symbol pairs, its delta, and the maximum after-side value, for comparison rather than as a verdict. `excluded` names the binary and unparseable changed files no feature could measure, and `verification.unresolved_symbols` names symbols whose reference scan did not complete, so nothing is dropped silently. Endpoint resolution is identical to analyze_diff. Test symbols and edges are always in scope because verification needs them. Builds an analyzer over the WHOLE target revision, not just changed files, because who calls a changed symbol is unanswerable from the diff's own files; expect the cost of a cold whole-repository analysis.",
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
