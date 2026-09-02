---
title: MCP Server
description: Run Bifrost as a stdio MCP server for code-intelligence tools.
---

Bifrost can run as a stdio MCP server. For a manual configuration, pass an explicit workspace root so the host analyzes the intended repository. For a coding agent that should navigate symbols and run structural queries, use the same query-capable composition as the packaged Bifrost plugins:

```bash
bifrost --root /path/to/project --mcp "symbol|extended"
```

Use `--mcp core` for the standard navigation, workspace, and diff-review surface without `query_code`. The chosen toolset controls whether an agent can query code.

## Tool Discovery Metadata

Bifrost uses only standard MCP metadata for tool discovery. It does not provide a separate tool-search method.

The initialize result contains routing instructions for the tools selected at startup. The first 512 characters contain the general routing guidance.

Each tool has a specific name, description, and input schema. Server instructions and tool descriptions contain no more than 2,000 characters.

The tool catalog stays fixed for the process lifetime. Therefore, Bifrost does not advertise `tools.listChanged` or send tool-list change notifications.

Hosts can use this metadata in different ways. Codex and Claude Code use it for deferred discovery.

Oh My Pi adds server instructions to its model prompt. The native Bifrost Pi extension forwards the same instructions itself.

Root and nested `.bifrostignore` files exclude matching tracked or untracked
files from code intelligence without hiding them from text-level tools
(`find_files_containing`, `search_file_contents`, `get_file_contents`).
Live sessions re-analyze when this
configuration changes. See [Workspace Scope](/workspace-scope/) for the full
contract.

## Semantic-pack activation

At workspace bind, MCP activates semantic packs through the same optional
`.bifrost/packs.json` contract used by the CLI and LSP hosts. An absent document
selects compatible packs from every ecosystem serving a language present in the
workspace. A configured document selects its named `ecosystems`; an empty
array explicitly disables dependency-pack activation. An omitted `catalog` is
ephemeral, while a configured catalog must be workspace-relative. Activation
through the generic catalog contract does not download packs or dependencies.
Compatibility and `review_required` gates remain authoritative, and `enable`
names the reviewed packs permitted by the workspace. The released
`brokk-bifrost` facade separately opts into fetching the immutable matching
public release bundle only for an exact generated production miss; set
`BIFROST_SEMANTIC_PACK_DOWNLOAD=off` to disable that path.

Activation is owned by the bound workspace generation and is reused by
`run_policy`; the policy result retains the shared activation review. Reports
identify `default`, `configured`, or `disabled` mode and the individual
selected, missing, incompatible, version-mismatched, rejected, or incomplete
decisions, so failed or unavailable activation cannot appear as a clean
negative.

## Query and RQL Availability

RQL is the [Rune Query Language](/rune-query-language/), a human-friendly syntax that compiles to canonical JSON `CodeQuery`. These surfaces do not accept it in the same way:

| Configuration or surface | `query_code` | Inline JSON | Inline RQL | Saved `.rql` |
| --- | --- | --- | --- | --- |
| MCP `core` | No | No | No | No |
| MCP `symbol\|extended` | Yes | Yes | No | Yes, through `query_file` |
| MCP `searchtools` | Yes | Yes | No | Yes, through `query_file` |
| CLI | Yes | `--tool query_code` | REPL | `--query-file` |
| VS Code RQL Play action | Separate LSP path | No | Yes, including unsaved text | Yes |

For MCP, call `query_code` with either inline canonical JSON fields or one `query_file` field naming a workspace-relative `.rql` or `.json` file. `query_file` is exclusive: filters, limits, execution mode, and other query fields must be inside the referenced file. MCP never accepts raw inline RQL text. Inline JSON can set `execution_mode` to `explain` or `profile`; a saved RQL file can use the equivalent wrappers. The versioned response contracts are documented under [Explain and Profile CodeQuery](/code-query-explain-profile/).

The `--mcp` argument accepts ordered toolset compositions. Combine toolsets with `|`, for example:

```bash
bifrost --root /path/to/project --mcp "symbol|workspace"
bifrost --root /path/to/project --mcp "text|extended"
```

The no-argument compatibility command, `bifrost`, uses the current working directory and the `searchtools` toolset. An explicit `bifrost --mcp <toolsets>` command without `--root` starts unbound and asks a roots-capable MCP client for `roots/list` when a tool call first needs a workspace. It selects the first usable local filesystem root in client order. Asking from inside the call that needs the answer is deliberate. The answer is consumed by that request, so a client can answer and immediately call a tool. Clients can send `notifications/roots/list_changed` to replace the root. Bifrost revokes the old root immediately and remains unbound until a new list is accepted. A root that the client supersedes while the request is still in flight is discarded rather than bound.

Current Codex does not advertise standard roots. For any rootless connection whose client did not advertise roots, Bifrost instead advertises the experimental `codex/sandbox-state-meta` capability. A compatible client may respond by attaching the active turn's canonical `sandboxCwd` file URI to every analyzer tool call; current Codex does so. Bifrost treats that per-call value as the current scope: a missing, invalid, or changed value revokes the previous metadata-derived workspace before the call fails or binds the replacement. A client that supports neither roots nor this negotiated extension remains unbound and receives an actionable error rather than analysis of process cwd.

## Protocol Revisions

Bifrost speaks MCP through [`rmcp`](https://github.com/modelcontextprotocol/rust-sdk), the official Rust SDK. It accepts every revision that SDK knows, including `2025-11-25` and `2026-07-28`. The negotiated revision is whatever the client asks for.

## Progress

A tool call that carries a `progressToken` in its `_meta` receives `notifications/progress` on its own request as the call moves through its phases; a call without the token receives none. Progress is truthful and low volume: at most one notification per phase the call actually enters -- `waiting for workspace readiness`, `waiting for analyzer admission`, `executing <tool>`, and `cancelling <tool>` when the request budget expires -- so a call sends at most four. The token is echoed exactly as supplied, string or number, and concurrent calls with distinct tokens never share notifications.

All phases are currently indeterminate: the `progress` value is a per-request monotonically increasing counter and `total` is never set, because none of the phases has a known item count -- the analyzer does not expose per-item counters at the MCP boundary, and Bifrost does not invent percentages. Workspace-mutating tools such as `activate_workspace` skip the readiness and admission phases because they take neither wait; `list_policies` reads only the built-in policy pack and reports no progress. An MRTR roots-activation round reports no progress either: it is an answer to the call, not a phase of an executing one. For work that may outlive the request or the connection, progress is the wrong tool; use the MCP Tasks support described below.

## Tasks

Bifrost implements the MCP Tasks extension (`io.modelcontextprotocol/tasks`, SEP-2663) for explicitly batch-shaped work, and advertises it through both `initialize` and `server/discover`. Exactly one tool is eligible: `run_policy`, whose runtime scales with the whole corpus times the policy count. A `2026-07-28` request that declares the extension in its client capabilities and calls `run_policy` receives a durable task handle (`resultType: "task"`) instead of blocking on the result; the client polls `tasks/get` until the task is terminal, and the terminal response embeds exactly the `CallToolResult` a synchronous call would have produced, including the structured policy report and the `run_policy` correlation id. `tasks/cancel` requests cooperative cancellation and the task settles as `cancelled`. Clients that do not declare the extension -- and legacy `2025-11-25` clients even when they do -- keep the fully synchronous behavior and never see a task-shaped result. Navigation tools are deliberately ineligible: waiting out cold initialization is the intended readiness model, not a reason to hand back a task handle.

Task execution runs under the same discipline as a synchronous call: it waits for workspace readiness, queues for a real analyzer slot, and is bound to the workspace authorization it was created under. If the client rebinds or revokes its workspace, running task work is cancelled promptly and every outstanding handle is refused from then on -- a task can never carry results across a workspace boundary. Tasks live for ten minutes by default (`BIFROST_MCP_TASK_TTL_MS` overrides this, in whole milliseconds); the TTL is also the execution deadline, so an expired task is marked `failed` at the same moment its analyzer work is cooperatively cancelled, and its terminal result stays pollable for one further TTL window before eviction. The advertised polling interval is one second, and at most eight tasks may be live at once.

The durability boundary is the process. Bifrost's MCP transport is stdio, so one connection is one process: a task survives the request that created it, which is the point, but not a process restart. If a launcher restarts Bifrost, every handle is gone and polling it fails with an unknown-task error. Progress notifications (above) remain the lighter mechanism for bounded interactive requests; tasks are for work that may legitimately outlive the request.

## Request budget

Analyzer-backed MCP requests have a five-second wall-clock budget by default. Set
`BIFROST_MCP_REQUEST_BUDGET_SECS` to a whole number from 5 through 60 to change
that process-wide cap; benchmark sessions set it to 60 seconds. Expired rmcp
requests return promptly while their cancelled analyzer work retains its slot
until it stops, so repeated timeouts cannot overcommit the analyzer pool.

A `2026-07-28` client gets three things a `2025-11-25` client does not. `server/discover` answers before any handshake, so a client can inspect Bifrost's capabilities without opening a session. Results carry the `resultType` discriminator. And `tools/list`, `resources/list`, and `resources/read` carry SEP-2549 cache hints: the tool list is `private` for five minutes because it is fixed for the life of the process but differs between servers started in different modes, and the agent-guidance resource is `public` for an hour because it is compiled into the binary. Tool results are never cacheable, because every one depends on the bound workspace and the current contents of its files. A `2025-11-25` client sees none of these fields.

Rootless activation differs by revision because `2026-07-28` removed the post-initialization roots lifecycle. A client on that revision receives an `input_required` result carrying an embedded `roots/list` request, answers it with `inputResponses`, and retries the same tool call; Bifrost validates those roots exactly as it validates a `roots/list` reply, so the echoed `requestState` grants nothing on its own. Only one such round is offered per call.

The two revisions also differ in where negotiation lives, and Bifrost keeps the two models separate. Legacy compatibility means the `2025-11-25` lifecycle is unchanged: a session opens with `initialize` and `notifications/initialized`, that handshake establishes the client's capabilities for the whole connection, and a rootless server acquires its workspace through the server-initiated `roots/list` exchange described above. Stateless execution means a `2026-07-28` client never sends `initialize` at all: it may probe with `server/discover`, and every request carries `io.modelcontextprotocol/protocolVersion` and `io.modelcontextprotocol/clientCapabilities` in its `_meta`. Each such request is validated on its own -- a missing or malformed negotiation key or an unsupported version is refused per request, whatever earlier requests carried -- and a rootless server binds its workspace through the `input_required` roots round above, with the same validation the legacy path applies. No connection-level handshake state is required or consulted for a stateless request. Codex sandbox-state metadata remains a legacy-lifecycle extension: it is negotiated during `initialize` and never binds a workspace for a stateless request.

Explicit `--root` integrations remain authoritative and do not require roots negotiation. The packaged launcher also translates `BIFROST_WORKSPACE_ROOT` into an explicit `--root`. Prefer an explicit root for manual fixed-project configurations. Packaged plugins use client-provided roots or Codex sandbox-state metadata so package-local command resolution stays independent from analyzer scope.

## Immutable Git Snapshot Diffs

An MCP host that captures review snapshots in a private Git object store can
launch Bifrost with `--diff-snapshot-object-dir /path/to/objects`. This trusted
launch setting names a Git `objects` directory; Bifrost resolves it to an
absolute path and rejects a missing or non-directory path at startup. It is not
an MCP tool argument, so an MCP caller cannot choose an arbitrary object-store
filesystem path.

`analyze_diff` accepts commit-ish or tree-ish values for explicit `base` and
`target` endpoints, preferring a commit when a spelling can resolve to either.
Its response labels commits by full hash and trees as `tree:<oid>`. Omitting
both endpoints compares the merge base of `HEAD` and the repository's default
branch against the live working tree, so committed and uncommitted feature-branch
changes are included. Bifrost reads the default branch from the local symbolic
`refs/remotes/origin/HEAD`; when that record is unavailable, it falls back to
`HEAD`. A commit supplied as `target` alone compares against its first parent,
while a tree-only target is rejected because trees have no parents and therefore
needs an explicit `base`. When both endpoints are immutable commits or trees,
Bifrost compares only those snapshots and ignores the live worktree, index, and
`.gitattributes`.
Objects available only in the snapshot store resolve only when the server was
launched with the flag.

`blast_radius` uses the same endpoint rules and trusted snapshot-object
configuration. It identifies callables changed by the diff, seeds every
analyzer-visible changed target file, and follows incoming edges in Bifrost's
structured direct file-dependency graph to suggest reached test files. The
graph includes ordinary imports and language-owned file relations such as Rust
external `mod` declarations. A changed file that contains tests is evidence at
dependency distance zero. Deleted and renamed-away preimages trigger
conditional base-graph recovery; ordinary edits use target state only, so a
removed import edge is not restored from the base.

`analysis.analyzer_changed_test_paths` lists the changed target files that the
target analyzer structurally classified as containing test code. Each listed
path is seeded at dependency distance zero even when presentation compaction
returns a containing directory instead of the exact file. These are file paths,
not runner-specific test identifiers.

Changed callable symbols expose `in_test_context` when a declaration is nested
in structurally attributed test code or lives under a recognized test-tree
path. This contextual flag does not mean the declaration is an individually
runnable test and does not make its file a distance-zero `TestScope`. Test-data
fixtures driven through generated runners or resource metadata require evidence
outside the file-import graph.

From a feature-branch checkout, the useful default CLI invocation is simply:

```bash
bifrost --tool blast_radius
```

The result is file-dependency evidence, not an exhaustive test-impact claim,
individual method-call graph, test-runner identifier map, or runtime coverage
report. `analysis.graph_completion` states only whether Bifrost completed the
selected file graphs; it does not claim that every way a test can depend on a
change is modeled. `analysis.paths_outside_file_graph` lists changed build,
data, documentation, and other non-analyzer paths whose validation the graph
cannot infer. In particular, zero reached tests is not proof that no repository
validation applies when this list is nonempty.

`max_scopes` defaults to 100 and accepts 1 through 1000. When exact reached
files exceed that limit, Bifrost returns deterministic directory scopes
selected to minimize additional analyzer-visible coverage.
`analysis.reached_test_file_count` remains the exact reached-file count, and
directory records include coverage, distance bounds, and up to five sample
reached files. Inspect `analysis.graph_completion`, `paths_outside_file_graph`,
`analyzer_changed_test_paths`, and typed `incomplete_reasons` when interpreting
an empty result. For example,
`compilation_scope_unresolved` means Bifrost preserved proven file-dependency
evidence but could not fully establish a language compilation boundary.

`cyclomatic_complexity` uses the same endpoints and the same heuristic scorer
as the file-oriented `compute_cyclomatic_complexity` tool. It returns functions
introduced or patch-edited by the diff. Introduced functions have a postimage
score; edited functions have preimage and postimage scores plus a signed delta,
including zero-delta edits. Deleted functions and pure moves are omitted.
Structurally detected test code is excluded unless `include_tests` is true.
Changed non-analyzer paths and unresolved analyzer paths are retained in the
result's `analysis` metadata.

`missing_tests` also shares those endpoint rules. It first reverse-walks the
cheap file-dependency graph to obtain the bounded importer closure for each
changed file. It then batches exact declaration-location usage scans inside
that closure and follows enclosing callers back toward test-context code. This
distinguishes an uncalled changed function from a called sibling in the same
file without constructing the bulk whole-workspace usage graph. A fully
exhausted search appears in `missing_functions`; cancelled, incomplete,
unresolved, ambiguous, and unproven searches appear in
`indeterminate_functions`. The result is static reachability evidence, not
runtime coverage.

`score_diff` shares those endpoint rules and returns a deterministic vector of
raw named features describing how hard a revision range makes future
maintenance. It publishes no weights and no single score, because no validated
weighting exists; a consumer combines the features itself. `geometry` counts
changed symbols, files, directories, insertions, deletions, edit clusters, and
pairwise directory distance. `coordination` counts external caller sites per
signature change, added and removed call-edge weight,
`unattributed_call_edge_changes`, and edited symbols that publish
`dispatch_extensibility: open`. `verification` lists changed production symbols
with no direct test reference; this is a symbol-level, non-transitive signal,
not coverage, so a symbol that a test reaches only through an intermediate is
still listed. `baseline` reports cognitive complexity before and after the
edited symbol pairs. `excluded` names the binary and unparseable changed files
no feature could measure, and `verification.unresolved_symbols` names symbols
whose reference scan did not complete, so nothing is dropped silently. Test
symbols and edges are always in scope because verification needs them. The tool
builds an analyzer over the whole target revision rather than the changed files
alone, because the diff's own files cannot answer who calls a changed symbol;
expect the cost of a cold whole-repository analysis.

When standard roots or sandbox-state metadata controls a rootless connection, `activate_workspace` is unavailable even if the selected toolset exposes it. Change the workspace through the MCP host instead. This prevents a tool call from widening the client-approved scope; explicit-root integrations retain the normal workspace activation behavior.

## Toolsets

| Toolset | Tools |
| --- | --- |
| `symbol` | `search_symbols`, `get_symbol_sources`, `get_summaries`, mode-specific usage and definition lookup tools, `get_type_by_location`, `rename_symbol`, `usage_graph` |
| `workspace` | `refresh`, `activate_workspace`, `get_active_workspace` |
| `diff` | `analyze_diff`, `blast_radius`, `cyclomatic_complexity`, `missing_tests`, `score_diff` |
| `extended` | `query_code`, `list_policies`, `run_policy`, `explain_policy`, `get_symbol_locations`, `get_symbol_ancestors`, `most_relevant_files` |
| `text` | `get_file_contents`, `search_file_contents`, `find_files_containing` |
| `slopcop` | `compute_cyclomatic_complexity`, `compute_cognitive_complexity`, `report_comment_density_for_code_unit`, `report_exception_handling_smells`, `report_comment_density_for_files`, `analyze_git_hotspots`, `report_test_assertion_smells`, `report_structural_clone_smells`, `report_long_method_and_god_object_smells`, `report_dead_code_and_unused_abstraction_smells`, `report_secret_like_code` |
| `cli` | `classify_test_files` |

`core` expands to `symbol|workspace|diff`. `searchtools` expands to every toolset above in registry order: `symbol|workspace|diff|extended|text|slopcop|cli`.

With line numbers enabled, `symbol` advertises `scan_usages_by_location`, `get_declarations_by_location`, and `get_definitions_by_location`. With `--no-line-numbers`, it instead advertises `scan_usages_by_reference` and `get_definitions_by_reference`; there is no declaration-by-reference tool.

Location navigation keeps declarations and definitions distinct. Both tools accept `{"references":[{"path":"src/file.ext","line":1,"column":1}]}`. Declaration results contain `operation: "declaration"` and a `declarations` array; definition results contain `operation: "definition"` and a `definitions` array. An empty operation-specific selection reports `no_declaration` or `no_definition`, and more than one selected target reports `ambiguous`. Declaration navigation prefers contracts such as C++ prototypes, Java interface methods, and Rust trait items, while definition navigation selects concrete bodies or implementation items. Entities without a separate body remain valid for both operations.

Exact MCP source positions use 1-based lines and 1-based Unicode code-point columns, with an exclusive end position. Individual `scan_usages` hits expose `line`, `column`, `end_line`, and `end_column`. Definition, declaration, and type-definition candidates expose `start_line`, `start_column`, `end_line`, and `end_column`. Column fields are omitted when a row is an aggregate or Bifrost cannot prove an exact token span; byte offsets are never part of the public result.

`searchtools` is the compatibility mode and exposes the full current union of MCP tools in toolset order. Use `symbol|extended` for the packaged coding-agent surface, or a smaller composition such as `symbol|workspace` when a host should see fewer tools.

Pass `--no-line-numbers` to remove rendered line and line-range prefixes from MCP text previews while keeping `structuredContent` unchanged.

## Discover and Run Policies

The `extended` toolset's read-only `list_policies` tool returns the deterministic
built-in pack catalog without constructing an analyzer. `run_policy` evaluates any
non-empty union of built-in selectors and workspace-relative `.rqlp` files:

```json
{
  "policy_packs": ["bifrost.code-smells"],
  "policy_categories": ["performance"],
  "policy_ids": ["bifrost.correctness.dynamic-evaluation"],
  "policy_files": [".bifrost/policies/security.rqlp"],
  "evaluation_date": "2026-07-27",
  "fail_on": "warning"
}
```

The selector arrays form a deduplicated union in catalog order, and
`policy_files` adds explicit workspace roots to the same batch. All arrays are
bounded and reject duplicate entries; unknown selectors are invalid parameters.
The tool never discovers or runs every file under `.bifrost/policies/`. Add
`"suppression_file":"reviews/accepted.json"` for one workspace-relative
override; otherwise it uses `.bifrost/suppressions.json`. The date is required
because the shared policy coordinator does not read the clock.

The structured result contains the canonical schema-5 `report`, a `status` of
`clean`, `finding`, or `unreliable`, and the equivalent `exit_status` value
`0`, `1`, or `2`. MCP itself does not exit for a finding. Evaluation is pinned
to the active immutable workspace snapshot and is cancelled if the client
cancels the request or revokes that workspace. See [Static-Analysis
Policies](/static-analysis-policies/#review-findings-with-exact-suppressions)
for the exact strong-identity and audit contract.

## Workspace Operations

`activate_workspace` lets a host swap the analyzer root mid-session without respawning the subprocess. The path must be absolute and is normalized to the nearest enclosing git root when one exists.

`refresh` forces a full rebuild of the code index. Normal tool calls already apply watcher-detected file changes automatically, so most hosts should keep `refresh` as a manual recovery tool rather than a routine pre-query step.

For MCP tool arguments that name files, directories, or file globs, callers may pass project-relative paths or absolute paths inside the active workspace. Absolute paths outside the active workspace are rejected with an explicit tool error.

For JSON-based MCP hosts, configure Bifrost as a stdio server:

```json
{
  "mcpServers": {
    "bifrost": {
      "command": "/path/to/bifrost",
      "args": ["--root", "/path/to/project", "--mcp", "symbol|extended"]
    }
  }
}
```

Use an absolute binary path if `bifrost` is not on the host's `PATH`. Replace `/path/to/project` with the project root syntax supported by your host, or with an absolute project path.

## Validate Host Integration

Treat installation, tool discovery, workspace binding, and individual toolsets
as separate checks. A plugin listed as installed does not prove that the current
agent session loaded its MCP server, and a prompt answered through ordinary file
reading does not prove that Bifrost ran.

After installing or changing Bifrost or its MCP configuration, restart or
reload the host as its integration page requires, then open a new agent session.
Run these checks in order:

1. Confirm the host lists the expected Bifrost server and that the active
   session or Agent profile exposes the expected tool schemas.
2. Call a Bifrost symbol tool for a declaration known to exist only in the
   active workspace. Forbid shell search and direct file reading in the smoke
   prompt.
3. Verify that the MCP result contains the expected project-relative source
   path. Reject results under an installed plugin, binary, or launcher cache.
4. Confirm `query_code` is advertised before testing inline JSON or a saved RQL
   file.

Keep the exact host tool event or structured MCP result as evidence. A model's
summary without the underlying tool result is not enough to distinguish an MCP
call from a fallback. If the symbol call reaches Bifrost but reports an unbound
workspace, inspect the host's explicit root, standard MCP roots, or negotiated
workspace metadata before testing query behavior.

The host-specific pages define how to restart, inspect, or discover tools in
Codex, Claude Code, Cursor, OpenCode, Zed Agent, Amp, and other supported
clients. Use this shared evidence contract without copying one host's lifecycle
or tool-discovery mechanism into another.

## Validate Query Access

After adding or changing MCP configuration, start a fresh agent session. First confirm that the host's advertised Bifrost tools include `query_code`; a successful `get_summaries` call proves symbol navigation, but does not prove query access.

Then run an inline canonical JSON smoke query:

<!-- code-query-test:json:mcp-smoke -->
```json
{"match":{"kind":"declaration"},"limit":1}
```

To prove saved RQL access, check this file into the workspace as `bifrost-smoke.rql`:

<!-- code-query-test:rql:mcp-smoke -->
```lisp
(limit 1 (declaration))
```

Call `query_code` with exactly:

```json
{"query_file":"bifrost-smoke.rql"}
```

Both calls should return a `results` array and a `truncated` field. A workspace with indexed declarations should return one result. If `query_code` is absent, check the configured toolset; if the saved query fails, check that the path is relative to the active workspace and that the agent session started after the configuration change.

Before asking an agent to claim “all callers” or “no matches,” teach it the diagnostic, truncation, proof, and provenance checks in [Agent Result Safety](/agent-result-safety/).

Use the host-specific pages for Pi, Codex, Claude Code, Cursor, OpenCode, Zed
Agent, Amp, and Antigravity setup flows. The intended external manual client is
the official MCP Inspector.
