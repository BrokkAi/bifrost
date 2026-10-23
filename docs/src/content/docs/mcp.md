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

Each tool has a name, a description, an input schema, and annotations. Up to nine tools also publish a JSON Schema 2020-12 `outputSchema` for their `structuredContent`. The count depends on the toolsets and mode. Every tool is annotated `readOnlyHint: true`, except `refresh` and `activate_workspace`. Server instructions and tool descriptions contain no more than 2,000 characters.

The `initialize` result carries the exact build identity of the binary in `_meta["io.bifrost/build-identity"]`. The server publishes one resource, `bifrost://agent-guidance/agents.md`; see [Agent Instructions](/agents/).

The tool catalog stays fixed for the process lifetime. Therefore, Bifrost does not advertise `tools.listChanged` or send tool-list change notifications.

[MCP Tools Reference](/reference/mcp-tools/) lists every tool with its arguments, outputs, and limits, and names the tools that publish an output schema. `bifrost --help <tool>` prints one tool's description and input schema.

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
`.bifrost/packs.json` contract used by the CLI. An absent document
selects compatible packs from every ecosystem serving a language present in the
workspace. A configured document selects its named `ecosystems`; an empty
array explicitly disables dependency-pack activation. An omitted `catalog`
follows the analyzer's persistence settings and host cache overrides, while a
configured catalog must be workspace-relative. Activation
through the generic catalog contract does not download packs or dependencies.
Compatibility and `review_required` gates remain authoritative, and `enable`
names the reviewed packs permitted by the workspace. Open semantic packs and
policy rules are distributed by
[Bifrost-packs](https://github.com/BrokkAi/bifrost-packs), independently from
engine releases. When a `bifrost` MCP or policy command starts without an
explicit `BIFROST_OPEN_SEMANTIC_PACK_BUNDLE` or
`BIFROST_POLICY_PACK_ROOT`, the binary selects, verifies, and caches a
compatible open release pair before catalog activation. This acquisition runs
outside the analysis library; local dependency generation still uses exact
artifact identity.

Activation is owned by the bound workspace generation and serves the session's
query tools. `run_policy` does not borrow it. Like the CLI, it evaluates on a
policy workspace built over the session's files under the policy analyzer
configuration, and activates the shipped models, the repository's reviewed
models and its packs document itself, so an MCP policy report, and the policy
units it publishes to the repository's analyzer cache, agree with the CLI's.
The policy result carries that activation's review. Reports
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
| VS Code extension RQL Play action | Through the separate language server | No | Yes, including unsaved text | Yes |

RQL text is the single authoring syntax. Generate canonical JSON from a decoded `CodeQuery` (for example, with REPL `:json`) for machine calls. For MCP, call `query_code` with either inline canonical JSON fields or one `query_file` field naming a workspace-relative `.rql` or `.json` file. `query_file` is exclusive: filters, limits, execution mode, and other query fields must be inside the referenced file. MCP never accepts raw inline RQL text. Inline JSON can set `execution_mode` to `explain` or `profile`; a saved RQL file can use the equivalent wrappers. The versioned response contracts are documented under [Explain and Profile CodeQuery](/code-query-explain-profile/).

The `--mcp` argument accepts ordered toolset compositions. Combine toolsets with `|`, for example:

```bash
bifrost --root /path/to/project --mcp "symbol|workspace"
bifrost --root /path/to/project --mcp "text|extended"
```

The no-argument compatibility command, `bifrost`, uses the current working directory and the `searchtools` toolset. An explicit `bifrost --mcp <toolsets>` command without `--root` starts unbound and asks a roots-capable MCP client for `roots/list` when a tool call first needs a workspace. It selects the first usable local filesystem root in client order. Asking from inside the call that needs the answer is deliberate. The answer is consumed by that request, so a client can answer and immediately call a tool. Clients can send `notifications/roots/list_changed` to replace the root. Bifrost revokes the old root immediately and remains unbound until a new list is accepted. A root that the client supersedes while the request is still in flight is discarded rather than bound.

Current Codex does not advertise standard roots. For any rootless connection whose client did not advertise roots, Bifrost instead advertises the experimental `codex/sandbox-state-meta` capability. A compatible client may respond by attaching the active turn's canonical `sandboxCwd` file URI to every analyzer tool call; current Codex does so. Bifrost treats that per-call value as the current scope: a missing, invalid, or changed value revokes the previous metadata-derived workspace before the call fails or binds the replacement. A client that supports neither roots nor this negotiated extension remains unbound and receives an actionable error rather than analysis of process cwd.

Explicit `--root` integrations remain authoritative and do not require roots negotiation. The `bifrost` binary does not read `BIFROST_WORKSPACE_ROOT`; the packaged launcher reads it and passes it to Bifrost as `--root`. Prefer an explicit root for manual fixed-project configurations. Packaged plugins use client-provided roots or Codex sandbox-state metadata so package-local command resolution stays independent from analyzer scope.

## Named workspaces

One server can serve several fixed workspaces. Give each workspace a name with
a repeatable `--workspace NAME=PATH` flag:

```bash
bifrost --mcp "symbol|extended" --workspace api=/src/api --workspace web=/src/web
```

In this mode:

- Every tool except `list_policies` has a required `workspace` argument. Its
  schema is a string enum of the configured names. The agent sets it to the
  workspace that contains the code for that call.
- `activate_workspace` and `get_active_workspace` are not advertised. The set
  of workspaces is fixed for the life of the process.
- The server instructions add one sentence that tells the agent to set the
  `workspace` argument.
- Bifrost initializes the first workspace at startup. It initializes each other
  workspace on its first use, so the first call to that workspace waits for
  its build.

Rules for the flag:

- `--workspace` requires `--mcp`. It cannot be combined with `--root` or
  `--diff-snapshot-object-dir`.
- A name starts with an ASCII letter or digit and contains only letters,
  digits, `.`, `_`, and `-`.
- Each path must be an existing directory. Bifrost resolves symbolic links.
- Duplicate names and duplicate paths are startup errors.

## Protocol Revisions

Bifrost speaks MCP through [`rmcp`](https://github.com/modelcontextprotocol/rust-sdk), the official Rust SDK. It supports two revisions: `2025-11-25` and `2026-07-28`. An `initialize` request always gets `2025-11-25` in reply, whatever revision the client asks for. A `2026-07-28` client does not send `initialize`. It names the revision in the `_meta` of each request, and `server/discover` lists both supported revisions.

A `2026-07-28` client gets three things a `2025-11-25` client does not. `server/discover` answers before any handshake, so a client can inspect Bifrost's capabilities without opening a session. Results carry the `resultType` discriminator. And `tools/list`, `resources/list`, and `resources/read` carry SEP-2549 cache hints: the tool list is `private` for five minutes because it is fixed for the life of the process but differs between servers started in different modes, and the agent-guidance resource is `public` for an hour because it is compiled into the binary. Tool results are never cacheable, because every one depends on the bound workspace and the current contents of its files. A `2025-11-25` client sees none of these fields.

Rootless activation differs by revision because `2026-07-28` removed the post-initialization roots lifecycle. A client on that revision receives an `input_required` result carrying an embedded `roots/list` request, answers it with `inputResponses`, and retries the same tool call; Bifrost validates those roots exactly as it validates a `roots/list` reply, so the echoed `requestState` grants nothing on its own. Only one such round is offered per call.

The two revisions also differ in where negotiation lives, and Bifrost keeps the two models separate. Legacy compatibility means the `2025-11-25` lifecycle is unchanged: a session opens with `initialize` and `notifications/initialized`, that handshake establishes the client's capabilities for the whole connection, and a rootless server acquires its workspace through the server-initiated `roots/list` exchange described above. Stateless execution means a `2026-07-28` client never sends `initialize` at all: it may probe with `server/discover`, and every request carries `io.modelcontextprotocol/protocolVersion` and `io.modelcontextprotocol/clientCapabilities` in its `_meta`. Each such request is validated on its own -- a missing or malformed negotiation key or an unsupported version is refused per request, whatever earlier requests carried -- and a rootless server binds its workspace through the `input_required` roots round above, with the same validation the legacy path applies. No connection-level handshake state is required or consulted for a stateless request. Codex sandbox-state metadata remains a legacy-lifecycle extension: it is negotiated during `initialize` and never binds a workspace for a stateless request.

## Progress

A tool call that carries a `progressToken` in its `_meta` receives `notifications/progress`; a call without the token receives none. The token is echoed exactly, string or number. The top-level `progress` is an increasing notification ordinal and `total` is absent. Neither is a file count or a percentage. Phase messages describe readiness, analyzer admission, execution, analyzer phases, and cancellation.

Workspace indexing observations use the same notification with `message: "workspace indexing"` and a structured payload at `params._meta["io.bifrost/workspace-build"]`:

```json
{
  "generation": 1,
  "workspace_generation": 1,
  "revision": 12,
  "status": "running",
  "request_id": 2,
  "counters": [
    { "language": "Python", "phase": "parse", "unit": "blobs", "completed": 7, "total": 24 }
  ],
  "intermediate": [
    { "language": "Python", "phase": "parse", "unit": "blobs", "completed": 1, "total": 24 }
  ]
}
```

`generation` identifies one build or refresh within this server process. `workspace_generation` identifies the authorized workspace binding, and `revision` changes as observations arrive. A retry or refresh starts a new build generation and clears its counters. `status` is `running`, `completed`, or `failed`; completion means the analyzer build completed, not that the requesting tool completed. A late subscriber waiting for startup can immediately receive the latest completed build snapshot. A warm refresh emits only its new generation and does not replay previous parse counters. Task observations also carry `task_id` while retaining the initiating `request_id` and progress token. When a readiness wait or execution budget ends, `request_status` distinguishes cancellation or failure of that wait from the shared build's status. A cancelled waiter does not cancel another request's shared cold build. MCP cancellation may suppress the cancelled request's final notification and response; in that case the client's own cancellation ends its stream.

Counters copy real analyzer events. `enumerate`, `reconcile`, and `index` use `files`; `parse` and `persist` use `blobs` (the source representatives selected for parsing/persistence). `reconcile` measures reuse of cached facts; cached files are not reported as newly parsed. Phases and languages have independent denominators: never sum them into a global percentage. A null `total` is indeterminate. Totals can change, and counters describe only the producer's work, not successful parsing or the absence of diagnostics. The `intermediate` array preserves the first actual nonterminal observation for each language/phase when the build finishes between notification ticks; it is a historical sample, not an additional counter to add to `counters`.

Observations contain no file labels, absolute paths, source text, or diagnostic strings. Recording starts before background cold indexing, so a first request can observe a build already in flight or completed. Refresh waits for the initial build before starting its own generation. The server retains at most 128 latest counters and 128 intermediate samples for one build per workspace, with no subscriber list or event history. Requests coalesce observations at 100 ms intervals and flush the latest state before returning. Transport waits are limited to 25 ms; slow or disconnected clients may miss observations without blocking indexing or cancellation. Request/task completion drops the observer, and workspace revocation prevents observations crossing workspace bindings.

`list_policies` reads only the built-in policy pack and reports no progress. Workspace activation rounds likewise report none: they are answers requesting authorization, not phases of an executing call. Tasks are useful when policy work may outlive its initiating request, as described below.

## Tasks

Bifrost implements the MCP Tasks extension (`io.modelcontextprotocol/tasks`, SEP-2663) for explicitly batch-shaped work, and advertises it through both `initialize` and `server/discover`. Only a single-workspace server offers tasks. A server started with `--workspace` does not advertise the extension and runs every call synchronously. Exactly one tool is eligible: `run_policy`, whose runtime scales with the whole corpus times the policy count. A `2026-07-28` request that declares the extension in its client capabilities and calls `run_policy` receives a durable task handle (`resultType: "task"`) instead of blocking on the result; the client polls `tasks/get` until the task is terminal, and the terminal response embeds exactly the `CallToolResult` a synchronous call would have produced, including the structured policy report and the `run_policy` correlation id. `tasks/cancel` requests cooperative cancellation and the task settles as `cancelled`. Clients that do not declare the extension -- and legacy `2025-11-25` clients even when they do -- keep the fully synchronous behavior and never see a task-shaped result. Navigation tools are deliberately ineligible: waiting out cold initialization is the intended readiness model, not a reason to hand back a task handle.

Task execution runs under the same discipline as a synchronous call: it waits for workspace readiness, queues for a real analyzer slot, and is bound to the workspace authorization it was created under. If the client rebinds or revokes its workspace, running task work is cancelled promptly and every outstanding handle is refused from then on -- a task can never carry results across a workspace boundary. Tasks live for ten minutes by default (`BIFROST_MCP_TASK_TTL_MS` overrides this, in whole milliseconds); the TTL is also the execution deadline, so an expired task is marked `failed` at the same moment its analyzer work is cooperatively cancelled, and its terminal result stays pollable for one further TTL window before eviction. The advertised polling interval is one second. At most 32 tasks can run at once; Bifrost refuses a new task request while 32 are running. Each running task still waits for one of the four analyzer slots.

The durability boundary is the process. Bifrost's MCP transport is stdio, so one connection is one process: a task survives the request that created it, which is the point, but not a process restart. If a launcher restarts Bifrost, every handle is gone and polling it fails with an unknown-task error. Progress notifications (above) remain the lighter mechanism for bounded interactive requests; tasks are for work that may legitimately outlive the request.

## Request budget

Every tool call except `refresh`, `activate_workspace`,
`get_active_workspace`, and `list_policies` has a wall-clock budget. The budget covers the wait for workspace readiness, the wait for an analyzer slot,
and execution.

- Without configuration, an ordinary call gets 60 seconds, and a synchronous
  `run_policy` call gets 240 seconds.
- While the workspace is still building, every tool except `search_symbols`
  fails after 4.5 seconds with a typed error that says the workspace is not
  ready. Retry the call after the build has had time to progress.
- `BIFROST_MCP_REQUEST_BUDGET_SECS` sets one budget, in whole seconds, for
  every tool except `list_policies`, including `run_policy` and the three
  workspace tools. The value must be
  a positive integer. Any other value stops the server at the first tool call.
- `run_policy` and the usage scans stop their analyzer a little before the
  deadline. `run_policy` then returns its canonical report with the
  termination state, and a usage scan returns partial results marked
  `time_budget`.
- An MCP Task uses its own TTL instead of this budget.

An expired call returns promptly. Its cancelled analyzer work keeps its slot
until it stops, so repeated timeouts cannot run more than four analyzer
executions at once. While 32 calls are already waiting for a slot, Bifrost
refuses further calls. The exact values are in
[MCP Tools Reference](/reference/mcp-tools/).

## Immutable Git Snapshot Diffs

An MCP host that captures review snapshots in a private Git object store can
launch Bifrost with `--diff-snapshot-object-dir /path/to/objects`. This trusted
launch setting names a Git `objects` directory; Bifrost resolves it to an
absolute path and rejects a missing or non-directory path at startup. It is not
an MCP tool argument, so an MCP caller cannot choose an arbitrary object-store
filesystem path.

`analyze_diff` accepts commit-ish or tree-ish values for explicit `base` and
`target` endpoints, preferring a commit when a spelling can resolve to either.
Its response labels commits by full hash, trees as `tree:<oid>`, and the
live working tree as `worktree`. Omitting
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

`list_function_sources` inventories callable declaration ranges in the current
indexed workspace. `paths` optionally selects exact workspace-relative files;
`include_tests` defaults to `true`. Its structured-only result contains `records`
and a `summary` with `file_count` (files contributing records), `record_count`,
and `skipped_files` with a path and reason when indexed source or blob identity
is unavailable. Each record includes `declaration_id`, `site_id`, `fq_name`,
`name`, `kind`, `signature`, `language`, `rel_path`, `blob_oid`, `start_line`,
`end_line`, `start_byte`, `end_byte`, `is_test`, and `source`. There is one record
per declaration range, including overload sites. Lines are
one-based and byte ranges are end-exclusive; these coordinates and `site_id`
refer to the declaration before comment expansion. `source` includes attached
leading comments and preserves the indexed text. `blob_oid` identifies the raw
indexed file bytes using Git's blob hash, even if disk contents later change.

The inventory follows the analyzer's callable declarations. Rust block-local
functions currently have native analysis facts but no declaration projection,
so they are included within their enclosing function's source rather than
returned as separate records.

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
whose reference scan did not complete, so nothing is dropped silently. Verification
uses source reference lines before interactive usage summaries, including for hot
symbols. Inline test membership comes from declaration ranges; merely sharing a
file with tests does not count. Caller time limits and analysis limits still
leave symbols unresolved. Test
symbols and edges are always in scope because verification needs them. The tool
builds an analyzer over the whole target revision rather than the changed files
alone, because the diff's own files cannot answer who calls a changed symbol;
expect the cost of a cold whole-repository analysis.

When standard roots or sandbox-state metadata controls a rootless connection, `activate_workspace` is unavailable even if the selected toolset exposes it. Change the workspace through the MCP host instead. This prevents a tool call from widening the client-approved scope; explicit-root integrations retain the normal workspace activation behavior.

## Toolsets

| Toolset | Purpose |
| --- | --- |
| `symbol` | Find declarations, read symbol source and summaries, find usages, definitions, declarations, and types, rename symbols, and build usage graphs. |
| `workspace` | Rebuild the index, switch the active workspace, and report the active workspace. |
| `diff` | Review a Git diff: semantic changes, reached test files, complexity changes, untested changes, and maintenance features. |
| `extended` | Run CodeQuery and saved RQL, list, run, and explain policies, locate symbols and ancestors, and rank related files. |
| `text` | Read files and search file contents with regular expressions. |
| `slopcop` | Code-quality reports: complexity, comment density, exception handling, hotspots, test assertions, clones, long methods, dead code, and secrets. |

`core` expands to `symbol|workspace|diff`. `searchtools` expands to every
toolset above in this order: `symbol|workspace|diff|extended|text|slopcop`.
[MCP Tools Reference](/reference/mcp-tools/) lists the tools in each toolset
and the rules of the `--mcp` expression.

`classify_test_files` is not part of any toolset. `bifrost --mcp cli`, and
any expression that names `cli`, fails with a structured error. Call it
through `bifrost --tool classify_test_files` or the Rust or Python API.

With line numbers enabled, `symbol` advertises `scan_usages_by_location`,
`get_declarations_by_location`, `get_definitions_by_location`, and
`get_type_by_location`. With `--no-line-numbers`, it advertises
`scan_usages_by_reference` and `get_definitions_by_reference` instead of those
four tools. No declaration-by-reference or type-by-reference tool exists.

Location navigation keeps declarations and definitions distinct. Both tools accept `{"references":[{"path":"src/file.ext","line":1,"column":1}]}`. Declaration results contain `operation: "declaration"` and a `declarations` array; definition results contain `operation: "definition"` and a `definitions` array. An empty operation-specific selection reports `no_declaration` or `no_definition`, and more than one selected target reports `ambiguous`. Declaration navigation prefers contracts such as C++ prototypes, Java interface methods, and Rust trait items, while definition navigation selects concrete bodies or implementation items. Entities without a separate body remain valid for both operations.

Exact MCP source positions use 1-based lines and 1-based Unicode code-point columns, with an exclusive end position. Individual `scan_usages` hits expose `line`, `column`, `end_line`, and `end_column`. Definition, declaration, and type-definition candidates expose `start_line`, `start_column`, `end_line`, and `end_column`. Column fields are omitted when a row is an aggregate or Bifrost cannot prove an exact token span; byte offsets are never part of the public result.

`searchtools` is the compatibility mode and exposes every MCP tool in toolset order. Use `symbol|extended` for the packaged coding-agent surface, or a smaller composition such as `symbol|workspace` when a host should see fewer tools.

`--no-line-numbers` changes the text content of results too: it removes line and line-range prefixes. `structuredContent` does not change.

## Discover and Run Policies

The `extended` toolset's read-only `list_policies` tool returns the deterministic
built-in pack catalog without constructing an analyzer. `run_policy` evaluates
built-in policies, workspace-relative `.rqlp` files, or both, in one batch:

```json
{
  "policy_packs": ["bifrost.code-smells"],
  "policy_categories": ["performance"],
  "policy_files": [".bifrost/policies/security.rqlp"],
  "evaluation_date": "2026-07-27",
  "fail_on": "warning"
}
```

This call runs the performance policies of the `bifrost.code-smells` pack and
the one workspace policy file. The built-in selectors follow these rules:

- Values within one selector array form a union. `"policy_categories":
  ["performance", "correctness"]` selects both categories.
- Different selector arrays intersect. A built-in policy runs only when it
  matches every array you supplied. `policy_packs` with `policy_ids` runs only
  the named policies inside those packs.
- A combination that matches no policy is an invalid-params error, and so is
  an unknown pack, category, or ID.
- An opt-in policy runs only when `policy_ids` names it. A pack or category
  selection never includes it.
- `policy_files` adds workspace policies to the same batch. The tool never
  discovers or runs every file under `.bifrost/policies/`.

All arrays are bounded and reject duplicate entries. At least one selector
array or `policy_files` is required. The date is required because the shared
policy coordinator does not read the clock.

The other arguments match the CLI policy flags:

- `suppression_file`, `baseline_file`, and `scope_file` name workspace-relative
  files. Without `suppression_file`, Bifrost reads
  `.bifrost/suppressions.json`, `.bifrost/suppressions.private.json`, and
  `.bifrost/suppressions.local.json`, in that order. A `suppression_file`
  replaces all three. The other defaults are `.bifrost/baseline.json` and
  `.bifrost/policy-scope.json`.
- `diff_base` names a Git revision. Bifrost also evaluates that revision,
  labels each finding new or persisting, and only new findings count toward
  `fail_on`.
- `fail_on` is `never`, `finding`, `note`, `warning` (default), or `error`.
- `incremental` (default `true`) reuses verified policy units from the
  analyzer cache. Set it to `false` to evaluate every policy in full. Findings
  and status are the same either way.
- `include_stage_timings` (default `false`) adds a `stage_timings` field with
  the wall-clock time of each evaluation stage.

[MCP Tools Reference](/reference/mcp-tools/) gives the type, bounds, and CLI
flag of each argument.

The structured result contains the canonical schema-5 `report` (see [Policy
Reference](/reference/policies/) for its fields), a `status` of
`clean`, `finding`, or `unreliable`, and the equivalent `exit_status` value
`0`, `1`, or `2`. Read each run's completion state before you call a result
clean; [Agent Result Safety](/agent-result-safety/) gives the safe claim for
each state. It also carries `request_correlation_id`, a `sha256:` digest
of the JSON-RPC request ID. MCP itself does not exit for a finding. Evaluation is pinned
to the active immutable workspace snapshot and is cancelled if the client
cancels the request or revokes that workspace. See [Static-Analysis
Policies](/static-analysis-policies/#review-findings-with-exact-suppressions)
for the exact strong-identity and audit contract.

## Workspace Operations

`activate_workspace` lets a host swap the analyzer root mid-session without respawning the subprocess. The path must be absolute and is normalized to the nearest enclosing git root when one exists. It cannot bind a server that has no workspace yet: an unbound server returns the not-bound error for every call, including `activate_workspace`. Start the server with `--root`, or let the client supply roots.

`refresh` forces a full rebuild of the code index. Normal tool calls already apply watcher-detected file changes automatically, so most hosts should keep `refresh` as a manual recovery tool rather than a routine pre-query step. When the server runs with `BIFROST_MCP_FILE_WATCHER=off`, it does not watch files, and `refresh` is the way to pick up edits.

For MCP tool arguments that name files, directories, or file globs, callers may pass project-relative paths or absolute paths inside the active workspace. Absolute paths outside the active workspace are rejected with an explicit tool error.

A path selector names one of three things: a file, a directory, or a glob. A directory selects every file beneath it, with or without a trailing separator, so `paths: ["src/parser"]` and `paths: ["src/parser/**"]` select the same files. A selector that names none of the three selected nothing, so the tool reports it instead of answering from a search it never ran. `scan_usages_by_reference` and `scan_usages_by_location` list it in `scope.unmatched_paths`, set `complete` to false with `incomplete_reason: "unmatched_paths"`, and report absence as `unverified_absent` rather than `verified_absent`. `usage_graph` adds an `unmatched_paths` entry to `incomplete_reasons`, and `search_file_contents` returns the selector in `unmatched_paths`.

### File names and `path#symbol` selectors

Several tools also accept a definition selector, `path#symbol`, which names the declaration `symbol` inside the workspace file `path`. A repository chooses its file names, so `$`, `.`, `#`, and spaces are ordinary characters inside one. All of these are legal targets: `src/Node$.scala`, `src/Outer.Part.cs`, `src/Outer.Part#one.cs`, and `src/$ dir/Node.part#two.scala`.

A target that names an existing workspace file is that file, whole. On file-capable surfaces such as `get_summaries` targets, the complete literal file wins over any `#` split of the same string: `targets: ["src/Outer.Part#one.cs"]` lists that file rather than reading `#one.cs` as a symbol inside `src/Outer.Part`. When both readings are possible -- an existing file whose name happens to spell a `path#symbol` selector for a different file, such as `src/a.cs#Widget` while `src/a.cs` also exists -- the whole-file reading still wins and that one spelling is shadowed; the declaration stays reachable through a bare symbol query or through a longer selector that anchors on the real file.

A target that is not itself an existing file is split at `#`. When the anchor also contains `#`, the split at the longest prefix that names a real file wins, so `src/Outer.Part#one.cs#Demo.Outer.Inner` resolves `Demo.Outer.Inner` in the file `src/Outer.Part#one.cs`. Ordinary selectors are unchanged: `src/db_column.rs#describe` still means the member `describe` in `src/db_column.rs`, and the Rust raw identifier `src/db_column.rs#r#type` keeps its first-`#` split because `src/db_column.rs#r` is not a file.

When a macro and a declaration in one file share a spelling, for example `#define IMNODES_NAMESPACE ImNodes` next to `namespace IMNODES_NAMESPACE`, the plain `path#symbol` selector matches both, and the tool reports the target as ambiguous with one kind-qualified selector per unit: `path#macro#symbol` and `path#module#symbol`. The kind word is the same word the output prints in `kind`. Re-call with one of those selectors to address a single unit. A selector whose first segment after the path is not a kind word is an ordinary `path#symbol` selector.

Selector characters never merge two declarations into one name. In Scala a trailing `$` in the name part is Bifrost's companion-object decoration, so `CharsetRange` and its companion print `CharsetRange` and `CharsetRange$`; a `$` the source itself writes remains part of the identifier, so `object Foo` and `object Foo$` in one file stay distinct declarations with distinct selectors.

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

## Packaged agent plugin

The Bifrost agent plugin package (`plugins/bifrost-agent` in the Bifrost
repository) contains a launcher, MCP server configuration for each host,
skills, and subagents. The launcher, `bin/bifrost-launcher.mjs`, finds or
downloads the pinned Bifrost binary and starts it as an MCP server with
`--mcp symbol|extended`. See [Data and Trust Boundaries](/data-boundaries/)
for how it resolves, downloads, and caches the binary.

| Host | Configuration file | MCP server | Skills | Subagents |
| --- | --- | --- | --- | --- |
| Claude Code | `.claude-plugin/plugin.json` | `claude-mcp.json` | `skills/` directory, not listed in the manifest | All eight, declared in the manifest |
| Cursor | `.cursor-plugin/plugin.json` | `cursor-mcp.json` | `skills/` directory, not listed in the manifest | All eight, declared in the manifest |
| Codex | `.codex-plugin/plugin.json` | `.mcp.json` | `skills/` directory, not listed in the manifest | None |
| Other Agent Plugins v1 hosts | `plugin.json` | `mcp.json` | `skills/` directory, not listed in the manifest | None |
| Pi | `package.json` (`pi` section) | Started by the Pi extension | All four, declared in `package.json` | None |

Only the Pi manifest lists the skills. Claude Code, Cursor, Codex, and other
hosts load skills from the package's `skills/` directory only if their own
plugin convention does so.

The Claude Code manifest also registers an LSP server through `.lsp.json`. It
runs the launcher with `--lsp`. That works only with the pinned release 0.12.0.
Later Bifrost builds reject `--lsp`, because the language server is now the
separate `bifrost-lsp` program. See [Claude Code](/claude-code/) and [LSP
Server](/lsp/).

Skills:

| Skill | What it teaches the agent |
| --- | --- |
| `bifrost-code-navigation` | Find definitions, references, call sites, and related files with `search_symbols`, `get_symbol_locations`, `scan_usages_by_location`, and `most_relevant_files`. |
| `bifrost-code-reading` | Read implementation details and source structure with `get_summaries` and `get_symbol_sources`. |
| `bifrost-codebase-search` | Find symbols, structural code shapes, and files with `search_symbols`, `query_code`, `scan_usages_by_location`, and `most_relevant_files`, and use host file search for paths and plain text. |
| `bifrost-policy-checking` | Discover policy packs and categories, run built-in and repository policies, and interpret `clean`, `finding`, and `unreliable` results. |

Subagents:

| Subagent | Role |
| --- | --- |
| `architect-reviewer` | Reviews a pull request for coupling, cohesion, SOLID principles, abstraction levels, and consistency with existing patterns. |
| `devops-reviewer` | Reviews infrastructure code, CI/CD configuration, resource management, logging, timeouts, and error handling. |
| `dry-reviewer` | Finds code in a pull request that duplicates logic already in the codebase. |
| `issue-diagnostician` | Finds affected files, traces code paths, and forms a root-cause hypothesis for an issue. |
| `issue-enhancer` | Adds source references, affected components, and technical context to a draft issue. |
| `issue-planner` | Turns a diagnosis into an ordered list of code changes with file paths and method names. |
| `security-reviewer` | Looks for injection, authentication bypasses, data leaks, cryptographic misuse, backdoors, and dependency vulnerabilities in a pull request. |
| `senior-dev-reviewer` | Checks that pull request changes match the stated description, and finds unrelated changes, scope creep, incomplete refactors, and missing tests. |

Launcher arguments and commands:

| Argument or command | Meaning |
| --- | --- |
| `--root DIR`, `--workspace-root DIR` | Workspace root to pass to Bifrost as `--root`. |
| `--mcp TOOLSETS`, `--toolset TOOLSETS` | Toolset expression. Default `symbol\|extended`. |
| `--lsp` | Pass `--lsp` to Bifrost instead of starting MCP. Cannot be combined with `--mcp` or `--toolset`. Works only with Bifrost 0.12.0; later builds reject `--lsp`. |
| `prepare [--json]` | Download and verify the pinned binary now, then report its status. Exit status 0 means ready. |
| `doctor [--json]` | Report the binary the launcher would use, without downloading. Exit status 0 means ready. |

For an MCP server, `BIFROST_WORKSPACE_ROOT` takes precedence over `--root`.
With neither, the launcher starts Bifrost without a root, and Bifrost binds to
the workspace that the host supplies through MCP roots or Codex sandbox
metadata. The launcher does not use its own working directory as the root.
Other arguments pass through to Bifrost unchanged.

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
