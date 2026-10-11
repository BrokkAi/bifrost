---
title: MCP Tools Reference
description: Every Bifrost MCP tool, its arguments, outputs, limits, and the server flags and environment variables that control the MCP surface.
---

This page lists every tool that the Bifrost MCP server can advertise. It also
lists the launch flags, environment variables, limits, and protocol metadata
of the server. For setup, workspace binding, and validation steps, see
[MCP Server](/mcp/).

The running binary can print the same information:

- `bifrost --help` lists every toolset and its tools.
- `bifrost --help <tool>` prints one tool's description and input schema.
- An MCP client's `tools/list` request returns the exact tools, input schemas,
  output schemas, and annotations of the running server.

In the argument tables, "Required" means the input schema lists the argument
in `required`. "-" means no default or no bound. Byte limits count UTF-8
bytes.

## MCP server configuration

### Launch flags

| Flag | Value | Default | Meaning |
| --- | --- | --- | --- |
| `--mcp TOOLSETS` | Toolset expression (see below) | `searchtools` when `bifrost` runs with no arguments | Run an MCP server over stdio with the named toolsets. |
| `--root DIR` | Directory | Current directory, only for the no-argument command | Bind the server to one fixed workspace. With `--mcp` and no `--root`, the server starts unbound and waits for client roots or Codex sandbox metadata. |
| `--workspace NAME=PATH` | Name and directory; repeatable | - | Start a named multi-workspace server. Requires `--mcp`. Cannot be combined with `--root` or `--diff-snapshot-object-dir`. See [Named workspaces](/mcp/#named-workspaces). |
| `--no-line-numbers` | - | Line numbers on | Remove line-number prefixes from the text content of results. It also changes the `symbol` toolset to its reference-mode tools. `structuredContent` does not change. |
| `--diff-snapshot-object-dir DIR` | Existing Git `objects` directory | - | Let diff tools resolve commits and trees that exist only in this object store. Bifrost resolves the path to an absolute directory at startup and rejects a missing path or a file. |
| `--server MODE` | Same as `--mcp` | - | Deprecated alias for `--mcp`. It prints a deprecation warning. `--server lsp` fails. |

`bifrost` with no arguments is the compatibility command. It analyzes the
current directory with the `searchtools` toolset. `bifrost --lsp` fails: the
language server is a separate program; see [LSP Server](/lsp/).

### Toolset expression

`--mcp` takes one or more toolset names separated by `|`, for example
`symbol|extended`. Bifrost trims spaces around each name.

| Name | Expands to |
| --- | --- |
| `symbol` | Symbol navigation tools |
| `workspace` | `refresh`, `activate_workspace`, `get_active_workspace` |
| `diff` | Diff-review tools |
| `extended` | Structural query, policy, and file-ranking tools |
| `text` | Raw file reading and text search |
| `slopcop` | Code-quality reports |
| `core` | `symbol\|workspace\|diff` |
| `searchtools` | `symbol\|workspace\|diff\|extended\|text\|slopcop` |

Rules:

- The server advertises tools in the order of the expression. A tool that two
  names select appears once, at its first position.
- An empty segment, such as `symbol||text`, is an error.
- An unknown name is an error: `Unsupported server mode: <name>`.
- `cli` is rejected. `classify_test_files` is available only through
  `bifrost --tool classify_test_files` and the Rust and Python APIs.

### Environment variables

| Variable | Values | Default | Meaning |
| --- | --- | --- | --- |
| `BIFROST_MCP_REQUEST_BUDGET_SECS` | Positive integer (seconds) | Not set | Wall-clock budget for every tool call, including `run_policy` and the workspace tools. A value that is not a positive integer stops the server with a panic at the first tool call. |
| `BIFROST_MCP_TASK_TTL_MS` | Integer of 1 or more (milliseconds) | `600000` (ten minutes) | Lifetime and execution deadline of an MCP Task. An invalid value prints a warning and uses the default. |
| `BIFROST_MCP_FILE_WATCHER` | `on` or `off` | `on` | With `off`, the server does not watch the workspace for file changes. Call `refresh` to pick up edits. Any other value is a startup error. |
| `BIFROST_MCP_LOG` | `off`, `error`, `warn`, `info`, `debug`, `trace` | `warn` | How much of the MCP transport's diagnostic log reaches stderr. Any other value is a startup error. |

The `bifrost` binary does not read `BIFROST_WORKSPACE_ROOT`. The packaged
agent-plugin launcher reads it and passes it to Bifrost as `--root`. For the
environment variables that affect analysis and caching in every mode, see
[Environment Variables](/reference/environment/).

### Request budget and limits

Bifrost picks one budget for each tool call when it accepts the call. The
budget covers the wait for workspace readiness, the wait for an analyzer slot,
and execution. The first matching row applies:

| Condition | Budget |
| --- | --- |
| `BIFROST_MCP_REQUEST_BUDGET_SECS` is set | That many seconds, for every tool |
| Tool is `run_policy` | 240 seconds |
| Tool is `refresh`, `activate_workspace`, `get_active_workspace`, or `list_policies` | No budget |
| The workspace is still building, and the tool is not `search_symbols` | 4.5 seconds |
| Any other call | 60 seconds |

When a budget expires, the call returns a typed error. On a workspace that is
still building, the error says the workspace is not ready and that the call
can be retried. A `run_policy` call asks its analyzer to stop early, by 5
seconds or a quarter of its budget, whichever is less. This lets it return the
canonical report with its termination state instead of a bare timeout.
`scan_usages_by_location` and `scan_usages_by_reference` use the same early
stop and return partial results with `incomplete_reason: "time_budget"`.

| Limit | Value |
| --- | --- |
| Concurrent analyzer executions | 4 |
| Calls waiting for an analyzer slot | 32; further calls are refused |
| Running MCP Tasks | 32; further task requests are refused |
| Server instructions and each tool description | 2,000 characters |
| Wait for a client's `roots/list` answer | 5 seconds |

`list_policies` never waits for an analyzer slot. In single-workspace mode,
the workspace tools (`refresh`, `activate_workspace`, `get_active_workspace`)
also skip the analyzer slot and run one at a time. In named-workspace mode,
`refresh` waits for a slot like other tools.

### MCP Tasks

Bifrost supports the MCP Tasks extension, `io.modelcontextprotocol/tasks`, in
single-workspace mode. A named-workspace server does not advertise it. Only
`run_policy` can run as a task, and only when the client uses protocol version
`2026-07-28` and declares the tasks capability. Other calls run synchronously.
A task lives for `BIFROST_MCP_TASK_TTL_MS`
(default ten minutes), which is also its execution deadline. Its final result
stays readable for one more TTL period. The suggested poll interval is one
second. Tasks end when the process ends. See [Tasks](/mcp/#tasks) for the
protocol details.

### Published metadata

| Item | Value |
| --- | --- |
| Server name | `bifrost`, with the binary version in `serverInfo.version` |
| Build identity | `initialize` result `_meta["io.bifrost/build-identity"]`: the exact source identity of the binary, as printed by `bifrost --build-identity` |
| Capabilities | `tools`, `resources`, and the `io.modelcontextprotocol/tasks` extension (single-workspace mode only). Bifrost does not advertise `tools.listChanged`, because the tool list is fixed for the life of the process. |
| Instructions | Routing text for the selected toolsets. A named-workspace server adds a sentence that tells the agent to set `workspace`. |
| Resources | One resource: `bifrost://agent-guidance/agents.md` (`text/markdown`), the text shown on [Agent Instructions](/agents/) |
| Annotations | Every tool has `readOnlyHint: true`, except `refresh` and `activate_workspace`, which have `readOnlyHint: false`. Every tool has `destructiveHint: false`, `idempotentHint: true`, and `openWorldHint: false`. |
| Output schemas | JSON Schema 2020-12 `outputSchema` for `search_symbols`, `get_definitions_by_location`, `get_active_workspace`, `blast_radius`, `cyclomatic_complexity`, `missing_tests`, `list_policies`, `report_test_assertion_smells`, and `report_structural_clone_smells`. Other tools return `structuredContent` without a published schema. |
| Cache hints (`2026-07-28` clients) | `tools/list` is `private` for five minutes. The agent-guidance resource is `public` for one hour. Tool results are not cacheable. |

## Result conventions

Every tool result has a `structuredContent` JSON object and a text content
block. The text block is a rendered preview for the model. Read
`structuredContent` when a program consumes the result. A failed call returns
a JSON-RPC error or a result with `isError: true`, and the message says what
failed. Invalid arguments use JSON-RPC code `-32602`. A call to an unbound
server fails with a message that explains how to bind a workspace.

- Paths in arguments can be project-relative or absolute inside the active
  workspace. An absolute path outside the workspace is an error.
- A path selector names a file, a directory (every file beneath it), or a
  glob.
- Lines and columns are 1-based. Columns count Unicode code points. End
  positions are exclusive.
- `path#symbol` names the declaration `symbol` in the file `path`. See
  [File names and path#symbol selectors](/mcp/#file-names-and-pathsymbol-selectors).
- Before you claim "all" or "none" from a result, read the completeness fields
  listed for each tool. [Agent Result Safety](/agent-result-safety/) explains
  the safe wording for each state.

## Named-workspace mode

With `--workspace NAME=PATH`, every tool except `list_policies` has one more
required argument:

| Argument | Type | Required | Meaning |
| --- | --- | --- | --- |
| `workspace` | string, one of the configured names | Yes | The named workspace that contains the code for this call. |

`activate_workspace` and `get_active_workspace` are not advertised in this
mode.

## symbol toolset

With line numbers on (the default), the toolset has nine tools:
`search_symbols`, `get_symbol_sources`, `get_summaries`,
`scan_usages_by_location`, `get_declarations_by_location`,
`get_definitions_by_location`, `get_type_by_location`, `rename_symbol`, and
`usage_graph`.

With `--no-line-numbers`, it has seven tools. `scan_usages_by_reference` and
`get_definitions_by_reference` replace `scan_usages_by_location`,
`get_declarations_by_location`, `get_definitions_by_location`, and
`get_type_by_location`. No declaration-by-reference or type-by-reference tool
exists.

### search_symbols

Find declarations (classes, functions, methods, fields, modules, macros) by
name.

| Argument | Type | Required | Default | Bounds | Meaning |
| --- | --- | --- | --- | --- | --- |
| `patterns` | array of strings | Yes | - | Up to 64 items; 4,096 bytes each; 65,536 bytes in total | Case-insensitive regular expressions matched against symbol names. A pattern with `*` or `?` that is not a valid regular expression, such as `*Name*`, is matched as a glob. |
| `include_tests` | boolean | No | `false` | - | Include test symbols. A symbol counts as a test when it is a test declaration or lives under a test-tree path. |
| `limit` | integer | No | `20` | 1 or more | Maximum number of matching symbols to return. |

Output: `patterns`, `files` (one entry per file with `path`, `loc`, and
`classes`, `functions`, `fields`, `modules`, `macros`; each hit has `symbol`,
`signature`, `line`, `is_type_alias`), `total_files`, `model_symbols`,
`total_model_symbols`, and `note`.

Completeness: `truncated` is true when `limit` cut the result.
`too_many_matches` (`total_candidates`, `cap`) replaces results when a
pattern matches too many symbols to rank. `invalid_patterns` lists patterns
that are neither a valid regular expression nor a glob; they matched nothing.
`session_subset` appears only when the session covers a named subset of files.

### get_symbol_sources

Return the exact source of known symbols. A file path or glob returns a flat
outline of that file's top-level symbols.

| Argument | Type | Required | Default | Bounds | Meaning |
| --- | --- | --- | --- | --- | --- |
| `symbols` | array of strings | Yes | - | Up to 64 items; 4,096 bytes each; 65,536 bytes in total | Fully qualified or short symbol names, or project-relative file paths or globs. |

Output: `sources` (each with `label`, `path`, `start_line`, `end_line`,
`text`), `not_found`, and `ambiguous` (at most 25 candidates per name; the
note gives the true count).

Completeness: `complete` is false when a lookup was cancelled; `incomplete`
lists each affected target with `reason: "cancelled"`. A glob that matches
more than 10 files is skipped and listed in `too_broad` (`target`, `matched`,
`cap`, `matched_kind`, `sample`, `note`). `ambiguous_paths` lists path inputs
that match more than one file.

### get_summaries

Summarize files, classes, and modules, or list the contents of a directory or
package.

| Argument | Type | Required | Default | Bounds | Meaning |
| --- | --- | --- | --- | --- | --- |
| `targets` | array of strings | Yes | - | - | Mixed targets. A directory lists its immediate child directories and Git-visible files. A language package or namespace lists its direct child packages and top-level types. A file, glob, class, or module returns ranged summaries. A real directory wins over a package with the same name. |

Output: `summaries`, `listings` (each with `target`, `kind` of `directory` or
`package`, `entries`, `total_entries`, `truncated`), `not_found`,
`ambiguous`, `degraded`, and `degradation`.

Completeness: the response has a 4,096-byte budget. When summaries exceed it,
Bifrost returns `compact_symbols` instead and sets `degraded: true` with
`degradation.reason: "response_budget_exceeded"`. A listing that exceeds it
keeps `total_entries` and sets `truncated: true`. A glob that matches more
than 20 files is skipped and listed in `too_broad`.

### scan_usages_by_location

Find references, call sites, callers, and related tests for declarations
selected by position. Line-number mode only.

| Argument | Type | Required | Default | Bounds | Meaning |
| --- | --- | --- | --- | --- | --- |
| `targets` | array of objects | Yes | - | 1 or more | Declarations to scan. |
| `targets[].path` | string | Yes | - | Not empty | Project-relative file that contains the declaration. |
| `targets[].line` | integer | Yes | - | 1 or more | Line that contains the declaration name. |
| `targets[].column` | integer | No | - | 1 or more | Column inside the declaration name. |
| `targets[].symbol` | string | No | - | Not empty | Exact declaration selector, for overlapping declarations. Use the selector that `search_symbols` returned. |
| `include_tests` | boolean | No | `false` | - | Include call sites in test files. |
| `include_same_owner` | boolean | No | `false` | - | List same-owner sites (self or this receiver, own-type static calls) in `same_owner_files`. When false, they are only counted in `same_owner_sites`. |
| `paths` | array of strings | No | - | - | Files, directories, or globs that limit where Bifrost searches. |

Output: `results` (one entry per target), `scope` (`include_tests`,
`whole_workspace`, `paths`, `unmatched_paths`, `session_subset`), and
`summary` (`requested`, `resolved`, `total_hits`, `partial`, and a count for
each status). Each result has `status`, `symbol`, `fq_name`,
`definition_path`, `definition_line`, `total_hits`, `unproven_hits`, `files`
(proven hits), `unproven_files`, `same_owner_sites`, and `rendering`. An
unproven hit can carry `reason_kind`, which names why it is not proven; for
example, `unknown_activation` marks a Rust site whose `cfg` cannot be decided
for the selected configuration. Sites whose `cfg` is proven inactive are not
reported.

`status` is one of:

| Status | Meaning |
| --- | --- |
| `found` | At least one external usage site was found. |
| `verified_absent` | The scan completed with no caveats and found no usage. Only this status supports "no usages". |
| `no_external_usages` | No external usage, but same-owner sites exist. |
| `unverified_absent` | No usage was found, but the scan has caveats or stopped early. `absence_caveats` lists `unproven_matches`, `candidate_files_truncated`, `reference_only_siblings`, or `scan_incomplete`. |
| `not_found` | The location does not select a declaration. |
| `ambiguous` | The input matched more than one declaration. `candidates` lists them, or `too_many_candidates` (`total_candidates`, `cap`) gives the count. |
| `too_many_callsites` | More than 1,000 call sites; `total_callsites` and `limit` give the counts. |
| `failure` | The scan failed; `message` says why. |

Completeness: `complete: false` (omitted when true) and `incomplete_reason`
mark a result that stopped early. Reasons: `cancelled`, `time_budget`,
`candidate_files`, `source_bytes`, `source_unavailable`, `semantic_analysis`,
`callsites`, `response_budget`, `resolution_candidates`, `unmatched_paths`.
`summary.partial` is true when any result is incomplete. The response has an
8,192-byte budget. Results with more than 10 hits show line rows, and results
with more than 100 hits show per-file counts (`rendering`: `full`, `lines`,
`summary`).

### scan_usages_by_reference

The same scan as `scan_usages_by_location`, but selected by symbol name.
Reference mode (`--no-line-numbers`) only.

| Argument | Type | Required | Default | Bounds | Meaning |
| --- | --- | --- | --- | --- | --- |
| `symbols` | array of strings | Yes | - | 1 or more; each must contain a non-space character | Fully qualified names from `search_symbols` are preferred. A short name can resolve fuzzily or be ambiguous. |
| `include_tests` | boolean | No | `false` | - | Include call sites in test files. |
| `include_same_owner` | boolean | No | `false` | - | As for `scan_usages_by_location`. |
| `paths` | array of strings | No | - | - | As for `scan_usages_by_location`. |

Output and completeness fields are the same as for
`scan_usages_by_location`.

### get_declarations_by_location

Resolve reference sites to their declarations or contracts, such as a C++
prototype, an interface method, or a Rust trait item. Line-number mode only.

| Argument | Type | Required | Default | Bounds | Meaning |
| --- | --- | --- | --- | --- | --- |
| `references` | array of objects | Yes | - | Up to 100 | Reference sites. |
| `references[].path` | string | Yes | - | - | Project-relative file that contains the reference. |
| `references[].line` | integer | Yes | - | 1 or more | Line of the reference. |
| `references[].column` | integer | No | - | 1 or more | Column inside the reference token. |

Output: `results`, one per reference, each with `query`, `reference`
(`path`, `target`), `operation: "declaration"`, `status`, `declarations`
(each with `name`, `fqn`, `kind`, `language`, `signature`, `path`,
`start_line`, `start_column`, `end_line`, `end_column`), and `diagnostics`.

Completeness: read `status`. The values are the same as for
[get_definitions_by_location](#get_definitions_by_location), except that an
empty selection reports `no_declaration`. Declaration results have no
`complete` or `incomplete_reason` field.

### get_definitions_by_location

Resolve reference sites to definitions: concrete bodies or implementation
items. Line-number mode only. Arguments are the same as for
`get_declarations_by_location`.

Output: `results`, each with `query`, `reference`, `operation: "definition"`,
`status`, `definitions` (same fields as `declarations`, plus
`canonical_selector` and `occurrence_role` when known), `diagnostics`,
`complete`, and `incomplete_reason`.

`status` is one of `resolved`, `ambiguous`, `no_definition` (or
`no_declaration` for declarations), `not_found`, `invalid_location`,
`unsupported_language`, `unresolvable_import_boundary`, `unavailable`,
`incomplete`, `cancelled`, or `exceeded_budget`. Bifrost can add new
inconclusive values, so treat any value other than `resolved` as "no single
answer". Only `resolved` with `complete` absent or true supports a definite
target. `complete` is omitted when true. `incomplete_reason` is one
of `cancelled`, `time_budget`, `resolution_budget`, `analysis_failure`,
`structure_unavailable`, or `navigation_targets`. A diagnostic can carry a
`claim` about indexing, with `subjects`, `role`, and a `kind`:
`external_boundary` (the subject is outside the indexed workspace),
`resolved_external` (the name resolved to an external declaration), or
`unindexed_owner` (the name may be declared by an owner the workspace does not
index).

### get_definitions_by_reference

Resolve references by copied source context instead of positions. Reference
mode (`--no-line-numbers`) only.

| Argument | Type | Required | Default | Bounds | Meaning |
| --- | --- | --- | --- | --- | --- |
| `references` | array of objects | Yes | - | - | Reference sites. |
| `references[].symbol` | string | Yes | - | - | Fully qualified symbol whose source contains the reference. |
| `references[].context` | string | Yes | - | - | Exact source text copied from around the reference. |
| `references[].target` | string | Yes | - | - | The single token to resolve inside `context`. For a qualified expression, use the member or name token. |

If the token occurs more than once in `context` and the occurrences resolve
differently, the result is `ambiguous`.

### get_type_by_location

Resolve expressions or identifiers to the workspace type definitions known for
them. Line-number mode only. Arguments are the same as for
`get_declarations_by_location` (up to 100 references, with a `path` to the
file that contains the expression or identifier).

Output: `results`, each with `query`, `reference`, `status`, `types` (each
with `fqn`, and `kind`, `language`, and `definitions` when known), and
`diagnostics`. `status` is one of `resolved`, `ambiguous`, `no_type`,
`not_found`, `invalid_location`, `unsupported_language`, `unavailable`,
`incomplete`, `cancelled`, or `exceeded_budget`. Only `resolved` gives a
definite type.

### rename_symbol

Return the edit set for renaming one symbol. It does not change files.

| Argument | Type | Required | Default | Bounds | Meaning |
| --- | --- | --- | --- | --- | --- |
| `path` | string | Yes | - | Not empty | Project-relative file that contains the declaration or a reference. |
| `line` | integer | Yes | - | 1 or more | Line of the identifier. |
| `column` | integer | Yes | - | 1 or more | Column inside the identifier. |
| `new_name` | string | Yes | - | 1 to 256 bytes | New identifier. It must be valid in the symbol's language. |

Output: `query`, `status`, `target` (`symbol`, `kind`, `path`), `old_name`,
`edits` (per file: `path` and `edits` with `start_line`, `start_column`,
`end_line`, `end_column`, `old_text`, `new_text`), and `diagnostics`.

`status` is `ok` when the edit set is safe to apply. Any other status rejects
the rename and returns no edits, and the diagnostic of the same kind says why.
Common values are `ambiguous`, `incomplete_analysis`, `invalid_location`,
`invalid_name`, `low_confidence`, `not_found`, `overlapping_edits`,
`read_failed`, `stale_location`, `too_many_callsites`, and `unsupported`. A
definition lookup that does not resolve passes its own status through, such
as `no_definition`, `cancelled`, or `exceeded_budget`. The set is open: treat
any value other than `ok` as a refusal.

### usage_graph

Build a caller-to-callee reference graph.

| Argument | Type | Required | Default | Bounds | Meaning |
| --- | --- | --- | --- | --- | --- |
| `paths` | array of strings | No | Every workspace declaration is a root | - | Files, directories, or globs whose declarations are graph roots. |
| `depth` | integer | No | `1` | 1 or more | Outbound hops expanded from the roots. Without `paths`, depth 1 is the complete workspace graph. |
| `include_tests` | boolean | No | `false` | - | Include references in test files. |

Output: `nodes` (`id`, `fqn`, `kind`, `language`, `path`, `start_line`),
`edges` (`from`, `from_id`, `to`, `to_id`, `language`, `weight`, and `sites`
with one `{path, line}` per reference), and `session_subset` when relevant.

`paths` chooses declaration roots, and `depth` expands outbound
caller-to-callee hops from those roots. The graph still resolves referenced
files as needed, so a narrow path or depth does not make resolution cost
proportional to a changed line range. `usage_graph` is not an inbound fan-in
query; use `scan_usages_by_location` for caller questions.

Completeness: `complete` is false when any part of the graph is missing.
`incomplete_reasons` lists each gap as `{code, message}`, including
`unmatched_paths` for a selector that matched nothing. `truncated_symbols`
lists symbols with more than 1,000 call sites (`fqn`, `total_callsites`,
`limit`); their inbound edges are omitted.

## workspace toolset

| Tool | Arguments | Output |
| --- | --- | --- |
| `refresh` | None | `analyzed_files`, `declarations`, `languages`. Rebuilds the code index from scratch. Normal calls already apply file changes that the watcher detects. |
| `activate_workspace` | `workspace_path` (string, required): absolute path | Same fields as `get_active_workspace`. Switches the active root, normalized to the enclosing Git root when one exists. It cannot bind a server that has no workspace yet; start the server with `--root` or let the client supply roots. Unavailable when client roots or Codex sandbox metadata control the workspace. |
| `get_active_workspace` | None | `workspace_path`; `usage_index_ready` (false while background usage analysis is catching up, so usage tools would wait); `semantic_packs_ready` (false while semantic packs are still resolving); `session_subset` when the session covers a named subset of files. |

## diff toolset

All five tools take the same endpoint arguments:

| Argument | Type | Required | Default | Bounds | Meaning |
| --- | --- | --- | --- | --- | --- |
| `base` | string | No | See below | Not empty | Commit-ish or tree-ish before the change. |
| `target` | string | No | Live working tree | Not empty | Commit-ish or tree-ish after the change. A tree-only target needs an explicit `base`. |

With neither endpoint, Bifrost compares the merge base of `HEAD` and the
default branch (from `refs/remotes/origin/HEAD`, or `HEAD` when that is
missing) with the live working tree. With only a commit `target`, `base` is
its first parent; a root commit has none, so that call fails. When a spelling
can be a commit or a tree, Bifrost uses the commit. When both endpoints are
commits or trees, the live working tree, index, and `.gitattributes` are not
read. Every output has `endpoints` with `base` and `target` as full commit
hashes, `tree:<oid>`, or `worktree` for the live working tree.

### analyze_diff

Report the semantic effects of a diff.

| Argument | Type | Required | Default | Meaning |
| --- | --- | --- | --- | --- |
| `base`, `target` | string | No | See above | Endpoints. |
| `include_tests` | boolean | No | `true` | Include symbols and call edges from test files. |
| `call_edges` | `changed_lines`, `changed_files`, or `omit` | No | `changed_lines` | Select changed reference start-line call facts, retain the full changed-file inventory, or omit call-edge analysis. |

Output: `file_changes` (`path`, `status`, `insertions`, `deletions`,
`is_binary`, `is_parseable`, `is_test`), `patch_symbols` (`edited`,
`introduced`, `deleted`, `moved`, `signature_changes`), `dependency_symbols`,
`import_changes`, `large_callsite_symbols`, and
`unattributed_call_edge_changes`. Every symbol has `is_test`. Edited and moved
records carry `added_calls` and `removed_calls`; introduced records carry
`calls`; deleted records carry `called`.

Call facts are selected by reference start-line inventory when `call_edges` is
`changed_lines`; they are not whole-function or whole-caller relationship
changes. Unchanged sites and import-only rebinding outside the selected lines
are intentionally omitted. A selected-line addition requires a complete base
scope, and a selected-line removal requires a complete target scope; a
directional delta without that opposite-side completeness is not precise.
`changed_files` retains the incumbent full-file call inventory and may return
best-effort deltas when `call_analysis` is incomplete. `omit` leaves all
call-edge arrays present and empty, while `import_changes` remains available.
The response always includes
`call_analysis` with `scope`, `status` (`complete`, `incomplete`, or `omitted`),
and optional `base`/`target` endpoint records containing `complete` and
`incomplete_reasons` (`code` and `message`). Completeness is relative to the
requested scope; an omitted site outside `changed_lines` is not an analysis
failure. `base` and `target` are absent when the requested scope is `omit`.

Language coverage remains part of completeness. For example, Python currently
reports `forward_reference_incomplete` with an uncovered `PatternPosition`
role. Empty selected deltas under that result do not prove that calls were
unchanged. Check the endpoint reasons before using a negative result.

The selected scope compares exact declaration IDs. It reports
`ambiguous_diff_attribution` when the patch-symbol name group cannot represent
distinct declarations, and `unknown_declaration_correspondence` when a moved
record supplies only a candidate correspondence. Similar bodies and Git rename
buckets do not prove that two exact endpoints are the same declaration.
Affected attribution is omitted with incomplete endpoint metadata.

Selection bounds reference target resolution, while endpoint parsing,
occurrence classification, and dependency materialization still read whole
files. `omit` uses the lighter symbol-image path and skips call resolution.

### blast_radius

Suggest test files reached through the file-dependency graph from changed
files.

| Argument | Type | Required | Default | Bounds | Meaning |
| --- | --- | --- | --- | --- | --- |
| `base`, `target` | string | No | See above | - | Endpoints. |
| `max_scopes` | integer | No | `100` | 1 to 1000 | Maximum file or directory scopes to return. Above this, Bifrost groups reached files into directory scopes. |

Output: `changed_callables` (`before`, `after`, `changes` with `edited`,
`introduced`, `deleted`, `moved`, `signature_changed`; each symbol has
`in_test_context`), `test_scopes` (`path`, `kind` of `file` or `directory`,
`reached_file_count`, `covered_analyzable_file_count`, minimum and maximum
dependency distance, `sample_reached_files`), and `analysis`.

Completeness, in `analysis` (which also has `mode: "file_imports"`):
`graph_completion` (`complete` or `incomplete`);
`incomplete_reasons` (`target_graph_cancelled`, `base_graph_cancelled`,
`compilation_scope_unresolved`, `unresolved_changed_paths`,
`unresolved_base_paths`); `paths_outside_file_graph` (changed paths the graph
cannot model, such as build or data files); `unresolved_changed_paths`;
`base_recovery` (`not_needed`, `complete`, `cancelled`);
`reached_test_file_count` (exact, even when scopes are grouped);
`analyzer_changed_test_paths`; and `unavailable_removed_test_count`. Zero
reached tests is not proof that no test applies when
`paths_outside_file_graph` is not empty.

### cyclomatic_complexity

Compare cyclomatic complexity of functions that the diff introduces or edits.

| Argument | Type | Required | Default | Meaning |
| --- | --- | --- | --- | --- |
| `base`, `target` | string | No | See above | Endpoints. |
| `include_tests` | boolean | No | `false` | Include functions in test code. |

Output: `summary` (`introduced`, `edited`, `increased`, `decreased`,
`unchanged`), `functions` (`change` of `introduced` or `edited`, `before`,
`after` with `complexity`, and `delta`), and `analysis`
(`paths_outside_analysis`, `unresolved_changed_paths`). Deleted functions and
pure moves are omitted.

### missing_tests

Find introduced or changed production functions with no structured call path
from test code.

| Argument | Type | Required | Default | Meaning |
| --- | --- | --- | --- | --- |
| `base`, `target` | string | No | See above | Endpoints. |

Output: `missing_functions` (searches that finished with no path from tests),
`indeterminate_functions` (searches that did not finish; each has
`incomplete_reasons`), and `analysis` (`mode`, `file_graph_completion`,
`exact_usage_completion`, `candidate_function_count`,
`reached_function_count`, `missing_function_count`,
`indeterminate_function_count`, `paths_outside_file_graph`,
`unresolved_changed_paths`, `incomplete_reasons`).

Incomplete reasons: `target_graph_cancelled`, `compilation_scope_unresolved`,
`unresolved_changed_path`, `changed_function_unresolved`, `usage_cancelled`,
`usage_time_budget`, `usage_candidate_files`, `usage_source_bytes`,
`usage_callsites`, `usage_response_budget`, `usage_resolution_candidates`,
`usage_target_not_found`, `usage_target_ambiguous`, `usage_analysis_failure`,
`usage_analysis_incomplete`, `unproven_references`,
`usage_site_without_enclosing_declaration`, `unresolved_changed_target`,
`open_binding_frontier`, `unsupported_binding_boundary`,
`unproven_binding_edge`, `reference_graph_cancelled`,
`reference_graph_stale`. Only `missing_functions` supports "no test reaches
this function", and only as static evidence, not runtime coverage.

### score_diff

Return raw maintenance-cost features for a diff, with no weights and no single
score.

| Argument | Type | Required | Default | Meaning |
| --- | --- | --- | --- | --- |
| `base`, `target` | string | No | See above | Endpoints. |

Output: `geometry` (symbol and file counts, insertions, deletions,
`edit_clusters`, mean and maximum directory distance), `coordination`
(external caller sites per signature change, added and removed call weight,
`unattributed_call_edge_changes`, `dispatch_extensible_edited_symbols`),
`verification` (`changed_production_symbols`,
`without_direct_test_reference`, `untested_fraction`, `unresolved_symbols`),
`baseline` (cognitive complexity before, after, delta, and maximum after), and
`excluded` (binary and unparseable files). `verification.unresolved_symbols`
lists symbols whose reference scan did not finish. Test symbols and edges are
always included. The first call builds an analyzer for the whole target
revision. Its internal call-edge facts retain the full changed-file semantics
used by the maintenance features; incomplete full-file features remain
best-effort rather than being blanket-suppressed.

## extended toolset

### query_code

Run a structural query written as canonical JSON `CodeQuery`, or a saved
`.rql` or `.json` file.

| Argument | Type | Required | Default | Bounds | Meaning |
| --- | --- | --- | --- | --- | --- |
| `query_file` | string | No | - | File up to 64 KiB | Workspace-relative `.rql` or `.json` file. When present, no other argument is allowed. |
| `schema_version` | string | No | `"1"` | `"1"` only | Query schema version. |
| `match`, `occurrences`, `scopes`, `bindings`, `paths` | object | One seed or one set operation is required | - | - | Query seed. Exactly one seed kind, or one of `union`, `intersect`, `except`. |
| `union`, `intersect`, `except` | array of query plans | See above | - | 2 to 16 branches | Combine typed branches. |
| `inside`, `inside_decl`, `not_inside` | object | No | - | - | Containment constraints on `match`. |
| `languages` | array of strings | No | All | Up to 32 | Language filter. |
| `where` | array of globs, or array of glob groups | No | Whole workspace | Up to 128 entries; 1,024 bytes per glob | Path scope. A flat list is OR; a list of lists is AND between groups and OR within a group. |
| `steps` | array of step objects | No | - | Up to 16 | Typed transformations. |
| `limit` | integer | No | `100` | 1 to 1000 | Maximum terminal results after deduplication. |
| `result_detail` | `compact` or `full` | No | `compact` | - | `full` adds match IDs, column ranges, decorator ranges, and capture ranges. |
| `execution_mode` | `results`, `explain`, `profile` | No | `results` | - | Return results, explain the plan without running it, or run it with an operator profile. |

The full vocabulary of seeds, patterns, kinds, roles, and steps is on
[CodeQuery Reference](/reference/code-query/). The `steps` description in
`tools/list` also lists every step this build accepts. MCP does not accept
inline RQL text.

Output: `results` (each with `result_type`, `path`, `start_line`, `end_line`,
`kind`, `language`, and other fields for the result type), `truncated`, and
`diagnostics` (`code`, `impact`, `language`, `message`). `truncated: true` or
a diagnostic with an incomplete impact means the result is a subset. See
[Explain and Profile CodeQuery](/code-query-explain-profile/) for the other
execution modes.

### list_policies

Return the built-in policy catalog. It takes no arguments and does not build
an analyzer.

Output: `schema_version` and `packs`. Each pack has `id`, `name`, `version`,
`description`, `schema_version`, and `policies`. Each policy has `id`,
`path`, `category`, `activation` (`default` or `opt-in`),
`supported_languages`, `required_capabilities`, `authored_hash`,
`resolved_semantic_hash`, `severity_rationale`, and `remediation`.
`bifrost --list-policies` prints the same catalog. See
[Policies Reference](/reference/policies/).

### run_policy

Evaluate built-in policies and workspace `.rqlp` files against the active
workspace snapshot.

| Argument | Type | Required | Default | Bounds | CLI flag | Meaning |
| --- | --- | --- | --- | --- | --- | --- |
| `policy_packs` | array of strings | One selector or `policy_files` is required | - | 1 to 256 items; 256 bytes each; no duplicates | `--policy-pack` | Built-in pack IDs. |
| `policy_categories` | array of strings | As above | - | As above | `--policy-category` | Built-in categories. |
| `policy_ids` | array of strings | As above | - | As above | `--policy-id` | Built-in policy IDs. The only way to select an opt-in policy. |
| `policy_files` | array of strings | As above | - | 1 to 256 items; 1,024 bytes each; no duplicates | `--policy-file` | Workspace-relative `.rqlp` files, evaluated in the same batch. |
| `evaluation_date` | string `YYYY-MM-DD` | Yes | - | - | `--evaluation-date` | UTC date for suppression expiry. |
| `fail_on` | `never`, `finding`, `note`, `warning`, `error` | No | `warning` | - | `--fail-on` | Finding threshold for `status`. `finding` includes unrated findings. |
| `suppression_file` | string | No | `.bifrost/suppressions.json`, `.bifrost/suppressions.private.json`, and `.bifrost/suppressions.local.json`, read in that order | 1 to 1,024 bytes | `--suppressions-file` | Accepted-finding file. When set, it replaces all three default files. |
| `baseline_file` | string | No | `.bifrost/baseline.json` | 1 to 1,024 bytes | `--baseline-file` | Bulk-acceptance baseline file. |
| `scope_file` | string | No | `.bifrost/policy-scope.json` | 1 to 1,024 bytes | `--scope-file` | Directory-scope file. |
| `diff_base` | string | No | - | 1 to 256 bytes | `--diff-base` | Git revision. Bifrost also evaluates that revision, labels each finding new or persisting, and only new findings count toward `fail_on`. |
| `incremental` | boolean | No | `true` | - | `--no-incremental` sets false | Reuse verified policy units from the analyzer cache. Findings and status are the same either way. |
| `include_stage_timings` | boolean | No | `false` | - | `--policy-timings` (CLI reports per-policy time instead) | Add a `stage_timings` field with wall-clock time per stage. |

Selector rules: values within one selector array form a union. Different
selector arrays intersect: a built-in policy runs only when it matches every
array you supplied. A combination that matches no policy is an invalid-params
error. An opt-in policy runs only when `policy_ids` names it. Unknown pack,
category, or ID values are invalid-params errors. No other property is
allowed.

Output: `status` (`clean`, `finding`, `unreliable`), `exit_status` (`0`, `1`,
`2`), `report` (the schema-5 policy report), `request_correlation_id`
(`sha256:` of the JSON-RPC request ID), and `stage_timings` when requested.
Each run in `report.runs` has a `completion` state; see
[Agent Result Safety](/agent-result-safety/). With no budget configured, a
synchronous call has 240 seconds. Run it as an MCP Task for a longer window.

### explain_policy

Explain one policy's result. It returns no status and no exit code.

| Argument | Type | Required | Default | Bounds | Meaning |
| --- | --- | --- | --- | --- | --- |
| `policy_packs`, `policy_categories`, `policy_ids`, `policy_files` | array of strings | One is required | - | Exactly 1 item each | The selection must resolve to exactly one policy. |
| `finding_id` | string | Exactly one of `finding_id`, `candidate`, `near_misses` | - | 64 lowercase hex characters | Why this retained finding exists. |
| `candidate` | object | As above | - | - | Why this source position produced no finding. Fields: `path` (1 to 1,024 bytes, required), `byte_start` (required), `byte_end` (exclusive; omit for a point). |
| `near_misses` | object | As above | - | - | Which subjects came closest. Set exactly one of `candidates` (1 to 64 positions, same shape as `candidate`) or `enumerate_from_policy_seed: true`. `max_candidates` (1 to 64, default 16) and `max_executions` (1 to 64, default 16) bound the work. |
| `workspace_generation` | string | No | - | 64 lowercase hex characters | Refuse instead of answering if the workspace has changed since this generation. |

Output: a `bifrost_policy_explanation/v2` document for `finding_id` and
`candidate`, or a `bifrost_policy_near_miss/v1` document for `near_misses`.
Every node has an outcome of `satisfied`, `failed`, or `unknown`; `unknown`
is never evidence of absence. Every answer includes `workspace_generation`.
`finding_id` works for match, taint, typestate, assertion, and flow policies;
`candidate` and `near_misses` work for match and assertion policies. See
[Static-Analysis Policies](/static-analysis-policies/).

### get_symbol_locations

Return file paths and line ranges for known symbols.

| Argument | Type | Required | Default | Bounds | Meaning |
| --- | --- | --- | --- | --- | --- |
| `symbols` | array of strings | Yes | - | Up to 64 items; 4,096 bytes each; 65,536 bytes in total | Symbol names, or file paths or globs. |

Output: `locations` (`symbol`, `path`, `start_line`, `end_line`, `loc`) and
`not_found`.

### get_symbol_ancestors

Return ancestor classes of known classes, nearest parent first. Arguments are
the same as for `get_symbol_locations`.

Output: `ancestors` (per input: `symbol` and its `ancestors`), `not_found`,
and `ambiguous`.

### most_relevant_files

Rank files related to seed files by imports, Git history, and file structure.

| Argument | Type | Required | Default | Bounds | Meaning |
| --- | --- | --- | --- | --- | --- |
| `seed_file_paths` | array of strings | Yes | - | - | Seed files. |
| `seed_weights` | array of numbers | No | `1.0` per seed | Same length as `seed_file_paths`; each greater than 0 | Weight per seed, by index. |
| `ranking_mode` | `cascade`, `history_imports`, `usage_graph`, `usage_graph_exact` | No | `cascade` | - | `cascade` uses tiers of test and source mirrors, shared basenames, Git co-edits, directory membership, and import adjacency. `history_imports` ranks by Git history, then imports. `usage_graph` runs PageRank on the file graph. `usage_graph_exact` ranks by the symbol-level call graph. |
| `recency_half_life` | number or `null` | No | `250` | Greater than 0 | Git recency half-life in commits. `null` weights all commits equally. |
| `limit` | integer | No | `20` | 0 or more | Maximum files to return. |

Output: `files` (`path`, and `test` of `test`, `test_support`, `production`,
or `ambiguous`), `not_found`, `ranking_mode_used`, and `complete`. When a
graph mode is cancelled or runs out of time, `complete` is false and the
ranking falls back to history and imports.

## text toolset

These tools read files directly. `.bifrostignore` does not hide files from
them.

### get_file_contents

| Argument | Type | Required | Default | Bounds | Meaning |
| --- | --- | --- | --- | --- | --- |
| `file_paths` | array of strings | Yes | - | - | Project-relative or absolute paths, or Git history paths such as `HEAD~2:src/main.rs`. |

Output: `files` (`path`, `content`, `total_lines`, `truncated`, and
`head_lines` and `tail_lines` when truncated), `not_found`, and
`ambiguous_paths` when a path matches more than one file. A file longer
than 50 lines returns only its first 25 and last 25 lines, with an omission
marker between them. Lines longer than 2,048 bytes are cut. Use
`get_symbol_sources` or `search_file_contents` to read the middle of a long
file.

### search_file_contents

| Argument | Type | Required | Default | Bounds | Meaning |
| --- | --- | --- | --- | --- | --- |
| `patterns` | array of strings | Yes | - | - | Regular expressions. A line matches when any pattern matches. |
| `file_path` | string | No | Whole workspace | - | File, directory, or glob that limits the search. |
| `context_lines` | integer | No | `2` | 0 or more; values above 20 are treated as 20 | Lines of context before and after each match. |
| `case_insensitive` | boolean | No | `false` | - | Ignore case. |

Output: `matches` (per file: `path`, `truncated`, and `matches` with `line`,
`text`, `before`, `after`), `truncated`, `invalid_patterns`,
`unmatched_paths`, and `ambiguous_paths`. The last two appear only when not
empty.

Limits: 50 matches per file, 500 matches in total, files up to 5 MiB and
200,000 lines, and binary files are skipped. `truncated` is true when a limit
removed matches.

### find_files_containing

| Argument | Type | Required | Default | Bounds | Meaning |
| --- | --- | --- | --- | --- | --- |
| `patterns` | array of strings | Yes | - | - | Regular expressions. A file matches when any pattern matches. |
| `limit` | integer | No | `50` | 1 or more | Maximum files to return. |
| `case_insensitive` | boolean | No | `false` | - | Ignore case. |

Output: `files` (paths), `truncated`, and `invalid_patterns`. Binary files
and files that `.gitignore` excludes are skipped.

## slopcop toolset

These tools return a Markdown `report`. Every tool except
`analyze_git_hotspots` also returns a `truncated` flag, which is true when a
count limit such as `max_findings` or `max_files` removed output.
`analyze_git_hotspots` states truncation inside the report text.
For the integer knobs below, a value of 0 or less (or less than 0, where the
table says so) uses the default.

### compute_cyclomatic_complexity

| Argument | Type | Required | Default | Meaning |
| --- | --- | --- | --- | --- |
| `file_paths` | array of strings | Yes | - | Files to analyze. |
| `threshold` | integer | No | `10` | Flag functions whose complexity exceeds this value. |

The score is 1 plus each `if`, `while`, `for`, `switch`, `case`, `catch`,
`&&`, `||`, and `?` in the function.

### compute_cognitive_complexity

| Argument | Type | Required | Default | Meaning |
| --- | --- | --- | --- | --- |
| `file_paths` | array of strings | Yes | - | Files to analyze. |
| `threshold` | integer | No | `15` | Flag functions whose cognitive complexity exceeds this value. |

Supports Java, Python, Rust, Ruby, Go, C and C++, JavaScript and JSX,
TypeScript and TSX, PHP, Scala, and C#.

### report_comment_density_for_code_unit

| Argument | Type | Required | Default | Meaning |
| --- | --- | --- | --- | --- |
| `fq_name` | string | Yes | - | Fully qualified name of one symbol. |
| `max_lines` | integer | No | `120` | Maximum output lines. |

### report_comment_density_for_files

| Argument | Type | Required | Default | Meaning |
| --- | --- | --- | --- | --- |
| `file_paths` | array of strings | Yes | - | Files to analyze. |
| `max_top_level_rows` | integer | No | `60` | Maximum declaration rows across all files. |
| `max_files` | integer | No | `25` | Maximum files. |

### report_exception_handling_smells

| Argument | Type | Required | Default | Meaning |
| --- | --- | --- | --- | --- |
| `file_paths` | array of strings | Yes | - | Files to analyze. |
| `min_score` | integer | No | `4` | Minimum score to report. |
| `max_findings` | integer | No | `80` | Maximum findings. |
| `generic_throwable_weight` | integer | No | `5` | Weight for catching `Throwable`. A value below 0 uses the default. |
| `generic_exception_weight` | integer | No | `3` | Weight for catching `Exception`. A value below 0 uses the default. |
| `generic_runtime_exception_weight` | integer | No | `2` | Weight for catching `RuntimeException`. A value below 0 uses the default. |
| `empty_body_weight` | integer | No | `5` | Weight for an empty handler. A value below 0 uses the default. |
| `comment_only_body_weight` | integer | No | `4` | Weight for a handler with only comments. A value below 0 uses the default. |
| `small_body_weight` | integer | No | `2` | Weight for a small handler. A value below 0 uses the default. |
| `log_only_body_weight` | integer | No | `2` | Weight for a handler that only logs. A value below 0 uses the default. |
| `small_body_max_statements` | integer | No | `2` | Most statements in a small handler. A value below 0 uses the default. |
| `meaningful_body_credit_per_statement` | integer | No | `1` | Credit subtracted per handler statement. A value below 0 uses the default. |
| `meaningful_body_statement_threshold` | integer | No | `6` | Most statements that earn credit. A value below 0 uses the default. |

Supports Java, Go, C++, JavaScript and JSX, TypeScript and TSX, Python, Rust,
PHP, Scala, C#, Ruby, and Kotlin. C is not supported.

### analyze_git_hotspots

| Argument | Type | Required | Default | Meaning |
| --- | --- | --- | --- | --- |
| `since_days` | integer | No | `7` | Window start, in days before now, when `since_iso` is empty. |
| `since_iso` | string | No | - | ISO-8601 start instant. Overrides `since_days`. |
| `until_iso` | string | No | No end | ISO-8601 end instant (exclusive). |
| `max_commits` | integer | No | `500` | Maximum commits to read; at most 5,000. |
| `max_files` | integer | No | `75` | Maximum files to return, by churn; at most 500. |

### report_test_assertion_smells

| Argument | Type | Required | Default | Meaning |
| --- | --- | --- | --- | --- |
| `file_paths` | array of strings | Yes | - | Files to analyze. |
| `min_score` | integer | No | `4` | Minimum score to report. |
| `max_findings` | integer | No | `80` | Maximum findings. |
| `no_assertion_weight` | integer | No | `5` | Weight for a test with no assertions. A value below 0 uses the default. |
| `tautological_assertion_weight` | integer | No | `6` | Weight for a self-comparison. A value below 0 uses the default. |
| `constant_truth_weight` | integer | No | `4` | Weight for an assertion such as `assertTrue(true)`. A value below 0 uses the default. |
| `constant_equality_weight` | integer | No | `4` | Weight for an assertion such as `assertEquals(1, 1)`. A value below 0 uses the default. |
| `nullness_only_weight` | integer | No | `2` | Weight for null checks only. A value below 0 uses the default. |
| `shallow_assertion_only_weight` | integer | No | `2` | Weight for a test whose assertions are all shallow. A value below 0 uses the default. |
| `overspecified_literal_weight` | integer | No | `2` | Weight for an exact large literal in an assertion. A value below 0 uses the default. |
| `anonymous_test_double_weight` | integer | No | `3` | Weight for an inline anonymous test double. A value below 0 uses the default. |
| `repeated_anonymous_test_double_weight` | integer | No | `5` | Weight for repeated anonymous test doubles in one file. A value below 0 uses the default. |
| `large_literal_length_threshold` | integer | No | `120` | Literal length that counts as large. A value below 0 uses the default. |
| `meaningful_assertion_credit` | integer | No | `1` | Credit subtracted per meaningful assertion. A value below 0 uses the default. |
| `meaningful_assertion_credit_cap` | integer | No | `4` | Most assertions that earn credit. A value below 0 uses the default. |

This tool also returns `structured` (published `outputSchema`): `schema_id`
`bifrost.quality.findings`, `schema_version`, `finding_kind:
"test_assertion"`, `findings`, `parameters`, `completion`
(`input_complete`, `analysis_complete`, `retention_complete`), and
`truncation` (`requested_max_findings`, `applied_max_findings`,
`retained_findings`, `omitted_findings`). The report is complete only when
all three completion flags are true and `omitted_findings` is 0.

### report_structural_clone_smells

| Argument | Type | Required | Default | Meaning |
| --- | --- | --- | --- | --- |
| `file_paths` | array of strings | Yes | - | Files to analyze. |
| `min_score` | integer | No | `60` | Minimum score to report. |
| `max_findings` | integer | No | `80` | Maximum findings. |
| `min_normalized_tokens` | integer | No | `12` | Minimum normalized tokens for a clone candidate. |
| `shingle_size` | integer | No | `2` | Token shingle size. |
| `min_shared_shingles` | integer | No | `3` | Minimum shared shingles before Bifrost compares candidates. |
| `ast_similarity_percent` | integer | No | `70` | Minimum syntax-tree similarity. |

This tool returns the same `structured` object as
`report_test_assertion_smells`, with `finding_kind: "structural_clone"`.

### report_long_method_and_god_object_smells

| Argument | Type | Required | Default | Meaning |
| --- | --- | --- | --- | --- |
| `file_paths` | array of strings | Yes | - | Files to analyze. |
| `max_findings` | integer | No | `20` | Maximum findings. |
| `max_files` | integer | No | `25` | Maximum files. |
| `long_method_span_lines` | integer | No | `80` | Function length that counts as long. |
| `god_object_span_lines` | integer | No | `300` | Type length that counts as a god object. |
| `god_object_functions` | integer | No | `15` | Function count that counts as a god object. |
| `god_object_direct_children` | integer | No | `20` | Direct member count that counts as a god object. |
| `helper_sprawl_functions` | integer | No | `10` | Function count that counts as helper sprawl. |
| `helper_sprawl_workflow_lines` | integer | No | `60` | Workflow size that triggers helper-sprawl scoring. |
| `high_complexity_threshold` | integer | No | `10` | Cyclomatic complexity that counts as high. |

### report_dead_code_and_unused_abstraction_smells

Find likely dead Rust declarations and abstractions with only one caller.

| Argument | Type | Required | Default | Meaning |
| --- | --- | --- | --- | --- |
| `file_paths` | array of strings | Yes | - | Files to scan. Pass `[]` to discover candidates across the workspace, up to `max_input_files`. |
| `fq_names` | array of strings | No | - | Fully qualified Rust symbols to check. |
| `min_score` | integer | No | `8` | Minimum score to report. |
| `max_findings` | integer | No | `40` | Maximum findings. |
| `max_input_files` | integer | No | `25` | Maximum files to scan for candidates. |
| `max_candidate_symbols` | integer | No | `200` | Maximum candidate symbols. |
| `max_usage_candidate_files` | integer | No | `1000` | Maximum candidate files per usage query. |
| `max_usages_per_symbol` | integer | No | `1` | Usage hits before a symbol is skipped as inconclusive; at most 1. |

Ambiguous results and limit hits are reported as skipped evidence, not as
findings.

### report_secret_like_code

Scan non-test text files on the current or default branch, and Git history,
for strings that look like secrets. Findings are redacted.

| Argument | Type | Required | Default | Meaning |
| --- | --- | --- | --- | --- |
| `max_findings` | integer | No | `100` | Maximum findings. |
| `max_commits` | integer | No | `2000` | Maximum commits to read from `HEAD`. |
| `include_history_only` | boolean | No | `false` | Include findings that exist only in history. |
| `include_low_confidence` | boolean | No | `false` | Include short credential-like assignments. |

Output: `report`, `truncated`, `findings`, and `diagnostics`.
