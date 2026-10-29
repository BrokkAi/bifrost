---
title: CLI Reference
description: Every bifrost subcommand and flag, with values, defaults, the modes each applies to, the conflict rules, and the exit status of every mode.
---

This page lists every subcommand and flag of the `bifrost` executable. For
task-oriented examples, see [CLI](/cli/) and
[Scan a Codebase](/scan-a-codebase/).

The installed binary prints the same information:

- `bifrost --help` lists every mode, flag, MCP toolset, and tool name.
- `bifrost scan --help` lists the scan options.
- `bifrost --help TOOL` prints one tool's description and input schema.
- `bifrost --list-policies` prints the built-in policy catalog.
- `bifrost --list-row-schemas` prints the row-relation catalog that relational
  policies can bind.

No flag has an environment-variable equivalent. Environment variables that
change behavior are listed in [Environment Variables](/reference/environment/).

## How Bifrost Chooses a Mode

Bifrost reads the command line in this order and runs the first mode that
applies:

1. `pack-engine-profile` or `install-semantic-packs` as the first argument runs
   that subcommand.
2. `scan` as the first argument runs the scan subcommand. In any other position,
   `scan` is an unknown argument.
3. Any policy flag anywhere on the command line makes the invocation a policy
   invocation. The policy flags are `--policy`, `--no-builtin-policies`,
   `--policy-file`, `--policy-pack`, `--policy-category`, `--policy-id`,
   `--exclude-policy-id`, `--list-policies`, `--list-row-schemas`, `--format`, `--fail-on`,
   `--suppressions-file`, `--scope-file`, `--baseline-file`, `--accept-current`,
   `--evaluation-date`, `--diff-base`, `--no-incremental`, `--policy-timings`, `--policy-cost-hints`,
   `--output`, `--color`, `--verbose`, `--require-explicit-schema-versions`,
   `--explain-finding`, `--explain-candidate`, `--explain-near-misses`, and
   `--explain-generation`.
4. `--install` registers Bifrost with coding hosts.
5. `--query-file` runs one saved code query.
6. `--tool` runs one tool.
7. `--repl` starts the interactive code-query REPL.
8. Otherwise Bifrost starts an MCP server over stdio. With no arguments, it uses
   the `searchtools` toolset and binds the current directory.

`--help`, `-h`, `--version`, `-V`, and `--build-identity` act as soon as the
parser reaches them. Arguments before them are parsed; arguments after them are
not.

## Subcommands

| Subcommand | Arguments | Output | Meaning |
| --- | --- | --- | --- |
| `bifrost scan [PATH] [OPTIONS]` | One optional project directory; default: current directory | Policy report on stdout; pack witness lines on stderr | Evaluates every default-active built-in policy on `PATH`. |
| `bifrost scan --list-builtin-policies` | None | JSON on stdout | Prints the built-in policy catalog, the same document as `--list-policies`, and runs nothing. |
| `bifrost pack-engine-profile` | None; any argument is an error | One JSON object on stdout | Prints this build's semantic-pack consumer profile: `engine_version`, `build_identity`, `model_set_sha256`, `capability_contract_version`, `schemas`, and `capabilities`. Pack acquisition reads the same profile in-process; this command is for inspection. |
| `bifrost install-semantic-packs BUNDLE_DIR CACHE_ROOT` | Two non-empty paths | One JSON object on stdout | Verifies a native semantic-pack bundle and installs its compatible packs into the catalog `CACHE_ROOT/semantic-pack-catalog.v<N>`. A relative `CACHE_ROOT` is resolved against the current directory. The output names the catalog root and each installed pack's `pack_id`, `pack_version`, and `manifest_digest`. A bundle that installs no compatible pack is an error. |

### Scan Options

`bifrost scan` accepts only these options. Each may appear once.

| Option | Value | Default | Meaning |
| --- | --- | --- | --- |
| `PATH` | Directory | Current directory | Project root to scan. When omitted, the scan prints the directory it uses on stderr. A path that is not a directory is an error. |
| `--list-builtin-policies` | None | Off | Print the built-in catalog as JSON and exit. Cannot be combined with `PATH` or any other option. |
| `--format FORMAT` | `human`, `json`, or `sarif` | `human` | Report format. |
| `--fail-on THRESHOLD` | `never`, `finding`, `note`, `warning`, or `error` | `warning` | Lowest severity of an active finding that makes the scan exit 1. |
| `--evaluation-date YYYY-MM-DD` | UTC calendar date, year 0 to 9999 | Today in UTC | Date used to decide whether suppressions have expired. |
| `--no-incremental` | None | Off | Evaluate every policy in full without reading or writing policy units in the analyzer cache. |
| `--output PATH` | File path | Standard output | Write the report atomically to `PATH`. |
| `--verbose` | None | Off | Print complete finding records, provenance, and audit details. Only with `--format human`. |
| `--color MODE` | `auto`, `always`, or `never` | `auto` | ANSI colors in human output. Only with `--format human`. |
| `-h`, `--help` | None | - | Print the scan help. |

Before the report, a scan writes one `builtin-policy-pack <id>@<version>
policies=<count>` line per shipped pack, one `builtin-policy-catalog
sha256=<digest>` line, and one activation summary line to stderr. The
`policies=<count>` values and the summary count every policy in the catalog,
including opt-in policies that the scan does not run.

A scan reads the default suppression, scope, and baseline files under `PATH`.
It does not accept `--sources`, `--policy-timings`, `--policy-cost-hints`, policy selectors, or
custom document paths. Use the flag surface for those.

## Flags

The **Modes** column uses these names: *MCP* (MCP server), *tool* (`--tool`),
*query* (`--query-file`), *REPL* (`--repl`), *install* (`--install`), and
*policy* (any policy invocation, including listings and explanations). "Once"
means that a second occurrence is an error. "Last wins" means that a later
occurrence replaces the earlier value without an error.

### Workspace and Server

| Flag | Value | Default | Repeat | Modes | Meaning |
| --- | --- | --- | --- | --- | --- |
| `--root DIR` | Directory | Current directory | Last wins | MCP, tool, query, REPL, policy | Workspace root to analyze. With `--mcp` and no `--root`, the server starts without a workspace and waits for the client to supply one. In REPL mode, and in MCP mode without `--mcp`, a missing `--root` makes Bifrost print the directory it uses on stderr. |
| `--workspace NAME=PATH` | Name and directory | - | Repeatable | MCP | Add one named workspace to a single MCP server. The name must start with an ASCII letter or digit and contain only letters, digits, `.`, `_`, and `-`. See [MCP Tools Reference](/reference/mcp-tools/). |
| `--mcp TOOLSETS` | Toolset names joined with `\|`: `searchtools`, `core`, `symbol`, `workspace`, `diff`, `extended`, `text`, `slopcop` | `searchtools` when `bifrost` runs with no mode flag | Last wins | MCP | Run an MCP server over stdio with these toolsets. `core` is `symbol`, `workspace`, and `diff`. `searchtools` is every toolset. |
| `--repl` | None | Off | - | REPL | Start the interactive code-query REPL. |
| `--diff-snapshot-object-dir DIR` | Path to a Git `objects` directory, absolute or relative to the current directory | None | Last wins | MCP, tool | Trusted extra object store for immutable diff-tool endpoints. Bifrost resolves the path and rejects a missing path or a non-directory before it serves requests. |
| `--no-line-numbers` | None | Off | - | MCP, tool, query | Remove line-number prefixes from rendered text. In MCP mode this also changes the `symbol` toolset: `get_definitions_by_reference` and `scan_usages_by_reference` replace `get_declarations_by_location`, `get_definitions_by_location`, and `scan_usages_by_location`. `--tool` and `--query-file` print only structured JSON, so most of their output is unchanged. |
| `--install` | None | Off | Once | install | Register a user-level MCP server named `brokk` with every supported coding host found on `PATH`. See [Install Bifrost](/install/#connect-coding-hosts). |

### One-Shot Tools and Queries

| Flag | Value | Default | Repeat | Modes | Meaning |
| --- | --- | --- | --- | --- | --- |
| `--tool NAME` | Tool name from `bifrost --help` | - | Once | tool | Run one tool and print one JSON object. Every tool in the `searchtools` toolsets is available, plus `classify_test_files`. See [MCP Tools Reference](/reference/mcp-tools/). |
| `--args JSON` | Inline JSON object | `{}` | Last wins | tool | Arguments for `--tool`, in the tool's MCP input shape. File arguments may use `<commit-ish>:<path>`. |
| `--sources PATH` | File, directory, or glob under the root | Whole workspace | Repeatable | tool, policy | Build the workspace from only these files. An explicit source overrides `.bifrostignore`. In policy mode it restricts evaluation to these files. |
| `--query-file PATH` | Workspace-relative `.rql` or `.json` file | - | Once | query | Run one saved CodeQuery through `query_code`. The path must stay inside the workspace after symlinks are resolved. |
| `--workspace-scaled-limits` | None | Off | Once | query | Run `--query-file` with the execution limits that policy evaluation uses, which scale with source volume, instead of the interactive limits. |

### Policy Selection

| Flag | Value | Default | Repeat | Meaning |
| --- | --- | --- | --- | --- |
| `--policy` | None | Off | Once | Enter policy mode without other policy flags. With no `--policy-file` and no selector, Bifrost evaluates every default-active built-in policy. |
| `--policy-file PATH` | Workspace-relative `.rqlp` file whose root is a `(policy ...)` document | None | Repeatable | Evaluate this workspace policy. Any explicit input replaces the built-in default. |
| `--policy-pack ID` | Built-in pack ID: `bifrost.code-smells`, `bifrost.correctness`, `bifrost.security`, `bifrost.effects` | None | Repeatable | Select built-in policies by pack. |
| `--policy-category NAME` | Built-in category: `correctness`, `performance`, `security`, `effects` | None | Repeatable | Select built-in policies by category. |
| `--policy-id ID` | Built-in policy ID from `--list-policies` | None | Repeatable | Select one built-in policy. This is the only way to run an opt-in policy. |
| `--exclude-policy-id ID` | Built-in policy ID from `--list-policies` | None | Repeatable | Skip one built-in policy after the positive selectors resolve. Use it to drop a policy from a pack while the run keeps every other member, including members added later. |
| `--no-builtin-policies` | None | Off | Once | Refuse the built-in default. Requires at least one `--policy-file`. Cannot be combined with the three selectors or `--exclude-policy-id`. |
| `--list-policies` | None | Off | Once | Print the built-in catalog as JSON and exit. |
| `--list-row-schemas` | None | Off | Once | Print the `bifrost_relation_schema/v1` catalog as JSON and exit. |

The pack and category values above are the ones in this build's catalog.
`--list-policies` prints the current list. An unknown pack, category, or ID is
an error with exit status 2.

Built-in selectors combine like this:

- Several values of one selector form a union. `--policy-category correctness
  --policy-category performance` selects both categories.
- Different selectors intersect. `--policy-pack bifrost.security
  --policy-category security` selects security-category policies in that pack.
  A combination that matches no policy is an error with exit status 2.
- A policy whose catalog `activation` is `opt-in` runs only when `--policy-id`
  names it. A pack or category selection, `--policy`, and `scan` skip it.
- `--exclude-policy-id` applies after the selectors above intersect. It needs
  at least one pack, category, or ID selector. Each excluded ID must be a known
  built-in policy that the selectors select, and the exclusion must leave at
  least one policy to run. An unknown ID, an ID the selectors do not select, and
  an exclusion that removes every selected policy are errors.
- A report from a run that selected built-in policies records the shipped
  catalog digest, the selected policy IDs, and the excluded policy IDs under
  `evaluation.builtin_selection`. A run of workspace `--policy-file` inputs alone
  has no such field.
- Selected built-in policies run in catalog order, without duplicates. They
  share one analyzer snapshot, report, and exit status with every
  `--policy-file` input.

### Policy Inputs

| Flag | Value | Default | Repeat | Meaning |
| --- | --- | --- | --- | --- |
| `--suppressions-file PATH` | Workspace-relative JSON file | `.bifrost/suppressions.json`, `.bifrost/suppressions.private.json`, and `.bifrost/suppressions.local.json`, read in that order when present | Once | Read accepted findings from this one file instead of the three default files. |
| `--scope-file PATH` | Workspace-relative JSON file | `.bifrost/policy-scope.json` | Once | Read directory-level acceptances and root exclusions from this file. |
| `--baseline-file PATH` | Workspace-relative JSON file | `.bifrost/baseline.json` | Once | Read, and with `--accept-current` write, the bulk-acceptance baseline. |
| `--evaluation-date YYYY-MM-DD` | UTC calendar date, year 0 to 9999 | Today in UTC | Once | Date used for suppression expiry. A suppression stays current on its `expires_at` date. |
| `--require-explicit-schema-versions` | None | Off | - | Reject a policy, endpoint, or RQL dependency that omits its schema version. |

The field tables of these files are on [Policies Reference](/reference/policies/).

### Policy Output and Gating

| Flag | Value | Default | Repeat | Meaning |
| --- | --- | --- | --- | --- |
| `--format FORMAT` | `human`, `json`, or `sarif` | `human` | Once | Report format. All three come from one canonical report. |
| `--verbose` | None | Off | Once | Human output only: print every finding, including applied suppressions, with provenance and audit details. |
| `--color MODE` | `auto`, `always`, or `never` | `auto` | Once | Human output only. `auto` uses ANSI colors only when the report goes to stdout (no `--output`), stdout is a terminal, `NO_COLOR` is unset, and the platform is not Windows. |
| `--output PATH` | File path | Standard output | Once | Write the report to a temporary file beside `PATH`, synchronize it, and atomically replace `PATH`. |
| `--fail-on THRESHOLD` | `never`, `finding`, `note`, `warning`, or `error` | `warning` | Once | Lowest severity of an active unsuppressed finding that makes a complete run exit 1. `finding` includes unrated findings. |
| `--diff-base REV` | Any revision `git rev-parse` accepts | None | Once | Also evaluate the committed content of `REV`, classify findings as new or persisting, and gate only on new findings. |
| `--no-incremental` | None | Off | Once | Evaluate every policy in full without reading or writing policy units in the analyzer cache. |
| `--accept-current` | None | Off | Once | Run the selected policies and write every current strong finding identity to the baseline file. Writes only when the run is reliable and complete and no suppression record is orphaned. |
| `--policy-cost-hints <path>` | JSON file path | Empty | Once | Object from non-empty policy IDs to non-negative integer milliseconds, at most 256 entries. Parallel batches start unknown policies first, then hinted policies from longest to shortest; hints never change the report. |
| `--policy-timings` | None | Off | Once | Add each policy's elapsed time to the report's work metrics (`evaluation.elapsed_ms`, plus `units.prefetch_ms`, `units.verify_ms`, `units.lookup_replay_ms` and `units.recompute_ms` for a policy that ran unit by unit). Also write one `bifrost: policy stage timings {...}` line to stderr whose JSON has `kind` `bifrost.policy-stage-timings` and `schema_version` `1`. |

### Policy Explanation

These flags ask a question about one policy. They print one JSON document.

| Flag | Value | Default | Repeat | Meaning |
| --- | --- | --- | --- | --- |
| `--explain-finding ID` | Finding ID as a policy report prints it | - | Once | Explain why the selected policy produced this finding. |
| `--explain-candidate PATH:BYTE_START[-BYTE_END]` | Workspace path and byte offsets; the last `:` separates the path | - | Once | Explain why the selected policy did not report this exact position. |
| `--explain-near-misses N` | Integer from 1 to 64 | - | Once | Rank the `N` subjects in the policy's own seed scope that came closest to matching. A policy whose seed declares no kind, language, or path scope is refused. |
| `--explain-generation HEX` | `workspace_generation` value from an earlier answer | - | Once | Answer only if the workspace still has this generation; otherwise exit 2. Requires one of the three flags above. |

The selection must resolve to exactly one policy, given by `--policy-file` or
a built-in selector.

### Help and Identity

| Flag | Value | Meaning |
| --- | --- | --- |
| `-h`, `--help [TOOL]` | Optional tool name; a following argument that starts with `-` is not a topic | Print the general help, or one tool's description and parameters. An unknown tool is an error. |
| `-V`, `--version` | None | Print `bifrost <version>`, then one `builtin-policy-pack <id>@<version> policies=<count>` line per shipped pack, then `builtin-policy-catalog sha256=<digest>`. |
| `--build-identity` | None | Print the embedded source identity: the source commit, with a `-dirty` suffix and digest when the build tree had local changes. |

### Removed and Deprecated Flags

| Flag | Behavior |
| --- | --- |
| `--server MODE` | Deprecated alias for `--mcp MODE`. Prints `bifrost: --server is deprecated; use --mcp <toolsets>` on stderr, then behaves like `--mcp MODE`. `bifrost --help` does not list it. |
| `--lsp` | Prints `the LSP server has moved out of this repository` and exits 1. The language server is the separate `bifrost-lsp` program. [LSP Server](/lsp/) describes it and the earlier releases that still accept `--lsp`. |
| `--server lsp` | Prints the `--server` deprecation warning, then the same message as `--lsp`, and exits 1. |

## Conflict Rules

Bifrost rejects these combinations before it does any work:

| Combination | Result |
| --- | --- |
| Any policy flag with `--install`, `--query-file`, `--tool`, `--args`, `--mcp`, `--repl`, `--no-line-numbers`, `--workspace-scaled-limits`, or `--diff-snapshot-object-dir` | Error, exit 2 |
| `--list-policies` with `--list-row-schemas` | Error, exit 2 |
| A listing flag with any other policy flag or `--sources` | Error, exit 2 |
| Two of `--explain-finding`, `--explain-candidate`, `--explain-near-misses` | Error, exit 2 |
| An explanation flag with `--format`, `--fail-on`, `--suppressions-file`, `--scope-file`, `--baseline-file`, `--accept-current`, `--evaluation-date`, `--diff-base`, `--policy-timings`, `--policy-cost-hints`, `--verbose`, `--color`, or `--sources` | Error, exit 2 |
| An explanation flag with no `--policy-file` and no built-in selector | Error, exit 2 |
| `--explain-generation` without an explanation flag | Error, exit 2 |
| `--no-builtin-policies` with a built-in selector, or without `--policy-file` | Error, exit 2 |
| `--verbose` or `--color` with `--format json` or `--format sarif` | Error, exit 2 |
| `--accept-current` with `--fail-on` or `--diff-base` | Error, exit 2 |
| `--install` with any other flag | Error, exit 1 |
| `--query-file` with `--tool`, `--args`, `--mcp`, `--repl`, `--diff-snapshot-object-dir`, or `--sources` | Error, exit 1 |
| `--workspace-scaled-limits` without `--query-file` | Error, exit 1 |
| `--tool` with `--mcp` or `--repl` | Error, exit 1 |
| `--sources` without `--tool` or a policy flag | Error, exit 1 |
| `--repl` with `--mcp` | Error, exit 1 |
| `--repl` with `--diff-snapshot-object-dir` | Error, exit 1 |
| `--workspace` with `--root` or `--diff-snapshot-object-dir`, or without `--mcp` | Error, exit 1 |
| A scan option outside the scan option list, a second `PATH`, or `--list-builtin-policies` with anything else | Error, exit 2 |

## Exit Status

| Mode | 0 | 1 | 2 |
| --- | --- | --- | --- |
| `bifrost scan` | The run was reliable, no active unsuppressed finding met `--fail-on`, and no suppression record is orphaned. Also a build that ships no policy packs. | The run was reliable, and at least one active unsuppressed finding met `--fail-on` or at least one suppression record is orphaned. | The run was unreliable: for example, a policy was inconclusive, unsupported, failed, or cancelled, or there was a suppression, scope, baseline, schema, output, or argument error. |
| Policy evaluation (`--policy`, `--policy-file`, selectors) | Same as scan. | Same as scan. | Same as scan. Status 2 takes precedence over status 1. |
| `--accept-current` | The run was reliable and complete, and the baseline was written. | At least one suppression record is orphaned, so nothing was written. | The run was not reliable and complete, so nothing was written; or the write failed. |
| `--diff-base` | As policy evaluation, counting only new findings. | As policy evaluation, counting only new findings. | As policy evaluation; also when the root is not in a Git repository or `REV` does not resolve. |
| `--list-policies`, `--list-row-schemas` | The catalog was printed. | Not used. | Argument error, or the catalog could not be loaded. |
| `--explain-finding`, `--explain-candidate`, `--explain-near-misses` | An answer was printed, including an outcome of `failed` or `unknown` and an empty ranking. | Not used. | No answer could be produced, the generation did not match, the output write failed, or an argument error. |
| `--tool` | The tool succeeded. | The tool failed, or an argument error. | Not used. |
| `--query-file` | The query ran. | The query failed, or an argument error. | Not used. |
| MCP server, `--repl` | The session ended normally. | Startup failed, including an invalid `BIFROST_MCP_LOG` or `BIFROST_MCP_FILE_WATCHER` value, or an argument error. | Not used. |
| `--install` | Every host found was registered. | No supported host was found, or registration failed for at least one host. | Not used. |
| `pack-engine-profile`, `install-semantic-packs` | The command succeeded. | Any error. | Not used. |
| `--help`, `--version`, `--build-identity` | Output was printed. | Unknown tool topic, or `--version` could not load the policy catalog. | Not used. |

Any argument error in a command line that contains a policy flag, or that
starts with `scan`, exits 2 rather than 1. For example, `bifrost --tool
search_symbols --format json` exits 2.

On Unix, a `--tool` or `--query-file` run checks every 2 seconds whether its
parent process has exited. If it has, Bifrost cancels the run, waits 20
seconds, and exits with status 3.

`--fail-on never` turns off only the finding threshold. An orphaned
suppression record still gives status 1, and an inconclusive, failed, or
unsupported policy still gives status 2. [Policies Reference](/reference/policies/)
lists every condition that makes a run unreliable.

## Development Helper: `most_relevant_files`

The source repository also builds a `most_relevant_files` binary. Release
packages do not include it. Build it with `cargo build --features devtools --bin most_relevant_files`.

```text
most_relevant_files [--root PROJECT_ROOT] [--recency-half-life COMMITS|none]
  [--ranking-mode cascade|history_imports|usage_graph|usage_graph_exact]
  [--history-only] [--exclude-tests] SEED_FILE...
```

| Argument | Value | Default | Meaning |
| --- | --- | --- | --- |
| `SEED_FILE` | One or more workspace paths | Required | Files to rank related files for. |
| `--root` | Directory | Current directory | Workspace root. |
| `--ranking-mode` | `cascade`, `history_imports`, `usage_graph`, `usage_graph_exact` | `cascade` | Ranking strategy. |
| `--recency-half-life` | Positive number of commits, or `none` | `250` | Half-life of the Git history weight. `none` turns off recency decay. |
| `--history-only` | None | Off | Rank by Git co-change only, without import-graph expansion. |
| `--exclude-tests` | None | Off | Drop files classified as `test` or `test_support` from the printed page. The page can then have fewer than the 100 results it ranks. |

Each output line is `path<TAB>kind`, where `kind` is `test`, `test_support`,
`production`, or `ambiguous`. Errors exit 1.
