---
title: MCP Server
description: Run Bifrost as a stdio MCP server for code-intelligence tools.
---

Bifrost can run as a stdio MCP server. Always pass an explicit workspace root so the host analyzes the intended repository. For a coding agent that should navigate symbols and run structural queries, use the same query-capable composition as the packaged Bifrost plugins:

```bash
bifrost --root /path/to/project --mcp "symbol|extended"
```

Use `--mcp core` only for a navigation-focused setup that should not expose `query_code`. The chosen toolset controls whether an agent can query code; installing Bifrost skills does not add tools by itself.

## Query and RQL Availability

RQL is the [Rune Query Language](/rune-query-language/), a human-friendly syntax that compiles to canonical JSON `CodeQuery`. These surfaces do not accept it in the same way:

| Configuration or surface | `query_code` | Inline JSON | Inline RQL | Saved `.rql` |
| --- | --- | --- | --- | --- |
| MCP `core` | No | No | No | No |
| MCP `symbol\|extended` | Yes | Yes | No | Yes, through `query_file` |
| MCP `searchtools` | Yes | Yes | No | Yes, through `query_file` |
| CLI | Yes | `--tool query_code` | REPL | `--query-file` |
| VS Code RQL Play action | Separate LSP path | No | Yes, including unsaved text | Yes |
| Skills without MCP | No tools exposed | No | No | No |

For MCP, call `query_code` with either inline canonical JSON fields or one `query_file` field naming a workspace-relative `.rql` or `.json` file. `query_file` is exclusive: filters, limits, and other query fields must be inside the referenced file. MCP never accepts raw inline RQL text.

The `--mcp` argument accepts ordered toolset compositions. Combine toolsets with `|`, for example:

```bash
bifrost --root /path/to/project --mcp "symbol|workspace"
bifrost --root /path/to/project --mcp "text|extended"
```

By default, `bifrost` uses the current working directory as `--root` and `searchtools` as the MCP toolset. For agent-host configuration, pass both values explicitly so the host analyzes the intended repository.

## Toolsets

| Toolset | Tools |
| --- | --- |
| `symbol` | `search_symbols`, `get_symbol_sources`, `get_summaries`, mode-specific usage and definition lookup tools, `get_type_by_location`, `rename_symbol`, `usage_graph`, `analyze_commit` |
| `nlp` | `semantic_search` when Bifrost is built with `--features nlp`, the active root is a git repository, and semantic search is available for the session. `semantic_search_status` is accepted for diagnostics but hidden from the advertised tool list. |
| `workspace` | `refresh`, `activate_workspace`, `get_active_workspace` |
| `extended` | `query_code`, `get_symbol_locations`, `get_symbol_ancestors`, `find_filenames`, `list_files`, `most_relevant_files`, `search_git_commit_messages`, `get_git_log`, `get_commit_diff`, `jq`, `xml_skim`, `xml_select` |
| `text` | `get_file_contents`, `search_file_contents`, `find_files_containing` |
| `slopcop` | `compute_cyclomatic_complexity`, `compute_cognitive_complexity`, `report_comment_density_for_code_unit`, `report_exception_handling_smells`, `report_comment_density_for_files`, `analyze_git_hotspots`, `report_test_assertion_smells`, `report_structural_clone_smells`, `report_long_method_and_god_object_smells`, `report_dead_code_and_unused_abstraction_smells`, `report_secret_like_code` |
| `cli` | `classify_test_files` |

`core` expands to `symbol|nlp|workspace`. In a default build, `nlp` contributes no advertised tools, so `core` effectively publishes `symbol|workspace`. `searchtools` expands to every toolset above in registry order: `symbol|nlp|workspace|extended|text|slopcop|cli`.

With line numbers enabled, `symbol` advertises `scan_usages_by_location` and `get_definitions_by_location`. With `--no-line-numbers`, it instead advertises `scan_usages_by_reference` and `get_definitions_by_reference`.

`searchtools` is the compatibility mode and exposes the full current union of MCP tools in toolset order. Use `symbol|extended` for the packaged coding-agent surface, or a smaller composition such as `symbol|workspace` when a host should see fewer tools.

Pass `--no-line-numbers` to remove rendered line and line-range prefixes from MCP text previews while keeping `structuredContent` unchanged.

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

## Skills Are Separate

MCP setup makes Bifrost tools available to an agent host. Agent Skills are
separate instructions that teach the host when and how to use those tools. For
hosts that load generic filesystem skills, install Bifrost's default
code-intelligence skills with:

```bash
bifrost --root /path/to/project --install-skills --target project
```

See [CLI](../cli/#install-agent-skills) for `--target global`,
`--skills-root`, `--mode`, `--skill-set`, `--dry-run`, and `--force`.

Use the host-specific pages for Codex, Claude Code, Cursor, OpenCode, Zed Agent,
Amp, and Antigravity setup flows. The intended external manual client is the
official MCP Inspector.
