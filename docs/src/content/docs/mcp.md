---
title: MCP Server
description: Run Bifrost as a stdio MCP server for code-intelligence tools.
---

Bifrost can run as a stdio MCP server. Always pass an explicit workspace root so the host analyzes the intended repository.

```bash
bifrost --root /path/to/project --mcp core
```

The `--mcp` argument accepts ordered toolset compositions. Combine toolsets with `|`, for example:

```bash
bifrost --root /path/to/project --mcp "symbol|workspace"
bifrost --root /path/to/project --mcp "text|extended"
```

By default, `bifrost` uses the current working directory as `--root` and `searchtools` as the MCP toolset. For agent-host configuration, pass both values explicitly so the host analyzes the intended repository.

## Toolsets

| Toolset | Tools |
| --- | --- |
| `symbol` | `search_symbols`, `get_symbol_sources`, `get_summaries`, `scan_usages`, `get_definitions_by_location`, `get_type_by_location`, `rename_symbol`, `usage_graph`, `analyze_commit` |
| `nlp` | `semantic_search` when Bifrost is built with `--features nlp`, the active root is a git repository, and semantic search is available for the session. `semantic_search_status` is accepted for diagnostics but hidden from the advertised tool list. |
| `workspace` | `refresh`, `activate_workspace`, `get_active_workspace` |
| `extended` | `search_ast`, `get_symbol_locations`, `get_symbol_ancestors`, `find_filenames`, `list_files`, `most_relevant_files`, `search_git_commit_messages`, `get_git_log`, `get_commit_diff`, `jq`, `xml_skim`, `xml_select` |
| `text` | `get_file_contents`, `search_file_contents`, `find_files_containing` |
| `slopcop` | `compute_cyclomatic_complexity`, `compute_cognitive_complexity`, `report_comment_density_for_code_unit`, `report_exception_handling_smells`, `report_comment_density_for_files`, `analyze_git_hotspots`, `report_test_assertion_smells`, `report_structural_clone_smells`, `report_long_method_and_god_object_smells`, `report_dead_code_and_unused_abstraction_smells`, `report_secret_like_code` |
| `cli` | `contains_tests` |

`core` expands to `symbol|nlp|workspace`. In a default build, `nlp` contributes no advertised tools, so `core` effectively publishes `symbol|workspace`. `searchtools` expands to every toolset above in registry order: `symbol|nlp|workspace|extended|text|slopcop|cli`.

`searchtools` is the compatibility mode and exposes the full current union of MCP tools in toolset order. Use a smaller composition such as `symbol|workspace` when a host should see fewer tools.

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
      "args": ["--root", "/path/to/project", "--mcp", "core"]
    }
  }
}
```

Use an absolute binary path if `bifrost` is not on the host's `PATH`. Replace `/path/to/project` with the project root syntax supported by your host, or with an absolute project path.

Use the host-specific pages for Codex, Claude Code, Cursor, Zed Agent, Amp, and Antigravity setup flows. The intended external manual client is the official MCP Inspector.
