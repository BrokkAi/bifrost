---
title: MCP Server
description: Run Bifrost as a stdio MCP server for code-intelligence tools.
---

Bifrost can run as a stdio MCP server. Always pass an explicit workspace root so the host analyzes the intended repository.

```bash
bifrost --root /path/to/project --mcp core
```

The `--mcp` argument accepts ordered toolset compositions. Combine toolsets with `|`, for example `--mcp symbol|workspace`.

## Toolsets

| Toolset | Tools |
| --- | --- |
| `symbol` | `search_symbols`, `get_symbol_sources`, `get_summaries`, `scan_usages`, `get_definition_by_location`, `get_type_by_location`, `rename_symbol`, `usage_graph`, `analyze_commit` |
| `workspace` | `refresh`, `activate_workspace`, `get_active_workspace` |
| `extended` | `get_symbol_locations`, `get_symbol_ancestors`, `find_filenames`, `list_files`, `most_relevant_files`, `search_git_commit_messages`, `get_git_log`, `get_commit_diff`, `jq`, `xml_skim`, `xml_select` |
| `text` | `get_file_contents`, `search_file_contents`, `find_files_containing` |
| `slopcop` | `compute_cyclomatic_complexity`, `compute_cognitive_complexity`, `report_comment_density_for_code_unit`, `report_exception_handling_smells`, `report_comment_density_for_files`, `analyze_git_hotspots`, `report_test_assertion_smells`, `report_structural_clone_smells`, `report_long_method_and_god_object_smells`, `report_dead_code_and_unused_abstraction_smells`, `report_secret_like_code` |
| `cli` | `contains_tests` |

`core` expands to `symbol|workspace` in the default build, plus `nlp` when Bifrost is built with the opt-in `nlp` feature. `searchtools` expands to every available toolset above in registry order: `symbol|workspace|extended|text|slopcop|cli`, plus `nlp` when enabled.

With the opt-in `nlp` feature, the `nlp` toolset adds `semantic_search`. It is only advertised for git workspaces. `semantic_search_status` is accepted for diagnostics but intentionally hidden from the advertised tool list.

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

Use the host-specific pages for Codex, Claude Code, Cursor, and Amp setup flows.
