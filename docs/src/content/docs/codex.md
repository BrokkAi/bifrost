---
title: Codex
description: Install and validate Bifrost in Codex.
---

Codex can use Bifrost through the Brokk agent plugin or through a manual MCP server entry. The plugin path is preferred because it includes Bifrost skills and a launcher that resolves the Bifrost binary.

## Plugin Install

Add the Brokk marketplace from GitHub, then install Bifrost:

```bash
codex plugin marketplace add BrokkAi/bifrost --sparse .agents/plugins --sparse plugins
codex plugin add brokk@bifrost
```

For local development from a checkout, add this repository root instead:

```bash
codex plugin marketplace add "$(pwd)"
codex plugin add brokk@bifrost
```

For a local checkout build, start Codex with the debug binary selected explicitly:

```bash
BIFROST_BINARY_PATH="$(pwd)/target/debug/bifrost" codex
```

Start a fresh Codex session after installing the plugin so the MCP server configuration is loaded at startup. The packaged plugin uses `symbol|extended`, so it exposes both symbol navigation and `query_code`.

## Can My Agent Run RQL?

Confirm that `query_code` appears in the fresh session's Bifrost tool list. Then ask Codex to call it once with the inline JSON fields `{"match":{"kind":"declaration"},"limit":1}`. To validate saved RQL, check a workspace file named `bifrost-smoke.rql` containing `(limit 1 (declaration))`, then ask Codex to call `query_code` with `{"query_file":"bifrost-smoke.rql"}`.

The inline call is canonical JSON, not RQL. MCP accepts RQL only from a workspace `.rql` file named by `query_file`. A successful `get_summaries` or `search_symbols` call proves symbol navigation but does not prove that `query_code` is enabled. See [MCP query and RQL availability](/mcp/#query-and-rql-availability) for the full surface matrix and [Agent Result Safety](/agent-result-safety/) before making completeness claims.

## Manual MCP Entry

Use a manual MCP entry when you want the raw command shape or a different toolset:

```bash
codex mcp add bifrost -- bifrost --root /path/to/project --mcp "symbol|extended"
codex mcp list
```

Use an absolute path to the Bifrost binary if `bifrost` is not intentionally installed on the host `PATH`.

Use `--mcp core` only when you intentionally want navigation without `query_code`.
