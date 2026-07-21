---
title: Claude Code
description: Install and validate Bifrost in Claude Code.
---

Claude Code can use Bifrost through the Brokk agent plugin or through a manual MCP server entry. The plugin path is preferred because it includes Bifrost skills and a launcher that resolves the Bifrost binary.

## Plugin Install

Add the Brokk marketplace from GitHub, then install Bifrost:

```bash
claude plugin marketplace add BrokkAi/bifrost --sparse .claude-plugin plugins
claude plugin install brokk@bifrost
```

Start a fresh Claude Code session after installing the plugin so the MCP server configuration is loaded at startup.

The plugin automatically registers its packaged MCP server, so do not add a duplicate manual entry. Without an explicit `BIFROST_WORKSPACE_ROOT` or launcher `--root`, Bifrost requests the host-approved project directory through MCP roots and never uses the installed plugin directory as analyzer scope.

## Local Plugin Testing

From the repository root, build Bifrost and start Claude Code with this package directory:

```bash
cargo build --bin bifrost
BIFROST_BINARY_PATH="$(pwd)/target/debug/bifrost" claude --plugin-dir plugins/bifrost-agent
```

Inspect `/plugin` to confirm the `bifrost` metadata loaded, then inspect `/mcp`. The packaged plugin uses `symbol|extended`, so it exposes both symbol navigation and `query_code`.

To test the repository as a local Claude Code marketplace, run:

```bash
claude plugin marketplace add "$(pwd)"
claude plugin install brokk@bifrost --scope local
BIFROST_BINARY_PATH="$(pwd)/target/debug/bifrost" claude
```

Start a fresh Claude Code session after installing the plugin so the MCP server configuration is loaded at startup.

## Can My Agent Run RQL?

Confirm that `query_code` appears in `/mcp` for the fresh session. Then ask Claude to call it once with the inline JSON fields `{"match":{"kind":"declaration"},"limit":1}`. To validate saved RQL, check a workspace file named `bifrost-smoke.rql` containing `(limit 1 (declaration))`, then ask Claude to call `query_code` with `{"query_file":"bifrost-smoke.rql"}`.

The inline call is canonical JSON, not RQL. MCP accepts RQL only from a workspace `.rql` file named by `query_file`. A successful `get_summaries` or `search_symbols` call proves symbol navigation but does not prove that `query_code` is enabled. See [MCP query and RQL availability](/mcp/#query-and-rql-availability) for the full surface matrix and [Agent Result Safety](/agent-result-safety/) before making completeness claims.

## Manual MCP Entry

Use a manual MCP entry instead of the plugin-provided server when you want the raw command shape or a different toolset:

```bash
claude mcp add --scope user bifrost -- bifrost --root /path/to/project --mcp "symbol|extended"
claude mcp list
```

Use an absolute path to the Bifrost binary if `bifrost` is not intentionally installed on the host `PATH`.

Use `--mcp core` only when you intentionally want navigation without `query_code`.
