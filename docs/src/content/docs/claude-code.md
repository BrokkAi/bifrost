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

## Local Plugin Testing

From the repository root, build Bifrost and start Claude Code with this package directory:

```bash
cargo build --bin bifrost
BIFROST_BINARY_PATH="$(pwd)/target/debug/bifrost" claude --plugin-dir plugins/bifrost-agent
```

Inspect `/plugin` to confirm the `bifrost` metadata loaded, then inspect `/mcp` or ask Claude to call a lightweight analyzer operation such as `get_summaries` or `search_symbols`.

To test the repository as a local Claude Code marketplace, run:

```bash
claude plugin marketplace add "$(pwd)"
claude plugin install brokk@bifrost --scope local
BIFROST_BINARY_PATH="$(pwd)/target/debug/bifrost" claude
```

Start a fresh Claude Code session after installing the plugin so the MCP server configuration is loaded at startup.

## Manual MCP Entry

Use a manual MCP entry when you want the raw command shape or a different toolset:

```bash
claude mcp add --scope user bifrost -- bifrost --root /path/to/project --mcp core
claude mcp list
```

Use an absolute path to the Bifrost binary if `bifrost` is not intentionally installed on the host `PATH`.
