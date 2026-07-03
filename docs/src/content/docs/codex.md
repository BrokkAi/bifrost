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

Start a fresh Codex session after installing the plugin so the MCP server configuration is loaded at startup. Verify the tools by asking Codex to call a lightweight analyzer operation such as `get_summaries` or `search_symbols` against files in the active workspace.

## Manual MCP Entry

Use a manual MCP entry when you want the raw command shape or a different toolset:

```bash
codex mcp add bifrost -- bifrost --root /path/to/project --mcp core
codex mcp list
```

Use an absolute path to the Bifrost binary if `bifrost` is not intentionally installed on the host `PATH`.
