# Bifrost Agent Plugin

This package installs Bifrost's MCP server configuration as an agent plugin for
Codex and Claude Code. It does not bundle the Bifrost binary or the Brokk host
workflow skills; it installs a launcher that resolves a released Bifrost binary
and makes a code-intelligence subset of the `bifrost` MCP tools discoverable
through each host's plugin system.

The plugin's stable install name is `bifrost`. The Codex UI-facing display name
is `Bifrost for Codex`; Claude Code uses the shared `bifrost` package metadata.

The plugin starts `./bin/bifrost-launcher.mjs --mcp "symbol|extended"`.
The launcher always starts Bifrost with an explicit `--root`, using
`BIFROST_WORKSPACE_ROOT` when set, then a host-provided `--root` or
`--workspace-root`, then the host session working directory.

Binary resolution order is:

1. `BIFROST_BINARY_PATH`, when set.
2. The launcher-managed cache for the pinned Bifrost release.
3. A compatible `bifrost` already on `PATH`, only when
   `BIFROST_LAUNCHER_ALLOW_PATH=1` is set.
4. A checksum-verified GitHub release download into the managed cache.

Set `BIFROST_LAUNCHER_AUTO_INSTALL=0` to disable downloads, or
`BIFROST_LAUNCHER_CACHE_DIR=/path/to/cache` to choose the managed cache
location. `BIFROST_BINARY_PATH` is the preferred local development override
because it bypasses ambient `PATH` lookup. Launcher diagnostics go to stderr so
stdio MCP traffic stays on stdin/stdout.

For local development, build this checkout and point the launcher at the debug
binary:

```bash
cargo build --bin bifrost
BIFROST_BINARY_PATH="$(pwd)/target/debug/bifrost" node plugins/bifrost-agent/bin/bifrost-launcher.mjs --root . --mcp "symbol|extended"
```

## Codex Local Marketplace Install

From the repository root, add this checkout as a local marketplace and install
the Codex plugin:

```bash
codex plugin marketplace add "$(pwd)"
codex plugin add bifrost@bifrost-local
```

For a local checkout build, start Codex with this repository's debug binary
selected explicitly:

```bash
BIFROST_BINARY_PATH="$(pwd)/target/debug/bifrost" codex
```

Start a fresh Codex session after installing the plugin. The plugin-provided
MCP server starts a separate stdio Bifrost process with:

```bash
bifrost --root <resolved-workspace-root> --mcp "symbol|extended"
```

The plugin gives Bifrost up to 60 seconds to start and up to 300 seconds for
individual analyzer tool calls. Large workspaces may need that budget because
Bifrost can build its persisted analyzer on the first real tool call.

The default plugin toolset intentionally omits Bifrost's `workspace` and `text`
MCP toolsets. That keeps local plugin installs focused on analyzer navigation
and avoids giving prompts a built-in way to switch the active workspace or read
arbitrary files through raw text tools. Users who explicitly want the full MCP
surface can still add a manual `codex mcp add` entry for `--mcp searchtools`.

Once the session starts, verify the tools by calling a lightweight analyzer
operation such as `get_summaries` or `search_symbols` against files in the
active workspace.

## Claude Code Local Testing

From the repository root, start Claude Code with this package directory:

```bash
BIFROST_BINARY_PATH="$(pwd)/target/debug/bifrost" claude --plugin-dir plugins/bifrost-agent
```

Inspect `/plugin` to confirm the `bifrost` metadata loaded, then inspect `/mcp`
or ask Claude to call a lightweight analyzer operation such as `get_summaries`
or `search_symbols`.

To test the repository as a local Claude Code marketplace, run:

```bash
claude plugin marketplace add "$(pwd)"
claude plugin install bifrost@bifrost-marketplace --scope local
BIFROST_BINARY_PATH="$(pwd)/target/debug/bifrost" claude
```

Start a fresh Claude Code session after installing the plugin so the MCP server
configuration is loaded at startup.

## Difference From `codex mcp add`

`codex mcp add` or `claude mcp add` registers one MCP server directly in a
user's host configuration. This plugin packages a safer default server shape
behind a marketplace entry, so users can install or remove Bifrost through the
host's plugin flow without hand-editing MCP configuration.

The MCP process created by this plugin is independent from the VS Code language
server process. They may point at the same `bifrost` binary, but each host
starts its own stdio process.
