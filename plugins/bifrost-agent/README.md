# Bifrost Agent Plugin

This package installs Bifrost's MCP server configuration as an agent plugin for
Codex and Claude Code. It does not bundle the Bifrost binary or the Brokk host
workflow skills; it only makes a code-intelligence subset of the `bifrost` MCP
tools discoverable through each host's plugin system.

The plugin's stable install name is `bifrost`. The Codex UI-facing display name
is `Bifrost for Codex`; Claude Code uses the shared `bifrost` package metadata.

The plugin expects `bifrost` to be available on `PATH`. For local development,
build this checkout and prepend `target/debug` while testing:

```bash
cargo build --bin bifrost
PATH="$(pwd)/target/debug:$PATH" bifrost --root . --tool get_summaries --args '{"targets":["README.md"]}'
```

## Codex Local Marketplace Install

From the repository root, add this checkout as a local marketplace and install
the Codex plugin:

```bash
codex plugin marketplace add "$(pwd)"
codex plugin add bifrost@bifrost-local
```

For a local checkout build, start Codex with this repository's debug binary on
`PATH`:

```bash
PATH="$(pwd)/target/debug:$PATH" codex
```

Start a fresh Codex session after installing the plugin. The plugin-provided
MCP server starts a separate stdio Bifrost process with:

```bash
bifrost --mcp "symbol|extended"
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
PATH="$(pwd)/target/debug:$PATH" claude --plugin-dir plugins/bifrost-agent
```

Inspect `/plugin` to confirm the `bifrost` metadata loaded, then inspect `/mcp`
or ask Claude to call a lightweight analyzer operation such as `get_summaries`
or `search_symbols`.

To test the repository as a local Claude Code marketplace, run:

```bash
claude plugin marketplace add "$(pwd)"
claude plugin install bifrost@bifrost-marketplace --scope local
PATH="$(pwd)/target/debug:$PATH" claude
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
