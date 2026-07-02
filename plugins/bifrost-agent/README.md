# Bifrost Agent Plugin

This package installs Bifrost's MCP server configuration as an agent plugin for
Codex and Claude Code. It does not bundle the Bifrost binary; it installs a
launcher that resolves a released Bifrost binary and makes a multi-language
code analysis subset of the `bifrost` MCP tools discoverable through each
host's plugin system. It also bundles the Brokk/Bifrost workflow skills and
specialist agents so the plugin is a one-stop shop for code intelligence,
GitHub issue work, and code review workflows.

The plugin's stable install name is `brokk`. The Codex UI-facing display name
is `Bifrost by Brokk`; Claude Code uses the shared plugin package metadata.
The public marketplace namespace is `bifrost`, so installs read as
`brokk@bifrost`.

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

## Codex Install

Add the Brokk marketplace from GitHub, then install Bifrost:

```bash
codex plugin marketplace add BrokkAi/bifrost --sparse .agents/plugins --sparse plugins
codex plugin add brokk@bifrost
```

For local development from a checkout, add the repository root instead:

```bash
codex plugin marketplace add "$(pwd)"
codex plugin add brokk@bifrost
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

## Bundled Skills

The Bifrost plugin owns the skills that explain the analyzer-backed MCP tools
it installs, plus the broader Brokk/Bifrost workflow skills that build on those
tools:

- `bifrost-code-navigation`: definitions, references, call sites, and related
  files with `search_symbols`, `get_symbol_locations`, `scan_usages`, and
  `most_relevant_files`.
- `bifrost-code-reading`: source summaries and exact symbol bodies with
  `get_summaries` and `get_symbol_sources`.
- `bifrost-codebase-search`: symbol, usage, file, and related-file discovery
  with shell grep reserved for arbitrary text.
- `brokk-git-exploration`: git-history exploration and commit inspection.
- `brokk-guided-issue`: end-to-end GitHub issue resolution.
- `brokk-guided-review`: interactive review of local changes, branches, or
  remote PRs with specialist reviewer agents.
- `brokk-review-pr`: adversarial multi-agent PR review.
- `review`: concise code-review guidance for ordinary review requests.
- `brokk-today`: GitHub issue and PR work-queue triage with a Slack-ready
  summary.
- `brokk-write-issue`: issue drafting with source-code context.

The plugin also includes the specialist reviewer and issue-planning agents used
by those workflows. The default plugin MCP toolset still does not expose
Bifrost's `workspace` lifecycle tools, so the Brokk `workspace` skill is not
copied here. Workflow skills should rely on the host-provided workspace context
and the plugin's analyzer tools, or gracefully skip explicit workspace
activation when `activate_workspace` is unavailable.

## Claude Code Install

Add the Brokk marketplace from GitHub, then install Bifrost:

```bash
claude plugin marketplace add BrokkAi/bifrost --sparse .claude-plugin plugins
claude plugin install brokk@bifrost
```

Start a fresh Claude Code session after installing the plugin so the MCP server
configuration is loaded at startup.

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
claude plugin install brokk@bifrost --scope local
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
