# Bifrost Agent Plugin

This directory implements the Agent Plugins v1 package for Bifrost. Codex uses
its package adapter, while the root package files remain the portable Agent
Plugins v1 fallback. Pi, Claude Code, and Cursor also use this directory with
their host adapters. Every host reuses the same launcher and pinned release
metadata. The npm package `@brokk/bifrost-agent` contains the Pi extension.

None of these distributions bundles the Bifrost binary. The launcher resolves a
released Bifrost binary and makes a multi-language code-analysis subset of the
`bifrost` MCP tools discoverable through each host's plugin system.

The Claude Code and Codex stable install name is `brokk`. Cursor uses the
Cursor-facing plugin name `bifrost` so the package is discoverable as Bifrost in
Cursor's Customize UI. The public marketplace namespace is `bifrost`, so
Claude/Codex marketplace installs read as `brokk@bifrost` where the host exposes
namespace-qualified install names.

Claude Code starts
`${CLAUDE_PLUGIN_ROOT}/bin/bifrost-launcher.mjs --mcp "symbol|extended"` from
the host-specific `claude-mcp.json`. Codex selects
`.codex-plugin/plugin.json`, which points to `.mcp.json` and resolves the same
launcher from the installed package root.

## Portable Agent Plugins v1 Package

The package root contains the portable Agent Plugins v1 files:

- `plugin.json` gives the shared package identity.
- `mcp.json` gives the portable Bifrost stdio server.
- `skills/` contains portable skill directories.

Codex uses `.codex-plugin/plugin.json` and `.mcp.json`; the root files remain
the portable fallback. Claude Code uses
`.claude-plugin/plugin.json` and
`claude-mcp.json`. Cursor uses `.cursor-plugin/plugin.json` and
`cursor-mcp.json` because Cursor needs `${CURSOR_PLUGIN_ROOT}` and timeout
settings. Pi uses its TypeScript extension.

We tested package discovery with Codex CLI. We did not explicitly test the
Agent Plugins v1 package with VS Code, GitHub Copilot, Kiro, or Cursor.

The launcher uses `BIFROST_WORKSPACE_ROOT` when set, then a host-provided
`--root` or `--workspace-root`. Without either explicit override, Bifrost
starts unbound and requests the host's approved workspace through standard MCP
roots. On a rootless connection without advertised roots, it offers the
`codex/sandbox-state-meta` extension; current Codex uses that capability to
supply the active task. Bifrost never treats the installed plugin directory as
the analyzer workspace.
Claude Code uses `${CLAUDE_PLUGIN_ROOT}` because its MCP commands otherwise
resolve relative to the project directory, not the installed plugin. Cursor's
plugin manifest explicitly selects `cursor-mcp.json`, which uses Cursor's documented `type: "stdio"` and
`${CURSOR_PLUGIN_ROOT}` placeholder. The root `mcp.json` remains portable.
Both host-specific entries start Bifrost rootless. Builds containing the post-0.8.9 Cursor compatibility fix
accept both standard `file:` root URIs and Cursor's native absolute-path form
while keeping MCP roots authoritative; the published 0.8.9 binary requires an
explicit fixed-project root. Amp uses a different direct server-map shape for
`mcp.json` and `--mcp-config`.

Binary resolution order is:

1. `BIFROST_BINARY_PATH`, when set to a compatible binary as an explicit override.
2. The exact preferred Bifrost release in the launcher-managed cache.
3. The newest compatible cached patch in the declared minor-series range.
4. A compatible `bifrost` already on `PATH`, only when
   `BIFROST_LAUNCHER_ALLOW_PATH=1` is set.
5. A checksum-verified download of the exact preferred release.

The launcher rejects other major or minor versions and rejects prereleases
unless release metadata explicitly allows them. It never downloads an
unpinned compatible fallback. Every packaged host adapter uses this shared
selection for MCP, and the Claude Code LSP adapter uses the same result.
When compatibility mode starts a server and automatic installation is enabled,
the launcher also starts a detached checksum-verified preparation of the exact
preferred release. The current server continues using its selected compatible
binary; the next fresh host task can select the prepared preferred binary.
Set `BIFROST_LAUNCHER_AUTO_INSTALL=0` to disable both foreground and background
downloads.

Set `BIFROST_LAUNCHER_AUTO_INSTALL=0` to disable downloads, or
`BIFROST_LAUNCHER_CACHE_DIR=/path/to/cache` to choose the managed cache
location. `BIFROST_BINARY_PATH` is the explicit local development override
that bypasses ambient `PATH` lookup. Launcher diagnostics go to stderr so
stdio MCP traffic stays on stdin/stdout.

The launcher also has commands that do not require a workspace. `doctor`
reports the preferred and selected versions, source, and exact or compatibility
mode without modifying the cache or downloading anything. Compatibility checks execute each selected
candidate with `--version`, so use `doctor` only with binary locations you
trust. `prepare` follows the normal resolution order and,
when automatic installation is enabled, downloads and verifies the preferred
pinned release without starting MCP. Both accept `--json` for stable machine-readable
output:

```bash
plugins/bifrost-agent/bin/bifrost-launcher.mjs doctor
plugins/bifrost-agent/bin/bifrost-launcher.mjs prepare
```

After `prepare` succeeds, start a fresh host task so it negotiates the restored
Bifrost tool surface. `prepare` respects `BIFROST_LAUNCHER_AUTO_INSTALL=0`; unset
that variable before explicitly preparing a missing release.

For local development, build this checkout and point the launcher at the debug
binary:

```bash
cargo build --bin bifrost
BIFROST_BINARY_PATH="$(pwd)/target/debug/bifrost" node plugins/bifrost-agent/bin/bifrost-launcher.mjs --root . --mcp "symbol|extended"
```

## Pi Install

Pi loads a native extension from this package. The extension resolves the same
pinned, checksum-verified Bifrost binary as the other hosts, starts one stdio
MCP child for the session's workspace, and closes the child on session shutdown
or reload. Pi-visible tools use a `bifrost_` namespace, so Bifrost's canonical
MCP `query_code` tool appears as `bifrost_query_code`. The extension adds a
short system-prompt note that explains this host-specific rendering. The
extension adds no host-specific instruction files.

Install a local checkout after installing its package dependencies:

```bash
cd plugins/bifrost-agent
npm install
pi install "$(pwd)"
```

For development against this checkout's Rust binary:

```bash
cargo build --bin bifrost
cd plugins/bifrost-agent
npm install
BIFROST_BINARY_PATH="$(cd ../.. && pwd)/target/debug/bifrost" pi -e "$(pwd)"
```

To install from GitHub before an npm release, clone the repository and install
the package directory as a local Pi package:

```bash
git clone https://github.com/BrokkAi/bifrost.git
cd bifrost/plugins/bifrost-agent
npm install
pi install "$(pwd)"
```

After `@brokk/bifrost-agent` is published to npm, install a pinned release with:

```bash
pi install npm:@brokk/bifrost-agent@0.10.3
```

Run `/bifrost` in Pi's interactive TUI to configure Bifrost for the current
workspace. The default enables symbol navigation, structural queries, and file
discovery/ranking. The settings list can also enable code-quality reports, Git
history, raw text search, or JSON/XML transforms. It never offers Bifrost
workspace-switching tools because Pi owns the session workspace.
Selections are stored in separate canonical-workspace files under
`<Pi agent directory>/bifrost/workspaces/` (normally
`~/.pi/agent/bifrost/workspaces/`), so they survive new sessions without
adding configuration to the repository or making concurrent workspaces rewrite
the same settings document. If a settings file is malformed, interactive Pi
reports the problem and starts with Bifrost disabled so `/bifrost` can repair
the selection. Pi modes without a UI context report the failure through the
extension error path and leave Bifrost unstarted instead of silently enabling
defaults; Pi itself can continue without Bifrost.

Changing a capability may restart the Bifrost child when it requires another
existing MCP server toolset. Tools discovered earlier remain registered with Pi
but are removed from Pi's active tool set when disabled or rejected by Pi's
command-line tool filters. The namespace note is omitted when Pi accepts no
Bifrost tools. A failed change before connection retirement leaves the prior
connection and saved selection active. If retiring that connection fails, the
saved selection remains but Bifrost tools are disabled because cleanup could
not be confirmed. In interactive Pi, startup, reconnect, and background
connection failures use Pi's error notifications; in modes without a UI
context, startup failures use Pi's extension error path. The extension does not
write directly into the TUI with `console.log` or `console.error`.

Tool calls time out after 300 seconds; startup times out after 60 seconds.
Cancellation stops the Pi request promptly, though the current Bifrost stdio
server may finish analyzer work before it reads the MCP cancellation
notification.

Bifrost results follow Pi's normal two-level output handling. The TUI shows a
five-visual-line preview and expands the bounded result with Pi's tool-output
shortcut (`Ctrl+O` by default). The model receives at most the first 2,000 lines
or 50 KB. When complete text exceeds that limit, the result includes the path
to a dedicated temporary overflow file containing the full output.

For a real-host smoke from the repository root, build Bifrost and ask Pi to
exercise navigation plus both supported structural-query inputs:

```bash
cargo build --bin bifrost
BIFROST_BINARY_PATH="$PWD/target/debug/bifrost" \
BIFROST_LAUNCHER_AUTO_INSTALL=0 \
pi --no-session -e "$PWD/plugins/bifrost-agent" -p \
  'Use the Bifrost tools directly. First call bifrost_get_summaries for src/mcp_common.rs. Then call bifrost_query_code with inline canonical JSON fields match.kind=declaration and limit=1. Then call bifrost_query_code with only query_file="docs/fixtures/ten-minute-evaluation/queries/find-audit.rql". Report whether all three calls succeeded and include one repository-relative path from each result.'
```

Expect all three calls to succeed. The saved query should return
`docs/fixtures/ten-minute-evaluation/src/app.py`; this also proves that
`query_file` is resolved from Pi's explicit session workspace rather than from
the installed package directory. Use Pi's JSON mode for protocol-level evidence
when needed; Bifrost diagnostics remain on stderr and must not appear as JSON
messages on stdout.

Package maintainers should keep `package.json`, `package-lock.json`,
`bifrost-release.json`, and the Rust crate version aligned. Validate the package before publication:

```bash
cd plugins/bifrost-agent
npm ci
npm run check
npm test
npm run test:packed
npm pack --dry-run
npm publish --dry-run
```

A real publication requires npm credentials and an unused matching version; the
repository does not imply that npm publishing is configured automatically.

## Codex Install

Add the Brokk marketplace from GitHub, then install the Agent Plugins v1
package:

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

Start a fresh Codex session after installing the package. The package-provided
MCP server is registered automatically; do not add a second manual Bifrost MCP
entry. It starts a separate stdio Bifrost process with:

```bash
bifrost --mcp "symbol|extended"
```

For that rootless process, Bifrost prefers standard MCP roots. When the client
did not advertise roots, Bifrost offers the `codex/sandbox-state-meta`
capability. A compatible client may then attach its active task directory to
each analyzer tool call; current Codex does so. Bifrost binds that exact
directory and revokes it when the per-call scope disappears or changes.
`BIFROST_WORKSPACE_ROOT` remains an explicit compatibility override. Client-root
and sandbox-metadata sessions keep analyzer and semantic cache writes under the
exact approved root, including for linked worktrees.

The plugin gives Bifrost up to 180 seconds to download, verify, extract, and
start a missing pinned release, and up to 300 seconds for individual analyzer
tool calls. Large workspaces may need the tool-call budget because Bifrost can
build its persisted analyzer on the first real tool call.

The default plugin toolset intentionally omits Bifrost's `workspace` and `text`
MCP toolsets. That keeps local plugin installs focused on analyzer navigation
and avoids giving prompts a built-in way to switch the active workspace or read
arbitrary files through raw text tools. Users who explicitly want the full MCP
surface can still add a manual `codex mcp add` entry for `--mcp searchtools`.

Once the session starts, verify the tools by calling a lightweight analyzer
operation such as `get_summaries` or `search_symbols` against files in the
active workspace.

## Host Instructions

This package provides MCP configuration, the launcher, and specialist agents.
It does not install instruction files into host-specific directories. Configure
the host MCP entry, then start a new session and call a tool such as
`get_summaries` or `search_symbols`.

## Claude Code Install

Add the Brokk marketplace from GitHub, then install Bifrost:

```bash
claude plugin marketplace add BrokkAi/bifrost --sparse .claude-plugin plugins
claude plugin install brokk@bifrost
```

Start a fresh Claude Code session after installing the plugin so its MCP and
native LSP server configurations are loaded at startup. The built-in `LSP`
tool handles position-based definition, references, hover, and diagnostics;
Bifrost's MCP tools provide workspace search, summaries, structural queries,
and policies.

## Claude Code Local Testing

From the repository root, start Claude Code with this package directory:

```bash
BIFROST_BINARY_PATH="$(pwd)/target/debug/bifrost" claude --plugin-dir plugins/bifrost-agent
```

Inspect `/plugin` to confirm the `bifrost` metadata and LSP server loaded, then
inspect `/mcp` or ask Claude to call a lightweight analyzer operation such as
`get_summaries` or `search_symbols`. Ask Claude to use only its built-in `LSP`
tool on a unique declaration and reference in the active project, verifying
definition, references, hover, and an automatic diagnostic after a temporary
syntax error. Results must point into the active project, never the installed
plugin directory.

To test the repository as a local Claude Code marketplace, run:

```bash
claude plugin marketplace add "$(pwd)"
claude plugin install brokk@bifrost --scope local
BIFROST_BINARY_PATH="$(pwd)/target/debug/bifrost" claude
```

Start a fresh Claude Code session after installing the plugin so the MCP and
LSP server configurations are loaded at startup. If LSP startup fails, inspect
the `/plugin` Errors tab, restart with `claude --debug`, and run
`plugins/bifrost-agent/bin/bifrost-launcher.mjs doctor` to verify the pinned
binary.

## Cursor Local Testing

From the repository root, build Bifrost and open Cursor with the local binary
selected:

```bash
cargo build --bin bifrost
BIFROST_BINARY_PATH="$(pwd)/target/debug/bifrost" cursor .
```

In the dedicated **Cursor Agents** window, open **Customize -> Plugins**, choose
**Add -> From Local Repo**, and select the repository root. Cursor reads
`.cursor-plugin/marketplace.json`, finds the `bifrost` plugin at
`plugins/bifrost-agent`, and offers it for installation. Do not select
`plugins/bifrost-agent` directly: **From Local Repo** expects the repository
marketplace manifest.

In the tested Cursor build, this route resolved plugin contents from the remote
default branch, not from the selected feature-branch commit or dirty worktree.
Use it only for a snapshot already reachable from that default branch. A local
Rust binary can still be tested through `BIFROST_BINARY_PATH`; fully quit Cursor
before running the command above so the new app process inherits the override.

After installing, open **Customize -> MCPs** in the Cursor Agents window,
enable Bifrost, verify that it connects, and start a fresh agent. Then use a
strict prompt that proves the result came through Bifrost instead of ordinary
file or shell search:

```text
Use only the installed Bifrost plugin MCP tools. First confirm query_code is in
the callable Bifrost MCP surface. Then call the Bifrost search_symbols MCP tool
with patterns ["reconcile_codex_sandbox_workspace"]. Do not use Shell,
terminal, rg, codebase search, file reading, or the bifrost CLI. Report the
exact MCP result, especially the returned path.
```

The published 0.8.9 binary does not accept Cursor's native-path `roots/list`
response. For a fixed-project 0.8.9 smoke, fully quit Cursor and start it from
the intended project with
`BIFROST_WORKSPACE_ROOT="$(pwd)" cursor .`. The override is authoritative and
must be changed when switching projects.

Cursor Agents 3.12.30 may return the base repository as its MCP root while an
agent runs in a separate worktree. In that mode, verify a branch-only symbol or
file instead of accepting a relative path that exists in both checkouts.

The `cursor agent --plugin-dir` CLI path is useful for checking plugin loading,
but it has not proven reliable for plugin-provided MCP servers. Treat the
desktop Customize/MCP path as the Cursor plugin MCP smoke.

To publish publicly, submit the repository URL at
<https://cursor.com/marketplace/publish>. The repository root contains
`.cursor-plugin/marketplace.json`, which points Cursor at this shared package.

## Antigravity Install and Local Testing

Antigravity can load Bifrost through manual MCP configuration. The visible
**Add MCP** flow is a curated marketplace, but Antigravity accepts the standard
`mcpServers` shape in global `~/.gemini/config/mcp_config.json` and
workspace-local `.agents/mcp_config.json` files. See Antigravity's official
[MCP](https://antigravity.google/docs/mcp) documentation for the host-side
convention.

```json
{
  "mcpServers": {
    "bifrost": {
      "command": "/absolute/path/to/bifrost/target/debug/bifrost",
      "args": [
        "--root",
        "/absolute/path/to/workspace",
        "--mcp",
        "symbol|extended"
      ]
    }
  }
}
```

This global entry is suitable only for one fixed workspace: it does not follow
Antigravity's active Project or Git worktree. For worktrees, add a separate
uncommitted `.agents/mcp_config.json` in each worktree. Set `cwd` to that
worktree's absolute path and pass `--root .`, for example:

```json
{
  "mcpServers": {
    "bifrost": {
      "command": "/absolute/path/to/bifrost",
      "cwd": "/absolute/path/to/this/worktree",
      "args": ["--root", ".", "--mcp", "symbol|extended"]
    }
  }
}
```

Bifrost requires that explicit binding because Antigravity does not currently
provide a dynamic MCP workspace root. Do not use the installed plugin
directory, the process CWD, or the selected Project as an inferred root. A
per-worktree installer may derive the path with `git rev-parse --show-toplevel`,
but it must merge only Bifrost's entry and leave every other MCP server intact.

Click **Refresh** in **Settings -> Customizations** after creating or changing
the file. Refresh normally reloads the MCP connection without restarting the
whole application; use a fresh conversation to validate its tool surface. If
the app still displays an old root after Refresh, fully quit and reopen it.

Open the project-specific settings page in Antigravity. Validate with a prompt
that requires a Bifrost MCP tool on source code:

```text
Use the Bifrost MCP get_summaries tool on src/analyzer/usages for source context, and name the files summarized from the MCP result.
```

## Amp Install and Local Testing

Configure Amp's direct MCP server map with the Bifrost launcher. For local
testing, use the checked-out binary and an explicit workspace root.

```json
{
  "bifrost": {
    "command": "/absolute/path/to/plugin/bin/bifrost-launcher.mjs",
    "cwd": "/absolute/path/to/workspace",
    "args": ["--root", ".", "--mcp", "symbol|extended"]
  }
}
```

Start a fresh Amp task after changing the MCP configuration. Validate with a
prompt that requires an analyzer MCP tool on source code:

```bash
BIFROST_BINARY_PATH="$(pwd)/target/debug/bifrost" amp -x \
  'Use the Bifrost MCP get_summaries tool on src/analyzer/usages/rust_graph/*.rs and name three symbols from the MCP result.'
```

## Difference From `codex mcp add`

`codex mcp add`, `claude mcp add`, a manual Cursor `mcp.json` entry, or
`amp mcp add` registers one MCP server directly in a user's host configuration.
This plugin packages a safer default server shape behind host plugin flows
where available, so users can install or remove Bifrost without hand-editing
MCP configuration. Amp uses its direct server-map configuration because it has
no matching host plugin manifest here.

The MCP process created by this plugin is independent from the VS Code language
server process. They may point at the same `bifrost` binary, but each host
starts its own stdio process.
