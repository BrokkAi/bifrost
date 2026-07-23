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

Refresh an existing marketplace installation before testing a newly published
Bifrost version:

```bash
codex plugin marketplace upgrade bifrost
codex plugin list
```

Confirm that `brokk@bifrost` is installed, enabled, and reports the expected
version.

For local development from a checkout, add this repository root instead:

```bash
codex plugin marketplace add "$(pwd)"
codex plugin add brokk@bifrost
```

For a local checkout build, start Codex with the debug binary selected explicitly:

```bash
BIFROST_BINARY_PATH="$(pwd)/target/debug/bifrost" codex
```

After installing, upgrading, or changing the plugin, fully quit and restart the
ChatGPT desktop app before opening a new Codex task. A new task inside an
already-running desktop process can retain the previous plugin files, MCP
process, or tool schemas. For Codex CLI, exit the current process and start a
new session. This follows Codex's
[plugin reload guidance](https://learn.chatgpt.com/docs/build-plugins).

The packaged plugin uses `symbol|extended`, so it exposes both symbol navigation
and `query_code`.

Installing the plugin automatically registers its packaged MCP server. Do not add a second manual Bifrost MCP entry for the same plugin. The launcher keeps package command resolution separate from analyzer scope: without an explicit override, Bifrost prefers standard MCP roots. On a rootless connection whose client did not advertise roots, Bifrost offers the `codex/sandbox-state-meta` extension. Current Codex accepts that capability and supplies the active task directory on each analyzer tool call. Bifrost binds that exact directory, follows later task-directory changes, and never analyzes the plugin cache. `BIFROST_WORKSPACE_ROOT` remains an authoritative explicit override for fixed-project or older-host configurations.

If the first launch needs to download the pinned Bifrost release, prepare it from a normal host shell before opening that fresh session:

```bash
~/.codex/.tmp/marketplaces/bifrost/plugins/bifrost-agent/bin/bifrost-launcher.mjs prepare --json
```

Wait for `"status":"ready"`. This avoids discovering a download, release-pin, or network failure only after Codex has already fixed the task's callable tool surface.

## Verify Plugin Loading and Workspace Binding

Run this check in a new Codex task rooted in the repository you intend to
analyze. Do not use a prompt that Codex can satisfy with shell search or direct
file reading.

First ask Codex to discover the deferred Bifrost tool schemas with the exact
tool-search query:

```text
Bifrost search_symbols query_code
```

The discovered `mcp__bifrost` surface should include both `search_symbols` and
`query_code`. Do not treat a guessed JavaScript call such as
`tools.mcp__bifrost__search_symbols(...)` as discovery; a missing generated
function only proves that the tool was not callable in that turn.

Next ask Codex to call the discovered Bifrost `search_symbols` tool for a
declaration that is unique to the active repository. Require the response to
include the MCP result and forbid shell, text-search, and direct-file
substitutes. The check passes only when the result identifies that declaration
at a project-relative path inside the active workspace.

For a Bifrost checkout, this deterministic request is:

```json
{"patterns":["reconcile_codex_sandbox_workspace"]}
```

The expected hit is `mcp_common.reconcile_codex_sandbox_workspace` in
`src/mcp_common.rs`. A path under the installed plugin or launcher cache is a
failure even if the symbol name looks plausible.

Use the failure boundary to decide what to inspect next:

| Observation | Boundary to inspect |
| --- | --- |
| `brokk@bifrost` is absent, disabled, or stale after a full restart | Marketplace installation and plugin enablement |
| Tool discovery returns no `mcp__bifrost` schemas | Plugin MCP registration, host policy, and desktop restart |
| A direct guessed function call fails before an MCP event exists | Deferred tool discovery; run the tool search first |
| Bifrost reports that it is not bound to a workspace | MCP roots or negotiated Codex sandbox-state metadata |
| A result points into a plugin or launcher cache | Incorrect analyzer workspace binding |
| Symbol tools work but `query_code` is absent | MCP toolset selection; inspect the packaged plugin configuration |

This layered check distinguishes installation, discovery, server startup,
workspace binding, and toolset failures. See
[Validate Host Integration](/mcp/#validate-host-integration) for the
client-independent contract.

## Can My Agent Run RQL?

Confirm that `query_code` appears in the fresh session's Bifrost tool list. Then ask Codex to call it once with the inline JSON fields `{"match":{"kind":"declaration"},"limit":1}`. To validate saved RQL, check a workspace file named `bifrost-smoke.rql` containing `(limit 1 (declaration))`, then ask Codex to call `query_code` with `{"query_file":"bifrost-smoke.rql"}`.

The inline call is canonical JSON, not RQL. MCP accepts RQL only from a workspace `.rql` file named by `query_file`. A successful `get_summaries` or `search_symbols` call proves symbol navigation but does not prove that `query_code` is enabled. See [MCP query and RQL availability](/mcp/#query-and-rql-availability) for the full surface matrix and [Agent Result Safety](/agent-result-safety/) before making completeness claims.

## Manual MCP Entry

Use a manual MCP entry instead of the plugin-provided server when you want the raw command shape or a different toolset:

```bash
codex mcp add bifrost -- bifrost --root /path/to/project --mcp "symbol|extended"
codex mcp list
```

Use an absolute path to the Bifrost binary if `bifrost` is not intentionally installed on the host `PATH`.

Use `--mcp core` only when you intentionally want navigation without `query_code`.
