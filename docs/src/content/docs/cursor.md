---
title: Cursor
description: Install and validate Bifrost in Cursor.
---

Cursor can use Bifrost through the native Cursor plugin package in this repository. The shared plugin package lives in `plugins/bifrost-agent`, and the repository root includes `.cursor-plugin/marketplace.json` so Cursor can discover the package.

## Install From GitHub

Use the dedicated **Cursor Agents** window, rather than the editor-adjacent
Customize page. In a new agent, run:

```text
/add-plugin bifrost@https://github.com/BrokkAi/bifrost
```

This opens the Plugins view. You can also reach the same flow through
**Customize -> Plugins -> Search or Paste Link** and paste:

```text
https://github.com/BrokkAi/bifrost
```

Open the Bifrost result, choose **Add to Cursor**, and confirm **Add Plugin**.
Cursor reads `.cursor-plugin/marketplace.json`, finds the `bifrost` package at
`plugins/bifrost-agent`, and installs it.

The plugin needs two Cursor-specific compatibility details: the MCP definition
resolves its launcher from Cursor's installed plugin directory, and Bifrost
accepts the absolute native path that Cursor returns from `roots/list`. A
connected MCP status or visible tool list is not sufficient evidence that both
boundaries worked; complete the smoke test below.

:::caution[Cursor and Bifrost 0.8.9]
Cursor can install the GitHub plugin at version 0.8.9, but the published 0.8.9
Bifrost binary rejects Cursor's bare absolute workspace path because it expects
a `file:` URI. Workspace-backed tool calls therefore remain unbound by default.
Use a newer Bifrost release containing Cursor native-root support when one is
available; do not treat the 0.8.9 installation alone as a successful
verification.

For one fixed project, 0.8.9 has an explicit compatibility override. Fully quit
Cursor, change to that project, and start a new app process with:

```bash
BIFROST_WORKSPACE_ROOT="$(pwd)" cursor .
```

This bypasses Cursor's roots negotiation and authorizes exactly that directory.
Fully quit and repeat the command when changing projects; do not use this
override for a reusable or multi-root setup.
:::

## Local Plugin Testing

Build Bifrost first:

```bash
cargo build --bin bifrost
```

Open Cursor with the local binary selected:

```bash
BIFROST_BINARY_PATH="$(pwd)/target/debug/bifrost" cursor .
```

In the **Cursor Agents** window, open **Customize -> Plugins**, choose
**Add -> From Local Repo**, and select the repository root. Do not select
`plugins/bifrost-agent` directly: **From Local Repo** expects the marketplace
manifest at `.cursor-plugin/marketplace.json`.

This flow imports the marketplace definition, but the tested Cursor build
resolved the plugin contents from the repository's remote default branch. It
ignored both uncommitted files and the selected feature-branch commit. Use it
only to test a snapshot already reachable from the default branch. For a local
Rust change, fully quit Cursor before starting it with
`BIFROST_BINARY_PATH` as shown above; do not use **From Local Repo** as evidence
for an unpublished plugin-manifest change.

## Enable MCP Tools

After installing the plugin, stay in the **Cursor Agents** window, open
**Customize -> MCPs**, and enable Bifrost for the workspace. Check that its
status is healthy, then start a fresh agent so the newly enabled tools are
attached to that agent. If a restored app session reports that Bifrost is not
bound, select the workspace first, open Bifrost's MCP details, choose
**Reload**, and then start another fresh agent.

Enabling the plugin's MCP entry is sufficient; do not create a duplicate manual
Bifrost server. The packaged Cursor definition supplies the installed launcher
location, starts Bifrost without an inferred root, and lets Cursor authorize the
active workspace through the standard `roots/list` mechanism with compatibility
for Cursor's native-path response. Bifrost never treats Cursor's process
directory or the installed plugin directory as the analyzer workspace.

Use this strict smoke prompt to prove Cursor called the plugin's MCP server
instead of silently falling back to file or shell tools:

```text
Use only the installed Bifrost plugin MCP tools. First confirm query_code is in the callable Bifrost MCP surface. Then call the Bifrost search_symbols MCP tool with patterns ["reconcile_codex_sandbox_workspace"]. Do not use Shell, terminal, rg, codebase search, file reading, or the bifrost CLI. Report the exact MCP result, especially the returned path.
```

Apply the shared
[host-integration evidence contract](/mcp/#validate-host-integration): retain
Cursor's Bifrost tool event and structured result, verify the result belongs to
the active workspace (the current smoke result is `src/mcp_common.rs`), and
reject ordinary file-reading fallbacks or paths under the installed plugin.

:::caution[Cursor Agents worktrees]
In Cursor Agents 3.12.30, `roots/list` can name the base repository while the
agent composer shows a separate worktree. A relative result such as
`src/mcp_common.rs` exists in both checkouts and cannot prove the binding is
correct. When using a worktree, also query a declaration or file that exists
only on that worktree and reject results from the base checkout. Cursor remains
unchecked in the cross-host verification matrix until this exact-checkout
boundary passes.
:::

The `cursor agent --plugin-dir` CLI path is useful for checking that Cursor can load plugin skills, but it has not proven reliable for plugin-provided MCP servers. Treat the desktop Customize/MCP flow as the MCP validation path.

## Can My Agent Run RQL?

The packaged plugin uses `symbol|extended`. In a fresh chat after enabling MCP, confirm that the Bifrost tool list includes `query_code`, then call it with the inline JSON fields `{"match":{"kind":"declaration"},"limit":1}`. To validate saved RQL, check a workspace file named `bifrost-smoke.rql` containing `(limit 1 (declaration))`, then call `query_code` with `{"query_file":"bifrost-smoke.rql"}`.

The inline call is canonical JSON. MCP accepts RQL only from a workspace `.rql` file through `query_file`. Loading plugin skills without enabling its MCP server provides instructions but no Bifrost tools. See [MCP query and RQL availability](/mcp/#query-and-rql-availability) for the full surface matrix and [Agent Result Safety](/agent-result-safety/) before making completeness claims.
