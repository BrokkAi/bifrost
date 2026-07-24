---
title: Cursor
description: Install and validate Bifrost in Cursor.
---

Cursor can use Bifrost through the native Cursor plugin package in this repository. The shared plugin package lives in `plugins/bifrost-agent`, and the repository root includes `.cursor-plugin/marketplace.json` so Cursor can discover the package.

## Install From GitHub

Use the dedicated **Cursor Agents** window. In a new agent, type
`/add-plugin`, select the **Add Plugin** slash-command suggestion, and press
Return. Cursor opens its Plugins view; in **Search or Paste Link**, paste:

```text
https://github.com/BrokkAi/bifrost
```

Open the Bifrost result, choose **Add to Cursor**, and confirm **Add Plugin**.
Cursor reads `.cursor-plugin/marketplace.json`, finds the `bifrost` package at
`plugins/bifrost-agent`, and installs it.

Cursor's settings labels vary by build. If **Customize -> Plugins** exposes
**Search or Paste Link**, pasting the same repository URL there is equivalent.
Typing the slash-command text as an ordinary chat prompt is not: select the
slash-command suggestion before submitting it.

To upgrade an existing installation, remove the GitHub-installed Bifrost
package from the Plugins view and repeat the GitHub install flow. Fully quit
and reopen Cursor afterward, then confirm that the installed plugin metadata
reports the expected version.

The plugin needs two Cursor-specific compatibility details: the MCP definition
resolves its launcher from Cursor's installed plugin directory, and Bifrost
accepts the absolute native path that Cursor returns from `roots/list`. A
connected MCP status or visible tool list is not sufficient evidence that both
boundaries worked; complete the smoke test below.

:::caution[Upgrade from Bifrost 0.8.9]
Bifrost 0.8.10 is the minimum release with both the Cursor plugin-root launcher
fix and support for Cursor's bare absolute workspace path. A 0.8.9 installation
can appear connected while workspace-backed calls remain unbound. Upgrade,
fully restart Cursor, and complete the exact-workspace smoke below rather than
treating installation or a visible tool list as verification.

If upgrading is temporarily impossible, 0.8.9 has an explicit compatibility
override for one fixed project. Fully quit Cursor, change to that project, and
start a new app process with:

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

Cursor can also import an installed Claude Code plugin automatically. If the
MCP list contains both the native `plugin-bifrost-bifrost` entry and an imported
`plugin-brokk-bifrost` entry, leave the native Cursor entry enabled and disable
the imported duplicate in Cursor. This does not disable the Claude Code
installation itself.

For strong exact-checkout evidence, add a temporary declaration whose name is
unique to the smoke:

```rust
// src/cursor_bifrost_host_probe_4f6f2b7.rs
pub fn cursor_bifrost_host_probe_4f6f2b7() {}
```

Use this strict smoke prompt to prove Cursor called the plugin's MCP server
instead of silently falling back to file or shell tools:

```text
Use only the installed Bifrost plugin MCP tools. First confirm query_code is in the callable Bifrost MCP surface. Call search_symbols with patterns ["cursor_bifrost_host_probe_4f6f2b7"]. Then call query_code with schema_version 2, languages ["rust"], match {"kind":"function","name":"cursor_bifrost_host_probe_4f6f2b7"}, limit 10, and result_detail "full". Do not use Shell, terminal, rg, codebase search, file reading, or the bifrost CLI. Show both exact structured MCP results. PASS only if both return src/cursor_bifrost_host_probe_4f6f2b7.rs.
```

Apply the shared
[host-integration evidence contract](/mcp/#validate-host-integration): retain
Cursor's Bifrost tool event and structured result, verify the result belongs to
the active workspace, and reject ordinary file-reading fallbacks or paths under
the installed plugin. Remove the temporary declaration after retaining the
evidence.

:::caution[Cursor Agents worktrees]
In Cursor Agents 3.12.30, this host issue remains after upgrading to Bifrost
0.8.10: `roots/list` can name the base repository while the agent composer
shows a separate worktree. Bifrost correctly accepts the native root supplied
by Cursor, but it cannot infer that Cursor meant a different checkout. A
relative result from a file shared by both checkouts cannot prove the binding
is correct. When using a worktree, run the unique-declaration smoke above and
reject results from the base checkout. Cursor remains unchecked in the
cross-host verification matrix until this exact-checkout boundary passes.
:::

The `cursor agent --plugin-dir` CLI path is useful for checking that Cursor can load plugin skills, but it has not proven reliable for plugin-provided MCP servers. Treat the desktop Customize/MCP flow as the MCP validation path.

## Can My Agent Run RQL?

The packaged plugin uses `symbol|extended`. In a fresh chat after enabling MCP, confirm that the Bifrost tool list includes `query_code`, then call it with the inline JSON fields `{"match":{"kind":"declaration"},"limit":1}`. To validate saved RQL, check a workspace file named `bifrost-smoke.rql` containing `(limit 1 (declaration))`, then call `query_code` with `{"query_file":"bifrost-smoke.rql"}`.

The inline call is canonical JSON. MCP accepts RQL only from a workspace `.rql` file through `query_file`. Loading plugin skills without enabling its MCP server provides instructions but no Bifrost tools. See [MCP query and RQL availability](/mcp/#query-and-rql-availability) for the full surface matrix and [Agent Result Safety](/agent-result-safety/) before making completeness claims.
