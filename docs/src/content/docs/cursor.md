---
title: Cursor
description: Install and validate Bifrost in Cursor.
---

Cursor has two independent Bifrost integrations:

| Integration | Process | Surface |
| --- | --- | --- |
| Bifrost editor extension | Version 0.11.5: `bifrost --root <workspace> --lsp`, using its own Bifrost 0.11.5 binary. Next version: `bifrost-lsp --root <workspace>`. | Editor features such as definitions, references, hover, rename, diagnostics, and workspace symbols, plus RQL and Rune editor features |
| Bifrost agent plugin | `bifrost --mcp symbol\|extended`, started by the plugin's launcher | Bifrost tools that Cursor agents can call |

Install either integration for its own surface, or install both. They run
separate processes. Never point the agent plugin at the extension's language
server.

:::caution[The language server moved to bifrost-lsp]
Bifrost built after release 0.12.0 does not serve LSP: `bifrost --lsp` exits
with an error. The language server is now the separate `bifrost-lsp` program, and
`bifrost-lsp` has no release yet. The extension version on Open VSX, 0.11.5,
still works because it downloads its own Bifrost 0.11.5 binary. See
[LSP Server](/lsp/).
:::

## Install the Editor Extension

Install the [Bifrost extension from Open VSX](https://open-vsx.org/extension/brokk/bifrost-vscode),
or open Cursor's **Extensions** view and search for `brokk.bifrost-vscode`.
Confirm that the publisher is **brokk**, choose **Install**, and open a supported
source workspace. With the default `auto` launch mode, accept the prompt to
install the managed server binary.

Open **Output > Bifrost** and keep the lines that show the download and the
installed version and path. The managed installer:

1. downloads the platform archive and its `.sha256` file from the GitHub
   release. Version 0.11.5 downloads Bifrost from BrokkAi/bifrost. The next
   version downloads `bifrost-lsp` from BrokkAi/bifrost-lsp;
2. checks that the `.sha256` file and the archive both match the hash built
   into the extension package; and
3. runs the binary with `--version` before it starts the language server.

A visible Bifrost status item does not by itself show that these checks
passed or that the server serves the active workspace.

To upgrade, choose **Update** for Bifrost in Cursor's Extensions view. Fully
quit and reopen Cursor. Then check the installed extension version and the
managed server version in **Output > Bifrost**. If the extension asks to
install a new managed binary, choose **Update**.

See [VS Code LSP](/vscode/) for all extension settings, commands, and launch
modes.

### Validate the Editor Extension

Use a normal workspace rather than a Cursor agent worktree for this smoke. Add
a temporary, uniquely named declaration and usage in a supported language. For
example, in Rust:

```rust
pub fn cursor_bifrost_lsp_probe_4f6f2b7() {}

pub fn call_cursor_bifrost_lsp_probe_4f6f2b7() {
    cursor_bifrost_lsp_probe_4f6f2b7();
}
```

From the usage, verify **Go to Definition**, **Find All References**, and
hover. Run **Rename Symbol**, confirm that both declaration and usage change,
then undo the rename. To exercise diagnostics, temporarily enable
`bifrost.unrecognizedSymbolDiagnostics`, replace the call with a unique missing
symbol, and confirm that Bifrost reports it before restoring the valid call and
disabling the experimental setting.

Pass only if every result belongs to the active checkout and **Output >
Bifrost** shows the language-server launch for that workspace. Remove the
temporary probe after you record the Cursor version, extension version,
managed server version, platform, output, and operation results.

### Troubleshoot the Editor Extension

- Run **Bifrost: Show Output** and check the full launch command, download,
  checksum, version, and handler errors.
- Run **Bifrost: Restart Language Server** after changing roots, exclusions, or
  launch settings.
- Set `bifrost.launchMode` to `bundled` to require the managed binary, or use
  `path` with `bifrost.serverPath` to diagnose a specific local binary.
- Set `bifrost.debug` to `true` for LSP request tracing and lower
  `bifrost.slowRequestMs` when investigating latency.
- If the output shows `the LSP server has moved out of this repository`, the
  extension started a Bifrost CLI newer than 0.12.0. Use `auto` or `bundled`
  mode, or point `bifrost.serverPath` at a server binary that serves LSP.
- Do not use healthy MCP status as evidence that the editor extension works;
  it is a different process and protocol.

## Install the Agent Plugin From GitHub

The shared agent plugin package lives in `plugins/bifrost-agent`, and the
repository root includes `.cursor-plugin/marketplace.json` so Cursor can
discover the package.

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

### What the Plugin Installs

The Cursor manifest of the plugin, version 0.12.0, installs one MCP server and
eight subagents.

| Item | Name | What it does |
| --- | --- | --- |
| MCP server | `bifrost` | Runs the plugin's launcher, which finds or installs a Bifrost binary and starts `bifrost --mcp symbol\|extended` over stdio. Cursor allows 180 seconds for startup and 300 seconds per tool call. |
| Subagent | `architect-reviewer` | Reviews a pull request's design: coupling, cohesion, SOLID principles, abstraction levels, and fit with existing patterns. |
| Subagent | `devops-reviewer` | Reviews infrastructure code, CI/CD configuration, resource management, logging, timeouts, and error handling. |
| Subagent | `dry-reviewer` | Looks for code added in a pull request that duplicates logic already in the codebase. |
| Subagent | `issue-diagnostician` | Finds the affected files and code paths for a GitHub issue and forms a root-cause hypothesis. |
| Subagent | `issue-enhancer` | Adds source references, affected components, and technical context to a draft GitHub issue. |
| Subagent | `issue-planner` | Turns a diagnosis into an ordered list of code changes with file paths and method names. |
| Subagent | `security-reviewer` | Looks for injection, authentication bypass, data leaks, cryptographic misuse, backdoors, and vulnerable dependencies in a pull request. |
| Subagent | `senior-dev-reviewer` | Checks that a pull request's changes match its description, and looks for unrelated changes, scope creep, incomplete refactors, and missing tests. |

All eight subagents are read-only: they cannot use the Write or Edit tools.

The package directory also contains four skills. The Cursor manifest does not
list them.

| Skill | What it covers |
| --- | --- |
| `bifrost-code-navigation` | Find definitions, references, call sites, and related files with `search_symbols`, `get_symbol_locations`, `scan_usages_by_location`, and `most_relevant_files`. |
| `bifrost-code-reading` | Read implementation details and structure with `get_summaries` and `get_symbol_sources`. |
| `bifrost-codebase-search` | Find symbols, code shapes, and files with `search_symbols`, `query_code`, `scan_usages_by_location`, and `most_relevant_files`. |
| `bifrost-policy-checking` | Find policy packs and categories, run built-in and repository RQL policies, and read clean, finding, and unreliable results. |

The portable package uses root `plugin.json` and `mcp.json` files. It can also
include optional `skills/` files.
Cursor still needs its native `.cursor-plugin/plugin.json` and
`cursor-mcp.json` adapter. The adapter resolves its launcher from Cursor's
installed plugin directory. Bifrost also accepts the absolute native path that
Cursor returns from `roots/list`. A connected MCP status or visible tool list is
not sufficient evidence that both boundaries worked; complete the smoke test
below.

If an agent reports that Bifrost is not bound to a workspace, Cursor did not
supply a usable root. For one fixed project, you can bypass roots negotiation:
fully quit Cursor, change to that project, and start Cursor with
`BIFROST_WORKSPACE_ROOT="$(pwd)" cursor .`. The plugin launcher passes that
directory to Bifrost as `--root`. Quit and repeat the command when you change
projects. Do not use this for a multi-root setup.

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
Use only the installed Bifrost plugin MCP tools. First confirm query_code is in the callable Bifrost MCP surface. Call search_symbols with patterns ["cursor_bifrost_host_probe_4f6f2b7"]. Then call query_code with schema_version 1, languages ["rust"], match {"kind":"function","name":"cursor_bifrost_host_probe_4f6f2b7"}, limit 10, and result_detail "full". Do not use Shell, terminal, rg, codebase search, file reading, or the bifrost CLI. Show both exact structured MCP results. PASS only if both return src/cursor_bifrost_host_probe_4f6f2b7.rs.
```

Apply the shared
[host-integration evidence contract](/mcp/#validate-host-integration): retain
Cursor's Bifrost tool event and structured result, verify the result belongs to
the active workspace, and reject ordinary file-reading fallbacks or paths under
the installed plugin. Remove the temporary declaration after retaining the
evidence.

:::caution[Cursor Agents worktrees]
In Cursor Agents 3.12.30, `roots/list` can name the base repository while the
agent composer shows a separate worktree. Bifrost correctly accepts the native root supplied
by Cursor, but it cannot infer that Cursor meant a different checkout. A
relative result from a file shared by both checkouts cannot prove the binding
is correct. When using a worktree, run the unique-declaration smoke above and
reject results from the base checkout. Cursor remains unchecked in the
cross-host verification matrix until this exact-checkout boundary passes.
:::

The `cursor agent --plugin-dir` CLI path is useful for checking plugin loading, but it has not proven reliable for plugin-provided MCP servers. Treat the desktop Customize/MCP flow as the MCP validation path.

## Can My Agent Run RQL?

The packaged plugin uses `symbol|extended`. In a fresh chat after enabling MCP, confirm that the Bifrost tool list includes `query_code`, then call it with the inline JSON fields `{"match":{"kind":"declaration"},"limit":1}`. To validate saved RQL, check a workspace file named `bifrost-smoke.rql` containing `(limit 1 (declaration))`, then call `query_code` with `{"query_file":"bifrost-smoke.rql"}`.

The inline call is canonical JSON. MCP accepts RQL only from a workspace `.rql` file through `query_file`. See [MCP query and RQL availability](/mcp/#query-and-rql-availability) for the full surface matrix and [Agent Result Safety](/agent-result-safety/) before making completeness claims.
