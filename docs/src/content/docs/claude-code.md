---
title: Claude Code
description: Install and validate Bifrost in Claude Code.
---

Claude Code can use Bifrost through the Brokk agent plugin or through a manual MCP server entry. The plugin path is preferred because it includes Bifrost skills, registers both MCP and native LSP code intelligence, and provides a launcher that resolves the Bifrost binary.

## Authenticate Claude Code

Claude Code authentication is separate from the Claude desktop app. Before
validating Bifrost, run:

```bash
claude auth login
claude auth status
```

The status must report `loggedIn: true`. If Claude's OAuth page says that the
current account cannot use Claude Code, use a supported subscription or an
Anthropic API key. Selecting Haiku or Sonnet in a Free desktop-app session does
not authenticate the Claude Code CLI.

## Plugin Install

Add the Brokk marketplace from GitHub, then install Bifrost:

```bash
claude plugin marketplace add BrokkAi/bifrost --sparse .claude-plugin plugins
claude plugin install brokk@bifrost
claude plugin list
claude mcp list
```

Start a fresh Claude Code session after installing the plugin so the MCP and LSP server configurations are loaded at startup.

To upgrade the user-scoped installation created above to the latest published
Bifrost plugin, refresh its marketplace metadata and update the installed
package:

```bash
claude plugin marketplace update bifrost
claude plugin update brokk@bifrost --scope user
claude plugin list
claude mcp list
```

Then run `/reload-plugins` or exit and start a fresh Claude Code session.
If the plugin was installed with another scope, pass that original scope to
`claude plugin update` instead.

The plugin automatically registers its packaged MCP and LSP servers, so do not add a duplicate manual MCP entry or separate Bifrost LSP plugin. The LSP launcher receives Claude Code's active project directory explicitly. Without an explicit `BIFROST_WORKSPACE_ROOT` or launcher `--root`, the MCP server requests the host-approved project directory through MCP roots and never uses the installed plugin directory as analyzer scope.

`claude plugin list` should show `brokk@bifrost` enabled. `claude mcp list`
should show `plugin:brokk:bifrost` connected. Bifrost 0.8.10 is the minimum
release with the Claude plugin-root launcher fix. If a v0.8.9 installation
instead reports `posix_spawn './bin/bifrost-launcher.mjs'`, run the upgrade
commands above, then reload plugins or start a fresh session. Claude caches
installed plugin contents by version, so refreshing the marketplace alone does
not replace an already cached v0.8.9 copy.

The two integrations serve different agent workflows:

- Claude Code's built-in `LSP` tool provides position-based definition, references, hover/type information, symbols, hierarchy, and automatic diagnostics after edits.
- Bifrost MCP tools provide agent-directed workspace search, summaries, structural queries, policies, and other operations that do not depend on an open editor position.

Claude Code starts separate LSP and MCP child processes. Both resolve the same pinned Bifrost binary, while each protocol owns its own workspace state and lifecycle.

## Local Plugin Testing

From the repository root, build Bifrost and start Claude Code with this package directory:

```bash
cargo build --bin bifrost
BIFROST_BINARY_PATH="$(pwd)/target/debug/bifrost" claude --plugin-dir plugins/bifrost-agent
```

Before spending a model turn, confirm that the local plugin resolves its
launcher independently of the project working directory:

```bash
claude --plugin-dir plugins/bifrost-agent mcp list
```

The local `plugin:brokk:bifrost` entry should report `Connected`.

Inspect `/plugin` to confirm the `bifrost` metadata and LSP server loaded without errors, then inspect `/mcp`. The packaged MCP server uses `symbol|extended`, so it exposes both symbol navigation and `query_code`. Ask Claude `What tools do you have access to?` and confirm that the built-in `LSP` tool is also available.

To test the repository as a local Claude Code marketplace, run:

```bash
claude plugin marketplace add "$(pwd)"
claude plugin install brokk@bifrost --scope local
BIFROST_BINARY_PATH="$(pwd)/target/debug/bifrost" claude
```

Start a fresh Claude Code session after installing the plugin so the MCP and LSP server configurations are loaded at startup.

Before testing query behavior, apply the shared
[host-integration evidence contract](/mcp/#validate-host-integration): retain
the `/mcp` tool event and structured result for a known workspace declaration,
verify its project-relative source path, and reject ordinary file-reading
fallbacks or paths under the installed plugin.

## Validate the Setup

For strong exact-checkout evidence, add a temporary declaration whose name is
unique to the smoke:

```rust
// src/claude_bifrost_host_probe_4f6f2b7.rs
pub fn claude_bifrost_host_probe_4f6f2b7() {}
```

Start a fresh Claude Code session in that checkout and use:

```text
Use only the Bifrost MCP server for this verification. Call search_symbols for claude_bifrost_host_probe_4f6f2b7, then call query_code with schema_version 1, languages ["rust"], match {"kind":"function","name":"claude_bifrost_host_probe_4f6f2b7"}, limit 10, and result_detail "full". Do not use terminal, file-reading, text-search, web, or any other tool. PASS only if both real structured results return src/claude_bifrost_host_probe_4f6f2b7.rs.
```

A valid pass shows real `mcp__plugin_brokk_bifrost__search_symbols` and
`mcp__plugin_brokk_bifrost__query_code` events with the same project-relative
path. Remove the temporary declaration after retaining the evidence.

## Validate Native LSP

For an exact-workspace smoke, create a temporary Rust file containing a unique declaration and reference:

```rust
// src/claude_bifrost_lsp_probe_4f6f2b7.rs
pub fn claude_bifrost_lsp_probe_4f6f2b7(value: i32) -> i32 {
    value + 1
}

pub fn call_claude_bifrost_lsp_probe_4f6f2b7() -> i32 {
    claude_bifrost_lsp_probe_4f6f2b7(41)
}
```

Start a fresh Claude Code session in that checkout, then ask:

```text
Use only the built-in LSP tool for this verification. In src/claude_bifrost_lsp_probe_4f6f2b7.rs, use the call on line 7 to find the definition and all references of claude_bifrost_lsp_probe_4f6f2b7, then request hover information for its definition. Do not use MCP, terminal, file search, grep, or file-reading tools. Report every path and line returned by LSP.
```

A valid pass contains real `LSP` tool events whose definition, references, and hover results point to the temporary file. To verify diagnostics, introduce a temporary syntax error in that file, make a harmless edit through Claude, and confirm that the LSP diagnostic is reported automatically after the edit. Restore valid syntax, confirm that the diagnostic clears, and remove the temporary file after retaining the evidence.

The launcher passes the active project as both the Bifrost fallback root and Claude Code's LSP workspace folder. Reject results under the installed plugin directory: they indicate incorrect host substitution or workspace binding.

## LSP Troubleshooting

If the `LSP` tool is absent or Bifrost does not start:

1. Run `claude plugin validate plugins/bifrost-agent --strict` for a local checkout, or inspect the installed plugin in `/plugin`.
2. Check the `/plugin` Errors tab and restart with `claude --debug` to see LSP registration and startup failures.
3. Run `plugins/bifrost-agent/bin/bifrost-launcher.mjs doctor` to verify the pinned binary, or set `BIFROST_BINARY_PATH` to an absolute compatible binary for local testing.
4. Disable another LSP plugin that claims the same extension. Claude Code assigns an extension to the first valid registered server.
5. Start a fresh session after plugin updates; an existing session keeps the previous LSP child and plugin path until plugins are reloaded.

## Can My Agent Run RQL?

Confirm that `query_code` appears in `/mcp` for the fresh session. Then ask Claude to call it once with the inline JSON fields `{"match":{"kind":"declaration"},"limit":1}`. To validate saved RQL, check a workspace file named `bifrost-smoke.rql` containing `(limit 1 (declaration))`, then ask Claude to call `query_code` with `{"query_file":"bifrost-smoke.rql"}`.

The inline call is canonical JSON, not RQL. MCP accepts RQL only from a workspace `.rql` file named by `query_file`. A successful `get_summaries` or `search_symbols` call proves symbol navigation but does not prove that `query_code` is enabled. See [MCP query and RQL availability](/mcp/#query-and-rql-availability) for the full surface matrix and [Agent Result Safety](/agent-result-safety/) before making completeness claims.

## Manual MCP Entry

Use a manual MCP entry instead of the plugin-provided server when you want the raw command shape or a different toolset:

```bash
claude mcp add --scope user bifrost -- bifrost --root /path/to/project --mcp "symbol|extended"
claude mcp list
```

Use an absolute path to the Bifrost binary if `bifrost` is not intentionally installed on the host `PATH`.

Use `--mcp core` only when you intentionally want navigation without `query_code`.
