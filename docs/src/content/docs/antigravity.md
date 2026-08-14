---
title: Antigravity
description: Install and validate Bifrost MCP tools in Google Antigravity.
---

Google Antigravity can use Bifrost through a manual MCP server entry. Antigravity's visible **Add MCP** flow is a curated marketplace, but the app also reads global MCP configuration from `~/.gemini/config/mcp_config.json` and workspace-local configuration from `<workspace>/.agents/mcp_config.json`.

For Antigravity's underlying host conventions, see the official [MCP](https://antigravity.google/docs/mcp) documentation.

## Configure MCP

Install the release verified with this setup and record its absolute path:

```bash
cargo install brokk-bifrost --version 0.8.9 --locked --force
command -v bifrost
bifrost --version
```

The version check should print `bifrost 0.8.9`.

### One fixed workspace

For a single fixed workspace, add a `bifrost` entry to the global
`~/.gemini/config/mcp_config.json`, using the absolute binary path reported by
`command -v bifrost`:

```json
{
  "mcpServers": {
    "bifrost": {
      "command": "/absolute/path/to/bifrost",
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

This global configuration is not dynamic. It always starts Bifrost for the
same path, even when Antigravity opens another Project or Git worktree.

### Git worktrees and multiple projects

Use workspace-local MCP configuration for worktrees and whenever you regularly
switch projects. Create or merge a `bifrost` entry into
`<worktree>/.agents/mcp_config.json` from that worktree:

```json
{
  "mcpServers": {
    "bifrost": {
      "command": "/absolute/path/to/bifrost",
      "cwd": "/absolute/path/to/this/worktree",
      "args": [
        "--root",
        ".",
        "--mcp",
        "symbol|extended"
      ]
    }
  }
}
```

`cwd` makes `--root .` resolve to this exact worktree. Do not omit either
field: Bifrost must not infer its analyzer root from Antigravity's process
working directory, plugin directory, or the selected Project. Antigravity does
not currently provide Bifrost with a dynamic MCP workspace-root signal, so a
rootless global server correctly remains unbound instead of following the
active worktree.

The local file contains an absolute, machine-specific worktree path. Keep it
uncommitted and create it in each new worktree. An installation helper may
derive the path with `git rev-parse --show-toplevel`, but it must merge only
the `bifrost` entry and must not overwrite other MCP servers in the file.

In Antigravity 2.x, create or select a Project that contains this same
workspace: click the folder-plus icon beside **Projects**, choose **New
Project**, and add the checkout. Use the **Local** environment when validating
an existing checkout. **New Worktree** intentionally creates another checkout,
so its expected analyzer root will differ.

Open **Settings -> Customizations** and click **Refresh** after creating or
changing either MCP configuration. Refresh is normally enough; it restarts the
MCP connection and reloads the tools without requiring a full Antigravity
restart. Start a fresh conversation for the smoke test below. If Refresh still
shows an old executable or workspace path, fully quit and reopen Antigravity
so its MCP process and cached tool schemas are recreated.
The **Installed MCP Servers** section should show `bifrost` with
`search_symbols` and `query_code`.

## Validate the Setup

For strong exact-checkout evidence, add a temporary declaration whose name is
unique to this smoke, for example:

```rust
// src/antigravity_bifrost_host_probe_4f6f2b7.rs
pub fn antigravity_bifrost_host_probe_4f6f2b7() {}
```

Start a fresh conversation under the Project you created above and use a prompt
that requires two real MCP calls:

```text
Use only Bifrost MCP tools for this verification; do not use terminal commands or built-in file-reading or search tools. Call search_symbols for antigravity_bifrost_host_probe_4f6f2b7, then call query_code with schema_version 1, languages ["rust"], match {"kind":"function","name":"antigravity_bifrost_host_probe_4f6f2b7"}, limit 10, and result_detail "full". PASS only if both real calls return src/antigravity_bifrost_host_probe_4f6f2b7.rs.
```

Antigravity should ask for permission to call `bifrost/*` the first time. You
can save that rule for only this Project. A successful smoke shows real
`bifrost/search_symbols` and `bifrost/query_code` calls, and both results name
the temporary project-relative path. Remove the temporary file after retaining
the evidence.

Avoid prompts that only ask about `README.md` or docs files; those can pass through ordinary file reading without proving the MCP server ran.

Apply the shared
[host-integration evidence contract](/mcp/#validate-host-integration): retain
the permitted Bifrost tool event and structured result, verify the result
belongs to the active project, and reject file-reading fallbacks.

## Can My Agent Run RQL?

The configuration above uses `symbol|extended`. In a fresh Antigravity session, confirm that the enabled Bifrost tool list includes `query_code`, then call it with the inline JSON fields `{"match":{"kind":"declaration"},"limit":1}`. To validate saved RQL, check a workspace file named `bifrost-smoke.rql` containing `(limit 1 (declaration))`, then call `query_code` with `{"query_file":"bifrost-smoke.rql"}`.

The inline call is canonical JSON. MCP accepts RQL only from a workspace `.rql` file through `query_file`. See [MCP query and RQL availability](/mcp/#query-and-rql-availability) for the full surface matrix and [Agent Result Safety](/agent-result-safety/) before making completeness claims.
