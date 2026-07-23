---
title: Antigravity
description: Install and validate Bifrost MCP tools and skills in Google Antigravity.
---

Google Antigravity can use Bifrost through a manual MCP server entry. Antigravity's visible **Add MCP** flow is a curated marketplace, but the app also reads local MCP configuration from `~/.gemini/config/mcp_config.json`.

For Antigravity's underlying host conventions, see the official [MCP](https://antigravity.google/docs/mcp) and [Skills](https://antigravity.google/docs/skills) documentation.

## Configure MCP

Install the release verified with this setup and record its absolute path:

```bash
cargo install brokk-bifrost --version 0.8.9 --locked --force
command -v bifrost
bifrost --version
```

The version check should print `bifrost 0.8.9`. Add a `bifrost` entry to the
global `~/.gemini/config/mcp_config.json`, using the absolute binary path
reported by `command -v bifrost`:

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

Antigravity also accepts a project-local MCP configuration at
`<workspace>/.agents/mcp_config.json`. Whichever scope you use, pass the exact
workspace path to `--root`; do not rely on Antigravity's subprocess working
directory.

In Antigravity 2.x, create or select a Project that contains this same
workspace: click the folder-plus icon beside **Projects**, choose **New
Project**, and add the checkout. Use the **Local** environment when validating
an existing checkout. **New Worktree** intentionally creates another checkout,
so its expected analyzer root will differ.

Restart Antigravity or open **Settings -> Customizations** and click **Refresh**.
The **Installed MCP Servers** section should show `bifrost` with
`search_symbols` and `query_code`. If an error still quotes an old executable
or workspace path after Refresh, fully quit and reopen Antigravity so its MCP
process and cached tool schemas are recreated.

## Add Skills

Antigravity documents skills as folders with `SKILL.md` under either the workspace or global skill directory:

- `<workspace-root>/.agents/skills/<skill-folder>/`
- `~/.gemini/config/skills/<skill-folder>/`

Install project-local skills when you want them limited to this checkout:

```bash
bifrost --root /path/to/workspace --install-skills --target project --mode copy
```

For a current global Antigravity installation, use:

```bash
bifrost --root /path/to/workspace \
  --install-skills \
  --skills-root ~/.gemini/config/skills \
  --mode copy
```

Antigravity 2.2.1 used the older
`~/.gemini/antigravity/skills` global directory. If you upgrade from that
version, reinstall the skills into `~/.gemini/config/skills`; leaving only the
old copies does not make them available to Antigravity 2.3.1. See
[CLI](/cli/#install-agent-skills) for the full option list.

Then restart Antigravity. Open the project-specific settings page, not only global **Customizations**. The project **Customizations** section should list `bifrost-code-navigation`, `bifrost-code-reading`, and `bifrost-codebase-search` alongside any global skills.

## Use It for Guided Review

Bifrost's default generic skills expose analyzer-backed navigation, reading,
search, and usage guidance. Use them as the code-intelligence layer for guided
review workflows: ask Antigravity to load the relevant Bifrost skill, inspect
the changed files, use Bifrost MCP tools for source context, and present review
findings with file and line references.

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
Load the bifrost-codebase-search skill. Use only Bifrost MCP tools for this verification; do not use terminal commands or built-in file-reading or search tools. Call search_symbols for antigravity_bifrost_host_probe_4f6f2b7, then call query_code with schema_version 2, languages ["rust"], match {"kind":"function","name":"antigravity_bifrost_host_probe_4f6f2b7"}, limit 10, and result_detail "full". PASS only if both real calls return src/antigravity_bifrost_host_probe_4f6f2b7.rs.
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

The inline call is canonical JSON. MCP accepts RQL only from a workspace `.rql` file through `query_file`. The separately installed skills provide guidance but do not expose MCP tools themselves. See [MCP query and RQL availability](/mcp/#query-and-rql-availability) for the full surface matrix and [Agent Result Safety](/agent-result-safety/) before making completeness claims.
