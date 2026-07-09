---
title: Antigravity
description: Install and validate Bifrost MCP tools and skills in Google Antigravity.
---

Google Antigravity can use Bifrost through a manual MCP server entry. Antigravity's visible **Add MCP** flow is a curated marketplace, but the app also reads local MCP configuration from `~/.gemini/config/mcp_config.json`.

For Antigravity's underlying host conventions, see the official [MCP](https://antigravity.google/docs/mcp) and [Skills](https://antigravity.google/docs/skills) documentation.

## Configure MCP

Build Bifrost first:

```bash
cargo build --bin bifrost
```

Add a `bifrost` entry to `~/.gemini/config/mcp_config.json`:

```json
{
  "mcpServers": {
    "bifrost": {
      "command": "/path/to/bifrost/target/debug/bifrost",
      "args": [
        "--root",
        "/path/to/workspace",
        "--mcp",
        "symbol|extended"
      ]
    }
  }
}
```

Restart Antigravity or open **Settings -> Customizations** and click **Refresh**. The **Installed MCP Servers** section should show `bifrost` with the Bifrost tools enabled.

## Add Skills

Antigravity documents skills as folders with `SKILL.md` under either the workspace or global skill directory:

- `<workspace-root>/.agents/skills/<skill-folder>/`
- `~/.gemini/antigravity/skills/<skill-folder>/`

In Antigravity 2.2.1 validation, workspace-local skills loaded reliably and appeared in project-specific settings. If global skills do not appear in your app session, install Bifrost's generic code-intelligence skills into each target workspace:

```bash
bifrost --root /path/to/workspace --install-skills --target project --mode copy
```

Use `--skills-root ~/.gemini/antigravity/skills` only when you explicitly want
to install into Antigravity's global app-state root. See
[CLI](/cli/#install-agent-skills) for the full option list.

Then restart Antigravity. Open the project-specific settings page, not only global **Customizations**. The project **Customizations** section should list `bifrost-code-navigation`, `bifrost-code-reading`, and `bifrost-codebase-search` alongside any global skills.

## Use It for Guided Review

Bifrost's default generic skills expose analyzer-backed navigation, reading,
search, and usage guidance. Use them as the code-intelligence layer for guided
review workflows: ask Antigravity to load the relevant Bifrost skill, inspect
the changed files, use Bifrost MCP tools for source context, and present review
findings with file and line references.

## Validate the Setup

Use a source-backed prompt that forces an MCP tool call:

```text
Use the bifrost-code-reading skill. Inspect the current changes, use the Bifrost MCP get_summaries tool on src/analyzer/usages for source context, and report review findings with file and line references.
```

Antigravity should ask for MCP permission the first time it calls the tool. A successful smoke should show a `bifrost / get_summaries` tool call before it presents review context or findings.

Avoid prompts that only ask about `README.md` or docs files; those can pass through ordinary file reading without proving the MCP server ran.
