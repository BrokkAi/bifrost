---
title: Cursor
description: Install and validate Bifrost in Cursor.
---

Cursor can use Bifrost through the native Cursor plugin package in this repository. The shared plugin package lives in `plugins/bifrost-agent`, and the repository root includes `.cursor-plugin/marketplace.json` so Cursor can discover the package.

## Install From GitHub

In Cursor, open **Customize**, then use **Manage -> Add Marketplace -> Import from GitHub** and enter:

```text
https://github.com/BrokkAi/bifrost
```

Cursor should read `.cursor-plugin/marketplace.json`, find the `bifrost` plugin at `plugins/bifrost-agent`, and offer it for installation.

## Local Plugin Testing

Build Bifrost first:

```bash
cargo build --bin bifrost
```

Open Cursor with the local binary selected:

```bash
BIFROST_BINARY_PATH="$(pwd)/target/debug/bifrost" cursor .
```

In Cursor, open **Customize**, then use **Manage -> Add Marketplace -> Import from Disk** and select the repository root.

If you are testing the package directory directly instead of the repository marketplace, select `plugins/bifrost-agent`.

## Enable MCP Tools

After installing the plugin, enable the Bifrost MCP server for the workspace from the plugin's **MCPs** section in Customize. Already-open agent chats may need a fresh chat before newly enabled MCP tools appear.

Use a smoke prompt that proves Cursor called Bifrost instead of just reading files:

```text
Use the Bifrost MCP get_summaries tool on src/analyzer/usages. Summarize the package structure in five bullets and explicitly name the MCP tool result you used.
```

The `cursor agent --plugin-dir` CLI path is useful for checking that Cursor can load plugin skills, but it has not proven reliable for plugin-provided MCP servers. Treat the desktop Customize/MCP flow as the MCP validation path.

## Can My Agent Run RQL?

The packaged plugin uses `symbol|extended`. In a fresh chat after enabling MCP, confirm that the Bifrost tool list includes `query_code`, then call it with the inline JSON fields `{"match":{"kind":"declaration"},"limit":1}`. To validate saved RQL, check a workspace file named `bifrost-smoke.rql` containing `(limit 1 (declaration))`, then call `query_code` with `{"query_file":"bifrost-smoke.rql"}`.

The inline call is canonical JSON. MCP accepts RQL only from a workspace `.rql` file through `query_file`. Loading plugin skills without enabling its MCP server provides instructions but no Bifrost tools. See [MCP query and RQL availability](/mcp/#query-and-rql-availability) for the full surface matrix and [Agent Result Safety](/agent-result-safety/) before making completeness claims.
