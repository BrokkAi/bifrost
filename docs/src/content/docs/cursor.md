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
