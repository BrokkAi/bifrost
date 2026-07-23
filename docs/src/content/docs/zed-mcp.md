---
title: Zed Agent MCP
description: Configure Zed Agent to call Bifrost MCP tools.
---

Zed's Agent Panel can call Bifrost through Model Context Protocol. This is
separate from Zed editor/LSP support: configure MCP when you want the agent to
call analyzer-backed tools such as `get_summaries`.

Until Bifrost is published through the official MCP registry, configure Bifrost
as a custom stdio context server in `settings.json`.

## Configure MCP

Build or install Bifrost first:

```bash
cargo install brokk-bifrost --locked --force
```

For local development, build this checkout and use an absolute path to the
debug binary:

```bash
cargo build --bin bifrost
```

Add a `context_servers` entry to your Zed settings:

```json
{
  "context_servers": {
    "bifrost": {
      "command": "/path/to/bifrost",
      "args": ["--root", "/path/to/project", "--mcp", "symbol|extended"],
      "env": {}
    }
  }
}
```

For a local checkout build, `command` should point at
`/path/to/bifrost/target/debug/bifrost`. Always pass an explicit `--root`;
otherwise Bifrost analyzes whatever directory Zed uses as the subprocess working
directory.

`symbol|extended` exposes the analyzer-backed code-intelligence tools used by
the Bifrost agent package, including `search_symbols`, `get_summaries`,
`scan_usages_by_location`, `get_symbol_locations`, and related repository discovery tools.
Use a smaller or larger MCP toolset only when the host should see a different
surface. See [MCP Server](/mcp/) for the available toolsets.

Open Zed's Agent settings and confirm the Model Context Protocol section lists
the Bifrost server with its tool count. If the server is disabled, enable it
there before starting a new Agent thread.

## Add Skills

Zed skills are separate from MCP tools. The MCP server makes Bifrost tools
available; skills provide reusable agent instructions for when and how to use
those tools.

Zed loads skills only from `~/.agents/skills/` and
`<worktree>/.agents/skills/`. It does not discover skills directly from
`plugins/bifrost-agent/skills`. If you want Zed to see the Bifrost
code-intelligence skills, use the Bifrost CLI to install them into one of Zed's
supported skill roots:

```bash
bifrost --root /path/to/project --install-skills --target project
```

Use `--target global` for `~/.agents/skills`, or `--mode copy` when you want a
self-contained install instead of a checkout-local symlink. See
[CLI](/cli/#install-agent-skills) for the full option list.

The recommended first set is:

- `bifrost-code-navigation`
- `bifrost-code-reading`
- `bifrost-codebase-search`

Workflow skills such as guided review or PR review may depend on host-specific
tools and should be installed only after validating that the host provides the
needed capabilities.

## Validate the Setup

Use a prompt that requires a Bifrost MCP tool result instead of ordinary file
reading:

```text
Use the Bifrost MCP get_summaries tool on src/main.rs. Reply with the symbols returned by the tool.
```

A successful response should name analyzer symbols from the MCP result, such as
modules, classes, fields, or functions from the target file. If the agent says
it cannot access Bifrost tools and falls back to reading files directly, check
that:

- the `context_servers` entry is present in the active Zed settings file,
- the server is enabled in Agent settings,
- the command path points at an existing Bifrost binary,
- `--root` points at the project you want analyzed, and
- the thread was created after the server was added or enabled.

Avoid prompts that only ask about `README.md` or docs files; those can pass
through ordinary file reading without proving the MCP server ran.

Apply the shared
[host-integration evidence contract](/mcp/#validate-host-integration): retain
Zed's Bifrost tool event and structured result for a known workspace
declaration, verify its project-relative source path, and reject paths under the
configured binary's install directory or another repository.

## Can My Agent Run RQL?

The configuration above uses `symbol|extended`. In a new Agent thread, confirm that the Bifrost tool list includes `query_code`, then call it with the inline JSON fields `{"match":{"kind":"declaration"},"limit":1}`. To validate saved RQL, check a workspace file named `bifrost-smoke.rql` containing `(limit 1 (declaration))`, then call `query_code` with `{"query_file":"bifrost-smoke.rql"}`.

The inline call is canonical JSON. MCP accepts RQL only from a workspace `.rql` file through `query_file`. Zed skills remain separate instructions and cannot expose Bifrost tools without the context server. See [MCP query and RQL availability](/mcp/#query-and-rql-availability) for the full surface matrix and [Agent Result Safety](/agent-result-safety/) before making completeness claims.
