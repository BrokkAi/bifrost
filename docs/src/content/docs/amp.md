---
title: Amp
description: Use Bifrost MCP tools from Amp.
---

Amp can use Bifrost as an MCP server. Configure the server directly in Amp's
MCP settings with an explicit workspace root:

```json
{
  "bifrost": {
    "command": "/absolute/path/to/bifrost",
    "cwd": "/absolute/path/to/workspace",
    "args": ["--root", ".", "--mcp", "symbol|extended"]
  }
}
```

For local development, set `command` to the checked-out Bifrost binary. Start a
fresh Amp task after changing the MCP configuration.

## Validate the Setup

Start Amp from the configured workspace, then ask it to call a Bifrost tool:

```text
Call the Bifrost get_summaries tool on src/analyzer/usages and summarize the package structure in five bullets.
```

Use a source directory or source file for validation. Avoid a prompt that only
asks about `README.md`, because that can pass through ordinary file reading
without proving that the MCP server ran.

Apply the shared [host-integration evidence contract](/mcp/#validate-host-integration):
retain the Bifrost tool event and structured result for a known workspace,
verify its project-relative source path, and reject file-reading fallbacks.

## Can My Agent Run RQL?

The configuration uses `symbol|extended`, so `query_code` is available. Ask Amp
to call `query_code` with the inline JSON fields
`{"match":{"kind":"declaration"},"limit":1}`. To validate saved RQL, create
`bifrost-smoke.rql` with `(limit 1 (declaration))`, then call
`query_code` with `{"query_file":"bifrost-smoke.rql"}`.

The inline call is canonical JSON. MCP accepts RQL only from a workspace `.rql`
file through `query_file`. See [MCP query and RQL availability](/mcp/#query-and-rql-availability)
for the full surface matrix.

## Direct MCP Shape

Bifrost's raw MCP command is:

```bash
bifrost --root /path/to/project --mcp "symbol|extended"
```

Use `--mcp core` only when you intentionally want navigation without
`query_code`.
