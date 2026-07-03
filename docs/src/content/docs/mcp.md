---
title: MCP Server
description: Run Bifrost as a stdio MCP server for code-intelligence tools.
---

Bifrost can run as a stdio MCP server. Always pass an explicit workspace root so the host analyzes the intended repository.

```bash
bifrost --root /path/to/project --mcp core
```

The `--mcp` argument accepts ordered toolset compositions:

- `core`: common agent tools.
- `searchtools`: compatibility mode exposing the full current tool union.
- `symbol|workspace`: a smaller explicit composition.
- `extended`: additional repository discovery tools.

Codex CLI example:

```bash
codex mcp add bifrost -- bifrost --root /path/to/project --mcp core
```

Claude Code example:

```bash
claude mcp add --scope user bifrost -- bifrost --root /path/to/project --mcp core
```
