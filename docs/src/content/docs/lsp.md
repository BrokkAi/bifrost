---
title: LSP Server
description: The Bifrost language server has moved out of this repository.
---

The Bifrost language server no longer ships from this repository. `bifrost --lsp`
and `bifrost --server lsp` now fail with a message saying so, so an editor that
still launches them reports a clear error instead of hanging on a server that
never starts.

Bifrost's code intelligence is available over MCP, which every supported agent
host and several editors can call:

```bash
bifrost --root /path/to/project --mcp searchtools
```

See [Claude Code](/claude-code/) and [opencode](/opencode/) for host setup, and
[Capabilities](/capabilities/) for what the tools answer. For terminal checks
and scripts, use [one-shot CLI tool mode](../cli/).

An editor integration that needs the Language Server Protocol should follow the
language server to its new home. This page stays as the pointer for links that
still reach it.

The standalone server and VS Code extension live in
[BrokkAi/bifrost-lsp](https://github.com/BrokkAi/bifrost-lsp). Open semantic
packs and policy rules come from
[Bifrost-packs](https://github.com/BrokkAi/bifrost-packs), with release
compatibility and qualification checked separately from the editor/server
version. The extension's persistent storage provides the cache for verified
content and offline reuse.
