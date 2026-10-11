---
title: Zed LSP
description: Status of Bifrost language-server support in Zed.
---

:::caution[No released Zed LSP setup yet]
The language server is the separate `bifrost-lsp` program, and `bifrost-lsp`
has no release yet. Bifrost built after release 0.12.0 does not serve LSP:
`bifrost --lsp` exits with an error. See [LSP Server](/lsp/).
:::

Bifrost has no published Zed extension. The Bifrost source repository contains
an unpublished development scaffold for one. It starts the language server with:

```bash
bifrost-lsp --root <worktree-root>
```

It uses the `binary.path` setting of the language server's own entry, then of
`lsp.bifrost`, and otherwise looks for `bifrost-lsp` on `PATH`. Values in
`lsp.bifrost.binary.arguments` are appended after `--root`.
Until `bifrost-lsp` is released, the scaffold has no release binary to start.
It is not a supported integration.

To use Bifrost tools from Zed's agent, configure MCP instead. MCP does not need
the language server. See [Zed MCP](/zed-mcp/).
