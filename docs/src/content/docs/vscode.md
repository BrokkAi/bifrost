---
title: VS Code LSP
description: Use the Bifrost VS Code extension for editor navigation.
---

The VS Code extension lives in `editors/vscode`. It starts Bifrost with:

```bash
bifrost --root <workspace-root> --lsp
```

For extension development:

```bash
cd editors/vscode
npm install
npm test
```

Use the extension setting `bifrost.serverPath` when testing a locally built Bifrost binary.

The extension also includes commands for MCP setup, including a copyable MCP configuration for the current workspace.
