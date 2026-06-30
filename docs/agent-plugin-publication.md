# Bifrost Agent Plugin Publication

This is the Bifrost-owned publication path for making the MCP server
discoverable as an Agent Plugin. It documents the repo-local artifact shape to
use when the plugin moves from planning to packaging.

## Plugin shape

Create a plugin directory whose manifest lives at `.codex-plugin/plugin.json`:

```json
{
  "name": "bifrost",
  "version": "0.6.8",
  "description": "Bifrost code intelligence over MCP.",
  "author": {
    "name": "Brokk",
    "url": "https://brokk.ai"
  },
  "homepage": "https://github.com/BrokkAi/bifrost",
  "repository": "https://github.com/BrokkAi/bifrost",
  "license": "LGPL-3.0-or-later",
  "keywords": ["bifrost", "mcp", "code-intelligence"],
  "mcpServers": "./.mcp.json",
  "interface": {
    "displayName": "Bifrost",
    "shortDescription": "Analyzer-backed code intelligence tools.",
    "longDescription": "Bifrost exposes search, symbol, workspace, and code-quality tools through a stdio MCP server.",
    "developerName": "Brokk",
    "category": "Developer Tools",
    "capabilities": ["Interactive", "Read", "Write"]
  }
}
```

Add the companion `.mcp.json` next to the manifest:

```json
{
  "mcpServers": {
    "bifrost": {
      "command": "/path/to/bifrost",
      "args": ["--root", "${workspaceFolder}", "--mcp", "searchtools"]
    }
  }
}
```

Use the same Bifrost release that the VS Code extension pins in
`editors/vscode/package.json`. When the host cannot expand
`${workspaceFolder}`, replace it with an absolute project root during
installation or setup.

## Publishing checklist

- Build and publish the Bifrost release archives for every supported platform.
- Update the VS Code extension's `bifrost.binaryVersion` and
  `bifrost.archiveSha256` entries to the same release.
- Package the Agent Plugin with `.codex-plugin/plugin.json` and `.mcp.json`.
- Validate that the plugin's MCP server entry launches:
  `bifrost --root <workspace-root> --mcp searchtools`.
- Confirm that plugin installation and VS Code LSP setup use separate Bifrost
  stdio processes, even when they point at the same binary/release.

## Current skill bundle

The Brokk host skills are still packaged from the Brokk plugin source rather
than this repository. Until that bundle moves here, publish the Bifrost Agent
Plugin as an MCP-server package only, and keep skill migration as a separate
tracked change.
