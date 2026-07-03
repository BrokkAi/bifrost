---
title: VS Code LSP
description: Use the Bifrost VS Code extension for editor navigation.
---

Install the extension from the [Visual Studio Marketplace](https://marketplace.visualstudio.com/items?itemName=Brokk.bifrost-vscode).

The extension source lives in `editors/vscode`. It starts Bifrost with:

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

## Extension Settings

| Setting | Default | Description |
| --- | --- | --- |
| `bifrost.launchMode` | `auto` | How to start Bifrost: `auto`, `bundled`, or `path`. |
| `bifrost.serverPath` | `bifrost` | Path to the `bifrost` binary, or command name to resolve on `PATH`. |
| `bifrost.debug` | `false` | Enable verbose LSP request and notification tracing. |
| `bifrost.slowRequestMs` | `2000` | Log LSP requests and notifications that take at least this many milliseconds. |
| `bifrost.extraArgs` | `[]` | Additional command-line arguments appended when launching the Bifrost LSP server. |
| `bifrost.roots` | `[]` | Workspace-relative or absolute directories to index instead of the full VS Code workspace. Empty means use VS Code workspace folders. |
| `bifrost.exclude` | `[]` | Workspace-relative or absolute files or directories to exclude from Bifrost indexing and LSP lookups. |
| `bifrost.formatterCommands` | `[]` | Ordered formatter command rules passed to Bifrost from user settings only. Rules run without a shell, receive document text on stdin, and write the formatted document to stdout. |

Launch mode behavior:

- `auto`: use `bifrost.serverPath` when explicitly configured, then the extension-managed binary when available, then a local development binary under `target/`, then `bifrost` on `PATH`.
- `bundled`: require the extension-managed binary for this platform and prompt to install it when missing.
- `path`: use `bifrost.serverPath`, falling back to `bifrost` on `PATH`.

`bifrost.formatterCommands` entries support:

| Field | Description |
| --- | --- |
| `include` | Workspace-relative glob patterns this formatter rule applies to. |
| `exclude` | Workspace-relative glob patterns this formatter rule must not apply to. |
| `language` | Optional Bifrost language filter, such as `rust`, `go`, `typescript`, `java`, `csharp`, `php`, or `ruby`. |
| `command` | Executable name or path. This is executed directly and is not shell-parsed. |
| `args` | Command arguments. Supports `{file}`, `{relativeFile}`, `{workspaceRoot}`, and `{language}` placeholders. |
| `cwd` | Working directory for the formatter. Relative paths are resolved against the workspace root and support placeholders. |

The extension also includes commands for MCP setup, including a copyable MCP configuration for the current workspace.
