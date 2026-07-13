---
title: VS Code LSP
description: Use the Bifrost VS Code extension for editor navigation.
---

Install the extension from the [Visual Studio Marketplace](https://marketplace.visualstudio.com/items?itemName=Brokk.bifrost-vscode).

Requirements:

- VS Code 1.90 or newer.
- A supported platform for extension-managed Bifrost binary downloads, or a `bifrost` binary available through one of the launch modes below.

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

## RQL Highlighting

The extension automatically recognizes `.rql` files as **Bifrost RQL** and
highlights RQL query structure, known forms, literals, and comments. It is a
TextMate grammar only, so opening a query file does not start the Bifrost
language server or validate the query. If another extension owns `.rql` in a
workspace, use VS Code's language-mode picker to select **Bifrost RQL**.
The Bifrost helmet is its default file icon when the active VS Code icon theme
does not provide a more specific `.rql` icon.

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
| `bifrost.unrecognizedSymbolDiagnostics` | `false` | Enable experimental unrecognized-symbol and member diagnostics. |

Changes to `bifrost.roots`, `bifrost.exclude`, `bifrost.formatterCommands`, and `bifrost.unrecognizedSymbolDiagnostics` apply to the running language server without a restart. Root and exclusion changes rebuild the workspace index; formatter changes affect subsequent formatting requests. Removing one of these settings sends its default value so the previous runtime setting is cleared.

Changes to process-launch settings still require a restart: `bifrost.launchMode`, `bifrost.serverPath`, `bifrost.debug`, `bifrost.slowRequestMs`, and `bifrost.extraArgs`. The extension prompts before restarting for those settings.

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

## MCP Setup

Run `Bifrost: Open MCP Setup` from the Command Palette to choose a setup action: copy generic `mcp.json`, copy a Codex CLI command, copy a Claude Code command, or open the Bifrost MCP docs. `Bifrost: Copy MCP Config` remains available when you only want the generic JSON entry.

These commands are manual. The extension does not open MCP setup on activation, does not mutate external host configuration, and does not prompt again after dismissal.

The MCP setup commands use the same binary resolution settings as the language server where practical: a configured `bifrost.serverPath`, the extension-managed binary, a local development build, or `bifrost` on `PATH`.

The copied entry uses the current workspace root and starts a separate Bifrost MCP process:

```json
{
  "mcpServers": {
    "bifrost": {
      "command": "/path/to/bifrost",
      "args": ["--root", "/path/to/workspace", "--mcp", "searchtools"]
    }
  }
}
```

Do not point MCP hosts at the VS Code LSP process. The extension and MCP hosts should launch separate stdio processes from the same Bifrost binary or release.
