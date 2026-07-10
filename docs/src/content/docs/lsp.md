---
title: LSP Server
description: Run Bifrost as a language server for editor code intelligence.
---

Bifrost can run as a Language Server Protocol server over stdio. Start it with an explicit workspace root:

```bash
bifrost --root /path/to/project --lsp
```

The server does not open a network port. It speaks LSP over stdin and stdout, builds the workspace index in the background, and lets the first request wait for indexing when necessary.

## Workspace Root

`--root` is the fallback workspace root. During LSP initialization, clients may send `workspaceFolders`, `rootUri`, or `rootPath`; Bifrost uses those client-provided roots when available. Use `--root` to make the server process deterministic and to provide a fallback when the client does not send a usable workspace root.

Clients can also pass Bifrost-specific `initializationOptions`:

```json
{
  "roots": ["src", "tests"],
  "exclude": ["target", "vendor/generated"]
}
```

`roots` limits indexing to selected directories under the fallback root. `exclude` removes generated output, dependency caches, or other directories from workspace symbols and document-level lookups.

## Runtime Configuration

Bifrost supports the LSP 3.18 [`workspace/didChangeConfiguration`](https://microsoft.github.io/language-server-protocol/specifications/lsp/3.18/specification/) notification. When the client advertises `workspace.configuration`, Bifrost requests the complete `bifrost` section with `workspace/configuration`. Clients without configuration-pull support can push the complete settings object directly or nest it under `bifrost`:

```json
{
  "settings": {
    "bifrost": {
      "roots": ["src", "tests"],
      "exclude": ["target"],
      "formatterCommands": []
    }
  }
}
```

Each accepted runtime value is a full snapshot. It replaces the startup `initializationOptions` and the previous runtime value; omitted or empty `roots`, `exclude`, and `formatterCommands` fields therefore clear those settings. Unknown fields are ignored, while an invalid recognized field rejects the complete snapshot and leaves the last working configuration active.

Changing only `formatterCommands` affects later formatting requests without rebuilding the analyzer. Changing `roots` or `exclude` rebuilds the workspace, preserves open editor buffers, cancels active formatter processes before swapping state, and clears published diagnostics for files that leave the workspace. Clearing `roots` restores the latest workspace folders reported by the editor.

## Protocol Surface

Bifrost advertises LSP capabilities only after the matching handler exists. Unsupported requests return JSON-RPC `MethodNotFound`; unsupported notifications are ignored.

Current support includes incremental and whole-document text synchronization, save notifications, diagnostics, definition/type-definition/implementation, hover, signature help, completion, references, rename, document highlights, document symbols, formatting, folding ranges, workspace symbols, type and call hierarchy, workspace folder and runtime configuration changes, watched-file notifications, startup progress, and formatting cancellation.

Semantic tokens and broader cancellation/progress support are intentional follow-up areas. Code actions, server-side execute commands, and pre-save hooks are not advertised until Bifrost has concrete safe edits or commands to expose.

## CLI Tooling

For terminal checks and scripts, use [one-shot CLI tool mode](../cli/) instead of starting an LSP session.
