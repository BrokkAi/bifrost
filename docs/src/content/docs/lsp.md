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

## Protocol Surface

Bifrost advertises LSP capabilities only after the matching handler exists. Unsupported requests return JSON-RPC `MethodNotFound`; unsupported notifications are ignored.

Current support includes incremental and whole-document text synchronization, save notifications, diagnostics, definition/type-definition/implementation, hover, signature help, completion, references, rename, document highlights, document symbols, formatting, folding ranges, workspace symbols, type and call hierarchy, workspace folder changes, watched-file notifications, startup progress, and formatting cancellation.

Runtime configuration changes, semantic tokens, and broader cancellation/progress support are intentional follow-up areas. Code actions, server-side execute commands, and pre-save hooks are not advertised until Bifrost has concrete safe edits or commands to expose.

## CLI Tooling

For terminal checks and scripts, use [one-shot CLI tool mode](../cli/) instead of starting an LSP session.
