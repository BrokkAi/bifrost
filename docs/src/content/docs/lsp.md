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

## CLI Tooling

For terminal checks and scripts, use one-shot tool mode instead of starting an LSP session:

```bash
bifrost --root /path/to/project --tool search_symbols --args '{"patterns":["MyClass"]}'
```

Limit one-shot workspace construction with `--sources` when the query only needs part of a repository:

```bash
bifrost --root /path/to/project --tool get_symbol_sources --sources src --sources 'tests/**/*.rs' --args '{"symbols":["src/main.rs"]}'
```

Tool mode prints JSON and exits. Use `bifrost --help` to list available modes and toolsets, or `bifrost --help <tool>` for a specific tool's parameters.
