---
title: LSP Server
description: Run Bifrost as a language server for editor code intelligence.
---

Bifrost can run as a Language Server Protocol server over stdio. Editors launch it with an explicit workspace root:

```bash
bifrost --root /path/to/project --lsp
```

The server does not open a network port. It speaks LSP over stdin and stdout, builds the workspace index in the background, and lets the first request wait for indexing when necessary.

## Editor Integration

Use the [VS Code extension](./vscode/) for the packaged editor experience. The extension starts Bifrost with:

```bash
bifrost --root <workspace-root> --lsp
```

Other editors that can launch a stdio LSP server can use the same command shape. Pass the repository or workspace directory as `--root` so Bifrost analyzes the intended project.

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
