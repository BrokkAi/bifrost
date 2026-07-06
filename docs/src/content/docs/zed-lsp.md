---
title: Zed LSP
description: Configure Zed to use Bifrost as an editor language server.
---

Zed can use Bifrost as an editor language server for navigation and references.
This is separate from Zed Agent/MCP support: configure the LSP adapter when you
want editor features, and configure MCP when you want the agent to call Bifrost
tools.

The Bifrost Zed extension lives in `editors/zed`. It starts Bifrost with:

```bash
bifrost --root <worktree-root> --lsp
```

## Install the Development Extension

For local development, build Bifrost from the repository root:

```bash
cargo build --bin bifrost
```

Then open Zed, run `zed: install dev extension`, and select `editors/zed`.

For the first smoke test, put the Bifrost binary on `PATH` and configure the
language to use the Bifrost adapter:

```json
{
  "languages": {
    "Rust": {
      "language_servers": ["bifrost-rust", "!rust-analyzer"]
    }
  }
}
```

If you want Bifrost to run alongside Zed's default language server, keep both
servers in the list:

```json
{
  "languages": {
    "Rust": {
      "language_servers": ["bifrost-rust", "rust-analyzer"]
    }
  }
}
```

Use the concrete Zed adapter ID for the language you are configuring, such as
`bifrost-rust`, `bifrost-python`, `bifrost-go`, `bifrost-javascript`,
`bifrost-typescript`, `bifrost-ruby`, `bifrost-php`, `bifrost-csharp`,
`bifrost-scala`, or `bifrost-java`.

Avoid `lsp.bifrost-rust.binary.path` for local testing. Zed treats that setting
as a direct language-server binary override and starts the executable without
the extension's `--root <worktree-root> --lsp` arguments. Prefer PATH-based
resolution or the dev extension path so the extension can add the workspace
root arguments.

## Validate the Setup

Open a supported source file and use Zed's normal go-to-definition or references
actions. Bifrost should be the language server handling the request for the
configured adapter.

If Zed rejects the settings block with a message like `Property bifrost is not
allowed`, check that the setting uses the adapter ID, such as `bifrost-rust`,
not a generic `bifrost` language-server key.
