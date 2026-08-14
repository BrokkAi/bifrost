# Bifrost for Zed

Local Zed extension scaffold for validating Bifrost's LSP mode.

## Development

Build Bifrost from the repository root:

```bash
cargo build --bin bifrost
```

Open Zed, run `zed: install dev extension`, and select `editors/zed`.

For the first smoke test, put the Bifrost binary on `PATH` and configure the
language to use only the Bifrost adapter:

```json
{
  "languages": {
    "Rust": {
      "language_servers": ["bifrost-rust", "!rust-analyzer"]
    }
  }
}
```

Avoid `lsp.bifrost-rust.binary.path` for local testing. Zed treats that as a
direct language-server binary override and starts it without the extension's
`--root <worktree-root> --lsp` arguments.

The extension starts Bifrost with:

```bash
bifrost --root <worktree-root> --lsp
```

Any `lsp.bifrost.binary.arguments` values are appended after `--lsp` and can
be used for local debugging flags.
