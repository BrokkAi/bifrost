# Bifrost VS Code Extension

Minimal VS Code language-client wrapper for the Bifrost LSP server.

## Development

Build the Bifrost server from the repository root:

```bash
cargo build --bin bifrost
```

Install and compile the extension:

```bash
cd editors/vscode
npm install
npm run compile
```

Open this folder in VS Code, set `bifrost.serverPath` to the absolute path of
the built server, for example:

```json
{
  "bifrost.serverPath": "/path/to/bifrost/target/debug/bifrost"
}
```

Run the extension in an Extension Development Host and open a workspace with a
supported source file. The extension starts Bifrost with:

```bash
bifrost --root <workspace-root> --server lsp
```

`--root` is only the fallback root. VS Code still sends the active workspace
folders during LSP initialization, including multi-root workspaces.

## Debugging

The extension pipes Bifrost stderr into `Output > Bifrost`.

Useful settings:

```json
{
  "bifrost.debug": true,
  "bifrost.slowRequestMs": 1000
}
```

`bifrost.debug` logs every LSP request/notification start and finish.
`bifrost.slowRequestMs` logs requests or notifications that take longer than
the configured threshold. Handler errors and panics are always logged with LSP
method context.
