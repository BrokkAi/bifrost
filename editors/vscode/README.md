# Bifrost: Multi-Language LSP & MCP Server

VS Code extension for Bifrost, Brokk's tree-sitter-backed multi-language code
intelligence server. The extension starts Bifrost in LSP mode and exposes
definitions, references, symbols, hierarchy, rename, diagnostics, completion,
hover, and related editor features.

## Requirements

- VS Code 1.90+
- A `bifrost` binary available through one of the launch modes below

## Configuration

| Setting | Description |
|---------|-------------|
| `bifrost.launchMode` | How to start Bifrost: `auto`, `bundled`, or `path`. |
| `bifrost.serverPath` | Path to the `bifrost` binary, or command name on `PATH`. |
| `bifrost.debug` | Enable verbose LSP request and notification tracing. |
| `bifrost.slowRequestMs` | Log LSP handlers that take at least this many milliseconds. |
| `bifrost.extraArgs` | Extra command-line arguments appended to the LSP server launch. |
| `bifrost.roots` | Workspace-relative or absolute directories to index instead of the full VS Code workspace. |
| `bifrost.exclude` | Workspace-relative or absolute files or directories to exclude from indexing and LSP lookups. |

Launch mode behavior:

- `auto`: use `bifrost.serverPath` when explicitly configured, then a bundled
  binary if present, then a local development build under `target/`, then
  `bifrost` on `PATH`.
- `bundled`: require a binary under `bin/<platform>-<arch>/bifrost`.
- `path`: use `bifrost.serverPath`, falling back to `bifrost` on `PATH`.

## Commands

- `Bifrost: Start Language Server`
- `Bifrost: Stop Language Server`
- `Bifrost: Restart Language Server`
- `Bifrost: Show Output`

The status bar item shows the current server state and can start or restart the
language server.

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

Open `editors/vscode` in VS Code, run the extension in an Extension
Development Host, and open a workspace with a supported source file. For local
development, either rely on the auto-detected `target/debug/bifrost` binary or
set:

```json
{
  "bifrost.launchMode": "path",
  "bifrost.serverPath": "/path/to/bifrost/target/debug/bifrost"
}
```

The extension starts Bifrost with:

```bash
bifrost --root <workspace-root> --server lsp
```

`--root` is the fallback root. VS Code still sends active workspace folders
during LSP initialization, including multi-root workspaces.

For large repositories, scope indexing before starting the server:

```json
{
  "bifrost.roots": ["src", "tests"],
  "bifrost.exclude": ["target", "vendor/generated"]
}
```

After changing these settings, run `Bifrost: Restart Language Server` or accept
the restart prompt. The extension sends the resolved paths as LSP
`initializationOptions`, so excluded files should disappear from workspace
symbol results and document-level LSP lookups.

## Packaging

The extension uses esbuild to bundle runtime dependencies into
`out/extension.js`.

```bash
npm run compile
npx vsce package
```

The `.vscodeignore` file excludes TypeScript sources and package manager
artifacts from the VSIX; run `npm run compile` before packaging.

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
