# Bifrost: Multi-Language LSP & MCP Server

VS Code extension for Bifrost, Brokk's tree-sitter-backed multi-language code
intelligence server. The extension starts Bifrost in LSP mode and exposes
definitions, references, symbols, hierarchy, rename, diagnostics, completion,
hover, and related editor features.

## Requirements

- VS Code 1.90+
- A supported platform for extension-managed downloads, or a `bifrost` binary
  available through one of the launch modes below

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

- `auto`: use `bifrost.serverPath` when explicitly configured, then the
  extension-managed binary if present or accepted for installation, then a
  local development build under `target/`, then
  `bifrost` on `PATH`.
- `bundled`: require the extension-managed binary for this platform and prompt
  to install it when missing.
- `path`: use `bifrost.serverPath`, falling back to `bifrost` on `PATH`.

The managed binary is pinned by the extension package metadata field
`bifrost.binaryVersion`, with expected archive hashes in
`bifrost.archiveSha256`. The extension downloads the existing GitHub Release
archives (`.tar.gz` on macOS/Linux and `.zip` on Windows), verifies each
archive against the package-pinned SHA-256 and the release `.sha256` sidecar,
extracts the `bifrost` executable into VS Code global storage at
`binaries/<version>/<platform>-<arch>/`, and removes older managed versions
after a successful install. Managed binaries are checked with
`bifrost --version` before the language server starts.

## Commands

- `Bifrost: Start Language Server`
- `Bifrost: Stop Language Server`
- `Bifrost: Restart Language Server`
- `Bifrost: Open MCP Setup`
- `Bifrost: Copy MCP Config`
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
npm test
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

The extension associates `.rql` files with **Bifrost RQL**, provides syntax
highlighting, and shows a play button in the RQL editor title. The button runs
the current editor text, including unsaved edits, through the active Bifrost
language server and displays typed structural-match, declaration, or file
results in the **Bifrost Query Results** Explorer view. Results are grouped by
file; select one to open it and, when the result has a source range, highlight
that range. It searches
every root currently indexed by that LSP session (all workspace folders by
default, or the scope configured by `bifrost.roots`). The server must already
be running and indexed; the button does not start or wait for it.

The extension starts Bifrost with:

```bash
bifrost --root <workspace-root> --lsp
```

`--root` is the fallback root. VS Code still sends active workspace folders
during LSP initialization, including multi-root workspaces.

The extension also associates `.rune` files with **Bifrost Rune IR**. Running
**Bifrost: Show Rune IR** from a supported source editor opens its preview in
that language mode, with canonical normalized kinds, roles, metadata, spans,
strings, and comments highlighted. The preview headings begin with `;`, so
saved previews remain valid Rune IR documents.

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

## MCP Setup

Run `Bifrost: Open MCP Setup` from the Command Palette to choose a setup action:
copy generic `mcp.json`, copy a Codex CLI command, copy a Claude Code command,
or open the Bifrost MCP docs. `Bifrost: Copy MCP Config` remains available when
you only want the generic JSON entry.

These commands are manual. The extension does not open MCP setup on activation,
does not mutate external host configuration, and does not prompt again after a
dismissal.

The MCP setup commands use the same binary resolution settings as the language
server where practical: a configured `bifrost.serverPath`, the
extension-managed binary, a local development build, or `bifrost` on `PATH`.

The copied entry uses the current workspace root and starts a separate Bifrost
MCP process:

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

Do not point MCP hosts at the VS Code LSP process. The extension and MCP hosts
should launch separate stdio processes from the same Bifrost binary/release.

## Packaging

The extension uses esbuild to bundle runtime dependencies into
`out/extension.js`.

```bash
npm run compile
npx vsce package
```

The `.vscodeignore` file excludes TypeScript sources and package manager
artifacts from the VSIX; run `npm run compile` before packaging.

Before publishing the VSIX, ensure:

- `package.json` has `bifrost.binaryVersion` set to the Bifrost release version
  without the leading `v`.
- `package.json` has `bifrost.archiveSha256` entries for every supported
  extension target. These hashes are the VSIX trust anchor for downloaded
  archives.
- The matching GitHub Release contains archive assets named
  `bifrost-v<version>-<target>.tar.gz` on macOS/Linux and
  `bifrost-v<version>-<target>.zip` on Windows.
- Each archive has a matching `.sha256` asset with the same filename plus
  `.sha256`.
- The release workflow has completed for macOS universal, Linux x64/arm64, and
  Windows x64/arm64 targets.

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
