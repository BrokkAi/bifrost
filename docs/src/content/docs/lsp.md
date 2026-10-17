---
title: LSP Server
description: The Bifrost language server is the separate bifrost-lsp program. This page explains its status, launch command, and versioning.
---

The `bifrost` command no longer serves the Language Server Protocol (LSP). The
language server is a separate program named `bifrost-lsp`. It comes from the
[BrokkAi/bifrost-lsp](https://github.com/BrokkAi/bifrost-lsp) repository.

:::caution[bifrost-lsp is not released yet]
The BrokkAi/bifrost-lsp repository has no published release. You cannot
download a `bifrost-lsp` binary yet. The editor pages show the configuration
that starts `bifrost-lsp`, so that it is ready when the first release ships.
:::

## Which Bifrost Versions Serve LSP

| Bifrost build | `bifrost --lsp` |
| --- | --- |
| Released 0.12.0 and earlier | Serves LSP over stdio. |
| Built from later source, including development builds that still report version 0.12.0 | Prints `the LSP server has moved out of this repository` and exits with status 1. |

`bifrost --server lsp` behaves the same way as `bifrost --lsp`. Until a
`bifrost-lsp` release exists, you have two working options:

- In VS Code or Cursor, install the published extension. It downloads its own
  Bifrost 0.11.5 binary. See [VS Code LSP](/vscode/).
- In another editor, start a released Bifrost 0.12.0 or earlier binary with
  `bifrost --root <workspace-root> --lsp`.

The Claude Code agent plugin registers an LSP server that runs `bifrost
--lsp`. It works only with the plugin's pinned release, Bifrost 0.12.0. See
[Claude Code](/claude-code/).

## Launch Command

Editors start the server as a child process and talk to it over stdin and
stdout:

```bash
bifrost-lsp --root <workspace-root>
```

`--root` names the fallback workspace root. The VS Code extension passes the
first workspace folder. It also appends the strings from its
`bifrost.extraArgs` setting after `--root`. The extension runs
`bifrost-lsp --version` to check a downloaded binary before it starts the
server.

These are the only command-line arguments that the published sources show.
The server's full option list is not published yet.

### Environment Variables

The VS Code extension sets these variables when it starts `bifrost-lsp`. The
`bifrost` CLI does not read them.

| Variable | Value the extension sets | Meaning |
| --- | --- | --- |
| `BIFROST_LSP_DEBUG` | `1` when `bifrost.debug` is on; otherwise the inherited value, or `0` | Log the start and end of every LSP request and notification. |
| `BIFROST_LSP_SLOW_MS` | The `bifrost.slowRequestMs` setting; default `2000` | Log requests and notifications that take at least this many milliseconds. |
| `RUST_BACKTRACE` | The inherited value, or `1` | Print a backtrace if the server panics. |

The VS Code extension copies the server's stderr to **Output > Bifrost**. In
other editors, look for stderr in the editor's language-server log.

### Initialization Options

The VS Code extension sends this object as the LSP `initializationOptions`. It
sends the same object when the server requests the `bifrost` section through
`workspace/configuration`.

| Field | Type | Meaning |
| --- | --- | --- |
| `roots` | array of absolute paths | Directories to index instead of the whole workspace. An empty array means the whole workspace. |
| `exclude` | array of absolute paths | Files or directories to leave out of indexing and lookups. |
| `formatterCommands` | array of formatter rules | External formatters to run for document formatting. See [VS Code LSP](/vscode/) for the rule fields. |
| `unrecognizedSymbolDiagnostics` | boolean | Report symbols and members that Bifrost cannot resolve. Experimental. Default `false`. |

The extension turns relative paths in its settings into absolute paths before
it sends them. When you configure another editor, send absolute paths too.

## Versions and the Compatibility Check

Three version numbers are independent of each other:

| Version | Where it comes from | Current value in the bifrost-lsp source |
| --- | --- | --- |
| Extension version | The VS Code extension's `version` | `0.12.0` (not published) |
| Server version | The `bifrost-lsp` release tag, `v<server>` | Preferred `0.1.0`, minimum `0.1.0` |
| Engine version | The Bifrost analysis engine built into `bifrost-lsp` | The extension accepts `>=0.11.0 <1.0.0` |

When the server starts, it must identify itself in its `initialize` result:

```json
{
  "capabilities": {
    "experimental": {
      "bifrost": {
        "protocolVersion": 1,
        "engineVersion": "0.12.0"
      }
    }
  }
}
```

`protocolVersion` must be `1`. `engineVersion` must be a three-part version
inside the extension's engine range. If either value is missing, malformed, or
out of range, the extension stops the server and shows the error in its status
bar item and output channel. Other editors do not run this check.

### Release Files

Each `bifrost-lsp` release on GitHub will contain one archive and one SHA-256
file for each platform:

| Platform | Archive |
| --- | --- |
| macOS (Intel and Apple silicon) | `bifrost-lsp-v<server>-universal-apple-darwin.tar.gz` |
| Linux x64 | `bifrost-lsp-v<server>-x86_64-unknown-linux-gnu.tar.gz` |
| Linux arm64 | `bifrost-lsp-v<server>-aarch64-unknown-linux-gnu.tar.gz` |
| Windows x64 | `bifrost-lsp-v<server>-x86_64-pc-windows-msvc.zip` |
| Windows arm64 | `bifrost-lsp-v<server>-aarch64-pc-windows-msvc.zip` |

The checksum file has the archive name plus `.sha256`. The archive contains a
top-level directory with the archive's base name and the `bifrost-lsp`
executable (`bifrost-lsp.exe` on Windows) inside it.

## Editor Setup

- [VS Code LSP](/vscode/)
- [Cursor](/cursor/)
- [Neovim and Vim LSP](/neovim/)
- [Helix LSP](/helix/)
- [Zed LSP](/zed-lsp/)
- [OpenCode](/opencode/)
- [RQL in VS Code](/rql-vscode/)

## Use MCP for Agents

Agents do not need the language server. Bifrost's code intelligence for agents
runs over the Model Context Protocol (MCP) from the `bifrost` command:

```bash
bifrost --root /path/to/project --mcp searchtools
```

See [Claude Code](/claude-code/) and [OpenCode](/opencode/) for host setup,
and [Capabilities](/capabilities/) for what the tools answer. For terminal
checks and scripts, use [one-shot CLI tool mode](/cli/).
