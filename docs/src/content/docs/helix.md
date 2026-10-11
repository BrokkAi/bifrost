---
title: Helix LSP
description: Configure Helix to start the bifrost-lsp language server.
---

Helix can start the Bifrost language server, `bifrost-lsp`, through its built-in language-server configuration. No Bifrost-specific Helix plugin is needed.

:::caution[bifrost-lsp is not released yet]
Bifrost built after release 0.12.0 does not serve LSP: `bifrost --lsp` exits with an error. The language server is now the separate `bifrost-lsp` program, and `bifrost-lsp` has no release yet. The configuration below is ready for its first release. See [LSP Server](/lsp/) for the status and for what to use until then.
:::

Put this in `~/.config/helix/languages.toml`, start Helix from the workspace root, and open a supported source file:

```toml
[language-server.bifrost]
command = "bifrost-lsp"
args = ["--root", "."]

[[language]]
name = "c"
language-servers = ["bifrost"]

[[language]]
name = "cpp"
language-servers = ["bifrost"]

[[language]]
name = "c-sharp"
language-servers = ["bifrost"]

[[language]]
name = "go"
language-servers = ["bifrost"]

[[language]]
name = "java"
language-servers = ["bifrost"]

[[language]]
name = "javascript"
language-servers = ["bifrost"]

[[language]]
name = "jsx"
language-servers = ["bifrost"]

[[language]]
name = "typescript"
language-servers = ["bifrost"]

[[language]]
name = "tsx"
language-servers = ["bifrost"]

[[language]]
name = "php"
language-servers = ["bifrost"]

[[language]]
name = "python"
language-servers = ["bifrost"]

[[language]]
name = "ruby"
language-servers = ["bifrost"]

[[language]]
name = "rust"
language-servers = ["bifrost"]

[[language]]
name = "scala"
language-servers = ["bifrost"]

[[language]]
name = "kotlin"
language-servers = ["bifrost"]
```

This assumes `bifrost-lsp` is on `PATH`. If it is not, set `command` to the absolute path of the binary.

Bifrost handles only the languages that list `bifrost` in `language-servers`. Remove the entries for languages you do not want it to handle.

## Workspace Roots

`--root` is the fallback workspace root. Helix sends the current working directory as `rootPath`, so `args = ["--root", "."]` works when you start Helix from the repository root:

```bash
cd /path/to/project
hx src/main/java/example/App.java
```

If you start Helix outside the project, pass an absolute root instead:

```toml
[language-server.bifrost]
command = "bifrost-lsp"
args = ["--root", "/path/to/project"]
```

Helix supports multiple language servers per language. If you want Bifrost to coexist with a language-specific server, include both names in that language's list:

```toml
[[language]]
name = "java"
language-servers = ["bifrost", "jdtls"]
```

Running multiple servers can be useful when another server provides formatting or diagnostics, but it can also produce duplicate or competing navigation results. Keep the `language-servers` list to Bifrost alone if you want Bifrost to be the only server Helix uses for that language.

## Confirm Bifrost Is Running

Check that Helix can find the configured Bifrost server:

```bash
hx --health java
```

The language server section should list `bifrost` with a check mark and the command path Helix will run.

To capture startup and request logs, launch Helix with an explicit log file:

```bash
hx -vvv --log /tmp/helix-bifrost.log src/main/java/example/App.java
```

Open a supported file and use Helix's normal LSP navigation commands, such as `gd` for go to definition or `gr` for references. The log should show `initialize`, `textDocument/definition`, or `textDocument/references` messages for `bifrost`.

For request timing from the server, set the two variables that the VS Code extension passes to `bifrost-lsp`. `BIFROST_LSP_DEBUG = "1"` logs every request and notification. `BIFROST_LSP_SLOW_MS` logs requests that take at least that many milliseconds; `0` logs all of them. The `bifrost` CLI does not read these variables. See [LSP Server](/lsp/).

```toml
[language-server.bifrost]
command = "bifrost-lsp"
args = ["--root", "."]
environment = { BIFROST_LSP_DEBUG = "1", BIFROST_LSP_SLOW_MS = "0" }
```
