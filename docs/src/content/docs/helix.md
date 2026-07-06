---
title: Helix LSP
description: Configure Helix to run Bifrost as a stdio language server.
---

Helix can run Bifrost directly through its built-in language-server configuration. No Bifrost-specific Helix plugin is required.

Put this in `~/.config/helix/languages.toml`, start Helix from the workspace root, and open a supported source file:

```toml
[language-server.bifrost]
command = "bifrost"
args = ["--root", ".", "--lsp"]

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
```

This assumes `bifrost` is installed on `PATH`:

```bash
cargo install brokk-bifrost --locked --force
```

For local development, build this checkout and use an absolute binary path:

```bash
cargo build --bin bifrost
```

Then update the Helix config:

```toml
[language-server.bifrost]
command = "/path/to/bifrost/target/debug/bifrost"
args = ["--root", ".", "--lsp"]

[[language]]
name = "java"
language-servers = ["bifrost"]
```

Add the same `language-servers = ["bifrost"]` entry for the other languages you want Bifrost to handle.

## Workspace Roots

`--root` is the fallback workspace root. Helix sends the current working directory as `rootPath`, so `args = ["--root", ".", "--lsp"]` works when you start Helix from the repository root:

```bash
cd /path/to/project
hx src/main/java/example/App.java
```

If you start Helix outside the project, pass an absolute root instead:

```toml
[language-server.bifrost]
command = "bifrost"
args = ["--root", "/path/to/project", "--lsp"]
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

For deeper Bifrost-side request timing in Helix's log, add debug environment variables to the language-server entry:

```toml
[language-server.bifrost]
command = "bifrost"
args = ["--root", ".", "--lsp"]
environment = { BIFROST_LSP_DEBUG = "1", BIFROST_LSP_SLOW_MS = "0" }
```
