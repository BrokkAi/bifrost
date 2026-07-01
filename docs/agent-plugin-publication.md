# Bifrost Agent Plugin Publication

This is the Bifrost-owned publication path for making the MCP server
discoverable as an Agent Plugin. The concrete Codex plugin package lives in
`plugins/bifrost-agent`, and the repo-local marketplace entry for testing lives
in `.agents/plugins/marketplace.json`.

## Plugin shape

The plugin manifest lives at
`plugins/bifrost-agent/.codex-plugin/plugin.json`. Treat that checked-in file
as the source of truth for marketplace metadata, including the plugin version,
icon paths, display text, and MCP configuration pointer. Keep the stable plugin
`name` as `bifrost`; use `Bifrost for Codex` for Codex-facing display text so
this package root can also host other agent manifests later.

The companion MCP configuration lives at `plugins/bifrost-agent/.mcp.json`:

```json
{
  "mcpServers": {
    "bifrost": {
      "command": "bifrost",
      "args": ["--mcp", "symbol|extended"],
      "startup_timeout_sec": 60,
      "tool_timeout_sec": 300
    }
  }
}
```

Use the same Bifrost release as the Rust crate and release tag. The plugin does
not bundle release archives; it expects `bifrost` to be available on `PATH`.
When testing a checkout build, prepend this repository's `target/debug`
directory to `PATH` before starting Codex. The plugin omits `--root` so Bifrost
uses the Codex session working directory as the analyzed workspace root.
The default plugin toolset is `symbol|extended`, not `searchtools`, so the
local plugin exposes analyzer navigation and related discovery tools without
the `activate_workspace` or raw text-file tools.

## Local testing

Build the local binary:

```bash
cargo build --bin bifrost
```

Verify the binary before installing the plugin:

```bash
./target/debug/bifrost --root . --tool get_summaries --args '{"targets":["README.md"]}'
```

Add the repo-local marketplace, install the plugin, and start a fresh Codex
session using the canonical local testing steps in
`plugins/bifrost-agent/README.md`. Then call a lightweight analyzer tool such
as `get_summaries` or `search_symbols` from the fresh session.

Validate that the plugin manifest version matches `Cargo.toml` and that all
plugin JSON files parse:

```bash
node scripts/check-codex-plugin-manifest.mjs
```

## Publishing checklist

- Build and publish the Bifrost release archives for every supported platform.
- Update the VS Code extension's `bifrost.binaryVersion` and
  `bifrost.archiveSha256` entries to the same release.
- Package the Agent Plugin from `plugins/bifrost-agent` with
  `.codex-plugin/plugin.json`, `.mcp.json`, and `assets/icon.png`.
- Validate that the plugin's MCP server entry launches:
  `bifrost --mcp "symbol|extended"`.
- Confirm that plugin installation and VS Code LSP setup use separate Bifrost
  stdio processes, even when they point at the same binary/release.

## Current skill bundle

The Brokk host skills are still packaged from the Brokk plugin source rather
than this repository. Until that bundle moves here, publish the Bifrost Agent
Plugin as an MCP-server package only, and keep skill migration as a separate
tracked change.
