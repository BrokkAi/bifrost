# Bifrost Agent Plugin Publication

This is the Bifrost-owned publication path for making the MCP server
discoverable as an Agent Plugin. The shared package lives in
`plugins/bifrost-agent`. Codex uses `.agents/plugins/marketplace.json` for the
repo-local marketplace, while Claude Code uses `.claude-plugin/marketplace.json`.
Both marketplace manifests use the public namespace `bifrost`, while the
plugin's stable install name remains `brokk`.

## Plugin shape

The Codex plugin manifest lives at
`plugins/bifrost-agent/.codex-plugin/plugin.json`. The Claude Code manifest
lives at `plugins/bifrost-agent/.claude-plugin/plugin.json`. Keep both manifest
versions aligned with `Cargo.toml` and keep the stable plugin `name` as
`brokk`. Use `Bifrost by Brokk` for Codex-facing display text.

The companion MCP configuration lives at `plugins/bifrost-agent/.mcp.json`:

```json
{
  "mcpServers": {
    "bifrost": {
      "command": "./bin/bifrost-launcher.mjs",
      "args": ["--mcp", "symbol|extended"],
      "startup_timeout_sec": 60,
      "tool_timeout_sec": 300
    }
  }
}
```

Use the same Bifrost release as the Rust crate and release tag. The plugin does
not bundle release archives; `plugins/bifrost-agent/bifrost-release.json`
stores the pinned version and per-target archive hashes. The launcher uses
`BIFROST_BINARY_PATH`, an existing managed cache entry, or a checksum-verified
GitHub release download. A compatible `bifrost` on `PATH` is used only when
`BIFROST_LAUNCHER_ALLOW_PATH=1` is set explicitly. Set
`BIFROST_LAUNCHER_AUTO_INSTALL=0` to disable downloads.

The launcher resolves the workspace root from `BIFROST_WORKSPACE_ROOT`, then a
host-provided `--root` or `--workspace-root`, then the host session working
directory. It always starts Bifrost with explicit `--root <resolved-root>`. The
default plugin toolset is `symbol|extended`, not `searchtools`, so the local
plugin exposes analyzer navigation and related discovery tools without the
`activate_workspace` or raw text-file tools.

The plugin manifests also point at `plugins/bifrost-agent/skills`. Keep these
skills limited to guidance for the default Bifrost MCP toolset unless the
toolset changes in the same release.

## Local testing

Build the local binary:

```bash
cargo build --bin bifrost
```

Verify the binary before installing the plugin:

```bash
./target/debug/bifrost --root . --tool get_summaries --args '{"targets":["README.md"]}'
```

Add the repo-local marketplace, install the plugin, and start a fresh host
session using the canonical local testing steps in
`plugins/bifrost-agent/README.md`. For checkout builds, set
`BIFROST_BINARY_PATH="$(pwd)/target/debug/bifrost"` before starting the host.
Then call a lightweight analyzer tool such as `get_summaries` or
`search_symbols` from the fresh session.

Public GitHub installs use the same `brokk@bifrost` name in both hosts:

```bash
codex plugin marketplace add BrokkAi/bifrost --sparse .agents/plugins --sparse plugins
codex plugin add brokk@bifrost
claude plugin marketplace add BrokkAi/bifrost --sparse .claude-plugin plugins
claude plugin install brokk@bifrost
```

Validate that the plugin manifest versions match `Cargo.toml` and that all
plugin JSON files, skill files, and launcher metadata parse:

```bash
node --test plugins/bifrost-agent/test/*.test.mjs
node scripts/check-codex-plugin-manifest.mjs
claude plugin validate plugins/bifrost-agent
claude plugin validate .
```

## Publishing checklist

- Build and publish the Bifrost release archives for every supported platform.
- Update the VS Code extension's `bifrost.binaryVersion` and
  `bifrost.archiveSha256` entries to the same release, and update
  `plugins/bifrost-agent/bifrost-release.json` from the same release sidecars.
- Confirm the release workflow uploads `bifrost-agent-<tag>.tar.gz` after
  preparing `plugins/bifrost-agent/bifrost-release.json`.
- Package the Codex Agent Plugin from `plugins/bifrost-agent` with
  `.codex-plugin/plugin.json`, `.mcp.json`, `bifrost-release.json`, `bin/`,
  `skills/`, and `assets/icon.png`.
- Package the Claude Code Agent Plugin from `plugins/bifrost-agent` with
  `.claude-plugin/plugin.json`, `.mcp.json`, `bifrost-release.json`, `bin/`,
  `skills/`, and `assets/icon.png`.
- Validate that the plugin's MCP server entry launches:
  `bifrost --root <resolved-root> --mcp "symbol|extended"`.
- Confirm that plugin installation and VS Code LSP setup use separate Bifrost
  stdio processes, even when they point at the same binary/release.

## Skill ownership

The Bifrost plugin owns code-intelligence skills that describe the MCP tools it
installs: code navigation, code reading, and codebase search. These skills must
refer only to tools available through `symbol|extended` or to host-provided
shell/file-reading tools.

The Brokk `workspace` skill is intentionally excluded because the default
Bifrost plugin does not expose `activate_workspace`, `get_active_workspace`, or
`refresh`. Higher-level Brokk workflows such as guided issue resolution, guided
review, PR review, GitHub issue drafting, today planning, and specialist
reviewer agents remain Brokk-owned unless a separate tracker issue moves them
into the Bifrost package.
