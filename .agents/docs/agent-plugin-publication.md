# Bifrost Agent Plugin Publication

This is the Bifrost-owned publication path for making the MCP server
discoverable as an Agent Plugin. The shared package lives in
`plugins/bifrost-agent`. Codex uses `.agents/plugins/marketplace.json` for the
repo-local marketplace, Claude Code uses `.claude-plugin/marketplace.json`, and
Cursor uses `.cursor-plugin/marketplace.json`. All marketplace manifests use the
public namespace `bifrost`, while the plugin's stable install name remains
`brokk`.

## Plugin shape

The Codex plugin manifest lives at
`plugins/bifrost-agent/.codex-plugin/plugin.json`. The Claude Code manifest
lives at `plugins/bifrost-agent/.claude-plugin/plugin.json`. The Cursor plugin
manifest lives at `plugins/bifrost-agent/.cursor-plugin/plugin.json`. Keep all
manifest versions aligned with `Cargo.toml` and keep the stable plugin `name` as
`brokk` for Claude/Codex. Cursor uses the Cursor-facing plugin name `bifrost`.
Use `Bifrost by Brokk` for UI-facing display text.

The Claude/Codex MCP configuration lives at `plugins/bifrost-agent/.mcp.json`.
Cursor uses the same server shape in `plugins/bifrost-agent/mcp.json`, with
Cursor's documented `type: "stdio"` field, because Cursor's plugin loader
detects root `mcp.json` directly. Amp does not use either of those wrapper
shapes: Amp `mcp.json` / `--mcp-config` expects a direct server-name map. The
Amp package is generated under `plugins/bifrost-agent/amp-skills` from the
canonical Bifrost code-intelligence skills.

```json
{
  "mcpServers": {
    "bifrost": {
      "command": "./bin/bifrost-launcher.mjs",
      "args": ["--mcp", "symbol|extended"],
      "startup_timeout_sec": 180,
      "tool_timeout_sec": 300
    }
  }
}
```

The Amp-equivalent direct server-map shape is:

```json
{
  "bifrost": {
    "command": "sh",
    "args": ["-lc", "<launcher-search-shim>", "bifrost-agent-launcher", "--root", ".", "--mcp", "symbol|extended"],
    "includeTools": ["search_symbols", "get_summaries", "scan_usages"]
  }
}
```

The generated Amp `mcp.json` uses the shell shim because the tested Amp CLI
resolved package-relative MCP commands from the Amp process working directory,
not from the skill directory. The shim finds the installed
`bifrost-code-intelligence` skill under workspace/global Amp skill locations or
`BIFROST_AGENT_SKILL_DIR`, then execs its bundled launcher. For released
binaries, omit `BIFROST_BINARY_PATH` and let the launcher resolve or download
the pinned Bifrost release. For local checkout testing, keep
`BIFROST_BINARY_PATH` so Amp cannot pick a stale binary from `PATH`.

Use the same Bifrost release as the Rust crate and release tag. The plugin does
not bundle release archives; `plugins/bifrost-agent/bifrost-release.json`
stores the pinned version and per-target archive hashes. The launcher uses
`BIFROST_BINARY_PATH`, an existing managed cache entry, or a checksum-verified
GitHub release download. A compatible `bifrost` on `PATH` is used only when
`BIFROST_LAUNCHER_ALLOW_PATH=1` is set explicitly. Set
`BIFROST_LAUNCHER_AUTO_INSTALL=0` to disable downloads.

The 180-second startup budget covers the launcher's bounded 60-second download,
60-second extraction, and 10-second version probe, plus startup margin. Keep the
Claude/Codex and Cursor values identical and above the minimum exported by the
canonical launcher. The package-local `doctor [--json]` command does not
modify the cache or download assets, but it does execute the selected binary's
`--version` probe and therefore assumes trusted candidate locations.
`prepare [--json]` resolves or installs the exact pinned release without
starting MCP. Run `prepare` before host startup when a host does not support a
configurable MCP startup timeout, then start a fresh task.

The launcher resolves the workspace root from `BIFROST_WORKSPACE_ROOT`, then a
host-provided `--root` or `--workspace-root`, then the host session working
directory. It always starts Bifrost with explicit `--root <resolved-root>`. The
default plugin toolset is `symbol|extended`, not `searchtools`, so the local
plugin exposes analyzer navigation and related discovery tools without the
`activate_workspace` or raw text-file tools.

The plugin manifests also point at `plugins/bifrost-agent/skills` and declare
the specialist agents under `plugins/bifrost-agent/agents`. Keep the
code-intelligence skills aligned with the default Bifrost MCP toolset, and keep
the workflow skills and agents in the same plugin so `brokk@bifrost` remains a
single installable bundle for code intelligence plus GitHub/review workflows.

## Local testing

Build the local binary:

```bash
cargo build --bin bifrost
```

Verify the binary before installing the plugin:

```bash
./target/debug/bifrost --root . --tool get_summaries --args '{"targets":["src/analyzer/usages"]}'
```

Add the repo-local marketplace, install the plugin, and start a fresh host
session using the canonical local testing steps in
`plugins/bifrost-agent/README.md`. For checkout builds, set
`BIFROST_BINARY_PATH="$(pwd)/target/debug/bifrost"` before starting the host.
Then call a lightweight analyzer tool such as `get_summaries` or
`search_symbols` from the fresh session. Prefer source directories or source
files such as `src/analyzer/usages` over README-style docs so the smoke proves
the analyzer-backed MCP path rather than ordinary file reading.

Public GitHub installs use the same `brokk@bifrost` name in both hosts:

```bash
codex plugin marketplace add BrokkAi/bifrost --sparse .agents/plugins --sparse plugins
codex plugin add brokk@bifrost
claude plugin marketplace add BrokkAi/bifrost --sparse .claude-plugin plugins
claude plugin install brokk@bifrost
```

Cursor installs the same shared package through its native plugin system. For
local testing, open Cursor with the local binary selected:

```bash
BIFROST_BINARY_PATH="$(pwd)/target/debug/bifrost" cursor .
```

Then use **Customize -> Manage -> Add Marketplace -> Import from Disk** and
select the repository root. Cursor should read `.cursor-plugin/marketplace.json`
and find the `bifrost` plugin at `plugins/bifrost-agent`. If testing only the
plugin package, select `plugins/bifrost-agent` directly.

For public submission, submit the repository at
`https://cursor.com/marketplace/publish`. The repo root includes
`.cursor-plugin/marketplace.json`, which points Cursor at
`plugins/bifrost-agent`.

For Cursor MCP validation, use the desktop Customize/MCP flow. Installed Cursor
plugin MCP servers do not appear in agent sessions until the user enables them
from Customize, and already-open chats may need to be restarted. The
`cursor agent --plugin-dir` CLI path can load plugin skills, but it has not
proven reliable for plugin-provided MCP servers.

For Amp validation, install the generated skill collection documented in
`plugins/bifrost-agent/README.md`. The smoke path is:

```bash
cargo build --bin bifrost
node scripts/generate-amp-skill-bundle.mjs
amp skill add "$(pwd)/plugins/bifrost-agent/amp-skills" --target "$(pwd)/.agents/skills" --overwrite
BIFROST_BINARY_PATH="$(pwd)/target/debug/bifrost" amp -x \
  'Load the bifrost-code-intelligence skill. Use the Bifrost MCP get_summaries tool on src/analyzer/usages/rust_graph/*.rs and name three symbols from the MCP result.'
```

After merge, verify the default-branch GitHub install path with Amp's
`owner/repo/path` source syntax:

```bash
amp skill add BrokkAi/bifrost/plugins/bifrost-agent/amp-skills --target /tmp/bifrost-amp-skills --overwrite
```

Do not use a browser `https://github.com/.../tree/...` URL for Amp skill
sources. The tested Amp CLI did not accept branch-qualified GitHub skill
sources, so PR-branch validation should use a local checkout path and
default-branch validation should happen after merge.

When testing skill-bundled MCP config in Amp, install the parent skill
collection, not an individual skill directory. Installing a single skill
directory can copy only `SKILL.md`, while parent collection installs preserve
support files such as `mcp.json`, `bin/`, and `bifrost-release.json`. Also
verify launcher paths in a real Amp prompt smoke because package-relative MCP
commands are not skill-relative in the tested CLI.

Validate that the plugin manifest versions match `Cargo.toml` and that all
plugin JSON files, skill files, and launcher metadata parse:

```bash
node --test plugins/bifrost-agent/test/*.test.mjs
node scripts/generate-amp-skill-bundle.mjs
node scripts/check-codex-plugin-manifest.mjs
claude plugin validate plugins/bifrost-agent
claude plugin validate .
```

## Publishing checklist

- Build and publish the Bifrost release archives for every supported platform.
- Update the VS Code extension's `bifrost.binaryVersion` and
  `bifrost.archiveSha256` entries to the same release, and update
  `plugins/bifrost-agent/bifrost-release.json` from the same release sidecars.
- The release workflow then checks out `master`, verifies that its Cargo
  version still matches the released tag, and persists the canonical plugin
  metadata plus its generated Amp copy. A version mismatch intentionally fails
  the release check before any metadata is committed; update or reconcile
  `master` rather than publishing release metadata onto a different version.
- The macOS release smoke downloads the published agent-plugin archive, starts
  from an empty launcher cache, runs `prepare --json`, and requires the
  packaged MCP server to advertise `search_symbols` through `tools/list`.
- Confirm the release workflow uploads `bifrost-agent-<tag>.tar.gz` after
  preparing `plugins/bifrost-agent/bifrost-release.json`.
- Package the Codex Agent Plugin from `plugins/bifrost-agent` with
  `.codex-plugin/plugin.json`, `.mcp.json`, `bifrost-release.json`, `bin/`,
  `skills/`, `agents/`, and `assets/icon.png`.
- Package the Claude Code Agent Plugin from `plugins/bifrost-agent` with
  `.claude-plugin/plugin.json`, `.mcp.json`, `bifrost-release.json`, `bin/`,
  `skills/`, `agents/`, and `assets/icon.png`.
- Package the Cursor Plugin from `plugins/bifrost-agent` with
  `.cursor-plugin/plugin.json`, `mcp.json`, `bifrost-release.json`, `bin/`,
  `skills/`, `agents/`, and `assets/icon.png`; submit through Cursor's manual
  marketplace review after local validation.
- Generate and package the Amp skill collection from
  `plugins/bifrost-agent/amp-skills` after running
  `node scripts/generate-amp-skill-bundle.mjs`. Use Amp's direct server-map
  config, not the Claude/Codex `.mcp.json` wrapper or Cursor root `mcp.json`.
- Validate that the plugin's MCP server entry launches:
  `bifrost --root <resolved-root> --mcp "symbol|extended"`.
- Validate a cold package cache with `doctor`, `prepare`, a second successful
  `doctor`, and a fresh MCP `tools/list` request before publishing.
- Confirm that plugin installation and VS Code LSP setup use separate Bifrost
  stdio processes, even when they point at the same binary/release.

## Skill ownership

The Bifrost plugin owns code-intelligence skills that describe the MCP tools it
installs: code navigation, code reading, and codebase search. These skills must
refer only to tools available through `symbol|extended` or to host-provided
shell/file-reading tools.

The Amp skill bundle is generated from those three canonical source skills.
Treat `plugins/bifrost-agent/skills/bifrost-code-navigation`,
`plugins/bifrost-agent/skills/bifrost-code-reading`, and
`plugins/bifrost-agent/skills/bifrost-codebase-search` as the source of truth;
do not edit `plugins/bifrost-agent/amp-skills` by hand.

The same plugin also owns the Brokk/Bifrost workflow skills for git
exploration, guided issue resolution, guided review, PR review, ordinary code
review, work-queue triage, and issue drafting. Keep their specialist agents in
`plugins/bifrost-agent/agents` and list them in both host manifests.

The Brokk `workspace` skill remains excluded because the default Bifrost plugin
does not expose `activate_workspace`, `get_active_workspace`, or `refresh`.
Workflow skills should treat explicit workspace activation as optional host
capability and continue with the plugin's current workspace root when those
tools are unavailable.
