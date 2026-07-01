# Agent Plugin Launcher

Issue #391 adds a package-local launcher for the Bifrost agent plugin so Codex
and Claude Code can start the MCP server without requiring a manually edited
`/path/to/bifrost` or an existing `PATH` install.

## Progress

- [x] (2026-07-01) Confirmed the branch
  `391-add-a-plugin-launcher-for-bifrost-binary-resolution-and-workspace-root-selection`
  is clean and up to date after `git fetch && git rebase`.
- [x] Add a plugin-local Node launcher that resolves a workspace root, resolves
  or installs the pinned Bifrost release, and execs Bifrost with explicit
  `--root`.
- [x] Point the shared agent plugin `.mcp.json` at the launcher while keeping
  the default `symbol|extended` toolset.
- [x] Add plugin release metadata and keep it aligned with release-sidecar
  preparation and manifest validation scripts.
- [x] Update user and publication docs so marketplace installs no longer
  require editing a binary path.
- [x] Ran the plugin, Node, VS Code, Rust, and focused launcher validation.
  Evidence: `node --test plugins/bifrost-agent/test/*.test.mjs`, `node
  scripts/check-codex-plugin-manifest.mjs`, `claude plugin validate
  plugins/bifrost-agent`, `cd editors/vscode && npm test`, `cargo fmt
  --check`, `cargo clippy-no-cuda`, a temporary release-prep metadata smoke,
  and a stub-binary launcher smoke all passed.

## Design

The launcher lives under `plugins/bifrost-agent/bin/` and is invoked by the
shared `.mcp.json` used by both Codex and Claude Code. It writes all launcher
diagnostics to stderr and transfers stdio to the final Bifrost process so the
stdio MCP protocol remains clean.

Workspace root precedence is `BIFROST_WORKSPACE_ROOT`, then a launcher
`--root` or `--workspace-root` argument supplied by a host, then `process.cwd()`.
The selected root must be an existing directory. The launcher always starts
Bifrost as:

```bash
bifrost --root <resolved-root> --mcp <toolset>
```

Binary resolution order is:

1. `BIFROST_BINARY_PATH`, validated as an executable and version-compatible.
2. A compatible managed binary in the plugin cache.
3. A compatible `bifrost` on `PATH`.
4. A checksum-verified download of the pinned GitHub release into the plugin
   cache, unless `BIFROST_LAUNCHER_AUTO_INSTALL=0`.

Plugin release metadata stores `binaryVersion` and per-target SHA-256 hashes.
The release-prep script updates that metadata from the same release sidecars as
the VS Code extension so both distribution paths use the same trust anchor.

## Validation

Run these after implementation:

```bash
node --test plugins/bifrost-agent/test/*.test.mjs
node scripts/check-codex-plugin-manifest.mjs
claude plugin validate plugins/bifrost-agent
cd editors/vscode && npm test
cargo fmt --check
cargo clippy-no-cuda
```

Also run a focused launcher smoke with a stub or built Bifrost binary to verify
that the spawned arguments include `--root <resolved-root> --mcp
symbol|extended` and that stdout/stderr are not pre-used for launcher chatter.
