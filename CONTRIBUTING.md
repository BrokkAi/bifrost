# Contributing

## Development Setup

Rust build:

```bash
cargo build --lib --bin bifrost
```

Python client build/install:

```bash
maturin develop
```

This repository has a maturin-backed `pyproject.toml` so `uv run python ...` can execute the `bifrost_searchtools` client through the PyO3 native Rust extension.

## Test

Rust:

```bash
cargo test
cargo fmt --check
cargo clippy-no-cuda
```

`cargo clippy-no-cuda` checks all targets with the optional `nlp` and `python`
features enabled, but leaves `nlp-gpu` off. Use
`cargo clippy --all-targets --all-features -- -D warnings` only on machines with
NVIDIA CUDA tooling available; `--all-features` enables Candle's CUDA backend,
whose build script expects `nvcc`.

Python:

```bash
scripts/test_python.sh
```

That wrapper provisions a uv-managed Python 3.12 environment, makes `maturin` available, installs the editable native extension, and then runs the unittest suite.

## Python Development

For repo-local development without installing the package, `SearchToolsClient(..., library_path=...)` can load a built debug library such as `target/debug/libbrokk_bifrost.so`.

## Release Process

The Rust crate, the `bifrost` binary, the Python wheel, and the agent/editor
plugin release metadata are versioned **together** and cut from a **single tag**.
`Cargo.toml` is the committed source of truth for the release version:
`pyproject.toml` inherits it via maturin's `dynamic = ["version"]`, and
`scripts/sync-release-version.mjs` copies it into the plugin and editor metadata
that require literal JSON versions.

The agent and editor plugin manifests also carry release metadata and must be
checked during release prep. Before tagging a release, edit only `Cargo.toml`,
then run:

```bash
node scripts/sync-release-version.mjs
```

That script updates these committed version fields:

- `plugins/bifrost-agent/.codex-plugin/plugin.json`
- `plugins/bifrost-agent/.claude-plugin/plugin.json`
- `plugins/bifrost-agent/.cursor-plugin/plugin.json`
- `.cursor-plugin/marketplace.json`
- `editors/vscode/package.json`
- `editors/vscode/package-lock.json`
- `plugins/bifrost-agent/bifrost-release.json`
- `plugins/bifrost-agent/amp-skills/bifrost-code-intelligence/bifrost-release.json`

The Codex and Claude marketplace files are also part of the plugin surface, but
currently do not carry version fields:

- `.agents/plugins/marketplace.json`
- `.claude-plugin/marketplace.json`

The VS Code extension and bundled agent plugin also pin the Bifrost release
archive checksums:

- `editors/vscode/package.json`
- `plugins/bifrost-agent/bifrost-release.json`
- `plugins/bifrost-agent/amp-skills/bifrost-code-intelligence/bifrost-release.json`

Those checksum-bearing files must match the actual release archives.
`scripts/sync-release-version.mjs` only copies the current
`plugins/bifrost-agent/bifrost-release.json` checksums into the VS Code manifest
when that release metadata is already on the same version as `Cargo.toml`. The
`release.yml` workflow prepares checksum metadata from the built `.sha256`
sidecars with `scripts/prepare-vscode-extension-manifest.mjs`, regenerates the
Amp skill bundle, validates the plugin manifests, packages
`bifrost-agent-<tag>.tar.gz`, and publishes the VSIX. If you perform those
packaging steps manually, run the same script against the release `dist/`
directory instead of hand-editing checksums.

To cut a release:

1. Bump `version` in `Cargo.toml`, run `node scripts/sync-release-version.mjs`,
   review the generated metadata diff, and merge.
2. If skills, agents, launcher files, MCP config, or plugin manifests changed,
   regenerate and validate the generated plugin bundles:

   ```bash
   node scripts/sync-release-version.mjs --check
   node scripts/generate-codex-skill-bundle.mjs
   node scripts/generate-amp-skill-bundle.mjs
   node scripts/check-codex-plugin-manifest.mjs
   node --test plugins/bifrost-agent/test/*.test.mjs
   ```

   `check-codex-plugin-manifest.mjs` checks the Codex, Claude, and Cursor plugin
   manifests, the Cursor marketplace versions, the generated Codex and Amp
   bundles, and parseability of the Codex and Claude marketplace files. It also
   checks `plugins/bifrost-agent/bifrost-release.json`, so run it after that
   release metadata has been prepared for the version being validated.
3. Tag the commit and push:

   ```bash
   git tag -a v0.6.4 -m "Release v0.6.4"
   git push origin refs/tags/v0.6.4
   ```

A single `vX.Y.Z` tag fans out to three workflows:

- `release.yml` — builds platform archives + SHA-256 checksums and publishes a
  GitHub Release, then prepares and publishes the VS Code extension and bundled
  agent plugin artifacts.
- `publish-crate.yml` — publishes the crate to crates.io.
- `publish-wheels.yml` — builds all platform wheels + sdist and publishes to PyPI.

Each publish workflow refuses to run if the tag does not match `Cargo.toml`, and
`publish-wheels.yml` additionally fails if `pyproject.toml` ever re-introduces a
hardcoded `version` (which would break the single-source invariant) or if a built
artifact does not carry the tagged version.

All three can also be triggered manually from the GitHub Actions UI with a `tag`
input.

## Version Policy

- The crate version in `Cargo.toml` is the single source of truth for the Rust
  crate, Python package, and release-aligned plugin/editor metadata. Never add a
  `version` to `pyproject.toml`; run `node scripts/sync-release-version.mjs` to
  update JSON metadata from `Cargo.toml`.
- The Tree-sitter grammar crate versions are intentionally not forced to share
  the same numeric version. The policy is documented in `Cargo.toml`.
