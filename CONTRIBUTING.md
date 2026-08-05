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

Run the core Rust checks before submitting a change:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
uv run --python 3.12 -- cargo test --features nlp,python
```

Bifrost's default feature set is empty. Include the `nlp` and `python` features
when running the full test suite; a featureless `cargo test` skips the
feature-gated integration suites. `--all-features` enables those same two
features. Embedding acceleration is selected by the Python sidecar at runtime,
so these checks do not require CUDA or Metal build tooling. Run Rust tests that
enable the `python` feature through uv so PyO3 uses the project's Python 3.12
environment rather than whichever system interpreter happens to be on `PATH`.

Python:

```bash
scripts/test_python.sh
```

That wrapper provisions a uv-managed Python 3.12 environment, makes `maturin` available, installs the editable native extension, and then runs the unittest suite.

For host-local changes, run the independently owned package contract first:

```bash
cargo test -p brokk-bifrost-mcp --features nlp
cargo test -p brokk-bifrost-lsp --all-features
```

Changes in `brokk-bifrost-core`, `brokk-bifrost-analysis`,
`brokk-bifrost-policy`, or `brokk-bifrost-runtime` affect both hosts and should
use the full workspace gate. MCP and LSP are versioned
implementation dependencies of the stable `brokk-bifrost` facade, not
separate public API commitments.

## Python Development

For repo-local development without installing the package, `SearchToolsClient(..., library_path=...)` can load a built debug library such as `target/debug/libbrokk_bifrost.so`.

## Citation Authorship Policy

`CITATION.cff` uses **Bifrost contributors** as the collective software author
and lists Brokk, Inc. as the project contact. Citation authorship records
creative and scholarly credit; it is separate from copyright ownership.

Keep the collective author unless the project adopts an explicit named-author
policy. Do not derive citation authorship from commit counts: they omit design,
review, testing, documentation, and work ported between repositories. Any future
named-author list should use documented contribution criteria, contributors'
preferred names and ORCIDs, and a release-by-release review.

Bifrost is a Rust port and continuation of analyzer work developed in Brokk's
Java codebase. Preserve the Brokk software reference in `CITATION.cff` so that
lineage remains machine-readable and contributors whose work predates the Rust
repository are not silently excluded. The public rationale and suggested
citation live in [`docs/src/content/docs/cite-bifrost.md`](docs/src/content/docs/cite-bifrost.md).

## Release Process

The Rust crate, the `bifrost` binary, the Python wheel, and the agent/editor
plugin release metadata are versioned **together** and cut from a **single tag**.
`Cargo.toml`'s `[workspace.package]` version is the committed source of truth for the release version:
`pyproject.toml` inherits it via maturin's `dynamic = ["version"]`, and
`scripts/release-version.mjs sync` copies it into the plugin and editor metadata
that require literal JSON versions.

Releases are stabilized on a dedicated RC branch rather than directly on
`master`. Development on `master` moves quickly and may continue throughout a
release build, so tagging its moving tip can accidentally include changes that
were not part of the release candidate. An RC branch freezes a known-stable
commit while still allowing narrowly scoped release fixes and repeatable
validation against one immutable source line.

Rust third-party license HTML is generated rather than committed. Release
workflows generate it automatically. To inspect or package it locally, install
`cargo-about` 0.9.1 and run:

```bash
scripts/generate-rust-third-party-notices.sh licenses/THIRD_PARTY_LICENSES.html
```

The generated path is ignored by Git.

The agent and editor plugin manifests also carry release metadata and must be
checked during release prep. Before tagging a release, edit only `Cargo.toml`,
then run:

```bash
node scripts/release-version.mjs sync
```

That script updates these committed version fields:

- `plugins/bifrost-agent/.codex-plugin/plugin.json`
- `plugins/bifrost-agent/.claude-plugin/plugin.json`
- `plugins/bifrost-agent/.cursor-plugin/plugin.json`
- `.cursor-plugin/marketplace.json`
- `editors/vscode/package.json`
- `editors/vscode/package-lock.json`
- `plugins/bifrost-agent/package.json`
- `plugins/bifrost-agent/package-lock.json`
- the pinned npm install command in `plugins/bifrost-agent/README.md`
- `plugins/bifrost-agent/bifrost-release.json`
- `plugins/bifrost-agent/amp-skills/bifrost-code-intelligence/bifrost-release.json`
- `docs/src/content/docs/rust-library.md`

The package and README entries keep the published Pi artifact and its install
instructions on the Cargo version. The Codex and Claude marketplace files are
also part of the plugin surface, but
currently do not carry version fields:

- `.agents/plugins/marketplace.json`
- `.claude-plugin/marketplace.json`

The VS Code extension and bundled agent plugin also pin the Bifrost release
archive checksums:

- `editors/vscode/package.json`
- `plugins/bifrost-agent/bifrost-release.json`
- `plugins/bifrost-agent/amp-skills/bifrost-code-intelligence/bifrost-release.json`

Those checksum-bearing files must match the actual release archives.
`scripts/release-version.mjs sync` only copies the current
`plugins/bifrost-agent/bifrost-release.json` checksums into the VS Code manifest
when that release metadata is already on the same version as `Cargo.toml`. The
`release.yml` workflow prepares checksum metadata from the built `.sha256`
sidecars with `scripts/prepare-vscode-extension-manifest.mjs`, regenerates the
Amp skill bundle, validates the plugin manifests, packages
`bifrost-agent-<tag>.tar.gz`, and publishes the VSIX. A separate Pi package job
prepares the same release metadata for the npm tarball, validates the packed
package, and attaches it to the existing GitHub Release. If you perform those
packaging steps manually, run the same script against the release `dist/`
directory instead of hand-editing checksums.

To cut a release:

1. Select a known-stable commit from `master` and create a dedicated RC branch
   from that exact commit, for example `dave/v0.8.22-rc`. Push the branch so the
   candidate and any subsequent stabilization fixes are preserved remotely.
   Do not merge the moving `master` tip into the RC branch during stabilization;
   bring over only changes that are deliberately required for the release.
2. On the RC branch, bump `[workspace.package].version` in `Cargo.toml`, run the
   version-sync command above, and review the generated metadata. Release
   workflows generate the Rust dependency report from the tagged `Cargo.lock`;
   it is not committed.
3. If skills, agents, launcher files, MCP config, or plugin manifests changed,
   regenerate and validate the generated plugin bundles:

   ```bash
   node scripts/release-version.mjs check
   node scripts/generate-codex-skill-bundle.mjs
   node scripts/generate-amp-skill-bundle.mjs
   node scripts/check-codex-plugin-manifest.mjs
   node --test plugins/bifrost-agent/test/*.test.mjs
   ```

   `check-codex-plugin-manifest.mjs` checks the Codex, Claude, Cursor, and Pi
   manifests, the Cursor marketplace versions, the generated Codex and Amp
   bundles, and parseability of the Codex and Claude marketplace files. It also
   checks `plugins/bifrost-agent/bifrost-release.json`, so run it after that
   release metadata has been prepared for the version being validated.
4. Sync the release version projection and every stabilization fix from the RC
   branch back to `master`. An RC-only fix is not complete until its equivalent
   has landed on `master`; use a cherry-pick or an equivalent focused commit and
   resolve any conflicts against current `master` deliberately. Changes that
   land on `master` after the branch point remain outside the release unless
   they are explicitly selected for the RC branch.
5. After the RC branch is frozen and validated, tag the validated RC commit -
   not the current `master` tip - and push the tag:

   ```bash
   git tag -a v0.8.22 -m "Release v0.8.22"
   git push origin refs/tags/v0.8.22
   ```

A single `vX.Y.Z` tag starts the **Release** workflow. It resolves the tagged
commit once, then builds and validates CLI archives, crate contents, wheels/sdist,
agent-plugin packages, Pi packages, and the VS Code extension before opening the
promotion gate. The GitHub Release, crates.io, PyPI, VS Code Marketplace, and
agent-plugin release assets only run after that common evidence is green.

`publish-crate.yml`, `build-wheels.yml`, and `publish-wheels.yml` are reusable
children of that parent workflow; they are not independently dispatchable. Each
receives the same tag, version, and immutable source commit. Wheel/sdist filenames
are checked against the validated version before the gate, and the crate package
contents are checked before trusted crates.io publication.

The package-set check creates and unpacks every `.crate` archive, then
builds a temporary consumer with local registry patches. Publication follows
the dependency graph: `brokk-bifrost-core`, then the language crates
`brokk-bifrost-go` and `brokk-bifrost-rust` (which may run in parallel), then
`brokk-bifrost-analysis`, then
its direct dependents `brokk-bifrost-policy`, `brokk-bifrost-nlp`, and
`brokk-bifrost-semantic-packs` (which may run in parallel), then
`brokk-bifrost-runtime`, then MCP and LSP (which may run in parallel), and the
stable `brokk-bifrost` facade last. Each publication waits for crates.io to
expose the exact version and archive checksum before its dependents proceed.

`brokk-bifrost-go` and `brokk-bifrost-rust` are new packages. Trusted
publishing cannot create a new crate. Before the next release tag, upload each one's first version with a scoped
crates.io API token from a clean, reviewed commit. Then set the crate owners to
match the other Bifrost crates. Then configure GitHub trusted publishing for
repository `BrokkAi/bifrost`, workflow `release.yml`, and environment
`release`. Verify this configuration before you tag.

Use the **Release** workflow's unqualified `vX.Y.Z` `tag` input for a manual release. If a target fails,
use GitHub Actions' **Re-run failed jobs** for that workflow run to reuse its
validated artifacts. If a new run is necessary, dispatch the same tag again; never
recover a partial release from a different branch, commit, or tag. The release
summary records completed and pending publication targets, including the VS Code
release attachment and Marketplace publication separately.

To announce a published GitHub Release in Discord, set the
`DISCORD_RELEASE_WEBHOOK_URL` repository Actions secret to the target channel's
webhook URL. The release workflow reuses GitHub's generated release notes,
prevents mentions from being parsed, suppresses automatic link embeds, and
leaves a failed Discord delivery as a warning so it cannot invalidate an
already-published release. It uses built-in runner tools, so no additional
GitHub Actions allowlist entry is needed.

## Version Policy

- The workspace package version in `Cargo.toml` is the single source of truth for all Rust
  packages, the Python package, and release-aligned plugin/editor metadata. Never add a
  `version` to `pyproject.toml`; run `node scripts/release-version.mjs sync` to
  update JSON metadata from `Cargo.toml`.
- The Tree-sitter grammar crate versions are intentionally not forced to share
  the same numeric version. The policy is documented in `Cargo.toml`.
