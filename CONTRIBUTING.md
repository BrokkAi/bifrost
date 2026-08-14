# Contributing

## Contribution Policy

Bifrost no longer accepts pull requests. We accept open source contributions only through [GitHub Issues](https://github.com/BrokkAi/bifrost/issues) and [GitHub Discussions](https://github.com/BrokkAi/bifrost/discussions). Please use those channels to report bugs, propose improvements, share use cases, or discuss potential changes.

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
cargo machete
uv run --python 3.12 -- cargo test --features nlp,python
```

`cargo machete` is the unused-dependency gate that CI's lint job runs; install
it with `cargo install --locked cargo-machete --version 0.9.2`. If it flags a
dependency that is genuinely used (macro-only, feature-gated, or build-script
use it cannot see), add the dependency to that crate's
`[package.metadata.cargo-machete] ignored` list with a comment explaining why
it is real; otherwise remove the dependency.

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
`scripts/release-version.mjs sync` copies it into citation, semantic-pack,
plugin, and editor metadata that require literal versions. The script does not
infer `CITATION.cff`'s `date-released`; setting the actual release date remains
an explicit release-preparation step.

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
checked during release prep. Before tagging a release, edit the workspace
version in `Cargo.toml`, set `CITATION.cff`'s `date-released` to the actual
release date, then run:

```bash
node scripts/release-version.mjs sync
```

That script updates these committed version fields and compatibility bounds:

- `CITATION.cff`'s `version` field, without changing `date-released`
- the exclusive Bifrost compatibility upper bound in shipped semantic-pack
  specifications and Bifrost-owned framework, golden, and sanitizer foundry
  sources; other pack metadata and lower bounds remain unchanged
- `plugins/bifrost-agent/plugin.json`
- `plugins/bifrost-agent/.claude-plugin/plugin.json`
- `plugins/bifrost-agent/.cursor-plugin/plugin.json`
- `plugins/bifrost-agent/plugin.json`
- `.cursor-plugin/marketplace.json`
- `editors/vscode/package.json`
- `editors/vscode/package-lock.json`
- `plugins/bifrost-agent/package.json`
- `plugins/bifrost-agent/package-lock.json`
- the pinned npm install command in `plugins/bifrost-agent/README.md`
- `plugins/bifrost-agent/bifrost-release.json`
- `docs/src/content/docs/rust-library.md`

The package and README entries keep the published Pi artifact and its install
instructions on the Cargo version. The Codex and Claude marketplace files are
also part of the plugin surface, but
currently do not carry version fields:

- `.agents/plugins/marketplace.json`
- `.claude-plugin/marketplace.json`

The VS Code extension and bundled agent plugin also share the preferred,
minimum, and prerelease compatibility fields and pin the preferred Bifrost
release archive checksums:

- `editors/vscode/package.json`
- `plugins/bifrost-agent/bifrost-release.json`

Those checksum-bearing files must match the actual release archives.
`scripts/release-version.mjs sync` only copies the current
`plugins/bifrost-agent/bifrost-release.json` checksums into the VS Code manifest
when that release metadata is already on the same version as `Cargo.toml`. The
`release.yml` workflow prepares checksum metadata from the built `.sha256`
sidecars with `scripts/prepare-vscode-extension-manifest.mjs`, validates the
plugin manifests, packages
`bifrost-agent-<tag>.tar.gz`, and publishes the VSIX. A separate Pi package job
prepares the same release metadata for the npm tarball, validates the packed
package, and attaches it to the existing GitHub Release. If you perform those
packaging steps manually, run the same script against the release `dist/`
directory instead of hand-editing checksums.

To cut a release:

1. Audit every publishable workspace crate against the inventory below.
   Confirm that each crate exists on crates.io and has the required trusted
   publisher. Bootstrap any new crate before release preparation. Do not use
   the version release to create a crate for the first time.
2. Select a known-stable commit from `master` and create a dedicated RC branch
   from that exact commit, for example `dave/v0.8.22-rc`. Push the branch so the
   candidate and any subsequent stabilization fixes are preserved remotely.
   Do not merge the moving `master` tip into the RC branch during stabilization;
   bring over only changes that are deliberately required for the release.
3. On the RC branch, bump `[workspace.package].version` in `Cargo.toml`, run the
   version-sync command above, and review the generated metadata. Release
   workflows generate the Rust dependency report from the tagged `Cargo.lock`;
   it is not committed.
4. If agents, launcher files, MCP config, or plugin manifests changed, validate
   the plugin bundles:

   ```bash
   node scripts/release-version.mjs check
   node scripts/check-agent-plugins-v1.mjs
   node scripts/check-codex-plugin-manifest.mjs
   node --test plugins/bifrost-agent/test/*.test.mjs
   ```

   `check-agent-plugins-v1.mjs` checks the portable root `plugin.json` and
   `mcp.json`. `check-codex-plugin-manifest.mjs` checks the portable package,
   Claude, Cursor, and Pi adapters, the Cursor marketplace versions, and the
   release metadata. Run both after
   the release metadata has been prepared for the version being validated.
5. Before you create the final tag, treat the RC commit as green only after its
   required branch checks and these release-specific checks pass:

   ```bash
   scripts/pre-push-gate.sh
   cargo build --release --locked --bin bifrost
   plugin_smoke_root="$(mktemp -d "${TMPDIR:-/tmp}/bifrost-agent-pretag.XXXXXX")"
   mkdir -p "$plugin_smoke_root/package" "$plugin_smoke_root/extracted"
   git archive HEAD plugins/bifrost-agent | tar -C "$plugin_smoke_root/package" -xf -
   cp plugins/bifrost-agent/LICENSE.md "$plugin_smoke_root/package/plugins/bifrost-agent/LICENSE.md"
   tar -C "$plugin_smoke_root/package/plugins" -czf "$plugin_smoke_root/bifrost-agent.tar.gz" bifrost-agent
   tar -C "$plugin_smoke_root/extracted" -xzf "$plugin_smoke_root/bifrost-agent.tar.gz"
   plugin_smoke_dir="$(cd "$plugin_smoke_root/extracted/bifrost-agent" && pwd -P)"
   node scripts/smoke-agent-plugin-release.mjs \
     --plugin-dir "$plugin_smoke_dir" \
     --cache-dir "$plugin_smoke_root/cache" \
     --binary-path "$(pwd)/target/release/bifrost"
   rm -rf "$plugin_smoke_root"
   target/release/bifrost \
     --root . \
     --format sarif \
     --output target/release-rc-policy.sarif \
     --fail-on never \
     --policy-pack bifrost.code-smells
   ```

   The staged-agent command reproduces the prepublication plugin boundary: it
   packages the portable plugin, extracts it away from the checkout, launches
   that package with the exact optimized binary to be tagged, and exercises
   both Codex metadata and MCP roots workspace binding plus policy discovery
   and execution. Do not substitute the plugin unit tests or manifest checks
   for this end-to-end smoke.

   The policy command is a release-artifact smoke test. Existing findings do
   not fail it. An unreliable scan still exits with status 2 and blocks the
   release. Do not tag the RC commit only because its ordinary branch CI is
   green. Confirm that each release-only promotion gate has an equivalent
   pre-tag check, and run it on the frozen RC commit.
6. Sync the release version projection and every stabilization fix from the RC
   branch back to `master`. An RC-only fix is not complete until its equivalent
   has landed on `master`; use a cherry-pick or an equivalent focused commit and
   resolve any conflicts against current `master` deliberately. Changes that
   land on `master` after the branch point remain outside the release unless
   they are explicitly selected for the RC branch.
7. After the RC branch is frozen and validated, tag the validated RC commit -
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

After the **Release** workflow succeeds, `publish-npm.yml` packages each native
archive as a platform package. It publishes the platform packages first. It
publishes `@brokkai/bifrost` only after all platform versions are visible from
npm. This npm CLI package is separate from the `@brokk/bifrost-agent` Pi
package. The npm workflow uses the `npm-publish` environment and npm trusted
publishing. It does not use a stored npm token.

`publish-crate.yml` and `build-wheels.yml` are reusable children of that parent
workflow; they are not independently dispatchable. Wheel publication runs as
the `publish-wheels` job inside `release.yml`. Each stage receives the same tag,
version, and immutable source commit. Wheel/sdist filenames are checked against
the validated version before the gate, and the crate package contents are
checked before trusted crates.io publication.

The package-set check creates and unpacks every `.crate` archive, then
builds a temporary consumer with local registry patches. Publication follows
the dependency graph: `brokk-bifrost-core`, then the language crates
`brokk-bifrost-cpp`, `brokk-bifrost-csharp`, `brokk-bifrost-go`,
`brokk-bifrost-js-ts`, `brokk-bifrost-jvm`, `brokk-bifrost-php`,
`brokk-bifrost-python`, `brokk-bifrost-ruby` and `brokk-bifrost-rust` (which may
run in parallel), and `brokk-bifrost-rql` in parallel, then
`brokk-bifrost-analysis`, then
its direct dependents `brokk-bifrost-policy`, `brokk-bifrost-nlp`, and
`brokk-bifrost-semantic-packs` (which may run in parallel), then
`brokk-bifrost-runtime`, then MCP and LSP (which may run in parallel), and the
stable `brokk-bifrost` facade last. Each publication waits for crates.io to
expose the exact version and archive checksum before its dependents proceed.

### Published crate inventory

This table is the expected crates.io publication set for the workspace.

| Package | Manifest | Publication order |
| --- | --- | --- |
| `brokk-bifrost-core` | `crates/bifrost-core/Cargo.toml` | 1 |
| `brokk-bifrost-cpp` | `crates/bifrost-cpp/Cargo.toml` | 2 |
| `brokk-bifrost-csharp` | `crates/bifrost-csharp/Cargo.toml` | 2 |
| `brokk-bifrost-go` | `crates/bifrost-go/Cargo.toml` | 2 |
| `brokk-bifrost-js-ts` | `crates/bifrost-js-ts/Cargo.toml` | 2 |
| `brokk-bifrost-jvm` | `crates/bifrost-jvm/Cargo.toml` | 2 |
| `brokk-bifrost-php` | `crates/bifrost-php/Cargo.toml` | 2 |
| `brokk-bifrost-python` | `crates/bifrost-python/Cargo.toml` | 2 |
| `brokk-bifrost-ruby` | `crates/bifrost-ruby/Cargo.toml` | 2 |
| `brokk-bifrost-rust` | `crates/bifrost-rust/Cargo.toml` | 2 |
| `brokk-bifrost-rql` | `crates/bifrost-rql/Cargo.toml` | 2 |
| `brokk-bifrost-analysis` | `crates/bifrost-analysis/Cargo.toml` | 3 |
| `brokk-bifrost-nlp` | `crates/bifrost-nlp/Cargo.toml` | 4 |
| `brokk-bifrost-policy` | `crates/bifrost-policy/Cargo.toml` | 4 |
| `brokk-bifrost-semantic-packs` | `crates/bifrost-semantic-packs/Cargo.toml` | 4 |
| `brokk-bifrost-runtime` | `crates/bifrost-runtime/Cargo.toml` | 5 |
| `brokk-bifrost-mcp` | `crates/bifrost-mcp/Cargo.toml` | 6 |
| `brokk-bifrost-lsp` | `crates/bifrost-lsp/Cargo.toml` | 6 |
| `brokk-bifrost` | `Cargo.toml` | 7 |

Before each release, compare this table with the root workspace members and
package names. Confirm these items for each package:

- The package exists on crates.io.
- The package trusts this repository's GitHub publisher.
- The publisher uses `release.yml` and the `release` environment.
- `release.yml` includes the package in its publication graph.
- Each internal dependency uses the release version.
- The manifest declares `description` and `readme`, and inherits the
  workspace `keywords`, `categories`, and `rust-version`.

Do not add a crate only to move code into a new directory. A new crate must
have a clear dependency, compilation, publication, or ownership boundary.

When a change adds a publishable crate, update this table and the release
workflow in the same change. Publish the crate through a separate bootstrap
change before the next version release. Configure its trusted publisher during
that bootstrap.

`brokk-bifrost-cpp`, `brokk-bifrost-csharp`, `brokk-bifrost-go`,
`brokk-bifrost-js-ts`, `brokk-bifrost-jvm`, `brokk-bifrost-php`,
`brokk-bifrost-python`, `brokk-bifrost-ruby` and `brokk-bifrost-rust` are new
packages that still await that bootstrap publication. `brokk-bifrost-rql` also
awaits its bootstrap publication. Trusted publishing cannot create a new crate, so
each one's first version must be uploaded with a scoped crates.io API token
from a clean, reviewed commit. Then set the crate owners and configure the
trusted publisher per the checklist above, and verify that configuration
before you tag.

Use the **Release** workflow's unqualified `vX.Y.Z` `tag` input for a manual
release. Dispatch it from `master`. The workflow definition comes from
`master`, but every build and publication input comes from the immutable tag.
This separation permits a workflow-only recovery without moving the tag or
changing the released source.

If a target fails, first use GitHub Actions' **Re-run failed jobs** for that
workflow run. This action reuses its validated artifacts. If a new run is
necessary, dispatch the same tag again. Never recover a partial release from a
different branch, commit, or tag.

Registry visibility can lag after a successful upload. For example, Open VSX
can accept a VSIX before its version API returns it. If the upload succeeded
but the visibility check timed out, confirm that the public artifact has the
expected version and checksum. Then rerun the failed job. Do not upload a
different artifact for the same version.

The npm publication workflow starts only after the parent Release workflow
succeeds. After recovery, confirm both workflows are green. Also confirm the
root npm package and all platform packages expose the released version. The
release summary records completed and pending publication targets, including
the VS Code release attachment and Marketplace publication separately.

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
