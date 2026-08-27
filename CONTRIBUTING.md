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
uv run --python 3.12 -- cargo test --features python
```

`cargo machete` is the unused-dependency gate that CI's lint job runs; install
it with `cargo install --locked cargo-machete --version 0.9.2`. If it flags a
dependency that is genuinely used (macro-only, feature-gated, or build-script
use it cannot see), add the dependency to that crate's
`[package.metadata.cargo-machete] ignored` list with a comment explaining why
it is real; otherwise remove the dependency.

Bifrost's default feature set is empty. Include the `python` feature when
running the Python-facing Rust test suite. Run Rust tests that
enable the `python` feature through uv so PyO3 uses the project's Python 3.12
environment rather than whichever system interpreter happens to be on `PATH`.

Python:

```bash
scripts/public/test_python.sh
```

That wrapper provisions a uv-managed Python 3.12 environment, makes `maturin` available, installs the editable native extension, and then runs the unittest suite.

For host-local changes, run the independently owned package contract first:

```bash
cargo test -p brokk-bifrost-mcp
cargo test -p brokk-bifrost-lsp --all-features
```

Changes in `brokk-bifrost-core`, `brokk-bifrost-analysis`,
`brokk-bifrost-flow`, `brokk-bifrost-rql`, `brokk-bifrost-policy`, or
`brokk-bifrost-runtime` affect both hosts and should use the full workspace
gate. MCP and LSP are versioned
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
`scripts/public/release-version.mjs sync` copies it into citation, semantic-pack,
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
scripts/public/generate-rust-third-party-notices.sh licenses/THIRD_PARTY_LICENSES.html
```

The generated path is ignored by Git.

The agent and editor plugin manifests also carry release metadata and must be
checked during release prep. Before tagging a release, edit the workspace
version in `Cargo.toml`, set `CITATION.cff`'s `date-released` to the actual
release date, then run:

```bash
node scripts/public/release-version.mjs sync
```

That script updates these committed version fields:

- `CITATION.cff`'s `version` field, without changing `date-released`
- `plugins/bifrost-agent/.claude-plugin/plugin.json`
- `plugins/bifrost-agent/.codex-plugin/plugin.json`
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
currently do not carry version fields.

The VS Code extension and bundled agent plugin also share the preferred,
minimum, and prerelease compatibility fields and pin the preferred Bifrost
release archive checksums:

- `editors/vscode/package.json`
- `plugins/bifrost-agent/bifrost-release.json`

Those checksum-bearing files must match the actual release archives.
`scripts/public/release-version.mjs sync` only copies the current
`plugins/bifrost-agent/bifrost-release.json` checksums into the VS Code manifest
when that release metadata is already on the same version as `Cargo.toml`. The
`release.yml` workflow prepares checksum metadata from the built `.sha256`
sidecars with `scripts/public/prepare-vscode-extension-manifest.mjs`, validates the
plugin manifests, packages
`bifrost-agent-<tag>.tar.gz`, and publishes the VSIX. A separate Pi package job
prepares the same release metadata for the npm tarball, validates the packed
package, and attaches it to the existing GitHub Release. If you perform those
packaging steps manually, run the same script against the release `dist/`
directory instead of hand-editing checksums.

### Changelog

Before tagging each release, update `CHANGELOG.md` with a concise, curated
summary of meaningful public changes. Group related work by capability or user
impact, and call out compatibility changes, migrations, and notable fixes when
they apply. Do not copy commit subjects, enumerate commits, or use a tag
comparison as the release notes.

The public repository is projected from this private canonical source, so its
commit history is not a complete record of the work in a release. Derive each
entry from the complete private release range, while keeping private
implementation details and private-only capabilities out of the public
changelog. GitHub-generated release notes and tag comparisons are supplemental;
they do not replace the curated entry.

Keep an `Unreleased` entry for the next intended version at the top of the
changelog. Preview the exact GitHub Release body during release preparation:

```bash
node scripts/public/extract-changelog-entry.mjs --version X.Y.Z
```

Before tagging, replace `Unreleased` with the actual release date. The release
workflow extracts the same entry from the qualified tag and fails rather than
falling back to generated pull-request notes when it is missing, duplicated, or
empty.

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
3. Regenerate the tracked projection inventory from the frozen RC commit, using
   the checked-in deterministic namespace shards as its baseline. Review every
   new or mode-changed path left with a `review` decision, record each explicit
   `public` or `private` approval, and inspect the affected shard diffs before
   cutting the tag. Do not combine or omit shards: their union is the exact
   fail-closed inventory.
   Private-only paths and other private additions remain outside the public
   projection. Do not proceed while the inventory is unreviewed or the
   projection reports an unclassified source path.
4. On the RC branch, bump `[workspace.package].version` in `Cargo.toml`, run the
   version-sync command above, update `CHANGELOG.md` for the release, and review
   the generated metadata and curated changelog entry. Release workflows
   generate the Rust dependency report from the tagged `Cargo.lock`; it is not
   committed.
5. If agents, launcher files, MCP config, or plugin manifests changed, validate
   the plugin bundles:

   ```bash
   node scripts/public/release-version.mjs check
   node scripts/public/check-agent-plugins-v1.mjs
   node scripts/public/check-codex-plugin-manifest.mjs
   node --test plugins/bifrost-agent/test/*.test.mjs
   ```

  `check-agent-plugins-v1.mjs` checks the portable root files, the Codex
  package adapter, and the Cursor adapter. `check-codex-plugin-manifest.mjs`
  checks the portable package, Codex, Claude, Cursor, and Pi adapters, the
  Cursor marketplace versions, and the release metadata. Run both after
   the release metadata has been prepared for the version being validated.
6. Before you create the final tag, treat the RC commit as green only after its
   required branch checks and these release-specific checks pass:

   ```bash
   scripts/public/pre-push-gate.sh
   cargo build --release --locked --bin bifrost
   plugin_smoke_root="$(mktemp -d "${TMPDIR:-/tmp}/bifrost-agent-pretag.XXXXXX")"
   mkdir -p "$plugin_smoke_root/package" "$plugin_smoke_root/extracted"
   git archive HEAD plugins/bifrost-agent | tar -C "$plugin_smoke_root/package" -xf -
   cp plugins/bifrost-agent/LICENSE.md "$plugin_smoke_root/package/plugins/bifrost-agent/LICENSE.md"
   tar -C "$plugin_smoke_root/package/plugins" -czf "$plugin_smoke_root/bifrost-agent.tar.gz" bifrost-agent
   tar -C "$plugin_smoke_root/extracted" -xzf "$plugin_smoke_root/bifrost-agent.tar.gz"
   plugin_smoke_dir="$(cd "$plugin_smoke_root/extracted/bifrost-agent" && pwd -P)"
   node scripts/public/smoke-agent-plugin-release.mjs \
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
7. Sync the release version projection and every stabilization fix from the RC
   branch back to `master`. An RC-only fix is not complete until its equivalent
   has landed on `master`; use a cherry-pick or an equivalent focused commit and
   resolve any conflicts against current `master` deliberately. Changes that
   land on `master` after the branch point remain outside the release unless
   they are explicitly selected for the RC branch.
8. After the RC branch is frozen and validated, project it to public `master`,
   qualify that public commit, and tag **the qualified public commit in
   `BrokkAi/bifrost`**. The tag does not go on the private RC commit and does
   not go in the private repository: `release.yml` is gated on
   `github.repository == 'BrokkAi/bifrost'`, so a tag pushed there starts
   nothing. The v-tags present in the private repository predate the
   open-core split and are not release tags.

   Do not improvise this step. Follow the numbered handoff under
   [Readiness handoff and recovery](#readiness-handoff-and-recovery),
   which is the authoritative sequence: project, wait for public CI, dispatch
   `Release readiness` against the exact public commit, inspect the retained
   qualification bundle, confirm ancestry with
   `scripts/check-build-ancestry.sh`, and only then create the public tag.

   The ancestry check compares the **qualified public commit** against the
   previous release tag's source, so that a higher version label cannot carry
   older source. Comparing the private RC commit answers a different question
   and does not establish that property for what is actually published.

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

### Post-release agent-plugin smoke

After the GitHub Release exposes the agent-plugin archive and the platform
Bifrost archives plus their `.sha256` sidecars, run the consumer smoke from a
clean checkout using the exact published version:

```bash
node scripts/public/smoke-published-agent-plugin.mjs --version 0.10.1
```

The command downloads `bifrost-agent-v<version>.tar.gz` away from the checkout,
extracts it, and creates a fresh launcher cache. It then prepares the preferred
binary with path lookup disabled (therefore exercising the published archive
and checksum sidecar), runs `doctor` in exact-version mode, and makes an actual
MCP `list_policies` call through both the published Codex and Claude adapter
configs. It also checks the exact release tag's Codex and Claude marketplace
entries, so a missing public marketplace cannot hide behind a valid package
archive. It does not modify Codex or Claude configuration, start a model
session, or require host API credentials. The smoke runs for the current
platform; run it on each supported release platform when platform-specific
archive coverage is required. The two MCP calls exercise the exact host
adapter launch configurations without pretending to validate a host's current
user session; after a pass, a fresh Codex/Claude task can be used for any
credentialed model-level check.

For a release asset downloaded separately, pass it explicitly:

```bash
node scripts/public/smoke-published-agent-plugin.mjs \
  --version 0.10.1 \
  --archive /path/to/bifrost-agent-v0.10.1.tar.gz \
  --keep-temp
```

`--keep-temp` preserves the isolated archive, extracted package, launcher
cache, and workspace for diagnosis. A checksum failure means the published
release metadata and sidecar do not describe the same archive; an adapter
failure means the plugin is present but its MCP server was not callable. Treat
either result as a release incident and do not claim that the policy-checking
skill is usable until a fresh run reports both adapter calls passed.

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
run in parallel), then `brokk-bifrost-analysis`, then `brokk-bifrost-flow`, then
`brokk-bifrost-rql` and
`brokk-bifrost-semantic-packs` in parallel, then `brokk-bifrost-policy`, then
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
| `brokk-bifrost-analysis` | `crates/bifrost-analysis/Cargo.toml` | 3 |
| `brokk-bifrost-flow` | `crates/bifrost-flow/Cargo.toml` | 4 |
| `brokk-bifrost-rql` | `crates/bifrost-rql/Cargo.toml` | 5 |
| `brokk-bifrost-semantic-packs` | `crates/bifrost-semantic-packs/Cargo.toml` | 5 |
| `brokk-bifrost-policy` | `crates/bifrost-policy/Cargo.toml` | 6 |
| `brokk-bifrost-runtime` | `crates/bifrost-runtime/Cargo.toml` | 7 |
| `brokk-bifrost-mcp` | `crates/bifrost-mcp/Cargo.toml` | 8 |
| `brokk-bifrost-lsp` | `crates/bifrost-lsp/Cargo.toml` | 8 |
| `brokk-bifrost` | `Cargo.toml` | 9 |

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

Every package in the inventory is now bootstrapped on crates.io, and the
latest publication entry for each carries `trustpub_data.repository` set to
`BrokkAi/bifrost`. For any future package, retain the bootstrap policy above:
trusted publishing cannot create a new crate, so the first version must be
uploaded with a scoped crates.io API token from a clean, reviewed commit. Then
set the crate owners and configure the trusted publisher per the checklist
above, and verify that configuration before you tag.

`brokk-bifrost-flow` was bootstrapped during the `v0.10.6` release rather than
before it, which is the failure this policy exists to prevent. The inventory
already listed the crate and already carried the warning; only the bootstrap
itself was missed, so the release published ten crates, refused the eleventh
with `Trusted Publishing tokens do not support creating new crates`, and
correctly withheld the facade rather than publishing one that depended on a
version nobody could resolve.

Recovery, if it happens again: upload the qualified `.crate` from the
readiness bundle with `scripts/public/publish-qualified-crate.mjs
--metadata-file ... --crate-file ... --expected-sha256 ...` and a personal
token, which publishes the exact qualified bytes rather than a local rebuild.
Then configure the trusted publisher and re-run the failed release jobs, which
reuse the validated artifacts. Verifying the configuration before tagging is
still cheaper: check the crate's settings page shows the workflow as
`release.yml`, the entry workflow, not the reusable `publish-crate.yml` that
contains the job.

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

### Readiness handoff and recovery

Use one explicit handoff from source projection to release publication:

0. Cut a release branch in the private repository at the reviewed source
   commit, and treat that branch as the release line for every later step. A
   qualification takes about an hour and private `master` takes a commit every
   few minutes, so a correction based on the qualified source is routinely not
   a fast-forward of `master` by the time it can be made. The release branch is
   the ref that holds still for the length of a release. Merge it back into
   `master` after the tag exists.
1. Project the release branch's commit to public `master`, then wait for
   public CI to validate that projection.
2. Dispatch `Release readiness` from the public repository with the exact
   public commit, release version, and independently observed public head.
   Select the run whose inputs and `preflight` output match those values; do
   not use the latest run merely because it is latest.
3. Inspect the retained `release-qualification.json` manifest and its recorded
   file digests, release inventory, commit, version, and workflow run. Treat
   that single qualification bundle as the evidence for the handoff. Confirm
   with `scripts/check-build-ancestry.sh` that the qualified public commit
   contains the prior release tag's source.
4. Sync the launcher checksums before tagging. The qualification's promoted
   sidecars are the first point at which the release's archive digests exist,
   and tracked source still records the previous release's. Dispatch
   `Sync qualified release metadata` (private repository) with the release
   tag, the qualification run, artifact, digest, the private source commit, and
   the release branch that commit is the tip of. It reads the sidecars from the
   qualification bundle rather than from published release assets, because at
   this point the tag does not exist yet and the release publishes its assets
   out of that same bundle. It corrects the three tracked checksum projections,
   commits them to the release branch, projects them to public `master`, and
   adopts that projection's conclusion, so a failure here means the corrected
   digests are not public and the tag must wait. The commit is pushed
   fast-forward only, so a release branch that moved under the run fails the
   operation rather than silently rebasing the correction onto a different
   source. Skipping this step is what left `v0.10.3` and `v0.10.4` publishing
   plugins whose committed checksums described the previous release, so a
   fresh marketplace install failed closed with `checksum_mismatch`.
5. Re-qualify the corrected commit. Dispatch `Release readiness` again against
   the new public head with `requalify_from_run` set to the run from step 2.
   Nothing is rebuilt: it verifies the correction touches only those three
   paths and re-labels the existing bundle for the corrected commit. That is
   sound because the build identity names the last commit that touched a
   compiled input, so the binaries already qualified report the same identity
   at either commit. A full readiness run here would not converge -- the
   binary compiles its identity in, so rebuilding the corrected commit yields
   digests that commit does not record.
6. Only after that inspection, separately create and authorize the public
   `vX.Y.Z` tag on the **corrected** public commit, whose committed checksums
   now describe its own artifacts. Projection does not create a tag, dispatch
   `Release`, or publish an artifact.
7. After promotion, invoke the post-release smoke workflow with that exact tag
   (through its reusable call or manual dispatch), then monitor registry and
   marketplace visibility and rerun only the failed smoke jobs when a target
   is still propagating.

Readiness artifacts are retained for 14 days. Use GitHub Actions **Re-run
failed jobs** on the same readiness run while its artifacts remain available.
If the qualification artifact has expired, dispatch a new readiness run with
the same exact inputs and inspect its new manifest from the beginning. Never
mix artifacts, manifests, or evidence from different runs, commits, versions,
or attempts into one release decision.

Readiness has read-only permissions and cannot substitute for publisher
authentication. Crates.io trusted publishing, PyPI, npm, and marketplace
credentials are available only to the separately protected public release
workflow and its configured environments; a green readiness run is not
evidence that those publisher identities are configured or that publication
has occurred. A release retry must use the publisher's existing protected
authentication and the already qualified artifact; it must not upload a new
artifact for the same version.

### Workflow-only recovery

A workflow-only recovery repairs a defect in the release workflow mechanics
themselves while the existing qualification remains valid. Its contract:

1. The repair may change only files under `.github/workflows/`. Publisher
   scripts, packaging code, and Rust sources are checked out from the
   immutable qualified release commit by the publication jobs, so changing
   them on public `master` cannot affect an existing tag; such a change needs
   a new qualification instead.
2. Land the repair on private `master`, then dispatch **Prepare open-core
   projection** with `workflow_recovery` set to true and the exact current
   public head. The projection proves, byte for byte, that the candidate
   differs from that public head only under `.github/workflows/` and then
   skips the projected Rust build gate. If anything else changed, the proof
   step fails and a full projection is required.
3. A workflow-only recovery does not require a new readiness run or a public
   CI wait before retrying. The prior immutable qualification (tag commit,
   readiness run, artifact ID, digest, manifest SHA-256) remains the release
   evidence. Re-dispatch **Release** with the same tag; the repaired workflow
   definition comes from public `master` while every publication input stays
   bound to the qualified artifact.
4. The release summary records the qualified release source and the mutable
   workflow definition source separately. A recovery retry may change only
   the mutable workflow source; a changed qualified identity or checksum is
   an incident, not a recovery.

The npm trusted-publishing client contract (pinned modern npm, no
classic-token configuration, cleared `NODE_AUTH_TOKEN`, explicit provenance,
master-ref child dispatch) is validated before any tag exists by
`scripts/public/check-npm-trusted-publishing.mjs`, which runs in the readiness
preflight and in private CI.

The workflows do not currently claim a fixed duration or speed improvement
from caching. Any timing target must be measured and recorded by a completed
rehearsal; it must not be inferred from configuration alone.

The release workflow also syncs the policy-scan composite action into the
standalone alias repository `BrokkAi/bifrost-policy-scan`, so workflows can
reference `uses: BrokkAi/bifrost-policy-scan@vX.Y.Z` instead of the
subdirectory form. `scripts/public/sync-policy-scan-action.sh` copies the canonical
`.github/actions/policy-scan/action.yml`, rewrites its `version` input default
to the release tag being published (keeping the action and the Bifrost binary
it installs in lockstep), pushes one commit, tags the exact release tag, and
force-moves the floating major tag (`v0`). Only the newest `vMAJOR.x.y`
release may move the floating tag and the default branch: an out-of-order
sync of an older release (a recovery re-run or a backport) publishes its
exact tag only, so it can never downgrade consumers that follow `@v0` or the
repository head. The push authenticates as a GitHub
App installation: the job mints a short-lived installation token with
`actions/create-github-app-token` from the `POLICY_SCAN_APP_CLIENT_ID`
variable and the `POLICY_SCAN_APP_PRIVATE_KEY` secret in the protected
`release` environment (the job runs under `environment: release` like the
other publisher jobs), downscoped at mint time to the alias repository and the
Contents permission. One-time setup: create the alias repository with an
initial commit; create a dedicated org-owned GitHub App with only the Contents
read/write repository permission; install it on the alias repository only; and
store the App client ID in the variable and a generated private key in the
secret, both on the `release` environment. Do not reuse the open-core projector App for this: its private key can
mint tokens with contents and workflows write on the public repository and
belongs only in the private repository's secret store. An exact alias tag is
immutable; if the remote tag
exists with different content the sync fails instead of moving it. The sync is
recorded in the release summary but does not gate npm publication; recover a
failed sync with **Re-run failed jobs**. Listing the alias repository on the
GitHub Marketplace is a one-time manual step from that repository's release UI.

To announce a published GitHub Release in Discord, set the
`DISCORD_RELEASE_WEBHOOK_URL` repository Actions secret to the target channel's
webhook URL. The release workflow reuses the curated changelog entry published
as the GitHub Release body, prevents mentions from being parsed, suppresses
automatic link embeds, and
leaves a failed Discord delivery as a warning so it cannot invalidate an
already-published release. It uses built-in runner tools, so no additional
GitHub Actions allowlist entry is needed.

## Version Policy

- The workspace package version in `Cargo.toml` is the single source of truth for all Rust
  packages, the Python package, and release-aligned plugin/editor metadata. Never add a
  `version` to `pyproject.toml`; run `node scripts/public/release-version.mjs sync` to
  update JSON metadata from `Cargo.toml`.
- The Tree-sitter grammar crate versions are intentionally not forced to share
  the same numeric version. The policy is documented in `Cargo.toml`.
