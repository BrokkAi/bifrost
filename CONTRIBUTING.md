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
BIFROST_OPEN_PACKS_DISABLE="${BIFROST_OPEN_PACKS_DISABLE-1}" uv run --python 3.12 -- cargo test --features python
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
BIFROST_OPEN_PACKS_DISABLE="${BIFROST_OPEN_PACKS_DISABLE-1}" cargo test -p brokk-bifrost-mcp
```

Changes in `brokk-bifrost-core`, `brokk-bifrost-analysis`,
`brokk-bifrost-flow`, `brokk-bifrost-rql`, `brokk-bifrost-policy`, or
`brokk-bifrost-runtime` affect both hosts and should use the full workspace
gate. MCP and LSP are versioned
implementation dependencies of the stable `brokk-bifrost` facade, not
separate public API commitments.

## Python Development

For repo-local development without installing the package, `SearchToolsClient(..., library_path=...)` can load a built debug library such as `target/debug/libbrokk_bifrost.so`.

The Python `query_code` result dataclasses, enums, and decoders are generated
from the Rust serialization contract. After changing a serializable result
type, regenerate the checked-in module from the repository root:

```bash
set -o pipefail
cargo run --quiet --locked -p brokk-bifrost-rql --bin query_result_schema |
  python3 scripts/public/generate-python-query-models.py \
    --output bifrost_searchtools/_generated_query_models.py \
    --root-name CodeQueryResult
```

Use the same command with `--check` to verify that the artifact is current.
The generator consumes JSON Schema only; it does not parse Rust source.
Unsupported schema constructs fail explicitly. Client lifecycle and result
rendering remain handwritten in `models.py`.

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

The Rust crates, the `bifrost` binary, the Python wheel, and the engine's agent
plugin release metadata are versioned **together** and cut from a **single tag**.
The standalone language server and VS Code extension in
[bifrost-lsp](https://github.com/BrokkAi/bifrost-lsp) have independent versions.
`Cargo.toml`'s `[workspace.package]` version is the committed source of truth for the release version:
`pyproject.toml` inherits it via maturin's `dynamic = ["version"]`, and
`scripts/public/release-version.mjs sync` copies it into citation, retained semantic-pack,
plugin, and editor metadata that require literal versions. The script does not
infer `CITATION.cff`'s `date-released`; setting the actual release date remains
an explicit release-preparation step.

Releases are cut from a release candidate (RC) branch rather than from the
moving tip of `master`, so that a release names one immutable commit. The rule
for what may be on that branch is deliberately narrow:

An RC is a master commit whose `Release gate` run is green, plus any number
of cherry-picks of commits that have already landed on `master`, plus at most
one metadata commit, in any order. The metadata commit may change only release
metadata: the workspace version and the files
`scripts/public/release-version.mjs sync` derives from it, `CHANGELOG.md`,
`CITATION.cff`, `Cargo.lock`, and the launcher checksum projections. Nothing
that `master` lacks goes on an RC: a fix lands on `master` through the merge
queue first, then `git cherry-pick -x <master-commit>` puts that exact commit
on the RC. Never commit a fix directly to an RC and never merge `master` into
one. The verifier enforces this: it walks first parents from the RC head to
the nearest `master` commit (at most 50 commits) and requires every commit on
the way to be a cherry-pick (its `git patch-id --stable` equals that of a
commit on `master` newer than the base) or the one metadata commit. A merge
commit, a second metadata commit, or a commit that matches no `master` commit
and touches a path outside release metadata is rejected with that commit named.
Cherry-pick a merge-queue batch's constituent commits, not the batch merge. The
patch-id covers context lines, so a cherry-pick that needed conflict resolution
no longer matches and cannot go on the RC; recut the RC from a newer `master`
commit instead.

When a gate run on the RC is red, first ask whether the source is red or the
run is. Re-dispatch the gate on the RC branch (`gh workflow run
release-gate.yml --ref candidate/vX.Y.Z-rc`) when the same commit already has a
green gate run on `master`, or when the failure is a single test that does not
reproduce on `master` at that commit; the latest run wins, so a green rerun
qualifies the same head with nothing recut. Only a failure that reproduces
means the source is red: land the repair on `master` through the merge queue
like every other change, then cherry-pick that commit onto the RC; a release
never waits on work that has not landed there. Recut the RC from a newer
`master` commit only when the cherry-picks cannot apply or the walk bound is
exceeded.
A regression that lands on `master` after the RC was cut does not touch the RC;
the RC is judged by runs at its own commit, not by the state of `master`.
There is no permanent release-ready branch, campaign registry, or promotion
controller.

`Release gate` (`.github/workflows/release-gate.yml`) runs on `master` every 8
hours when `master` has moved, on every push to a `candidate/v*-rc` (or legacy `dave/v*-rc`) branch, and on
demand through `workflow_dispatch`. It runs the whole workspace with
`--cfg scheduled_tests` on Windows/x86, Linux/ARM64 and macOS/ARM64, the
hourly detector's subset on native Windows/ARM64, the cadenced Python,
extension and plugin legs, the
licenses-and-crates assurance job (which also packages the exact crate
archives), the open-core `classification` check, and the `release preflight`
job, which rehearses the release harness on Linux/x86 against a locally built
release binary: the pinned cargo-about, cargo-zigbuild and Zig install paths,
the glibc-2.28 binary and semantic-pack tool builds, the ELF and MCP
compatibility contracts, the Python client and uv CLI wheels, the sdist, the
agent-plugin, DSH, Pi and npm packaging, and the prepublish Codex and Claude
`list_policies` smoke. A green run means the commit compiles, passes every
test on every platform we ship, classifies every tracked path, and packages
through the release scripts, so `Release readiness` on the public repository
can only fail on platform-specific builds, the offline semantic-pack policy
acceptance, or public-only identity checks. Pick the newest master commit
with a green run as the release base; dispatch the gate by hand when you want
evidence for a commit before the schedule reaches it.

Qualification requires a green per-push CI run and a green `Release gate` run
for the exact RC head, and green `policy-scan-smoke` and `docs` runs when
those ran for it. The latest attempt wins; a newer failed run is a failure,
and an older green run cannot hide it. A scheduled gate run that skipped
because `master` had not moved resolves to the earlier executed run for the
same commit. The checksum sync commit changes only the two launcher
checksum projections, which no Rust leg reads, so it inherits its parent's
gate run and needs only its own CI run; every other RC commit needs a gate
run at its own head. Nothing else gates: quick and full performance and the
repository policy scan are diagnostics, read on their own dashboards and
never consulted by the verifier. An accepted performance regression is a line
in the changelog, not an exception record.

Public projection is manual. Dispatch `prepare-open-core-projection.yml` from
master with the explicit versioned RC branch in `source_ref` and the independently
observed public head. The workflow pins the source SHA, uses qualification tools
from its immutable workflow revision, and rechecks evidence immediately before
pushing. Classification, public builds, readiness, tags, and publication remain
separate gates. A branch name is never proof of qualification.

Rust third-party license HTML is generated rather than committed. Release
workflows generate it automatically. To inspect or package it locally, install
`cargo-about` 0.9.1 and run:

```bash
scripts/public/generate-rust-third-party-notices.sh licenses/THIRD_PARTY_LICENSES.html
```

The generated path is ignored by Git.

The agent plugin manifests also carry release metadata and must be
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
- `plugins/bifrost-agent/package.json`
- `plugins/bifrost-agent/package-lock.json`
- the pinned npm install command in `plugins/bifrost-agent/README.md`
- `plugins/bifrost-agent/bifrost-release.json`
- `docs/src/content/docs/rust-library.md`

The package and README entries keep the published Pi artifact and its install
instructions on the Cargo version. The Codex and Claude marketplace files are
also part of the plugin surface, but
currently do not carry version fields.

The bundled agent plugin pins the preferred, minimum, and prerelease
compatibility fields and the preferred Bifrost release archive checksums:

- `plugins/bifrost-agent/bifrost-release.json`

Those checksum-bearing files must match the actual release archives.
`scripts/public/release-version.mjs sync` only copies the current
`plugins/bifrost-agent/bifrost-release.json` checksums into the retained
release metadata when that metadata is already on the same version as
`Cargo.toml`. The release-readiness workflow prepares checksum metadata from the
built `.sha256` sidecars, validates the plugin manifests, and packages
`bifrost-agent-<tag>.tar.gz`. VSIX packaging and publishing are owned by
[`BrokkAi/bifrost-lsp`](https://github.com/BrokkAi/bifrost-lsp). A separate Pi
package job prepares the same release metadata for the npm tarball, validates
the packed package, and attaches it to the existing GitHub Release. If you
perform those packaging steps manually, run the same script against the release
`dist/` directory instead of hand-editing checksums.

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
2. Select the newest master commit whose `Release gate` run is green and
   create the RC branch from that exact SHA, for example `candidate/v0.8.22-rc`. The branch name carries no username;
   `dave/vX.Y.Z-rc` is still accepted for one release cycle, and the RC
   branch ruleset matches both forms. Do not name an RC `release/...`: the
   workflow security audit (zizmor) treats a `release/` push trigger as a
   publishing trigger and flags every cached job.
   Push the branch. Never merge `master` into it and never commit a fix to
   it. If its gate run is red on a flake, re-dispatch the gate at the same
   head; if the failure reproduces, land the fix on `master` and cherry-pick
   that commit onto the RC.
3. Confirm the tracked projection inventory is complete at that commit. The
   inventory is maintained on `master`; `check-open-core-classification`
   runs in per-push CI and the verifier rechecks it at the RC head. If a
   path is unclassified, classify it on `master` and cherry-pick that commit
   onto the RC. A metadata commit may not touch the projection inventory or
   its policy.
4. On the RC branch, in one commit, bump `[workspace.package].version` in
   `Cargo.toml`, run the version-sync command above, and replace the
   `Unreleased` heading in `CHANGELOG.md` with the release date. Review the
   generated metadata and curated changelog entry. Release workflows generate
   the Rust dependency report from the tagged `Cargo.lock`; it is not
   committed. That push runs CI and `Release gate` for the RC head.
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
   policy_smoke_root="$(mktemp -d "${TMPDIR:-/tmp}/bifrost-policy-pretag.XXXXXX")"
   trap 'rm -rf -- "$policy_smoke_root"' EXIT
   BIFROST_LAUNCHER_CACHE_DIR="$policy_smoke_root/cache" \
     target/release/bifrost \
     --root . \
     --format sarif \
     --output target/release-rc-policy.sarif \
     --fail-on never \
     --policy-pack bifrost.code-smells
   rm -rf -- "$policy_smoke_root"
   trap - EXIT
   ```

   The staged-agent command reproduces the prepublication plugin boundary: it
   packages the portable plugin, extracts it away from the checkout, launches
   that package with the exact optimized binary to be tagged, and exercises
   both Codex metadata and MCP roots workspace binding plus policy discovery
   and execution. Do not substitute the plugin unit tests or manifest checks
   for this end-to-end smoke.

   The policy command is a release-artifact smoke test. Existing findings do
   not fail it. An unreliable scan still exits with status 2 and blocks the
   release. Its verified Bifrost-packs selection and exact receipt match Release
   Readiness, so the absent-member policy has the declaration surface it needs
   to distinguish a clean result from incomplete capability coverage. Missing
   eligible, integrity-verified pack releases block this preparation; do not
   generate a substitute bundle or accept incomplete coverage as a clean scan.
7. Keep the qualified RC head frozen during the public release handoff.
   Open a pull request that lands the metadata commit on `master` through the
   queue. If anything about the candidate must change, land the change on
   `master` and cherry-pick it onto the RC, or recut the RC; a different SHA is
   a different candidate with its own evidence.
8. After the RC branch is frozen and validated, project it to public `master`,
   qualify that public commit, and tag **the qualified public commit in
   `BrokkAi/bifrost`**. The tag does not go on the private RC commit and does
   not go in the private repository: `release.yml` is gated on
   `github.repository == 'BrokkAi/bifrost'`, so a tag pushed there starts
   nothing. The v-tags present in the private repository predate the
   open-core split and are not release tags.

   Do not improvise this step. Follow the numbered handoff under
   [Readiness handoff and recovery](#readiness-handoff-and-recovery),
   which is the authoritative sequence: project, dispatch `Release
   readiness` against the exact public commit while public CI runs, inspect the retained
   qualification bundle, confirm ancestry with
   `scripts/check-build-ancestry.sh`, and only then create the public tag.

   The ancestry check compares the **qualified public commit** against the
   previous release tag's source, so that a higher version label cannot carry
   older source. Comparing the private RC commit answers a different question
   and does not establish that property for what is actually published.

A single `vX.Y.Z` tag starts the **Release** workflow. It resolves the tagged
commit once, then builds and validates CLI archives, crate contents, wheels/sdist,
and agent-plugin packages before opening the promotion gate. The GitHub Release,
crates.io, PyPI, and agent-plugin release assets only run after that common
evidence is green.

Open semantic packs and policy rules are maintained and released in
[`BrokkAi/bifrost-packs`](https://github.com/BrokkAi/bifrost-packs). Submit open
content and generation-recipe changes there. Its `packs/vX.Y.Z` and
`rules/vX.Y.Z` streams have independent versions and machine-readable engine,
schema, capability, and qualification requirements. Engine releases no longer
generate, assemble, or publish native semantic-pack content. They retain the
semantic-pack installer and authoring tooling needed by pack producers.
Engine CI may still generate focused fixtures to test analyzer behavior; that
does not publish a pack release.

Bifrost no longer ships packs built in. Standard-library-style packs belong
in `bifrost-packs`; other packs, including third-party library models,
typically belong in the private premium pack authoring repository. Content
required by WebGoat or another popular open benchmark may have a public home
after an explicit review of the coverage need, rationale and licensing. This
exception does not make all library content public.

Do not author new product content in the engine's legacy pack directories.
Use minimal test-only fixtures for engine regressions and preserve parser,
type/declaration and tooling assets according to their actual role. Run
`node scripts/check-pack-authoring-drift.mjs` in the private engine checkout;
the transitional sources and embedded payloads are frozen until their
dependencies are rewired after verified v0.13.0 release. This cleanup must not
change or block the frozen release candidate.

During v0.13.0 preparation, plugin acquisition must select compatible pack
metadata and verify artifact hashes before exposing a cache to the server.
A pending pack release or a matching version label does not establish runtime
qualification. Offline reuse must retain the exact selected source commit,
manifest, and artifact hashes. The v0.13 core ships without product rules;
repository rule fixtures support regression tests and are excluded from
published crate archives. Hosts own external rule acquisition and activation.
Core qualification records the empty catalog and an explicit not-evaluated
scan separately from requested external-content acceptance. Parser assets and
separate semantic/type/declaration packs retain their existing boundaries.
Legacy authored and embedded semantic content still present in the checkout
is transition debt, not a second authoring stream; its source removal is a
separate post-release migration.

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
run in parallel), then `brokk-bifrost-semantic`, then `brokk-bifrost-store`,
then `brokk-bifrost-analysis`,
then `brokk-bifrost-go-analysis`, `brokk-bifrost-cpp-analysis`, `brokk-bifrost-csharp-analysis`, `brokk-bifrost-php-analysis`, `brokk-bifrost-python-analysis`, `brokk-bifrost-ruby-analysis`, `brokk-bifrost-rust-analysis`, `brokk-bifrost-js-ts-analysis` and `brokk-bifrost-flow` in parallel, then
`brokk-bifrost-tools` and `brokk-bifrost-semantic-packs` in parallel, then
`brokk-bifrost-rql`, then `brokk-bifrost-policy`, then
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
| `brokk-bifrost-semantic` | `crates/bifrost-semantic/Cargo.toml` | 3 |
| `brokk-bifrost-store` | `crates/bifrost-store/Cargo.toml` | 1 |
| `brokk-bifrost-analysis` | `crates/bifrost-analysis/Cargo.toml` | 4 |
| `brokk-bifrost-go-analysis` | `crates/bifrost-go-analysis/Cargo.toml` | 5 |
| `brokk-bifrost-csharp-analysis` | `crates/bifrost-csharp-analysis/Cargo.toml` | 5 |
| `brokk-bifrost-php-analysis` | `crates/bifrost-php-analysis/Cargo.toml` | 5 |
| `brokk-bifrost-cpp-analysis` | `crates/bifrost-cpp-analysis/Cargo.toml` | 5 |
| `brokk-bifrost-python-analysis` | `crates/bifrost-python-analysis/Cargo.toml` | 5 |
| `brokk-bifrost-ruby-analysis` | `crates/bifrost-ruby-analysis/Cargo.toml` | 5 |
| `brokk-bifrost-js-ts-analysis` | `crates/bifrost-js-ts-analysis/Cargo.toml` | 5 |
| `brokk-bifrost-rust-analysis` | `crates/bifrost-rust-analysis/Cargo.toml` | 5 |
| `brokk-bifrost-tools` | `crates/bifrost-tools/Cargo.toml` | 6 |
| `brokk-bifrost-flow` | `crates/bifrost-flow/Cargo.toml` | 5 |
| `brokk-bifrost-rql` | `crates/bifrost-rql/Cargo.toml` | 7 |
| `brokk-bifrost-semantic-packs` | `crates/bifrost-semantic-packs/Cargo.toml` | 7 |
| `brokk-bifrost-policy` | `crates/bifrost-policy/Cargo.toml` | 8 |
| `brokk-bifrost-runtime` | `crates/bifrost-runtime/Cargo.toml` | 9 |
| `brokk-bifrost-mcp` | `crates/bifrost-mcp/Cargo.toml` | 10 |
| `brokk-bifrost` | `Cargo.toml` | 11 |

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

Registry visibility can lag after a successful upload. If the upload succeeded
but the visibility check timed out, confirm that the public artifact has the
expected version and checksum. Then rerun the failed job. Do not upload a
different artifact for the same version.

The npm publication workflow starts only after the parent Release workflow
succeeds. After recovery, confirm both workflows are green. Also confirm the
root npm package and all platform packages expose the released version. The
release summary records completed and pending publication targets.

### Readiness handoff and recovery

Use one explicit handoff from source projection to release publication:

0. Cut the RC branch in the private repository from the newest master commit
   with a green `Release gate` run, add the one metadata commit, and qualify
   the exact RC head before proceeding. Keep that branch as the release line
   throughout the handoff while master development continues. Land the
   version and changelog on master through the queue before cutting, so the
   RC needs no metadata commit of its own: the launcher checksum correction
   in step 4 is a metadata commit, and an RC may carry only one. Public
   projection has no schedule and runs only when explicitly dispatched for
   an RC.
1. Project the release branch's commit to public `master`.
2. Dispatch `Release readiness` from the public repository with the exact
   public commit, release version, and independently observed public head,
   right away: do not wait for the public CI run the projection started.
   Readiness builds while CI tests, and its final bundle job waits for that
   CI run and refuses to assemble a bundle unless it is green. When CI fails
   on a flake, rerun its failed jobs and then readiness's failed job.
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
   the release branch that commit is the tip of, with `dispatch_projection`
   left on. It reads the sidecars from the
   qualification bundle rather than from published release assets, because at
   this point the tag does not exist yet and the release publishes its assets
   out of that same bundle. It corrects the three tracked checksum projections,
   commits them to the release branch, waits for that commit's CI run, projects
   them to public `master`, and adopts that projection's conclusion. The
   correction's CI runs in `checksum` mode (quick policy and the plugin legs,
   a few minutes), its gate push skips the platform legs, and the verifier
   takes the gate and full CI evidence from the parent RC head. Do not
   dispatch it with `dispatch_projection` off to wait for a full RC CI run;
   none will come, and none is needed. A failure here means the corrected
   digests are not public and the tag must wait. The commit is pushed
   fast-forward only, so a release branch that moved under the run fails the
   operation rather than silently rebasing the correction onto a different
   source. Skipping this step is what left `v0.10.3` and `v0.10.4` publishing
   plugins whose committed checksums described the previous release, so a
   fresh marketplace install failed closed with `checksum_mismatch`.
5. Re-qualify the corrected commit. Dispatch `Release readiness` again against
   the new public head with `requalify_from_run` set to the run from step 2,
   without waiting for the public CI run the re-projection started: the
   correction is checksum-only and the source run already required green
   public CI for the built commit.
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
   differs from that public head only under `.github/workflows/`. If
   anything else changed, the proof step fails and a full projection is
   required.
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
