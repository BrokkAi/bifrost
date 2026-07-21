# Persist generated agent-plugin release metadata

## Purpose

The agent plugin downloads a Bifrost release binary using checksums in
`plugins/bifrost-agent/bifrost-release.json`. Before this work, the release
workflow calculated correct checksums while packaging the plugin but discarded
the checkout afterwards. Marketplace installs could therefore receive stale
metadata and reject a valid release archive before MCP tools started.

After this change, every tagged release verifies its packaged macOS plugin from
a cold cache and then synchronizes the generated metadata to `master` only
when `master` still declares the released Cargo version. A version mismatch is
an intentional failed release check, not a partial update.

## Progress

- [x] Identify the release-only metadata boundary in the `vscode` job.
- [x] Add the packaged macOS launcher and MCP smoke.
- [x] Add the guarded metadata synchronization job.
- [x] Document the publish-time safety boundary and validate the changed scripts.

## Design

The `vscode` job remains the release packaging source of truth. It downloads
the build artifacts and invokes `scripts/prepare-vscode-extension-manifest.mjs`,
which reads their `.sha256` sidecars. The new macOS job waits for that job to
publish `bifrost-agent-<tag>.tar.gz`, downloads that public release asset, and
extracts it outside the checkout. `scripts/smoke-agent-plugin-release.mjs` runs
the extracted launcher with a unique empty cache, checks `prepare --json`, and
performs MCP `initialize` plus `tools/list`. Success requires
`search_symbols` in the advertised tools.

The metadata job checks out `master`, compares the Cargo version with the
release tag, and fails before writing if they differ. It downloads the same
build artifacts, reruns the existing preparation script for the canonical
plugin metadata, regenerates the Amp bundle, and validates manifests. It
permits a diff only in the canonical metadata file and the generated Amp copy.
When those files changed, it commits and pushes exactly them; when they did
not, it exits successfully without a commit.

## Validation

Run from the repository root:

    node --check scripts/smoke-agent-plugin-release.mjs
    node --test plugins/bifrost-agent/test/launcher.test.mjs
    node scripts/generate-amp-skill-bundle.mjs
    node scripts/check-codex-plugin-manifest.mjs

For a published release on macOS, download and extract the matching agent
plugin archive, then run:

    node scripts/smoke-agent-plugin-release.mjs \
      --plugin-dir /tmp/bifrost-agent \
      --workspace "$PWD" \
      --cache-dir /tmp/bifrost-agent-cold-cache

The command must report that the packaged plugin prepared and advertised
`search_symbols`. The release workflow is additionally reviewed to ensure a
Cargo/tag mismatch exits before `git add` or `git push`, and that only the two
generated metadata files can be committed.

## Decision log

- 2026-07-21: A `master` Cargo/tag mismatch is a hard failure. Skipping would
  leave marketplace metadata stale without an actionable release signal.
- 2026-07-21: The smoke forces automatic installation while disabling explicit
  and PATH binaries, so a passing result proves the packaged release metadata
  can install the released macOS binary into an empty managed cache.
