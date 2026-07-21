# Verify released plugin archive metadata

This ExecPlan is a living document. Maintain it according to `.agents/PLANS.md`.

## Purpose / Big Picture

Codex, Claude Code, Cursor, and Amp install Bifrost through a launcher that downloads a pinned release archive. The launcher must accept the real release checksum before it can start MCP and expose code-intelligence tools. This work corrects the v0.8.6 macOS checksum and adds a verification command that compares committed plugin metadata with the published release sidecars.

## Progress

- [x] (2026-07-21 11:40Z) Reproduced the Codex MCP startup failure and found the macOS checksum sidecar differs from committed metadata.
- [x] (2026-07-21 12:05Z) Corrected the canonical macOS checksum and regenerated the Amp bundle.
- [x] (2026-07-21 12:07Z) Ran manifest and launcher tests, then prepared v0.8.6 successfully in the normal host environment.
- [x] (2026-07-21 12:09Z) Initialized the corrected MCP server and confirmed it advertises the `symbol|extended` toolset; `get_summaries` returned the `SearchToolsService` outline from this checkout.
- [x] (2026-07-21 12:12Z) Found that a clean Codex reinstall retained `./bin/bifrost-launcher.mjs` but launched it from the workspace, producing `No such file or directory` before MCP initialization.
- [ ] Add the plugin-package working directory, reinstall again, and confirm a fresh Codex task injects the advertised Bifrost tools.

## Surprises & Discoveries

- Observation: The release workflow generates correct metadata in its temporary VS Code packaging checkout, but does not persist that generated file to the marketplace source tree.
  Evidence: `scripts/prepare-vscode-extension-manifest.mjs` writes the metadata after checkout; the repository's `plugins/bifrost-agent/bifrost-release.json` contained a different macOS hash.

## Decision Log

- Decision: Treat the committed plugin metadata as the marketplace source of truth and verify it against release sidecars with an explicit networked script.
  Rationale: The launcher must retain an independently committed checksum rather than trusting the archive and sidecar fetched from the same release at runtime.
  Date/Author: 2026-07-21 / Codex

## Outcomes & Retrospective

The v0.8.6 macOS archive can now be downloaded, checksum-verified, and launched. A clean Codex reinstall additionally revealed that the shared MCP config needs to declare the plugin package as its working directory; otherwise Codex resolves the relative launcher command from the workspace.

## Context and Orientation

`plugins/bifrost-agent/bifrost-release.json` supplies the release version and SHA-256 archive hashes used by `plugins/bifrost-agent/bin/bifrost-launcher.mjs`. `scripts/generate-amp-skill-bundle.mjs` copies that file into the generated Amp bundle. A release sidecar is the small `.sha256` file published beside each archive on GitHub; it states the digest that the launcher expects.

## Plan of Work

Update the canonical macOS release checksum using the published v0.8.6 sidecar, then regenerate the derived Amp artifact. Declare the plugin package working directory in the shared MCP config so the relative launcher command resolves correctly after a clean Codex install. Run the manifest and launcher tests, perform a normal-host preparation plus MCP handshake, and reinstall from the local checkout before expecting a new Codex task to advertise the corrected server.

## Concrete Steps

From the repository root, run:

    node scripts/generate-amp-skill-bundle.mjs
    node scripts/check-codex-plugin-manifest.mjs
    node --test plugins/bifrost-agent/test/launcher.test.mjs
    node plugins/bifrost-agent/bin/bifrost-launcher.mjs prepare --json

`prepare` should return JSON with `status` equal to `ready` and then a fresh Codex task should list Bifrost MCP tools.

## Validation and Acceptance

Acceptance requires the generated Amp release metadata to match the canonical file, all manifest and launcher tests to pass, and a normal-host launcher preparation to install or reuse Bifrost v0.8.6. After reinstalling the local plugin, a newly created Codex task must expose and successfully call `search_symbols` in this repository.

## Idempotence and Recovery

The generator and verifier are repeatable. If preparation is interrupted, rerun it; the launcher removes incomplete downloads and validates an existing managed binary before reuse. If a release sidecar changes unexpectedly, do not overwrite metadata blindly: investigate the release artifact before updating the committed pin.

## Artifacts and Notes

The failing sidecar comparison was:

    expected: 8d47d1d7603bf190ed11467ce91688bfc42d88321cc2ff0ce550530ad91e3dc1
    published: 4180aa87c76f4ddf3889b67ee5cddbf20e758c71c32b814c6a4230e421ba41fd

## Interfaces and Dependencies

The launcher already verifies the committed hash against both the published sidecar and the downloaded archive. The host `prepare` smoke is the end-to-end proof of this contract for the release being repaired.

Revision note (2026-07-21): Updated after the first clean reinstall showed that Codex launched the relative command from the workspace. The plan now records the package working-directory requirement and repeats the fresh-session validation.
