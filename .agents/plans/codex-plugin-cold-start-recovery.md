# Make Codex plugin cold starts verify the published binary

This ExecPlan is a living document. Maintain it according to `.agents/PLANS.md`.

## Purpose / Big Picture

After this work, installing the Bifrost Codex plugin into a clean location and opening a new task will download the exact Bifrost binary release named by the plugin, verify it, start MCP, and expose `search_symbols`, `list_policies`, and `run_policy`. A failed download or verification will report the pinned version, cache path, and recovery commands instead of silently leaving only skills visible.

## Progress

- [x] (2026-07-30 19:21Z) Started from clean `origin/master` commit `ce694ac9` in dedicated branch `dave/fix-codex-plugin-cold-start`.
- [x] (2026-07-30 19:21Z) Reproduced the empty-cache diagnostic state and compared public v0.8.16 checksums with the plugin metadata.
- [ ] Add a Codex-manifest-driven packaged cold-cache smoke and release immutability guard.
- [ ] Correct the stale v0.8.16 release checksum projections and validate download, MCP initialization, tool list, and recovery commands.
- [ ] Run package and policy validation; record outcomes.

## Surprises & Discoveries

- Observation: The public v0.8.16 universal macOS archive has SHA-256 `48ea117f1f6ee391972b771ec41662713c0e07ff9d67af9a58c089589aeb93a1`, while the current plugin metadata names `3fbf9387c0165a7c3816292a41b4b1f358d6a53cf9e9e5b4cb9de037f97fbfe6`.
  Evidence: The public release checksum sidecar and GitHub release asset metadata agree on `48ea...93a1`; an isolated `doctor --json` reports `missing` and `prepare` begins the rejected pinned download.
- Observation: The existing staged-release smoke starts through `claude-mcp.json`, not the Codex manifest and `.mcp.json` requested for this regression.
  Evidence: `scripts/smoke-agent-plugin-release.mjs` resolves `.claude-plugin/plugin.json` in `resolveClaudePluginLauncher`.

## Decision Log

- Decision: Keep the launcher’s metadata checksum verification and correct the projection/release process rather than trusting an unpinned sidecar.
  Rationale: The sidecar alone detects transfer corruption but cannot guarantee that the plugin starts the intended release artifact. The failure is metadata drift caused by mutable/repeated release asset uploads.
  Date/Author: 2026-07-30 / Codex.
- Decision: Drive the new release smoke through `.codex-plugin/plugin.json` and its `mcpServers` file.
  Rationale: It proves the exact Codex package contract that failed in a fresh Codex task, including package-relative command and working-directory resolution.
  Date/Author: 2026-07-30 / Codex.

## Outcomes & Retrospective

Pending implementation and validation.

## Context and Orientation

`plugins/bifrost-agent/bin/bifrost-launcher.mjs` resolves a binary from an isolated cache and downloads a GitHub Release archive when no compatible binary is present. `plugins/bifrost-agent/bifrost-release.json` is the pinned version and SHA-256 map. Codex discovers the launcher through `plugins/bifrost-agent/.codex-plugin/plugin.json`, which points to `plugins/bifrost-agent/.mcp.json`.

`scripts/smoke-agent-plugin-release.mjs` is invoked by `.github/workflows/release.yml` after staging the plugin and after the GitHub Release exists. It currently exercises a recorded Codex handshake but chooses the Claude plugin manifest, so a malformed Codex launch contract can escape the release gate. Release archives are tar or zip files uploaded to the GitHub Release; re-uploading the same asset name can change its bytes and invalidate an already-staged plugin checksum.

## Plan of Work

First, make the staged-agent smoke resolve the Codex manifest and `.mcp.json`, then retain its empty cache, `prepare`, MCP initialize, and `tools/list` assertions. Ensure the smoke reports launcher stderr and the selected manifest/config path when startup fails. Correct all supported v0.8.16 checksum projections from the published release asset digests and regenerate the Amp and VS Code copies through the repository script.

Next, make the release upload refuse to overwrite an existing release asset. This preserves the bytes that the staged plugin metadata verified and makes a recovery release fail loudly instead of mutating an immutable pinned artifact. Add a source-level workflow regression test that asserts this setting and the Codex smoke invocation, so ordinary test runs catch future drift.

## Concrete Steps

Run from `/Users/dave/.codex/worktrees/d502/bifrost`:

    node --test plugins/bifrost-agent/test/*.test.mjs
    node scripts/check-codex-plugin-manifest.mjs
    node scripts/smoke-agent-plugin-release.mjs --plugin-dir <staged-plugin> --cache-dir <empty-cache>

The smoke must emit a successful Codex MCP initialize and a tools list containing `search_symbols`, `list_policies`, and `run_policy`. The launcher’s `doctor --json` must initially report `missing`; `prepare` must report `ready`; a new MCP process must then use the managed cache binary.

## Validation and Acceptance

Acceptance requires a clean packaged plugin location, an initially empty cache, a real download of the public v0.8.16 archive, SHA-256 verification against the pinned metadata, MCP initialize, and `tools/list` containing the three named tools. The smoke must additionally call `list_policies` and `run_policy`, so a visible skill alone cannot be mistaken for a registered MCP server. A deliberately disabled install must leave stdout protocol-clean and print doctor/prepare recovery instructions on stderr.

## Idempotence and Recovery

All validation caches and workspaces use `mkdtemp` locations under `/private/tmp`; never remove the user cache. Re-running `prepare` against a ready isolated cache should reuse the verified managed binary. When a real install fails, run the packaged launcher’s `doctor --json`, then `prepare`, and start a fresh Codex task after success.

## Artifacts and Notes

The public v0.8.16 archive digest evidence is retained in the `Surprises & Discoveries` section. The final validation transcript will record the package path, cache state transition, and MCP tool names.

## Interfaces and Dependencies

The launcher continues to expose `doctor --json`, `prepare [--json]`, and serve mode. The smoke accepts `--plugin-dir <directory>` and `--cache-dir <empty-directory>` and must derive the executable and working directory from the Codex manifest’s `mcpServers` JSON rather than hardcoding a host-specific path. The release action must pass an explicit `overwrite_files: false` setting to prevent a later run from replacing an archive referenced by a prior package.

Plan update (2026-07-30 19:21Z): recorded the published-checksum mismatch and refined the plan to test the Codex manifest rather than the existing Claude-only selection.
