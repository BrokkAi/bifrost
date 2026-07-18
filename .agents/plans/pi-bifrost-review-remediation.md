# Harden and package the Pi Bifrost integration

This ExecPlan is a living document. Maintain `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` in accordance with `.agents/PLANS.md`. This plan and the two earlier Pi ExecPlans are committed implementation history and remain with the review-ready change.

## Purpose / Big Picture

After this work, the Pi package will not start a Bifrost child after its session has shut down, report successful reconfiguration only while the replacement connection remains live, and surface startup failures through Pi in both interactive and noninteractive modes. Persisted settings will be parsed through a schema rather than a hand-written object predicate. The package artifact will contain its license, be install-tested from the actual npm tarball, stay aligned with Cargo version bumps, and be built before the GitHub release becomes public.

## Progress

- [x] (2026-07-18 00:00Z) Triaged automated and independent review findings with the user; collision checks and a manifest-checker rename were explicitly rejected.
- [x] (2026-07-18 00:05Z) Re-read the session, settings, adapter, tests, CI, release workflow, package metadata, and repository planning rules.
- [x] (2026-07-18 01:05Z) Refactored the Pi session lifecycle around explicit state and structured errors; shutdown and replacement revalidation tests now pass.
- [x] (2026-07-18 01:05Z) Replaced hand-written settings shape checks with TypeBox parsing and removed unsupported Semantic Search configuration.
- [x] (2026-07-18 01:05Z) Adopted MCP SDK protocol types, refreshed schemas on reconnect, and required complete capability tool sets while accepting the server's location/reference render alternatives.
- [x] (2026-07-18 01:40Z) Repaired version synchronization, licensing, packed-install validation, and release job sequencing.
- [x] (2026-07-18 03:45Z) Updated public and maintainer documentation, removed the standalone HTML explainer, retained all ExecPlans, and completed comprehensive package, workflow, AST-rule, and real-Pi validation.

## Surprises & Discoveries

- Observation: The repository's local AST rules ban both the exact `isRecord(unknown)` predicate and the exact generic `formatError(unknown)` helper used by the Pi extension.
  Evidence: `/home/josh/projects/joshuadavidthomas/ast-grep-rules/rules/typescript-no-hand-rolled-object-type-guard.yml` and `typescript-no-generic-error-message-helper.yml` classify those patterns as errors.

- Observation: The pinned MCP SDK exports `Tool` and `CallToolResult`, so local protocol interface copies are unnecessary.
  Evidence: `plugins/bifrost-agent/node_modules/@modelcontextprotocol/sdk/dist/esm/types.d.ts` exports both inferred types.

- Observation: The previous release workflow published binary assets before downstream editor and Pi package checks.
  Evidence: Before remediation, `.github/workflows/release.yml` made the combined `vscode` job depend on `release`. The final workflow makes `release` depend on separate `vscode-package` and `agent-package` jobs.

- Observation: Pi's `registerTool` replaces an existing same-name registration, which lets reconnect discovery refresh MCP descriptions and schemas without a parallel registry.
  Evidence: The focused reconnect test records two registrations of `bifrost_search_symbols` and observes the second description through Pi's current tool map.

- Observation: The symbol server advertises two complete render variants rather than every location/reference tool at once.
  Evidence: `src/mcp_core.rs::symbol_tool_descriptors` selects location-based scan, definition, and type tools when line-number rendering is enabled, or reference-based scan and definition tools otherwise. Capability validation now models those variants declaratively.

- Observation: MCP SDK initialization failure starts asynchronous cleanup without awaiting it.
  Evidence: `Client.connect()` calls `void this.close()` in its initialization catch. `AwaitableCloseClient` captures that promise so session cleanup can await the same child teardown; the failed-initialization process test proves the child is gone when close returns.

## Decision Log

- Decision: Remove the namespaced collision policy rather than preserving a speculative guard.
  Rationale: The user considers another extension deliberately claiming a `bifrost_*` name unrealistic, and Pi already defines replacement-by-name behavior.
  Date/Author: 2026-07-18 / user and Pi agent.

- Decision: Keep `scripts/check-codex-plugin-manifest.mjs` and its existing name.
  Rationale: It already validates the shared Codex, Claude, Cursor, Amp, and release projections; Pi belongs with that shared validation.
  Date/Author: 2026-07-18 / user and Pi agent.

- Decision: Remove Semantic Search from the shipped Pi capability registry.
  Rationale: Release binaries are built without the `nlp` Cargo feature, so the package must not advertise a setting its normal binary cannot provide. Supporting custom NLP binaries is not a reason to expose a broken default capability.
  Date/Author: 2026-07-18 / Pi agent.

- Decision: Keep the npm tarball release artifact and make it production-ready.
  Rationale: The package artifact is useful when it contains license notices and is validated through its installed shape; removing it would defer rather than solve the publication boundary.
  Date/Author: 2026-07-18 / Pi agent.

- Decision: Keep all Pi ExecPlans in the review-ready change.
  Rationale: The repository commits its implementation plans, and the user wants the change to show its design and execution history. Only the standalone HTML explainer was pre-PR presentation material, so it was removed.
  Date/Author: 2026-07-18 / user and Pi agent.

## Outcomes & Retrospective

The remediation is complete. Session shutdown clears workspace authority before awaiting cleanup, waits for every child close already in flight, invalidates stale selections, and reports replacement success only while that client remains live. Operation failures have one reporting owner, retain structured causes, and use Pi-native UI or headless extension paths. Settings use TypeBox parsing, discovered MCP schemas refresh on reconnect, and capability validation requires complete server-supported tool variants without advertising unavailable semantic search.

The npm artifact now contains exact license/source notices and passes a clean installed-package discovery smoke. Version synchronization covers the Pi manifest, lockfile, and pinned README command. Separate VS Code and agent package jobs gate one final GitHub release, with marketplace publication afterward. Fresh validation passed 68 Node tests, TypeScript/package checks, clean `npm ci`, packed install, `npm audit`, pack/publish dry runs, workflow lint, shared manifest/version checks, the user's AST rules, and a real Pi `bifrost_get_summaries` call returning `src/mcp_common.rs`. No Bifrost child from the smoke remained alive.

## Context and Orientation

`plugins/bifrost-agent/extensions/bifrost-session.ts` owns one MCP child per Pi session, dynamic tool registration, active-tool selection, replacement connections, and shutdown. `plugins/bifrost-agent/extensions/bifrost.ts` adapts Pi lifecycle events and the `/bifrost` TUI to that controller. `plugins/bifrost-agent/extensions/bifrost-settings.ts` stores one JSON file per canonical workspace. `plugins/bifrost-agent/extensions/mcp-adapter.ts` translates MCP schemas and results into Pi tool definitions.

The npm package is declared in `plugins/bifrost-agent/package.json`. `plugins/bifrost-agent/test/package-contents.mjs` inspects `npm pack`, while `.github/workflows/ci.yml` runs package validation. `.github/workflows/release.yml` builds binaries, prepares release-specific checksum metadata, packages the VS Code extension and agent distributions, and publishes release assets. `scripts/sync-release-version.mjs` projects the Cargo version into host package manifests.

## Plan of Work

First, change the session controller's failure contract from strings to `Error` objects that retain causes. Put lifecycle data in one explicit state record and make shutdown clear the workspace before awaiting cleanup. Reconfiguration must use a generation ticket and confirm that the replacement remains the active connected client after the old client closes. Discovered tools must be registered again by name so Pi receives current schemas, while the owned-name set remains solely for active-tool reconciliation.

Second, define a TypeBox schema for the persisted settings envelope and parse unknown JSON through TypeBox's `Parse` function. Retain explicit validation for capability membership so unknown IDs produce a focused settings error. Remove the Semantic Search capability and every claim or test that says the normal package exposes it.

Third, import MCP `Tool` and `CallToolResult` types from the SDK. Keep the adapter because it performs real protocol-to-host translation. Remove duplicated namespace prose, host-internal full-result claims, and full descriptions as prompt snippets. Capability validation will list every missing requirement from the selected groups while treating location- and reference-rendered symbol tools as declared alternatives.

Fourth, add the npm package and lockfile to `scripts/sync-release-version.mjs`, include LGPL/source notice files in the npm tarball, and extend package checks to assert them. Add a CI smoke that packs the package, installs the tarball in a clean temporary package, and asks Pi to discover the extension and skills without launching Bifrost. Split release preparation into validation/package jobs that depend on binary builds, then make the final release job depend on those packaged artifacts so no public release is created before Pi and VS Code checks pass.

Finally, update README and maintainer documentation, remove only the standalone implementation explainer, retain all three Pi ExecPlans, run TypeScript checks and Node tests, run package and manifest checks, inspect the final diff, and ask independent reviewers to check lifecycle and release seams.

## Concrete Steps

Run commands from `/home/josh/projects/BrokkAi/bifrost` unless a working directory is stated.

1. Edit the four Pi extension modules and their focused Node tests.
2. Run `npm run check` and `npm test` from `plugins/bifrost-agent`.
3. Edit package metadata, synchronization, CI, release workflow, and documentation.
4. Run `node scripts/sync-release-version.mjs --check`, `node scripts/check-codex-plugin-manifest.mjs`, and the package dry-run checks.
5. Run a clean `npm ci`, the full package tests, and a real Pi discovery smoke from the packed tarball.
6. Remove the standalone HTML explainer, inspect `jj diff --stat`, and confirm `jj st` contains only intended files.

## Validation and Acceptance

The session tests must prove that shutdown clears the workspace and prevents a later settings rollback from reconnecting. Another test must close the replacement while old-client cleanup is pending and observe a failed application rather than persisted success. Extension tests must prove that a failed `session_start` throws in headless mode but reports through `ctx.ui.notify` in TUI mode.

Settings tests must reject arrays, null, malformed JSON, incorrect versions, extra fields, wrong workspaces, and unknown capability IDs through the schema boundary. Capability tests must no longer advertise Semantic Search and must require every declared tool requirement for a selected capability, including coverage for location/reference alternatives.

The npm package must include `LICENSE.md`, `GPL-3.0.md`, and `SOURCE.md`. CI and local validation must install the produced `.tgz` into a clean temporary package and prove Pi can load the extension and exactly the three canonical skills. The release workflow must have no publication step upstream of Pi and VS Code package validation.

## Idempotence and Recovery

All code and metadata edits are ordinary source changes. Session cleanup remains idempotent through `closeOnce`. Package smoke tests must use an operating-system temporary directory and remove temporary files through tracked process cleanup and a `finally` block. If release workflow restructuring fails validation, retain artifact names and restore only dependency edges rather than changing public artifact naming.

## Artifacts and Notes

The final review-ready diff does not include `.agents/docs/pi-bifrost-implementation-explainer.html`. It retains `.agents/plans/pi-bifrost-package.md`, `.agents/plans/pi-bifrost-tool-configuration.md`, and this remediation plan as implementation history.

## Interfaces and Dependencies

`BifrostSessionDependencies.reportError` and `BifrostSessionController.setErrorHandler` will accept `Error`, not string. `BifrostSessionStatus.error` will be `Error | undefined`. Unknown dependency failures will be wrapped with operation-specific `Error` objects using `{ cause }`.

`BifrostSessionClient.listTools` will return the MCP SDK's `Tool[]`; `callTool` will return `CallToolResult`. `mcp-adapter.ts` will export only Pi-specific result details and mapper functions.

`parseSettingsDocument(source, expectedWorkspace?)` continues returning the internal `BifrostSettingsDocument`, but raw `JSON.parse` output passes through a TypeBox schema before field access.

Revision note (2026-07-18): Completed review remediation and updated this living plan with final lifecycle, package, publication, documentation, and validation evidence. The user chose to retain all ExecPlans as implementation history while removing only the standalone HTML explainer.
