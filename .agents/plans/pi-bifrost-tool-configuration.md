# Make the Pi Bifrost tool surface namespaced and configurable

This ExecPlan is a living document. Maintain `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` in accordance with `.agents/PLANS.md`.

## Purpose / Big Picture

After this Pi-package-only change, users can open `/bifrost` and choose which Bifrost capabilities Pi presents to the model. Pi-visible tools use collision-safe names such as `bifrost_query_code`; calls still use canonical MCP names such as `query_code`. A short Pi-only system-prompt note explains that mapping, so the shared skills remain unchanged.

The implementation must not alter Bifrost's Rust server, registry, or CLI. It consumes the server's existing `symbol`, `extended`, `text`, `slopcop`, and `nlp` toolsets. Within the broad existing `extended` set, the Pi package groups tools into query, files, Git, and transforms for presentation and activation. That grouping is Pi host policy, not a new Bifrost protocol contract.

## Progress

- [x] (2026-07-17 20:44Z) Reviewed Pi's `SettingsList`, active-tool, system-prompt, session, and custom TUI APIs.
- [x] (2026-07-17 21:08Z) Reverted an over-broad attempted Rust registry refactor after the user clarified that Rust changes are outside this task.
- [x] (2026-07-17 21:15Z) Namespaced Pi tools while preserving canonical MCP names for protocol calls.
- [x] (2026-07-17 21:15Z) Added one Pi-local capability registry over the existing MCP toolsets, with symbols, query, and files enabled by default.
- [x] (2026-07-17 21:25Z) Added transactional selection reconciliation and independent, atomic per-workspace persistence under Pi's agent directory.
- [x] (2026-07-17 21:20Z) Replaced the status-only `/bifrost` command with a SettingsList TUI and added the concise namespace/workspace prompt clarification.
- [x] (2026-07-17 21:31Z) Added focused namespace, activation, restart, race, rollback, persistence, prompt, and settings tests; all 55 Node tests pass.
- [x] (2026-07-17 21:31Z) Updated Pi package and maintainer documentation; package checks, clean install, manifest validation, npm audit, pack dry-run, and publish dry-run pass. A model-driven real-Pi smoke was attempted but explicitly denied, so it was not retried.

## Surprises & Discoveries

- Observation: Pi can register discovered tools once and independently control which are model-visible with `pi.setActiveTools()`.
  Evidence: Pi documents `getActiveTools`, `getAllTools`, and `setActiveTools`; `examples/extensions/tools.ts` uses `SettingsList` for this exact interaction model.

- Observation: Bifrost's existing `extended` set mixes query, files, Git, and transform tools, so a Pi-only implementation must classify those advertised names if it wants separate TUI controls.
  Evidence: `src/mcp_extended.rs::extended_tool_descriptors` advertises all twelve together. This plan deliberately leaves that Rust code unchanged.

- Observation: Enabling `text`, `slopcop`, or `nlp` after startup requires reconnecting because those descriptors are absent unless their existing server toolset is requested.
  Evidence: The MCP descriptor list is fixed by the launcher's `--mcp` expression and discovered once with `tools/list`.

## Decision Log

- Decision: Make no Rust changes.
  Rationale: The user explicitly scoped this follow-up to the Pi integration. The attempted registry refactor was reverted immediately.
  Date/Author: 2026-07-17 / Pi agent, confirmed by user.

- Decision: Prefix every Pi-visible tool with `bifrost_`, retaining its canonical MCP name in the execution closure.
  Rationale: Generic names such as `jq` and `list_files` can collide. One consistent prefix is predictable.
  Date/Author: 2026-07-17 / Pi agent, confirmed by user.

- Decision: Keep shared skills unchanged and inject one concise Pi-specific namespace rule through `before_agent_start`.
  Rationale: The extension owns host rendering; duplicating skills would create drift.
  Date/Author: 2026-07-17 / Pi agent, confirmed by user.

- Decision: Configure capabilities in the `/bifrost` TUI, not through CLI flags.
  Rationale: This matches Pi's `/settings` interaction and is discoverable after installation.
  Date/Author: 2026-07-17 / Pi agent, confirmed by user.

- Decision: Persist each canonical workspace selection in its own Bifrost-owned file under Pi's agent directory.
  Rationale: Settings survive new sessions without modifying the analyzed repository. Independent files avoid cross-workspace lost updates between concurrent Pi processes, while one scope avoids precedence complexity.
  Date/Author: 2026-07-17 / Pi agent, confirmed by user.

## Outcomes & Retrospective

The Pi-only implementation is complete. Pi tools are consistently namespaced, the shared skills remain unchanged, `/bifrost` provides the requested settings-style TUI, and selections persist safely per workspace. Reconfiguration keeps the old connection usable until a replacement succeeds, rolls back when persistence fails, and handles shutdown/start races without resurrecting stale children. The cost is a small Pi-local classification of `extended` tool names, but that classification directly expresses the host's activation UI rather than pretending to be Bifrost's canonical registry. No Rust or canonical-skill files changed.

## Context and Orientation

The Pi package is `plugins/bifrost-agent`. `extensions/bifrost.ts` wires lifecycle events, the `/bifrost` SettingsList, persistence, and the prompt clarification. `extensions/bifrost-session.ts` derives an existing Bifrost server expression from the selected capabilities, discovers tools, registers namespaced Pi names, forwards canonical MCP names, reconciles active tools, and owns transactional cleanup. `extensions/mcp-adapter.ts` maps schemas and results.

The Pi capability groups are `symbols`, `query`, `files`, `quality`, `git`, `text`, `transforms`, and `semantic`. The default is `symbols`, `query`, and `files`. `symbols` maps to Bifrost's existing `symbol` server toolset. Query, files, Git, and transforms classify names from `extended`. Quality, text, and semantic map to existing `slopcop`, `text`, and `nlp` server toolsets. Workspace management is never requested or shown.

The server expression is derived from enabled capabilities. It always deduplicates toolsets. Query, files, Git, or transforms require `extended`; quality requires `slopcop`; text requires `text`; semantic requires `nlp`. The session registers every tool discovered from the selected server expression but activates only those allowed by the selected capabilities. Unrelated active Pi tools remain untouched.

## Plan of Work

Add a small TypeScript capability module under `plugins/bifrost-agent/extensions`. It defines the closed capability set, labels, descriptions, defaults, mappings from existing MCP names to capabilities, and the server expression builder. Keeping this in one module avoids scattering private name lists.

Refactor `extensions/bifrost-session.ts` so registration uses `bifrost_<canonical-name>`. Track canonical and Pi names separately. Start and apply-selection operations accept capabilities, reconnect when the required server expression changes, register newly discovered tools, and reconcile only Bifrost-owned names in `pi.setActiveTools`. A no-op selection must not reconnect.

Add a settings store module. Use Pi's exported `getAgentDir()` by default, hash each canonical absolute workspace path into an independent filename, store the canonical path inside a versioned JSON document, and use atomic sibling-file replacement. Tests inject a temporary directory. Malformed settings produce a concise error and use defaults; an explicit valid selection replaces the malformed workspace file.

Update `extensions/bifrost.ts` to load settings before session startup, register a SettingsList-based `/bifrost`, save only after a successful apply, and inject the short namespace/fixed-workspace note through `before_agent_start`. Non-TUI invocation of `/bifrost` reports that TUI mode is required.

Update tests and README. Do not modify canonical skills, generated skill bundles, Rust files, or Bifrost's server registry.

## Concrete Steps

Run focused package checks from the repository root:

    cd plugins/bifrost-agent && npm run check && npm test

Validate generated/shared package metadata:

    node scripts/check-codex-plugin-manifest.mjs
    cd plugins/bifrost-agent && npm pack --dry-run

Use the existing reusable Cargo target only for the repository-required unchanged-Rust gates if needed. Do not invoke isolated-target cleanup and do not edit Rust.

For real-host validation, build or reuse `target/debug/bifrost`, start Pi with `BIFROST_BINARY_PATH`, verify default namespaced calls, open `/bifrost`, enable quality and disable transforms, and start a second session in the same workspace to prove persistence.

## Validation and Acceptance

Pi advertises `bifrost_search_symbols` and `bifrost_query_code`, not raw names. A call to `bifrost_query_code` sends `query_code` over MCP. The default active set includes only symbols, query, and files among Bifrost-owned tools. Git, transforms, quality, text, and semantic are inactive.

`/bifrost` displays connection state, fixed workspace, and settings rows. Toggling a capability applies without disturbing built-in or third-party Pi tools. Enabling a capability whose server toolset was not connected restarts Bifrost, discovers and registers it, and activates it. Disabling a capability removes its tools from the active set. Reopening the command reflects current state. A new session in the same canonical workspace restores the saved selection; a different workspace uses defaults.

The system prompt contains one namespace mapping and fixed-workspace clarification only when Bifrost has active tools. Canonical skills remain byte-for-byte unchanged. Shutdown and failed restarts leak no child processes and do not persist a failed selection.

All TypeScript checks, Node tests, package checks, manifest validation, npm pack inspection, and real Pi smokes pass. The final diff contains no Rust changes.

## Idempotence and Recovery

Reapplying the same selection avoids reconnecting but restores the configured Bifrost active-tool set if another Pi UI changed it. Registered tools remain registered but inactive when deselected because Pi has no unregister API. Settings use one file per canonical workspace and atomic temporary-sibling replacement. A failed selection keeps the previous saved selection and closes any partial child. A failed save rolls the runtime selection back. The extension kills only the child it created through the MCP SDK.

## Artifacts and Notes

The original package implementation is commit `2380835a`. The review explainer is `.agents/docs/pi-bifrost-implementation-explainer.html`; its fixed-surface and unprefixed-name sections become historical after this follow-up.

The prompt addition is intentionally short:

    Bifrost MCP tools are namespaced as bifrost_<name> in Pi. When a Bifrost skill refers to query_code, for example, call bifrost_query_code. Bifrost is fixed to the current Pi workspace; do not activate another workspace.

## Interfaces and Dependencies

The controller exposes startup, selection application, shutdown, and status. Status includes workspace, connection state, selected capabilities, active namespaced tool count, and an optional error.

The persistence module exposes load and save operations parameterized by workspace. Its dependencies are injectable so tests never touch the real agent directory.

The TUI uses `SettingsList` and `getSettingsListTheme` from Pi's supported APIs. It must not build a custom toggle widget.

Revision note (2026-07-17): Rewrote the plan after reverting the out-of-scope Rust registry work. The implementation is now strictly confined to the Pi package and its documentation/tests.

Revision note (2026-07-17 21:23Z): Recorded review-driven lifecycle and persistence hardening: transactional old-client use, stale-start protection, same-selection reconciliation, save rollback, corrupt-file repair, and independent per-workspace files.

Revision note (2026-07-17 21:31Z): Marked implementation and automated validation complete after 55 passing tests and a no-blocker final review cycle. Recorded that the denied model-driven Pi smoke was not retried.
