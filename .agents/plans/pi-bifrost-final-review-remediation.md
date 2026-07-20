# Finish the Pi Bifrost lifecycle and release remediation

This ExecPlan is a living document. Maintain `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` in accordance with `.agents/PLANS.md`.

## Purpose / Big Picture

After this change, Pi users can keep their intended Bifrost capability settings through startup failures, trust `/bifrost` to show the live connection state, and rely on Pi command-line tool filters without receiving prompts for unavailable Bifrost tools. Session replacement and shutdown will move through consistent states owned by one session object, including all child-process ledgers and Pi tool effects. Headless settings failures will stop startup with a diagnostic rather than silently enabling defaults. A future release can prepare and attach the Pi npm package without changing the existing GitHub or VS Code release sequence.

## Progress

- [x] (2026-07-18 04:56Z) Reproduced the final review findings from source and Pi’s pinned runtime implementation.
- [x] (2026-07-18 05:35Z) Replaced the passive lifecycle record and captured orchestration closures with one transition-owning session implementation.
- [x] (2026-07-18 06:20Z) Added lifecycle, desired-selection, host-filter, same-toolset, stale-error, restart-midpoint, candidate-ownership, and cleanup-retry regression tests.
- [x] (2026-07-18 06:05Z) Made settings startup failures fail closed in modes without a UI context and kept the `/bifrost` header live on every render and asynchronous outcome.
- [x] (2026-07-18 05:45Z) Repaired release checksum projection for the Pi package.
- [x] (2026-07-18) Removed the synthetic cross-host workflow regression and restored the pre-existing GitHub and VS Code release sequence after a scope audit.
- [x] (2026-07-18 06:35Z) Completed package, repository, artifact, real-Pi, process-leak, AST-rule, workflow, and independent-review validation.
- [x] (2026-07-20) Addressed maintainer review: aligned cross-toolset capability requirements with the Rust registry, made process and package tests portable, and expanded Pi package CI to Linux, macOS, and Windows.
- [x] (2026-07-20) Sanitized MCP- and model-controlled terminal content before trusted Pi theme styling while preserving raw oversized diagnostics in overflow files.

## Surprises & Discoveries

- Observation: Pi filters dynamically registered tools in its internal registry, and `setActiveTools` silently ignores names absent from that registry.
  Evidence: the pinned Pi `AgentSession._refreshToolRegistry` filters registered tools before rebuilding `_toolRegistry`, while `setActiveToolsByName` retains only names found in that registry. The extension must read `getActiveTools()` after setting the requested list.

- Observation: Preparing both Pi and VS Code projections in the Pi package job couples an otherwise Pi-only change to editor release policy.
  Evidence: `scripts/prepare-vscode-extension-manifest.mjs` accepts `--plugin-release` independently, so the dedicated Pi job can prepare only its package sidecar while the existing VS Code job retains its previous behavior.

- Observation: Same-server capability changes still need discovery validation.
  Evidence: query, files, Git, and transforms share the `extended` server expression. A regression now starts a query-only advertised surface, attempts to enable transforms, and observes failure because `jq` is absent without reconnecting or changing the saved selection.

- Observation: Publishing a replacement before old-client cleanup allowed a newer operation to adopt a candidate that its stale owner could later close.
  Evidence: the final implementation keeps the candidate owned but unpublished, withdraws Pi tools while retiring the old client, and publishes only after cleanup, generation, and liveness checks. Deferred-cleanup tests cover stale adoption and concurrent shutdown.

- Observation: A weak close-promise cache cannot prove shutdown after a rejected close.
  Evidence: `ownedClients` now retains every client strongly until cleanup fulfills; rejected attempts clear only their promise identity, and a later shutdown retries. The cleanup-retry test rejects once and then proves the second shutdown closes the same client.

- Observation: The configured `claude-agent-sdk` model rejected one Bifrost schema with a top-level union, while Pi’s `openai-codex/gpt-5.4-mini` path accepted the same registered tools.
  Evidence: the first real smoke failed before a tool call with an API schema error. The fresh accepted-provider smoke called `bifrost_get_summaries`, returned `BifrostSession — plugins/bifrost-agent/extensions/bifrost-session.ts`, exited zero, and left the pre-existing Bifrost process list unchanged.

- Observation: Capability-derived fake MCP advertisements can repeat a declaration error instead of catching it.
  Evidence: Symbols required `analyze_commit` while requesting only the `symbol` server toolset, and the old test fixture invented the same impossible advertisement. Independent Symbol, Slopcop, and Extended fixtures now make the default startup test exercise the real registry boundary.

## Decision Log

- Decision: Represent session state as a desired capability selection plus a discriminated published connection, with candidate and cleanup resources owned separately by the same session object.
  Rationale: Transactional reconnects deliberately keep the old published connection usable while a candidate starts. One flat `connection` enum cannot represent both facts without invalid combinations.
  Date/Author: 2026-07-18 / Pi agent.

- Decision: Keep the SDK client subclass and add an adjacent explanation instead of replacing it.
  Rationale: MCP SDK initialization starts `close()` without awaiting it; capturing the virtual call’s promise is necessary for process-safe cleanup and is covered by a real child-process test.
  Date/Author: 2026-07-18 / Pi agent.

- Decision: Fail closed when persisted settings cannot be read.
  Rationale: Headless startup must throw through Pi’s extension path, and interactive startup must notify and leave Bifrost disabled rather than silently broadening a user’s configured tool surface.
  Date/Author: 2026-07-18 / Pi agent.

- Decision: Keep Pi release packaging independent from the existing VS Code and GitHub release sequence.
  Rationale: The Pi job needs only its own checksum sidecar, package gates, npm tarball, and release attachment. Reordering existing host publication is unrelated to issue #835.
  Date/Author: 2026-07-18 / user and Pi agent.

- Decision: Let one Pi capability request multiple server toolsets while retaining capability-based activation.
  Rationale: `analyze_commit` belongs to the Rust `slopcop` registry but is part of Pi's default Symbols capability. Declaring both `symbol` and `slopcop` models that boundary without changing Rust or activating unrelated quality tools.
  Date/Author: 2026-07-20 / Pi agent after maintainer review.

- Decision: Sanitize untrusted terminal text with Node's built-in VT-control remover plus visible escaping for residual controls, before applying Pi theme styling.
  Rationale: OSC, CSI, C0, and C1 handling is a terminal boundary concern. The standard-library implementation avoids another package dependency, while raw complete diagnostics remain available only in overflow files.
  Date/Author: 2026-07-20 / Pi agent after security review.

## Outcomes & Retrospective

The final remediation is complete. `BifrostSession` now owns desired configuration, a discriminated published connection, generation authority, every launched client, candidate liveness, close identity, registered Pi names, active-tool effects, and tool dispatch. Replacement candidates remain unpublished until old-client cleanup commits. Rejected cleanup remains strongly owned and retryable, and shutdown cannot report success while any owned client close fails. Every asynchronous failure publication is generation-guarded.

Startup failure retains the saved desired capabilities; ordinary failed changes retain the prior selection. Same-toolset changes validate discovery. Status and execution read Pi’s current accepted tools, so later host-tool changes also suppress the prompt and calls. Malformed settings notify and start disabled with a UI context, or throw through Pi’s extension error path before Bifrost starts without one. `/bifrost` reads status on every render and refreshes every success, failure, and rollback path.

Release preparation now has a dedicated Pi job that writes only the Pi checksum sidecar, validates the package, and attaches the npm tarball after the existing GitHub release. The pre-existing VS Code packaging and Marketplace sequence remains unchanged. Fresh validation passed the Node tests, TypeScript/package checks, clean `npm ci`, packed installation, audit, pack and publish dry runs, version/manifest checks, changed-workflow `actionlint`, `cargo fmt --check`, and the personal AST rules. Full-repository `actionlint` also surfaced only pre-existing shellcheck findings in `.github/workflows/benchmark.yml`; the changed release and CI workflows pass directly. The real Pi smoke returned a source symbol through `bifrost_get_summaries`, exited zero, and added no surviving Bifrost process.

## Context and Orientation

`plugins/bifrost-agent/extensions/bifrost-session.ts` owns the MCP client launched for one Pi session. MCP means Model Context Protocol; here it is the JSON protocol carried over a Bifrost child process’s standard input and output. The module discovers Bifrost tools, registers Pi names such as `bifrost_search_symbols`, changes selected capabilities transactionally, and closes children during replacement and shutdown.

`plugins/bifrost-agent/extensions/bifrost.ts` connects that controller to Pi lifecycle events and implements the `/bifrost` settings dialog. `plugins/bifrost-agent/extensions/bifrost-settings.ts` persists one settings document per canonical workspace. `.github/workflows/release.yml` builds release-specific package artifacts. `scripts/prepare-vscode-extension-manifest.mjs` reads built checksum sidecars and writes trusted hashes to the VS Code manifest or Pi release sidecar. `scripts/sync-release-version.mjs` verifies committed host projections.

The existing implementation has a mutable `SessionLifecycle` record but leaves starting clients, close promises, and registered-tool ownership in sibling closure variables. Desired settings and connected settings share one field, so initial failure erases the settings the user intended to retry. Pi tool reconciliation records requested names before Pi applies host filters. Restart clears parts of connection state without atomically removing old Pi tools. The settings dialog’s header is built once.

## Plan of Work

First, replace `SessionLifecycle` and the orchestration closure cluster in `plugins/bifrost-agent/extensions/bifrost-session.ts` with a private session implementation that satisfies `BifrostSessionController`. Give it one state containing the workspace, desired capabilities, generation, and a discriminated published connection. A published connection is disconnected, connecting, connected with its client, toolset, discovered names, and optional last-operation error, or failed with an error. Keep every owned and starting client, close identity, candidate liveness, registered Pi names, dependencies, and the error reporter as private resources on the same owner.

Centralize transitions in methods that publish connecting, connected, disconnected, and failed states. Restart must publish connecting or disconnected and remove old Pi tools before its first await. Successful no-op operations must clear the last operation error. Initial startup must set desired capabilities before connecting and retain them if connection fails; ordinary failed TUI changes must preserve the previous desired selection. Dynamic tool execution must ask the owner for the current connected client and active discovered name.

Make Pi reconciliation compute requested MCP names with a pure helper and apply their Pi names. Derive effective names live from `pi.getActiveTools()` whenever status or execution needs them instead of caching a second active set. Status and prompt injection then reflect both startup filters and later host-tool changes. Preserve unrelated Pi tools and registered-but-disabled Bifrost definitions.

Second, change `plugins/bifrost-agent/extensions/bifrost.ts` so malformed persisted settings fail closed. Interactive sessions notify and start with no capabilities, allowing `/bifrost` to repair the file; headless sessions throw the structured settings error before starting Bifrost. Rename the status error field to `lastOperationError`. Build the dialog header through a helper and update its `Text` after each successful, failed, or rolled-back operation.

Third, add a dedicated Pi release job that prepares only the Pi release sidecar, runs the package gates, and attaches the npm tarball. Preserve the existing GitHub release and VS Code publication sequence.

Finally, update this plan as evidence arrives. Run focused tests first, then all package checks, clean install, packed install, audit, pack and publish dry runs, workflow lint, shared manifest checks, relevant repository gates, and a real Pi call using the namespaced Bifrost tool. Track the child PID or inspect only the process launched by the smoke; never kill processes by pattern.

## Concrete Steps

Run commands from `/home/josh/projects/BrokkAi/bifrost` unless a command changes directory explicitly.

1. Edit `plugins/bifrost-agent/extensions/bifrost-session.ts` and `plugins/bifrost-agent/test/bifrost-session.test.mjs`, then run:

       cd plugins/bifrost-agent && npm test -- --test-name-pattern='startup|filter|restart|no-op'
       npm run check

2. Edit `plugins/bifrost-agent/extensions/bifrost.ts` and its extension tests, then run the complete package test suite:

       cd plugins/bifrost-agent && npm test

3. Edit `.github/workflows/release.yml` to add only the Pi package job, then rerun package tests and:

       node scripts/sync-release-version.mjs --check
       node scripts/check-codex-plugin-manifest.mjs
       actionlint

4. Run the comprehensive acceptance commands listed below and inspect `jj diff` and `jj status`.

## Validation and Acceptance

Behavior-focused session tests must pause restart cleanup and observe a connecting or disconnected status, no active Pi Bifrost tools, and no callable old client. They must fail initial startup with a nonempty selection and observe that same desired selection in status. A later toggle must be based on that preserved selection. A failed replacement followed by successful no-op reapplication must clear `lastOperationError`. A fake Pi host that rejects selected registered names must produce zero active Bifrost tools and no Bifrost prompt note.

Extension tests must show malformed settings notify and start disabled in TUI mode, throw the same structured error without calling `start` in headless mode, and never say defaults were enabled. Rendering after the last capability is disabled must show `disconnected`; rendering after recovery must show `connected`.

The release workflow must prepare the Pi sidecar from built checksum assets, complete the Pi package tests, and attach only the npm tarball. It must not change the existing GitHub release or VS Code dependency edges.

Run and require fresh success from:

    cd plugins/bifrost-agent
    npm ci
    npm test
    npm run check
    npm run test:packed
    npm audit
    npm pack --dry-run
    npm publish --dry-run

Then, from the repository root:

    node scripts/sync-release-version.mjs --check
    node scripts/check-codex-plugin-manifest.mjs
    actionlint
    cargo fmt --check

Run the repository’s applicable TypeScript AST rules if available. Use Pi against the package extension with an explicit local Bifrost binary and call at least one `bifrost_` tool against this workspace. The result must identify real repository source. Confirm the smoke’s Bifrost child exits; do not inspect or kill unrelated agents’ processes by name.

Before completion, inspect `jj diff --stat`, `jj diff`, and `jj status`. Every goal requirement must map to a changed file or fresh command, test, artifact, UI render, or process log. No requirement may remain probable, deferred, or hidden behind a scope qualification.

## Idempotence and Recovery

Tests use operating-system temporary directories and synthetic checksum files, so rerunning them does not change committed manifests. MCP cleanup remains idempotent by retaining one close promise per client. If an operation becomes stale, its generation ticket prevents it from publishing state, and its candidate is closed. If implementation validation fails, keep the prior connected client authoritative until the failure is understood; do not add a compatibility state shape.

## Artifacts and Notes

The earlier `.agents/plans/pi-bifrost-review-remediation.md` records the previous completed hardening pass. This plan records the final review remediation and does not rewrite that historical outcome.

## Interfaces and Dependencies

`createBifrostSession(pi, dependencies)` continues returning `BifrostSessionController`; callers do not learn about the implementation class. `BifrostSessionStatus` exposes `state`, optional `workspace`, `toolCount`, desired `capabilities`, and optional `lastOperationError`. The controller retains `start`, `applySelection`, `shutdown`, `status`, and `setErrorHandler`.

The session implementation uses Pi’s dependency-native `ExtensionAPI` and MCP SDK `Tool` and `CallToolResult` types. It does not duplicate protocol shapes. `AwaitableCloseClient` continues extending the pinned MCP `Client` solely to join the SDK’s internally initiated initialization cleanup.

Revision note (2026-07-18): Created this follow-up ExecPlan from the final review findings because the prior remediation plan is completed implementation history and does not describe this remaining work.

Revision note (2026-07-18): Recorded the completed lifecycle owner, race and cleanup discoveries, release projection fix, documentation behavior, and fresh acceptance evidence after independent reviewers returned no lifecycle blockers.

Revision note (2026-07-18): A later scope audit found that reordering GitHub and VS Code publication was unrelated to the Pi issue. Restored the existing sequence, removed its cross-host workflow regression, and retained only a dedicated Pi package job.

Revision note (2026-07-20): Recorded maintainer-review remediation for the default capability/toolset mismatch, independent registry-boundary fixtures, portable npm subprocesses, canonical temporary paths, and three-platform Pi package CI.

Revision note (2026-07-20): Added terminal-control sanitization and security regressions after review reproduced an OSC 52 sequence surviving call and result rendering.
