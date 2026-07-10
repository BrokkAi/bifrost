# Support runtime LSP configuration changes

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document follows `.agents/PLANS.md` and must be maintained in accordance with that file.

## Purpose / Big Picture

Bifrost currently reads editor configuration only from LSP `initializationOptions`, so changing the indexed roots, excluded paths, or formatter commands requires restarting the language server. After this work, an editor can notify the running server that its Bifrost settings changed. Modern clients will let Bifrost pull the complete `bifrost` settings section with `workspace/configuration`; older clients can still push the complete settings object in `workspace/didChangeConfiguration`.

Users can observe the result without restarting Bifrost: a new formatter command affects the next formatting request, changing roots or exclusions rebuilds the indexed workspace, and diagnostics for files that leave the workspace are cleared. The implementation follows the LSP 3.18 configuration protocol at <https://microsoft.github.io/language-server-protocol/specifications/lsp/3.18/specification/>.

## Progress

- [x] (2026-07-10 07:27Z) Refreshed the existing `576-support-runtime-lsp-configuration-changes` branch with `git fetch && git rebase`; it was already current.
- [x] (2026-07-10 07:27Z) Inspected the current LSP loop, workspace rebuild path, formatter lifecycle, diagnostics tracking, VS Code configuration flow, and LSP 3.18 configuration contract.
- [x] (2026-07-10 07:43Z) Implemented dynamic registration, configuration pulls, legacy pushed snapshots, newest-response-wins handling, and strict full-snapshot parsing. Evidence: six `lsp::server::tests` unit tests and `bifrost_lsp_server_runtime_configuration_registers_and_pulls_bifrost_section` pass.
- [x] (2026-07-10 07:43Z) Refactored runtime state to preserve editor roots separately, normalize configuration, prepare replacement analyzers transactionally, replay overlays, cancel formatter jobs before commit, and clear stale diagnostic state.
- [x] (2026-07-10 07:49Z) Added Rust unit and end-to-end coverage for registration/pull, direct and nested legacy snapshots, newest-pull ordering, malformed/error retention, editor-root restoration, exclusions, stale diagnostics, overlay replay, formatter replacement, formatter cancellation, and Windows handle cleanup. Evidence: six server unit tests and seven macOS runtime-configuration integration tests pass; the Windows-only `cmd.exe` cleanup case is compiled and exercised by Windows CI.
- [x] (2026-07-10 07:55Z) Updated the VS Code extension so startup and `workspace/configuration` pulls share one complete settings builder, workspace-scoped formatter rules remain excluded, and only launch-setting changes prompt for restart. Evidence: all 29 extension tests pass.
- [x] (2026-07-10 07:55Z) Documented full-snapshot precedence, pull/legacy shapes, rebuild and diagnostic behavior, live VS Code settings, and the LSP 3.18 reference; updated the API audit. Evidence: Astro check and production build pass, and both changed pages were inspected in the rendered local preview.
- [ ] Run focused and full validation, perform self-review, and record the final outcome.

## Surprises & Discoveries

- Observation: LSP 3.18 has no static server capability for `workspace/didChangeConfiguration`; clients advertise dynamic registration and `workspace.configuration` support instead.
  Evidence: `lsp-types` 0.97 models `DidChangeConfigurationClientCapabilities` as dynamic-registration capability data and exposes `WorkspaceConfiguration` as a server-to-client request.

- Observation: the VS Code language client automatically sends an initial configuration-change notification when a dynamic registration includes a `section`, and its normal pull handler returns merged workspace configuration.
  Evidence: `vscode-languageclient` 9.0.1 `configuration.ts` calls `onDidChangeConfiguration` during registration when a section is present and supports `middleware.workspace.configuration` around `workspace/configuration` requests.

- Observation: merged VS Code settings cannot be returned directly because `bifrost.formatterCommands` is intentionally trusted only from user settings.
  Evidence: `editors/vscode/src/extension.ts::trustedFormatterCommands` explicitly rejects workspace and workspace-folder formatter rules.

- Observation: explicit startup roots currently replace and discard the editor workspace-root set, which prevents an empty runtime root list from restoring the latest editor folders.
  Evidence: `collect_workspace_config` chooses either configured roots or client roots and `ServerState` stores only the chosen `active_roots`.

- Observation: `lsp_server::Connection::initialize_finish` consumes the client's `initialized` notification before returning.
  Evidence: the first end-to-end registration test waited indefinitely when registration was dispatched from `handle_notification`; `lsp-server` 0.7.9 receives and validates `initialized` inside `initialize_finish`. Registration now runs immediately after `ServerState` construction, which is already after that protocol boundary.

- Observation: populating a fresh `OverlayProject` before `WorkspaceAnalyzer::build_persisted` does not always make persisted reconciliation reparse an open file whose disk metadata is unchanged.
  Evidence: the overlay replay integration test rebuilt successfully but returned only the disk snapshot until the replacement analyzer explicitly called `update` with every replayed open `ProjectFile`. The rebuild preparation now performs that update after the persisted build.

## Decision Log

- Decision: use the modern pull model when `workspace.configuration` is advertised, and use pushed settings only for clients without pull support.
  Rationale: this follows LSP 3.18 and prevents pull-capable clients' untrusted notification payload from bypassing the VS Code middleware that preserves the formatter trust boundary.
  Date/Author: 2026-07-10 / Codex and user.

- Decision: dynamically register `workspace/didChangeConfiguration` with `registerOptions.section = "bifrost"` when supported.
  Rationale: the section limits client notifications to relevant settings and causes VS Code to perform an initial runtime synchronization after initialization.
  Date/Author: 2026-07-10 / Codex.

- Decision: every accepted runtime value is a complete snapshot of `roots`, `exclude`, and `formatterCommands`.
  Rationale: removing a setting in the editor must clear it in the server; patch semantics would leave deleted settings active indefinitely.
  Date/Author: 2026-07-10 / Codex and user.

- Decision: accept both a direct legacy settings object and an object nested under `bifrost`.
  Rationale: clients differ in whether synchronized section names are represented in the pushed JSON, while both shapes can express the same complete Bifrost snapshot.
  Date/Author: 2026-07-10 / Codex.

- Decision: reject an entire runtime snapshot when any recognized field is malformed, while ignoring unrelated fields.
  Rationale: partial application could rebuild roots while silently retaining or clearing a malformed formatter configuration. Unrelated fields include launch-only VS Code settings and are not part of the server runtime schema.
  Date/Author: 2026-07-10 / Codex.

- Decision: do not expose `AnalyzerConfig` tuning fields in issue #576.
  Rationale: the existing LSP/editor surface contains only roots, exclusions, and formatter commands; adding parallelism, cache budgets, or Java dependency schemas is a separate public-interface change.
  Date/Author: 2026-07-10 / Codex and user.

- Decision: formatter-only snapshots replace rules immediately without canceling already-running requests, while roots or exclusion changes prepare a new analyzer and cancel all formatter jobs before committing the swap.
  Rationale: formatting requests already snapshot command resolution before their worker starts. Analyzer rebuilds must not cross the swap boundary with old child processes or old project/storage state alive.
  Date/Author: 2026-07-10 / Codex.

- Decision: preserve the last working runtime configuration on pull errors, malformed responses, candidate-build failures, or formatter cleanup timeout.
  Rationale: `workspace/didChangeConfiguration` is a notification and cannot return an error to the client; retaining known-good state is safer than applying a partial or empty configuration.
  Date/Author: 2026-07-10 / Codex.

## Outcomes & Retrospective

The protocol, transactional runtime state, behavioral regressions, VS Code integration, and documentation milestones are complete. Bifrost now applies the three existing editor settings without a restart while retaining initialization options as startup state and preserving the formatter trust boundary. Final full-repository formatting, linting, and self-review remain before completion.

## Context and Orientation

The LSP transport and single-threaded message-dispatch loop live in `src/lsp/server.rs`. `run_with_connection` decodes the initialize request, creates `ServerState`, and enters `main_loop`. `handle_message` currently dispatches client requests and notifications but ignores responses because startup work-done progress is the only existing server-to-client request and waits for its response before the main loop starts. Runtime configuration adds server-to-client requests after initialization, so response dispatch must become stateful.

`ServerState` owns the active workspace roots, excluded paths, formatter rules, `WorkspaceAnalyzer`, overlay-aware project, completion cache, open-document snapshots, published-diagnostic URI list, document generations, and active formatting jobs. `rebuild_workspace` is already used for `workspace/didChangeWorkspaceFolders`: it constructs a project, replays open overlays, rebuilds the analyzer, replaces state, clears completion data, and returns diagnostic URIs that no longer belong to the project. Runtime configuration should reuse these invariants but split preparation from commit so a failed candidate does not mutate the live state.

An LSP workspace root has an identity URI/path from the editor and a canonical analyzer path. Initialization options currently choose explicit `roots` instead of editor workspace folders and store only that chosen list. Runtime clearing requires two lists: the latest editor workspace roots, updated by every workspace-folder notification, and the effective active roots, which are explicit configuration roots when nonempty and editor roots otherwise.

`src/lsp/handlers/formatting.rs` defines `FormatterCommandRule`, which is cloneable and equality-comparable. `handle_formatting_request` resolves the current rules and document text on the LSP thread before spawning a bounded worker. Therefore replacing the rule vector is sufficient for later requests; active workers do not borrow it.

The VS Code extension reads settings in `editors/vscode/src/extension.ts`, while pure lifecycle/configuration types and helpers live in `editors/vscode/src/lifecycle.ts`. `formatterCommands` must continue to come only from `WorkspaceConfiguration.inspect(...).globalValue`. `vscode-languageclient` exposes configuration middleware, allowing the extension to return a sanitized Bifrost snapshot when the server requests the `bifrost` section.

## Plan of Work

Milestone 1 adds the protocol machinery and parser. Extend initialization-derived state with booleans for pull support and dynamic registration. Handle `initialized` by sending `client/registerCapability` for `workspace/didChangeConfiguration` with the Bifrost section. Handle configuration notifications by either issuing a uniquely identified `workspace/configuration` request or parsing legacy pushed settings. Dispatch inbound responses by ID, track monotonically increasing pull generations, and apply only the latest response. The parser accepts direct or nested objects, defaults absent recognized fields to empty arrays, ignores unknown fields, and rejects malformed recognized fields as one transaction.

Milestone 2 makes snapshots observable. Refactor workspace configuration into the latest editor roots, the canonical configuration base, and the current full Bifrost snapshot. Normalize candidate roots and exclusions before comparing. Formatter-only changes replace the rule vector. Root or exclusion changes prepare a replacement project, overlay, analyzer, active roots, open-document path updates, and stale-diagnostic list without mutating live state. Once preparation succeeds, cancel formatter jobs and wait for the existing grace period; on success swap all candidate state, clear completion data, drop old objects, and publish empty diagnostics for departed URIs. Workspace-folder notifications always update editor roots but rebuild only when explicit configuration roots are empty.

Milestone 3 updates clients and documentation. Extract one settings-snapshot builder used by VS Code initialization and configuration middleware. The builder resolves roots/exclusions as before and receives only trusted global formatter rules. Add middleware that answers the one-item Bifrost configuration request and delegates unrelated requests. Replace the broad restart prompt with launch-setting checks so runtime settings apply live. Document the wire shapes, full-snapshot semantics, rebuild behavior, error retention, trust rule, and LSP 3.18 reference in the LSP and VS Code docs, then update the LSP API audit row to implemented.

After each milestone, update this ExecPlan, run the focused checks, self-review the diff, and commit only the milestone files with a multiline checkpoint message explaining the behavior and rationale.

## Concrete Steps

Work from `/Users/dave/.codex/worktrees/85f2/bifrost` on `576-support-runtime-lsp-configuration-changes`. Do not create or switch branches.

For milestone 1, edit `src/lsp/server.rs` and focused tests, then run:

    cargo test lsp::server::tests --lib
    cargo fmt --check

For milestone 2, extend `tests/bifrost_lsp_server.rs` and run focused runtime-configuration tests:

    cargo test --test bifrost_lsp_server runtime_configuration
    cargo fmt --check

For milestone 3, update the extension and docs, then run:

    cd editors/vscode && npm test
    cd docs && npm run check && npm run build

Final validation from the repository root is:

    cargo fmt --check
    cargo test lsp::server::tests --lib
    cargo test --test bifrost_lsp_server runtime_configuration
    cargo clippy-no-cuda

This macOS environment does not have CUDA, so use `cargo clippy-no-cuda` rather than enabling all features.

## Validation and Acceptance

A client advertising dynamic registration receives a `client/registerCapability` request whose registration method is `workspace/didChangeConfiguration` and whose section is `bifrost`. A pull-capable client notification causes one `workspace/configuration` request for that section. If two pulls are outstanding, the response to the newest request determines state even when the older response arrives later.

A client without pull support can send either:

    {"settings":{"roots":[],"exclude":[],"formatterCommands":[]}}

or:

    {"settings":{"bifrost":{"roots":[],"exclude":[],"formatterCommands":[]}}}

Both are full snapshots. Empty or omitted arrays clear prior values. A malformed recognized field logs an error and leaves the last working configuration untouched.

After a formatter-only update, the next formatting request resolves the new command without rebuilding symbols. After roots or exclusions change, workspace symbols and document requests reflect the new file set, still-open document text is replayed, and every previously diagnosed file outside the new project receives `textDocument/publishDiagnostics` with an empty list.

A rebuild with an active slow formatter cancels and reaps that formatter before installing candidate state. The Windows integration case uses `cmd.exe`, waits for the canceled formatting response, synchronizes with a later request, and removes the departed root and `.bifrost` cache while the LSP process is still alive; success demonstrates that old child processes and storage handles are not retained.

VS Code answers configuration pulls with the same three runtime fields used at startup. Removing settings produces empty arrays. Workspace or workspace-folder `formatterCommands` never enter either startup or pull payloads. Changing runtime settings produces no restart prompt, while changing launch settings still does.

## Idempotence and Recovery

Configuration notifications are safe to repeat. A normalized snapshot equal to the active snapshot is a no-op. Pull responses are generation-tagged, so delayed duplicates cannot roll state backward. Candidate workspace construction is side-effect-free with respect to live `ServerState`; failures keep the old analyzer available. If formatter cleanup exceeds the grace period, the candidate is discarded and a later notification may retry.

Tests use temporary workspaces and explicit stub commands. They do not download models or formatter binaries. On interruption, inspect `git status`, update `Progress` with completed and remaining work, and continue forward without resetting unrelated changes.

## Artifacts and Notes

The dynamic registration is a server-to-client request:

    method: client/registerCapability
    registrations[0].method: workspace/didChangeConfiguration
    registrations[0].registerOptions.section: bifrost

The modern configuration pull is:

    method: workspace/configuration
    params.items: [{"section":"bifrost"}]
    result: [{"roots":[],"exclude":[],"formatterCommands":[]}]

Runtime failures are logged to stderr with a stable `[bifrost-lsp]` prefix because notifications have no response channel. Do not display modal editor messages for invalid settings.

## Interfaces and Dependencies

No new dependency is required. Use `lsp-types` 0.97 types `Initialized`, `DidChangeConfiguration`, `DidChangeConfigurationParams`, `RegisterCapability`, `Registration`, `RegistrationParams`, `WorkspaceConfiguration`, `ConfigurationItem`, and `ConfigurationParams`.

The internal Rust runtime snapshot should be equality-comparable and contain the normalized effective configuration inputs:

    struct BifrostRuntimeConfiguration {
        configured_roots: Vec<WorkspaceRoot>,
        excluded_paths: Vec<PathBuf>,
        formatter_commands: Vec<FormatterCommandRule>,
    }

The protocol tracker should own pull capability flags, a monotonic request generation, the newest requested generation, and pending request IDs. Registration uses a separate stable string request ID so responses cannot collide with configuration pulls or startup progress.

The VS Code settings builder returns a complete `BifrostInitializationOptions` with all three arrays present. Initialization and pull middleware both call it; only the extension layer may inspect setting scope and supply trusted formatter rules.

Plan update (2026-07-10 07:43Z): recorded completion of the protocol and state milestones plus the `initialize_finish` lifecycle discovery that moved dynamic registration out of ordinary notification dispatch.

Plan update (2026-07-10 07:49Z): recorded the completed behavioral test matrix and the persisted-overlay replay fix discovered by the end-to-end rebuild test.

Plan update (2026-07-10 07:55Z): recorded the completed VS Code and documentation milestones, including extension tests, Astro validation, and rendered-page inspection.
