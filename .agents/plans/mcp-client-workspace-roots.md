# Bind packaged MCP servers to client-approved workspace roots

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. This document follows `.agents/PLANS.md` and must remain self-contained.

## Purpose / Big Picture

After this change, an installed Bifrost agent plugin can start its packaged MCP server without confusing the plugin installation directory for the repository being analyzed. A client that implements the standard Model Context Protocol roots capability supplies one or more approved filesystem roots; Bifrost selects a usable root, builds the analyzer only for that root, and follows later root-list changes. A client that does not implement roots receives a live but unbound server whose lifecycle tools explain that a workspace must be selected. Any explicit `BIFROST_WORKSPACE_ROOT` or `--root` remains authoritative and preserves existing command-line integrations.

This does not require users to install a second MCP server. The agent plugin continues to register the packaged server automatically. Current Codex does not yet advertise MCP roots, so complete Codex behavior also requires a small host-side change: Codex must expose its already-known runtime workspace roots to MCP servers, or resolve package-relative plugin commands independently while leaving process cwd at the task workspace. The Bifrost half must be correct and useful for roots-capable clients without relying on private Codex cache paths, inherited `PWD`, parent-process inspection, or unrestricted filesystem switching.

## Progress

- [x] (2026-07-21 18:00Z) Reproduced issue #1031 and confirmed that Codex launches the packaged command from the plugin cache, which the launcher forwards as Bifrost `--root`.
- [x] (2026-07-21 18:20Z) Audited current Codex source and confirmed that configured plugin cwd overrides the runtime task cwd and that Codex does not currently implement `roots/list` for MCP servers.
- [x] (2026-07-21 18:45Z) Prototyped exposing existing `activate_workspace`, then backed it out after review showed it could escape the task boundary and broaden nested project roots to an enclosing Git root.
- [x] (2026-07-21 19:20Z) Implemented an explicit rootless lifecycle in `SearchToolsService` and MCP startup while preserving explicit-root callers and bare-command cwd compatibility.
- [x] (2026-07-21 19:40Z) Implemented MCP `roots/list` request/response handling, root-change notifications, coalesced refreshes, revocation, and standards-aware file-URI parsing.
- [x] (2026-07-21 19:45Z) Constrained protocol binding to exact client-returned canonical roots and added actionable unbound-state errors; the unrestricted lifecycle tool remains absent from the packaged toolset.
- [x] (2026-07-21 20:00Z) Updated the packaged launcher, generated skill bundles, release smoke, security-boundary docs, and Codex/Claude/Cursor installation guidance.
- [ ] Run Rust CI-equivalent checks, the packaged release smoke where practical, a real roots-capable host smoke, and the guided specialist review. Focused MCP, URI, manifest, and launcher tests pass.

## Surprises & Discoveries

- Observation: Bifrost already implements `activate_workspace` and `get_active_workspace`, including transactional analyzer replacement, but the default plugin intentionally omits the `workspace` toolset.
  Evidence: `src/mcp_core.rs` defines the descriptors, `src/searchtools_service.rs` handles activation, and `plugins/bifrost-agent/README.md` documents the omission.

- Observation: Exposing existing activation is not a safe compatibility fix. It accepts any readable absolute directory and promotes nested paths to the nearest Git root, allowing an installed MCP process to analyze outside Codex's task sandbox.
  Evidence: the post-implementation security and architecture reviews traced `handle_activate_workspace` through `resolve_workspace_root` and the persisted analyzer builder. The prototype was removed and the worktree returned to clean before this plan was created.

- Observation: MCP has a standard client roots capability. Supporting clients declare `capabilities.roots`, servers request `roots/list`, and clients may send `notifications/roots/list_changed`.
  Evidence: MCP specification version 2025-11-25, client feature “Roots”. Bifrost's hand-written JSON-RPC loop currently handles only client requests and notifications, so it needs a small bidirectional connection state machine.

- Observation: A root-change notification can race an outstanding roots request, and an empty replacement list revokes the previous workspace rather than meaning “keep using it.”
  Evidence: the connection state now coalesces an in-flight change into one follow-up request, and the host-equivalent integration test replaces then revokes the selected workspace.

## Decision Log

- Decision: Do not use `PWD`, `CODEX_HOME` cache scanning, parent-process cwd inspection, or editor-specific private state to recover a task root.
  Rationale: those values are global or private implementation details, are not tied reliably to a Codex task, and are not portable across macOS, Linux, Windows, or remote executors.
  Date/Author: 2026-07-21 / Codex

- Decision: Do not expose unrestricted `activate_workspace` in the default plugin as the issue fix.
  Rationale: MCP subprocesses run outside the agent's workspace filesystem sandbox. An arbitrary absolute-path switch would let prompt-injected content escape the approved task boundary and could create cache files or watchers in unrelated directories.
  Date/Author: 2026-07-21 / Codex

- Decision: Implement standards-based roots in Bifrost even though current Codex also requires an upstream change.
  Rationale: this gives Claude, Cursor, and future Codex builds one correct protocol contract and prevents the plugin package directory from being eagerly indexed. It cleanly separates package command resolution from analyzer workspace selection.
  Date/Author: 2026-07-21 / Codex

- Decision: Keep explicit environment and command-line roots authoritative.
  Rationale: existing CLI, Amp, release, and manual MCP configurations already provide a trusted root and must not incur a roots negotiation or behavior change.
  Date/Author: 2026-07-21 / Codex

- Decision: Preserve the historical bare `bifrost` command as `searchtools` on cwd, but make explicit `--mcp <toolsets>` launches rootless when no trusted root is supplied.
  Rationale: packaged and configured MCP clients use the explicit form, while existing shell integrations may rely on the documented no-argument compatibility behavior.
  Date/Author: 2026-07-21 / Codex

## Outcomes & Retrospective

The Bifrost and packaging halves are implemented. An explicit root remains deterministic; a package-launched server without one stays unbound until a roots-capable client approves a local directory, follows later root changes, and drops access when the list is revoked. The release smoke now exercises this host-equivalent protocol and a real symbol search. Current Codex still needs its host-side roots implementation before the original clean-install acceptance can pass end to end.

## Context and Orientation

`plugins/bifrost-agent/.mcp.json` is shared by Claude Code and Codex. Its package-relative command needs `cwd: "."` in current Codex so `./bin/bifrost-launcher.mjs` resolves inside the installed plugin. `plugins/bifrost-agent/mcp.json` is Cursor's equivalent. The Node launcher in `plugins/bifrost-agent/bin/bifrost-launcher.mjs` resolves a workspace in this order: `BIFROST_WORKSPACE_ROOT`, explicit `--root` or `--workspace-root`, then `process.cwd()`. It always invokes the Rust binary with `--root`, so current Codex turns the plugin cache into the analyzer root.

`src/bin/bifrost.rs` parses CLI arguments and currently initializes `root` to `env::current_dir()` before it knows which mode will run. For MCP mode it resolves a toolset and calls `mcp_common::run_stdio_server(root, ...)`. `src/mcp_common.rs` is a synchronous, line-delimited JSON-RPC server. It immediately constructs `SearchToolsService::new_deferred(root)` and assumes every inbound object with an id is a client request. Standard MCP roots require the server to send its own `roots/list` request after initialization and later recognize the client's JSON-RPC response.

`src/searchtools_service.rs` owns the analyzer, watcher, cache, and semantic index. Its `session: RwLock<Option<WorkspaceSession>>` already uses `None` temporarily, but public construction always has a concrete `root: RwLock<PathBuf>`. Rootless startup therefore needs an explicit lifecycle representation rather than a fake empty path. Existing workspace replacement is transactional: it builds a replacement before swapping active state and closes the old semantic index afterwards. Root discovery and approved activation must reuse that behavior.

A “client-approved root” is a local directory represented by a `file:` URI returned from MCP `roots/list`. Bifrost remains a single-root MCP server in this issue: when several approved roots are supplied, it selects the first usable root in the client's order. Multi-root analyzer composition is separate work.

## Plan of Work

Milestone 1 introduces a rootless service lifecycle without changing protocol negotiation. In `src/bin/bifrost.rs`, preserve the current directory fallback for LSP, REPL, one-shot tools, policy evaluation, skill installation, and ordinary MCP invocations that receive an explicit root. For MCP mode without an explicit root, pass `None` to `run_stdio_server`. In `src/searchtools_service.rs`, replace the bare root field with a small lifecycle representation that can distinguish unbound, building, ready, and failed states without manufacturing a path. Add a rootless constructor. Refactor first activation and replacement through one transactional helper. Analyzer tools called while unbound must return an error that says the client must provide MCP roots; lifecycle/status calls may remain available. Tests must prove failed first initialization leaves the service unbound and failed later replacement preserves the old workspace.

Milestone 2 adds the bidirectional MCP roots state machine in `src/mcp_common.rs`. Parse `initialize.params.capabilities.roots`. After writing the initialize response and receiving `notifications/initialized`, send a server request with a collision-safe string id and method `roots/list`. Distinguish inbound requests, notifications, successful responses, and error responses. Correlate only the pending roots request. Convert local file URIs to native paths with an existing URI library already present in the dependency graph where possible; do not parse URIs with string splitting. Reject non-file URIs, relative paths, missing directories, symlink escapes outside the canonical approved root, and malformed Windows drive or UNC forms. Empty or failed roots results keep the server alive but unbound. On `notifications/roots/list_changed`, request roots again and switch transactionally if the selected root changes.

Milestone 3 updates plugin packaging. The Node launcher must preserve explicit environment/argument precedence but omit `--root` for serve mode when neither is supplied, rather than converting package cwd into an analyzer root. The Rust binary will then start rootless. The shared and Cursor manifests keep their package command behavior and request a narrow lifecycle surface together with `symbol|extended`; `refresh` must not be added merely to bootstrap root selection. If a new narrow toolset alias is needed, define it declaratively in `src/mcp_registry.rs` using the existing activation/status descriptors rather than duplicating schemas. Skills should prefer automatic roots and mention activation only as a constrained compatibility fallback. Generated Codex and Amp artifacts must be regenerated with their existing scripts, not edited directly.

Milestone 4 updates verification and documentation. `scripts/smoke-agent-plugin-release.mjs` must launch the packaged plugin from the plugin directory without an explicit root, simulate a roots-capable MCP client, return the checkout workspace URI, call `search_symbols`, and find a known workspace symbol. A second test must cover a client without roots and verify an actionable unbound error rather than analysis of plugin files. Public Codex, Claude Code, and Cursor docs must say the plugin installs the MCP automatically; users should not add a duplicate manual MCP entry.

## Concrete Steps

Run all commands from `/Users/dave/.codex/worktrees/7765/bifrost`.

After Milestone 1:

    cargo fmt --all
    cargo test --test searchtools_service
    cargo test --test bifrost_mcp_server

Expect existing explicit-root tests to stay green and new rootless lifecycle tests to pass. Commit only the milestone's source, tests, and this updated plan with a multiline message explaining why fake cwd roots were removed.

After Milestone 2:

    cargo fmt --all
    cargo test --test bifrost_mcp_server

Expect roots-capable fake-client tests to observe a server-originated `roots/list` request after initialization, reply with a fixture URI, and then find fixture symbols. Run focused unit tests for URI conversion on Unix and Windows spellings even when the current host is macOS.

After Milestone 3:

    node scripts/generate-codex-skill-bundle.mjs
    node scripts/generate-amp-skill-bundle.mjs
    node scripts/check-codex-plugin-manifest.mjs
    node --test plugins/bifrost-agent/test/launcher.test.mjs

Expect manifests and generated bundles to be current, explicit launcher roots to retain precedence, and rootless launcher invocations to omit `--root`.

Before completion:

    cargo fmt --all
    scripts/with-isolated-cargo-target.sh cargo clippy --all-targets --all-features -- -D warnings
    scripts/with-isolated-cargo-target.sh cargo test --features nlp,python

The isolated-target helper removes its temporary build directory automatically. If the full suite is impractical after focused validation, record the exact incomplete command and reason in this plan rather than claiming it passed.

## Validation and Acceptance

The defining automated acceptance is a host-equivalent packaged smoke. Start the launcher with cwd equal to the unpacked plugin directory and no root override. The MCP client declares roots support, receives a `roots/list` request, responds with the checkout workspace's file URI, and calls `search_symbols` for `SearchToolsService`. The result must contain that workspace symbol and must not report symbols from the plugin package.

An explicit-root regression must start Bifrost with `--root <fixture>` and prove no roots request is required. Environment root and argv root precedence must remain environment, then argv, then protocol roots. A no-roots client must receive a usable initialize and tool list, but analyzer calls must fail with an actionable unbound-workspace error and must not create `.brokk/bifrost_cache.db` under the plugin directory.

Security acceptance requires that every protocol-derived path is a canonical local file root returned by the client. Activation outside the approved roots, including through symlinks or enclosing-Git-root promotion, must be rejected. Root changes must never let a stale background build overwrite a newer selected root.

Real-host acceptance requires a fresh plugin install and task. On a roots-capable client, no manual activation is needed. On current Codex, the Bifrost server should remain safely unbound until the corresponding Codex host change exposes task roots; it must never silently analyze the plugin cache. Once Codex advertises the task root, `search_symbols` must find a known symbol from the active worktree.

## Idempotence and Recovery

All generation and test commands are safe to repeat. Root activation with the same approved canonical root is a no-op. Failed root parsing or analyzer construction leaves the prior ready workspace unchanged, or leaves a never-initialized server unbound. Do not delete caches or build directories manually; use the repository's isolated Cargo helper and cleanup script.

If protocol work destabilizes explicit-root MCP mode, retain the old explicit-root construction path alongside rootless mode until its existing tests pass. Do not work around failures by restoring cwd fallback for rootless plugin launches, because that recreates the original bug.

## Artifacts and Notes

Current reproduction:

    codex mcp list --json

reports the installed Bifrost server cwd under `.codex/plugins/cache/bifrost/brokk/0.8.7/.`. The launcher then emits `--root` with that directory. This proves startup and tool advertisement can be healthy while the analyzer is bound to the wrong repository.

The rejected shortcut was `workspace|symbol|extended` in the default plugin plus unconditional skill activation. It passed focused MCP tests but failed review because activation was unrestricted and not exact-root preserving. No part of that prototype remains in the worktree at the start of this plan.

## Interfaces and Dependencies

At the end of Milestone 1, `mcp_common::run_stdio_server` accepts an optional initial root, and `SearchToolsService` has a rootless constructor plus an accessor that returns `Option<PathBuf>` or an equivalent explicit lifecycle type. Existing explicit-root constructors keep their signatures unless a shared private helper reduces duplication.

At the end of Milestone 2, `mcp_common.rs` owns a connection-state type that records initialization state, client roots capability, and the pending server request id. File-URI conversion is delegated to a standards-aware library already in `Cargo.toml` or added deliberately with tests. The service exposes a method that applies client-approved roots transactionally; ordinary `activate_workspace` cannot escape that allowlist in rootless/plugin mode.

At the end of Milestone 3, the launcher has a helper that builds Bifrost arguments with an optional root. Explicit roots produce `--root <path>`; absent roots do not. Plugin manifests expose only the lifecycle operations required for binding plus the existing analyzer/query tools. Amp retains its explicit `--root .` behavior and does not inherit rootless plugin guidance.

Revision note (2026-07-21): Initial plan created after the activation-only prototype was rejected in security and architecture review. The plan now makes MCP client roots the authority and records the required Codex host dependency.
