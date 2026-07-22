# Bind Codex MCP tools to the active task workspace

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept current as implementation proceeds. It follows `.agents/PLANS.md` and is self-contained.

## Purpose / Big Picture

After this change, the packaged Bifrost MCP server in Codex Desktop can discover the active task workspace without treating the plugin installation directory as source code and without requiring Codex to implement standard MCP roots first. A rootless Bifrost server whose client did not advertise roots offers the experimental `codex/sandbox-state-meta` capability. A compatible client may then supply the active turn's canonical `sandboxCwd` file URI on every `tools/call`; current Codex does so, and Bifrost binds that exact directory before running the analyzer tool.

The authorization order remains deliberate. An explicit `--root` or `BIFROST_WORKSPACE_ROOT` is authoritative. A client that advertises standard MCP roots is authoritative through `roots/list`. Only a rootless connection whose client did not advertise roots may use sandbox metadata; the client name is diagnostic, not an authorization boundary. Missing, malformed, or changed metadata revokes any previous metadata-derived binding before the call fails or rebinds, so a stale task cannot remain queryable.

The user-visible proof is stronger than the v0.8.8 release smoke from issue #1031. A shared recorded-handshake fixture captures the shape Codex 0.145.0-alpha.30 actually sends, with no fabricated roots capability, and both Rust integration coverage and the Node release smoke consume it. The release workflow stages the exact agent archive, exercises its extracted contents with the just-built Linux binary before publishing anything, publishes only the binary assets, and then makes that same staged archive perform a managed cold download from those assets. Only after both proofs pass does the workflow publish the agent archive and announce the release. A separate real-host run proves current Codex itself can resolve a symbol. Concise stderr events make an installed Desktop session auditable without printing the full sandbox permission payload.

## Progress

- [x] (2026-07-22 12:20Z) Reproduced issue #1067 in the active Codex task: the installed v0.8.8 Bifrost server reports that it is unbound.
- [x] (2026-07-22 12:35Z) Audited issue #1031, PR #1035, and the v0.8.8 release smoke; confirmed the smoke fabricated `capabilities.roots` and answered `roots/list`, unlike current Codex.
- [x] (2026-07-22 12:50Z) Audited the live launcher process and current Codex source; process cwd is the plugin cache and neither argv nor environment contains the task root.
- [x] (2026-07-22 12:59Z) Identified and designed around Codex's supported `codex/sandbox-state-meta` server capability and per-call `sandboxCwd` metadata.
- [x] (2026-07-22 13:15Z) Implemented root-source tracking, capability advertisement, fail-closed per-call metadata reconciliation, duplicate-initialize rejection, and concise transition logs in `src/mcp_common.rs`.
- [x] (2026-07-22 13:25Z) Added behavior-focused integration coverage for binding, revocation, malformed metadata, root changes, explicit-root precedence, roots precedence, and a compatible non-Codex-named client.
- [x] (2026-07-22 13:45Z) Corrected the release proof with distinct metadata and roots scenarios, one shared recorded handshake, an explicit-binary mode, safe process shutdown, a prepublication workflow gate, and a managed cold-download gate before the agent archive or announcement becomes public; the exact prepublication command passed locally against `target/debug/bifrost`.
- [x] (2026-07-22 14:48Z) Closed the final review's workspace-authority bypass: rootless connections controlled by standard roots or Codex metadata reject `activate_workspace`, and the metadata fast path also verifies the active root still equals the recorded canonical root.
- [x] (2026-07-22 15:02Z) Completed final validation: 27 MCP integration tests, 33 launcher tests, manifest and workflow validation, recorded-handshake package smoke, formatting, diff hygiene, and strict all-target/all-feature Clippy pass; retained the known macOS PyO3 link boundary for the full feature gate.
- [x] (2026-07-22 15:02Z) Closed specialist review after security, architecture, test, duplication, DevOps, release-ordering, full-diff, and client-authority rechecks reported no remaining actionable findings.

## Surprises & Discoveries

- Observation: The installed Bifrost server is healthy and rootless, not accidentally bound to the plugin cache. Its tool calls fail with the intended unbound diagnostic because current Codex never performs the standard roots negotiation implemented for #1031.
  Evidence: the live `get_summaries` call returned JSON-RPC error `-32603`, and the v0.8.8 process cwd was the plugin cache with no `BIFROST_WORKSPACE_ROOT` or task-root environment variable.

- Observation: The #1031 release smoke tested an imagined roots-capable host rather than current Codex. It manually placed `roots` in `initialize.params.capabilities`, waited for Bifrost's `roots/list`, and supplied the checkout URI.
  Evidence: `scripts/smoke-agent-plugin-release.mjs` constructs both sides of that exchange; the release workflow invokes that Node script directly rather than launching Codex.

- Observation: Current Codex intentionally offers an MCP-server opt-in for the exact missing context. When the server advertises `capabilities.experimental["codex/sandbox-state-meta"]`, Codex adds `_meta["codex/sandbox-state-meta"].sandboxCwd` as a canonical local file URI to each tool call. It also supplies `_meta.threadId`, which is useful only for correlating logs.
  Evidence: current Codex source reads the experimental server capability in `codex-mcp`, injects sandbox state in the core MCP tool-call path, and has a stdio integration test for the metadata. The installed binary contains the same capability string, and another live MCP server received the metadata in this task.

- Observation: stderr is useful evidence but not an authority. Codex records MCP server stderr, allowing a clean-install smoke to correlate initialization and binding with a task, but only the protocol metadata may select the workspace.
  Evidence: the Codex stdio launcher captures server stderr; the metadata itself supplies the exact canonical workspace URI.

- Observation: An exact `clientInfo.name` comparison does not make the extension an authorization boundary because an MCP client chooses that value. It would only prevent compatible clients from using a negotiated capability and make recorded handshakes brittle.
  Evidence: the implementation now advertises the extension from connection state alone—rootless launch and no advertised roots—and an integration test exercises the same metadata contract with a generic compatible client name.

- Observation: The old release smoke ran only after the GitHub release and Visual Studio Marketplace publication, so a failure could diagnose a bad release but could not prevent it.
  Evidence: `.github/workflows/release.yml` now builds one agent archive in `agent-plugin-package`, extracts that exact archive in `agent-plugin-prepublish-smoke`, and pairs it with the `bifrost-x86_64-unknown-linux-gnu` build through `--binary-path` before `release`. `release` publishes only binary assets. The macOS smoke then extracts the same staged archive and makes its launcher download the published binary through the generated checksum metadata. `publish-agent-plugin` exposes the already validated agent archive and announces the release only after that cold path passes; Pi and Marketplace jobs wait for publication.

- Observation: A search smoke that only looked for its pattern in serialized output was vacuous because `search_symbols` echoes requested patterns even when `files` is empty. Running against the checkout also wrote the client-bound cache into the worktree because client roots intentionally ignore `BIFROST_CACHE_DIR`.
  Evidence: the finalized smoke creates a tiny disposable Java workspace per scenario, requires a non-empty file result and the exact class hit, verifies the cache appears under that disposable root, and removes the whole root after the MCP process closes.

- Observation: A real current-Codex run succeeds through this negotiated path without roots or an explicit workspace override.
  Evidence: `codex exec --ephemeral --ignore-user-config` launched the branch binary from the plugin directory while the task cwd was a tiny temporary Git workspace; `search_symbols` returned `smoke.RealCodexWorkspace` from `RealCodexWorkspace.java`.

- Observation: Workspace lifecycle tools are themselves part of the authorization surface. A rootless `workspace`, `core`, or `searchtools` server could expose `activate_workspace`; allowing it after a roots- or metadata-derived bind would let a tool call replace the exact host-approved scope.
  Evidence: final adversarial review reproduced the path through `SearchToolsService::handle_activate_workspace`. The MCP layer now rejects that tool for both client-derived binding sources, and integration tests attempt the escape before proving the approved workspace remains active.

- Observation: The strict all-target, all-feature Clippy gate passes with the matching Homebrew Cargo and rustc, while the full `nlp,python` test gate reaches the final macOS dynamic-library link and then hits the repository's known unresolved Python C symbols.
  Evidence: `scripts/with-isolated-cargo-target.sh env RUSTC=/opt/homebrew/bin/rustc /opt/homebrew/bin/cargo clippy --all-targets --all-features -- -D warnings` passed. The analogous `cargo test --features nlp,python` run failed only at the PyO3 link boundary rather than in the changed MCP code or tests.

- Observation: Explicit-root MCP fixture tests in this linked worktree discover the primary checkout for their shared persisted cache, which is read-only inside this sandbox.
  Evidence: the unmodified suite reported SQLite open failures under `/Users/dave/Workspace/BrokkAi/bifrost/.brokk`; rerunning serially with a temporary `BIFROST_CACHE_DIR` passed all 27 tests and removed the temporary cache afterward.

## Decision Log

- Decision: Advertise and consume `codex/sandbox-state-meta` rather than inspect private Codex databases, parent processes, plugin paths, or broad turn metadata.
  Rationale: this is the narrow server-negotiated contract Codex implements for sandbox-aware tools. It supplies the active turn cwd directly and is testable through JSON-RPC.
  Date/Author: 2026-07-22 / Codex

- Decision: Offer sandbox-state metadata negotiation to every rootless connection whose client did not advertise standard roots; use `clientInfo.name` only in diagnostic logs.
  Rationale: explicit roots must remain stable, and future roots-capable Codex versions must use the standard protocol without a second authority racing a refresh. The experimental capability is opt-in, so clients that do not understand it ignore it and remain safely unbound. Because a client supplies its own name, an exact-name check would be a brittle compatibility gate rather than meaningful authorization.
  Date/Author: 2026-07-22 / Codex

- Decision: Treat every eligible tool call's sandbox metadata as the current authorization scope, not merely as a one-time bootstrap hint.
  Rationale: one MCP process may outlive a turn or task. If metadata disappears or changes, keeping the prior analyzer available would expose stale workspace data. Missing or unusable metadata therefore unbinds a metadata-derived workspace before returning an actionable error; a different valid cwd revokes first and then binds the replacement.
  Date/Author: 2026-07-22 / Codex

- Decision: Reject `activate_workspace` whenever standard roots or Codex sandbox metadata selected the active workspace, and require the same-URI metadata fast path to match the recorded canonical root.
  Rationale: client-derived scope must change only through its owning host contract. Even an activation targeting the apparent current path is unsafe because the service deliberately normalizes that tool to enclosing Git roots. Explicit-root integrations remain free to use the lifecycle tool.
  Date/Author: 2026-07-22 / Codex

- Decision: Bind the exact canonical directory represented by `sandboxCwd`; do not promote it to an enclosing Git repository.
  Rationale: sandbox cwd is an authorization boundary. Existing `bind_client_workspace` already preserves client-derived roots and keeps caches inside that exact directory, including linked worktrees.
  Date/Author: 2026-07-22 / Codex

- Decision: Preserve the standards-roots smoke as a separate compatibility scenario and add a recorded Codex 0.145.0-alpha.30 replay rather than renaming the old test.
  Rationale: both contracts matter, but only the recorded no-roots shape exercises issue #1067. Keeping them distinct prevents a synthetic roots exchange from being described as Codex-equivalent again, while the separate real-host run remains necessary evidence beyond the replay.
  Date/Author: 2026-07-22 / Codex

- Decision: Log only protocol mode, binding source, canonical root, and optional thread id; never log the full `_meta` or permission profile.
  Rationale: these fields are sufficient to diagnose installed sessions while minimizing disclosure and avoiding noisy payload dumps.
  Date/Author: 2026-07-22 / Codex

- Decision: Store one recorded Codex handshake under `tests/fixtures/mcp/` and consume that same JSON from both Rust integration tests and the Node release smoke.
  Rationale: independently reconstructed handshakes allowed #1031's synthetic roots flow to be mistaken for real Codex behavior. One fixture makes protocol drift visible and keeps every proof tied to the same observed host shape.
  Date/Author: 2026-07-22 / Codex

- Decision: Build the agent archive once, smoke its extracted contents with the just-built Linux release binary, publish only binary assets, then require that same staged archive to cold-download and verify a published binary before making the agent archive public.
  Rationale: the first gate blocks a broken package, launcher, binary, or protocol combination before any release exists. The macOS gate then proves the generated release metadata and managed install path against actual GitHub binary assets without exposing an unvalidated plugin. Agent publication, the announcement, Pi, and Marketplace all wait for that proof.
  Date/Author: 2026-07-22 / Codex

## Outcomes & Retrospective

The core binding is implemented and has resolved a known symbol through both the integration harness and a real current-Codex host while the MCP process started outside the workspace. The tests cover fail-closed withdrawal, malformed metadata, root replacement, explicit-root precedence, standard-roots precedence, duplicate initialization, and attempted workspace activation under both client-derived authorities, including activation as the first metadata-bearing call. Rust and Node load one recorded handshake, the launcher smoke drains and terminates its process tree, and the release workflow proves the staged package first with the built Linux binary and then through a managed download from the binary-only GitHub release before publishing the plugin or announcement. The exact local package replay passed, all 27 MCP and 33 launcher tests passed, strict all-feature Clippy passed, and final specialist reviews found no remaining actionable issue. The only broad-suite limitation is the pre-existing macOS PyO3 dynamic-link failure in the full `nlp,python` gate.

## Context and Orientation

`plugins/bifrost-agent/.mcp.json` launches `./bin/bifrost-launcher.mjs` with package-relative cwd so Codex can resolve the installed launcher. The launcher deliberately omits `--root` when no explicit root is configured. `src/bin/bifrost.rs` consequently calls `mcp_common::run_stdio_server(None, ...)` for the installed plugin.

`src/mcp_common.rs` owns the hand-written line-delimited JSON-RPC state machine. `McpConnectionState` records whether the process may accept client roots, whether the client advertised standard roots, which source selected the active workspace, initialization state, and any pending `roots/list`. `dispatch_message` extracts initialize capabilities, `initialize_result` returns server capabilities, `handle_response` applies standard roots, and `handle_tool_call` reconciles negotiated sandbox metadata before it requires an active analyzer workspace.

`SearchToolsService::bind_client_workspace` canonicalizes a local directory, builds an exact-root analyzer and cache transactionally, and swaps the active session only after a successful build. `unbind_client_workspace` clears the session. These methods are the correct lifecycle boundary for both standards roots and Codex sandbox metadata; the MCP layer must decide which authority is active.

The Codex extension is server-negotiated. A rootless Bifrost initialize response includes an empty object under `capabilities.experimental["codex/sandbox-state-meta"]`. Current Codex then places a camel-case `sandboxCwd` value under the same key in `tools/call.params._meta`. Its value is a canonical `file:` URI, so the existing standards-aware `file_uri_to_path` helper should parse it. `_meta.threadId` is diagnostic correlation only.

A “metadata-derived binding” means one rootless connection with no advertised roots whose current active root was selected from that negotiated per-call URI. Current Codex is the first supported producer, but the server does not use the client name as authority. Standard-roots and explicit-root bindings are different sources and must never be revoked or replaced by missing sandbox metadata.

## Plan of Work

First, extend `McpConnectionState` with a small binding-source enum and the information needed to determine whether the connection is rootless and whether the client advertised roots. Return the experimental capability only for a rootless connection without client roots; this makes the extension discoverable to compatible clients without changing explicit-root or standards-roots behavior. Retain the client name only for a concise initialization line describing the negotiated mode.

Second, reconcile eligible Codex metadata before the existing active-root check in `handle_tool_call`. Extract only `_meta.threadId` and `_meta["codex/sandbox-state-meta"].sandboxCwd`. Parse the URI structurally, canonicalize and validate the directory, then compare it with the active exact root. A same-root call is a no-op. A changed valid root first clears the old metadata binding and then binds the replacement. A missing, malformed, non-file, nonexistent, or nondirectory root clears a prior metadata binding and returns an actionable unbound or invalid-metadata error. Set the binding source only after a successful bind. Standard `roots/list` responses set the standard-roots source; roots-change notifications clear it while the replacement is pending.

Third, add behavior-focused integration tests in `tests/bifrost_mcp_server.rs`. Use the existing inline project/test process helpers and load the recorded request shapes from `tests/fixtures/mcp/codex-sandbox-state-handshake.json`. Replay current Codex initialize with empty client capabilities, assert the server advertises the extension and never emits `roots/list`, then send the recorded tool-call shape with substituted workspace, thread, and symbol values and find a known fixture symbol. Prove a later missing metadata call revokes access, a later different cwd moves access, malformed and non-file URIs fail closed, explicit `--root` ignores conflicting metadata, a roots-capable client never lets metadata fill a refresh gap, and a compatible client name can negotiate the same capability.

Fourth, split `scripts/smoke-agent-plugin-release.mjs` into reusable process and protocol helpers and two labeled scenarios. Load the same recorded handshake fixture as the Rust integration test. The recorded-Codex scenario starts the launcher from package cwd, initializes without roots, asserts the advertised experimental capability, substitutes a disposable workspace URI into the recorded sandbox metadata, and requires an exact symbol hit from that workspace. The standards scenario retains the existing roots exchange against a separate disposable workspace. Capture stderr through process close, assert one source-specific bind transition and exact root for each scenario, verify the analyzer cache stays under the disposable root, forward wrapper termination signals to Bifrost, and prove the package directory does not gain a cache. Add `--binary-path`, stage the agent archive once, and make `.github/workflows/release.yml` run the extracted archive with the just-built Linux executable before `release`; publish only the binary assets, use the same staged archive for the managed cold-install proof, and publish the plugin only afterward. Neither scripted flow should be described as launching a real Codex host: it is a pinned 0.145.0-alpha.30 replay, while the separate manual run is the real-host proof.

Finally, validate with formatting, focused Rust and Node tests, the repository's strict isolated Clippy gate, and the full feature test gate when practical. Build the branch binary and run one local `codex exec` smoke against a tiny temporary Git workspace while configuring the MCP process to start elsewhere; verify both the tool result and concise stderr correlation. Then run parallel security, architecture, implementation, and test reviews and repair all confirmed in-scope findings.

## Concrete Steps

Run commands from `/Users/dave/.codex/worktrees/aa92/bifrost`.

After the protocol implementation and integration tests:

    cargo fmt --all
    cargo test --test bifrost_mcp_server codex_sandbox
    cargo test --test bifrost_mcp_server rootless_mcp

Expect the Codex-shaped test to initialize without any server-originated `roots/list`, advertise the extension, bind only after the metadata-bearing call, and resolve the fixture symbol. Expect all existing roots and unbound tests to remain green.

After the release-smoke update:

    node --test plugins/bifrost-agent/test/launcher.test.mjs
    node scripts/check-codex-plugin-manifest.mjs

Run the prepublication form against a built executable:

    node scripts/smoke-agent-plugin-release.mjs \
      --plugin-dir plugins/bifrost-agent \
      --cache-dir /path/to/new-empty-cache \
      --binary-path /absolute/path/to/bifrost

It must report separate `codex sandbox metadata` and `MCP roots` scenarios, use the recorded handshake for the former, and include source-specific stderr evidence. Omitting `--binary-path` retains the cold managed-install mode used by the post-publication release job.

Before completion:

    cargo fmt --all -- --check
    scripts/with-isolated-cargo-target.sh cargo clippy --all-targets --all-features -- -D warnings
    scripts/with-isolated-cargo-target.sh cargo test --features nlp,python

The isolated-target helper removes its managed temporary directory. Record any platform dependency that blocks the full feature gate rather than treating compilation alone as a pass. The task instructions do not authorize staging, committing, pushing, rebasing, or opening a pull request, so changes remain on the existing issue branch for user review.

## Validation and Acceptance

The defining automated acceptance starts Bifrost rootless from a directory other than a disposable fixture workspace, loads the initialize and tool-call shapes recorded in `tests/fixtures/mcp/codex-sandbox-state-handshake.json`, observes `capabilities.experimental["codex/sandbox-state-meta"]`, and sends a real `search_symbols` call whose substituted `sandboxCwd` is the fixture's file URI. The structured response must contain a non-empty file result and the exact fixture class hit; the echoed request pattern is not evidence. No `roots/list` exchange may occur, the analyzer cache must appear only below the disposable root, and that root must be removed after shutdown.

Authorization acceptance requires all of the following. An explicit root ignores metadata. A roots-capable connection uses only roots and remains unbound during a roots refresh even if a call carries Codex metadata. A metadata-bound connection loses access when a later eligible call lacks or invalidates the metadata. A different valid metadata cwd revokes the old root before binding the new one. Binding or rebuild failure leaves the connection unbound rather than restoring the stale root.

Client-derived binding acceptance additionally requires a workspace-enabled rootless server to reject `activate_workspace` under both standard roots and Codex metadata. The rejected call must leave the approved root active, and a later same-URI metadata call must not accept any mismatched active root as reconciled.

Diagnostic acceptance requires initialization and successful binding lines to state the selected protocol/source. A metadata rejection should state its reason and optional thread id, but stderr must not contain `permissionProfile`, the full `_meta`, environment variables, or raw request JSON.

Real-host acceptance runs the current installed Codex client against the branch binary or locally assembled plugin. A task rooted at a tiny fixture repository must call Bifrost successfully without `--root`, `BIFROST_WORKSPACE_ROOT`, or standard roots. The observed bound path must be the fixture rather than the plugin/package cwd.

Release acceptance requires `agent-plugin-package` to produce the single agent archive with generated release metadata and `agent-plugin-prepublish-smoke` to extract that exact archive and pair it with the build matrix's `bifrost-x86_64-unknown-linux-gnu` artifact through `--binary-path`. `release` must publish only the binary archives and checksums. `agent-plugin-release-smoke` must extract the same staged agent artifact and use an empty cache without `--binary-path`, proving its generated checksum metadata and managed download against the public binary assets. Only `publish-agent-plugin` may then upload that validated archive and announce the release; Pi and Marketplace publication must depend on it.

## Idempotence and Recovery

All test and generation commands are safe to repeat. Reconciliation with the same canonical metadata root is a no-op. A bad metadata call after a metadata-derived binding intentionally leaves the service unbound; a later valid call may bind again. A failed transition to a different root must not restore the previous workspace automatically because the new per-call scope revoked it.

If capability parsing or reconciliation destabilizes explicit-root mode, keep the new path gated behind the two authoritative connection conditions—rootless launch and no advertised standard roots—and fix the gate rather than adding cwd fallback. Do not add a client-name check as security theater, inspect Codex private storage, or broaden a sandbox cwd to an enclosing repository as a recovery mechanism.

## Artifacts and Notes

The issue #1067 reproduction is the active Codex task itself: the installed Bifrost MCP tool returns an unbound error even though the task cwd is this worktree. The prior release smoke's roots exchange remains useful as a generic-client contract but is not evidence of current Codex behavior.

The relevant current-Codex call shape is conceptually:

    {
      "name": "search_symbols",
      "arguments": {"patterns": ["FixtureSymbol"]},
      "_meta": {
        "threadId": "...",
        "codex/sandbox-state-meta": {
          "sandboxCwd": "file:///absolute/canonical/workspace"
        }
      }
    }

Only `sandboxCwd` participates in authorization. `threadId` appears in logs for correlation; all other sandbox fields are ignored.

## Interfaces and Dependencies

`McpConnectionState` gains a private binding-source value such as `None`, `ExplicitRoot`, `ClientRoots`, or `CodexSandboxState`, plus the raw sandbox URI needed for a same-root fast path. `dispatch_request` and `handle_tool_call` receive mutable connection state so a tool call may reconcile its authorized workspace before argument normalization. Client identity remains log context only.

`initialize_result` gains a boolean or mode argument controlling whether it publishes:

    "experimental": {
      "codex/sandbox-state-meta": {}
    }

The server does not add a new public Bifrost tool or command-line option. It reuses `file_uri_to_path`, `SearchToolsService::bind_client_workspace`, `SearchToolsService::unbind_client_workspace`, and `SearchToolsService::active_workspace_root`. No new dependency should be necessary.

Revision note (2026-07-22): Initial plan created after reproducing #1067, auditing #1031's synthetic smoke, and finding Codex's server-negotiated sandbox metadata contract. It supersedes the older plan's conclusion that a host-side roots implementation is required for current Codex.

Revision note (2026-07-22 13:38Z): Updated after implementation and specialist review. The capability is now offered to any compatible rootless/no-roots client rather than gated by a forgeable client name; the proof uses one recorded handshake in Rust and Node; publication is blocked on a built-Linux-binary smoke while retaining the released-package cold smoke; and the plan records focused, strict-Clippy, real-host, and macOS PyO3-link outcomes.

Revision note (2026-07-22 14:31Z): Tightened the publication graph after final release review. The binary assets are the only public prerequisite for the managed cold-download smoke; the staged agent archive, Discord announcement, Pi package, and Marketplace extension all remain gated until that smoke succeeds.

Revision note (2026-07-22 14:48Z): Added the final authorization defense after adversarial review found that a workspace-enabled rootless server could otherwise escape a client-derived scope through `activate_workspace`.
