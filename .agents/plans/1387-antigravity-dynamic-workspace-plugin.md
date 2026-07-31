# Add an Antigravity plugin with dynamic MCP workspace binding

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. Maintain it according to `.agents/PLANS.md` from the repository root.

## Purpose / Big Picture

Antigravity users should be able to install Bifrost once and analyze whichever local Project or Git worktree they select, without editing a global MCP configuration to name that checkout. The plugin will start Bifrost rootless. A rootless Bifrost server remains unbound until the host supplies a local filesystem root through standard MCP `roots/list`; it must not use the plugin directory or process current directory as a guessed analyzer scope. The observable proof is two separate Antigravity Projects backed by different Bifrost worktrees: each source-backed MCP query finds only the unique probe in the selected worktree.

## Progress

- [x] (2026-07-31 06:00Z) Inspected the current rootless MCP binding implementation and Antigravity documentation; created GitHub issue #1387.
- [x] (2026-07-31 06:07Z) Recorded the implementation and live-worktree validation plan.
- [x] (2026-07-31 06:17Z) Tested a rootless Bifrost 0.8.17 server against an actual Antigravity Project and captured the capability-only initialization contract.
- [x] (2026-07-31 06:35Z) Documented the supported per-worktree `.agents/mcp_config.json` route, with an explicit process CWD and `--root .` binding.
- [x] (2026-07-31 06:37Z) Parsed every JSON example in the changed documentation and ran `git -c core.fsmonitor=false diff --check` successfully. The Astro check is blocked because `docs/node_modules` is absent and `astro` is not installed.
- [x] (2026-07-31 06:39Z) Ran `bifrost.code-smells` with evaluation date 2026-07-31. The report is unreliable because several existing whole-repository policies exhausted their execution budgets; this is not a clean validation result.
- [ ] Blocked: obtain a supported Antigravity workspace-to-MCP handoff before adding an automatic dynamic-root plugin. Do not add a CWD fallback.

## Surprises & Discoveries

- Observation: The installed Antigravity global configuration still contains the literal `--root /absolute/path/to/workspace` template.
  Evidence: `/Users/dave/.gemini/config/mcp_config.json` read at 2026-07-31 06:00Z.
- Observation: Bifrost already has a rootless server mode designed for plugin hosts. It requests `roots/list` only after the client has initialized and advertised roots support, and it revokes the active root while a replacement list is pending.
  Evidence: `src/bin/bifrost.rs` selects `None` as the initial root for explicit MCP launch without `--root`; `crates/bifrost-mcp/src/mcp_common.rs` implements the request and refresh state machine.
- Observation: Antigravity's published plugin documentation permits `plugin.json`, `mcp_config.json`, and skills, but its MCP documentation does not promise either `roots/list` or a workspace-variable expansion.
  Evidence: https://www.antigravity.google/docs/plugins and https://antigravity.google/docs/mcp checked on 2026-07-31.
- Observation: In Antigravity 2.3.1, a rootless Bifrost MCP server receives initialize parameters `protocolVersion`, `clientInfo`, and `capabilities`, with capabilities only `{ "elicitation": { "form": {}, "url": {} } }`. It neither advertises standard roots nor supplies a workspace path, so Bifrost correctly remains unbound.
  Evidence: A capability-only temporary proxy recorded `/private/tmp/antigravity-mcp-capabilities-1387.json`; the real Project conversation returned Bifrost's unbound-workspace error for both unique source probes.
- Observation: Antigravity started both global and project-local temporary MCP launchers with working directory `/`, not the selected worktree.
  Evidence: `lsof -a -p <temporary-launcher-pids> -d cwd` returned `/` for both. A generic CWD fallback would therefore analyze the filesystem root or other incidental host context.

## Decision Log

- Decision: Treat host-provided MCP roots as the only dynamic workspace authority.
  Rationale: A global plugin's own directory and process CWD can be unrelated to the selected Project, especially when the user opens a Git worktree. Binding either would silently analyze the wrong files.
  Date/Author: 2026-07-31 / Codex.
- Decision: Validate the real Antigravity client against two Git worktrees before baking a packaging contract into the repository.
  Rationale: Synthetic Bifrost MCP tests prove the server's roots implementation, not that Antigravity advertises or responds to the protocol correctly.
  Date/Author: 2026-07-31 / Codex.
- Decision: Do not check in a plugin until Antigravity offers an authenticated workspace handoff, such as standard MCP roots, a documented per-server workspace variable, or a documented plugin API that can pass `workspacePaths` to the MCP process.
  Rationale: Antigravity hooks expose `workspacePaths` to hook commands, but hooks cannot reconfigure an already-started stdio MCP process or bind a specific MCP connection. Writing a shared root file would race across conversations and weaken the workspace trust boundary.
  Date/Author: 2026-07-31 / Codex.
- Decision: Document Antigravity's workspace-local MCP configuration as the supported worktree route.
  Rationale: Antigravity documents `<workspace>/.agents/mcp_config.json` and an explicit stdio `cwd`. A local entry can bind `--root .` to the exact worktree without depending on an undocumented dynamic root exchange. The generated absolute path is machine-specific, so it stays uncommitted and must be created in each worktree.
  Date/Author: 2026-07-31 / Codex.

## Outcomes & Retrospective

The proof of concept established that a rootless server is safe but unusable in the current Antigravity client: it remains unbound rather than silently indexing the wrong directory. The original Antigravity configuration was restored and the two disposable `/private/tmp` worktrees were removed. The documentation now gives worktree users a safe local-MCP route while the dynamic-root host-contract follow-up remains open.

The documentation examples are valid JSON and their tracked-file diff has no whitespace errors. The full documentation type check could not start because this worktree has no installed Astro dependency. The required `bifrost.code-smells` run was unreliable: the expensive nested-loop, file-read-in-loop, parsing-in-loop, serialization-in-loop, and sort-in-loop policies exhausted their repository-wide execution budgets. Those results are unrelated to the documentation change and do not establish a green policy gate.

## Context and Orientation

`src/bin/bifrost.rs` parses the CLI and deliberately starts `bifrost --mcp ...` without `--root` as an unbound server. `crates/bifrost-mcp/src/mcp_common.rs` implements the Model Context Protocol (MCP), a JSON message protocol between Antigravity and Bifrost. Its `McpConnectionState` sends `roots/list` after initialization when the host advertises the standard roots capability. `crates/bifrost-mcp/src/searchtools_service.rs` receives the selected path through `bind_client_workspace`, canonicalizes it, and asynchronously builds the analyzer for exactly that directory.

The existing shared host package is `plugins/bifrost-agent`. Its `bin/bifrost-launcher.mjs` resolves a pinned Bifrost release and passes a root only when a host supplies `BIFROST_WORKSPACE_ROOT`, `--root`, or `--workspace-root`. The current Claude, Cursor, and Codex MCP configurations already use the launcher rootlessly. `docs/src/content/docs/antigravity.md` instead currently describes a manually configured Bifrost binary with a fixed `--root` argument.

An Antigravity plugin is a directory rooted by `plugin.json`. It may contain `mcp_config.json`, which declares the stdio program Antigravity starts, and a `skills/` directory containing `SKILL.md` files. The package must start the launcher from its installed location without using that package location as the analyzer root.

## Plan of Work

First, create two disposable Git worktrees that start from the same Bifrost commit. Add a differently named, untracked Rust source probe to each worktree. Configure the installed Antigravity client temporarily with one rootless MCP entry pointing at the local Bifrost launcher and local test binary. Select each worktree as an Antigravity Project in turn and use source-backed MCP calls to search for both probes. The active worktree's probe must be returned; the other probe must not be returned. Record the client initialization/roots evidence and restore the prior global configuration if the test configuration cannot coexist with the final plugin layout. This prototype instead proved that Antigravity supplied no root signal and launched at `/`; do not proceed to dynamic plugin packaging until the host contract changes.

Until then, document the supported local route in `docs/src/content/docs/antigravity.md` and `plugins/bifrost-agent/README.md`: users create or merge an uncommitted `<worktree>/.agents/mcp_config.json` entry with `cwd` set to the absolute worktree path and `args` containing `--root . --mcp symbol|extended`. Antigravity's documented `cwd` makes the relative root exact, while the configuration stays local to the checkout. The instructions must say to use Settings -> Customizations -> Refresh and a fresh conversation after creation or modification.

If Antigravity later supplies standard roots, add an Antigravity-specific plugin directory below `plugins/bifrost-agent` with `plugin.json`, a rootless `mcp_config.json`, and the four canonical generic skills. Resolve the launcher from the installed plugin directory using only a host-documented mechanism. If Google publishes a documented workspace variable or plugin-to-MCP handoff, add narrowly scoped support for that exact signal and repeat the two-worktree proof. Never use launcher CWD as an inferred root.

Extend the JavaScript package validation so it checks the Antigravity manifest, MCP launch arguments, exact skill set, and rootless invariant. Update `docs/src/content/docs/antigravity.md` and `plugins/bifrost-agent/README.md` to explain that users install or copy the plugin, select an Antigravity Project, and verify a source-backed MCP result. The documentation must say precisely what happens if the host does not provide roots.

## Concrete Steps

From `/Users/dave/.codex/worktrees/127d/bifrost`:

1. Inspect `git worktree list --porcelain` and create two temporary detached worktrees under `/private/tmp`. Place a unique Rust source probe in each without committing it.
2. Record the current `/Users/dave/.gemini/config/mcp_config.json` content, then install a temporary rootless local-development MCP entry. The command must use the local launcher and a matching local Bifrost binary, and its args must be `--mcp symbol|extended` without `--root`.
3. In the Antigravity GUI, refresh MCP configuration, create/select a Local Project for worktree A, and require Bifrost `search_symbols` to return A's unique probe and not B's. Repeat after switching to worktree B. Retain only non-sensitive protocol/log evidence and restore temporary configuration if it was changed solely for testing.
4. Add the plugin files and focused package tests with `apply_patch`.
5. Run `node scripts/check-codex-plugin-manifest.mjs`, the relevant `plugins/bifrost-agent` Node tests, `cargo fmt --check`, `git diff --check`, and one MCP `run_policy` selecting `bifrost.code-smells` plus any repository policy roots discovered from the tree.

## Validation and Acceptance

Acceptance requires a real Antigravity session to run the same rootless server against two separate Git worktrees. In worktree A, `search_symbols` for probe A must produce a path under A, while probe B has no result. After switching to worktree B, the inverse must hold. This demonstrates the dynamic root changes with the selected Project rather than the global configuration or plugin install directory.

The checked-in validation must also reject any Antigravity MCP configuration containing `--root`, `--workspace-root`, `BIFROST_WORKSPACE_ROOT`, an unexpanded host placeholder, or a package CWD presented as analyzer scope. JavaScript tests must prove the plugin ships only the canonical Bifrost skills and points to the launcher using the validated Antigravity convention.

## Idempotence and Recovery

Temporary worktrees live under `/private/tmp` and must be removed after the client test only after inspecting their exact paths. The original Antigravity configuration is recorded before editing and restored if the temporary local-development entry needs replacement. Rootless binding is safe to retry: no Bifrost tool can run until Antigravity sends an approved root. If Antigravity does not advertise roots or fails to answer `roots/list`, keep the test result as evidence, leave Bifrost unbound, and document the project-local fixed-root configuration as the fallback.

## Artifacts and Notes

The tracking issue is https://github.com/BrokkAi/bifrost/issues/1387. The source-backed probes must use distinct names such as `antigravity_worktree_a_probe_1387` and `antigravity_worktree_b_probe_1387`; paths and symbols from one worktree are not accepted as proof for the other.

## Interfaces and Dependencies

The plugin uses Antigravity's public directory contract: `plugin.json` marks the package, `mcp_config.json` declares a stdio MCP server, and `skills/<name>/SKILL.md` contains reusable agent guidance. It reuses `plugins/bifrost-agent/bin/bifrost-launcher.mjs` and `plugins/bifrost-agent/skills/` instead of adding a second binary resolver or duplicate skill text.

At completion, the Antigravity MCP entry must be equivalent in behavior to:

    command: <installed plugin launcher>
    args: ["--mcp", "symbol|extended"]

No root argument or workspace environment override is permitted. Bifrost's existing `McpConnectionState::roots_request`, `handle_response`, and `SearchToolsService::bind_client_workspace` remain the authoritative root-selection API.

Plan revised 2026-07-31: created with issue #1387 and the explicit two-worktree real-client validation requirement so packaging cannot mask a static workspace binding.

Plan revised 2026-07-31: recorded the real Antigravity 2.3.1 prototype result. The host advertises only elicitation, supplies no root metadata, and starts stdio MCP processes at `/`; dynamic binding is therefore blocked safely rather than implemented through a CWD or shared-file workaround.
