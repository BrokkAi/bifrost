# Ship Bifrost code intelligence as a first-party Pi package

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

Maintain this document in accordance with `.agents/PLANS.md` from the repository root.

## Purpose / Big Picture

After this change, a Pi user can install the existing Bifrost agent package and immediately receive both native Pi tools backed by Bifrost's analyzer and the three matching code-intelligence skills. The package starts one Bifrost Model Context Protocol (MCP) stdio subprocess for the Pi session's actual workspace, discovers the available tools from that process, forwards calls and results, and closes the process on reload or exit. A user can prove the integration by installing the local package into Pi and successfully calling symbol navigation and structural query tools against this repository.

## Progress

- [x] (2026-07-17 19:33Z) Read issue #835, the existing agent plugin and launcher, Pi's package and extension documentation, existing host publication checks, and the repository planning rules.
- [x] (2026-07-17 19:33Z) Decide the package boundary, launcher reuse strategy, runtime lifecycle, schema adapter, and result mapping.
- [x] (2026-07-17 19:45Z) Added the Pi package manifest, pinned MCP dependency, peer dependencies, lockfile, and strict TypeScript configuration to `plugins/bifrost-agent`.
- [x] (2026-07-17 20:00Z) Implemented the Pi MCP extension with explicit workspace resolution, dynamic tool registration, model-visible structured results, cancellation forwarding, unexpected-close handling, and idempotent lifecycle cleanup.
- [x] (2026-07-17 20:00Z) Added focused unit and process-boundary tests for schemas, calls, errors, cancellation, lifecycle races, launcher resolution, child cleanup, and package contents; 37 tests pass.
- [x] (2026-07-17 20:05Z) Extended ordinary CI, release packaging, publication validation, and documentation for Pi installation, local development, npm packaging, and real-host smoke testing.
- [x] (2026-07-17 20:12Z) Ran generated-artifact checks, TypeScript/package checks, 37 Node tests, isolated local package installation, npm pack/publish dry runs, npm audit, Rust formatting, and all-target/all-feature Clippy successfully. The feature-complete Rust suite reached 1030 passes, 4 ignored, and 3 unrelated failures caused by existing tests assuming a `master` default branch while this environment creates `main`; no Rust source changed.
- [x] (2026-07-17 19:56Z) Ran real Pi host smokes proving `get_summaries`, inline canonical-JSON `query_code`, and workspace-relative saved `.rql` execution. Pi returned `src/mcp_common.rs`, `bifrost_searchtools/__init__.py`, and `docs/fixtures/ten-minute-evaluation/src/app.py`; JSON mode recorded successful native `query_code` execution and structured output.
- [x] (2026-07-17 20:18Z) Audited the 22-file final diff and mapped every issue acceptance criterion to implementation, tests, package artifacts, CI, docs, and real Pi logs. A fresh independent final review found no blockers.

## Surprises & Discoveries

- Observation: Pi deliberately has no MCP client, but its extension API permits tools to be registered during `session_start` and refreshes them immediately.
  Evidence: Pi `docs/usage.md` states MCP is extension-owned, while `docs/extensions.md` documents runtime `pi.registerTool()` calls.

- Observation: The existing standalone launcher cannot itself be used as the MCP SDK transport command without leaving an unnecessary parent process, but its exported resolution functions already contain the required release trust policy.
  Evidence: `plugins/bifrost-agent/bin/bifrost-launcher.mjs` exports `resolveWorkspaceRoot`, `resolveBifrostBinary`, and `buildBifrostArgs`; `spawnBifrost` uses inherited stdio and process-level exit forwarding intended for declarative hosts.

- Observation: Pi tool parameters are TypeBox schemas, while MCP returns ordinary JSON Schema at runtime.
  Evidence: Pi's documented extension examples construct TypeBox schemas; `Type.Unsafe` can retain Bifrost's complete discovered schema without duplicating its declarative Rust registry.

- Observation: Pi abort can cancel the SDK request promptly, but Bifrost currently processes stdio requests synchronously and cannot consume an MCP cancellation notification during a running tool call.
  Evidence: `src/mcp_common.rs` reads and handles one line at a time. The extension documents that cancellation settles Pi's request while analyzer work may finish in the child.

- Observation: The repository's feature-complete Rust suite has three environment-sensitive baseline failures unrelated to this TypeScript/package-only change.
  Evidence: `cargo test --features nlp,python` passed 1030 tests and failed `tool_reports_cached_duplicate_blob_at_each_path`, `tool_reports_current_and_history_findings_and_excludes_tests`, and `get_commit_diff_handles_merge_commit`. Their fixtures report or request `master`, while command output shows temporary repositories initialized with `main`; the changed-file set contains no Rust source.

- Observation: Running npm installation inside the shared package initially made dependency files visible to jj and would also have put `node_modules` into the broad release archive.
  Evidence: `.gitignore` now ignores nested `node_modules` and `.brokk` analyzer caches; release tar creation excludes and asserts the absence of `node_modules`; `jj st` now contains only 22 intended files.

## Decision Log

- Decision: Make `plugins/bifrost-agent` itself the Pi package instead of creating a separate Pi-only package.
  Rationale: The existing directory already owns the canonical skills, launcher, pinned release metadata, host documentation, tests, and release archive. A second package would duplicate the trust boundary and introduce version drift.
  Date/Author: 2026-07-17 / Pi

- Decision: Expose only `bifrost-code-navigation`, `bifrost-code-reading`, and `bifrost-codebase-search` through Pi's package manifest.
  Rationale: Issue #835 requests the three generic skills. Other skills assume host-specific agents or workflows and would advertise capabilities this Pi package does not provide. Referencing the canonical directories directly avoids generated copies and drift.
  Date/Author: 2026-07-17 / Pi

- Decision: Import launcher resolution functions, then let the MCP SDK spawn the resolved Bifrost binary directly.
  Rationale: This preserves `BIFROST_BINARY_PATH`, managed cache, pinned version, checksum verification, and explicit root handling while giving the SDK ownership of stdin, stdout, stderr, and child cleanup.
  Date/Author: 2026-07-17 / Pi

- Decision: Discover and eagerly register every tool advertised by `symbol|extended` once per session.
  Rationale: This keeps schemas and descriptions aligned with Bifrost's declarative registry. The tool count is modest and issue #835 asks for a seamless install, so a lazy proxy would add ceremony without meaningful benefit.
  Date/Author: 2026-07-17 / Pi

- Decision: Preserve discovered JSON Schema through `Type.Unsafe`, including `$defs`, references, required fields, and `additionalProperties`.
  Rationale: Rebuilding schemas by hand would drift, while stripping constraints silently weakens Bifrost's public argument contract.
  Date/Author: 2026-07-17 / Pi

- Decision: Throw for MCP `isError` results and make successful `structuredContent` model-visible rather than hiding it in Pi `details`.
  Rationale: Pi marks thrown tool executions as errors, and only `content` is sent to the model. Bifrost's canonical structured result must remain usable even when its rendered text is abbreviated.
  Date/Author: 2026-07-17 / Pi

## Outcomes & Retrospective

The first-party Pi package is implemented in the existing shared agent package. It reuses the launcher's pinned/checksum-verified binary policy, exposes only the three canonical generic skills, registers Bifrost's discovered `symbol|extended` tools natively in Pi, forwards errors and cancellation correctly, makes structured results model-visible, and handles startup, stale sessions, unexpected closes, reload, and shutdown. Ordinary CI and release CI validate the package, and release CI produces an npm tarball without contaminating the shared archive with dependencies. Real Pi smokes succeeded for navigation, inline CodeQuery JSON, and a workspace-relative saved RQL query.

The final acceptance audit found no deferred issue requirement. Package loading is proved by the isolated `pi install`/`pi list` run and manifest/package checks. Native analyzer calls are proved by the real Pi outputs and JSON-mode tool events. Explicit workspace selection is proved by launcher tests that reject an environment-root override and by saved RQL resolving to the repository fixture. Local and released binary trust paths remain shared in the launcher and covered by launcher tests. Lifecycle and protocol safety are proved by 37 Node tests, including cancellation, stale starts, unexpected closure, stdio process boundaries, and child exit. Canonical skill ownership is proved by the exact manifest paths and 11-file npm artifact. Documentation, ordinary CI, release packaging, generated Amp assets, format, Clippy, package checks, audit, and dry-run publication have all been inspected or executed.

## Context and Orientation

Bifrost is a Rust command-line program. `src/bin/bifrost.rs` parses `--root` and `--mcp`; with `--mcp "symbol|extended"` it starts a newline-delimited MCP server over standard input and standard output. `src/mcp_common.rs` implements the protocol methods `initialize`, `tools/list`, and `tools/call`. `src/mcp_registry.rs`, `src/mcp_core.rs`, and `src/mcp_extended.rs` define the advertised analyzer tools. The `extended` toolset contains `query_code`.

`plugins/bifrost-agent` is the shared host package. Its `bin/bifrost-launcher.mjs` selects an explicitly configured development binary, a compatible managed-cache binary, an explicitly allowed PATH binary, or a checksum-verified pinned release download. `bifrost-release.json` stores the required version and archive hashes. The three canonical skills required here are `plugins/bifrost-agent/skills/bifrost-code-navigation/SKILL.md`, `plugins/bifrost-agent/skills/bifrost-code-reading/SKILL.md`, and `plugins/bifrost-agent/skills/bifrost-codebase-search/SKILL.md`.

A Pi package is an npm-compatible directory with a `package.json` whose `pi` field names extensions and skills. A Pi extension is a TypeScript factory receiving `ExtensionAPI`. It may register tools dynamically during the `session_start` event and must release session-owned processes during `session_shutdown`. MCP is not built into Pi, so this package must include an MCP client dependency.

The extension will use one MCP client and one stdio transport for each Pi session. A lifecycle generation number distinguishes the active session from an older asynchronous startup. A stale startup must close its client and must not register tools. The explicit root is `ctx.cwd`, resolved and validated by the shared launcher helper. The SDK transport starts the resolved binary with `--root <absolute-root> --mcp symbol|extended`, using the workspace as the child working directory. Diagnostics remain on stderr; stdout remains exclusively MCP protocol traffic.

## Plan of Work

Add `plugins/bifrost-agent/package.json`, its lockfile, and a TypeScript configuration. Declare a pinned `@modelcontextprotocol/sdk` runtime dependency, peer dependencies for Pi's host-provided packages, and development dependencies needed for type checking and Node tests. Point the Pi manifest at one extension and exactly the three canonical skill directories. Add scripts for type checking, tests, and package-content validation.

Refactor `plugins/bifrost-agent/bin/bifrost-launcher.mjs` only enough to expose a single launch-resolution helper shared by its command-line `main` and the Pi extension. The helper must resolve and validate an explicit root, resolve the trusted binary, construct final Bifrost arguments, and return the command, arguments, working directory, and environment without spawning. Keep standalone launcher behavior unchanged and extend its existing tests.

Create `plugins/bifrost-agent/extensions/bifrost.ts` and small focused modules if needed. Separate pure adapters from lifecycle wiring so tests can cover them without running Pi. Normalize a missing MCP input schema to an empty object schema, preserve valid schema fields, and wrap it with `Type.Unsafe`. Convert MCP content into Pi text/image content where compatible. For structured success, serialize `structuredContent` into model-visible text and retain rendered MCP content in `details`; for text-only success, return its text. Throw a readable error for MCP `isError` results or SDK failures. Use Pi's truncation utility so model-visible output respects 50 KB and 2,000-line limits and clearly reports truncation.

During `session_start`, increment the generation, close any previous client, resolve the launch command from `ctx.cwd`, connect the MCP client with a 60-second timeout, request the tool list, reject names that collide with existing Pi tools, and dynamically register each tool. Each tool forwards its arguments using `client.callTool(request, undefined, { signal, timeout: 300_000 })`. Before publishing state, confirm the generation is still current; otherwise close the stale client. On startup failure, close partially created resources, report a concise stderr diagnostic, and leave calls unavailable rather than retaining a rejected promise. During `session_shutdown`, invalidate the generation and idempotently close the active or starting client. Add a `/bifrost` status command that reports the workspace, connection state, and registered tool count without introducing mutable configuration.

Add Node tests under `plugins/bifrost-agent/test`. Test schema preservation, text and structured result mapping, MCP errors, output truncation, collision detection, signal and timeout forwarding, stale-start cleanup, restart and shutdown behavior, and explicit workspace launch arguments. Use a small fake stdio MCP server fixture for a process-boundary test that proves initialization, discovery, calls, and cleanup. Do not use the real analyzer in every unit test.

Extend `scripts/check-codex-plugin-manifest.mjs` to require the Pi package version to match `Cargo.toml`, require exactly the three canonical Pi skills, require the extension and runtime package assets, and reject stale or missing package files. Add package checks proving `npm pack --dry-run` includes the launcher, metadata, extension, and three skills. Update `plugins/bifrost-agent/README.md` and `.agents/docs/agent-plugin-publication.md` with Pi local/GitHub/npm installation, `BIFROST_BINARY_PATH` development, release alignment, deterministic tests, and real-host smoke commands. Update the release workflow if necessary so the package dependencies and npm artifact are validated and published or at least produced consistently with the repository's currently available credentials; do not claim npm publication unless configured.

Build the local Rust binary and install or load the package in an isolated Pi configuration. Run a deterministic real-host smoke that checks tool registration and direct calls without relying on model tool selection where possible. Then run a real Pi prompt smoke and capture evidence that `get_summaries` or `search_symbols` succeeds, inline canonical JSON passed to `query_code` succeeds, a workspace-relative saved `.rql` file passed through `query_file` succeeds, the child root is this repository, no protocol text reaches Pi's stdout, and shutdown leaves no child launched by the smoke alive.

## Concrete Steps

Work from the repository root `/home/josh/projects/BrokkAi/bifrost`.

First describe the current jj change, then add package files and dependencies:

    jj describe -m "feat: add first-party Pi integration"
    cd plugins/bifrost-agent && npm install && npm run check && npm test

Run shared plugin validation and generation checks:

    node scripts/generate-codex-skill-bundle.mjs
    node scripts/generate-amp-skill-bundle.mjs
    node scripts/check-codex-plugin-manifest.mjs
    node --test plugins/bifrost-agent/test/*.test.mjs

Inspect the package artifact without publishing:

    cd plugins/bifrost-agent && npm pack --dry-run

Run Rust repository gates from the root. Use the repository helper for isolated Cargo targets where an isolated build is needed:

    cargo fmt --check
    scripts/with-isolated-cargo-target.sh cargo clippy --all-targets --all-features -- -D warnings
    scripts/with-isolated-cargo-target.sh cargo test --features nlp,python

Build a binary for the real-host smoke if the feature-complete test target has been cleaned:

    cargo build --bin bifrost

Use a temporary Pi agent directory and the local package for install validation. Set `BIFROST_BINARY_PATH` to the absolute local debug binary and `BIFROST_LAUNCHER_AUTO_INSTALL=0`. The proven real-host command is documented in `plugins/bifrost-agent/README.md`; it runs Pi with `-e "$PWD/plugins/bifrost-agent"` and asks for `get_summaries`, inline `query_code`, and saved-RQL `query_code` in one session.

After all checks, inspect:

    jj st
    jj diff

Create a completed change on the current branch only after the acceptance audit passes:

    jj commit -m "feat: add first-party Pi integration"

## Validation and Acceptance

The package manifest must load one extension and exactly the three canonical generic code-intelligence skills. `npm pack --dry-run` must show the extension, launcher, release metadata, and those skill files. Manifest validation must prove its version matches `Cargo.toml` and that it references canonical skills instead of copied variants.

Automated extension tests must prove that the workspace supplied to the launch helper is absolute and equals the Pi session workspace; `symbol|extended` is passed; `BIFROST_BINARY_PATH` still selects the local checkout binary; normal release resolution still verifies the pinned version and checksums; startup errors do not leave live resources; restart, stale startup, reload, and shutdown close clients idempotently; MCP stdout is consumed only as protocol; dynamic schemas retain complex JSON Schema; calls carry arguments, signal, and a 300-second timeout; successful structured results are model-visible; MCP failures become failed Pi tools; and oversized output is truncated according to Pi's limits.

A real Pi session must advertise the discovered Bifrost tools and successfully call `get_summaries` or `search_symbols` against repository source. In the same integration, `query_code` must succeed once with inline canonical CodeQuery JSON and once with a workspace-relative `.rql` file through `query_file`. Logs or JSON-mode events must show successful tool results and repository-relative source paths. The smoke must verify that the child uses this repository as root even when Pi's process launch context differs, and must verify that the specific child process launched for the test exits on Pi shutdown.

`cargo fmt --check`, feature-complete Clippy, applicable package checks, generated-asset checks, and feature-complete Rust tests must pass. If a full Rust test cannot run because of an external environment dependency, record the exact failing command and evidence, run the largest relevant subsets, and do not mark the overall goal complete unless the objective's required evidence is otherwise obtained without narrowing acceptance.

## Idempotence and Recovery

Package generation, manifest checks, Node tests, Cargo checks, and local package installation are repeatable. Use temporary Pi configuration directories for smoke tests so global user settings are not changed. Track only child process identifiers created by the smoke and terminate only those identifiers if cleanup itself fails; never kill by process name or pattern.

If npm installation fails partway, rerun it in `plugins/bifrost-agent`; the lockfile is the source of dependency resolution. If an MCP startup becomes stale because of reload, the generation guard must close it automatically. If generated host assets drift, rerun their canonical generator and inspect the resulting diff before proceeding. Use `jj st`, `jj diff`, and `jj op log` to inspect or recover version-control state without discarding unrelated user changes.

## Artifacts and Notes

The intended launch boundary is:

    command: <trusted resolved bifrost binary>
    args: ["--root", "<absolute Pi ctx.cwd>", "--mcp", "symbol|extended"]
    cwd: <absolute Pi ctx.cwd>
    transport: stdio

The required real behavior is not merely that names appear in a manifest. A fresh Pi runtime must discover schemas from Bifrost itself and execute analyzer-backed calls.

## Interfaces and Dependencies

`plugins/bifrost-agent/bin/bifrost-launcher.mjs` must export an asynchronous launch resolver with an interface equivalent to:

    resolveBifrostLaunch({ root, env, toolset })
      -> { command, args, cwd, env, source }

The standalone launcher and Pi extension must both use this helper.

The extension's pure MCP adapter must accept discovered tool objects containing `name`, `description`, and `inputSchema`, and register corresponding Pi tools. Each registered execution must call the active session client with the original MCP name and arguments. The lifecycle state must include the MCP client, workspace root, registered tool names, and a generation identity sufficient to prevent stale publication.

Use `@modelcontextprotocol/sdk` version `1.29.0` as the pinned MCP client implementation unless hands-on API validation finds a concrete incompatibility. Use Pi's host-provided `@earendil-works/pi-coding-agent` and `typebox` packages as peer dependencies with `*` ranges, following Pi package guidance. Development dependencies may pin current versions for reproducible type checking, but runtime dependencies needed by the installed package must remain under `dependencies`.

Revision note (2026-07-17): Created the initial self-contained plan after codebase, issue, launcher, publication, and Pi API investigation. The design keeps Pi inside the existing shared package to avoid a second release trust boundary.

Revision note (2026-07-17 20:12Z): Updated the living plan after implementation, review fixes, package/CI integration, real Pi smoke tests, and validation. Recorded the three unrelated default-branch-sensitive Rust test failures rather than hiding the feature-complete suite result.

Revision note (2026-07-17 20:18Z): Completed the acceptance audit after fresh package tests, manifest checks, workflow lint, formatting, and an independent no-blocker review.
