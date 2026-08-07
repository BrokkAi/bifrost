# Remove the legacy MCP host

This ExecPlan is a living document. Keep its `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` sections current. Follow `.agents/PLANS.md` from the repository root.

## Purpose / Big Picture

Bifrost now has two standard-input and standard-output MCP hosts. MCP means Model Context Protocol. A host reads MCP messages and runs Bifrost tools. The old host is hand-written. The new host uses `rmcp`, the official Rust SDK.

After this work, every MCP launch uses RMCP. Users cannot select the old host. The result removes duplicated protocol handling and gives every client the same Roots, cancellation, authorization, and timing behavior.

A user can prove this by starting `bifrost --mcp workspace`, sending an RMCP initialize request, and running `search_symbols`. The contract and benchmark tests must also pass without a host selector.

## Progress

- [x] (2026-08-07 07:43Z) Read issue #1745 and inspect the clean detached worktree at `a70336882`.
- [x] (2026-08-07 07:43Z) Trace both host entry points, affected tests, CI, release checks, replay tool, benchmark, and documentation.
- [x] (2026-08-07 07:43Z) Find the `--diff-snapshot-object-dir` MCP contract that the RMCP entry point must keep.
- [x] (2026-08-07 07:43Z) Write this ExecPlan.
- [x] (2026-08-07 07:43Z) Port `diff_snapshot_object_dir` to the RMCP standard server entry point.
- [ ] Remove the selector and all handwritten stdio server code.
- [ ] Make contracts, support tools, CI, release checks, benchmark, and documentation RMCP-only.
- [ ] Run focused tests, policy validation, the MCP contract suite, and the interactive benchmark checks.

## Surprises & Discoveries

- Observation: `--diff-snapshot-object-dir` is valid for MCP server mode.
  Evidence: `src/bin/bifrost.rs` validates the option before its MCP launch. `mcp_common.rs` gives it to `SearchToolsService::with_diff_snapshot_object_dir`.

- Observation: RMCP does not yet receive this option.
  Evidence: `rmcp_host::run_stdio_server_with_build_identity` has no object-directory argument. It creates the service directly.

- Observation: `mcp_common.rs` is not only old-host code.
  Evidence: `rmcp_host.rs` imports server types, watcher parsing, request budgets, URI conversion, policy correlation, and output fitting from it.

## Decision Log

- Decision: Keep shared MCP code in `crates/bifrost-mcp/src/mcp_common.rs`.
  Rationale: RMCP imports these parts. Removing the module would copy or break active code.
  Date/Author: 2026-08-07 / Codex.

- Decision: Add the optional diff snapshot object directory to RMCP before deleting the old host.
  Rationale: This keeps the documented MCP `analyze_diff` behavior. It is not a rollback-only feature.
  Date/Author: 2026-08-07 / Codex.

- Decision: Keep the existing RMCP contract coverage. Change only the test helpers that select two hosts.
  Rationale: The issue requires the coverage to remain. RMCP-specific tests already prove newer protocol behavior.
  Date/Author: 2026-08-07 / Codex.

## Outcomes & Retrospective

Milestone 1 now preserves the object-directory value in the RMCP service. The old host remains until Milestone 2.

## Context and Orientation

`crates/bifrost-mcp/src/mcp_common.rs` contains shared MCP support and the old host. Its `run_stdio_server_with_build_identity` function reads `BIFROST_MCP_RMCP`. When the value is `off`, it runs a hand-written JSON-RPC loop. JSON-RPC is the message format under MCP.

`crates/bifrost-mcp/src/rmcp_host.rs` contains the supported host. `run_stdio_server_with_build_identity` starts a standard server. `run_named_workspace_stdio_server_with_build_identity` starts a named-workspace server. Both use `run_stdio_server_impl`.

`SearchToolsService` executes Bifrost tools. An optional Git object directory lets `analyze_diff` read trusted immutable Git objects. `SearchToolsService::with_diff_snapshot_object_dir` sets this option. Named workspaces reject this option already.

`crates/bifrost-mcp/tests/bifrost_mcp_server.rs` is the end-to-end MCP contract suite. It starts the test server and exchanges real standard-input messages. `McpHost` and its helpers select the old or new server. The suite has loops that run both routes.

The root binary in `src/bin/bifrost.rs` parses CLI options. `src/benchmark/mcp_session.rs` starts benchmark clients. `.github/workflows/ci.yml` runs the MCP contract job. `.github/workflows/release.yml` runs plugin smoke checks.

## Plan of Work

### Milestone 1: Preserve the supported service configuration in RMCP

Add `diff_snapshot_object_dir: Option<PathBuf>` to `rmcp_host::run_stdio_server_with_build_identity`. Create the service as today. When the option is present, call `SearchToolsService::with_diff_snapshot_object_dir` before wrapping the service in `Arc`.

Update the standard server call from `mcp_common` or move the call site directly to `rmcp_host`. Preserve the existing `run_stdio_server` facade used by `mcp_core`, `mcp_extended`, and `mcp_slopcop`. It must still take the option and forward it to RMCP.

Keep `run_named_workspace_stdio_server_with_build_identity` unchanged. The CLI rejects the option for named workspaces.

Update `tests/suite_mcp_cli/bifrost_tool_cli.rs` only if a CLI test must prove that the option remains valid for a standard MCP launch. Keep the present rejected-path tests.

Run this focused command from the repository root:

    cargo test --test suite_mcp_cli -- bifrost_tool_cli::diff_snapshot_object_dir

The command must pass. A missing path and a regular file must still give the current validation errors.

### Milestone 2: Remove the handwritten host

In `crates/bifrost-mcp/src/mcp_common.rs`, remove `MCP_RMCP_HOST_ENV`, `rmcp_host_enabled`, its unit test, and `run_stdio_server_with_build_identity` code that parses, dispatches, writes, and cancels old-host messages. Remove only private items that no remaining code references.

Keep `McpRenderOptions`, `McpServerSpec`, descriptor builders, schemas, watcher parsing, request budgets, URI parsing, policy correlation, output-budget helpers, and all symbols imported by `rmcp_host.rs`.

Remove old-host-only imports and constants. Then run `cargo fmt` and `cargo check -p brokk-bifrost-mcp`. Use compiler errors as the final shared-code audit. Do not replace the old protocol path with text parsing or another fallback.

In `crates/bifrost-mcp/src/lib.rs`, remove `MCP_RMCP_HOST_ENV` from `benchmark_api`. Update downstream imports that then fail.

In `src/bin/bifrost.rs`, import the standard RMCP entry point through the supported facade. Remove the named-workspace selector guard. Update the `--workspace` help and example. They must state that named workspaces require `--mcp`, not an environment variable.

### Milestone 3: Make end-to-end contracts RMCP-only

In `crates/bifrost-mcp/tests/bifrost_mcp_server.rs`, remove `McpHost`, `spawn_server_on`, and `spawn_rootless_server_on`. Replace the loops at the current rootless authorization, policy, sandbox metadata, and transport timing tests with one RMCP launch. Keep the existing rootless, Roots, workspace authorization, cancellation, policy, and transport timing assertions.

Use `spawn_server` and `spawn_rootless_server` as the common helpers. Keep tests that explicitly prove RMCP protocol revision, MRTR Roots behavior, and response delivery order.

In `tests/mcp_build_identity_facade.rs`, require the RMCP `_meta/io.bifrost/build-identity` value. Remove the old `serverInfo.buildIdentity` alternative.

Run from the repository root:

    cargo test -p brokk-bifrost-mcp --test bifrost_mcp_server
    cargo test --test mcp_build_identity_facade

Each command must pass. No test may set `BIFROST_MCP_RMCP`.

### Milestone 4: Remove all external selector paths

In `.github/workflows/ci.yml`, replace the host matrix with one MCP contract job. Remove the selector environment value. Update `scripts/ci-impact-workflow.test.mjs` to test the single job.

In `.github/workflows/release.yml`, remove explicit `BIFROST_MCP_RMCP=on` values. Update `scripts/release-promotion-workflow.test.mjs`.

In `scripts/smoke-agent-plugin-release.mjs`, remove the old-host timing branch. Always send the first tool request before awaiting `roots/list`, which is the RMCP sequence.

In `scripts/mcp-replay.py`, remove the `rmcp|legacy` option, selector environment assignment, dual-stack wording, and stack-difference reporting. Keep the scenario input, Roots capability, cancellation, and timing reports.

In `src/benchmark/mcp_session.rs`, remove `MCP_RMCP_HOST_ENV`, `BIFROST_BENCHMARK_MCP_RMCP`, and all host-selection code. Always validate RMCP transport timings and build identity. In `tests/suite_mcp_cli/bifrost_benchmark_run.rs`, remove the legacy rollback case. Keep the default ambient-environment stripping test when it still proves harness isolation.

In `docs/src/content/docs/mcp.md`, remove rollback-host instructions. Describe RMCP as the sole host and retain its supported protocol revisions and Roots behavior.

Run these source checks from the repository root:

    rg -n 'BIFROST_MCP_RMCP|BIFROST_BENCHMARK_MCP_RMCP|rmcp_host_enabled' .
    node --test scripts/ci-impact-workflow.test.mjs scripts/release-promotion-workflow.test.mjs

The search must return no production, test, workflow, script, or documentation occurrences. The Node tests must pass.

### Milestone 5: Validate the completed sole host

Run `cargo fmt` first. Run the focused featureless tests again. Then run the full MCP contract suite because issue acceptance includes all toolsets and RMCP protocol paths.

Before an NLP build, inspect free disk space. Do not start another NLP build in a sibling worktree. Use the managed target helper so its target directory is removed after the command.

From the repository root, run:

    df -h .
    scripts/with-isolated-cargo-target.sh cargo test -p brokk-bifrost-mcp --features nlp
    cargo test --test suite_mcp_cli -- bifrost_benchmark_run

The MCP suite must pass. The benchmark harness test must pass with only RMCP behavior. If a real interactive benchmark is configured in the current checkout, run its existing documented command with an RMCP-only session. Record the report path and duration in this plan.

Before completing code changes, run the installed Bifrost policy check. Select `bifrost.code-smells` and every executable repository policy root. A `finding` needs review. An `unreliable` result fails validation.

## Concrete Steps

Work from `/Users/dave/.codex/worktrees/1622/bifrost`.

1. Read the current function bodies before each edit. Start with `mcp_common.rs:368`, `mcp_common.rs:394`, and `rmcp_host.rs:1812`.
2. Implement Milestone 1. Run its focused CLI tests.
3. Implement Milestone 2. Run `cargo fmt` and `cargo check -p brokk-bifrost-mcp`.
4. Implement Milestone 3. Run its MCP contract tests.
5. Implement Milestone 4. Run the selector search and Node workflow tests.
6. Run Milestone 5. Record command results in `Artifacts and Notes`.
7. Update `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` after each milestone.

## Validation and Acceptance

Acceptance requires these observable results.

- `bifrost --mcp workspace` starts one RMCP server with no host selector.
- A rootless, Roots-capable client can bind an allowed workspace and run a tool.
- A rootless client cannot bind an unauthorized workspace.
- Cancellation, `run_policy`, and transport timing contracts pass in `bifrost_mcp_server`.
- `analyze_diff` keeps its trusted object directory in standard MCP mode.
- CI and release smoke scripts no longer set or test a host selector.
- `rg` finds no selector name or old selector helper.
- The full MCP contract suite and the interactive benchmark checks pass.

## Idempotence and Recovery

All edits are source changes. Re-running `cargo fmt`, tests, Node tests, and `rg` checks is safe.

If deletion breaks RMCP imports, restore only the named shared item. Do not restore old JSON-RPC framing, dispatch, Roots, cancellation, or writer code. If the full MCP suite needs an NLP build, stop other NLP builds and use the isolated target helper.

Do not change a release version, tag, publish, or deploy for this issue. Do not commit unrelated files.

## Artifacts and Notes

Pre-change evidence:

    mcp_common.rs:396 reads BIFROST_MCP_RMCP.
    mcp_common.rs:423 starts the handwritten server path.
    rmcp_host.rs:1812 starts the RMCP standard server.
    rmcp_host.rs:1842 starts the named-workspace RMCP server.
    src/bin/bifrost.rs:703 validates and forwards diff_snapshot_object_dir.

Add concise test output and benchmark report paths here during implementation.

## Interfaces and Dependencies

The final standard entry must retain this behavior. The exact parameter order may change only with every caller updated.

    pub fn run_stdio_server_with_build_identity(
        root: Option<PathBuf>,
        render_options: McpRenderOptions,
        spec: &McpServerSpec,
        diff_snapshot_object_dir: Option<PathBuf>,
        build_identity: &str,
    ) -> Result<(), String>

The function must be backed by RMCP after this change. It must create `SearchToolsService` with the same root and watcher choices. When the optional directory exists, it must call `with_diff_snapshot_object_dir` before serving.

`run_named_workspace_stdio_server_with_build_identity` remains the named-workspace interface. It does not accept a snapshot directory because the CLI rejects that combination.

Plan revision: 2026-08-07 07:43Z. Added the required RMCP port for `diff_snapshot_object_dir` after the source audit found the old host owned it.

Plan revision: 2026-08-07 07:43Z. Recorded the completed RMCP object-directory port before host removal.
