# Add Direct `bifrost --tool` Invocation

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with `.agent/PLANS.md`.

## Purpose / Big Picture

Today `bifrost` has a merge conflict in `src/bin/bifrost.rs` between the default-MCP-server CLI behavior from `origin/master` and an in-progress `--summarize` one-shot mode. After this change, users will be able to keep the current MCP server startup defaults and also run any existing search tool directly from the terminal with `bifrost --tool TOOL_NAME --args '{"...": ...}'`. They should be able to see it working by invoking a tool like `get_summaries` or `get_file_contents` once, getting the same rendered text they would normally see through MCP, and reusing the same absolute-path normalization rules that MCP already enforces.

## Progress

- [x] (2026-06-08T16:04:56Z) Read `.agent/PLANS.md`, inspected the dirty worktree, confirmed `src/bin/bifrost.rs` is the only merge-conflicted file, and verified the conflict is between default server startup and an in-progress `--summarize` path.
- [x] (2026-06-08T16:04:56Z) Inspected `src/mcp_common.rs`, `src/searchtools_service.rs`, `src/mcp_registry.rs`, `README.md`, and the current test suite to confirm that direct tool invocation can reuse `SearchToolsService` and that MCP currently owns the path-normalization logic.
- [x] (2026-06-08T16:14:44Z) Added `src/tool_arguments.rs`, moved MCP path-normalization logic into the shared helper, and switched `src/mcp_common.rs` to call that helper.
- [x] (2026-06-08T16:14:44Z) Replaced the conflicted `src/bin/bifrost.rs` contents with a direct `--tool` mode backed by `SearchToolsService`, preserved the current default MCP server behavior, and removed the abandoned `--summarize` path.
- [x] (2026-06-08T16:14:44Z) Added `tests/bifrost_tool_cli.rs`, updated README/help text, ran `cargo fmt`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo test --test bifrost_tool_cli`, `cargo test --test bifrost_mcp_server`, and a full `cargo test` pass.

## Surprises & Discoveries

- Observation: the existing MCP stdio transport is line-delimited JSON-RPC, not `Content-Length` framed I/O.
  Evidence: `src/mcp_common.rs` reads `stdin.lock().lines()` and writes one serialized JSON response per line.

- Observation: the direct service layer already exposes the exact abstraction needed for a one-shot CLI.
  Evidence: `SearchToolsService::call_tool_output` in `src/searchtools_service.rs` accepts `(name, arguments, render_options)` and returns either `ToolOutput::Text` or `ToolOutput::Structured { structured, rendered_text }`.

- Observation: `origin/master` documentation and tests already depend on `bifrost` defaulting to current working directory plus the `searchtools` server.
  Evidence: `README.md` states that default explicitly, and `tests/bifrost_mcp_server.rs` includes `bifrost_defaults_to_cwd_searchtools_server`.

- Observation: `get_summaries` does not render Markdown section headers in the direct CLI path; it prints the same concise ranged text that MCP returns in its `content[0].text`.
  Evidence: the first `tests/bifrost_tool_cli.rs` expectations had to be corrected from `## A.java` to `3..52: public class A`, and the rerun passed with that shape.

- Observation: some tools, such as `get_file_contents`, currently return structured data without a custom rendered-text payload, so direct CLI mode needs a JSON fallback to stay usable.
  Evidence: `tool_normalizes_absolute_paths_inside_workspace` initially failed because stdout was pretty-printed JSON containing `"path": "A.java"` rather than a Markdown/text renderer.

## Decision Log

- Decision: replace the in-progress `--summarize` feature with a general `--tool` one-shot CLI mode instead of trying to preserve both interfaces.
  Rationale: `--tool` covers the original human-readable summary use case while avoiding a one-off codepath that duplicates tool dispatch and rendering.
  Date/Author: 2026-06-08 / Codex

- Decision: invoke tools directly through `SearchToolsService` instead of spawning an MCP subprocess or sending MCP JSON-RPC to self.
  Rationale: the direct service path already exists, avoids transport overhead, and keeps CLI concerns separate from the wire protocol while still reusing the same underlying tool implementations.
  Date/Author: 2026-06-08 / Codex

- Decision: keep `--tool` arguments as inline JSON via `--args`, allow any tool name directly, and print rendered text by default.
  Rationale: those choices minimize CLI surface area, match the existing service/Python JSON-shaped API, and preserve the terminal-friendly behavior that motivated `--summarize`.
  Date/Author: 2026-06-08 / Codex

- Decision: fall back to pretty-printed structured JSON when a tool returns `ToolOutput::Structured` without `rendered_text`.
  Rationale: direct CLI mode must remain usable for file/text tools and any other structured-only outputs without inventing tool-specific renderers in the binary.
  Date/Author: 2026-06-08 / Codex

## Outcomes & Retrospective

Implementation outcome 2026-06-08: the merge conflict in `src/bin/bifrost.rs` is resolved in favor of a general `--tool` one-shot CLI plus the existing default MCP-server behavior. Shared argument normalization now lives in `src/tool_arguments.rs` and is reused by both MCP and the new CLI path. The new `tests/bifrost_tool_cli.rs` suite covers rendered summaries, line-number suppression, absolute-path normalization, outside-workspace rejection, unknown tools, invalid flag combinations, and help text. Validation succeeded with targeted tests, clippy, and a full `cargo test` run.

One worktree caveat remains external to this feature: the repository still contains unrelated staged benchmark-harness changes from the user’s existing work. To avoid sweeping those into an unrelated checkpoint, this pass only marked `src/bin/bifrost.rs` as resolved in the index and left the rest of the dirty worktree untouched.

## Context and Orientation

The `bifrost` binary has two relevant layers today. The first is the CLI entrypoint in `src/bin/bifrost.rs`, which decides whether to start the MCP server or some other top-level mode. The second is the reusable service layer in `src/searchtools_service.rs`, which owns workspace startup and dispatches named tool calls to analyzers, file tools, git tools, and code-quality tools. The MCP transport in `src/mcp_common.rs` sits on top of that service layer: it performs JSON-RPC parsing, enforces the active toolset from `src/mcp_registry.rs`, normalizes path-shaped arguments to workspace-relative slash paths, and then calls `SearchToolsService`.

The current conflict exists because one side of the merge added a `--summarize` mode directly in `src/bin/bifrost.rs` by constructing a `FileSetProject` and calling `get_summaries` manually, while the other side changed CLI defaults so plain `bifrost` starts the `searchtools` MCP server rooted at the current working directory. The plan for this work is to discard the ad hoc summary-specific path and replace it with a generic CLI tool runner that reuses the service layer and shared path normalization.

The main files involved are `src/bin/bifrost.rs` for argument parsing and top-level dispatch, `src/mcp_common.rs` for the normalization logic that must become shared, `src/lib.rs` for exporting any new helper module, and `tests/bifrost_mcp_server.rs` plus a new CLI-focused test file for regression coverage. `README.md` also needs updates because it currently documents only server mode defaults.

## Plan of Work

First, add a small shared module in the library for tool argument normalization. Move the absolute-path normalization functions and the tool-name-to-field mapping out of `src/mcp_common.rs` into that shared module without changing their semantics. The new module must accept a tool name, a JSON value of arguments, and the active workspace root, and it must return normalized arguments or the same error strings MCP already uses. `src/mcp_common.rs` should call this helper so existing MCP behavior stays stable.

Next, rewrite `src/bin/bifrost.rs` to resolve the merge conflict in favor of current server defaults plus a new direct `--tool` mode. Parse `--tool NAME` and optional `--args JSON` in the existing argument loop, reject invalid combinations such as `--tool` with `--server`, and keep `--root`, `--no-line-numbers`, `--help`, and `--version`. When `--tool` is present, canonicalize the root, normalize the JSON arguments against that root, call `SearchToolsService::new(root)` and then `call_tool_output`, and print rendered text when present. For structured results without rendered text, pretty-print the structured JSON so every tool remains usable from the terminal. When `--tool` is absent, keep the current behavior from `origin/master`: `--root` defaults to the current working directory, `--server` defaults to `searchtools`, and plain `bifrost` starts the MCP server.

Then, add direct CLI tests. These tests should launch `env!("CARGO_BIN_EXE_bifrost")` the same way the existing benchmark CLI tests do, rather than trying to simulate the internals. Cover a happy-path rendered summary call, `--no-line-numbers`, absolute in-workspace path normalization, outside-workspace rejection, invalid tool names, and the rejected `--tool` plus `--server` combination. Existing MCP tests should remain in place to prove the extraction did not change transport behavior.

Finally, update `README.md` and the binary help text so users can see both the default server mode and the new one-shot tool mode. Run `cargo fmt`, `cargo clippy --all-targets --all-features -- -D warnings`, and targeted or full tests as needed. Record any failures caused by unrelated dirty-worktree changes in this plan rather than hiding them.

## Concrete Steps

Work from the repository root:

    cd /home/jonathan/Projects/bifrost

Implement and validate in this order:

    cargo fmt
    cargo test --test bifrost_tool_cli
    cargo test --test bifrost_mcp_server
    cargo clippy --all-targets --all-features -- -D warnings

If focused tests pass and no unrelated worktree drift blocks it, optionally run:

    cargo test

Expected CLI proof after implementation:

    cargo run --bin bifrost -- --root tests/fixtures/testcode-java --tool get_summaries --args '{"targets":["A.java"]}'

Expected output should include a rendered summary for `A.java` and should not require starting an MCP session.

## Validation and Acceptance

Acceptance for this work is behavioral, not just structural. Plain `bifrost` must still start the `searchtools` MCP server rooted at the current working directory, as proven by the existing end-to-end MCP test. A user must also be able to run `bifrost --tool get_summaries --args '{"targets":["A.java"]}'` and receive human-readable summary text directly on stdout. Passing an absolute path inside the workspace to a file-oriented tool must succeed and surface a project-relative path in the result, while passing an absolute path outside the workspace must fail with the same rejection message used by MCP. `cargo fmt` and `cargo clippy --all-targets --all-features -- -D warnings` must pass before this work is considered complete.

## Idempotence and Recovery

These changes are source-only and can be re-applied safely. If the work stops midway, recover by ensuring `src/mcp_common.rs` and the new shared normalization module agree on the helper signature first, because every CLI and MCP path depends on that boundary. Do not revert unrelated dirty-worktree changes. If tests fail after the normalization extraction, rerun the direct CLI tests and `tests/bifrost_mcp_server.rs` first; together they isolate whether the regression is in the new CLI path or in preserved MCP behavior.

## Artifacts and Notes

The most important artifact before implementation is the current conflict shape in `src/bin/bifrost.rs`: one side introduces `--summarize` and manual `FileSetProject` handling, while the other side introduces optional `--root`, default `searchtools`, and a current-directory stderr notice. The implementation intentionally resolves that conflict by deleting the summary-specific branch and replacing it with a generic direct tool path that reuses `SearchToolsService`.

## Interfaces and Dependencies

The shared normalization helper should live in a library module exported by `src/lib.rs` so both `src/mcp_common.rs` and `src/bin/bifrost.rs` can use it. The stable interface that must exist at the end of this work is:

    pub fn normalize_tool_arguments(
        tool_name: &str,
        arguments: serde_json::Value,
        workspace_root: &std::path::Path,
    ) -> Result<serde_json::Value, String>;

`src/bin/bifrost.rs` must call `brokk_bifrost::SearchToolsService::new(root)` and then:

    SearchToolsService::call_tool_output(
        &self,
        name: &str,
        arguments: serde_json::Value,
        render_options: brokk_bifrost::searchtools_render::RenderOptions,
    ) -> Result<brokk_bifrost::ToolOutput, brokk_bifrost::SearchToolsServiceError>

The direct CLI path must not depend on `McpServerSpec`, JSON-RPC envelopes, or a subprocess loop. It depends only on the existing library service layer plus the extracted normalization helper.

Revision note: 2026-06-08 / Codex. Created this ExecPlan before implementation because `AGENTS.md` requires an ExecPlan for significant features or refactors, and this work both resolves an active merge conflict and changes the public `bifrost` CLI surface.
Revision note: 2026-06-08 / Codex. Updated the ExecPlan after implementation to record the final helper extraction, the direct `--tool` CLI shape, the structured-JSON fallback decision, and the passing validation commands.
