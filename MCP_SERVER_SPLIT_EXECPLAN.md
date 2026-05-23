# Split MCP searchtools server into core, extended, and slopcop modes

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document is maintained in accordance with [.agent/PLANS.md](/home/jonathan/Projects/bifrost/.agent/PLANS.md).

## Purpose / Big Picture

After this change, `bifrost` can start three separate MCP stdio servers instead of one monolith: `core`, `extended`, and `slopcop`. Existing `--server searchtools` callers keep working and still see the full tool union. A human can verify the split by starting each mode, calling `tools/list`, and observing that each server publishes only its assigned tool bucket while `searchtools` still exposes everything.

## Progress

- [x] (2026-05-23 20:05Z) Confirmed the existing MCP transport lived entirely in `src/mcp_server.rs`, with one stdio loop and one `tools/list` registry.
- [x] (2026-05-23 20:18Z) Designed the split so `SearchToolsService` remains the single execution backend and only the MCP registry/transport layer changes.
- [x] (2026-05-23 20:34Z) Replaced `src/mcp_server.rs` with `src/mcp_common.rs`, `src/mcp_core.rs`, `src/mcp_extended.rs`, and `src/mcp_slopcop.rs`, keeping `searchtools` as a compatibility aggregate.
- [x] (2026-05-23 20:41Z) Updated `src/bin/bifrost.rs`, crate exports, README, and MCP integration tests for the new server modes.
- [ ] Run focused MCP tests plus `cargo fmt --check` and `cargo clippy --all-targets --all-features -- -D warnings`, then fix any regressions they expose.

## Surprises & Discoveries

- Observation: the existing MCP file already kept all business logic in `SearchToolsService`, so the server split does not need any analyzer or tool implementation refactor.
  Evidence: `src/mcp_server.rs` only built descriptors, parsed JSON-RPC, and forwarded to `SearchToolsService::call_tool_output(...)`.

## Decision Log

- Decision: keep `--server searchtools` as the compatibility mode and make it expose the full tool union.
  Rationale: tests and README already treat `searchtools` as the stable entrypoint, so preserving that contract avoids unnecessary downstream breakage.
  Date/Author: 2026-05-23 / Codex

- Decision: introduce `src/mcp_common.rs` as the only place that knows about the JSON-RPC loop and MCP response shaping.
  Rationale: the split is mostly a registry partition. Centralizing the transport avoids code drift across the new servers.
  Date/Author: 2026-05-23 / Codex

- Decision: enforce subset boundaries in the MCP layer by checking each server spec's allowed tool-name slice before forwarding to `SearchToolsService`.
  Rationale: that preserves one backend while still making subset servers reject out-of-bucket tool calls with MCP tool errors.
  Date/Author: 2026-05-23 / Codex

## Outcomes & Retrospective

The refactor is implemented but not yet validated in this document revision. The intended outcome is a DRY split of the MCP tool surface with unchanged payload semantics and a preserved `searchtools` compatibility path. Remaining work is limited to running the checks and resolving any compile or lint fallout.

## Context and Orientation

`src/bin/bifrost.rs` is the CLI entrypoint for the `bifrost` binary. Before this change it only recognized `--server searchtools` and `--server lsp`. `src/mcp_server.rs` previously held the full MCP transport loop, tool descriptors, and tool-call forwarding logic. `src/searchtools_service.rs` is the shared backend that decodes JSON arguments and executes every tool against the analyzer workspace. `tests/bifrost_mcp_server.rs` is the end-to-end stdio integration test that spawns the binary and speaks JSON-RPC over pipes.

In this repository, an MCP server is a process that reads one JSON-RPC request per stdin line and writes one JSON-RPC response per stdout line. The split in this plan is only about which tools each process publishes in `tools/list` and accepts in `tools/call`; it does not change the tool implementations themselves.

## Plan of Work

Create `src/mcp_common.rs` and move the JSON-RPC loop, response helpers, schema helpers, and `McpRenderOptions` there. Define a small `McpServerSpec` that provides the instructions string, the allowed tool names, and a function that builds the descriptor list. Update the shared `tools/call` handler so it first rejects tools not present in the spec before forwarding allowed calls into `SearchToolsService`.

Create `src/mcp_core.rs`, `src/mcp_extended.rs`, and `src/mcp_slopcop.rs`. Each module should expose one stdio runner function and one descriptor builder. `src/mcp_core.rs` also keeps `run_searchtools_stdio_server(...)` as the compatibility aggregate by concatenating the descriptor lists from the three buckets and exposing the union of their allowed tool names.

Update `src/lib.rs` and `src/bin/bifrost.rs` to export and dispatch the new modules. Update `tests/bifrost_mcp_server.rs` so it still validates the full `searchtools` path, and add coverage for the three subset modes' `tools/list` boundaries and out-of-registry tool errors. Update the README so users can discover the new modes and understand that `searchtools` remains the full compatibility surface.

## Concrete Steps

From the repository root:

    cargo test --test bifrost_mcp_server
    cargo fmt --check
    cargo clippy --all-targets --all-features -- -D warnings

Expected successful behavior:

    the MCP integration test passes
    rustfmt reports no diff needed
    clippy reports no warnings

## Validation and Acceptance

Acceptance is that:

1. `./target/debug/bifrost --root /path/to/project --server core` starts and `tools/list` omits `get_file_contents` and `report_secret_like_code`.
2. `./target/debug/bifrost --root /path/to/project --server extended` starts and `tools/list` includes `get_file_contents` but omits `refresh` and `report_secret_like_code`.
3. `./target/debug/bifrost --root /path/to/project --server slopcop` starts and `tools/list` includes `report_secret_like_code` but omits `get_summaries`.
4. `./target/debug/bifrost --root /path/to/project --server searchtools` still starts and exposes the full current union.
5. `tools/call` for an out-of-bucket tool returns an MCP tool error payload with `isError: true` rather than executing.

## Idempotence and Recovery

The refactor is additive and repeatable. Re-running the validation commands is safe. If one subset server exposes the wrong tool list, the safest recovery path is to compare its `*_TOOL_NAMES` slice with its descriptor builder and the `searchtools` aggregate list in `src/mcp_core.rs`.

## Artifacts and Notes

The most important implementation detail is that subset enforcement happens in the MCP transport layer, not in `SearchToolsService`. This keeps one backend and one set of JSON-decoding rules while allowing multiple published tool surfaces.

## Interfaces and Dependencies

In `src/mcp_common.rs`, define:

    pub struct McpRenderOptions {
        pub render_line_numbers: bool,
    }

    pub struct McpServerSpec {
        pub instructions: &'static str,
        pub tool_names: &'static [&'static str],
        pub tool_descriptors: fn() -> Vec<serde_json::Value>,
    }

    pub fn run_stdio_server(
        root: std::path::PathBuf,
        render_options: McpRenderOptions,
        spec: &McpServerSpec,
    ) -> Result<(), String>;

In the server modules, define:

    pub fn run_core_stdio_server(...)
    pub fn run_extended_stdio_server(...)
    pub fn run_slopcop_stdio_server(...)
    pub fn run_searchtools_stdio_server(...)

Revision note: this plan was added during implementation because the repository instructions require an ExecPlan for significant refactors, and this change materially restructures the MCP entrypoint layout.
