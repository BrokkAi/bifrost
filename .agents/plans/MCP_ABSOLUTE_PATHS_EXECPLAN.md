# Normalize absolute MCP path arguments

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with `.agent/PLANS.md` in this repository.

## Purpose / Big Picture

Bifrost's MCP servers currently describe most file inputs as project-relative paths. MCP clients often hold absolute editor or filesystem paths, so callers either have to manually strip the workspace prefix or receive misleading `not_found`-style results. After this change, MCP `tools/call` requests can pass absolute paths that point inside the active workspace. Bifrost will convert them to the project-workspace-relative paths expected by the existing tools. If an absolute path points outside the active workspace, the MCP tool call will return an explicit tool error instead of pretending the path was merely absent from the project.

This change applies only at the MCP JSON-RPC boundary. Direct Rust and Python calls through `SearchToolsService` keep their current argument behavior.

## Progress

- [x] (2026-05-24 09:50Z) Inspected `src/mcp_common.rs`, `src/searchtools_service.rs`, and the tool parameter structs to identify which MCP arguments are paths, globs, symbols, regexes, or other strings.
- [x] (2026-05-24 10:15Z) Added MCP-only normalization helpers in `src/mcp_common.rs` and exposed the active workspace root from `SearchToolsService`.
- [x] (2026-05-24 10:20Z) Updated MCP tool descriptions for path-like fields to advertise absolute in-workspace path support.
- [x] (2026-05-24 10:35Z) Added focused unit tests and MCP subprocess integration tests for absolute literal paths, absolute globs, outside-workspace errors, parent-directory escapes, and workspace switching.
- [x] (2026-05-24 10:50Z) Ran final formatting, focused MCP/unit tests, and clippy. `cargo test --test searchtools_service` still has one unrelated rendered-text assertion failure in `python_boundary_returns_canonical_rendered_text_payload`.

## Surprises & Discoveries

- Observation: The shared `SearchToolsService` is used by MCP and by Python-facing tests.
  Evidence: `src/mcp_common.rs` calls `SearchToolsService::call_tool_output`, while `python_tests/test_searchtools_client.py` and `tests/searchtools_service.rs` exercise direct service behavior. The user's requested scope is MCP-only, so normalization belongs in `src/mcp_common.rs`, not in every tool implementation.

- Observation: Some path-like fields are intentionally also glob fields.
  Evidence: `file_patterns`, `targets`, `filepath`, and `find_filenames.patterns` accept glob syntax, while fields like `symbols`, `fq_names`, regex `patterns`, `revision`, and `xpath` are not filesystem paths and must not be normalized.

- Observation: Non-existing absolute paths need lexical parent-directory handling.
  Evidence: An input such as `/workspace/../outside/Missing.java` cannot be canonicalized because it may not exist, but simple prefix stripping would otherwise produce `../outside/Missing.java`. The normalizer now collapses `.` and `..` after prefix stripping and rejects paths that escape above the workspace.

- Observation: Full direct service validation is blocked by an unrelated rendered-text expectation.
  Evidence: `cargo test --test searchtools_service` passes 21 tests but fails `python_boundary_returns_canonical_rendered_text_payload` because the rendered source output now uses a `## A.method2` heading plus a `- Location: A.java:8..10` line, while the test expects the older inline heading text `A.method2 (A.java:8..10)`.

- Observation: Clippy surfaced an unrelated existing warning.
  Evidence: `cargo clippy --all-targets --all-features -- -D warnings` initially failed on `src/searchtools_render.rs` for consecutive `str::replace` calls. The code now uses `replace(['\n', '\r'], " ")`, and clippy passes.

## Decision Log

- Decision: Normalize arguments in `src/mcp_common.rs` after the MCP tool-name allow-list check and before service dispatch.
  Rationale: This keeps the behavior MCP-only, centralizes workspace-boundary validation, and avoids duplicating path normalization in every tool.
  Date/Author: 2026-05-24 / Codex

- Decision: Return outside-workspace absolute paths as MCP tool errors (`isError: true`) instead of JSON-RPC invalid-params errors.
  Rationale: The user selected this behavior during planning, and it matches the existing convention that unknown tools outside a server registry are represented as tool-level errors.
  Date/Author: 2026-05-24 / Codex

- Decision: Convert absolute globs lexically when they are rooted inside the active workspace.
  Rationale: Glob paths may include wildcards that cannot be canonicalized as real files, but clients still benefit from passing editor-rooted absolute glob strings such as `/repo/src/**/*.rs`.
  Date/Author: 2026-05-24 / Codex

- Decision: Keep relative path arguments untouched in MCP normalization.
  Rationale: Existing tools already apply their own normalization and validation for relative paths. The new behavior is specifically for absolute paths, so preserving relative inputs reduces compatibility risk.
  Date/Author: 2026-05-24 / Codex

## Outcomes & Retrospective

The MCP path normalization feature is implemented. MCP `tools/call` now converts absolute in-workspace path arguments to relative paths before service dispatch, rejects outside-workspace absolute paths as tool-level errors, and keeps direct service behavior unchanged. Focused unit and MCP integration tests pass. The remaining known gap is the unrelated `tests/searchtools_service.rs` rendered-text assertion described in `Surprises & Discoveries`.

## Context and Orientation

The MCP server code lives in `src/mcp_common.rs`. It reads JSON-RPC messages, validates the requested tool against the selected MCP server's registry, and forwards the raw `arguments` JSON to `SearchToolsService::call_tool_output`.

`SearchToolsService` lives in `src/searchtools_service.rs`. It owns the active `WorkspaceAnalyzer`, supports `activate_workspace`, and dispatches decoded parameters to tool implementations. The active workspace root is available through `self.workspace.analyzer().project().root()`, but there is not currently a public accessor for the MCP layer.

Most tool implementations already expect project-relative paths. For example, `get_file_contents` uses `filenames`, code-quality tools use `file_paths`, `most_relevant_files` uses `seed_files`, `get_git_log` uses optional `path`, and `jq`/XML tools use `filepath`. Other strings are not paths: symbol names, regex patterns, commit revisions, jq filters, XPath expressions, and fully qualified names must pass through unchanged.

## Plan of Work

First, add a small public accessor on `SearchToolsService` that returns the current active workspace root as `&Path`. This lets `src/mcp_common.rs` use the same root that tools will query, including after `activate_workspace`.

Second, add MCP-only normalization helpers in `src/mcp_common.rs`. The helper takes a tool name, an arguments JSON object, and the active workspace root. It mutates only the path-like fields for that specific tool. If a string is absolute and inside the workspace, replace it with a normalized slash-separated relative string. If an absolute string is outside the workspace, return a message that `handle_tool_call` wraps with `tool_error_result`. If the path is relative, leave the tool's existing normalization behavior intact except for preserving current JSON shape.

Third, update path parameter descriptions in `src/mcp_common.rs`, `src/mcp_extended.rs`, and `src/mcp_slopcop.rs` where the MCP tool schema explicitly says "Project-relative" so users know absolute in-workspace paths are allowed.

Fourth, add tests. Unit tests in `src/mcp_common.rs` should cover literal absolute paths, absolute globs, outside paths, nonexistent inside paths, and untouched non-path fields. Integration tests in `tests/bifrost_mcp_server.rs` should prove end-to-end MCP behavior for `get_file_contents`, a summary or symbol listing tool, a glob-style tool, an outside-workspace error, and root changes after `activate_workspace`.

## Validation

Run these commands from `/home/jonathan/Projects/bifrost`:

    cargo fmt --check
    cargo test --test bifrost_mcp_server
    cargo test --test searchtools_service
    cargo clippy --all-targets --all-features -- -D warnings

The relevant acceptance result is that MCP calls using absolute paths under the workspace return normal successful tool results with relative paths in output, while an absolute path outside the workspace returns a `tools/call` result containing `isError: true` and an explicit outside-workspace message.
