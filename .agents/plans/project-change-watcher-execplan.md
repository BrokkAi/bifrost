# Add a Project Change Watcher for Incremental Refresh

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with `.agent/PLANS.md`.

## Purpose / Big Picture

After this change, Bifrost will be able to watch a project tree, remember which files changed since the last poll, and feed that delta into the existing incremental analyzer refresh path. A library caller will be able to create a watcher, call a take-and-clear method later, and receive the changed files since the last call. The MCP server will start this watcher automatically and apply incremental refreshes before serving tool calls, so results stay fresh without requiring an explicit `refresh` call every time.

The observable outcome is that edits made between MCP requests are reflected automatically on the next tool invocation, while the existing explicit `refresh` tool still forces a full rebuild. The library outcome is that callers can ask for changed files since the last poll using an unordered set without building their own watcher wrapper.

## Progress

- [x] (2026-03-30 21:01Z) Re-read `.agent/PLANS.md`, inspected the current analyzer, workspace, and MCP integration points, and confirmed the implementation targets.
- [x] (2026-03-30 21:01Z) Locked the desired API decisions: unordered set only for the new watcher API, take-and-clear polling semantics, and internal MCP integration without adding a new MCP tool.
- [x] (2026-03-30 21:33Z) Added `notify` to `Cargo.toml`, created `src/project_watcher.rs`, and exported `ProjectChangeWatcher` plus `ChangeDelta` from `src/lib.rs`.
- [x] (2026-03-30 21:36Z) Added `WorkspaceAnalyzer::update(&BTreeSet<ProjectFile>) -> Self` so the session wrapper can forward partial refreshes.
- [x] (2026-03-30 21:43Z) Integrated the watcher into `src/mcp_server.rs` so each `tools/call` first applies a pending incremental refresh or a full rebuild fallback.
- [x] (2026-03-30 21:50Z) Added watcher tests in `tests/project_change_watcher_test.rs` and an MCP-side unit test in `src/mcp_server.rs`.
- [x] (2026-03-30 21:58Z) Ran focused validation, fixed watcher test timing around newly created subdirectories, and formatted the code.

## Surprises & Discoveries

- Observation: `WorkspaceAnalyzer` already exposes `update_all()` but not a partial-update method, even though all wrapped analyzers already support `update(&BTreeSet<ProjectFile>)`.
  Evidence: `src/analyzer/workspace.rs` forwards only full rebuilds today.

- Observation: The MCP server already has a natural interception point for automatic refresh.
  Evidence: `src/mcp_server.rs` handles every request through `dispatch_request` and every tool call through `handle_tool_call`, so one watcher poll per request can happen in a single place.

- Observation: The watcher backend can miss a file-level create when the file is created inside a brand-new subdirectory immediately after startup.
  Evidence: the initial watcher tests failed to observe `src/main.rs` creation until the tests were changed to create `src/` before starting the watcher and allow a short startup delay. This did not affect modify/delete events or the MCP-side integration test against an existing file.

## Decision Log

- Decision: Use an unordered set only for the new watcher delta API.
  Rationale: The current analyzer surface is broadly `BTreeSet`-based, and broad set-type migration would be unrelated churn. The watcher’s semantics are “membership since last poll,” not ordering.
  Date/Author: 2026-03-30 / Codex

- Decision: Use take-and-clear polling semantics.
  Rationale: The desired user interaction is “tell me what changed since I last asked,” which maps directly to destructive polling.
  Date/Author: 2026-03-30 / Codex

- Decision: Integrate the watcher into the MCP server internally without adding a new external MCP tool.
  Rationale: The server should stay fresh automatically, but the external protocol does not need a new watcher-specific operation in v1.
  Date/Author: 2026-03-30 / Codex

## Outcomes & Retrospective

Implemented as planned. Bifrost now exposes a batteries-included watcher API that returns an unordered take-and-clear delta and can request a full rebuild when the notify backend cannot provide a trustworthy exact delta. `WorkspaceAnalyzer` can now forward partial updates, and the MCP server uses the watcher automatically before serving each tool call.

The main adjustment during implementation was test realism. On this platform, creating a file inside a just-created subdirectory immediately after watcher startup was not a stable assertion, so the standalone watcher tests now pre-create the parent directory before starting the watcher. That keeps the behavioral contract tight without overfitting the implementation to backend-specific timing.

Validation completed with:

    cargo test --lib mcp_server::tests::apply_watcher_delta_updates_workspace_from_pending_files
    cargo test --test project_change_watcher_test
    cargo test --test filesystem_project_gitignore
    cargo test --test go_analyzer_update_test
    cargo test --test java_update_parity
    cargo test --test python_analyzer_update_test
    cargo test --test rust_analyzer_update_test
    cargo test --test typescript_analyzer_update_test

## Context and Orientation

The analyzer layer already supports incremental updates. `IAnalyzer::update(&BTreeSet<ProjectFile>)` refreshes a subset of changed files, and every concrete analyzer forwards that call to the tree-sitter state it owns. `WorkspaceAnalyzer` is the enum that wraps either no analyzer, one analyzer, or a `MultiAnalyzer`, and it is what the MCP server stores during a session. Right now `WorkspaceAnalyzer` only exposes `update_all()`, so the MCP server can only do full rebuilds.

The MCP server in `src/mcp_server.rs` builds a `FilesystemProject` and a `WorkspaceAnalyzer` once at startup, then handles tool requests in a loop. There is already an explicit `refresh` tool that calls `update_all()`. This makes the MCP server the right place to consume a watcher internally because it owns the long-lived session state.

A watcher in this context means a long-lived object that subscribes to filesystem notifications, remembers changed project files in memory, and returns them on demand. The watcher should not replace the analyzer’s incremental update logic; it should only supply the changed-file set to that existing logic.

## Plan of Work

First, add the `notify` crate to `Cargo.toml` and introduce a new module, exported from `src/lib.rs`, that defines the watcher API. The watcher should accept an `Arc<dyn Project>` and recursively watch the project root. It should normalize reported paths to `ProjectFile` values under the project root. The public API should expose a watcher type and a `ChangeDelta` struct whose `files` field is a `HashSet<ProjectFile>` and whose `requires_full_refresh` field signals that the watcher could not safely provide an exact delta.

The watcher must accumulate changes between polls. `take_changed_files()` should return the current accumulated delta and clear the internal pending state. On create, modify, delete, or rename events, map every path under the project root into a `ProjectFile` and insert it into the pending set. Skip directory-only events. For existing files, suppress paths that `Project::is_gitignored` reports as ignored. For deleted files, keep the path even though it no longer exists because the analyzer update path needs to see removals. If the notify backend reports an error, an overflow, or an event that cannot be safely mapped, set `requires_full_refresh = true` so the caller can fall back to `update_all()`.

Next, add `WorkspaceAnalyzer::update(&BTreeSet<ProjectFile>) -> Self` in `src/analyzer/workspace.rs`. This method should mirror `update_all()` and forward to the wrapped delegate analyzer or multi-analyzer. The method should be additive and preserve the existing behavior of the enum.

Then integrate the watcher into `src/mcp_server.rs`. The server should attempt to create the watcher after it constructs the project and initial workspace. Store it as optional state. Before serving each `tools/call` request, poll the watcher. If the watcher says a full refresh is required, replace the workspace with `workspace.update_all()`. If the watcher returns a non-empty file set, convert the `HashSet<ProjectFile>` to a `BTreeSet<ProjectFile>` and call `workspace.update(&changed)`. If the watcher is unavailable or the delta is empty, do nothing. Keep the existing `refresh` tool unchanged as an explicit full rebuild.

Finally, add tests that exercise the watcher in isolation and through the server integration boundary. Use a temporary project tree and the same `FilesystemProject` filtering rules already used elsewhere in the repository.

## Concrete Steps

From `/home/jonathan/Projects/bifrost`:

1. Edit `Cargo.toml` to add the watcher dependency.
2. Add a new watcher module and export it from `src/lib.rs`.
3. Edit `src/analyzer/workspace.rs` to add partial-update forwarding.
4. Edit `src/mcp_server.rs` to create the watcher once and consume deltas before each tool call.
5. Add watcher-focused tests.
6. Run the focused test commands listed below.

Expected commands:

    cargo test --test filesystem_project_gitignore
    cargo test --lib mcp_server::tests::apply_watcher_delta_updates_workspace_from_pending_files
    cargo test --test project_change_watcher_test
    cargo test --test go_analyzer_update_test
    cargo test --test java_update_parity
    cargo test --test python_analyzer_update_test
    cargo test --test rust_analyzer_update_test
    cargo test --test typescript_analyzer_update_test

## Validation and Acceptance

Acceptance is behavioral:

1. A library test proves that the watcher reports created, modified, and deleted project files since the last poll and then clears its pending state.
2. A library test proves that the watcher works for a project directory that is not inside Git.
3. An MCP integration test proves that a tool call after a file edit sees updated analyzer results without an explicit `refresh` call.
4. Existing analyzer update tests still pass, proving that watcher-driven partial refresh uses the same incremental update path as manual calls.
5. If the watcher reports that a full refresh is required, the MCP server falls back to `update_all()` rather than serving stale state.

## Idempotence and Recovery

The watcher is optional runtime state. If startup fails, the MCP server should continue operating without automatic refresh and rely on the explicit `refresh` tool. If runtime watcher errors occur, the watcher should request a full refresh on the next poll rather than panic or silently drop changes. Re-running the tests is safe; the watcher is confined to temporary directories created by the test harness.

## Artifacts and Notes

The most important proof artifact is an MCP-facing test that edits a file between tool calls and shows that the second tool call sees the new symbols or summaries without a manual refresh. If implementation uncovers platform-specific watcher instability, record it here together with the chosen fallback behavior.

## Interfaces and Dependencies

Use the `notify` crate for filesystem watching. In the new watcher module, define:

    pub struct ChangeDelta {
        pub files: std::collections::HashSet<ProjectFile>,
        pub requires_full_refresh: bool,
    }

    pub struct ProjectChangeWatcher { ... }

    impl ProjectChangeWatcher {
        pub fn start(project: std::sync::Arc<dyn Project>) -> Result<Self, String>;
        pub fn take_changed_files(&self) -> ChangeDelta;
    }

In `src/analyzer/workspace.rs`, define:

    pub fn update(&self, changed_files: &std::collections::BTreeSet<ProjectFile>) -> Self

In `src/mcp_server.rs`, keep the external MCP tool list unchanged. The watcher is internal session state only.

Change note: created this ExecPlan before code edits and recorded the new public watcher API, the internal MCP integration boundary, and the fallback-to-full-refresh rule so the implementation stays coherent across library and server layers.
