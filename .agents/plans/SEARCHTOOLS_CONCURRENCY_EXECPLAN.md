# Concurrent Python SearchTools sessions

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with [.agent/PLANS.md](../../.agent/PLANS.md).

## Purpose / Big Picture

After this change, one `bifrost_searchtools.SearchToolsClient` can be shared by multiple Python threads and issue concurrent analyzer-backed requests. Python will still expose the same synchronous API, but Rust will no longer serialize all calls through one mutex. Each request will acquire an immutable `WorkspaceAnalyzer` snapshot and run against that snapshot, while later watcher updates or refreshes publish a new snapshot without mutating snapshots already in use.

## Progress

- [x] (2026-06-02) Confirmed the current bottleneck: Python holds a request-wide `_lock`, PyO3 holds `Mutex<Option<SearchToolsService>>`, and `SearchToolsService` requires `&mut self`.
- [x] (2026-06-02) Chosen implementation direction: make `SearchToolsService` internally synchronized with one `RwLock<Option<WorkspaceSession>>`, keep `ProjectChangeWatcher` uniquely owned by the session, and clone only `Arc<WorkspaceAnalyzer>` per query.
- [x] (2026-06-02) Refactored `SearchToolsService` methods to take `&self`, split query dispatch from lifecycle mutation, and publish snapshots through `WorkspaceSession`.
- [x] (2026-06-02) Removed the Python request-wide lock while preserving lazy startup and close safety.
- [x] (2026-06-02) Added Rust and Python concurrency coverage.
- [x] (2026-06-02) Ran formatting, clippy, focused Rust service tests, and Python tests.

## Surprises & Discoveries

- Observation: the analyzer core already has snapshot semantics.
  Evidence: `WorkspaceAnalyzer::update` and `update_all` return new values, and tree-sitter analyzer state is held behind `Arc<AnalyzerState>`.

- Observation: service-level snapshot consistency is currently hidden by mutable service ownership.
  Evidence: `SearchToolsService::call_tool_output` calls `prepare_for_call()` and then runs the tool while holding `&mut self`.

## Decision Log

- Decision: use one `RwLock<Option<WorkspaceSession>>` instead of a separate update mutex.
  Rationale: the watcher and workspace snapshot must stay root-consistent. Holding the session write lock while rebuilding blocks new request startup but not already-running queries, and avoids stale-builder publication races.
  Date/Author: 2026-06-02 / Codex + user

- Decision: clone only `Arc<WorkspaceAnalyzer>` per request; never clone `ProjectChangeWatcher`.
  Rationale: the watcher owns OS watcher state and pending-change drainage. It should remain uniquely owned and be replaced only on `activate_workspace`.
  Date/Author: 2026-06-02 / Codex + user

## Outcomes & Retrospective

Implemented. `SearchToolsService` now synchronizes its active session internally, query calls clone an `Arc<WorkspaceAnalyzer>` and run outside the session lock, and Python no longer serializes full native calls. The `ProjectChangeWatcher` remains uniquely owned by `WorkspaceSession`; only the analyzer snapshot is cloned per request.

Validation passed:

- `cargo test --test searchtools_service`
- `scripts/test_python.sh`
- `cargo fmt --check`
- `cargo clippy --all-targets --all-features -- -D warnings`

## Context and Orientation

The Python package lives in `bifrost_searchtools/` and calls the PyO3 module in `src/python_module.rs`. The shared service lives in `src/searchtools_service.rs` and is used by both the Rust MCP server and the Python native extension. The MCP server remains Rust-native; this plan changes only service synchronization and the Python wrapper’s request locking.

## Plan of Work

Refactor `SearchToolsService` to store:

```rust
pub struct SearchToolsService {
    session: RwLock<Option<WorkspaceSession>>,
    update_strategy: UpdateStrategy,
}

struct WorkspaceSession {
    snapshot: Arc<WorkspaceAnalyzer>,
    watcher: Option<ProjectChangeWatcher>,
}
```

Public service call methods should take `&self`. Normal query calls should briefly take the session write lock, apply pending watcher deltas if any, clone `Arc<WorkspaceAnalyzer>`, drop the lock, and then run the query. Lifecycle calls keep using the same session lock: `refresh` replaces `snapshot`, `activate_workspace` replaces the whole `WorkspaceSession`, and `close` clears it.

Update PyO3 so `SearchToolsNativeSession` owns `Option<SearchToolsService>` only for lifecycle closure, not for request serialization. Remove Python’s request-wide `_lock`; keep a lifecycle lock around lazy startup and close.

## Validation and Acceptance

Acceptance is behavioral:

- Multiple Rust threads can call one `Arc<SearchToolsService>` concurrently and all receive valid JSON results.
- Multiple Python threads can share one `SearchToolsClient` and run mixed read-only tools without transport errors.
- Post-close calls still raise `SearchToolsError`.
- Existing MCP and Python result shapes remain unchanged.
