# Make analyzer-cache GC owned by the workspace lifetime

This ExecPlan is a living document. Maintain it under `.agents/PLANS.md`.

## Purpose / Big Picture

Closing a Python `SearchToolsClient` must mean no Bifrost task can subsequently write under that client's workspace. Today an analyzer-cache garbage-collection (GC) thread is detached from the workspace and can create or update `.brokk/bifrost_cache.db` after the client returns from `close()`. After this change, shutdown waits for any GC task belonging to the workspace, so callers can immediately delete a temporary repository safely while normal long-lived workspaces retain asynchronous GC.

## Progress

- [x] (2026-07-11 03:31Z) Identified the CI failure and traced it to the detached analyzer GC task.
- [x] (2026-07-11 03:35Z) Add workspace-owned GC task coordination and make shutdown join the tasks.
- [ ] Cover the close/delete race through the existing Python client regression; local native rebuild output was interrupted by Cargo target locks, so fresh CI remains the cross-platform proof.
- [ ] Run full Python tests and fresh GitHub Actions.

## Surprises & Discoveries

- Observation: Python Linux and Windows fail only after test assertions succeed, while deleting a `TemporaryDirectory`.
  Evidence: `test_most_relevant_files_explicit_none_pins_uniform_git_weighting` reports `OSError: [Errno 39] Directory not empty` on cleanup.
- Observation: `src/analyzer/store/gc.rs` starts a detached thread after every persisted analyzer build or update. The task opens the cache database by path and does not belong to `SearchToolsService`.
  Evidence: `maybe_gc_in_background` uses `std::thread::Builder::spawn` and drops the handle.

## Decision Log

- Decision: Preserve asynchronous GC, but make it owned by the shared persisted analyzer store context and join it on final context drop.
  Rationale: Running GC synchronously would add maintenance latency to workspace builds; disabling persistence for Python would hide the product bug. A workspace-owned coordinator keeps the request path asynchronous and gives `close()` a real completion boundary.
  Date/Author: 2026-07-11 / Codex
- Decision: Do not modify Python temporary-directory cleanup or weaken its assertion.
  Rationale: The test correctly exposes Bifrost writing after its public close operation returns.
  Date/Author: 2026-07-11 / Codex

## Outcomes & Retrospective

The implementation preserves best-effort asynchronous GC during analysis but establishes a shutdown boundary: the final `AnalyzerStoreContext` drop joins all scheduled GC tasks. `cargo fmt`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --features nlp --test analyzer_store_reconcile` pass locally. The existing Python cleanup test is the end-to-end acceptance test because it creates a git repository, starts the default persisted Python service, closes it, and immediately deletes the workspace.

## Context and Orientation

`SearchToolsService` in `src/searchtools_service.rs` owns a `WorkspaceSession`, which owns an `Arc<WorkspaceAnalyzer>`. Closing the service removes that session. Persisted `WorkspaceAnalyzer` instances create an `AnalyzerStoreContext` in `src/analyzer/tree_sitter_analyzer.rs`; every language analyzer in that workspace shares the context's `Arc<AnalyzerStore>`.

`src/analyzer/tree_sitter_analyzer.rs` currently invokes `src/analyzer/store/gc.rs::maybe_gc_in_background` after persisted builds and updates. The function launches a detached thread. GC is cache maintenance: it scans git-reachable content and removes stale SQLite rows. It may legitimately write the database, but it must not outlive its workspace.

`python_tests/test_searchtools_client.py` uses `SearchToolsClient` as a context manager. Its `__exit__` calls native `SearchToolsService::close`, then Python deletes the temporary root. The regression test builds a small git repository and calls `most_relevant_files`; that path creates the persisted analyzer cache and schedules GC.

## Plan of Work

In `src/analyzer/store/gc.rs`, replace the detached helper with an `AnalyzerGcCoordinator` held in an `Arc`. It will keep a mutex-protected list of active `JoinHandle<()>` values and a closing flag. Its `schedule` method will ignore in-memory stores, reap completed tasks, and start one best-effort GC task using a weak reference to the coordinator. The task must check the closing flag before touching the repository or database. `Drop` for the coordinator will set closing, drain the handles, and join each one. Therefore destruction of the last workspace store context blocks until all its maintenance writes are complete.

In `src/analyzer/tree_sitter_analyzer.rs`, add `gc: Arc<AnalyzerGcCoordinator>` to `AnalyzerStoreContext`, create it in `store_context`, and call `store_context.gc.schedule(project.root(), Arc::clone(&store_context.store))` at the existing build/update locations. This preserves one coordinator across every language delegate and across incremental analyzer snapshots, instead of spawning unrelated tasks per language.

Add a deterministic test beside the GC implementation. Use the existing git test helpers to create a persisted temporary repository, force GC eligibility through the existing tuning guard, schedule a task, release the final coordinator, then remove the temporary root. The test must prove the coordinator's drop waits for maintenance rather than relying on a timing sleep. Keep the Python test unchanged and use it as the end-to-end regression coverage.

## Concrete Steps

From `/Users/dave/.codex/worktrees/42d7/bifrost`:

1. Implement the coordinator and connect it to `AnalyzerStoreContext` and the two existing scheduling sites.
2. Run `cargo fmt --all`.
3. Run `cargo test --features nlp analyzer::store::gc` and the focused Python client test through `scripts/test_python.sh` or the equivalent `uv run --python 3.12 --with maturin python -m unittest python_tests.test_searchtools_client.SearchToolsClientTest.test_most_relevant_files_explicit_none_pins_uniform_git_weighting`.
4. Run `cargo clippy --all-targets --all-features -- -D warnings`, then `scripts/test_python.sh`.
5. Push and wait for all Rust and Python CI matrix jobs.

Expected focused Python result:

    Ran 1 test in ...
    OK

## Validation and Acceptance

The exact Python test that previously failed during `TemporaryDirectory` cleanup passes repeatedly on the local machine. The full Python suite passes. The Rust test proves coordinator destruction joins outstanding GC work before the temporary repository can be removed. GitHub Actions reports every Rust and Python matrix job successful.

## Idempotence and Recovery

The coordinator is best-effort maintenance: a GC error remains non-fatal, as it is today. Re-running a failed test is safe because every test owns a unique temporary repository. If a task cannot start, preserve the existing behavior of skipping maintenance rather than failing analysis.

## Interfaces and Dependencies

In `src/analyzer/store/gc.rs`, introduce a crate-private coordinator with this externally used surface:

    pub(crate) struct AnalyzerGcCoordinator;
    impl AnalyzerGcCoordinator {
        pub(crate) fn schedule(self: &Arc<Self>, workspace_root: &Path, store: Arc<AnalyzerStore>);
    }

Its `Drop` implementation is the shutdown contract. `AnalyzerStoreContext` must retain `Arc<AnalyzerGcCoordinator>` so all persisted language analyzers share the same task ownership boundary.

Plan created 2026-07-11 to replace detached analyzer GC after Python CI exposed a close/delete race.

Plan updated 2026-07-11 after implementing workspace-owned task coordination; CI remains required for the Python native-module regression.
