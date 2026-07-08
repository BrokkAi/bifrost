# Rust Semantic Index Hardening

This ExecPlan is a living document. It follows `.agents/PLANS.md`, the canonical instructions for ExecPlans in this repository.

## Purpose / Big Picture

The semantic indexer should never look permanently hung when the worker has actually failed or when a slow first build is still making progress. After this change, panics inside the indexer worker become a structured failed status, sidecar startup fails promptly when readiness never arrives, and semantic status reports monotonic file-materialization counters that distinguish a slow build from a frozen one. The behavior is demonstrated by model-free Rust tests plus the repository's required formatting, lint, and test commands.

## Progress

- [x] (2026-07-07 00:00Z) Read `.agents/PLANS.md`, `src/nlp/indexer.rs`, `src/nlp/voyage_sidecar.rs`, `src/searchtools_service.rs`, `bifrost_searchtools/models.py`, and existing semantic tests.
- [x] (2026-07-07 00:00Z) Add panic-to-failed handling around `worker_loop` and a model-free panic test.
- [x] (2026-07-07 00:00Z) Add sidecar warmup failure and ready-timeout handling with a stub-script test.
- [x] (2026-07-07 00:00Z) Add materialization progress counters to status, Rust coverage, and Python client fields.
- [x] (2026-07-07 00:00Z) Run `cargo fmt`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --features nlp`.

## Surprises & Discoveries

- Observation: `semantic_search_status` returns `indexer.status(&snapshot)` through `structured_only`, so additional `SemanticIndexStatus` fields are serialized automatically on the Rust tool surface.
  Evidence: `src/searchtools_service.rs` `handle_semantic_search_status` calls `Self::structured_only(indexer.status(&snapshot))`.
- Observation: `EmbeddedGroup` already owns the exact blob list persisted by the writer stage.
  Evidence: `src/nlp/materialize.rs` stores `pending_blobs` in `EmbeddedGroup`; a small `blob_count` accessor is enough for progress accounting.
- Observation: A panic inside the embed scoped thread is rethrown by the existing `join().expect("embed thread panicked")`, so the worker-boundary panic payload is the join message rather than the original embedder panic string.
  Evidence: The focused test saw `semantic index unavailable: indexer worker panicked: embed thread panicked: Any { .. }`.

## Decision Log

- Decision: Keep the worker-loop failure logic structurally unchanged and add a small shared helper for setting `Phase::Failed`.
  Rationale: The requested fix is around the spawned thread closure; sharing the bookkeeping avoids duplicating the local closure's exact semantics without restructuring the loop.
  Date/Author: 2026-07-07 / Codex.
- Decision: Test sidecar timeout through a private unit test in `src/nlp/voyage_sidecar.rs`, making `spawn_sidecar` take its timeout as a parameter and testing env parsing separately.
  Rationale: This avoids racy process-global env mutation while still proving the timeout and process cleanup path with a model-free stub script.
  Date/Author: 2026-07-07 / Codex.

## Outcomes & Retrospective

The hardening work is complete in the working tree. Worker panics are caught at the semantic-indexer thread boundary and converted to `Phase::Failed`; sidecar startup now has a configurable ready timeout and warmup failures abort load; semantic status exposes materialization progress counters through Rust serialization and the Python client model. All required quality gates passed.

## Context and Orientation

`src/nlp/indexer.rs` owns the background semantic indexer. `SemanticIndexer::start_with_provider` creates a `Shared` state object with a `phase`, a `pending` batch count, and a condition variable used by `wait_ready`. The worker thread runs `worker_loop`, which already has failure bookkeeping for ordinary `Result` errors but currently does not catch panics from scoped pipeline threads in `materialize_missing`.

`src/nlp/voyage_sidecar.rs` owns the PyTorch sidecar process client. `spawn_sidecar` launches `uv run scripts/voyage_sidecar.py` and waits for a ready frame. `SidecarProc::Drop` kills both the direct child and, on Unix, the child process group. `load_sidecar_embedder` creates one worker per device and currently ignores warmup embedding errors.

`src/searchtools_service.rs` exposes `semantic_search_status` by serializing `SemanticIndexStatus`. `bifrost_searchtools/models.py` has a Python `SemanticSearchStatus` dataclass that enumerates status fields explicitly.

## Plan of Work

First, introduce a helper in `src/nlp/indexer.rs` that sets `Phase::Failed`, stores `pending` as zero, and notifies waiters unless the indexer has already been closed. Use that helper from `worker_loop` and from a `catch_unwind(AssertUnwindSafe(...))` wrapper around the spawned worker closure. Add a test embedder that panics from `embed_passages` and assert `wait_ready` returns a panic-containing structured failure promptly and `status().phase` is `failed`.

Second, make sidecar loading robust. Add a ready-timeout constant and parser for `BIFROST_SIDECAR_READY_TIMEOUT_SECS`, move the blocking ready handshake into a helper thread, and have the spawning thread `recv_timeout`. On timeout, kill the child process group using the same Unix pattern as `Drop`, kill and wait the child, then return a descriptive error. Make warmup errors abort `load_sidecar_embedder` with the device string. Add a unit test that points `spawn_sidecar_with_timeout` at a sleeping stub script and verifies a one-second timeout plus child cleanup.

Third, add `files_total` and `files_done` atomics to `Shared`, expose them as `materialize_total_files` and `materialized_files` on `SemanticIndexStatus`, increment the total by `targets.len()` at the start of each non-empty `materialize_missing`, and increment done by each embedded group's blob count after successful persistence. Update the Python status dataclass and add a Rust test that a successful fake-engine build reports equal nonzero counters.

## Concrete Steps

Run all commands from `/home/jonathan/Projects/bifrost`.

Edit files with `apply_patch` only for manual changes. Do not commit.

Validation commands:

    cargo fmt
    cargo clippy --all-targets --all-features -- -D warnings
    cargo test --features nlp

## Validation and Acceptance

The new panic test should fail before the `catch_unwind` wrapper by timing out or observing a non-failed phase, then pass with `wait_ready` returning an error that mentions the panic payload and `status().phase == "failed"`.

The sidecar timeout test should fail before the timeout code by hanging, then pass by returning an error containing `did not become ready within 1s` promptly and confirming the direct child process no longer exists.

The status counter test should pass after a fake-engine build with `materialized_files == materialize_total_files` and the value greater than zero.

The final acceptance is all three quality gates passing with their terminal pass lines recorded in the final report.

## Idempotence and Recovery

The tests use temporary directories and model-free fake embedders or stub scripts. Re-running the tests should not require network access or GPU sidecars. If validation fails, keep the working tree changes and fix forward; do not reset or revert unrelated user changes.

## Artifacts and Notes

Validation evidence:

    cargo fmt
    no stdout; command exited with status 0

    cargo clippy --all-targets --all-features -- -D warnings
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 18.64s

    cargo test --features nlp
    test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.10s
    test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

## Interfaces and Dependencies

`SemanticIndexStatus` must contain these fields:

    pub indexed_chunks: usize
    pub pending_batches: u64
    pub phase: String
    pub materialized_files: u64
    pub materialize_total_files: u64

`spawn_sidecar` remains the production entry point and delegates to an internal timeout-aware helper so tests can avoid global env races.
