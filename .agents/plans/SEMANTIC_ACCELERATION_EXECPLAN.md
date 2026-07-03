# Semantic embedding acceleration

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with `.agent/PLANS.md`.

## Purpose / Big Picture

Bifrost's semantic search currently embeds source-code chunks with one ONNX Runtime model session and fixed-size batches. That leaves multi-GPU machines mostly idle, wastes GPU time when short and long chunks are padded together, and gives Apple Silicon users no native acceleration path. After this change, Bifrost can choose CPU, CUDA, or CoreML acceleration, can load multiple CUDA embedding workers, and can feed those workers length-aware batches from a shared queue so faster devices naturally take more work.

The visible behavior is still the same `semantic_search` tool and the same semantic index database. The difference is observable through configuration and tests: `cargo test -p brokk-bifrost nlp::engine::tests` proves CUDA device parsing, token-aware batch packing, and scheduler result ordering without downloading models; hardware smoke tests can later be run on CUDA and Apple Silicon hosts.

## Progress

- [x] (2026-06-11 00:00Z) Inspected current `src/nlp/engine.rs`, `src/nlp/indexer.rs`, `Cargo.toml`, and pinned `ort`/`orp` features. Confirmed current behavior is single embedding session, fixed `EMBED_BATCH = 16`, CUDA-only optional provider, and no CoreML feature.
- [x] (2026-06-11 00:20Z) Added `nlp-coreml`, accelerator selection, CUDA device parsing, CoreML provider selection, provider-specific runtime parameters, and production embedding/reranking constructors.
- [x] (2026-06-11 00:35Z) Added a scheduler-backed embedder that bin-packs by token count and lets multiple workers pull batches from a shared queue.
- [x] (2026-06-11 00:40Z) Wired `DefaultEngineProvider` to use the production scheduler constructor for embeddings and provider-aware constructor for reranking.
- [x] (2026-06-11 00:50Z) Added model-free unit tests for CUDA device parsing, bin packing, scheduler result ordering, and faster-worker queue pulling.
- [x] (2026-06-11 00:55Z) Ran `cargo test -p brokk-bifrost nlp::engine::tests`; all 10 focused engine tests passed.
- [x] (2026-06-11 01:05Z) Tightened the scheduler so accelerated single-worker paths still use token-aware packing, and made explicit `BIFROST_CUDA_DEVICES=auto` prefer `CUDA_VISIBLE_DEVICES` over the legacy single-device setting.
- [x] (2026-06-11 01:10Z) Ran `cargo fmt`, `cargo test -p brokk-bifrost nlp::engine::tests`, `cargo test -p brokk-bifrost nlp::indexer::tests`, and `cargo clippy --all-targets --all-features -- -D warnings`; all passed.

## Surprises & Discoveries

- Observation: The pinned `ort` rc.9 crate already exposes `CoreMLExecutionProvider` behind `ort/coreml`, and `orp` exposes a matching `coreml` feature.
  Evidence: `~/.cargo/registry/src/.../ort-2.0.0-rc.9/src/execution_providers/coreml.rs` defines `CoreMLExecutionProvider`; `orp-0.9.2/Cargo.toml` has `coreml = ["ort/coreml"]`.

- Observation: CoreML rc.9 provider options are limited.
  Evidence: The local `CoreMLExecutionProvider` wrapper supports only `with_cpu_only`, `with_subgraphs`, and `with_ane_only`, so cache directory and newer compute-unit options are not available through the pinned safe wrapper.

- Observation: Bifrost cannot reliably enumerate all physical CUDA devices today without adding a CUDA/NVML dependency.
  Evidence: The current code only checks `CUDAExecutionProvider::default().is_available()` and sets a single `device_id`; no crate in use exposes CUDA device count.

- Observation: The queue-backed scheduler can be tested without hardware.
  Evidence: `scheduled_embedder_lets_faster_workers_pull_more_batches` uses fake embedders with different delays and passed under `cargo test -p brokk-bifrost nlp::engine::tests`.

- Observation: The CoreML feature compiles under `--all-features` on this Linux host even though no Apple runtime is available.
  Evidence: `cargo clippy --all-targets --all-features -- -D warnings` completed successfully after enabling `nlp-coreml`.

## Decision Log

- Decision: Preserve the public `Embedder` trait and make the production embedder internally scheduler-backed instead of changing indexer call sites broadly.
  Rationale: `src/nlp/indexer.rs` already depends on `Embedder::embed_passages`, `embed_query`, `count_tokens`, and `fingerprint`; preserving this contract keeps the semantic index and query paths stable.
  Date/Author: 2026-06-11 / Codex

- Decision: Interpret `BIFROST_CUDA_DEVICES=auto` from `CUDA_VISIBLE_DEVICES` when set, and otherwise use one CUDA worker on logical device 0.
  Rationale: CUDA remaps logical IDs after `CUDA_VISIBLE_DEVICES`, but Bifrost currently has no CUDA device-count API. This default keeps behavior predictable and allows explicit multi-GPU opt-in with `BIFROST_CUDA_DEVICES=0,1,...`.
  Date/Author: 2026-06-11 / Codex

- Decision: Add CoreML as `nlp-coreml`, not as part of `nlp-gpu`.
  Rationale: CUDA and CoreML are different ONNX Runtime execution providers with different platform support. Separate features keep Linux CUDA and macOS Apple Silicon builds explicit.
  Date/Author: 2026-06-11 / Codex

## Outcomes & Retrospective

Implemented the semantic embedding acceleration plan. Bifrost now has explicit CPU/CUDA/CoreML runtime target selection, a CoreML cargo feature, multi-CUDA embedding worker selection, and a queue-backed scheduler that token-packs passage batches while preserving result order. The indexer keeps its existing `Embedder` abstraction and now receives the production scheduler from `DefaultEngineProvider`.

Validation passed without downloading models or requiring accelerator hardware. The remaining hardware-specific work is an Apple Silicon smoke test with `BIFROST_ACCELERATOR=coreml` and, separately, CUDA throughput testing on a multi-GPU host.

## Context and Orientation

`src/nlp/engine.rs` owns embedding and reranking model loading. `GteEmbedder` wraps a `gte-rs` text embedding pipeline and an `orp::model::Model`, which uses ONNX Runtime under the hood. `runtime_params()` currently selects CPU by default and, with the `nlp-gpu` feature, optionally appends a single CUDA execution provider using `BIFROST_CUDA_DEVICE` or device `0`.

`src/nlp/indexer.rs` owns the background semantic indexer. It extracts chunks from analyzed source files, deduplicates component texts by content hash, calls `embedder.embed_passages(&texts)`, and stores returned vectors in SQLite. The indexer should not learn about individual GPUs; it should still ask an `Embedder` for vectors and receive one vector per input text in the same order.

In this plan, "bin packing" means grouping texts with similar token lengths into the same ONNX inference batch. ONNX batches pad every item to the longest item in the batch, so a batch containing one 8,000-token text and many 50-token texts wastes work. "Worker" means one loaded model session bound to one accelerator device; workers pull batches from a shared queue so faster devices process more batches.

## Plan of Work

First, update `Cargo.toml` features so `nlp-coreml` enables `ort/coreml` and `orp/coreml`. Keep `nlp-gpu` as CUDA. No default feature changes are required.

Next, refactor `src/nlp/engine.rs` around explicit runtime targets. Add an `AcceleratorPreference` parsed from `BIFROST_ACCELERATOR=auto|cpu|cuda|coreml`. Add a runtime target enum for CPU, CUDA device ID, and CoreML. Replace `runtime_params()` with a function that accepts one runtime target and builds `orp::params::RuntimeParameters` for that target. Keep CPU as the fallback when a requested provider is unavailable.

Then, add a production constructor that can return either one `GteEmbedder` or a scheduler-backed embedder. The scheduler-backed embedder should hold multiple `Arc<GteEmbedder>` instances, one per selected CUDA device. Its `embed_query`, `count_tokens`, `fingerprint`, and `dim` can delegate to the first worker because all workers load the same model. Its `embed_passages` should prefix passages, compute token lengths, build packed batches, and run those batches on a shared queue with one host thread per worker.

For bin packing, add helper functions in `src/nlp/engine.rs` that accept jobs with original index, text, and token count. Sort by token count descending and use first-fit decreasing into batches constrained by `BIFROST_EMBED_BATCH_MAX_ITEMS` and `BIFROST_EMBED_BATCH_MAX_TOKENS`. Default max items should preserve current behavior at 16. Default max tokens should be `16 * MAX_SEQ_TOKENS`, so the item cap remains the primary default limit while allowing users to lower the token cap.

For CUDA device parsing, add `BIFROST_CUDA_DEVICES`. If set to a comma-separated list, parse that as logical CUDA device IDs. If set to `auto` or unset, and `CUDA_VISIBLE_DEVICES` is set to a non-empty list other than `-1`, create logical device IDs `0..len`. If `CUDA_VISIBLE_DEVICES` is unset, use `[BIFROST_CUDA_DEVICE or 0]`. Keep `BIFROST_CUDA_DEVICE` as backwards-compatible single-device behavior when `BIFROST_CUDA_DEVICES` is not set.

For CoreML, add selection support when `nlp-coreml` is enabled and the target OS is macOS or iOS. In `auto`, prefer CUDA when available, else CoreML when available, else CPU. For now, use the pinned `CoreMLExecutionProvider::default().build()` and expose `BIFROST_COREML_ANE_ONLY=1` to opt into `with_ane_only()`. Do not promise cache-directory support until the pinned `ort` wrapper exposes it or we add a lower-level binding.

Finally, update tests in `src/nlp/engine.rs`. Add tests for CUDA device parsing, first-fit batch packing, scheduler result ordering, and dynamic pull behavior with fake embedders that have different delays. These tests must not download models or require CUDA/CoreML hardware.

## Concrete Steps

Run commands from `/home/jonathan/Projects/bifrost`.

After implementation, run:

    cargo fmt
    cargo test -p brokk-bifrost nlp::engine::tests
    cargo test -p brokk-bifrost nlp::indexer::tests
    cargo clippy --all-targets --all-features -- -D warnings

The hardware smoke tests are intentionally not part of normal CI. On an Apple Silicon machine, the follow-up test should be:

    cargo test -p brokk-bifrost --features nlp-coreml --test nlp_semantic_search_models -- --ignored

with `BIFROST_NLP_MODEL_TESTS=1` and `BIFROST_ACCELERATOR=coreml`.

## Validation and Acceptance

Acceptance is that the default CPU behavior remains compatible, `nlp-gpu` builds can use `BIFROST_CUDA_DEVICES=0,1` to create multiple embedding workers, `nlp-coreml` builds can request CoreML with `BIFROST_ACCELERATOR=coreml`, and the model-free tests prove deterministic scheduling behavior.

The new scheduler tests should fail before the scheduler exists and pass after implementation. The focused indexer tests should continue to pass, proving the indexer still receives vectors in the correct order and persists them normally.

## Idempotence and Recovery

All changes are code and tests only. They can be retried by re-running `cargo fmt` and the focused tests. If CoreML feature compilation fails on non-Apple systems under `--all-features`, guard CoreML provider registration with platform `cfg` while keeping parser tests available on all platforms.

## Artifacts and Notes

Current relevant code excerpt before this work:

    const EMBED_BATCH: usize = 16;
    fn runtime_params() -> orp::params::RuntimeParameters { ... single CUDA device or CPU ... }
    impl Embedder for GteEmbedder {
        fn embed_passages(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, String> {
            let prefixed = texts.iter().map(|text| format!("{PASSAGE_PREFIX}{text}")).collect();
            self.embed_raw(&prefixed)
        }
    }

## Interfaces and Dependencies

At completion, `src/nlp/engine.rs` should expose no new public semantic-search API. Internal/test-visible helpers may exist for parsing and packing:

    enum RuntimeTarget { Cpu, Cuda { device_id: i32 }, CoreMl }
    struct EmbedBatch { jobs: Vec<EmbedJob>, max_tokens: usize }
    fn parse_cuda_devices(cuda_devices: Option<&str>, cuda_visible_devices: Option<&str>, legacy_device: Option<&str>) -> Result<Vec<i32>, String>
    fn pack_embed_jobs(jobs: Vec<EmbedJob>, max_items: usize, max_tokens: usize) -> Vec<EmbedBatch>

`DefaultEngineProvider::embedder()` in `src/nlp/indexer.rs` should call the new production constructor instead of directly loading a single `GteEmbedder`.

Revision note 2026-06-11 / Codex: Initial ExecPlan created after inspecting current code and dependency surfaces. The plan resolves CUDA auto-enumeration pragmatically because no current dependency exposes CUDA device count.

Revision note 2026-06-11 / Codex: Updated progress after implementing accelerator selection, scheduler-backed embedding, production provider wiring, README documentation, and focused model-free tests.

Revision note 2026-06-11 / Codex: Marked implementation complete after focused engine/indexer tests and all-targets/all-features clippy passed.
