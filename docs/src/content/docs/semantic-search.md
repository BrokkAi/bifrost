---
title: Semantic Search
description: Enable and operate Bifrost semantic code search.
---

`semantic_search` searches code by meaning and returns its constituent rankings directly. The dense vector leg is function-oriented, using function-level chunks with enclosing class or file context. The co-edit leg is file-oriented. It searches code, not prose or markdown.

Semantic search is opt-in. Build Bifrost with the `nlp` feature:

```bash
cargo build --features nlp --bin bifrost
```

Then enable background indexing for the process:

```bash
BIFROST_SEMANTIC_INDEX=auto bifrost --root /path/to/project --mcp core
```

Without the `nlp` feature, the `nlp` toolset publishes no tools and `core` degrades to `symbol|workspace`.
This example is intentionally scoped to symbol navigation plus semantic search and does not expose `query_code`. Add `extended` to the composition when the same agent also needs structural queries.

## Index

The semantic index shares `.bifrost/cache/bifrost_cache.v<N>.db` with the analyzer cache, where `<N>` is the cache schema version the running build reads. Every entry point places that path at the primary repository root and therefore shares it across linked worktrees, including MCP sessions bound through client roots. An explicit `BIFROST_CACHE_DIR` continues to place the database directly at `$BIFROST_CACHE_DIR/bifrost_cache.v<N>.db`. Vectors and chunk rows are keyed by content hash, so switching branches re-points rows instead of re-embedding unchanged content.

Once enabled, a background build starts when the workspace is activated. `semantic_search` waits until the index is ready, and the file watcher keeps it updated incrementally.

`refresh` forces a full rebuild of the code index. Normal tool calls already apply watcher-detected file changes automatically, so most hosts should not call `refresh` during routine operation.

## Model and Runtime

Embeddings use `brokkai/Muninn` when CUDA or Apple Metal is available. Bifrost truncates Muninn output to 512 dimensions. Without an accelerator, Bifrost uses the native 384-dimensional `brokkai/Muninn-small` model. The selected model downloads from the Hugging Face hub on first use and runs in a PyTorch SDPA sidecar launched with:

```bash
uv run scripts/voyage_sidecar.py
```

Rust keeps the indexing pipeline and token counting in-process. The sidecar owns model forward passes and selects CUDA, Apple Metal, or CPU at runtime.

## Environment

| Variable | Description |
| --- | --- |
| `BIFROST_SEMANTIC_INDEX=auto` | Enables background indexing. The default is off. |
| `BIFROST_EMBED_MODEL_DIR` | Local Sentence Transformers model directory; takes precedence over the hub. |
| `BIFROST_EMBED_MODEL_ID` | Explicit Hugging Face repository ID; takes precedence over automatic Muninn selection. |
| `BIFROST_ACCELERATOR=auto|cpu|cuda|metal` | Controls whether `semantic_search` is advertised and started based on the available accelerator. The default is `auto`; `cpu` hides the tool unless force-enabled with `--force-semantic-cpu`. |
| `BIFROST_SIDECAR_DEVICES=<uuid|index,...>` | CUDA devices the Rust scheduler should use. Bifrost launches one sidecar worker per listed device and sets that child's `CUDA_VISIBLE_DEVICES`. |

If `BIFROST_SIDECAR_DEVICES` is unset, Bifrost honors an existing `CUDA_VISIBLE_DEVICES` list. If that is also unset, it uses every GPU reported by `nvidia-smi`. If no CUDA GPU is visible, it launches one unpinned sidecar, which may use Metal or CPU.

A local model directory must contain the model, tokenizer, `config_sentence_transformers.json`, and `1_Pooling/config.json`. Bifrost reads dimensions, prompts, and pooling from this metadata. Bidirectional Qwen Muninn models use 512-dimensional Matryoshka truncation.

`BIFROST_ACCELERATOR` is a Bifrost tool-availability gate, not a CUDA device binding.
