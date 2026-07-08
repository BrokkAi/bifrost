---
title: Semantic Search
description: Enable and operate Bifrost semantic code search.
---

`semantic_search` searches code by meaning and returns its constituent rankings directly. The vector and BM25 legs are function-oriented, using function-level chunks with enclosing class or file summary context. The co-edit leg is file-oriented. It searches code, not prose or markdown.

Semantic search is opt-in. Build Bifrost with the `nlp` feature:

```bash
cargo build --features nlp --bin bifrost
```

Then enable background indexing for the process:

```bash
BIFROST_SEMANTIC_INDEX=auto bifrost --root /path/to/project --mcp core
```

Without the `nlp` feature, the `nlp` toolset publishes no tools and `core` degrades to `symbol|workspace`.

## Index

The index lives in `.brokk/semantic_index.db` of the primary repository. Linked git worktrees share the primary repository's index. Vectors and BM25 rows are keyed by content hash, so switching branches re-points rows instead of re-embedding unchanged content.

Once enabled, a background build starts when the workspace is activated. `semantic_search` waits until the index is ready, and the file watcher keeps it updated incrementally.

`refresh` forces a full rebuild of the code index. Normal tool calls already apply watcher-detected file changes automatically, so most hosts should not call `refresh` during routine operation.

## Model and Runtime

Embeddings use `voyageai/voyage-4-nano`, downloaded from the Hugging Face hub on first use, and run in a PyTorch SDPA sidecar launched with:

```bash
uv run scripts/voyage_sidecar.py
```

Rust keeps the indexing pipeline and token counting in-process. The sidecar owns model forward passes and selects CUDA, Apple Metal, or CPU at runtime.

## Environment

| Variable | Description |
| --- | --- |
| `BIFROST_SEMANTIC_INDEX=auto` | Enables background indexing. The default is off. |
| `BIFROST_EMBED_MODEL_DIR` | Local directory containing `config.json`, `tokenizer.json`, and `model.safetensors`; takes precedence over the hub. |
| `BIFROST_EMBED_MODEL_ID` | Alternate Hugging Face repository id. |
| `BIFROST_ACCELERATOR=auto|cpu|cuda|metal` | Controls whether `semantic_search` is advertised and started based on the available accelerator. The default is `auto`; `cpu` hides the tool unless force-enabled with `--force-semantic-cpu`. |
| `BIFROST_SIDECAR_DEVICES=<uuid|index,...>` | CUDA devices the Rust scheduler should use. Bifrost launches one sidecar worker per listed device and sets that child's `CUDA_VISIBLE_DEVICES`. |

If `BIFROST_SIDECAR_DEVICES` is unset, Bifrost honors an existing `CUDA_VISIBLE_DEVICES` list. If that is also unset, it uses every GPU reported by `nvidia-smi`. If no CUDA GPU is visible, it launches one unpinned sidecar, which may use Metal or CPU.

`BIFROST_ACCELERATOR` is a Bifrost tool-availability gate, not a CUDA device binding.
