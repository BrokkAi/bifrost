# bifrost

`bifrost` is a Rust port of Brokk's Tree-sitter-backed analyzer suite.

At the library level, this repository builds the `brokk_bifrost` crate. It provides single-language analyzers, a `MultiAnalyzer`, snapshot-style updates, import analysis, type hierarchy queries, test-file detection, and source/skeleton extraction.

At the tool level, this repository also provides:

- `bifrost`, a stdio MCP server that exposes analyzer-backed search tools
- `bifrost_searchtools`, a Python import package backed by a native Rust extension
- `most_relevant_files`, a CLI that ranks related project files from one or more seed files

## Status

The current tree includes analyzers for:

- Java
- JavaScript
- TypeScript
- Rust
- Go
- Python
- C++
- C#
- PHP
- Scala

## Contributing

For local development, test commands, repository-local Python workflow, and release tagging, see [CONTRIBUTING.md](/home/jonathan/Projects/bifrost/CONTRIBUTING.md).

## Rust Library Usage

The crate name is `brokk_bifrost`.

Example:

```rust
use std::sync::Arc;

use brokk_bifrost::{AnalyzerConfig, FilesystemProject, WorkspaceAnalyzer};

fn main() -> Result<(), String> {
    let project = Arc::new(FilesystemProject::new(".")?);
    let workspace = WorkspaceAnalyzer::build(project, AnalyzerConfig::default());
    let analyzer = workspace.analyzer();

    println!("languages: {:?}", analyzer.languages());
    println!("files: {}", analyzer.get_analyzed_files().len());
    println!("declarations: {}", analyzer.get_all_declarations().len());
    Ok(())
}
```

The main public exports are re-exported from src/lib.rs, including:

- `WorkspaceAnalyzer`
- `MultiAnalyzer`
- `IAnalyzer`
- `ProjectFile`
- `CodeUnit`
- `ImportAnalysisProvider`
- `TypeHierarchyProvider`
- `TypeAliasProvider`
- `TestDetectionProvider`

## MCP Server

Build the server binary:

```bash
cargo build --bin bifrost
```

Run it against a project root:

```bash
./target/debug/bifrost --root /path/to/project --server searchtools
```

Or just start it from the project root and let the defaults kick in:

```bash
cd /path/to/project
bifrost
```

By default, `bifrost` uses the current working directory as `--root` and `searchtools` as `--server`. Run `bifrost --help` to see all options.

For one-shot terminal use, `bifrost` can also invoke a tool directly without starting an MCP session:

```bash
./target/debug/bifrost --root /path/to/project --tool get_summaries --args '{"targets":["src/main.rs"]}'
```

Direct `--tool` mode prints rendered text by default. The `--args` payload is inline JSON matching the existing tool argument objects, and absolute paths inside the selected workspace are normalized the same way they are for MCP calls.

`--server` accepts ordered compositions of toolsets separated by `|`:

- `searchtools` expands to all toolsets in the canonical order `symbol|nlp|workspace|extended|text|slopcop`
- `core` expands to `symbol|nlp|workspace`
- `slopcop` stays available as its own set

Examples:

```bash
./target/debug/bifrost --root /path/to/project --server core
./target/debug/bifrost --root /path/to/project --server "symbol|workspace"
./target/debug/bifrost --root /path/to/project --server extended
./target/debug/bifrost --root /path/to/project --server "text|extended"
./target/debug/bifrost --root /path/to/project --server slopcop
```

`searchtools` remains the compatibility mode and exposes the full current union of MCP tools in toolset order. Pass `--no-line-numbers` to remove rendered line and line-range prefixes from the MCP text preview while keeping `structuredContent` unchanged.

This starts a stdio MCP server that publishes these tools:

- `symbol`: `search_symbols`, `get_symbol_locations`, `get_symbol_sources`, `get_summaries`, `list_symbols`, `scan_usages`
- `nlp`: `semantic_search`
- `workspace`: `refresh`, `activate_workspace`, `get_active_workspace`
- `extended`: `find_filenames`, `list_files`, `most_relevant_files`, `search_git_commit_messages`, `get_git_log`, `get_commit_diff`, `jq`, `xml_skim`, `xml_select`
- `text`: `get_file_contents`, `search_file_contents`, `find_files_containing`
- `slopcop`: `compute_cyclomatic_complexity`, `compute_cognitive_complexity`, `report_comment_density_for_code_unit`, `report_exception_handling_smells`, `report_comment_density_for_files`, `analyze_git_hotspots`, `report_test_assertion_smells`, `report_structural_clone_smells`, `report_long_method_and_god_object_smells`, `report_dead_code_and_unused_abstraction_smells`, `report_secret_like_code`

The subset toolsets are now composable rather than fixed server modes. `core` is the `symbol|nlp|workspace` alias, and `searchtools` is the alias for the full union.

### Semantic search

`semantic_search` (in the `nlp` toolset) finds source files by meaning: function-level chunks are embedded (averaged with their enclosing class or file summary), fused with grounded-strings BM25 and git co-edit relevance, then reranked by a cross-encoder. It searches code only, not prose or markdown.

The index lives in `.brokk/semantic_index.db` of the **primary** repository (linked git worktrees share the primary's index). Vectors and BM25 rows are keyed by content hash, so switching branches re-points rows instead of re-embedding. Once enabled, a background build starts when the workspace is activated; `semantic_search` blocks until the index is ready, and the file watcher keeps it updated incrementally.

Models load via ONNX (`gte-rs`). Defaults are downloaded from the HuggingFace hub on first use: `onnx-community/granite-embedding-small-english-r2-ONNX` for embeddings and `Alibaba-NLP/gte-reranker-modernbert-base` for reranking (full-precision variants when CUDA/CoreML acceleration is selected, int8 variants on CPU). Environment overrides:

- `BIFROST_SEMANTIC_INDEX=auto` enables background indexing; the default is off
- `BIFROST_EMBED_MODEL_DIR` / `BIFROST_RERANK_MODEL_DIR`: local directory containing `tokenizer.json` + `model.onnx` (e.g. a fine-tune); takes precedence over the hub
- `BIFROST_EMBED_MODEL_ID` / `BIFROST_RERANK_MODEL_ID`: alternate HuggingFace repo ids
- `BIFROST_ACCELERATOR=auto|cpu|cuda|coreml`: execution provider preference (default `auto`)
- `BIFROST_CUDA_DEVICES=auto|0,1,...`: CUDA device ids for embedding workers when built with `nlp-gpu`; ids are logical ids after `CUDA_VISIBLE_DEVICES` masking/remapping
- `BIFROST_CUDA_DEVICE`: legacy single CUDA device id for `nlp-gpu` when `BIFROST_CUDA_DEVICES` is unset (default 0)
- `BIFROST_COREML_ANE_ONLY=1`: only enable CoreML on devices with a compatible Apple Neural Engine when built with `nlp-coreml`
- `BIFROST_EMBED_BATCH_MAX_ITEMS` / `BIFROST_EMBED_BATCH_MAX_TOKENS`: cap scheduler batches by item count and by padded attention cost. Inputs are padded to the longest text in a batch, so a batch of `n` texts costs `n * longest^2`; `MAX_TOKENS` (default 8192, the model max) budgets each batch at the cost of one sequence of that length — a max-length chunk runs alone, 2k-token chunks batch 4 at a time, short chunks fill `MAX_ITEMS`

`uv run scripts/optimize_onnx_attention.py <model.onnx>...` rewrites a downloaded model's per-head-tiled attention masks into MultiHeadAttention's `key_padding_mask` input plus one shared sliding-window bias, verifying output parity before writing a `.bifrost-opt.onnx` sibling that model resolution then prefers automatically. On the default embedding model this roughly halves peak inference memory and is several times faster at 8k-token chunks. (A head-broadcast `(batch,1,seq,seq)` bias would be smaller still, but the ONNX Runtime 1.20 CPU kernel bundled by `ort` 2.0.0-rc.9 misindexes that shape for batches > 1 — see the script docstring.)

The `nlp` cargo feature is opt-in; build with `--features nlp` on targets where onnxruntime is available. Without that feature, the `nlp` toolset publishes no tools and `core` degrades to `symbol|workspace`. Add `--features nlp,nlp-gpu` for CUDA or `--features nlp,nlp-coreml` for Apple CoreML acceleration.

`refresh` forces a full rebuild of the code index. Normal tool calls already apply watcher-detected file changes automatically, so most hosts should not call it during routine operation. Keep it as a manual recovery tool when you want to discard incremental state and rescan the whole workspace from disk.

`activate_workspace` lets a host swap the analyzer's root mid-session without respawning the subprocess. The path must be absolute and is normalized to the nearest enclosing git root when one exists.

For MCP tool arguments that name files, directories, or file globs, callers may pass project-relative paths or absolute paths inside the active workspace. Absolute paths outside the active workspace are rejected with an explicit tool error.

The intended external manual client is the official MCP Inspector.

## CLI

Build the CLI binaries:

```bash
cargo build --bin bifrost --bin most_relevant_files
```

Rank related files from one or more seed files:

```bash
./target/debug/most_relevant_files --root /path/to/project path/to/seed_file.py
```

## Python Client

The Python distribution is `bifrost-searchtools`. Import it as `bifrost_searchtools`.

Example:

```bash
uv run --python 3.12 --with maturin maturin develop
uv run --python 3.12 python - <<'PY'
from bifrost_searchtools import SearchToolsClient

with SearchToolsClient("tests/fixtures/testcode-java") as client:
    print(client.get_summaries(["A.java"]).render_text())
    print(client.most_relevant_files(["A.java"]).render_text())
PY
```

Run the Python test suite with:

```bash
scripts/test_python.sh
```

Pass `render_line_numbers=False` to `SearchToolsClient(...)` to omit line numbers from rendered text while keeping the structured line metadata in the result objects.

`SearchToolsClient.refresh()` forces a full rebuild of the code index. Query methods already apply watcher-detected file changes automatically, so most callers should treat `refresh()` as an escape hatch for recovery or explicit full rescans rather than a step to run before every request.

The client exposes:

- `refresh()`
- `search_symbols(...)`
- `get_symbol_locations(...)`
- `get_symbol_sources(...)`
- `get_summaries(...)`
- `list_symbols(...)`
- `most_relevant_files(...)`

`get_summaries(...)` remains directory-aware for MCP callers: directory targets surface a `compact_symbols` inventory alongside ordinary summaries when mixed with file or class targets. The direct Rust `brokk_bifrost::searchtools::get_summaries(...)` API and the Python `searchtools` client are narrower and report directory targets in `not_found` instead of embedding directory inventory in `SummaryResult`.

The client talks directly to Rust through a native extension module. The Python/Rust boundary stays JSON-shaped: Python sends tool names plus JSON arguments and Rust returns structured JSON plus canonical rendered text. The line-number policy now lives in the shared Rust renderer used by both the MCP server and the Python client:

- source blocks use original file line numbers
- summaries use original line ranges in `N..M: ...` form on the first line
