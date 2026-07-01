# bifrost

`bifrost` is a Rust port of Brokk's Tree-sitter-backed analyzer suite.

At the library level, this repository builds the `brokk_bifrost` crate. It provides single-language analyzers, a `MultiAnalyzer`, snapshot-style updates, import analysis, type hierarchy queries, test-file detection, and source/skeleton extraction.

At the tool level, this repository also provides:

- `bifrost`, a stdio MCP server that exposes analyzer-backed search tools
- `bifrost_searchtools`, a Python import package backed by a native Rust extension
- `most_relevant_files`, a CLI that ranks related project files from one or more seed files
- `editors/vscode`, a minimal VS Code extension that launches Bifrost's LSP server

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
- Ruby

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
./target/debug/bifrost --root /path/to/project --mcp searchtools
```

Or start it from the project root with an explicit MCP toolset:

```bash
cd /path/to/project
bifrost --mcp searchtools
```

By default, `bifrost` uses the current working directory as `--root` and `searchtools` as the MCP toolset. Select a different mode with `--mcp`, `--lsp`, or `--tool`. Run `bifrost --help` to see all options.

### Integrating with MCP hosts

Install a released `bifrost` binary first:

```bash
cargo install brokk-bifrost --locked --force
```

For local development, build this checkout instead and use the absolute path to
`target/debug/bifrost` in the examples below:

```bash
cargo build --bin bifrost
```

`bifrost` is a stdio MCP server, so MCP hosts need a command plus arguments.
Always pass an explicit `--root`; otherwise the server analyzes whatever
directory the host uses as the subprocess working directory.

Codex CLI:

```bash
codex mcp add bifrost -- bifrost --root /path/to/project --mcp core
codex mcp list
```

Claude Code:

```bash
claude mcp add --scope user bifrost -- bifrost --root /path/to/project --mcp core
claude mcp list
```

For JSON-based MCP configuration, such as Claude Desktop's
`claude_desktop_config.json`, add a stdio server entry:

```json
{
  "mcpServers": {
    "bifrost": {
      "command": "/path/to/bifrost",
      "args": ["--root", "${workspaceFolder}", "--mcp", "searchtools"]
    }
  }
}
```

Use an absolute binary path if `bifrost` is not on the host's `PATH`, for
example `/path/to/bifrost/target/debug/bifrost`. Replace
`${workspaceFolder}` with the project root syntax supported by your host, or
with an absolute project path. Use `searchtools` to expose every Bifrost MCP
tool, `core` for the common agent toolset, or a smaller composition such as
`symbol|workspace` when the host should see fewer tools.

## VS Code LSP Extension

The repository includes a minimal VS Code language-client wrapper in
`editors/vscode`. It starts the existing Bifrost stdio LSP server with
`bifrost --root <workspace-root> --lsp`.

See `editors/vscode/README.md` for development-host setup, the
`bifrost.serverPath` setting, `Bifrost: Open MCP Setup`,
`Bifrost: Copy MCP Config`, and debug settings such as `bifrost.debug` and
`bifrost.slowRequestMs`.

#### Skills and workflow commands

The MCP configuration above exposes Bifrost tools such as `search_symbols`,
`get_summaries`, and `scan_usages`. It does not install host-specific agent
skills such as `/brokk:guided-review`.

Those skills are currently packaged by the Brokk host plugin, whose source lives
in `BrokkAi/brokk` under `claude-plugin/`. The repository name is historical:
the plugin uses Bifrost for its analyzer-backed MCP tools, but the skill bundle
has not yet moved into this repository. See
`docs/agent-plugin-publication.md` for the Bifrost-owned Agent Plugin
publication path.

Claude Code plugin install:

```text
/plugin marketplace add BrokkAi/brokk
/plugin install brokk@brokk-marketplace
```

Codex plugin install for the Bifrost-owned MCP server plugin:

```bash
codex plugin marketplace add /path/to/bifrost
codex plugin add bifrost@bifrost-local
codex
```

Claude Code plugin install for the Bifrost-owned MCP server plugin:

```bash
claude plugin marketplace add /path/to/bifrost
claude plugin install bifrost@bifrost-marketplace --scope local
claude
```

The Bifrost plugin package lives in `plugins/bifrost-agent`, and the local
marketplace entries live in `.agents/plugins/marketplace.json` for Codex and
`.claude-plugin/marketplace.json` for Claude Code. That package README is the
canonical local testing guide. The plugin installs the Bifrost MCP server
configuration through the host's plugin flow instead of registering a one-off
server with `codex mcp add` or `claude mcp add`. The plugin starts a
package-local launcher that resolves `BIFROST_BINARY_PATH`, a managed cache
entry, or a checksum-verified GitHub release download. A compatible `bifrost`
on `PATH` is used only when `BIFROST_LAUNCHER_ALLOW_PATH=1` is set explicitly.
The launcher resolves the workspace root from `BIFROST_WORKSPACE_ROOT` or the
host session working directory and always starts Bifrost with explicit `--root
<resolved-root>`. Its default toolset is `symbol|extended`, which exposes code
navigation and related discovery tools without workspace activation or raw text
file tools. For local checkout builds, use:

```bash
cargo build --bin bifrost
BIFROST_BINARY_PATH="/path/to/bifrost/target/debug/bifrost" codex
```

The Brokk workflow skills, such as `/brokk:guided-review`, are still packaged
separately by the Brokk host plugin. To install those skills, use the Brokk
plugin marketplace:

```bash
codex plugin marketplace add BrokkAi/brokk
codex plugin add brokk@brokk-marketplace
```

Start a fresh host session after installing a plugin or adding an MCP server so
the host can load the new skills and tools at startup.

For one-shot terminal use, `bifrost` can also invoke a tool directly without starting an MCP session:

```bash
./target/debug/bifrost --root /path/to/project --tool get_summaries --args '{"targets":["src/main.rs"]}'
```

Direct `--tool` mode prints rendered text by default. The `--args` payload is inline JSON matching the existing tool argument objects, and absolute paths inside the selected workspace are normalized the same way they are for MCP calls. Repeat `--sources PATH` to restrict one-shot workspace construction to explicit files, directories, or glob matches when you do not want to index the entire repo for a simple query.

```bash
./target/debug/bifrost --root /path/to/project --tool get_symbol_sources --sources src --sources 'tests/**/*.rs' --args '{"symbols":["src/main.rs"]}'
```

`--mcp` accepts ordered compositions of toolsets separated by `|`:

- `searchtools` expands to all toolsets in the canonical order `symbol|nlp|workspace|extended|text|slopcop`
- `core` expands to `symbol|nlp|workspace`
- `slopcop` stays available as its own set

Examples:

```bash
./target/debug/bifrost --root /path/to/project --mcp core
./target/debug/bifrost --root /path/to/project --mcp "symbol|workspace"
./target/debug/bifrost --root /path/to/project --mcp extended
./target/debug/bifrost --root /path/to/project --mcp "text|extended"
./target/debug/bifrost --root /path/to/project --mcp slopcop
```

`searchtools` remains the compatibility mode and exposes the full current union of MCP tools in toolset order. Pass `--no-line-numbers` to remove rendered line and line-range prefixes from the MCP text preview while keeping `structuredContent` unchanged.

This starts a stdio MCP server that publishes these tools:

- `symbol`: `search_symbols`, `get_symbol_locations`, `get_symbol_sources`, `get_summaries`, `scan_usages`, `rename_symbol`
- `nlp`: `semantic_search`
- `workspace`: `refresh`, `activate_workspace`, `get_active_workspace`
- `extended`: `find_filenames`, `list_files`, `most_relevant_files`, `search_git_commit_messages`, `get_git_log`, `get_commit_diff`, `jq`, `xml_skim`, `xml_select`
- `text`: `get_file_contents`, `search_file_contents`, `find_files_containing`
- `slopcop`: `compute_cyclomatic_complexity`, `compute_cognitive_complexity`, `report_comment_density_for_code_unit`, `report_exception_handling_smells`, `report_comment_density_for_files`, `analyze_git_hotspots`, `report_test_assertion_smells`, `report_structural_clone_smells`, `report_long_method_and_god_object_smells`, `report_dead_code_and_unused_abstraction_smells`, `report_secret_like_code`

The subset toolsets are now composable rather than fixed server modes. `core` is the `symbol|nlp|workspace` alias, and `searchtools` is the alias for the full union.

### Semantic search

`semantic_search` (in the `nlp` toolset) searches code by meaning and returns its constituent rankings directly: vector and BM25 legs are function-oriented (`fqfn` hits over function-level chunks, averaged with enclosing class or file summary context), while the co-edit leg remains file-oriented. It searches code only, not prose or markdown.

The index lives in `.brokk/semantic_index.db` of the **primary** repository (linked git worktrees share the primary's index). Vectors and BM25 rows are keyed by content hash, so switching branches re-points rows instead of re-embedding. Once enabled, a background build starts when the workspace is activated; `semantic_search` blocks until the index is ready, and the file watcher keeps it updated incrementally.

Models load via ONNX (`gte-rs`). Defaults are downloaded from the HuggingFace hub on first use: `onnx-community/granite-embedding-small-english-r2-ONNX` for embeddings and `Alibaba-NLP/gte-reranker-modernbert-base` for reranking (full-precision variants when CUDA/CoreML acceleration is selected, int8 variants on CPU). Environment overrides:

- `BIFROST_SEMANTIC_INDEX=auto` enables background indexing; the default is off
- `BIFROST_EMBED_MODEL_DIR` / `BIFROST_RERANK_MODEL_DIR`: local directory containing `tokenizer.json` + `model.onnx` (e.g. a fine-tune); takes precedence over the hub
- `BIFROST_EMBED_MODEL_ID` / `BIFROST_RERANK_MODEL_ID`: alternate HuggingFace repo ids
- `BIFROST_ACCELERATOR=auto|cpu|cuda|metal`: whether to advertise `semantic_search` based on the available accelerator (default `auto`); `cpu` hides the tool unless force-enabled. The sidecar still selects its own runtime device.
- `BIFROST_SIDECAR_DEVICES=<uuid|index,...>`: which devices the sidecar spawns workers on (else every GPU `nvidia-smi` reports, honoring `CUDA_VISIBLE_DEVICES`)
- `BIFROST_EMBED_BATCH_MAX_ITEMS` / `BIFROST_EMBED_BATCH_MAX_TOKENS`: cap scheduler batches by item count and by padded attention cost. Inputs are padded to the longest text in a batch, so a batch of `n` texts costs `n * longest^2`; `MAX_TOKENS` (default 8192, the model max) budgets each batch at the cost of one sequence of that length — a max-length chunk runs alone, 2k-token chunks batch 4 at a time, short chunks fill `MAX_ITEMS`

`uv run scripts/optimize_onnx_attention.py <model.onnx>...` rewrites a downloaded model's per-head-tiled attention masks into MultiHeadAttention's `key_padding_mask` input plus one shared sliding-window bias, verifying output parity before writing a `.bifrost-opt.onnx` sibling that model resolution then prefers automatically. On the default embedding model this roughly halves peak inference memory and is several times faster at 8k-token chunks. (A head-broadcast `(batch,1,seq,seq)` bias would be smaller still, but the ONNX Runtime 1.20 CPU kernel bundled by `ort` 2.0.0-rc.9 misindexes that shape for batches > 1 — see the script docstring.)

The `nlp` cargo feature is opt-in; build with `--features nlp`. Without that feature, the `nlp` toolset publishes no tools and `core` degrades to `symbol|workspace`. There are no longer compile-time accelerator features: the embedder runs in the PyTorch SDPA sidecar (`scripts/voyage_sidecar.py`, launched via `uv`), which selects CUDA, Apple Metal (MPS), or CPU at runtime. Pin which devices it uses with `BIFROST_SIDECAR_DEVICES` (else every GPU `nvidia-smi` reports, honoring `CUDA_VISIBLE_DEVICES`).

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

The Python distribution is `brokk-bifrost-searchtools`. Import it as `bifrost_searchtools`.

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

On macOS, all-features Rust checks also enable `nlp-gpu`, which requires
NVIDIA CUDA tooling (`nvcc`) and is not a local Apple Silicon path. For local
non-CUDA clippy coverage, use the repo alias:

```bash
cargo clippy-no-cuda
```

CUDA-capable environments can still run the full all-features check:

```bash
cargo clippy --all-targets --all-features -- -D warnings
```

All-features Rust tests also enable the PyO3 extension module. Pass the same
linker flags used by CI so Python symbols are resolved by the loading
interpreter:

```bash
RUSTFLAGS='-C link-arg=-undefined -C link-arg=dynamic_lookup' cargo test --all-targets --all-features
```

`scripts/test_python.sh` provisions Python 3.12 through `uv`; the default Xcode
Python may be older than the package test requirements.

Pass `render_line_numbers=False` to `SearchToolsClient(...)` to omit line numbers from rendered text while keeping the structured line metadata in the result objects.

`SearchToolsClient.refresh()` forces a full rebuild of the code index. Query methods already apply watcher-detected file changes automatically, so most callers should treat `refresh()` as an escape hatch for recovery or explicit full rescans rather than a step to run before every request.

The client exposes a typed method per tool, each returning a dataclass from
`bifrost_searchtools.models` (rather than a raw dict):

- workspace: `refresh()`, `update_paths(...)`, `activate_workspace(...)`, `get_active_workspace()`
- symbols: `search_symbols(...)`, `get_symbol_locations(...)`, `get_symbol_ancestors(...)`, `get_symbol_sources(...)`, `get_summaries(...)`, `list_symbols(...)`, `contains_tests(...)`, `scan_usages(...)`, `rename_symbol(...)`, `usage_graph(...)`, `most_relevant_files(...)`
- definitions: `get_definition_by_location(...)`, `get_definition_by_reference(...)`
- types: `get_type_by_location(...)`
- semantic: `semantic_search(...)`, `semantic_search_status()`
- files: `get_file_contents(...)`, `find_filenames(...)`, `search_file_contents(...)`, `find_files_containing(...)`, `list_files(...)`
- git: `get_git_log(...)`, `get_commit_diff(...)`, `search_git_commit_messages(...)`
- structured data: `jq(...)`, `xml_skim(...)`, `xml_select(...)`
- code quality (slopcop): `compute_cyclomatic_complexity(...)`, `compute_cognitive_complexity(...)`, `report_comment_density_for_code_unit(...)`, `report_comment_density_for_files(...)`, `report_exception_handling_smells(...)`, `report_test_assertion_smells(...)`, `report_structural_clone_smells(...)`, `report_long_method_and_god_object_smells(...)`, `report_dead_code_and_unused_abstraction_smells(...)`, `report_secret_like_code(...)`, `analyze_git_hotspots(...)`

The git tools return their own rendered text (a `GitTextResult` carrying `.text`);
the slopcop tools return a `CodeQualityReport` carrying `.report`. The remaining
tools return structured dataclasses. The many per-rule tuning knobs on the
slopcop smell reports are accepted through an `options` dict whose keys map 1:1 to
the underlying Rust tool arguments.

`get_summaries(...)` remains directory-aware for MCP callers: directory targets surface a `compact_symbols` inventory alongside ordinary summaries when mixed with file or class targets. The direct Rust `brokk_bifrost::searchtools::get_summaries(...)` API and the Python `searchtools` client are narrower and report directory targets in `not_found` instead of embedding directory inventory in `SummaryResult`.

The client talks directly to Rust through a native extension module. The Python/Rust boundary stays JSON-shaped: Python sends tool names plus JSON arguments and Rust returns structured JSON plus canonical rendered text. The line-number policy now lives in the shared Rust renderer used by both the MCP server and the Python client:

- source blocks use original file line numbers
- summaries use original line ranges in `N..M: ...` form on the first line
