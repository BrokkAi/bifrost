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

`--server` accepts ordered compositions of toolsets separated by `|`:

- `searchtools` expands to all toolsets in the canonical order `symbol|workspace|extended|text|slopcop`
- `core` expands to `symbol|workspace`
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
- `workspace`: `refresh`, `activate_workspace`, `get_active_workspace`
- `extended`: `find_filenames`, `list_files`, `most_relevant_files`, `search_git_commit_messages`, `get_git_log`, `get_commit_diff`, `jq`, `xml_skim`, `xml_select`
- `text`: `get_file_contents`, `search_file_contents`, `find_files_containing`
- `slopcop`: `compute_cyclomatic_complexity`, `compute_cognitive_complexity`, `report_comment_density_for_code_unit`, `report_exception_handling_smells`, `report_comment_density_for_files`, `analyze_git_hotspots`, `report_test_assertion_smells`, `report_structural_clone_smells`, `report_long_method_and_god_object_smells`, `report_dead_code_and_unused_abstraction_smells`, `report_secret_like_code`

The subset toolsets are now composable rather than fixed server modes. `core` is the `symbol|workspace` alias, and `searchtools` is the alias for the full union.

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

`get_summaries(...)` remains directory-aware for MCP and Python callers: directory targets surface a `directory_symbols` inventory alongside ordinary summaries when mixed with file or class targets. The Rust-level `brokk_bifrost::searchtools::get_summaries(...)` API is narrower and reports directory targets in `not_found` instead of embedding directory inventory in `SummaryResult`.

The client talks directly to Rust through a native extension module. The Python/Rust boundary stays JSON-shaped: Python sends tool names plus JSON arguments and Rust returns structured JSON plus canonical rendered text. The line-number policy now lives in the shared Rust renderer used by both the MCP server and the Python client:

- source blocks use original file line numbers
- summaries use original line ranges in `N..M: ...` form on the first line
