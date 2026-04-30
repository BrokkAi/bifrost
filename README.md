# bifrost

`bifrost` is a Rust port of Brokk's Tree-sitter-backed analyzer suite.

At the library level, this repository builds the `brokk_analyzer` crate. It provides single-language analyzers, a `MultiAnalyzer`, snapshot-style updates, import analysis, type hierarchy queries, test-file detection, and source/skeleton extraction.

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

The crate name is `brokk_analyzer`.

Example:

```rust
use std::sync::Arc;

use brokk_analyzer::{AnalyzerConfig, FilesystemProject, WorkspaceAnalyzer};

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

This starts a stdio MCP server that publishes these tools:

- `refresh`
- `activate_workspace`
- `get_active_workspace`
- `search_symbols`
- `get_symbol_locations`
- `get_symbol_summaries`
- `get_symbol_sources`
- `get_summaries`
- `list_symbols`
- `most_relevant_files`

`activate_workspace` lets a host swap the analyzer's root mid-session without respawning the subprocess. The path must be absolute and is normalized to the nearest enclosing git root when one exists.

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
maturin develop
python - <<'PY'
from bifrost_searchtools import SearchToolsClient

with SearchToolsClient("tests/fixtures/testcode-java") as client:
    print(client.get_summaries(["A.java"]).render_text())
    print(client.most_relevant_files(["A.java"]).render_text())
PY
```

Pass `render_line_numbers=False` to `SearchToolsClient(...)` to omit line numbers from rendered text while keeping the structured line metadata in the result objects.

The client exposes:

- `refresh()`
- `search_symbols(...)`
- `get_symbol_locations(...)`
- `get_symbol_summaries(...)`
- `get_symbol_sources(...)`
- `get_summaries(...)`
- `list_symbols(...)`
- `most_relevant_files(...)`

The client talks directly to Rust through a native extension module. The Python/Rust boundary stays JSON-shaped: Python sends tool names plus JSON arguments and Rust returns JSON result objects. Rendering still lives in the Python package:

- source blocks use original file line numbers
- summaries use original line ranges in `N..M: ...` form on the first line
