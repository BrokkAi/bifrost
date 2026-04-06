# bifrost

`bifrost` is a Rust port of Brokk's Tree-sitter-backed analyzer suite.

At the library level, this repository builds the `brokk_analyzer` crate. It provides single-language analyzers, a `MultiAnalyzer`, snapshot-style updates, import analysis, type hierarchy queries where supported, test-file detection, and source/skeleton extraction across a set of vendored fixture corpora copied from Brokk.

At the tool level, this repository also provides:

- `bifrost`, a stdio MCP server that exposes analyzer-backed search tools
- `bifrost_searchtools`, a Python client package backed by a native Rust extension

## Status

The analyzer port is substantial rather than minimal. The current tree includes analyzers for:

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

The repository vendors Brokk's Tree-sitter query files under [resources/treesitter](/home/jonathan/Projects/bifrost/resources/treesitter) and fixture projects under [tests/fixtures](/home/jonathan/Projects/bifrost/tests/fixtures).

## Repository Layout

- [src/analyzer](/home/jonathan/Projects/bifrost/src/analyzer): core analyzer library
- [src/searchtools.rs](/home/jonathan/Projects/bifrost/src/searchtools.rs): analyzer-backed searchtools result layer
- [src/searchtools_service.rs](/home/jonathan/Projects/bifrost/src/searchtools_service.rs): shared JSON tool service used by both MCP and Python FFI
- [src/mcp_server.rs](/home/jonathan/Projects/bifrost/src/mcp_server.rs): MCP stdio server implementation for `bifrost --server searchtools`
- [src/bin/bifrost.rs](/home/jonathan/Projects/bifrost/src/bin/bifrost.rs): `bifrost` binary entrypoint
- [bifrost_searchtools](/home/jonathan/Projects/bifrost/bifrost_searchtools): Python FFI client and renderers
- [python_tests](/home/jonathan/Projects/bifrost/python_tests): Python client tests
- [tests](/home/jonathan/Projects/bifrost/tests): Rust integration tests

## Build

Rust:

```bash
cargo build --lib --bin bifrost
```

Python client build/install:

```bash
maturin develop
```

This repository has a mixed Python/Rust [pyproject.toml](/home/jonathan/Projects/bifrost/pyproject.toml) so `bifrost_searchtools` can be installed as a normal Python package while loading the native `bifrost_searchtools._native` PyO3 extension.

## Test

Rust:

```bash
cargo test
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
```

Python:

```bash
uv run python -m unittest discover -s python_tests -p 'test_*.py'
```

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

The main public exports are re-exported from [src/lib.rs](/home/jonathan/Projects/bifrost/src/lib.rs), including:

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
- `search_symbols`
- `get_symbol_locations`
- `get_symbol_summaries`
- `get_symbol_sources`
- `get_file_summaries`
- `skim_files`
- `most_relevant_files`

The intended external manual client is the official MCP Inspector.

## Python Client

The Python package is `bifrost_searchtools`.

Example:

```bash
maturin develop
python - <<'PY'
from bifrost_searchtools import SearchToolsClient

with SearchToolsClient("tests/fixtures/testcode-java") as client:
    print(client.get_file_summaries(["A.java"]).render_text())
    print(client.most_relevant_files(["A.java"]).render_text())
PY
```

The client exposes:

- `refresh()`
- `search_symbols(...)`
- `get_symbol_locations(...)`
- `get_symbol_summaries(...)`
- `get_symbol_sources(...)`
- `get_file_summaries(...)`
- `skim_files(...)`
- `most_relevant_files(...)`

The client talks directly to Rust through a native extension module. The Python/Rust boundary stays JSON-shaped: Python sends tool names plus JSON arguments and Rust returns JSON result objects. Rendering still lives in the Python package:

- source blocks use original file line numbers
- summaries use original line ranges in `N..M: ...` form on the first line

For repo-local development without installing the package, `SearchToolsClient(..., library_path=...)` can load a built debug library such as `target/debug/libbrokk_analyzer.so`.

## Notes

- The repository contains living implementation plans in [EXECPLAN.md](/home/jonathan/Projects/bifrost/EXECPLAN.md), [SEARCHTOOLS_MCP_EXECPLAN.md](/home/jonathan/Projects/bifrost/SEARCHTOOLS_MCP_EXECPLAN.md), and [SEARCHTOOLS_PYO3_EXECPLAN.md](/home/jonathan/Projects/bifrost/SEARCHTOOLS_PYO3_EXECPLAN.md).
- The Tree-sitter grammar crate versions are intentionally not forced to share the same numeric version. The policy is documented in [Cargo.toml](/home/jonathan/Projects/bifrost/Cargo.toml).
- The standalone MCP server remains available for external clients even though the Python client no longer uses MCP internally.
