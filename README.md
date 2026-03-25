# bifrost

`bifrost` is a Rust port of Brokk's Tree-sitter-backed analyzer suite.

At the library level, this repository builds the `brokk_analyzer` crate. It provides single-language analyzers, a `MultiAnalyzer`, snapshot-style updates, import analysis, type hierarchy queries where supported, test-file detection, and source/skeleton extraction across a set of vendored fixture corpora copied from Brokk.

At the tool level, this repository also provides:

- `bifrost`, a stdio MCP server that exposes analyzer-backed search tools
- `bifrost_searchtools`, a Python client package for talking to that MCP server
- `summarize`, a small Java-only CLI for Brokk-style summary output

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
- [src/mcp_server.rs](/home/jonathan/Projects/bifrost/src/mcp_server.rs): MCP stdio server implementation for `bifrost --server searchtools`
- [src/bin/bifrost.rs](/home/jonathan/Projects/bifrost/src/bin/bifrost.rs): `bifrost` binary entrypoint
- [src/bin/summarize.rs](/home/jonathan/Projects/bifrost/src/bin/summarize.rs): Java summary CLI
- [bifrost_searchtools](/home/jonathan/Projects/bifrost/bifrost_searchtools): Python MCP client and renderers
- [python_tests](/home/jonathan/Projects/bifrost/python_tests): Python client tests
- [tests](/home/jonathan/Projects/bifrost/tests): Rust integration tests

## Build

Rust:

```bash
cargo build
```

Python client dependencies:

```bash
uv sync
```

This repository has a minimal [pyproject.toml](/home/jonathan/Projects/bifrost/pyproject.toml) so `uv run python ...` can execute the `bifrost_searchtools` client against the official Python MCP SDK dependency.

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

The intended external manual client is the official MCP Inspector.

## Python Client

The Python package is `bifrost_searchtools`.

Example:

```bash
uv run python - <<'PY'
from bifrost_searchtools import SearchToolsClient

with SearchToolsClient("tests/fixtures/testcode-java", server_path="target/debug/bifrost") as client:
    print(client.get_file_summaries(["A.java"]).render_text())
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

Rendering lives in the Python package:

- source blocks use original file line numbers
- summaries use original line ranges in `N..M: ...` form on the first line

## `summarize` CLI

The `summarize` binary is currently Java-only.

Build and run:

```bash
cargo build --bin summarize
./target/debug/summarize --root tests/fixtures/testcode-java A
```

It accepts:

- absolute file paths under the chosen root
- Java FQCNs

and prints Brokk-style summaries using the Rust analyzer implementation.

## Notes

- The repository contains living implementation plans in [EXECPLAN.md](/home/jonathan/Projects/bifrost/EXECPLAN.md) and [SEARCHTOOLS_MCP_EXECPLAN.md](/home/jonathan/Projects/bifrost/SEARCHTOOLS_MCP_EXECPLAN.md).
- The Tree-sitter grammar crate versions are intentionally not forced to share the same numeric version. The policy is documented in [Cargo.toml](/home/jonathan/Projects/bifrost/Cargo.toml).
- The Python client is intended primarily for consumption from sibling tooling such as `../mistral-vibe`, but it is usable directly from this repository as well.
