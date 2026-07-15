---
title: Rust Library
description: Embed Bifrost directly as a Rust crate.
---

The Cargo package is `brokk-bifrost`, and the Rust crate name is `brokk_bifrost`. It exports the analyzer core, project abstractions, searchtools service, and common result types from `src/lib.rs`.

## Add to a Project

Add the released crate with Cargo:

```bash
cargo add brokk-bifrost
```

That produces a dependency like:

```toml
[dependencies]
brokk-bifrost = "0.8.3"
```

For local development against a checkout, use a path dependency:

```bash
cargo add brokk-bifrost --path /path/to/bifrost
```

The package name uses a hyphen, but Rust imports use the crate name with an underscore:

```rust
use brokk_bifrost::{AnalyzerConfig, FilesystemProject, WorkspaceAnalyzer};
```

## Minimal Analyzer

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

## Main Public Exports

The top-level crate re-exports the public analyzer and service types most callers need:

| Export | Use |
| --- | --- |
| `WorkspaceAnalyzer` | Build a workspace-backed analyzer with default multi-language routing. |
| `MultiAnalyzer` | Route analysis across multiple language analyzers. |
| `IAnalyzer` | Trait for common analyzer operations. |
| `FilesystemProject`, `FileSetProject`, `OverlayProject`, `MultiRootProject` | Project backends for different file-source shapes. |
| `ProjectFile`, `CodeUnit`, `DeclarationInfo`, `Language`, `Range` | Core source and symbol model types. |
| `SearchToolsService`, `ToolOutput` | In-process access to the same tool implementations exposed over MCP. |
| `ImportAnalysisProvider`, `TypeHierarchyProvider`, `TypeAliasProvider`, `TestDetectionProvider` | Optional analyzer capability traits. |

For most embedded code-intelligence workflows, prefer `SearchToolsService` over manually composing individual analyzer calls. It keeps the tool argument and rendering behavior aligned with MCP and the Python client.

## Features

The default Rust build has no optional features enabled.

`nlp` enables semantic search support. It adds the model download, tokenization, and semantic-index plumbing, while the embedding sidecar selects CUDA, Apple Metal, or CPU at runtime.

`python` enables the PyO3 extension module used by the Python package. Maturin turns this on automatically through `pyproject.toml`; ordinary CLI and library builds do not need it.
