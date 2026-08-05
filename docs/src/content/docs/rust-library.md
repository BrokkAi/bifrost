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
brokk-bifrost = "0.8.22"
```

For local development against a checkout, use a path dependency:

```bash
cargo add brokk-bifrost --path /path/to/bifrost
```

The package name uses a hyphen, but Rust imports use the crate name with an underscore:

```rust
use brokk_bifrost::{AnalyzerConfig, FilesystemProject, WorkspaceAnalyzer};
```

## Choose a Package

`brokk-bifrost` is the supported default dependency. It is the compatibility
facade: it re-exports the analyzer and service API, and Cargo resolves the
analysis, runtime, MCP, and LSP implementation crates automatically. Most
applications should depend on this package alone.

For an application that only hosts Bifrost over the Language Server Protocol,
depend directly on the focused LSP host instead:

```bash
cargo add brokk-bifrost-lsp@0.8
```

Start its stdio server with a deterministic fallback workspace root:

```rust
use std::path::PathBuf;

fn main() -> Result<(), String> {
    brokk_bifrost_lsp::run_lsp_stdio_server(PathBuf::from("/path/to/project"))
}
```

The LSP client can replace that fallback with its advertised workspace folders
during initialization. Reserve the process's standard input and output for LSP
messages, and follow the [LSP server guide](/lsp/) for protocol configuration.

`brokk-bifrost-core`, `brokk-bifrost-analysis`, `brokk-bifrost-policy`,
`brokk-bifrost-nlp`, `brokk-bifrost-runtime`, and `brokk-bifrost-mcp` are
lower-level workspace components. They are published
so focused hosts can compose them, but they are not necessary for ordinary
library consumers; prefer the facade unless you specifically own one of those
protocol boundaries.

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
| `CodeQuery`, `CodeQueryExecutionMode`, `CodeQueryResponse` | Parse a canonical JSON/RQL query and select ordinary results, planning-only explain, or an opt-in profile. |
| `CodeQueryExplain`, `CodeQueryProfile` | Stable versioned public report models; internal benchmark/profiler structs are not exposed. |
| `ImportAnalysisProvider`, `TypeHierarchyProvider`, `TypeAliasProvider`, `TestDetectionProvider` | Optional analyzer capability traits. |
| `RustAnalyzerConfig`, `RustDependencyApiEvidence`, `RustSelectedTarget`, `RustPackageApiArtifact` | Describe passive, exact Cargo and rustdoc evidence supplied by a host. |
| `resolve_rust_semantic_pack_dependencies`, `RustDependencyPackAdapter` | Validate exact Rust dependency selections and prepare reusable semantic-model packs without invoking build tools. |
| `RubyAnalyzerConfig`, `RubyDependencyApiEvidence`, `RubyGemApiArtifact` | Describe passive, exact Bundler and local gem archive evidence supplied by a host. |
| `resolve_ruby_semantic_pack_dependencies`, `RubyDependencyPackAdapter` | Validate exact Ruby dependency selections and prepare reusable RBS/RBI/source semantic-model packs without invoking Ruby tools. |

For most embedded code-intelligence workflows, prefer `SearchToolsService` over manually composing individual analyzer calls. It keeps the tool argument and rendering behavior aligned with MCP and the Python client.

`analyzer::structural::execute` always returns ordinary rows for embedders that own execution policy. Use the top-level `execute_request` to honor the query's root `execution_mode`; its untagged `CodeQueryResponse::Results` variant preserves the existing serialized result shape. Explain performs logical lowering and physical selection without reading analyzer data during that phase, while profile nests the exact ordinary result. Cancellable embedders can call `execute_request_with_cancellation` with a top-level `CancellationToken` and receive the versioned profile, including cancellation observations and a cancellation-safe partial result. See [Explain and Profile CodeQuery](/code-query-explain-profile/) for the stable wire contract and measurement caveats.

## Features

The default Rust build has no optional features enabled.

`nlp` enables semantic search support. It adds the model download, tokenization, and semantic-index plumbing, while the embedding sidecar selects CUDA, Apple Metal, or CPU at runtime.

`python` enables the PyO3 extension module used by the Python package. Maturin turns this on automatically through `pyproject.toml`; ordinary CLI and library builds do not need it.
