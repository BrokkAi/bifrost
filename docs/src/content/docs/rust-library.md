---
title: Rust Library
description: Embed Bifrost directly as a Rust crate.
---

The Cargo package is `brokk-bifrost`, and the Rust crate name is `brokk_bifrost`. It exports the analyzer core, project abstractions, the searchtools service, CodeQuery execution, the stable extension API, and common result types from `src/lib.rs`.

Every package, feature, export, and service method is listed in the [Rust API reference](/reference/rust-api/).

## Add to a Project

Add the released crate with Cargo:

```bash
cargo add brokk-bifrost
```

That produces a dependency like:

```toml
[dependencies]
brokk-bifrost = "0.14.2"
```

For local development against a checkout, use a path dependency:

```bash
cargo add brokk-bifrost --path /path/to/bifrost
```

The package name uses a hyphen, but Rust imports use the crate name with an underscore:

```rust
use brokk_bifrost::{AnalyzerConfig, FilesystemProject, WorkspaceAnalyzer};
```

The crates need Rust 1.99 or later.

## Choose a Package

`brokk-bifrost` is the supported default dependency. It is the compatibility
facade: it re-exports the analyzer and service API, and Cargo resolves the
core, analysis, language-adapter, RQL, flow, policy, semantic-pack, runtime,
and MCP crates automatically. Most applications should depend on this package
alone.

### Language Adapters

Each language family is a separate published adapter crate. This split keeps
language-specific parser and resolver code separate from the shared analysis
engine.

| Source language | Cargo package | Rust crate |
| --- | --- | --- |
| C and C++ | `brokk-bifrost-cpp` | `brokk_bifrost_cpp` |
| C# | `brokk-bifrost-csharp` | `brokk_bifrost_csharp` |
| Go | `brokk-bifrost-go` | `brokk_bifrost_go` |
| JavaScript and TypeScript | `brokk-bifrost-js-ts` | `brokk_bifrost_js_ts` |
| Java, Kotlin, and Scala | `brokk-bifrost-jvm` | `brokk_bifrost_jvm` |
| PHP | `brokk-bifrost-php` | `brokk_bifrost_php` |
| Python | `brokk-bifrost-python` | `brokk_bifrost_python` |
| Ruby | `brokk-bifrost-ruby` | `brokk_bifrost_ruby` |
| Rust | `brokk-bifrost-rust` | `brokk_bifrost_rust` |

`brokk-bifrost` and `brokk-bifrost-analysis` depend on all of these adapters.
Adding one adapter directly does not limit the languages that
`WorkspaceAnalyzer` loads or reduce the facade dependency set.

Use a direct adapter dependency only when you own a focused host or an adapter
integration. Keep every direct Bifrost dependency on the same release version.
The adapter APIs are internal and can change between releases.

### Lower-Level Crates

These crates are published so that focused hosts can compose them. Ordinary
library consumers do not need them. Prefer the facade unless you own one of
these boundaries.

| Cargo package | Contents |
| --- | --- |
| `brokk-bifrost-core` | Source model, project, and workspace utilities. |
| `brokk-bifrost-analysis` | The analysis engine, analyzer store, and search tools. |
| `brokk-bifrost-rql` | RQL syntax, typed query IR, planning, and execution. |
| `brokk-bifrost-flow` | Dataflow, value-flow, taint, and typestate engines. |
| `brokk-bifrost-policy` | Policy loading, evaluation, and reporting. |
| `brokk-bifrost-semantic-packs` | The shipped semantic-model packs and pack bundle installation. |
| `brokk-bifrost-runtime` | The protocol-neutral runtime and the stable extension API. |
| `brokk-bifrost-mcp` | The MCP server implementation and `SearchToolsService`. |

## Stability

`brokk-bifrost`'s exported surface is the supported tier. While the project is
pre-1.0, nothing is contractually frozen. Changes to that surface are
deliberate, and release notes call them out.

Two parts of the facade differ from that rule:

- `brokk_bifrost::extension` is the one module with a versioned compatibility
  contract. Clients negotiate an API version and the operations they need, and
  every response names its operation and stability. See [Stable Extension
  API](#stable-extension-api).
- The modules `benchmark`, `dataflow_differential`, `mcp_install`,
  `mcp_property_fuzzer`, `owasp_benchmark`, `reference_differential`, and
  `repo_status` are public only so that Bifrost's own binaries and tests can
  use them. They are not part of the supported surface.

Everything beneath the facade may change in any release, including a patch.
The lower-level packages exist so that a host that owns one of those boundaries
can compose them, not as a general-purpose API. Their types, traits, module
paths, and crate boundaries change when the internal design requires it.

Nothing enforces this boundary: there is no sealing and no `#[doc(hidden)]`
marking. Depending directly on an internal package compiles and works, but you
are then tracking internals, and an upgrade may require source changes.

## Minimal Analyzer

```rust
use std::sync::Arc;

use brokk_bifrost::{AnalyzerConfig, FilesystemProject, WorkspaceAnalyzer};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    brokk_bifrost::install_bifrost_semantic_model_packs()?;

    let project = Arc::new(FilesystemProject::new(".")?);
    let workspace = WorkspaceAnalyzer::build_persisted(project, AnalyzerConfig::default())?;
    let analyzer = workspace.analyzer();

    println!("languages: {:?}", analyzer.languages());
    println!("files: {}", analyzer.get_analyzed_files().len());
    println!("declarations: {}", analyzer.get_all_declarations().len());
    Ok(())
}
```

`install_bifrost_semantic_model_packs()` registers the shipped semantic-model
packs for the process. Call it once before you build an analyzer or a
`SearchToolsService`. Without it, no shipped packs activate. If the environment
variable `BIFROST_OPEN_SEMANTIC_PACK_BUNDLE` names a pack bundle directory,
Bifrost installs that bundle instead of the shipped packs each time it opens a
catalog for activation. An empty value or a bundle with no compatible pack
makes that activation fail; the call to
`install_bifrost_semantic_model_packs()` itself still succeeds.

`build_persisted` writes the persisted analyzer cache and reuses it on later
runs. [Data and Trust Boundaries](/data-boundaries/) describes where the cache
lives. `build_ephemeral_footgun` builds over a temporary store that is deleted
when the analyzer drops. Use it for tests, immutable fixtures, or a checkout
you must not write to. All `WorkspaceAnalyzer` constructors return
`Result<WorkspaceAnalyzer, StoreError>`.

## Main Public Exports

The most-used exports are below. The complete list is in the [Rust API
reference](/reference/rust-api/).

| Export | Use |
| --- | --- |
| `WorkspaceAnalyzer` | Build a workspace-backed analyzer with default multi-language routing. |
| `IAnalyzer` | Trait for common analyzer operations. |
| `FilesystemProject`, `FileSetProject`, `OverlayProject`, `MultiRootProject` | Project backends for different file-source shapes. |
| `ProjectFile`, `CodeUnit`, `DeclarationInfo`, `Language`, `Range` | Core source and symbol model types. |
| `AnalyzerConfig` | Analyzer settings, including per-language dependency evidence. |
| `SearchToolsService`, `ToolOutput`, `SearchToolsServiceError` | In-process access to the same tool implementations exposed over MCP. |
| `CodeQuery`, `CodeQueryExecutionMode`, `CodeQueryResponse`, `CodeQueryExecutionLimits` | Parse a JSON or RQL query, select results, explain, or profile, and bound execution. |
| `execute_request`, `execute_request_with_limits`, `execute_request_with_cancellation` | Run a `CodeQuery` against an analyzer. |
| `CancellationToken` | Cancel long-running calls. |
| `extension` | The stable, versioned extension API. |
| `install_bifrost_semantic_model_packs`, `open_pack_engine_profile` | Register the shipped semantic packs; report the pack-consumer profile. |
| `BIFROST_VERSION`, `BIFROST_BUILD_IDENTITY` | The package version and the exact source revision of this build. |

The facade also exports passive dependency-evidence types for Rust, Ruby, PHP,
and JVM dependencies (for example `RustDependencyApiEvidence`,
`PhpDependencyApiEvidence`, and `JvmExternalDependencies`). A host supplies
this evidence. Bifrost reads it without running build tools.

## SearchToolsService

For most embedded code-intelligence work, use `SearchToolsService` instead of
composing analyzer calls yourself. It keeps tool arguments and rendering the
same as MCP and the Python client.

```rust
use std::path::PathBuf;

use brokk_bifrost::SearchToolsService;
use serde_json::json;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    brokk_bifrost::install_bifrost_semantic_model_packs()?;

    let service = SearchToolsService::new_manual_persisted(PathBuf::from("."))?;
    let symbols = service.call_tool_value("search_symbols", json!({ "patterns": ["parse_*"] }))?;
    println!("{symbols:#}");

    // After the caller changes files on disk:
    service.call_tool_value("update_paths", json!({ "paths": ["src/main.rs"] }))?;

    service.close()?;
    Ok(())
}
```

`SearchToolsService::new(root)` starts a file watcher, so later calls see file
changes. `new_manual_persisted(root)` has no watcher; the caller reports changes
with the `update_paths` or `refresh` tool. Both build the index before they
return and use the persisted analyzer cache.

`call_tool_value(name, arguments)` returns the structured JSON result.
`call_tool_output(name, arguments, render_options)` also returns the rendered
text. `query_code_result(arguments)` runs `query_code` and returns a typed
`CodeQueryResponse`. `request_cache_gc()` forces a cache collection. The tool
names and arguments are the MCP tool names and arguments, plus `update_paths`,
`list_symbols`, and `classify_test_files`. The [Rust API
reference](/reference/rust-api/) lists every constructor and method.

[Library Integration](/code-query-tutorials/library-integration/) is the executable walkthrough: it runs one canonical query through `SearchToolsService::query_code_result(...)` against a checked-in fixture, shows the typed result consumption, states when to use the lower-level `execute_request` API instead, and runs the same query through the Python client so the two stay in step.

## Run CodeQuery Directly

Build a query with `CodeQuery::from_json(&value)` or, for RQL text,
`CodeQuery::from_source(text)`. Then run it against an analyzer:

| Function | Behavior |
| --- | --- |
| `execute_request(analyzer, &query)` | Honors the query's root `execution_mode`. Uses default limits. |
| `execute_request_with_limits(analyzer, &query, limits)` | Same, with caller-supplied `CodeQueryExecutionLimits`. |
| `execute_request_with_cancellation(analyzer, &query, limits, &cancellation)` | Same, with a `CancellationToken`. The profile response includes cancellation observations and a partial result that is safe to read. |
| `brokk_bifrost::rql::execute(analyzer, &query)` | Always returns ordinary rows, for embedders that own execution policy. |

`CodeQueryExecutionLimits::default()` gives the interactive limits. Its fields
and defaults are in the [Rust API reference](/reference/rust-api/).

The untagged `CodeQueryResponse::Results` variant keeps the ordinary serialized
result shape. Explain performs logical lowering and physical selection without
reading analyzer data in that phase. Profile includes the exact ordinary
result. See [Explain and Profile CodeQuery](/code-query-explain-profile/) for
the wire format and measurement caveats.

```rust
use std::sync::Arc;

use brokk_bifrost::{
    AnalyzerConfig, CancellationToken, CodeQuery, CodeQueryExecutionLimits, FilesystemProject,
    WorkspaceAnalyzer, execute_request_with_cancellation,
};
use serde_json::json;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    brokk_bifrost::install_bifrost_semantic_model_packs()?;
    let project = Arc::new(FilesystemProject::new(".")?);
    let workspace = WorkspaceAnalyzer::build_persisted(project, AnalyzerConfig::default())?;

    let query = CodeQuery::from_json(&json!({
        "match": { "kind": "function", "name": "run" }
    }))?;
    let cancellation = CancellationToken::new();
    let response = execute_request_with_cancellation(
        workspace.analyzer(),
        &query,
        CodeQueryExecutionLimits::default(),
        &cancellation,
    );
    let result = response.result().expect("results mode returns rows");
    println!("rows: {}, truncated: {}", result.results.len(), result.truncated);
    Ok(())
}
```

## Registered Query Steps

The CodeQuery steps `typestate`, `value_flow`, and `taint` read a compiled
protocol, a value-flow plan, or retained taint results that the host
registered. Only Rust can register them, on a `SearchToolsService`:

- `register_query_protocol` and `unregister_query_protocol`
- `register_query_value_flow_plan` and `unregister_query_value_flow_plan`
- `register_query_taint_results` and `unregister_query_taint_results`

A query names a registration with a `namespace:name` reference, such as
`"taint_ref": "request:http-to-database"`. The CLI, REPL, MCP server, and
Python client cannot register, so these steps return an unresolved-reference
diagnostic there. The `execute_request` functions have no registrations
either. The reference format, outcomes, and limits are in the [Rust API
reference](/reference/rust-api/).

## Stable Extension API

`brokk_bifrost::extension` is the versioned API for independent applications.
It is at version 1.1. A client states the API versions and operations it needs
in an `ExtensionCompatibility` value. `negotiate_extension_api` accepts or
rejects it, and every request carries it again.

| Operation | Stability | Support |
| --- | --- | --- |
| `structural.query` | stable | complete |
| `experimental.semantic.control_flow` | experimental | complete |
| `experimental.semantic.value_dependence` | experimental | partial |
| `experimental.semantic.typestate` | experimental, added in 1.1 | partial |

Open a workspace with `ExtensionWorkspace::open(ExtensionWorkspaceOptions::new(root))`.
The default store is in memory. Call `.persisted()` on the options to use the
persisted analyzer cache. The workspace then answers `structural_query`,
`semantic_relations`, and `typestate_check` requests. Each request names the
workspace generation it expects, and each response reports its completion,
diagnostics, work, and limits. The module also has a JSON codec
(`decode_request_json`, `encode_request_json`, `encode_response_json`). The
[Rust API reference](/reference/rust-api/) has the full API and an example.

## Features

The default build enables no optional features.

| Feature | Use |
| --- | --- |
| `python` | Builds the PyO3 extension module that the Python package uses. |
| `extension-module` | Stops the build from linking libpython. maturin enables it together with `python` when it builds the Python package. Do not enable it for an executable, because the link fails. |
| `test-support` | Re-exports test-only hooks for use in a downstream crate's own tests. |

`release-tooling` and `randomized-hash` are internal features for Bifrost's
release and CI builds. Ordinary CLI and library builds need no feature.
