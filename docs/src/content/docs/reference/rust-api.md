---
title: Rust API
description: Published crates, features, top-level exports, SearchToolsService methods, CodeQuery execution, query registration, and the stable extension API of the brokk_bifrost crate.
---

This page lists the public Rust surface of Bifrost 0.12.0. The Cargo package is
`brokk-bifrost` and the crate name is `brokk_bifrost`. For a task-oriented
introduction and the stability policy, see [Rust Library](/rust-library/).

Generate the complete item-level documentation for your dependency tree with
`cargo doc -p brokk-bifrost --open`.

## Published Crates

Every workspace package is published to crates.io at the same version.
Keep every direct Bifrost dependency on the same version.

| Cargo package | Rust crate | Contents |
| --- | --- | --- |
| `brokk-bifrost` | `brokk_bifrost` | The facade. Re-exports the supported API and builds the `bifrost` binary. Most applications depend on this package alone. |
| `brokk-bifrost-core` | `brokk_bifrost_core` | Source model, project, and workspace utilities shared by every other crate. |
| `brokk-bifrost-analysis` | `brokk_bifrost_analysis` | The protocol-neutral analysis engine: analyzers, the analyzer store, search tools, and usage analysis. |
| `brokk-bifrost-rql` | `brokk_bifrost_rql` | RQL syntax, typed query IR, planning, and execution. |
| `brokk-bifrost-flow` | `brokk_bifrost_flow` | Dataflow, value-flow, taint, and typestate engines. |
| `brokk-bifrost-policy` | `brokk_bifrost_policy` | Policy loading, evaluation, and reporting. |
| `brokk-bifrost-semantic-packs` | `brokk_bifrost_semantic_packs` | The shipped semantic-model packs and pack bundle installation. It also has a `bifrost-semantic-pack` binary that requires the `release-tooling` feature. |
| `brokk-bifrost-runtime` | `brokk_bifrost_runtime` | The protocol-neutral runtime and the stable extension API. |
| `brokk-bifrost-mcp` | `brokk_bifrost_mcp` | The MCP server implementation and `SearchToolsService`. |
| `brokk-bifrost-cpp` | `brokk_bifrost_cpp` | C and C++ language adapter. |
| `brokk-bifrost-csharp` | `brokk_bifrost_csharp` | C# language adapter. |
| `brokk-bifrost-go` | `brokk_bifrost_go` | Go language adapter. |
| `brokk-bifrost-js-ts` | `brokk_bifrost_js_ts` | JavaScript and TypeScript language adapter. |
| `brokk-bifrost-jvm` | `brokk_bifrost_jvm` | Java, Kotlin, and Scala language adapter. |
| `brokk-bifrost-php` | `brokk_bifrost_php` | PHP language adapter. |
| `brokk-bifrost-python` | `brokk_bifrost_python` | Python language adapter. |
| `brokk-bifrost-ruby` | `brokk_bifrost_ruby` | Ruby language adapter. |
| `brokk-bifrost-rust` | `brokk_bifrost_rust` | Rust language adapter. |

The minimum Rust version is 1.99, and the crates use the 2024 edition.

## Facade Features

| Feature | Default | Meaning |
| --- | --- | --- |
| `python` | off | Builds the PyO3 extension module `bifrost_searchtools._native`. |
| `extension-module` | off | Stops the build from linking libpython, which a Python extension needs. maturin enables it together with `python`. Do not enable it for an executable: the link fails. |
| `test-support` | off | Re-exports the test-only hooks of the implementation crates, for use in a downstream crate's own tests. Never enable it in a shipped build. |
| `release-tooling` | off | Internal. Benchmark and release artifact tooling. |
| `randomized-hash` | off | Internal. A CI mode that seeds internal hash tables randomly. |

The Python package's build configuration enables `python` and
`extension-module`. Ordinary library and CLI builds need no feature.

## Module Status

These are the public modules of `brokk_bifrost`.

| Module | Status |
| --- | --- |
| `extension` | Stable extension API with a negotiated version. See [Extension API](#extension-api). |
| `rql`, `sexp` | CodeQuery and RQL: the `brokk-bifrost-rql` crate, and its S-expression parser and formatter. |
| `analyzer`, `searchtools`, `searchtools_render`, `navigation`, `usages`, `summary`, `symbol_rename`, `relevance`, `diff_analysis`, `cyclomatic_complexity_diff`, `code_quality`, `file_tools`, `compact_graph`, `model_context`, `workspace_document` | Analysis modules from `brokk-bifrost-analysis`. |
| `cancellation`, `cache_db`, `cache_gc`, `git_file`, `gitblob`, `hash`, `panic_report`, `path_normalization`, `path_utils`, `process`, `profiling`, `schema_version`, `seam_profile`, `text_utils`, `util` | Support modules from `brokk-bifrost-analysis`. |
| `flow` | The `brokk-bifrost-flow` crate. |
| `policy` | The `brokk-bifrost-policy` crate. |
| `semantic_packs` | The `brokk-bifrost-semantic-packs` crate. |
| `code_intelligence` | Host implementation interface from `brokk-bifrost-runtime`. No compatibility guarantee. |
| `searchtools_service`, `mcp_cli`, `mcp_common`, `mcp_core`, `mcp_diff`, `mcp_extended`, `mcp_registry`, `mcp_slopcop`, `mcp_text`, `rmcp_host`, `scoped_project`, `tool_arguments` | MCP server implementation from `brokk-bifrost-mcp`. |
| `benchmark`, `dataflow_differential`, `mcp_install`, `mcp_property_fuzzer`, `owasp_benchmark`, `reference_differential`, `repo_status` | Internal harnesses for Bifrost's own binaries and tests. Not part of the supported surface. |
| `summary_foundry_fixtures`, `summary_foundry_demand` | Internal. Present only with the `release-tooling` feature. |

## Top-Level Items

These items are re-exported at `brokk_bifrost::<name>`.

### Workspaces and Analyzers

| Item | Kind | Meaning |
| --- | --- | --- |
| `WorkspaceAnalyzer` | enum | A workspace analyzer with multi-language routing and an analyzer store. See [WorkspaceAnalyzer Constructors](#workspaceanalyzer-constructors). |
| `MultiAnalyzer` | struct | Routes requests across per-language analyzers. |
| `AnalyzerDelegate` | enum | One per-language analyzer inside a `MultiAnalyzer`. |
| `EmptyAnalyzer` | struct | The analyzer for a project with no supported files. |
| `IAnalyzer` | trait | Common analyzer operations: files, declarations, sources, summaries, and lookups. |
| `TreeSitterAnalyzer` | struct | The shared tree-sitter analyzer implementation that each language analyzer wraps. |
| `CppAnalyzer`, `CSharpAnalyzer`, `GoAnalyzer`, `JavaAnalyzer`, `JavascriptAnalyzer`, `KotlinAnalyzer`, `PhpAnalyzer`, `PythonAnalyzer`, `RubyAnalyzer`, `RustAnalyzer`, `ScalaAnalyzer`, `TypescriptAnalyzer` | structs | Per-language analyzers. |
| `AnalyzerConfig` | struct | Analyzer settings. See [AnalyzerConfig](#analyzerconfig). |
| `DispatchHierarchyExpansion` | struct | Which class-hierarchy expansions call dispatch adds. Constants `OFF` and `CONCRETE_OVERRIDES`. |
| `AnalyzerDefinitionLookup` | struct | A bounded forward-lookup view over an analyzer. |
| `CapabilityProvider` | trait | Gives access to an analyzer's optional capability traits. |
| `ImportAnalysisProvider`, `TypeHierarchyProvider`, `TypeAliasProvider`, `TestDetectionProvider` | traits | Optional analyzer capabilities. |
| `ImportReachability` | enum | Whether a candidate file can reference a target declaration: `Reaches`, `DoesNotReach` (only from a complete proof), or `Unknown`. |
| `collect_workspace_files` | function | Lists every file under a root that the analyzer considers part of the workspace. Respects ignore files and skips `.git/`. |
| `ensure_global_rayon_pool` | function | Configures the process-wide rayon thread pool. Safe to call more than once; the first call wins. |
| `CancellationToken` | struct | A cloneable cancellation flag for long-running calls. |

### Projects and Source Model

| Item | Kind | Meaning |
| --- | --- | --- |
| `Project` | trait | A source of project files and their contents. |
| `FilesystemProject` | struct | A project read from a directory. `FilesystemProject::new(root) -> std::io::Result<Self>`. |
| `FileSetProject` | struct | A project with a fixed list of files. `FileSetProject::new(root, rel_paths)`. |
| `OverlayProject` | struct | Wraps another project and serves in-memory buffers for some files. |
| `MultiRootProject` | struct | A project over several directory roots. |
| `TestProject` | struct | A small project for tests. |
| `ProjectFile` | struct | A file path inside a project root. |
| `SourceContent` | struct | The text of one source file. |
| `Language` | enum | A supported source language. |
| `CodeUnit` | struct | A declaration: class, function, field, or module. |
| `CodeUnitType` | enum | The coarse category of a `CodeUnit`. |
| `CodeUnitIndex` | struct | An index of code units. |
| `DeclarationInfo`, `DeclarationKind` | struct, enum | Declaration details and kind. |
| `ImportInfo` | struct | One import statement. |
| `NavigationOperation` | enum | `Declaration` or `Definition`. |
| `ParseError`, `ParseErrorKind` | struct, enum | A tree-sitter parse error and its kind. |
| `Range` | struct | A source range. |
| `CodeBaseMetrics` | struct | Workspace size metrics. |
| `SummaryInput`, `RenderedSummary`, `summarize_inputs` | struct, struct, function | Render summaries for a set of inputs. |
| `CloneSmell`, `CloneSmellWeights`, `TestAssertionSmell`, `TestAssertionWeights` | structs | Code-quality findings and their scoring weights. |

### Dependency Evidence and Semantic Packs

A host supplies dependency evidence. Bifrost reads the named files and does not
run build tools for these types.

| Item | Kind | Meaning |
| --- | --- | --- |
| `RustAnalyzerConfig`, `RustDependencyApiEvidence`, `RustSelectedTarget`, `RustPackageApiArtifact` | structs | Exact Cargo and rustdoc evidence for Rust dependencies. |
| `resolve_rust_semantic_pack_dependencies`, `RustDependencyPackAdapter` | function, struct | Validate exact Rust dependency selections and prepare reusable semantic-model packs. |
| `RubyAnalyzerConfig`, `RubyDependencyApiEvidence`, `RubyGemApiArtifact` | structs | Exact Bundler and local gem archive evidence. |
| `resolve_ruby_semantic_pack_dependencies`, `RubyDependencyPackAdapter` | function, struct | Validate exact Ruby dependency selections and prepare RBS, RBI, or source packs. |
| `PhpAnalyzerConfig`, `PhpDependencyApiEvidence` | structs | Composer metadata and installed package trees under approved vendor roots. Bifrost never runs Composer or dependency code and opens no network connection. |
| `resolve_php_semantic_pack_dependencies`, `PhpDependencyPackAdapter` | function, struct | Validate exact PHP dependency selections and prepare packs. |
| `JvmAnalyzerConfig` | struct | JVM settings: `external_dependencies`, `dependency_discovery`, and `standard_library_discovery`. |
| `JvmExternalDependencies` | struct | `artifact_paths`, `coordinates`, `repository_roots`, and `gradle_cache_roots`. |
| `JvmExternalArtifact`, `JvmMavenCoordinate` | structs | One artifact path (with optional source artifact and coordinate) and one Maven coordinate (`group_id`, `artifact_id`, `version`). |
| `JvmDependencyDiscoveryConfig` | struct | `mode`, `maven_executable`, `gradle_executable`, `timeout` (default 30 seconds). |
| `JvmDependencyDiscoveryMode` | enum | `Disabled`, `Metadata` (default), `OfflineBuildTools`. |
| `DependencyPackWorkspaceContext` | struct | Caller-owned state needed to activate configured dependency packs. A workspace never opens a pack catalog unless the host supplies this. |
| `DependencyPackEcosystem`, `DependencyPackEcosystemOutcome`, `DependencyPackActivationOutcome` | enum, structs | The ecosystems a host can activate, and the result of one activation. |
| `PythonSemanticModelWorkspaceContext` | struct | Workspace context for Python semantic models. |
| `install_bifrost_semantic_model_packs` | function | `fn() -> Result<(), String>`. Registers the shipped semantic packs for the process. If `BIFROST_OPEN_SEMANTIC_PACK_BUNDLE` names a bundle directory, Bifrost installs that bundle instead whenever it opens a catalog for activation; an empty value or a bundle with no compatible pack makes that activation fail. Call it once before you build analyzers or a `SearchToolsService`. Without it, no shipped packs activate. Later calls return the first result. |
| `open_pack_engine_profile` | function | `fn() -> serde_json::Value`. The pack-consumer profile of this build: engine version, build identity, model-set digest, supported schema versions, and capabilities. `bifrost pack-engine-profile` prints the same JSON. |
| `BIFROST_VERSION` | `&str` | The facade package version. |
| `BIFROST_BUILD_IDENTITY` | `&str` | The exact source revision embedded at build time. `bifrost --build-identity` prints it. |

### Service and CodeQuery

| Item | Kind | Meaning |
| --- | --- | --- |
| `SearchToolsService` | struct | In-process access to every Bifrost tool. See [SearchToolsService](#searchtoolsservice). |
| `SearchToolsServiceError` | struct | `code: SearchToolsServiceErrorCode` and `message: String`. Implements `std::error::Error`. |
| `SearchToolsServiceErrorCode` | enum | `InvalidParams`, `StaleWorkspaceGeneration { requested, current }`, `UnknownTool`, `DeadlineExceeded`, `Internal`. |
| `ToolOutput` | enum | `Text(String)` or `Structured { structured: Value, rendered_text: Option<String> }`. |
| `ProjectChangeWatcher`, `ChangeDelta` | struct, struct | The file watcher that a watched service uses, and one batch of changes. |
| `CodeQuery` | struct | A parsed query. See [CodeQuery Execution](#codequery-execution). |
| `CodeQueryExecutionMode` | enum | `Results`, `Explain`, `Profile`. |
| `CodeQueryExecutionLimits` | struct | Execution limits for one query. |
| `CodeQueryResponse` | enum | `Results(CodeQueryResult)`, `Explain(CodeQueryExplain)`, or `Profile(Box<CodeQueryProfile>)`. `result()` returns the ordinary result for `Results` and `Profile`. |
| `CodeQueryExplain`, `CodeQueryProfile` | structs | Versioned explain and profile reports. See [Explain and Profile CodeQuery](/code-query-explain-profile/). |
| `execute_request`, `execute_request_with_limits`, `execute_request_with_cancellation` | functions | Run a `CodeQuery` against an analyzer. |
| `CodeIntelligenceRuntime` | struct | Host implementation interface that runs typed requests against one caller-owned workspace. No compatibility guarantee. |

With the `test-support` feature, the facade also exports
`reset_rust_tree_parse_counters_for_test`, `rust_tree_parse_count_for_test`,
`rust_tree_parse_request_count_for_test`, and `rust_tree_parsed_bytes_for_test`.

## AnalyzerConfig

`AnalyzerConfig` has public fields. `AnalyzerConfig::default()` reads two
environment variables.

| Field | Type | Default |
| --- | --- | --- |
| `parallelism` | `Option<usize>` | `BIFROST_PARALLELISM` if it is a positive integer, else the number of available CPUs. |
| `memo_cache_budget_bytes` | `Option<u64>` | 256 MiB. |
| `dispatch_hierarchy_expansion` | `DispatchHierarchyExpansion` | `concrete_overrides` is on when `BIFROST_CHA_CONCRETE_OVERRIDES` is set, and off otherwise. |
| `rust` | `RustAnalyzerConfig` | default |
| `jvm` | `JvmAnalyzerConfig` | default |
| `csharp` | `analyzer::CSharpAnalyzerConfig` | default. `assembly_paths` lists extra assemblies to index. |
| `js_ts` | `analyzer::JsTsAnalyzerConfig` | default |
| `go` | `analyzer::GoAnalyzerConfig` | default |
| `python` | `analyzer::PythonAnalyzerConfig` | default |
| `ruby` | `RubyAnalyzerConfig` | default |
| `php` | `PhpAnalyzerConfig` | default |

## WorkspaceAnalyzer Constructors

Every constructor takes `project: Arc<dyn Project>` and `config:
AnalyzerConfig`, and returns `Result<WorkspaceAnalyzer, StoreError>`. Call
`analyzer()` on the result to get `&dyn IAnalyzer`.

| Constructor | Store |
| --- | --- |
| `build_persisted(project, config)` | The repository's persisted analyzer cache. Reuses stored facts across runs and collects the cache automatically. Fails if the project has no persistence root. |
| `build_persisted_for_languages(project, config, &BTreeSet<Language>)` | Same cache. Runs only the parsers of the given languages. |
| `build_persisted_without_automatic_gc(project, config)` | Same cache. Collects only when the host asks. |
| `build_persisted_with_progress(project, config, progress)` and `build_persisted_without_automatic_gc_with_progress(project, config, progress)` | As above, with a progress callback. |
| `build_persisted_with_tier_access(project, config)` | As `build_persisted`, and also returns a record of which information tiers the build read. |
| `build_scoped_persisted(project, config)` | Shares stored facts with the full workspace but keeps an isolated file list for a partial project. |
| `build_ephemeral_footgun(project, config)` | A temporary store that is deleted when the analyzer drops. Nothing is reused. Use it for tests, for a checkout you must not write to, or for cold-build measurement. |
| `build_ephemeral_for_languages_footgun(project, config, &BTreeSet<Language>)` and `build_ephemeral_with_tier_access_footgun(project, config)` | Ephemeral variants. |

[Data and Trust Boundaries](/data-boundaries/) describes where the persisted
cache lives and what it contains.

## SearchToolsService

`SearchToolsService` runs the same tool implementations as the MCP server, in
process. Call `install_bifrost_semantic_model_packs()` before you construct it.

### Constructors

All constructors return `Result<SearchToolsService, String>`, except
`new_unbound` and `new_unbound_manual`, which return `Self`. Every service uses
the persisted analyzer cache unless the row says otherwise.

| Constructor | File changes | Index build |
| --- | --- | --- |
| `new(root: PathBuf)` | A file watcher applies changes before each query. | Before the constructor returns. |
| `new_manual_persisted(root: PathBuf)` | Only `update_paths` and `refresh` apply changes. | Before the constructor returns. |
| `new_deferred(root: PathBuf)` | File watcher. | On a background thread. The constructor returns at once. |
| `new_deferred_manual(root: PathBuf)` | Only `refresh` and `update_paths`. | On a background thread. |
| `new_one_shot(root: PathBuf)` | None. For a process that answers one call and exits. | Before the constructor returns. |
| `new_one_shot_workspace_independent(root: PathBuf)` | None. For one diff tool call that reads only Git endpoints. | Only if a call needs the workspace. |
| `new_unbound()`, `new_unbound_manual()` | Watcher, or manual. | After `bind_client_workspace(root)`. Until then, analyzer tools return an error. |
| `new_manual_persisted_for_project(project: Arc<dyn Project>, config: AnalyzerConfig)` | Manual. Cache collection only on request. | Before the constructor returns. |
| `new_manual_persisted_with_progress_for_project(project, config, progress)` | As above, with a progress callback. | Before the constructor returns. |
| `new_manual_scoped_persisted_for_project(project, config)` | Manual, over a partial project. | Before the constructor returns. |
| `new_manual_ephemeral_footgun_for_project(project, config)` | Manual. Uses an ephemeral store that is deleted when the service drops. | Before the constructor returns. |

Configuration methods, called on a new service:

| Method | Meaning |
| --- | --- |
| `with_diff_snapshot_object_dir(self, dir: PathBuf) -> Self` | Trusted Git objects directory for immutable diff endpoints. |
| `with_workspace_scaled_query_limits(self) -> Self` | Scales `query_code` execution limits to the analyzed source volume, as policy evaluation does. |

### Tool Calls

Tool names and arguments are the same as the MCP tools, plus `update_paths`,
`list_symbols`, and `classify_test_files`. See the [MCP tools
reference](/reference/mcp-tools/).

| Method | Returns | Meaning |
| --- | --- | --- |
| `call_tool_value(&self, name: &str, arguments: Value)` | `Result<Value, SearchToolsServiceError>` | Structured result as JSON. |
| `call_tool_json(&self, name: &str, arguments_json: &str)` | `Result<String, SearchToolsServiceError>` | Same, with JSON text in and out. |
| `call_tool_output(&self, name: &str, arguments: Value, render_options: RenderOptions)` | `Result<ToolOutput, SearchToolsServiceError>` | Structured result and rendered text. `RenderOptions` is in `searchtools_render` and has one field, `render_line_numbers`. |
| `call_tool_output_with_cancellation(&self, name, arguments, render_options, cancellation: Option<&CancellationToken>)` | `Result<ToolOutput, SearchToolsServiceError>` | Same, with cancellation. |
| `call_tool_payload_json(&self, name, arguments_json, render_options)` | `Result<String, SearchToolsServiceError>` | JSON text `{"structured": ..., "rendered_text": ...}`. The Python client uses this method. |
| `query_code_result(&self, arguments: Value)` | `Result<CodeQueryResponse, SearchToolsServiceError>` | Runs `query_code` and returns the typed response instead of JSON. |
| `tool_is_workspace_independent(name: &str, arguments: &Value) -> bool` | `bool` | Associated function. True for tools that read only Git endpoints. |

### Lifecycle

| Method | Meaning |
| --- | --- |
| `close(&self) -> Result<(), SearchToolsServiceError>` | Drops the session. Later analyzer calls fail. |
| `request_cache_gc(&self) -> Result<(), SearchToolsServiceError>` | Forces a Git-reachability collection of the persisted cache and waits until it finishes. |
| `active_workspace_root(&self) -> Option<PathBuf>` | The current workspace root. |
| `analyzer_snapshot(&self) -> Result<Arc<WorkspaceAnalyzer>, String>` | The current workspace analyzer, for read-only use. |
| `bind_client_workspace(&self, root: PathBuf)` | Binds an unbound service to a root. Returns the canonical root. |
| `unbind_client_workspace(&self)` | Removes a bound root. |
| `wait_workspace_ready(&self, cancelled: &dyn Fn() -> bool)` and `wait_workspace_ready_until(&self, cancelled, deadline: Option<Instant>)` | Wait for a deferred build to finish. |
| `workspace_build_pending(&self) -> bool` | Whether a deferred build is still running. |
| `evaluate_policy_inputs(&self, root, policy_inputs, options)` and `evaluate_policy_inputs_with_observer(...)` | Evaluate a policy batch against the service's workspace. |

### Query Registration

The CodeQuery steps `typestate`, `value_flow`, and `taint` read a protocol, a
plan, or a result that the host registered on this service. Registration is
available only through these Rust methods. The CLI, the REPL, the MCP server,
and the Python client never register anything, so in those surfaces these
steps return an `unresolved_protocol_reference`,
`unresolved_value_flow_plan_reference`, or `unresolved_taint_result_reference`
diagnostic and no rows. A `.rqlp` policy runs these analyses without
registration; see [Static Analysis Policies](/static-analysis-policies/).

| Method | Arguments | Returns |
| --- | --- | --- |
| `register_query_protocol` | `protocol_ref: rql::ProtocolRef`, `expected_root: analyzer::semantic::ProcedureHandle`, `protocol: Arc<flow::typestate::CompiledProtocol>`, `bindings: Arc<flow::typestate::TypestateBindingPlan>` | `Result<rql::ProtocolRegistrationOutcome, SearchToolsServiceError>` |
| `unregister_query_protocol` | `&rql::ProtocolRef` | `Result<bool, SearchToolsServiceError>` (whether a registration was removed) |
| `register_query_value_flow_plan` | `plan_ref: rql::ValueFlowPlanRef`, `plan: Arc<flow::value_flow::ValueFlowPlan>` | `Result<rql::ValueFlowPlanRegistrationOutcome, SearchToolsServiceError>` |
| `unregister_query_value_flow_plan` | `&rql::ValueFlowPlanRef` | `Result<bool, SearchToolsServiceError>` |
| `register_query_taint_results` | `taint_ref: rql::TaintResultRef`, `results: Vec<Arc<policy::ProductionTaintAnalysisResult>>` | `Result<rql::TaintResultRegistrationOutcome, SearchToolsServiceError>` |
| `unregister_query_taint_results` | `&rql::TaintResultRef` | `Result<bool, SearchToolsServiceError>` |

The query refers to a registration by its reference string: `protocol_ref` in
a `typestate` step, `plan_ref` in a `value_flow` step, and `taint_ref` in a
`taint` step.

Registration outcomes:

| Outcome | Meaning |
| --- | --- |
| `Inserted` | A new registration was stored under the reference. |
| `Aliased` | An identical registration already existed under another reference. The new reference points to it. |
| `Unchanged` | The reference already names an identical registration. |

Registering a different value under a reference that is already in use fails
with `InvalidParams`. Each registration records the workspace generation. After
the workspace changes, a query that uses it returns
`typestate_registration_stale`, `value_flow_registration_stale`, or
`taint_registration_stale`.

Reference format: `namespace:name`. Parse one with `str::parse` or build one
with `new(namespace, name)`.

| Rule | Value |
| --- | --- |
| Whole reference | At most 192 bytes. |
| Namespace | 1 to 63 bytes. |
| Name | 1 to 128 bytes. |
| Characters | Lowercase ASCII letters, digits, `-`, `_`, and `.`. The first and last character must be a letter or digit. |

Limits per service, for each of the three kinds:

| Limit | Protocols | Value-flow plans | Taint results |
| --- | --- | --- | --- |
| References (names, including aliases) | 256 | 256 | 256 |
| Distinct registrations | 128 | 128 | 128 |
| Retained bytes | protocols 4 MiB, binding plans 16 MiB, artifacts 64 MiB | plans 64 MiB, artifacts 64 MiB | plans 64 MiB, reports 64 MiB, artifacts 64 MiB |
| Results per registration | | | 256 |

## CodeQuery Execution

Build a query from JSON with `CodeQuery::from_json(&serde_json::Value) ->
Result<CodeQuery, QueryError>`, or from RQL text with
`CodeQuery::from_source(&str) -> Result<CodeQuery, String>`. RQL text is
limited to 64 KiB. `CodeQuery::to_canonical_json()` returns the canonical JSON
form. The `sexp` module holds the S-expression parser (`parse_sexp`,
`parse_sexp_with_limits`, `parse_sexp_document_with_limits`) and formatter
(`format_sexp_document`) that RQL, RQLP, and Rune IR share.

| Function | Signature |
| --- | --- |
| `execute_request` | `fn(analyzer: &dyn IAnalyzer, query: &CodeQuery) -> CodeQueryResponse` |
| `execute_request_with_limits` | `fn(analyzer: &dyn IAnalyzer, query: &CodeQuery, limits: CodeQueryExecutionLimits) -> CodeQueryResponse` |
| `execute_request_with_cancellation` | `fn(analyzer: &dyn IAnalyzer, query: &CodeQuery, limits: CodeQueryExecutionLimits, cancellation: &CancellationToken) -> CodeQueryResponse` |
| `rql::execute` | `fn(analyzer: &dyn IAnalyzer, query: &CodeQuery) -> CodeQueryResult`. Ignores `execution_mode` and always returns ordinary rows. |

The `execute_request` functions honor the query's `execution_mode`. They have
no registrations, so `typestate`, `value_flow`, and `taint` steps report an
unresolved reference. Use `SearchToolsService::query_code_result` for those.

`CodeQueryExecutionLimits::default()` values:

| Field | Default |
| --- | --- |
| `max_scanned_files` | 20,000 |
| `max_scanned_source_bytes` | 128 MiB |
| `max_fact_nodes` | 2,000,000 |
| `max_pipeline_rows` | 50,000 |
| `semantic` (`CodeQuerySemanticLimits`) | `max_materialized_files` 256, `max_source_bytes` 16 MiB, `max_rows_per_dimension` 1,000,000, `max_retained_bytes` 256 MiB, `rows_per_dimension` `None` |
| `typestate` (`CodeQueryTypestateLimits`) | `max_reached_rows` 1,000,000, `max_candidates` 8,192, `max_witness_steps` 64, `max_witness_expansions` 4,096, `max_total_witness_expansions` 1,000,000, `max_witness_bytes` 64 MiB, `solver_work` engine default |
| `value_flow` (`CodeQueryValueFlowLimits`) | `max_retained_relations` 262,144, `max_retained_bytes` 16 MiB, `max_endpoints` 50,000, `max_witnesses` 4,096, `max_witness_steps` 4,096, `max_witness_expansions` 16,384, `max_witness_bytes` 4 MiB, `max_total_witness_steps` 262,144, `max_total_witness_expansions` 1,048,576, `max_total_witness_bytes` 16 MiB, `solver_work` engine default |
| `taint` (`CodeQueryTaintLimits`) | `max_findings` 50,000, `max_projected_bytes` 64 MiB, `max_origins_per_finding` 4,096, `max_witnesses_per_finding` 4,096, `max_steps_per_witness` 4,096, `max_witness_bytes` 4 MiB |

Semantic source and row capacities bound resident admissions. Scans and traversal
visits never refuse: receipts report their cumulative counts and largest
per-root work balances separately from resident peaks. Cumulative counts include
admissions plus work, so the same held-and-scanned bytes can count twice.

For the typestate, value-flow, and taint groups, a zero value or a value above
the group's hard maximum makes a query that uses that analysis return an
`invalid_plan` diagnostic.

## Extension API

`brokk_bifrost::extension` (the same module as
`brokk_bifrost_runtime::extension`) is the versioned API for independent
applications. Types outside this module carry no compatibility promise.

| Constant | Value |
| --- | --- |
| `EXTENSION_API_VERSION` | `ExtensionApiVersion { major: 1, minor: 1 }`. Minor versions only add. |
| `EXTENSION_RUN_MANIFEST_SCHEMA` | `"2.0"` |
| `TYPESTATE_OPERATION` | `"experimental.semantic.typestate"` |
| `MAX_RETAINED_SEMANTIC_GAP_REASONS` | 16 |

### Published Operations

`PUBLISHED_OPERATIONS` is the single list of what the API offers.
`ExtensionWorkspace::capabilities()` reports it, and negotiation accepts exactly
the operations whose support is `Complete` or `Partial`.

| Operation id | Stability | Support | Entry point |
| --- | --- | --- | --- |
| `structural.query` | stable | complete | `ExtensionWorkspace::structural_query` |
| `experimental.semantic.control_flow` | experimental since minor 0 | complete | `ExtensionWorkspace::semantic_relations` |
| `experimental.semantic.value_dependence` | experimental since minor 0 | partial | `ExtensionWorkspace::semantic_relations` with `SemanticRelationKind::ValueDependence` |
| `experimental.semantic.typestate` | experimental since minor 1 | partial | `ExtensionWorkspace::typestate_check` |

`Partial` limits coverage, not availability. The per-language rows of the
capability report (`LanguageCapabilityReport`: `control_flow`,
`value_dependence`, `typestate`) say where an operation is unavailable. Every
response states its operation and stability in its metadata.

### Negotiation

```rust
pub struct ExtensionCompatibility {
    pub major: u16,
    pub minimum_minor: u16,
    pub maximum_minor: u16,
    pub required_capabilities: Box<[ExtensionCapabilityId]>,
}
```

`ExtensionCompatibility::default()` is major 1, minors 0 to 0, no required
capabilities. `negotiate_extension_api(&ExtensionCompatibility)` returns
`NegotiatedExtensionApi { version, capabilities }` or one of these
`ExtensionCompatibilityError` values:

| Error | Cause |
| --- | --- |
| `UnsupportedMajor { requested, supported }` | `major` is not 1. |
| `InvalidMinorRange { minimum, maximum }` | `minimum_minor` is greater than `maximum_minor`. |
| `TooNewMinor { requested, supported }` | `minimum_minor` is greater than 1. |
| `MissingCapability(id)` | A required capability is not served. |
| `DuplicateCapability(id)` | A capability is listed twice. |
| `InvalidCapability(text)` | `ExtensionCapabilityId::new` rejected the text. Ids are non-empty and use lowercase ASCII letters, digits, `.`, `_`, and `-`. |

Every request carries its own `compatibility` and `expected_generation`.
`structural_query`, `semantic_relations`, and `typestate_check` negotiate
again for each request. Every entry point returns
`ExtensionError::StaleGeneration` when `expected_generation` is not the
workspace's current generation.

### Opening a Workspace

`ExtensionWorkspaceOptions` has public fields:

| Field | Type | Default from `ExtensionWorkspaceOptions::new(root)` |
| --- | --- | --- |
| `roots` | `Vec<PathBuf>` | `vec![root]`. API version 1 requires exactly one root. |
| `analyzer_config` | `AnalyzerConfig` | `AnalyzerConfig::default()` |
| `limits` | `ExtensionLimits` | `ExtensionLimits::default()` |
| `persistence` | `ExtensionPersistenceMode` | `Ephemeral`: an in-memory store discarded when the workspace drops. `.persisted()` selects `Persisted`, the repository's persisted analyzer cache. |

`ExtensionWorkspace::open(options)` reads every workspace file into memory and
builds the analyzer. A file that is not valid UTF-8 is skipped and reported in
`open_diagnostics()`. A file larger than `limits.source_bytes` fails the open.
Errors are `ExtensionWorkspaceError::InvalidRoots`, `Project`, `Analyzer`, or
`Store` (a persisted store could not be opened; there is no fallback to an
in-memory store).

| Method | Returns |
| --- | --- |
| `generation()` | `&WorkspaceGeneration`, the identity that every request must name. |
| `content_identity()` | `&WorkspaceContentIdentity`, a hash of the normalized source and analyzer configuration. Two roots with the same content and configuration have the same value. |
| `capabilities()` | `&ExtensionCapabilityReport`: `generation`, per-language rows, and operation rows. |
| `store()` | `&ExtensionStoreReport`: `requested`, `engaged`, `cache_db` (path when persisted), `diagnostics`. |
| `open_diagnostics()` | `&[ExtensionDiagnostic]`, files skipped at open. |
| `open_tiers()` | `ExtensionTierReport`, the information tiers the open read. |
| `describe()` | `ExtensionWorkspaceDescription`, all of the above plus the API version, in one serializable value. |
| `structural_query(StructuralRequest, &ExtensionCancellation)` | `Result<ExtensionOutcome<StructuralResult>, ExtensionError>` |
| `semantic_relations(SemanticRelationRequest, &ExtensionCancellation)` | `Result<ExtensionOutcome<SemanticRelationSnapshot>, ExtensionError>` |
| `typestate_check(TypestateRequest, &ExtensionCancellation)` | `Result<ExtensionOutcome<TypestateSnapshot>, ExtensionError>` |
| `map_observations(&ObservationDocument, &ExtensionCancellation)` | `Result<ObservationMappingResult, ExtensionError>`. Maps range and branch records from another tool onto workspace nodes. |
| `execute(ExtensionRequest, &ExtensionCancellation)` | `Result<ExtensionResponse, ExtensionError>`. Dispatches any of the four requests above. |

`ExtensionError` values are `Compatibility`, `StaleGeneration { expected,
actual }`, `InvalidRequest`, and `Execution`.

### Requests

| Request | Fields |
| --- | --- |
| `StructuralRequest` | `compatibility`, `expected_generation`, `query: CodeQuery`, `limits: ExtensionLimits`. Serializes as a four-element array with the query in canonical JSON. `StructuralResult` has `items: Box<[serde_json::Value]>`, one CodeQuery row each. |
| `SemanticRelationRequest` | `schema_version`, `compatibility`, `expected_generation`, `seeds` (`Source { span }` or `StableNode { id }`), `scope` (`Procedure`, `File`, or `BoundedCalls { max_call_depth }`), `relations` (`ControlFlow`, `Call`, `Return`, `ControlDependence`, `ValueDependence`), `direction` (`Outgoing`, `Incoming`, `Both`), `limits: SemanticRelationLimits`. |
| `TypestateRequest` | `schema_version`, `compatibility`, `expected_generation`, `protocol` (the protocol document as JSON), `subject`, `events`, `terminals`, `scope` (only `Procedure` is served), `limits: TypestateLimits`. |
| `ObservationDocument` | `schema_version`, `compatibility`, `expected_generation`, `repository`, `subject`, the observation records, and mapping limits. |

### Limits and Cancellation

`ExtensionLimits::new(ExtensionLimitValues)` rejects any zero value.
`ExtensionLimits::default()` uses these values:

| Field | Default |
| --- | --- |
| `result_items` | 1,000 |
| `result_bytes` | 8 MiB |
| `diagnostics` | 256 |
| `source_bytes` | 16 MiB |
| `semantic_nodes` | 10,000 |
| `semantic_edges` | 20,000 |
| `semantic_files` | 128 |
| `traversal_steps` | 1,000,000 |
| `call_depth` | 8 |

For `structural_query`, `result_items` caps rows, `source_bytes` caps scanned
source bytes, and `semantic_files` caps scanned files.
`SemanticRelationLimits` can be built from `ExtensionLimitValues` with `From`.

`ExtensionCancellation::new()` creates a token. `cancel()` stops the work, and a
cancelled request returns completion `Cancelled`.

### Outcomes

`ExtensionOutcome<T>` has `completion: ExtensionCompletion`, `value:
Option<T>`, and `metadata: ExtensionResultMetadata`. The metadata holds `api`,
`operation`, `stability`, `generation`, `diagnostics`, `work`, `tiers`,
`limits`, and `provenance`.

| `ExtensionCompletion` | Meaning |
| --- | --- |
| `Complete` | The answer is complete. |
| `Ambiguous` | More than one answer is possible. |
| `Unknown` | The analysis could not decide. |
| `Unsupported { capability }` | The operation is not available here. |
| `Unproven` | The returned items are proven, but the absence of other items is not proven. |
| `Truncated { limit }` | A caller limit stopped the work. `limit` names it, so the caller knows which value to raise. |
| `FrontierBounded { kinds }` | The analysis reached an edge of what it can know while every caller limit still had room. Larger limits give the same answer. |
| `ExceededBudget { dimension }` | A budget was exhausted. `dimension` names it. |
| `Cancelled` | The caller cancelled the request. |

`ExtensionTierReport` counts tier crossings: `syntax` (file parses), `imports`
(import reads), `supertypes` (supertype reads), and `usage_graph` (usage index
builds). Zero means the tier was not consulted.

### JSON Codec

| Function | Meaning |
| --- | --- |
| `decode_request_json(&[u8]) -> Result<ExtensionRequest, ExtensionDecodeError>` | Decode a request. |
| `encode_request_json(&ExtensionRequest) -> Result<Vec<u8>, ExtensionEncodeError>` | Encode a request. |
| `encode_response_json(&ExtensionResponse) -> Result<Vec<u8>, ExtensionEncodeError>` | Encode a response. |

`ExtensionRequest` and `ExtensionResponse` serialize as
`{"operation": "structural" | "semantic_relations" | "typestate" | "observations", "request" | "response": ...}`.
The module also has per-type codecs: `encode_relation_request_json`,
`decode_relation_request_json`, `encode_relation_snapshot_json`,
`decode_relation_snapshot_json`, `write_relation_snapshot_jsonl`,
`read_relation_snapshot_jsonl`, `encode_typestate_request_json`,
`decode_typestate_request_json`, `encode_typestate_snapshot_json`,
`decode_typestate_snapshot_json`, `encode_observation_document_json`,
`decode_observation_document_json`, `encode_observation_result_json`,
`decode_observation_result_json`, `write_observation_mapping_jsonl`, and
`read_observation_mapping_jsonl`.

### Run Manifests and Reproduction

The module also describes extension runs so that another machine can check
them. `RunManifestBuilder` builds an `ExtensionRunManifest` (schema `2.0`) from
a workspace. `encode_run_manifest_json`, `decode_canonical_run_manifest_json`,
and `decode_and_canonicalize_run_manifest_json` serialize it.
`verify_extension_bundle(root, BundleVerificationLimits)` checks a bundle
directory and returns a `VerifiedExtensionBundle`. `plan_reproduction` compares
a verified bundle with the local environment and returns a
`ReproductionMismatchReport` when they differ. `execute_reproduction` runs the
plan into a new destination directory.

### Example

```rust
use brokk_bifrost::extension::{
    CodeQuery, ExtensionCancellation, ExtensionCapabilityId, ExtensionCompatibility,
    ExtensionLimits, ExtensionWorkspace, ExtensionWorkspaceOptions, StructuralRequest,
    negotiate_extension_api,
};
use serde_json::json;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let compatibility = ExtensionCompatibility {
        major: 1,
        minimum_minor: 0,
        maximum_minor: 1,
        required_capabilities: Box::new([ExtensionCapabilityId::new("structural.query")?]),
    };
    let negotiated = negotiate_extension_api(&compatibility)?;
    println!("api {}.{}", negotiated.version.major, negotiated.version.minor);

    let workspace = ExtensionWorkspace::open(ExtensionWorkspaceOptions::new(".").persisted())?;
    let query = CodeQuery::from_json(&json!({
        "match": { "kind": "function", "name": "run" }
    }))?;
    let outcome = workspace.structural_query(
        StructuralRequest {
            compatibility,
            expected_generation: workspace.generation().clone(),
            query,
            limits: ExtensionLimits::default(),
        },
        &ExtensionCancellation::new(),
    )?;
    println!("completion: {:?}", outcome.completion);
    if let Some(result) = outcome.value {
        for item in result.items.iter() {
            println!("{item}");
        }
    }
    Ok(())
}
```
