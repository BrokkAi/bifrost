//! Stable CLI and Python facade for the Bifrost workspace packages.

pub mod benchmark;
pub mod mcp_property_fuzzer;
#[cfg(feature = "python")]
mod python_module;
pub mod skill_install;

#[cfg(feature = "nlp")]
pub use brokk_bifrost_analysis::nlp;
pub use brokk_bifrost_analysis::{
    AnalyzerConfig, AnalyzerDelegate, CSharpAnalyzer, CancellationToken, CapabilityProvider,
    CloneSmell, CloneSmellWeights, CodeBaseMetrics, CodeQuery, CodeQueryExecutionLimits,
    CodeQueryExecutionMode, CodeQueryExplain, CodeQueryProfile, CodeQueryResponse, CodeUnit,
    CodeUnitType, CppAnalyzer, DeclarationInfo, DeclarationKind, EmptyAnalyzer, FileSetProject,
    FilesystemProject, GoAnalyzer, IAnalyzer, ImportAnalysisProvider, ImportInfo, JavaAnalyzer,
    JavascriptAnalyzer, JvmAnalyzerConfig, JvmDependencyDiscoveryConfig,
    JvmDependencyDiscoveryMode, JvmExternalArtifact, JvmExternalDependencies, JvmMavenCoordinate,
    KotlinAnalyzer, Language, MultiAnalyzer, MultiRootProject, NavigationOperation, OverlayProject,
    ParseError, ParseErrorKind, PhpAnalyzer, Project, ProjectFile, PythonAnalyzer, Range,
    RenderedSummary, RubyAnalyzer, RustAnalyzer, ScalaAnalyzer, SourceContent, SummaryInput,
    TestAssertionSmell, TestAssertionWeights, TestDetectionProvider, TestProject,
    TreeSitterAnalyzer, TypeAliasProvider, TypeHierarchyProvider, TypescriptAnalyzer,
    WorkspaceAnalyzer, collect_workspace_files, execute_request, execute_request_with_cancellation,
    execute_request_with_limits, reset_rust_tree_parse_counters_for_test,
    rust_tree_parse_count_for_test, rust_tree_parse_request_count_for_test,
    rust_tree_parsed_bytes_for_test, summarize_inputs,
};
pub use brokk_bifrost_analysis::{
    analyzer, cache_db, cache_gc, cancellation, code_quality, compact_graph, diff_analysis,
    file_tools, git_file, gitblob, hash, model_context, navigation, path_normalization, path_utils,
    policy, process, profiling, reference_differential, relevance, schema_version, searchtools,
    searchtools_render, sexp, summary, symbol_rename, text_utils, usages, util, workspace_document,
};
pub use brokk_bifrost_lsp::lsp;
pub use brokk_bifrost_mcp::{
    mcp_cli, mcp_common, mcp_core, mcp_extended, mcp_nlp, mcp_registry, mcp_slopcop, mcp_text,
    scoped_project, searchtools_service, structured_data, tool_arguments,
};
pub use brokk_bifrost_runtime::{CodeIntelligenceRuntime, code_intelligence};
pub use brokk_bifrost_semantic_packs as semantic_packs;

/// Exact source revision embedded into every binary from this Cargo build.
/// Benchmark clients use it to reject a stale sibling MCP server.
pub const BIFROST_BUILD_IDENTITY: &str = env!("BIFROST_BUILD_IDENTITY");

pub use brokk_bifrost_mcp::{ChangeDelta, ProjectChangeWatcher};
pub use brokk_bifrost_mcp::{
    SearchToolsService, SearchToolsServiceError, SearchToolsServiceErrorCode, ToolOutput,
};
