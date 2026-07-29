pub mod analyzer;
pub mod benchmark;
pub mod cache_db;
pub mod cache_gc;
mod cancellation;
pub mod code_quality;
mod compact_graph;
pub mod diff_analysis;
pub mod file_tools;
mod git_file;
pub mod gitblob;
pub mod hash;
pub mod lsp;
pub mod mcp_cli;
pub mod mcp_common;
pub mod mcp_core;
pub mod mcp_extended;
pub mod mcp_nlp;
pub mod mcp_property_fuzzer;
pub mod mcp_registry;
pub mod mcp_slopcop;
pub mod mcp_text;
mod model_context;
pub mod navigation;
#[cfg(feature = "nlp")]
pub mod nlp;
mod path_normalization;
mod path_utils;
mod process;
pub mod profiling;
mod project_watcher;
#[cfg(feature = "python")]
mod python_module;
pub mod reference_differential;
mod relevance;
mod schema_version;
pub mod scoped_project;
pub mod searchtools;
pub mod searchtools_render;
pub mod searchtools_service;
mod sexp;
pub mod skill_install;
pub mod structured_data;
pub mod summary;
mod symbol_rename;
#[cfg(test)]
mod test_support;
mod text_utils;
pub mod tool_arguments;
mod util;
mod workspace_document;

/// Exact source revision embedded into every binary from this Cargo build.
/// Benchmark clients use it to reject a stale sibling MCP server.
pub const BIFROST_BUILD_IDENTITY: &str = env!("BIFROST_BUILD_IDENTITY");
pub use analyzer::policy;
pub use analyzer::usages;

pub use analyzer::structural::{
    CodeQuery, CodeQueryExecutionLimits, CodeQueryExecutionMode, CodeQueryExplain,
    CodeQueryProfile, CodeQueryResponse, execute_request, execute_request_with_cancellation,
    execute_request_with_limits,
};
pub use analyzer::{
    AnalyzerConfig, AnalyzerDelegate, CSharpAnalyzer, CapabilityProvider, CloneSmell,
    CloneSmellWeights, CodeBaseMetrics, CodeUnit, CodeUnitType, CppAnalyzer, DeclarationInfo,
    DeclarationKind, EmptyAnalyzer, FileSetProject, FilesystemProject, GoAnalyzer, IAnalyzer,
    ImportAnalysisProvider, ImportInfo, JavaAnalyzer, JavascriptAnalyzer, JvmAnalyzerConfig,
    JvmDependencyDiscoveryConfig, JvmDependencyDiscoveryMode, JvmExternalArtifact,
    JvmExternalDependencies, JvmMavenCoordinate, KotlinAnalyzer, Language, MultiAnalyzer,
    MultiRootProject, OverlayProject, ParseError, ParseErrorKind, PhpAnalyzer, Project,
    ProjectFile, PythonAnalyzer, Range, RubyAnalyzer, RustAnalyzer, ScalaAnalyzer, SourceContent,
    TestAssertionSmell, TestAssertionWeights, TestDetectionProvider, TestProject,
    TreeSitterAnalyzer, TypeAliasProvider, TypeHierarchyProvider, TypescriptAnalyzer,
    WorkspaceAnalyzer, collect_workspace_files, reset_rust_tree_parse_counters_for_test,
    rust_tree_parse_count_for_test, rust_tree_parse_request_count_for_test,
    rust_tree_parsed_bytes_for_test,
};
pub use cancellation::CancellationToken;
pub use navigation::NavigationOperation;
pub use project_watcher::{ChangeDelta, ProjectChangeWatcher};
pub use searchtools_service::{
    SearchToolsService, SearchToolsServiceError, SearchToolsServiceErrorCode, ToolOutput,
};
pub use summary::{RenderedSummary, SummaryInput, summarize_inputs};
