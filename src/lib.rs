//! Stable CLI and Python facade for the Bifrost workspace packages.

pub mod benchmark;
pub mod mcp_property_fuzzer;
#[cfg(feature = "python")]
mod python_module;
// Differential validation tooling for the reference/usage analyzers. It lives
// here rather than in brokk-bifrost-analysis because its only consumers are the
// `bifrost_reference_differential` binary and `tests/suite_semantic`, both of
// which belong to this package.
pub mod reference_differential;
pub mod skill_install;

pub use brokk_bifrost_analysis::{
    AnalyzerConfig, AnalyzerDelegate, CSharpAnalyzer, CancellationToken, CapabilityProvider,
    CloneSmell, CloneSmellWeights, CodeBaseMetrics, CodeQuery, CodeQueryExecutionLimits,
    CodeQueryExecutionMode, CodeQueryExplain, CodeQueryProfile, CodeQueryResponse, CodeUnit,
    CodeUnitIndex, CodeUnitType, CppAnalyzer, DeclarationInfo, DeclarationKind,
    DependencyPackActivationOutcome, DependencyPackEcosystem, DependencyPackEcosystemOutcome,
    DependencyPackWorkspaceContext, EmptyAnalyzer, FileSetProject, FilesystemProject, GoAnalyzer,
    IAnalyzer, ImportAnalysisProvider, ImportInfo, ImportReachability, JavaAnalyzer,
    JavascriptAnalyzer, JvmAnalyzerConfig, JvmDependencyDiscoveryConfig,
    JvmDependencyDiscoveryMode, JvmExternalArtifact, JvmExternalDependencies, JvmMavenCoordinate,
    KotlinAnalyzer, Language, MultiAnalyzer, MultiRootProject, NavigationOperation, OverlayProject,
    ParseError, ParseErrorKind, PhpAnalyzer, PhpAnalyzerConfig, PhpDependencyApiEvidence,
    PhpDependencyPackAdapter, Project, ProjectFile, PythonAnalyzer,
    PythonSemanticModelWorkspaceContext, Range, RenderedSummary, RubyAnalyzer, RubyAnalyzerConfig,
    RubyDependencyApiEvidence, RubyDependencyPackAdapter, RubyGemApiArtifact, RustAnalyzer,
    RustAnalyzerConfig, RustDependencyApiEvidence, RustDependencyPackAdapter,
    RustPackageApiArtifact, RustSelectedTarget, ScalaAnalyzer, SourceContent, SummaryInput,
    TestAssertionSmell, TestAssertionWeights, TestDetectionProvider, TestProject,
    TreeSitterAnalyzer, TypeAliasProvider, TypeHierarchyProvider, TypescriptAnalyzer,
    WorkspaceAnalyzer, collect_workspace_files, execute_request, execute_request_with_cancellation,
    execute_request_with_limits, resolve_php_semantic_pack_dependencies,
    resolve_ruby_semantic_pack_dependencies, resolve_rust_semantic_pack_dependencies,
    summarize_inputs,
};
pub use brokk_bifrost_analysis::{
    analyzer, cache_db, cache_gc, cancellation, code_quality, compact_graph, diff_analysis,
    file_tools, git_file, gitblob, hash, model_context, navigation, path_normalization, path_utils,
    process, profiling, relevance, schema_version, searchtools, searchtools_render, sexp, summary,
    symbol_rename, text_utils, usages, util, workspace_document,
};
#[cfg(any(test, feature = "test-support"))]
pub use brokk_bifrost_analysis::{
    reset_rust_tree_parse_counters_for_test, rust_tree_parse_count_for_test,
    rust_tree_parse_request_count_for_test, rust_tree_parsed_bytes_for_test,
};
pub use brokk_bifrost_lsp::lsp;
pub use brokk_bifrost_mcp::{
    mcp_cli, mcp_common, mcp_core, mcp_extended, mcp_nlp, mcp_registry, mcp_slopcop, mcp_text,
    rmcp_host, scoped_project, searchtools_service, tool_arguments,
};
#[cfg(feature = "nlp")]
pub use brokk_bifrost_nlp as nlp;
pub use brokk_bifrost_policy as policy;
pub use brokk_bifrost_runtime::{CodeIntelligenceRuntime, code_intelligence};
pub use brokk_bifrost_semantic_packs as semantic_packs;

use std::sync::OnceLock;

/// Connect the facade's reviewed semantic packs to MCP workspace creation.
pub fn install_bifrost_semantic_model_packs() -> Result<(), String> {
    static RESULT: OnceLock<Result<(), String>> = OnceLock::new();
    RESULT
        .get_or_init(|| {
            brokk_bifrost_mcp::searchtools_service::install_semantic_model_catalog_bootstrap(
                register_bifrost_semantic_model_packs,
            )
            .map_err(str::to_owned)
        })
        .clone()
}

fn register_bifrost_semantic_model_packs(
    catalog: &brokk_bifrost_analysis::analyzer::semantic_model::SemanticPackCatalog,
) -> Result<(), String> {
    brokk_bifrost_semantic_packs::BIFROST_EMBEDDED_PACKS
        .register_all(
            catalog,
            &brokk_bifrost_analysis::analyzer::semantic_model::DecodeLimits::default(),
        )
        .map(|_| ())
        .map_err(|error| format!("failed to register shipped semantic packs: {error}"))
}

/// Exact source revision embedded into every binary from this Cargo build.
/// Benchmark clients use it to reject a stale sibling MCP server.
pub const BIFROST_BUILD_IDENTITY: &str = env!("BIFROST_BUILD_IDENTITY");

pub use brokk_bifrost_mcp::{ChangeDelta, ProjectChangeWatcher};
pub use brokk_bifrost_mcp::{
    SearchToolsService, SearchToolsServiceError, SearchToolsServiceErrorCode, ToolOutput,
};
