//! Stable CLI and Python facade for the Bifrost workspace packages.

pub mod mcp_install;
// OWASP BenchmarkJava taint bakeoff scorer. Like `summary_foundry_demand`, it
// runs the require-model taint policy through the production evaluator and so
// needs both the semantic-model machinery from brokk-bifrost-analysis and the
// evaluator from brokk-bifrost-policy; this package is the only one that sees
// both. It stays ungated so its hermetic scoring-core unit tests run under a
// plain `cargo test`.
pub mod owasp_benchmark;
#[cfg(feature = "python")]
mod python_module;
// Stage 4 of the procedure-summary foundry (#1871). It runs generated fixtures
// through the production policy evaluator, so it needs both the foundry IR from
// brokk-bifrost-semantic-packs and the evaluator from brokk-bifrost-policy;
// this package is the only one that depends on both.
#[cfg(feature = "release-tooling")]
pub mod summary_foundry_fixtures;
pub use brokk_bifrost_analysis::{
    AnalyzerConfig, AnalyzerDefinitionLookup, AnalyzerDelegate, CSharpAnalyzer, CancellationToken,
    CapabilityProvider, CloneSmell, CloneSmellWeights, CodeBaseMetrics, CodeUnit, CodeUnitIndex,
    CodeUnitType, CppAnalyzer, DeclarationInfo, DeclarationKind, DependencyPackActivationOutcome,
    DependencyPackEcosystem, DependencyPackEcosystemOutcome, DependencyPackWorkspaceContext,
    DispatchHierarchyExpansion, EmptyAnalyzer, FileSetProject, FilesystemProject, GoAnalyzer,
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
    WorkspaceAnalyzer, collect_workspace_files, ensure_global_rayon_pool,
    resolve_php_semantic_pack_dependencies, resolve_ruby_semantic_pack_dependencies,
    resolve_rust_semantic_pack_dependencies, summarize_inputs,
};
pub use brokk_bifrost_analysis::{
    analyzer, cache_db, cache_gc, cancellation, code_quality, compact_graph,
    cyclomatic_complexity_diff, diff_analysis, file_tools, git_file, gitblob, hash, model_context,
    navigation, panic_report, path_normalization, path_utils, process, profiling, relevance,
    schema_version, seam_profile, searchtools, searchtools_render, summary, symbol_rename,
    text_utils, usages, util, workspace_document,
};
#[cfg(any(test, feature = "test-support"))]
pub use brokk_bifrost_analysis::{
    reset_rust_tree_parse_counters_for_test, rust_tree_parse_count_for_test,
    rust_tree_parse_request_count_for_test, rust_tree_parsed_bytes_for_test,
};
pub use brokk_bifrost_flow as flow;
pub use brokk_bifrost_mcp::{
    mcp_cli, mcp_common, mcp_core, mcp_diff, mcp_extended, mcp_registry, mcp_slopcop, mcp_text,
    rmcp_host, scoped_project, searchtools_service, tool_arguments,
};
pub use brokk_bifrost_policy as policy;
pub use brokk_bifrost_rql::{
    self as rql, CodeQuery, CodeQueryExecutionLimits, CodeQueryExecutionMode, CodeQueryExplain,
    CodeQueryProfile, CodeQueryResponse, execute_request, execute_request_with_cancellation,
    execute_request_with_limits, sexp,
};
pub use brokk_bifrost_runtime::{CodeIntelligenceRuntime, code_intelligence, extension};
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
            .map_err(str::to_owned)?;
            Ok(())
        })
        .clone()
}

fn register_bifrost_semantic_model_packs(
    catalog: &brokk_bifrost_analysis::analyzer::semantic_model::SemanticPackCatalog,
) -> Result<(), String> {
    if let Some(bundle) = std::env::var_os("BIFROST_OPEN_SEMANTIC_PACK_BUNDLE") {
        if bundle.is_empty() {
            return Err(
                "BIFROST_OPEN_SEMANTIC_PACK_BUNDLE must name a native bundle directory".into(),
            );
        }
        let installed = brokk_bifrost_semantic_packs::release_bundle::install_release_bundle(
            std::path::Path::new(&bundle),
            catalog,
        )
        .map_err(|error| format!("failed to install configured open semantic packs: {error}"))?;
        if installed.is_empty() {
            return Err("configured open semantic bundle installs no compatible packs".into());
        }
        return Ok(());
    }
    brokk_bifrost_semantic_packs::BIFROST_EMBEDDED_PACKS
        .register_all(
            catalog,
            &brokk_bifrost_analysis::analyzer::semantic_model::DecodeLimits::default(),
        )
        .map(|_| ())
        .map_err(|error| format!("failed to register shipped semantic packs: {error}"))
}

/// Conservative pack-consumer profile for this exact engine build.
///
/// This describes supported document formats, not workspace analysis coverage.
/// Capability requirements remain unsupported until explicitly advertised.
pub fn open_pack_engine_profile() -> serde_json::Value {
    use sha2::{Digest, Sha256};

    let mut model_set = Sha256::new();
    for pack in semantic_packs::BIFROST_EMBEDDED_PACKS.packs() {
        model_set.update((pack.source_id().len() as u64).to_le_bytes());
        model_set.update(pack.source_id().as_bytes());
        model_set.update((pack.manifest_bytes().len() as u64).to_le_bytes());
        model_set.update(pack.manifest_bytes());
    }
    serde_json::json!({
        "engine_version": BIFROST_VERSION,
        "build_identity": BIFROST_BUILD_IDENTITY,
        "model_set_sha256": format!("{:x}", model_set.finalize()),
        "capability_contract_version": 1,
        "schemas": {
            "policy_document": [policy::schema::POLICY_SCHEMA_VERSION],
            "rql": rql::query::schema::supported_query_schema_versions(),
            "builtin_catalog": [policy::BUILT_IN_MANIFEST_SCHEMA_VERSION],
            "policy_bundle": [],
            "semantic_model_read": analyzer::semantic_model::SEMANTIC_MODEL_SUPPORTED_SCHEMA_VERSIONS,
            "semantic_model_write": [analyzer::semantic_model::SEMANTIC_MODEL_SCHEMA_VERSION],
            "semantic_spec": [],
            "release_index": [semantic_packs::release_bundle::RELEASE_BUNDLE_SCHEMA_VERSION],
            "runtime": [],
        },
        "capabilities": [],
    })
}

/// Exact source revision embedded into every binary from this Cargo build.
/// Benchmark clients use it to reject a stale sibling MCP server.
pub const BIFROST_BUILD_IDENTITY: &str = env!("BIFROST_BUILD_IDENTITY");

/// Bifrost facade package version embedded into this Cargo build.
pub const BIFROST_VERSION: &str = env!("CARGO_PKG_VERSION");

pub use brokk_bifrost_mcp::{ChangeDelta, ProjectChangeWatcher};
pub use brokk_bifrost_mcp::{
    SearchToolsService, SearchToolsServiceError, SearchToolsServiceErrorCode, ToolOutput,
};
