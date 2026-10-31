//! Stable CLI and Python facade for the Bifrost workspace packages.

pub use brokk_bifrost_analysis::analyzer::PythonSemanticModelWorkspaceContext;
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
mod shard;
// Stage 4 of the procedure-summary foundry (#1871). It runs generated fixtures
// through the production policy evaluator, so it needs both the foundry IR from
// brokk-bifrost-semantic-packs and the evaluator from brokk-bifrost-policy;
// this package is the only one that depends on both.
#[cfg(feature = "release-tooling")]
pub mod summary_foundry_fixtures;
pub use brokk_bifrost_analysis::{
    AnalyzerConfig, AnalyzerDefinitionLookup, AnalyzerDelegate, CancellationToken,
    CapabilityProvider, CloneSmell, CloneSmellWeights, CodeBaseMetrics, CodeUnit, CodeUnitIndex,
    CodeUnitType, DeclarationInfo, DeclarationKind, DependencyPackActivationOutcome,
    DependencyPackEcosystem, DependencyPackEcosystemOutcome, DependencyPackWorkspaceContext,
    DispatchHierarchyExpansion, EmptyAnalyzer, FileSetProject, FilesystemProject, IAnalyzer,
    ImportAnalysisProvider, ImportInfo, ImportReachability, JvmAnalyzerConfig,
    JvmDependencyDiscoveryConfig, JvmDependencyDiscoveryMode, JvmExternalArtifact,
    JvmExternalDependencies, JvmMavenCoordinate, Language, MultiAnalyzer, MultiRootProject,
    NavigationOperation, OverlayProject, ParseCompleteness, ParseError, ParseErrorKind,
    PhpAnalyzerConfig, PhpDependencyApiEvidence, Project, ProjectFile, Range, RubyAnalyzerConfig,
    RubyDependencyApiEvidence, RubyGemApiArtifact, SourceContent, TestAssertionSmell,
    TestAssertionWeights, TestDetectionProvider, TestProject, TreeSitterAnalyzer,
    TypeAliasProvider, TypeHierarchyProvider, WorkspaceAnalyzer, collect_workspace_files,
    ensure_global_rayon_pool,
};
pub use brokk_bifrost_analysis::{
    cache_db, cache_gc, cancellation, compact_graph, git_file, gitblob, hash, navigation,
    panic_report, path_normalization, path_utils, process, profiling, schema_version, seam_profile,
    sqlite_template, text_utils, util, workspace_document,
};
pub use brokk_bifrost_flow as flow;
pub use brokk_bifrost_jvm_analysis::analyzer::{JavaAnalyzer, KotlinAnalyzer, ScalaAnalyzer};
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
pub use brokk_bifrost_rust_analysis::{
    RustAnalyzer, RustDependencyPackAdapter, resolve_rust_semantic_pack_dependencies,
};
#[cfg(any(test, feature = "test-support"))]
pub use brokk_bifrost_rust_analysis::{
    reset_rust_tree_parse_counters_for_test, rust_tree_parse_count_for_test,
    rust_tree_parse_request_count_for_test, rust_tree_parsed_bytes_for_test,
};
pub use brokk_bifrost_semantic_packs as semantic_packs;
pub use brokk_bifrost_tools::{RenderedSummary, SummaryInput, summarize_inputs};
pub use brokk_bifrost_tools::{
    code_quality, cyclomatic_complexity_diff, diff_analysis, file_tools, function_sources,
    model_context, relevance, searchtools, searchtools_render, summary, symbol_rename,
};

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
        let root = std::path::Path::new(&bundle);
        if root
            .join(brokk_bifrost_semantic_packs::prepared_registry::PREPARED_REGISTRY_MARKER)
            .try_exists()
            .map_err(|error| format!("read configured semantic selection: {error}"))?
        {
            return brokk_bifrost_semantic_packs::prepared_registry::register_prepared_registry(
                root, catalog,
            )
            .map(|_| ())
            .map_err(|error| format!("failed to register configured semantic selection: {error}"));
        }
        let installed =
            brokk_bifrost_semantic_packs::release_bundle::install_release_bundle(root, catalog)
                .map_err(|error| {
                    format!("failed to install configured open semantic packs: {error}")
                })?;
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

/// Pack-consumer profile for this exact engine build.
///
/// Capabilities are the policy capabilities this engine provides
/// ([`policy::ENGINE_POLICY_CAPABILITIES`]). They do not guarantee a complete
/// result for every workspace, language, model set, or query budget. A policy
/// that requires an unlisted capability is reported as not run.
pub fn open_pack_engine_profile() -> serde_json::Value {
    use sha2::{Digest, Sha256};

    let capabilities = policy::ENGINE_POLICY_CAPABILITIES;

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
            "release_index": semantic_packs::release_bundle::READABLE_RELEASE_BUNDLE_SCHEMA_VERSIONS,
            "runtime": [],
        },
        "capabilities": capabilities,
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

pub use brokk_bifrost_ruby_analysis::{
    RubyAnalyzer, RubyDependencyPackAdapter, resolve_ruby_semantic_pack_dependencies,
};

pub use brokk_bifrost_cpp_analysis::CppAnalyzer;
pub use brokk_bifrost_go_analysis::*;
pub use brokk_bifrost_js_ts_analysis::{JavascriptAnalyzer, TypescriptAnalyzer};
pub use brokk_bifrost_php_analysis::{
    PhpAnalyzer, PhpDependencyPackAdapter, resolve_php_semantic_pack_dependencies,
};
pub use brokk_bifrost_python_analysis::PythonAnalyzer;
pub mod analyzer {
    pub use brokk_bifrost_analysis::analyzer::semantic;
    pub use brokk_bifrost_analysis::analyzer::*;
    pub use brokk_bifrost_go_analysis::GoAnalyzer;
    pub use brokk_bifrost_go_analysis::analyzer::go;
    pub use brokk_bifrost_js_ts_analysis::analyzer::js_ts::*;
    pub use brokk_bifrost_js_ts_analysis::analyzer::{javascript, js_ts, typescript};
    pub use brokk_bifrost_js_ts_analysis::{JavascriptAnalyzer, TypescriptAnalyzer};
    pub use brokk_bifrost_jvm_analysis::analyzer::{
        JavaAnalyzer, JavaAnnotationTypeResolution, JavaAnnotationTypeStatus, JavaCallResultUse,
        JavaCallResultUseIndex, JavaCallResultUseOpen, JavaCallResultUseRelationIndex,
        JavaJarPackProducer, JavaLocalAssignmentConversionProver, JavaLocalAssignmentEvidence,
        JdkSourceArchiveLayout, JdkSourceArchivePackProducer, JdkVersion, JvmDependencyPackAdapter,
        KotlinAnalyzer, KotlinSourceJarPackProducer, ScalaAnalyzer, ScalaSourceJarPackProducer,
        java_call_result_use_site, java_plain_string_literal, kotlin_declared_scalar_types,
        resolve_java_annotation_type, resolve_jvm_semantic_pack_dependencies,
        scala_declared_scalar_types,
    };
    #[cfg(any(test, feature = "test-support"))]
    pub use brokk_bifrost_jvm_analysis::analyzer::{
        JavaNativeCallRelations, JavaNativeRenameProvider, JavaNativeSelectedInverseProvider,
        JavaNativeSelectedReferenceIndex, JavaNativeUsageStrategy, JavaSelectedReverseOutcome,
        java_native_incoming_calls, java_native_rename, java_selected_inverse_for,
    };
    pub use brokk_bifrost_jvm_analysis::analyzer::{java, jvm, kotlin, scala};
    pub use brokk_bifrost_rust_analysis::analyzer::rust;
    pub use brokk_bifrost_rust_analysis::analyzer::{
        RustAnalyzer, RustCallResultUseIndex, RustDependencyPackAdapter, RustNativeObligationProof,
        RustReferenceContext, RustReferenceNamespace, RustdocJsonPackProducer,
        acquire_rust_file_dependency_evidence, resolve_rust_semantic_pack_dependencies,
        rust_call_is_standard_drop, rust_call_result_use, rust_declaration_is_enum_variant,
        rust_declaration_matches_reference_namespace, rust_failure_handler_body_shapes,
        rust_file_dependency_evidence, rust_is_field_declaration_name,
        rust_native_result_obligation, rust_reference_namespace,
    };
    #[cfg(any(test, feature = "test-support"))]
    pub use brokk_bifrost_rust_analysis::analyzer::{
        RustSelectedReverseOutcome, RustSelectedReverseQueries,
        reset_rust_tree_parse_counters_for_test, rust_scope_index_build_count_for_test,
        rust_tree_parse_count_for_test, rust_tree_parse_request_count_for_test,
        rust_tree_parsed_bytes_for_test, with_rust_selected_reverse_queries,
    };
}
pub mod usages {
    pub mod get_definition {
        pub use brokk_bifrost_analysis::usages::get_definition::*;
        pub use brokk_bifrost_jvm_analysis::analyzer::usages::get_definition::{
            java, kotlin, scala,
        };
    }
    pub mod get_type {
        pub use brokk_bifrost_analysis::usages::get_type::*;
        pub use brokk_bifrost_jvm_analysis::analyzer::usages::get_type::{java, scala};
    }
    pub use brokk_bifrost_analysis::usages::*;
    pub use brokk_bifrost_js_ts_analysis::JsTsExportUsageGraphStrategy;
    pub use brokk_bifrost_jvm_analysis::{
        JavaUsageGraphStrategy, KotlinUsageGraphStrategy, ScalaUsageGraphStrategy,
    };
    pub use brokk_bifrost_rust_analysis::RustNativeUsageStrategy;
}

pub use brokk_bifrost_csharp_analysis::CSharpAnalyzer;
pub use brokk_bifrost_rust_analysis::{
    RustAnalyzerConfig, RustDependencyApiEvidence, RustPackageApiArtifact, RustSelectedTarget,
};
