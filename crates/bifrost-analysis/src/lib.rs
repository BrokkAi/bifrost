//! Protocol-neutral analysis engine for Bifrost hosts and runtimes.
//!
//! Internal implementation detail of `brokk-bifrost`; no stability guarantees --
//! depend on `brokk-bifrost` instead.
//!
//! The foundation layer -- the analyzer data model, the project abstraction,
//! the structural kind/role vocabulary, and the process-wide utilities -- lives
//! in [`brokk_bifrost_core`]. Every item it owns is re-exported here at its
//! historical path, so a consumer never has to know which side of the seam a
//! name came from.

#[cfg(test)]
extern crate self as brokk_bifrost_analysis;

#[cfg(test)]
#[path = "../../../test-support/inline_project.rs"]
pub(crate) mod inline_project;

pub mod analyzer;
pub mod blast_radius;
// `cache_gc` and `path_utils` keep a module here rather than a re-export: each
// has a small tail that needs an `AnalyzerStore` or an `IAnalyzer`, which core
// cannot see. Both re-export their core half at the top of the file.
pub mod cache_gc;
pub mod code_quality;
pub mod cyclomatic_complexity_diff;
pub mod diff_analysis;
pub mod diff_scoring;
pub mod file_tools;
pub mod model_context;
pub mod navigation;
pub mod path_utils;
pub mod process;
pub mod relevance;
pub mod searchtools;
pub mod searchtools_render;
pub mod summary;
pub mod symbol_rename;
#[cfg(test)]
mod test_support;
pub mod workspace_document;

pub use brokk_bifrost_core::{
    cache_db, cancellation, compact_graph, define_identifier, git_file, gitblob, hash,
    panic_report, path_normalization, profiling, schema_version, text_utils, util,
};

/// The reader seam's per-method counters (`BIFROST_SEAM_PROFILE`).
///
/// Re-exported here because the MCP host opens the request boundary and the
/// resolution module itself is crate-private.
pub use analyzer::resolution::seam_profile;
/// Reference-seed read repetition per tool call (`BIFROST_SEED_KEY_PROFILE`).
///
/// Re-exported for the same reason as [`seam_profile`]: the MCP host opens the
/// call boundary and the resolution module itself is crate-private.
pub use analyzer::resolution::seed_key_profile;
pub use analyzer::usages;
pub use analyzer::{
    AnalyzerConfig, AnalyzerDefinitionLookup, AnalyzerDelegate, BIFROST_IGNORE_FILE_NAME,
    CSharpAnalyzer, CapabilityProvider, CloneSmell, CloneSmellWeights, CodeBaseMetrics, CodeUnit,
    CodeUnitIndex, CodeUnitType, CppAnalyzer, DeclarationInfo, DeclarationKind,
    DependencyPackActivationOutcome, DependencyPackEcosystem, DependencyPackEcosystemOutcome,
    DependencyPackWorkspaceContext, DispatchHierarchyExpansion, EmptyAnalyzer,
    ExceptionHandlingAnalysis, ExceptionHandlingSmell, ExceptionSmellWeights, FileSetProject,
    FilesystemProject, GoAnalyzer, IAnalyzer, ImportAnalysisProvider, ImportInfo,
    ImportReachability, IngestedSource, JavaAnalyzer, JavascriptAnalyzer, JvmAnalyzerConfig,
    JvmDependencyDiscoveryConfig, JvmDependencyDiscoveryMode, JvmExternalArtifact,
    JvmExternalDependencies, JvmMavenCoordinate, JvmStandardLibraryDiscoveryConfig, KotlinAnalyzer,
    Language, MultiAnalyzer, MultiRootProject, OverlayProject, ParseError, ParseErrorKind,
    PhpAnalyzer, PhpAnalyzerConfig, PhpDependencyApiEvidence, PhpDependencyPackAdapter, Project,
    ProjectCoverage, ProjectFile, PythonAnalyzer, PythonSemanticModelWorkspaceContext, Range,
    RubyAnalyzer, RubyAnalyzerConfig, RubyDependencyApiEvidence, RubyDependencyPackAdapter,
    RubyGemApiArtifact, RustAnalyzer, RustAnalyzerConfig, RustDependencyApiEvidence,
    RustDependencyPackAdapter, RustPackageApiArtifact, RustSelectedTarget, RustdocJsonPackProducer,
    ScalaAnalyzer, SourceContent, SourceIngestionError, SourceIngestionKind, SubsetCoverage,
    TestAssertionAnalysis, TestAssertionSmell, TestAssertionWeights, TestDetectionProvider,
    TestProject, TreeSitterAnalyzer, TypeAliasProvider, TypeHierarchyProvider, TypescriptAnalyzer,
    WorkspaceAnalyzer, WorkspaceFileListingCache, collect_workspace_files,
    ensure_global_rayon_pool, ingest_source_bytes, resolve_php_semantic_pack_dependencies,
    resolve_ruby_semantic_pack_dependencies, resolve_rust_semantic_pack_dependencies,
};
#[cfg(any(test, feature = "test-support"))]
pub use analyzer::{
    reset_rust_tree_parse_counters_for_test, rust_scope_index_build_count_for_test,
    rust_tree_parse_count_for_test, rust_tree_parse_request_count_for_test,
    rust_tree_parsed_bytes_for_test,
};
pub use cancellation::CancellationToken;
pub use navigation::NavigationOperation;
pub use summary::{RenderedSummary, SummaryInput, summarize_inputs};

/// Unstable native-resolution fixtures for the private differential harness.
/// Shipped builds do not expose this module.
#[cfg(any(test, feature = "test-support"))]
pub mod native_resolution_test_support {
    pub use crate::analyzer::resolution::*;
    pub use crate::analyzer::usages::workspace_graph::{
        SelectedWorkspaceUsageRankingBuildOutcome, SelectedWorkspaceUsageRankingGraph,
        build_selected_workspace_usage_ranking_graph,
    };
    pub use crate::analyzer::{
        GoNativeCallRelations, GoNativeRenameProvider, GoNativeSelectedInverseProvider,
        GoNativeSelectedReferenceIndex, GoNativeUsageStrategy, GoSelectedReverseOutcome,
        go_native_incoming_calls, go_native_rename, go_selected_inverse_for,
        persist_live_go_sources_for_test,
    };
    pub use crate::analyzer::{
        JavaNativeCallRelations, JavaNativeRenameProvider, JavaNativeSelectedInverseProvider,
        JavaNativeSelectedReferenceIndex, JavaNativeUsageStrategy, JavaSelectedReverseOutcome,
        java_native_incoming_calls, java_native_rename, java_selected_inverse_for,
    };
    pub use crate::analyzer::{NativeTypeProbe, probe_native_definition, probe_native_type};
    pub use crate::analyzer::{
        RustSelectedReverseOutcome, RustSelectedReverseQueries, with_rust_selected_reverse_queries,
    };
    pub use crate::blast_radius::{
        SelectedMissingTestsTelemetry, missing_tests_at_root_with_selected_inverse_index,
    };
    pub use crate::relevance::{SelectedExactRelevanceTelemetry, SelectedExactUsageGraphLifecycle};
    pub use crate::searchtools::{
        MostRelevantFile, MostRelevantFilesIncompleteReason, MostRelevantFilesParams,
        MostRelevantFilesRankingMode, MostRelevantFilesResult,
        most_relevant_files_with_selected_exact_graph_builder,
    };
    pub use crate::searchtools::{
        SelectedUsageGraphBuildOutcome, SelectedUsageGraphTelemetry,
        build_selected_unscoped_usage_graph,
    };
    pub use brokk_bifrost_core::analyzer::model::Language;
    pub use brokk_bifrost_core::analyzer::resolution_facts::{
        BindingProjectionKind, DeclarationTypeRole, FileResolutionFacts, IntrinsicTypeKind,
        ResolutionCallableReceiverOrigin, ResolutionConstructionRequirementKind,
        ResolutionEngineRuleKind, ResolutionGapFact, ResolutionGapKind, ResolutionImportRouteKind,
        ResolutionMemberAccess, ResolutionMemberKind, ResolutionMemberQualifierCompatibility,
        ResolutionNamespace, ResolutionReferenceEnumerationGapFact, ResolutionScopeFact,
        ResolutionScopeId, ResolutionScopeKind, ResolutionSiteFact, ResolutionSiteId,
        ResolutionSiteKind, ResolutionSupertypeKind, ResolutionTypeSlotFact, ResolutionTypeSlotId,
        ResolutionTypeSlotRole, ResolutionTypeTransferKind,
    };
    pub use brokk_bifrost_rust::cargo_routes::rust_static_string_literal;

    /// One fixture identity per label, for a differential suite that needs
    /// distinct identities and no catalog. See `SemanticId::for_test`.
    pub fn fixture_semantic(label: &str) -> SemanticId {
        SemanticId::for_test(label)
    }

    /// See [`fixture_semantic`].
    pub fn fixture_node(label: &str) -> BindingNodeId {
        BindingNodeId::for_test(label)
    }

    /// See [`fixture_semantic`].
    pub fn fixture_path_id(label: &str) -> PartialPathId {
        PartialPathId::for_test(label)
    }

    /// See [`fixture_semantic`].
    pub fn fixture_fragment(label: &[u8]) -> BindingFragmentId {
        BindingFragmentId::for_test(label)
    }

    /// One lowered artifact and the catalog that numbered it, for a
    /// differential suite. The two halves come from one lowering: two
    /// lowerings build two catalogs, and their positions agree only on the
    /// sites.
    pub fn lower_fixture_facts(
        fragment: BindingFragmentId,
        language: Language,
        facts: &FileResolutionFacts,
    ) -> (LoweredResolutionFragment, LoweredTypedFragment) {
        let lowered = lower_for_test(fragment, language, facts);
        (lowered.lexical().clone(), lowered.typed().clone())
    }

    /// Return the exact schema-owned universal root identity for private SQL
    /// differential fixtures without exposing its constructor in shipped APIs.
    pub fn universal_root_binding_node() -> BindingNodeId {
        BindingNodeId::universal_root()
    }

    /// Run the production Java parse walk and return only its target-independent
    /// native-resolution facts for the private differential harness.
    pub fn parse_java_resolution_facts(
        file: &brokk_bifrost_core::analyzer::ProjectFile,
        source: &str,
    ) -> FileResolutionFacts {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_java::LANGUAGE.into())
            .expect("Java grammar must match the shared tree-sitter runtime");
        let tree = parser
            .parse(source, None)
            .expect("Java differential fixture must produce a syntax tree");
        brokk_bifrost_jvm::java::declarations::parse_java_file(file, source, &tree).resolution_facts
    }

    /// Run the production Rust parse walk and return only its target-independent
    /// native-resolution facts for the private differential harness.
    pub fn parse_rust_resolution_facts(
        file: &brokk_bifrost_core::analyzer::ProjectFile,
        source: &str,
    ) -> FileResolutionFacts {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("Rust grammar must match the shared tree-sitter runtime");
        let tree = parser
            .parse(source, None)
            .expect("Rust differential fixture must produce a syntax tree");
        brokk_bifrost_rust::declarations::parse_rust_file(file, source, &tree).resolution_facts
    }
}
