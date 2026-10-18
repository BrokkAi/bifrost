mod analyzer_definition_lookup;
mod assignment_facts;
mod loop_facts;
mod source_admission;
pub use assignment_facts::{
    OverwrittenLocalCandidate, OverwrittenLocalCandidates, OverwrittenLocalSourceKind,
    PlainAssignmentCandidate, PlainAssignmentCandidates, PlainAssignmentVerdict,
    go_overwritten_local_candidates, java_overwritten_local_candidates,
    js_ts_overwritten_local_candidates, plain_assignment_candidates,
    python_overwritten_local_candidates, single_target_overwritten_local_candidates,
};
pub use loop_facts::{
    LoopCandidate, LoopCandidates, LoopCoordinates, LoopKind, LoopSite, LoopSyntax,
    NestedLoopFacts, loop_candidates, nested_loop_facts,
};
pub(crate) use loop_facts::{build_loop_candidates, weight_loop_candidates};
pub mod branch_boolean;
mod cache_weight;
mod clone_detection;
pub mod cognitive_complexity;
mod comment_density;
pub mod common;
pub mod configuration;
pub mod content_identity;
pub mod correspondence;
mod cpp;
pub(crate) mod dependency_support;
pub use cpp::expression_branch_facts::{
    CAssignmentCandidate, CAssignmentCandidates, CAssignmentSyntaxVerdict, c_assignment_candidates,
    cpp_overwritten_local_candidates,
};
pub use cpp::initializer_facts::{
    CppInitializerAccessKind, CppInitializerCandidate, CppInitializerCandidates,
    CppInitializerSyntaxVerdict, cpp_initializer_candidates,
};
pub use cpp::provenance_facts::{
    CppProvenanceOutcome, cpp_provenance_for_anchor, cpp_provenance_for_anchor_with_model_key,
};
pub use cpp::range_facts;
pub use dependency_support::resolve_dependency_path;
mod csharp;
pub mod declaration_range;
pub(crate) mod digest;
pub(crate) mod exception_handling;
mod go;
#[cfg(test)]
pub(crate) use go::native_graph::GoNativeWorkspaceGraphProvider;
pub use go::package_identity::{
    modeled_go_callable_result_nominal_type, modeled_go_callable_result_pointer_field,
};
pub use go::{
    GO_MODELED_RESULT_BINDING_TYPE_PROOF_MAX_SOURCE_BYTES,
    GO_MODELED_RESULT_BINDING_TYPE_PROOF_MAX_STEPS, GoHttpHandlerDispatch, GoHttpHandlerOpenReason,
    go_http_handler_dispatch, go_modeled_result_binding_type_identity_is_exact,
    go_modeled_result_binding_type_identity_proof_work, go_native_error_function_value_obligation,
    go_native_error_result_obligation, go_native_obligation_exclusion,
    reference_assertion_payload_type_is_exact, workspace_reference_assertion_accepts_payload,
};
pub mod declared_scalar;
mod i_analyzer;
mod index_warmer;
pub mod invalidation;
mod java;
pub mod java_integral_parameter;
mod javascript;
mod js_ts;
pub(crate) mod jvm;
mod kotlin;
pub(crate) mod languages;
pub mod lexical_definitions;
mod multi_analyzer;
// Shared bounded native point-resolution machinery used by production language routes.
mod native_points;
#[cfg(any(test, feature = "test-support"))]
pub use native_points::{
    NativeAssignmentValueProbe, NativeTypeProbe, probe_native_assignment_value,
    probe_native_definition, probe_native_definition_trace, probe_native_type,
};
pub mod packs_document;
mod php;
mod python;
pub mod read_ledger;
pub mod read_verification;
pub mod reference_candidates;
pub(crate) mod relational_frontier;
// The native engine lands before the first language route so its algebra can
// be tested independently. Remove this allowance when the Java spike becomes
// its first non-test caller.
#[allow(dead_code, unused_imports)]
pub(crate) mod resolution;
mod ruby;
mod rust;

pub(crate) fn whole_workspace_descendants(
    operation: impl for<'scope> FnOnce(
        &DescendantIndexScope<'scope>,
    ) -> Option<crate::hash::HashSet<CodeUnit>>,
) -> crate::hash::HashSet<CodeUnit> {
    let cancellation = crate::cancellation::CancellationToken::default();
    let scope = DescendantIndexScope::whole_workspace(&cancellation);
    operation(&scope).expect("a descendant index that cannot stop always completes")
}

pub(crate) use rust::crate_identity::RustOverlayCrates;
pub(crate) use rust::generated_model::{
    is_generated_function as is_rust_generated_function,
    resolve_generated_functions as resolve_rust_generated_functions,
};
#[cfg(any(test, feature = "test-support"))]
pub use rust::selected_reverse::{
    RustSelectedReverseOutcome, RustSelectedReverseQueries, with_rust_selected_reverse_queries,
};
#[cfg(test)]
pub(crate) use rust::selected_shadow::selected_rust_native_usage_consumer_shadow;
pub use rust::{
    RustNativeObligationProof, rust_call_is_standard_drop, rust_native_result_obligation,
};
#[cfg(test)]
pub(crate) use rust::{
    RustNativeWorkspaceGraphOutcome, build_rust_native_workspace_graph_for_files,
};
pub(crate) mod scala;
pub mod semantic;
pub mod semantic_model;
mod source_ingestion;
pub mod store;
pub mod structural;
pub(crate) mod symbol_lookup;
pub mod topology;
pub use brokk_bifrost_core::analyzer::test_assertions;

pub(crate) fn test_assertion_source(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    language: Language,
) -> Option<String> {
    if crate::analyzer::common::language_for_file(file) != language
        || !analyzer.contains_tests(file)
    {
        return None;
    }
    analyzer.project().read_source(file).ok()
}

pub(crate) fn with_analyzer_usage_definitions(
    analyzer: &dyn IAnalyzer,
    language: brokk_bifrost_core::analyzer::model::Language,
    read: &mut dyn FnMut(
        &dyn brokk_bifrost_core::analyzer::definition_lookup::BoundedDefinitionLookup,
    ),
) {
    let lookup = AnalyzerDefinitionLookup::new(analyzer, language);
    read(&lookup);
}

pub(crate) fn test_assertion_smells_for_file(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    language: Language,
    detect: impl FnOnce(&str) -> Vec<TestAssertionSmell>,
) -> Vec<TestAssertionSmell> {
    let Some(source) = test_assertion_source(analyzer, file, language) else {
        return Vec::new();
    };
    detect(&source)
}

pub(crate) mod tier_demand;
pub mod tree_sitter_analyzer;
pub(crate) mod tree_walk;

#[cfg(test)]
pub(crate) mod test_support;
mod typescript;
pub mod usages;

#[cfg(test)]
pub(crate) fn test_typescript_project(
    source: &str,
) -> (
    tempfile::TempDir,
    crate::analyzer::ProjectFile,
    TypescriptAnalyzer,
) {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical temp dir");
    let file = crate::analyzer::ProjectFile::new(root.clone(), "src/app.ts");
    file.write(source).expect("write source");
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    (temp, file, analyzer)
}
pub(crate) use brokk_bifrost_core::analyzer::weighted_cache;
pub(crate) use brokk_bifrost_core::analyzer::work_budget;
pub(crate) use brokk_bifrost_core::complete_value_cache;
mod workspace;

/// Retain a lazy external index until one of its discovery inputs changes.
pub(crate) fn updated_external_index<T>(
    current: &std::sync::Arc<std::sync::OnceLock<T>>,
    changed_files: &std::collections::BTreeSet<ProjectFile>,
    is_dependency_input: impl Fn(&ProjectFile) -> bool,
) -> std::sync::Arc<std::sync::OnceLock<T>> {
    if changed_files.iter().any(is_dependency_input) {
        std::sync::Arc::new(std::sync::OnceLock::new())
    } else {
        std::sync::Arc::clone(current)
    }
}

/// Add a collection's shallow size to the estimates of its retained values.
pub(crate) fn estimate_collection_bytes<T>(
    collection_size: u64,
    values: impl IntoIterator<Item = T>,
    estimate_value: impl Fn(T) -> u64,
) -> u64 {
    collection_size + values.into_iter().map(estimate_value).sum::<u64>()
}

// The model layer moved to `brokk-bifrost-core` (the analyzer data model, the
// project abstraction, identifier/dense-id machinery, the language-blind half
// of `common`). Re-exported here at the exact paths they had, so nothing above
// this crate has to know where they now live: the `pub use <module>::{...}`
// blocks below read the same as when the modules were declared here.
// Each keeps the visibility its `mod` declaration had, so the seam does not
// quietly widen this crate's public surface.
pub use brokk_bifrost_core::analyzer::{canonical_hash, identifier, test_paths};
use brokk_bifrost_core::analyzer::{
    capabilities, code_unit_index, config, definition_lookup, model, pool_memo, project,
    source_content,
};
pub(crate) use brokk_bifrost_core::analyzer::{dense_id, fq_name, type_relations};
pub use code_unit_index::CodeUnitIndex;
pub(crate) use code_unit_index::default_parent_fq_name;
pub(crate) use definition_lookup::{
    BoundedDefinitionLookup, DefinitionLanguageScope, RelationalBatchError, RelationalBatchOutcome,
    RelationalCallableFact, RelationalDefinitionFrontier, RelationalDefinitionLookup,
    RelationalDefinitionQuery, RelationalDefinitionQuestion, RelationalDefinitionRequest,
    RelationalDefinitionResult, RelationalDefinitionValue, RelationalFrontierOutcome, sort_units,
};

/// The damaged-tree namespace index, for the root suites' index-level
/// regressions over corpus-derived C++ fixtures that stay private.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub use brokk_bifrost_cpp::graph::resolver::OrphanedNamespaceScopeIndex;
pub(crate) use brokk_bifrost_cpp::imports::{
    include_paths as cpp_include_paths, resolve_include_targets, resolve_include_targets_with_index,
};
pub use capabilities::{
    AdditionalFileDependencies, CapabilityProvider, DescendantIndexScope, DescendantIndexVariant,
    FileDependencyFacts, ImportAnalysisProvider, ImportGraphBindingSurface,
    ImportGraphInputDigests, ImportLookupDependency, ImportReachability,
    ImportResolutionDependencies, ImportedFileEdgeFacts, TestDetectionProvider, TypeAliasProvider,
    TypeHierarchyProvider,
};
pub(crate) use capabilities::{
    DirectDescendantIndex, build_direct_descendant_index, build_reverse_file_index,
    build_reverse_import_index, descendants_from_variant_index, memoized_reverse_file_index,
    memoized_reverse_import_index, resolve_imported_files_from_infos,
};
pub use config::{
    AnalyzerConfig, CSharpAnalyzerConfig, DispatchHierarchyExpansion, GoAnalyzerConfig,
    GoDependencyDiscoveryConfig, GoDependencyDiscoveryMode, JsTsAnalyzerConfig,
    JsTsDependencyDiscoveryConfig, JvmAnalyzerConfig, JvmDependencyDiscoveryConfig,
    JvmDependencyDiscoveryMode, JvmExternalArtifact, JvmExternalArtifactOrigin,
    JvmExternalDependencies, JvmMavenCoordinate, JvmSourceToolchainBinding,
    JvmSourceToolchainSelectionOpen, JvmStandardLibraryDiscoveryConfig, PhpAnalyzerConfig,
    PhpDependencyApiEvidence, PythonAnalyzerConfig, PythonEnvironmentConfig,
    PythonEnvironmentLimits, RubyAnalyzerConfig, RubyDependencyApiEvidence, RubyGemApiArtifact,
    RustAnalyzerConfig, RustDependencyApiEvidence, RustPackageApiArtifact, RustSelectedTarget,
    ensure_global_rayon_pool,
};
pub use cpp::CppAnalyzer;
pub(crate) use cpp::{
    CppCallableUnitRole, cpp_callable_definitions_share_identity_evidence,
    cpp_header_body_files_are_related, node_text as cpp_node_text,
};
pub use cpp::{CppNativeObligationProof, cpp_native_result_obligation};
pub use cpp::{
    cpp_is_constructor_or_destructor_declarator_name, cpp_is_conversion_operator_target_type,
    cpp_is_recovered_macro_character_token_type,
};
pub use csharp::external::{
    CSharpAssemblyPackProducer, CSharpDependencyPackAdapter, CSharpExternalDeclarationIndex,
    CSharpExternalDeclarationSource, CSharpExternalMember, CSharpExternalMemberKind,
    CSharpExternalType, CSharpExternalTypeKind, CSharpVisibility,
    resolve_csharp_semantic_pack_dependencies,
};
pub use csharp::{CSharpAnalyzer, CSharpCatchFacts, CSharpCatchTypeRelation, csharp_catch_facts};
// The C# usage graph left with `brokk-bifrost-csharp`, taking most of this
// block's consumers with it. What remains is what the parked definition route
// (`usages/get_definition/csharp.rs`, `usages/get_type/csharp.rs`) and the
// framework hub still read.
pub use analyzer_definition_lookup::{AnalyzerDefinitionLookup, DefinitionLookupMemo};
pub(crate) use analyzer_definition_lookup::{ForwardQueryProvider, impl_forward_query_provider};
pub use brokk_bifrost_csharp::syntax::csharp_transparent_expression_parent;
pub(crate) use csharp::{
    csharp_attribute_name_node, csharp_attribute_type_names, csharp_conditional_member_access,
    csharp_member_name, csharp_normalize_full_name, csharp_source_identifier,
};
pub use csharp::{csharp_source_name_segment, strip_csharp_generic_arity};
pub use fq_name::FqName;
// Go language knowledge lives in `brokk-bifrost-go`; these keep their
// historical `crate::analyzer::` paths for the analysis-side consumers
// (symbol_lookup, searchtools, the definition routes).
pub(crate) use brokk_bifrost_go::packages::{
    GO_MODULE_SCOPE_SEGMENT, GoModuleRoot, go_internal_import_allowed, go_module_roots,
};
/// The git object id a [`ReadKey::File`] and a policy unit's seed partition
/// name their blob by.
///
/// Re-exported because those types are public and a consumer outside this
/// crate cannot otherwise name the type of a field it holds.
pub use git2::Oid;
pub use go::build_evidence::{
    GoBuildSnapshot, collect_go_build_evidence, go_build_project, go_build_workspace,
    go_evidence_version_cmp,
};

pub use brokk_bifrost_core::analyzer::structural::native_obligation::{
    NativeResultObligation, NativeResultObligationBasis, NativeResultObligationKind,
};
pub use brokk_bifrost_core::analyzer::structural::result_use::{
    CallResultUse, CallResultUseFact, CallResultUseIndex, CallResultUseOpenReason,
    CallResultUseSite, IntentionalDiscardKind,
};
pub use brokk_bifrost_csharp::structural::{CSharpCallResultUseIndex, csharp_call_result_use};
pub use brokk_bifrost_python::declarations::python_function_has_decorator;
pub use cpp::{CppCallResultUseIndex, cpp_call_result_use};
#[cfg(any(test, feature = "test-support"))]
pub use go::native_call_relations::{GoNativeCallRelations, go_native_incoming_calls};
#[cfg(any(test, feature = "test-support"))]
pub use go::native_rename::{GoNativeRenameProvider, go_native_rename};
#[cfg(any(test, feature = "test-support"))]
pub use go::native_usages::GoNativeUsageStrategy;
#[cfg(any(test, feature = "test-support"))]
pub use go::persist_live_go_sources_for_test;
#[cfg(any(test, feature = "test-support"))]
pub use go::selected_reverse::{
    GoNativeSelectedInverseProvider, GoNativeSelectedReferenceIndex, GoSelectedReverseOutcome,
    go_selected_inverse_for,
};
pub use go::{
    GoAggregateOperand, GoAggregateSourceBinding, GoAnalyzer,
    GoAnonymousCallableIdentityBindingError, GoBoundAnonymousCallableIdentity,
    GoCallableCaptureBindingError, GoCaptureSlot, GoCaptureSlotPlan,
    GoCatalogAnonymousCallableBindingError, GoDeclaredTypeShape, GoDeclaredTypeUnknown,
    GoDependencyPackAdapter, GoExternalField, GoExternalFieldGap, GoExternalFieldMemory,
    GoExternalFieldQuery, GoFieldReplayRoute, GoFunctionParameterShape, GoFunctionTypeShape,
    GoMaterializedAnonymousCallable, GoModulePackProducer, GoOuterTypeShape, GoPinnedPackage,
    GoReceiverOwnerUnknown, GoReceiverTypeOwner, GoSourceAnchor, GoSourceByteRange,
    GoSourceDeclarationIdentity, GoSourceDeclarationKind, GoSourceIdentityAnalysis,
    GoSourceIdentityGap, GoSourceIdentityGapKind, GoSourceName, GoSourceTypeNode,
    GoStructFieldIdentity, analyze_go_package_source_identities,
    bind_catalog_go_anonymous_callable_target, bind_go_aggregate_operand_source,
    bind_go_anonymous_callable_identity, bind_go_external_field_source,
    go_aggregate_object_is_singleton, go_failure_handler_body_shapes,
    materialize_go_anonymous_callable, observe_go_aggregate_object, resolve_go_external_field,
    resolve_go_semantic_pack_dependencies,
};
pub use go::{GoCallResultUseIndex, go_call_result_use};
pub use i_analyzer::AnalyzerStreamingFileScope;
pub(crate) use i_analyzer::replay_query_reads;
pub(crate) use i_analyzer::with_query_scope;
pub use i_analyzer::{
    AnalyzerBuildTierAccess, AnalyzerQueryContext, AnalyzerSnapshotCaches, IAnalyzer,
    PersistedImportAdjacency, PersistedImportDependencies, PersistedImportDirection,
    PersistedImportEdge, PersistedImportGraphRefresh, QueryBatch, QueryReadIncomplete,
    SearchSymbolCandidates, SearchSymbolPatternBatch, WorkspaceFileIndex, WorkspaceFileIndexCell,
    capture_query_reads,
};
pub use i_analyzer::{AnalyzerQueryScope, InformationTier, QueryScope, QueryToken};
#[cfg(any(test, feature = "test-support"))]
pub use i_analyzer::{AnalyzerTestHooks, NoOpAnalyzerTestHooks};
pub use index_warmer::IndexWarmer;
#[cfg(any(test, feature = "test-support"))]
pub use java::native_call_relations::{JavaNativeCallRelations, java_native_incoming_calls};
#[cfg(any(test, feature = "test-support"))]
pub use java::native_rename::{JavaNativeRenameProvider, java_native_rename};
#[cfg(any(test, feature = "test-support"))]
pub use java::native_usages::JavaNativeUsageStrategy;
#[cfg(any(test, feature = "test-support"))]
pub use java::selected_reverse::{
    JavaNativeSelectedInverseProvider, JavaNativeSelectedReferenceIndex,
    JavaSelectedReverseOutcome, java_selected_inverse_for,
};
pub use java::{
    JavaAnalyzer, JavaAnnotationTypeResolution, JavaAnnotationTypeStatus, JavaCallResultUse,
    JavaCallResultUseIndex, JavaCallResultUseOpen, JavaCallResultUseRelationIndex,
    JavaLocalAssignmentConversionProver, JavaLocalAssignmentEvidence, java_call_result_use_site,
    java_plain_string_literal, resolve_java_annotation_type,
};
pub use javascript::JavascriptAnalyzer;
pub use js_ts::dependency_evidence;
pub(crate) use js_ts::{AliasResolver, resolve_js_ts_module_specifier};
pub use js_ts::{
    JsTsCallResultUseIndex, JsTsDependencyPackAdapter, JsTsLexicalBindingIndex,
    JsTsLexicalBindingScope, TYPESCRIPT_STDLIB_PACKAGE, TYPESCRIPT_STDLIB_VERSION,
    TypeScriptDeclarationPackProducer, TypeScriptLibraryActivationOutcome,
    resolve_js_ts_semantic_pack_dependencies, static_member_property, static_property_name,
    ts_object_literal_property_name, typescript_library_activation_evidence,
};
pub use jvm::external::{
    JdkVersion, JvmDependencyPackAdapter, resolve_jvm_semantic_pack_dependencies,
};
pub use jvm::java_artifact::JavaJarPackProducer;
pub use jvm::jdk_artifact::{JdkSourceArchiveLayout, JdkSourceArchivePackProducer};
pub use jvm::kotlin_artifact::KotlinSourceJarPackProducer;
pub use jvm::scala_artifact::ScalaSourceJarPackProducer;
pub use kotlin::KotlinAnalyzer;
pub use kotlin::kotlin_declared_scalar_types;
pub use model::{
    CallableArity, CallableFacts, CallableOverrideModifier, CloneSmell, CloneSmellWeights,
    CodeBaseMetrics, CodeUnit, CodeUnitType, CommentDensityStats, DeclarationId, DeclarationInfo,
    DeclarationKind, DispatchExtensibility, ExceptionHandlingAnalysis, ExceptionHandlingSmell,
    ExceptionSmellWeights, ImportInfo, JVM_SEMANTIC_PACK_LANGUAGES, Language, LanguageDialect,
    MaintainabilitySizeSmell, MaintainabilitySizeSmellWeights, PackageAnchor, ParameterMetadata,
    ParseCompleteness, ParseError, ParseErrorKind, ProjectFile, Range, RubyMethodDispatchMode,
    ScalaExportInfo, ScalaExportSelector, SearchSymbolCandidate, SemanticAbsenceProof,
    SemanticDiagnostic, SemanticDiagnosticDomain, SemanticDiagnosticIncompleteReason,
    SemanticDiagnosticOutcome, SemanticDiagnosticReport, SemanticDiagnosticReportStatus,
    SignatureMetadata, StructuredImportPath, StructuredImportPathKind, StructuredImportScope,
    StructuredTypeIdentity, StructuredTypeName, SummaryFileProjection, TestAssertionAnalysis,
    TestAssertionSmell, TestAssertionWeights, metrics_from_declarations, semantic_pack_realm,
};
pub use ruby::{RubyCallResultUseIndex, ruby_call_result_use};

/// Select the earliest range by source line, then by byte offset.
pub fn primary_range(ranges: &[Range]) -> Option<Range> {
    ranges
        .iter()
        .min_by_key(|range| (range.start_line, range.start_byte))
        .copied()
}

pub(crate) use model::{CallableLinkage, CppFieldLinkage, CppTemplateMetadata};
pub(crate) use multi_analyzer::forward_query_provider;
pub use multi_analyzer::resolve_analyzer;
pub use multi_analyzer::{AnalyzerDelegate, MultiAnalyzer, is_language_configuration_input};
pub use php::{
    ComposerPackagePackProducer, ComposerPinnedAutoloadRule, PhpDeclarationStubPackProducer,
    PhpDependencyPackAdapter, resolve_php_semantic_pack_dependencies,
};
pub use php::{
    PhpAnalyzer, PhpCallResultUseIndex, PhpUseAliases, parse_php_use_aliases,
    parse_php_use_aliases_by_kind, parse_php_use_aliases_from_source, php_call_result_use,
    php_declared_scalar_types, php_namespace_to_fq,
};
pub(crate) use pool_memo::{
    KeyedPoolSafeMemo, PoolSafeMemo, install_on_dedicated_build_pool, spawn_on_dedicated_build_pool,
};
pub use project::{
    BIFROST_IGNORE_FILE_NAME, DEFAULT_MAX_OVERLAY_BYTES, FileSetProject, FilesystemProject,
    MultiRootProject, OverlayProject, OverlayRevision, Project, ProjectCoverage,
    ProjectSourceOrigin, ProjectSourceSnapshot, SubsetCoverage, TestProject,
    WorkspaceFileListingCache, collect_workspace_files,
};
pub use python::packaging as python_packaging;
pub use python::runtime_artifact as python_runtime_artifact;
pub(crate) use python::{
    ModuleBindingEventKind, ModuleBindingTimeline, python_exact_external_receiver_identities,
    python_external_class_call_identity, python_external_member_declaration,
    resolve_fqn_candidates, resolve_module_code_unit, retain_modules_for_importer,
    usage_resolve_module_files,
};
pub use python::{
    PythonAnalyzer, PythonImportBinding,
    external::{
        PythonArtifactPackProducer, PythonDependencyPackAdapter,
        resolve_python_semantic_pack_dependencies,
    },
    parse_python_import_bindings, parse_python_import_infos, python_builtin_exception_is_subclass,
    python_builtin_exception_name,
};
pub use read_ledger::{
    IndexFamily, LookupKind, LookupQuestion, ReadKey, ReadLedger, ReadSetDigest,
    absent_summary_digest,
};
pub use read_verification::{
    ChangedFacts, ChangedRead, HeadInputs, LookupMemo, LookupReplayLimits, NoSummaryAnswers,
    ProcedureDispatchReadCallError, ReadVerdict, SummaryAnswers, WorkspaceFactIndex,
    analysis_epoch_digest, procedure_dispatch_read_call, replay_lookup,
    verify_procedure_dispatch_read, verify_read_set, verify_read_set_for_artifact,
};
#[cfg(any(test, feature = "test-support"))]
pub use resolution::{
    reset_reverse_fact_evaluation_count_for_test, reverse_fact_evaluation_count_for_test,
};
pub use ruby::RubyAnalyzer;
pub use ruby::{
    RubyDependencyPackAdapter, RubyGemArchivePackProducer, resolve_ruby_semantic_pack_dependencies,
    ruby_declared_scalar_types,
};
pub(crate) use rust::is_rust_public_like_declaration;
pub use rust::rust_is_field_declaration_name;
pub use rust::{
    RustAnalyzer, RustDependencyPackAdapter, RustReferenceContext, RustReferenceNamespace,
    RustdocJsonPackProducer, acquire_rust_file_dependency_evidence,
    failure_handlers::rust_failure_handler_body_shapes, resolve_rust_semantic_pack_dependencies,
    rust_declaration_is_enum_variant, rust_declaration_matches_reference_namespace,
    rust_file_dependency_evidence, rust_reference_namespace,
};
pub use rust::{RustCallResultUseIndex, rust_call_result_use};
#[cfg(any(test, feature = "test-support"))]
pub use rust::{
    reset_rust_tree_parse_counters_for_test, rust_scope_index_build_count_for_test,
    rust_tree_parse_count_for_test, rust_tree_parse_request_count_for_test,
    rust_tree_parsed_bytes_for_test,
};
pub use scala::ScalaAnalyzer;
pub use scala::scala_declared_scalar_types;
pub use source_content::SourceContent;
pub use source_ingestion::{
    IngestedSource, SourceIngestionError, SourceIngestionKind, ingest_source_bytes,
};
pub(crate) use tree_sitter_analyzer::{
    AnalyzerStoreContext, BuildAbort, BulkFileStateSource, RevisionBlobIdentities,
    ephemeral_store_context, persistent_store_context,
    persistent_store_context_without_automatic_gc, revision_image_store_context,
    scoped_store_context,
};
pub use tree_sitter_analyzer::{
    BuildProgress, BuildProgressEvent, BuildProgressPhase, LanguageAdapter, TreeSitterAnalyzer,
};
pub use typescript::TypescriptAnalyzer;
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub use usages::java_usage_evidence_cache::JavaUsageEvidenceCacheStats;
pub use usages::workspace_graph::UsageEcosystem;
pub use workspace::{
    DependencyPackActivationOutcome, DependencyPackEcosystem, DependencyPackEcosystemOutcome,
    DependencyPackWorkspaceContext, EmptyAnalyzer, InstalledDependencyPackActivationOutcome,
    PythonSemanticModelActivationOutcome, PythonSemanticModelWorkspaceContext, WorkspaceAnalyzer,
};
pub(crate) use workspace::{SharedAnalyzerCache, WorkspaceProjectionLease};

/// Which of a language's grammars parses one file.
///
/// Named for the grammar, not for the dialect that asked for it: two dialects
/// select [`ParserFlavor::Tsx`], TypeScript's `.tsx` and JavaScript's `.jsx`
/// (#3322), and a language that ships one grammar answers [`Self::Default`]
/// for every dialect it has.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ParserFlavor {
    Default,
    Tsx,
}

impl ParserFlavor {
    const fn for_dialect(dialect: LanguageDialect) -> Self {
        match dialect {
            // C and C++ share one grammar; the dialect only changes how the
            // parsed tree is interpreted, never which parser produces it.
            LanguageDialect::Standard(_) | LanguageDialect::CppC => Self::Default,
            LanguageDialect::TypeScriptTsx | LanguageDialect::JavaScriptJsx => Self::Tsx,
        }
    }
}

/// Resolve the default parser grammar registered for a language.
pub fn parser_language_for(language: Language) -> Option<tree_sitter::Language> {
    parser_language_for_flavor(language, ParserFlavor::Default)
}

/// Resolve the parser grammar for one [`LanguageDialect`].
///
/// [`LanguageDialect`] itself is core-owned so language crates can name it;
/// the grammar registry it would need for this is analysis machinery, so the
/// resolution stays here as a free function.
pub fn parser_language_for_dialect(dialect: LanguageDialect) -> Option<tree_sitter::Language> {
    parser_language_for_flavor(dialect.language(), ParserFlavor::for_dialect(dialect))
}

/// Resolve a parser grammar from the canonical language registry.
pub(crate) fn parser_language_for_flavor(
    language: Language,
    flavor: ParserFlavor,
) -> Option<tree_sitter::Language> {
    languages::language_support(language).map(|support| support.parser_language(flavor))
}

/// Resolve the parser grammar used by the indexed analyzer for a specific path.
pub(crate) fn parser_language_for_path(
    language: Language,
    path: &std::path::Path,
) -> Option<tree_sitter::Language> {
    parser_language_for_flavor(language, parser_flavor_for_path(language, path))
}

pub(crate) fn parser_flavor_for_path(language: Language, path: &std::path::Path) -> ParserFlavor {
    ParserFlavor::for_dialect(LanguageDialect::for_path(language, path))
}

/// Resolve the normalized structural adapter registered for a language
/// without constructing a workspace analyzer.
pub fn structural_spec_for(language: Language) -> Option<&'static dyn structural::StructuralSpec> {
    languages::language_support(language).map(languages::LanguageSupport::structural_spec)
}

/// Swap `tree` for the repair `language`'s bundled grammar needs, when it needs
/// one.
///
/// This is the language-blind form of the repair the indexed path applies
/// through `LanguageAdapter::reparse_grammar_gap`. A consumer that resolves a
/// grammar from this registry and parses for itself -- comment density, clone
/// detection, exception-handling smells -- must read the same tree the
/// declaration walk read, or it reports roles from a recovery region the
/// analyzer itself does not have (issue #3325). Only Go answers this today.
///
/// Post-parse only: C#'s pre-parse included ranges are not applied here, which
/// is exactly what these consumers did before. They have always parsed C#
/// whole, and narrowing that is a C# decision rather than a Go one.
pub(crate) fn repaired_grammar_gap_tree(
    language: Language,
    source: &str,
    tree: tree_sitter::Tree,
) -> tree_sitter::Tree {
    structural_spec_for(language)
        .and_then(|spec| spec.reparse_grammar_gap(source, &tree, None))
        .unwrap_or(tree)
}
