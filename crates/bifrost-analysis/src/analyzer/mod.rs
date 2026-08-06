#[cfg(test)]
pub(crate) mod benchmark_provenance;
pub(crate) mod bounded_output;
mod clone_detection;
pub mod cognitive_complexity;
#[cfg(test)]
mod cognitive_complexity_tests;
mod comment_density;
pub mod common;
mod complete_value_cache;
mod cpp;
mod csharp;
pub mod dataflow;
pub mod declaration_range;
pub(crate) mod exception_handling;
mod global_usage_definition_index;
mod go;
mod i_analyzer;
mod index_warmer;
mod java;
mod javascript;
mod js_ts;
pub(crate) mod jvm;
mod kotlin;
pub(crate) mod languages;
pub mod lexical_definitions;
mod multi_analyzer;
mod php;
mod python;
pub mod reference_candidates;
mod ruby;
mod rust;
mod scala;
pub mod semantic;
pub mod semantic_model;
mod source_ingestion;
pub mod store;
pub mod structural;
pub(crate) mod symbol_lookup;
pub mod taint;
pub use brokk_bifrost_core::analyzer::test_assertions;
pub mod tree_sitter_analyzer;
pub(crate) mod tree_walk;
mod typescript;
pub mod typestate;
mod usage_facts;
pub mod usages;
pub mod value_flow;
pub(crate) mod weighted_cache;
mod work_budget;
mod workspace;

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
pub(crate) use definition_lookup::{BoundedDefinitionLookup, sort_units};

pub(crate) use brokk_bifrost_cpp::imports::{
    include_paths as cpp_include_paths, resolve_include_targets, resolve_include_targets_with_index,
};
pub use capabilities::{
    CapabilityProvider, ImportAnalysisProvider, ImportReachability, TestDetectionProvider,
    TypeAliasProvider, TypeHierarchyProvider,
};
pub(crate) use capabilities::{
    DirectDescendantIndex, build_direct_descendant_index, build_reverse_file_index,
    build_reverse_import_index, memoized_reverse_file_index, memoized_reverse_import_index,
    resolve_imported_files_from_infos,
};
pub use config::{
    AnalyzerConfig, CSharpAnalyzerConfig, GoAnalyzerConfig, GoDependencyDiscoveryConfig,
    JsTsAnalyzerConfig, JsTsDependencyDiscoveryConfig, JvmAnalyzerConfig,
    JvmDependencyDiscoveryConfig, JvmDependencyDiscoveryMode, JvmExternalArtifact,
    JvmExternalArtifactOrigin, JvmExternalDependencies, JvmMavenCoordinate,
    JvmStandardLibraryDiscoveryConfig, PythonAnalyzerConfig, PythonEnvironmentConfig,
    PythonEnvironmentLimits, RubyAnalyzerConfig, RubyDependencyApiEvidence, RubyGemApiArtifact,
    RustAnalyzerConfig, RustDependencyApiEvidence, RustPackageApiArtifact, RustSelectedTarget,
};
pub use cpp::CppAnalyzer;
pub(crate) use cpp::{
    CppCallableUnitRole, CppOccurrenceClassifier, CppOccurrenceRole,
    cpp_callable_definitions_share_identity_evidence, cpp_callable_unit_role,
    cpp_header_body_files_are_related, cpp_indexed_callable_linkage, node_text as cpp_node_text,
};
pub use csharp::CSharpAnalyzer;
pub use csharp::external::{
    CSharpAssemblyPackProducer, CSharpDependencyPackAdapter, CSharpExternalDeclarationIndex,
    CSharpExternalDeclarationSource, CSharpExternalMember, CSharpExternalMemberKind,
    CSharpExternalType, CSharpExternalTypeKind, CSharpVisibility,
    resolve_csharp_semantic_pack_dependencies,
};
// The C# usage graph left with `brokk-bifrost-csharp`, taking most of this
// block's consumers with it. What remains is what the parked definition route
// (`usages/get_definition/csharp.rs`, `usages/get_type/csharp.rs`) and the
// framework hub still read.
pub(crate) use csharp::{
    csharp_attribute_name_node, csharp_attribute_type_names, csharp_callable_arity,
    csharp_conditional_member_access, csharp_member_name, csharp_method_generic_arity,
    csharp_normalize_full_name, csharp_source_identifier,
};
pub use csharp::{csharp_source_name_segment, strip_csharp_generic_arity};
pub use fq_name::FqName;
pub(crate) use global_usage_definition_index::{
    AnalyzerDefinitionLookup, ForwardQueryProvider, impl_forward_query_provider,
};
pub use global_usage_definition_index::{DefinitionIndexHandle, GlobalUsageDefinitionIndex};
// Go language knowledge lives in `brokk-bifrost-go`; these keep their
// historical `crate::analyzer::` paths for the analysis-side consumers
// (symbol_lookup, searchtools, the definition routes).
pub(crate) use brokk_bifrost_go::packages::{
    GO_MODULE_SCOPE_SEGMENT, GoModuleRoot, go_internal_import_allowed, go_module_roots,
};
pub use go::{GoAnalyzer, GoDependencyPackAdapter, resolve_go_semantic_pack_dependencies};
pub use i_analyzer::AnalyzerQueryScope;
pub use i_analyzer::AnalyzerStreamingFileScope;
pub use i_analyzer::{
    AnalyzerQueryContext, AnalyzerSnapshotCaches, IAnalyzer, QueryBatch, SearchSymbolCandidates,
    SearchSymbolPatternBatch, WorkspaceFileIndex, WorkspaceFileIndexCell,
};
#[cfg(any(test, feature = "test-support"))]
pub use i_analyzer::{AnalyzerTestHooks, NoOpAnalyzerTestHooks};
pub use index_warmer::IndexWarmer;
pub use java::JavaAnalyzer;
pub use javascript::JavascriptAnalyzer;
pub(crate) use js_ts::{AliasResolver, resolve_js_ts_module_specifier};
pub use js_ts::{
    JsTsDependencyPackAdapter, TypeScriptDeclarationPackProducer,
    resolve_js_ts_semantic_pack_dependencies,
};
pub use jvm::external::{JvmDependencyPackAdapter, resolve_jvm_semantic_pack_dependencies};
pub use jvm::java_artifact::JavaJarPackProducer;
pub use jvm::jdk_artifact::{JdkSourceArchiveLayout, JdkSourceArchivePackProducer};
pub use jvm::kotlin_artifact::KotlinSourceJarPackProducer;
pub use jvm::scala_artifact::ScalaSourceJarPackProducer;
pub use kotlin::KotlinAnalyzer;
pub use model::{
    CallableArity, CallableFacts, CloneSmell, CloneSmellWeights, CodeBaseMetrics, CodeUnit,
    CodeUnitType, CommentDensityStats, DeclarationInfo, DeclarationKind, DispatchExtensibility,
    ExceptionHandlingAnalysis, ExceptionHandlingSmell, ExceptionSmellWeights, ImportInfo, Language,
    LanguageDialect, MaintainabilitySizeSmell, MaintainabilitySizeSmellWeights, PackageAnchor,
    ParameterMetadata, ParseError, ParseErrorKind, ProjectFile, Range, RubyMethodDispatchMode,
    ScalaExportInfo, ScalaExportSelector, SearchSymbolCandidate, SemanticAbsenceProof,
    SemanticDiagnostic, SemanticDiagnosticDomain, SemanticDiagnosticIncompleteReason,
    SemanticDiagnosticOutcome, SemanticDiagnosticReport, SemanticDiagnosticReportStatus,
    SignatureMetadata, StructuredImportPath, StructuredImportPathKind, StructuredImportScope,
    StructuredTypeIdentity, StructuredTypeName, SummaryFileProjection, TestAssertionAnalysis,
    TestAssertionSmell, TestAssertionWeights, metrics_from_declarations,
};
pub(crate) use model::{CallableLinkage, CppFieldLinkage, CppTemplateMetadata};
pub use multi_analyzer::resolve_analyzer;
pub use multi_analyzer::{AnalyzerDelegate, MultiAnalyzer};
pub use php::{
    PhpAnalyzer, PhpUseAliases, parse_php_use_aliases, parse_php_use_aliases_by_kind,
    parse_php_use_aliases_from_source, php_namespace_to_fq,
};
pub(crate) use pool_memo::PoolSafeMemo;
pub use project::{
    BIFROST_IGNORE_FILE_NAME, DEFAULT_MAX_OVERLAY_BYTES, FileSetProject, FilesystemProject,
    MultiRootProject, OverlayProject, OverlayRevision, Project, ProjectSourceOrigin,
    ProjectSourceSnapshot, TestProject, WorkspaceFileListingCache, collect_workspace_files,
};
pub(crate) use python::{
    ModuleBindingEventKind, ModuleBindingTimeline, resolve_fqn_candidates,
    resolve_module_code_unit, usage_resolve_module_files,
};
pub use python::{
    PythonAnalyzer, PythonImportBinding,
    external::{
        PythonArtifactPackProducer, PythonDependencyPackAdapter,
        resolve_python_semantic_pack_dependencies,
    },
    parse_python_import_bindings, parse_python_import_infos,
};
pub use ruby::RubyAnalyzer;
pub use ruby::{RubyDependencyPackAdapter, resolve_ruby_semantic_pack_dependencies};
pub(crate) use rust::is_rust_public_like_declaration;
pub use rust::rust_is_field_declaration_name;
pub use rust::{
    RustAnalyzer, RustDependencyPackAdapter, RustReferenceContext, RustdocJsonPackProducer,
    resolve_rust_semantic_pack_dependencies,
};
#[cfg(any(test, feature = "test-support"))]
pub use rust::{
    reset_rust_tree_parse_counters_for_test, rust_tree_parse_count_for_test,
    rust_tree_parse_request_count_for_test, rust_tree_parsed_bytes_for_test,
};
pub use scala::ScalaAnalyzer;
pub use source_content::SourceContent;
pub use source_ingestion::{
    IngestedSource, SourceIngestionError, SourceIngestionKind, ingest_source_bytes,
};
pub(crate) use tree_sitter_analyzer::{
    AnalyzerStoreContext, BulkFileStateSource, default_store_context, persistent_store_context,
};
pub use tree_sitter_analyzer::{
    BuildProgress, BuildProgressEvent, BuildProgressPhase, LanguageAdapter, TreeSitterAnalyzer,
};
pub use typescript::TypescriptAnalyzer;
pub(crate) use usage_facts::UsageFactsIndex;
pub use workspace::{
    DependencyPackActivationOutcome, DependencyPackEcosystem, DependencyPackEcosystemOutcome,
    DependencyPackWorkspaceContext, EmptyAnalyzer, PythonSemanticModelActivationOutcome,
    PythonSemanticModelWorkspaceContext, WorkspaceAnalyzer,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ParserFlavor {
    Default,
    TypeScriptTsx,
}

impl ParserFlavor {
    const fn for_dialect(dialect: LanguageDialect) -> Self {
        match dialect {
            LanguageDialect::Standard(_) => Self::Default,
            LanguageDialect::TypeScriptTsx => Self::TypeScriptTsx,
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
pub(crate) fn parser_language_for_dialect(
    dialect: LanguageDialect,
) -> Option<tree_sitter::Language> {
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
pub(crate) fn structural_spec_for(
    language: Language,
) -> Option<&'static dyn structural::StructuralSpec> {
    languages::language_support(language).map(languages::LanguageSupport::structural_spec)
}
