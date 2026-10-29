#[doc(hidden)]
pub mod analyzer_definition_lookup;
#[doc(hidden)]
pub mod assignment_facts;
#[doc(hidden)]
pub mod loop_facts;
#[doc(hidden)]
pub mod source_admission;
pub use assignment_facts::OverwrittenLocalCandidate;
pub use assignment_facts::OverwrittenLocalCandidates;
pub use assignment_facts::OverwrittenLocalSourceKind;
pub use assignment_facts::PlainAssignmentCandidate;
pub use assignment_facts::PlainAssignmentCandidates;
pub use assignment_facts::PlainAssignmentVerdict;
pub use assignment_facts::go_overwritten_local_candidates;
pub use assignment_facts::java_overwritten_local_candidates;
pub use assignment_facts::js_ts_overwritten_local_candidates;
pub use assignment_facts::plain_assignment_candidates;
pub use assignment_facts::python_overwritten_local_candidates;
pub use assignment_facts::single_target_overwritten_local_candidates;

pub use loop_facts::LoopCandidate;
pub use loop_facts::LoopCandidates;
pub use loop_facts::LoopCoordinates;
pub use loop_facts::LoopKind;
pub use loop_facts::LoopSite;
pub use loop_facts::LoopSyntax;
pub use loop_facts::NestedLoopFacts;
pub use loop_facts::loop_candidates;
pub use loop_facts::nested_loop_facts;

pub(crate) use loop_facts::build_loop_candidates;
pub(crate) use loop_facts::weight_loop_candidates;

pub use source_admission::AdmissionDimension;
pub use source_admission::SourceAdmissionRefusal;

pub mod branch_boolean;
#[doc(hidden)]
pub mod cache_weight;
#[doc(hidden)]
pub mod clone_detection;
pub mod cognitive_complexity;
#[doc(hidden)]
pub mod comment_density;
pub mod common;
pub mod configuration;
pub mod content_identity;
pub mod correspondence;

#[doc(hidden)]
pub mod dependency_support;

pub use dependency_support::resolve_dependency_path;

pub mod declaration_range;
pub(crate) mod digest;
pub(crate) mod exception_handling;

pub mod declared_scalar;
#[doc(hidden)]
pub mod i_analyzer;
#[doc(hidden)]
pub mod index_warmer;
pub mod invalidation;

pub mod java_integral_parameter;

#[doc(hidden)]
pub mod languages;
pub mod lexical_definitions;
#[doc(hidden)]
pub mod multi_analyzer;
// Shared bounded native point-resolution machinery used by production language routes.
#[doc(hidden)]
pub mod native_points;
#[cfg(any(test, feature = "test-support"))]
pub use native_points::NativeAssignmentValueProbe;
#[cfg(any(test, feature = "test-support"))]
pub use native_points::NativeTypeProbe;
#[cfg(any(test, feature = "test-support"))]
pub use native_points::probe_native_assignment_value;
#[cfg(any(test, feature = "test-support"))]
pub use native_points::probe_native_definition;
#[cfg(any(test, feature = "test-support"))]
pub use native_points::probe_native_definition_trace;
#[cfg(any(test, feature = "test-support"))]
pub use native_points::probe_native_type;

pub mod packs_document;
pub mod read_ledger;
pub mod read_verification;
pub mod reference_candidates;
#[doc(hidden)]
pub mod relational_frontier;
pub mod rename;
// The native engine lands before the first language route so its algebra can
// be tested independently. Remove this allowance when the Java spike becomes
// its first non-test caller.
#[allow(dead_code, unused_imports)]
#[doc(hidden)]
pub mod resolution;

#[doc(hidden)]
pub fn whole_workspace_descendants(
    operation: impl for<'scope> FnOnce(
        &DescendantIndexScope<'scope>,
    ) -> Option<crate::hash::HashSet<CodeUnit>>,
) -> crate::hash::HashSet<CodeUnit> {
    let cancellation = crate::cancellation::CancellationToken::default();
    let scope = DescendantIndexScope::whole_workspace(&cancellation);
    operation(&scope).expect("a descendant index that cannot stop always completes")
}

mod source_ingestion;
pub mod store;
#[doc(hidden)]
pub mod store_bridge;
pub mod structural;
#[doc(hidden)]
pub mod symbol_lookup;
pub mod topology;
pub use brokk_bifrost_core::analyzer::test_assertions;

/// Whether test-assertion detection for `language` reads `file`: a file of
/// that language that the analyzer recorded as containing tests.
#[doc(hidden)]
pub fn is_test_assertion_candidate(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    language: Language,
) -> bool {
    crate::analyzer::common::language_for_file(file) == language && analyzer.contains_tests(file)
}

#[doc(hidden)]
pub fn test_assertion_source(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    language: Language,
) -> Option<String> {
    if !is_test_assertion_candidate(analyzer, file, language) {
        return None;
    }
    // A candidate whose source cannot be read yields no findings; record why,
    // so the report is not complete with nothing decided.
    match analyzer.project().read_source(file) {
        Ok(source) => Some(source),
        Err(error)
            if error.get_ref().is_some_and(|cause| {
                cause.is::<brokk_bifrost_core::analyzer::project::BinarySourceRejection>()
            }) =>
        {
            analyzer
                .record_query_incomplete(QueryReadIncomplete::StructureUnavailable(file.clone()));
            None
        }
        Err(error) => {
            analyzer.record_query_failure(store::StoreError::new(format!(
                "reading test assertion source for {file:?}: {error}"
            )));
            None
        }
    }
}

#[doc(hidden)]
pub fn with_analyzer_usage_definitions(
    analyzer: &dyn IAnalyzer,
    language: brokk_bifrost_core::analyzer::model::Language,
    read: &mut dyn FnMut(
        &dyn brokk_bifrost_core::analyzer::definition_lookup::BoundedDefinitionLookup,
    ),
) {
    let lookup = AnalyzerDefinitionLookup::new(analyzer, language);
    read(&lookup);
}

#[doc(hidden)]
pub fn test_assertion_smells_for_file(
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
#[doc(hidden)]
pub mod tree_walk;

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod test_support;

pub mod usages;

pub(crate) use brokk_bifrost_core::analyzer::weighted_cache;

pub(crate) use brokk_bifrost_core::complete_value_cache;

#[doc(hidden)]
pub mod workspace;

/// Retain a lazy external index until one of its discovery inputs changes.
#[doc(hidden)]
pub fn updated_external_index<T>(
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
#[doc(hidden)]
pub fn estimate_collection_bytes<T>(
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
pub use brokk_bifrost_core::analyzer::canonical_hash;
pub use brokk_bifrost_core::analyzer::identifier;
pub use brokk_bifrost_core::analyzer::test_paths;

use brokk_bifrost_core::analyzer::capabilities;
use brokk_bifrost_core::analyzer::code_unit_index;
use brokk_bifrost_core::analyzer::config;
use brokk_bifrost_core::analyzer::model;
use brokk_bifrost_core::analyzer::pool_memo;
use brokk_bifrost_core::analyzer::project;
use brokk_bifrost_core::analyzer::source_content;

pub(crate) use brokk_bifrost_core::analyzer::dense_id;
pub(crate) use brokk_bifrost_core::analyzer::fq_name;

pub use code_unit_index::CodeUnitIndex;

pub(crate) use definition_lookup::BoundedDefinitionLookup;
pub(crate) use definition_lookup::DefinitionLanguageScope;
pub(crate) use definition_lookup::RelationalBatchError;
pub(crate) use definition_lookup::RelationalBatchOutcome;
pub(crate) use definition_lookup::RelationalCallableFact;
pub(crate) use definition_lookup::RelationalDefinitionFrontier;
pub(crate) use definition_lookup::RelationalDefinitionLookup;
pub(crate) use definition_lookup::RelationalDefinitionQuery;
pub(crate) use definition_lookup::RelationalDefinitionQuestion;
pub(crate) use definition_lookup::RelationalDefinitionRequest;
pub(crate) use definition_lookup::RelationalDefinitionResult;
pub(crate) use definition_lookup::RelationalDefinitionValue;
pub(crate) use definition_lookup::RelationalFrontierOutcome;
pub(crate) use definition_lookup::sort_units;

pub use analyzer_definition_lookup::AnalyzerDefinitionLookup;
pub use analyzer_definition_lookup::DefinitionLookupMemo;

pub(crate) use analyzer_definition_lookup::ForwardQueryProvider;

#[doc = " The damaged-tree namespace index, for the root suites' index-level"]
#[doc = " regressions over corpus-derived C++ fixtures that stay private."]
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub use brokk_bifrost_cpp::graph::resolver::OrphanedNamespaceScopeIndex;

pub use brokk_bifrost_csharp::syntax::csharp_transparent_expression_parent;

pub use capabilities::AdditionalFileDependencies;
pub use capabilities::CapabilityProvider;
pub use capabilities::DescendantIndexScope;
pub use capabilities::DescendantIndexVariant;
pub use capabilities::FileDependencyFacts;
pub use capabilities::ImportAnalysisProvider;
pub use capabilities::ImportGraphBindingSurface;
pub use capabilities::ImportGraphInputDigests;
pub use capabilities::ImportLookupDependency;
pub use capabilities::ImportReachability;
pub use capabilities::ImportResolutionDependencies;
pub use capabilities::ImportedFileEdgeFacts;
pub use capabilities::TestDetectionProvider;
pub use capabilities::TypeAliasProvider;
pub use capabilities::TypeHierarchyProvider;

pub(crate) use capabilities::resolve_imported_files_from_infos;

pub use config::AnalyzerConfig;
pub use config::CSharpAnalyzerConfig;
pub use config::DispatchHierarchyExpansion;
pub use config::GoAnalyzerConfig;
pub use config::GoDependencyDiscoveryConfig;
pub use config::GoDependencyDiscoveryMode;
pub use config::JsTsAnalyzerConfig;
pub use config::JsTsDependencyDiscoveryConfig;
pub use config::JvmAnalyzerConfig;
pub use config::JvmDependencyDiscoveryConfig;
pub use config::JvmDependencyDiscoveryMode;
pub use config::JvmExternalArtifact;
pub use config::JvmExternalArtifactOrigin;
pub use config::JvmExternalDependencies;
pub use config::JvmMavenCoordinate;
pub use config::JvmSourceToolchainBinding;
pub use config::JvmSourceToolchainSelectionOpen;
pub use config::JvmStandardLibraryDiscoveryConfig;
pub use config::PhpAnalyzerConfig;
pub use config::PhpDependencyApiEvidence;
pub use config::PythonAnalyzerConfig;
pub use config::PythonEnvironmentConfig;
pub use config::PythonEnvironmentLimits;
pub use config::RubyAnalyzerConfig;
pub use config::RubyDependencyApiEvidence;
pub use config::RubyGemApiArtifact;
pub use config::RustAnalyzerConfig;
pub use config::RustDependencyApiEvidence;
pub use config::RustPackageApiArtifact;
pub use config::RustSelectedTarget;
pub use config::ensure_global_rayon_pool;

pub use fq_name::FqName;

// Go language knowledge lives in `brokk-bifrost-go`; these keep their
// historical `crate::analyzer::` paths for the analysis-side consumers
// (symbol_lookup, searchtools, the definition routes).
pub(crate) use brokk_bifrost_go::packages::GO_MODULE_SCOPE_SEGMENT;

#[doc = " The git object id a [`ReadKey::File`] and a policy unit's seed partition"]
#[doc = " name their blob by."]
#[doc = ""]
#[doc = " Re-exported because those types are public and a consumer outside this"]
#[doc = " crate cannot otherwise name the type of a field it holds."]
pub use git2::Oid;

pub use brokk_bifrost_core::analyzer::structural::native_obligation::NativeResultObligation;
pub use brokk_bifrost_core::analyzer::structural::native_obligation::NativeResultObligationBasis;
pub use brokk_bifrost_core::analyzer::structural::native_obligation::NativeResultObligationKind;

pub use brokk_bifrost_core::analyzer::structural::result_use::CallResultUse;
pub use brokk_bifrost_core::analyzer::structural::result_use::CallResultUseFact;
pub use brokk_bifrost_core::analyzer::structural::result_use::CallResultUseIndex;
pub use brokk_bifrost_core::analyzer::structural::result_use::CallResultUseOpenReason;
pub use brokk_bifrost_core::analyzer::structural::result_use::CallResultUseSite;
pub use brokk_bifrost_core::analyzer::structural::result_use::IntentionalDiscardKind;

pub use brokk_bifrost_csharp::structural::CSharpCallResultUseIndex;

pub use brokk_bifrost_python::declarations::python_function_has_decorator;

pub use i_analyzer::AnalyzerStreamingFileScope;

pub(crate) use i_analyzer::replay_query_reads;

pub use i_analyzer::AnalyzerBuildTierAccess;
pub use i_analyzer::AnalyzerQueryContext;
pub use i_analyzer::AnalyzerSnapshotCaches;
pub use i_analyzer::IAnalyzer;
pub use i_analyzer::PersistedImportAdjacency;
pub use i_analyzer::PersistedImportDependencies;
pub use i_analyzer::PersistedImportDirection;
pub use i_analyzer::PersistedImportEdge;
pub use i_analyzer::PersistedImportGraphRefresh;
pub use i_analyzer::QueryBatch;
pub use i_analyzer::QueryReadIncomplete;
pub use i_analyzer::SearchSymbolCandidates;
pub use i_analyzer::SearchSymbolPatternBatch;
pub use i_analyzer::WorkspaceFileIndex;
pub use i_analyzer::WorkspaceFileIndexCell;
pub use i_analyzer::{capture_query_reads, replay_query_read_keys};

pub use i_analyzer::AnalyzerQueryScope;
pub use i_analyzer::InformationTier;
pub use i_analyzer::QueryScope;
pub use i_analyzer::QueryToken;

#[cfg(any(test, feature = "test-support"))]
pub use i_analyzer::AnalyzerTestHooks;
#[cfg(any(test, feature = "test-support"))]
pub use i_analyzer::NoOpAnalyzerTestHooks;

pub use index_warmer::IndexWarmer;

pub use model::CallableArity;
pub use model::CallableFacts;
pub use model::CallableOverrideModifier;
pub use model::CloneSmell;
pub use model::CloneSmellWeights;
pub use model::CodeBaseMetrics;
pub use model::CodeUnit;
pub use model::CodeUnitType;
pub use model::CommentDensityStats;
pub use model::DeclarationId;
pub use model::DeclarationInfo;
pub use model::DeclarationKind;
pub use model::DispatchExtensibility;
pub use model::ExceptionHandlingAnalysis;
pub use model::ExceptionHandlingSmell;
pub use model::ExceptionSmellWeights;
pub use model::ImportInfo;
pub use model::JVM_SEMANTIC_PACK_LANGUAGES;
pub use model::Language;
pub use model::LanguageDialect;
pub use model::MaintainabilitySizeSmell;
pub use model::MaintainabilitySizeSmellWeights;
pub use model::PackageAnchor;
pub use model::ParameterMetadata;
pub use model::ParseCompleteness;
pub use model::ParseError;
pub use model::ParseErrorKind;
pub use model::ProjectFile;
pub use model::Range;
pub use model::RubyMethodDispatchMode;
pub use model::ScalaExportInfo;
pub use model::ScalaExportSelector;
pub use model::SearchSymbolCandidate;
pub use model::SemanticAbsenceProof;
pub use model::SemanticDiagnostic;
pub use model::SemanticDiagnosticDomain;
pub use model::SemanticDiagnosticIncompleteReason;
pub use model::SemanticDiagnosticOutcome;
pub use model::SemanticDiagnosticReport;
pub use model::SemanticDiagnosticReportStatus;
pub use model::SignatureMetadata;
pub use model::StructuredImportPath;
pub use model::StructuredImportPathKind;
pub use model::StructuredImportScope;
pub use model::StructuredTypeIdentity;
pub use model::StructuredTypeName;
pub use model::SummaryFileProjection;
pub use model::TestAssertionAnalysis;
pub use model::TestAssertionSmell;
pub use model::TestAssertionWeights;
pub use model::metrics_from_declarations;
pub use model::semantic_pack_realm;

/// Select the earliest range by source line, then by byte offset.
pub fn primary_range(ranges: &[Range]) -> Option<Range> {
    ranges
        .iter()
        .min_by_key(|range| (range.start_line, range.start_byte))
        .copied()
}

pub(crate) use model::CppTemplateMetadata;

pub use multi_analyzer::resolve_analyzer;

pub use multi_analyzer::AnalyzerDelegate;
pub use multi_analyzer::LanguageAnalyzer;
pub use multi_analyzer::MultiAnalyzer;
pub use multi_analyzer::is_language_configuration_input;

pub(crate) use pool_memo::install_on_dedicated_build_pool;
pub(crate) use pool_memo::spawn_on_dedicated_build_pool;

pub use project::BIFROST_IGNORE_FILE_NAME;
pub use project::DEFAULT_MAX_OVERLAY_BYTES;
pub use project::FileSetProject;
pub use project::FilesystemProject;
pub use project::MultiRootProject;
pub use project::OverlayProject;
pub use project::OverlayRevision;
pub use project::Project;
pub use project::ProjectCoverage;
pub use project::ProjectSourceOrigin;
pub use project::ProjectSourceSnapshot;
pub use project::SubsetCoverage;
pub use project::TestProject;
pub use project::WorkspaceFileListingCache;
pub use project::collect_workspace_files;

pub use read_ledger::IndexFamily;
pub use read_ledger::LookupKind;
pub use read_ledger::LookupQuestion;
pub use read_ledger::ReadKey;
pub use read_ledger::ReadLedger;
pub use read_ledger::ReadSetDigest;
pub use read_ledger::absent_summary_digest;

pub use read_verification::ChangedFacts;
pub use read_verification::ChangedRead;
pub use read_verification::HeadInputs;
pub use read_verification::LookupMemo;
pub use read_verification::LookupReplayLimits;
pub use read_verification::NoSummaryAnswers;
pub use read_verification::ProcedureDispatchReadCallError;
pub use read_verification::ReadVerdict;
pub use read_verification::SummaryAnswers;
pub use read_verification::WorkspaceFactIndex;
pub use read_verification::analysis_epoch_digest;
pub use read_verification::procedure_dispatch_read_call;
pub use read_verification::replay_lookup;
pub use read_verification::verify_procedure_dispatch_read;
pub use read_verification::verify_read_set;
pub use read_verification::verify_read_set_for_artifact;

#[cfg(any(test, feature = "test-support"))]
pub use resolution::reset_reverse_fact_evaluation_count_for_test;
#[cfg(any(test, feature = "test-support"))]
pub use resolution::reverse_fact_evaluation_count_for_test;

pub use source_content::SourceContent;

pub use source_ingestion::IngestedSource;
pub use source_ingestion::SourceIngestionError;
pub use source_ingestion::SourceIngestionKind;
pub use source_ingestion::ingest_source_bytes;

pub(crate) use tree_sitter_analyzer::AnalyzerStoreContext;
pub(crate) use tree_sitter_analyzer::BuildAbort;

pub(crate) use tree_sitter_analyzer::RevisionBlobIdentities;
pub(crate) use tree_sitter_analyzer::revision_image_store_context;

pub use tree_sitter_analyzer::BuildProgress;
pub use tree_sitter_analyzer::BuildProgressEvent;
pub use tree_sitter_analyzer::BuildProgressPhase;
pub use tree_sitter_analyzer::LanguageAdapter;
pub use tree_sitter_analyzer::TreeSitterAnalyzer;

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub use usages::java_usage_evidence_cache::JavaUsageEvidenceCacheStats;

pub use usages::workspace_graph::UsageEcosystem;

pub(crate) use workspace::WorkspaceProjectionLease;

pub use workspace::DependencyPackActivationOutcome;
pub use workspace::DependencyPackEcosystem;
pub use workspace::DependencyPackEcosystemOutcome;
pub use workspace::DependencyPackWorkspaceContext;
pub use workspace::EmptyAnalyzer;
pub use workspace::InstalledDependencyPackActivationOutcome;
pub use workspace::PythonSemanticModelActivationOutcome;
pub use workspace::PythonSemanticModelWorkspaceContext;
pub use workspace::WorkspaceAnalyzer;

pub use brokk_bifrost_core::analyzer::language_knowledge::ParserFlavor;

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
    languages::language_knowledge(language).map(|knowledge| knowledge.parser_language(flavor))
}

/// Resolve the parser grammar used by the indexed analyzer for a specific path.
#[doc(hidden)]
pub fn parser_language_for_path(
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
    languages::language_knowledge(language).map(|knowledge| knowledge.structural_spec())
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

#[doc(hidden)]
pub use brokk_bifrost_core::analyzer::definition_lookup;

pub mod semantic;
pub mod semantic_model;

pub(crate) mod selected_services;

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod store_support;

pub use brokk_bifrost_core::analyzer::carried_context::CarriedContext;
pub use i_analyzer::{
    ReadAttribution, ReadAttributionGuard, read_attribution_fallback_count,
    read_attribution_records_reads,
};
