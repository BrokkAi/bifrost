//! Find call sites and references for a [`crate::analyzer::CodeUnit`].
//!
//! This analyzer-owned subsystem resolves usage queries from tree-sitter analyzer state.
//! JDT-driven Java analysis and the LLM-based disambiguator from Brokk are intentionally
//! omitted because Bifrost is tree-sitter-only and the LLM layer belongs to the embedding host.
//!
//! Public entry point is [`UsageFinder`], which wires a [`CandidateFileProvider`] together
//! with a language-specific graph strategy. The default query chain is:
//!
//! - [`ImportGraphCandidateProvider`] for the candidate file set, with
//!   [`TextSearchCandidateProvider`] as a substring-scan fallback.
//! - Language-specific graph strategies for JavaScript / TypeScript, Python, PHP, Rust,
//!   Java, Kotlin, C#, C++, Go, Ruby, and Scala targets.

pub mod applicability;
pub mod call_binding;
pub mod call_conversion;
pub mod call_relations;
pub mod call_shape;
pub mod callable_signature;
#[doc(hidden)]
pub mod candidates;
#[doc(hidden)]
pub mod common;

pub mod effects;
#[doc(hidden)]
pub mod file_usage_graph;
#[doc(hidden)]
pub mod finder;
pub mod get_definition;
pub mod get_type;

#[doc(hidden)]
pub mod inverted_edges;
pub(crate) mod java_graph;
pub(crate) mod java_usage_evidence_cache;

pub(crate) mod kotlin_graph;
pub mod member_completion;
pub mod member_family;
pub mod overload_selection;
pub(crate) mod parsed_tree;

pub mod python_class_hierarchy;

pub mod receiver_query;
#[doc(hidden)]
pub mod receiver_sites;

pub(crate) mod scala_graph;
pub mod target_kind;
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod test_support;
#[doc(hidden)]
pub mod traits;
#[doc(hidden)]
pub mod workspace_graph;
#[doc(hidden)]
pub mod workspace_graph_cache;

// The language-blind half of this subsystem moved to `brokk-bifrost-core`: the
// usage products (`model`), the graph outcome wrapper, the pure local-inference
// engine, reference-site resolution, receiver-analysis vocabulary, the import
// edge types, the same-owner routing policy, and the re-export seed walk. Each
// module keeps the visibility its `mod` declaration had here, except where every
// item it holds was already crate-private, in which case the alias narrows to
// `pub(crate)` rather than re-publishing core's promoted `pub` items.
use brokk_bifrost_core::analyzer::usages::local_inference;
use brokk_bifrost_core::analyzer::usages::model;

pub use brokk_bifrost_core::analyzer::usages::outcome;
pub use brokk_bifrost_core::analyzer::usages::receiver_analysis;
pub use brokk_bifrost_core::analyzer::usages::reference_site;

#[doc(hidden)]
pub fn read_source(file: &crate::analyzer::ProjectFile) -> Result<String, String> {
    file.read_to_string().map_err(|err| {
        format!(
            "failed to read `{}`: {err}",
            crate::path_utils::rel_path_string(file)
        )
    })
}

pub(crate) fn range_for_span(
    facts: &crate::analyzer::structural::FileFacts,
    span: crate::analyzer::structural::Span,
) -> crate::analyzer::Range {
    brokk_bifrost_core::analyzer::semantic_diagnostics::range_for_byte_offsets(
        facts.line_starts(),
        span.start_byte,
        span.end_byte,
    )
}

#[doc(hidden)]
pub const fn proof_rank(proof: crate::analyzer::usages::UsageProof) -> u8 {
    match proof {
        crate::analyzer::usages::UsageProof::Proven => 0,
        crate::analyzer::usages::UsageProof::Unproven => 1,
    }
}

pub(crate) fn source_location_request(
    file: &crate::analyzer::ProjectFile,
    line: Option<usize>,
    column: Option<usize>,
    start_byte: Option<usize>,
    end_byte: Option<usize>,
) -> brokk_bifrost_core::analyzer::usages::reference_site::SourceLocationRequest {
    brokk_bifrost_core::analyzer::usages::reference_site::SourceLocationRequest {
        file: file.clone(),
        line,
        column,
        start_byte,
        end_byte,
    }
}

#[cfg(test)]
pub(crate) fn test_unit(name: &str) -> crate::analyzer::CodeUnit {
    let file = crate::analyzer::ProjectFile::new(std::env::temp_dir(), "Main.java");
    crate::analyzer::CodeUnit::new(
        file,
        crate::analyzer::CodeUnitType::Function,
        "app",
        format!("Widget.{name}"),
    )
}

#[cfg(any(test, feature = "test-support"))]
pub use call_relations::CallArgument;

pub use call_relations::CallBindingCache;
pub use call_relations::CallBindingStatus;
pub use call_relations::CallRelationDiagnostic;
pub use call_relations::CallRelationDiagnosticCode;
pub use call_relations::CallRelationLimits;
pub use call_relations::CallRelationResult;
pub use call_relations::CallSite;
pub use call_relations::bind_call_site_arguments;

pub(crate) use call_relations::CallDispatchBoundaryKind;
pub(crate) use call_relations::CallDispatchLookup;
pub(crate) use call_relations::CallDispatchSession;
pub(crate) use call_relations::CallDispatchTarget;
pub(crate) use call_relations::call_dispatch_equivalence_source;

pub use call_relations::CallRelationService;
pub use call_relations::is_call_relation_unit;
pub use call_relations::nearest_call_relation_unit;

pub use candidates::ExplicitCandidateProvider;
pub use candidates::FallbackCandidateProvider;
pub use candidates::ImportGraphCandidateProvider;
pub use candidates::TextSearchCandidateProvider;
pub use candidates::default_provider;

pub use finder::DEFAULT_MAX_FILES;
pub use finder::DEFAULT_MAX_USAGES;
pub use finder::QueryResult;
pub use finder::ReferenceEngine;
pub use finder::UsageFinder;
pub use finder::UsageQueryCompletion;

pub use kotlin_graph::KotlinUsageGraphStrategy;

pub use local_inference::LocalBindingsSnapshot;
pub use local_inference::LocalInferenceConfig;
pub use local_inference::LocalInferenceEngine;
pub use local_inference::SymbolResolution;

pub use member_family::Admission;
pub use member_family::CSharpFamilyRules;
pub use member_family::ExternalMemberFamilyAnswer;
pub use member_family::ExternalMemberFamilyIncompleteReason;
pub use member_family::ExternalMemberFamilyStatus;
pub use member_family::JavaFamilyRules;
pub use member_family::JvmExternalMemberIdentity;
pub use member_family::JvmReceiverSemantics;
pub use member_family::MemberFacts;
pub use member_family::MemberFamilyAnswer;
pub use member_family::MemberFamilyEdge;
pub use member_family::MemberFamilyProvider;
pub use member_family::MemberFamilySupport;
pub use member_family::NominalFamilyRules;
pub use member_family::ScalaFamilyRules;
pub use member_family::csharp_member_family;
pub use member_family::csharp_member_family_capability;
pub use member_family::java_member_family;
pub use member_family::java_member_family_capability;
pub use member_family::member_family_id;
pub use member_family::member_family_support;
pub use member_family::nominal_member_family;
pub use member_family::nominal_member_family_capability;
pub use member_family::scala_member_family;
pub use member_family::scala_member_family_capability;

pub use model::CONFIDENCE_THRESHOLD;
pub use model::ExportEntry;
pub use model::ExportIndex;
pub use model::FuzzyResult;
pub use model::ImportBinder;
pub use model::ImportBinding;
pub use model::ImportKind;
pub use model::ReceiverTargetRef;
pub use model::ReexportStar;
pub use model::ReferenceCandidate;
pub use model::ReferenceGraphResult;
pub use model::ReferenceHit;
pub use model::ReferenceKind;
pub use model::ResolvedReceiverCandidate;
pub use model::UsageAnalysisDiagnostic;
pub use model::UsageHit;
pub use model::UsageHitKind;
pub use model::UsageHitSurface;
pub use model::UsageProof;
pub use model::UsageProofAuthority;

pub(crate) use traits::GraphUsageAnalyzer;

pub use traits::CandidateFileProvider;
pub use traits::UsageAnalyzer;

use crate::analyzer::CodeUnit;
use crate::analyzer::IAnalyzer;

/// Convenience equivalent to [`crate::analyzer::IAnalyzer::find_usages`] for callers that
/// only hold a `&dyn IAnalyzer`.
pub fn find_usages(analyzer: &dyn IAnalyzer, overloads: &[CodeUnit]) -> FuzzyResult {
    let result = crate::analyzer::i_analyzer::capture_usage_lookup_reads(analyzer, || {
        UsageFinder::new().find_usages(analyzer, overloads, DEFAULT_MAX_FILES, DEFAULT_MAX_USAGES)
    });
    crate::analyzer::i_analyzer::record_usage_lookup(analyzer, overloads, &result);
    result
}
