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

pub mod call_relations;
pub mod call_shape;
mod candidates;
pub(crate) mod common;
pub mod cpp_graph;
pub(crate) mod csharp_graph;
pub(crate) mod file_usage_graph;
mod finder;
pub mod get_definition;
pub mod get_type;
pub(crate) mod go_graph;
pub(crate) mod inverted_edges;
pub(crate) mod java_graph;
pub(crate) mod js_ts_graph;
pub(crate) mod kotlin_graph;
pub(crate) mod parsed_tree;
pub(crate) mod php_graph;
pub(crate) mod python_graph;
pub(crate) mod receiver_query;
pub(crate) mod receiver_sites;
pub(crate) mod ruby_graph;
pub(crate) mod rust_graph;
pub(crate) mod scala_graph;
pub mod target_kind;
mod traits;
pub(crate) mod workspace_graph;
pub(crate) mod workspace_graph_cache;

// The language-blind half of this subsystem moved to `brokk-bifrost-core`: the
// usage products (`model`), the graph outcome wrapper, the pure local-inference
// engine, reference-site resolution, receiver-analysis vocabulary, the import
// edge types, the same-owner routing policy, and the re-export seed walk. Each
// module keeps the visibility its `mod` declaration had here, except where every
// item it holds was already crate-private, in which case the alias narrows to
// `pub(crate)` rather than re-publishing core's promoted `pub` items.
use brokk_bifrost_core::analyzer::usages::{local_inference, model};
pub(crate) use brokk_bifrost_core::analyzer::usages::{outcome, receiver_analysis, reference_site};

#[cfg(test)]
pub(crate) use call_relations::CallArgument;
pub(crate) use call_relations::{
    CallBindingCache, CallBindingStatus, CallDispatchBoundaryKind, CallDispatchTarget,
    CallRelationDiagnostic, CallRelationDiagnosticCode, CallRelationLimits, CallRelationResult,
    CallSite, ExactCallLocation, bind_call_site_arguments, call_dispatch_equivalence_source,
};
pub use call_relations::{CallRelationService, is_call_relation_unit, nearest_call_relation_unit};
pub use candidates::{
    ExplicitCandidateProvider, FallbackCandidateProvider, ImportGraphCandidateProvider,
    TextSearchCandidateProvider, default_provider,
};
pub use cpp_graph::CppUsageGraphStrategy;
pub use csharp_graph::CSharpUsageGraphStrategy;
pub use finder::{
    DEFAULT_MAX_FILES, DEFAULT_MAX_USAGES, QueryResult, UsageFinder, UsageQueryCompletion,
};
pub use go_graph::GoUsageGraphStrategy;
pub use java_graph::JavaUsageGraphStrategy;
pub use js_ts_graph::JsTsExportUsageGraphStrategy;
pub use kotlin_graph::KotlinUsageGraphStrategy;
pub use local_inference::{
    LocalBindingsSnapshot, LocalInferenceConfig, LocalInferenceEngine, SymbolResolution,
};
pub use model::{
    CONFIDENCE_THRESHOLD, ExportEntry, ExportIndex, FuzzyResult, ImportBinder, ImportBinding,
    ImportKind, ReceiverTargetRef, ReexportStar, ReferenceCandidate, ReferenceGraphResult,
    ReferenceHit, ReferenceKind, ResolvedReceiverCandidate, UsageAnalysisDiagnostic, UsageHit,
    UsageHitKind, UsageHitSurface, UsageProof,
};
pub use php_graph::PhpUsageGraphStrategy;
pub use python_graph::PythonExportUsageGraphStrategy;
pub use ruby_graph::RubyUsageGraphStrategy;
pub use rust_graph::RustExportUsageGraphStrategy;
pub use scala_graph::ScalaUsageGraphStrategy;
pub(crate) use traits::GraphUsageAnalyzer;
pub use traits::{CandidateFileProvider, UsageAnalyzer};

use crate::analyzer::{CodeUnit, IAnalyzer};

/// Convenience equivalent to [`crate::analyzer::IAnalyzer::find_usages`] for callers that
/// only hold a `&dyn IAnalyzer`.
pub fn find_usages(analyzer: &dyn IAnalyzer, overloads: &[CodeUnit]) -> FuzzyResult {
    UsageFinder::new().find_usages(analyzer, overloads, DEFAULT_MAX_FILES, DEFAULT_MAX_USAGES)
}
