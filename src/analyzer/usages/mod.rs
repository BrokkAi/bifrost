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
//!   Java, C#, C++, Go, and Scala targets.

mod call_relations;
mod candidates;
mod common;
mod cpp_call_match;
pub(crate) mod cpp_graph;
pub(crate) mod csharp_graph;
mod finder;
pub(crate) mod get_definition;
pub(crate) mod get_type;
pub(crate) mod go_graph;
mod graph_core;
pub(crate) mod inverted_edges;
pub(crate) mod java_graph;
pub(crate) mod js_ts_graph;
mod local_inference;
mod model;
mod outcome;
pub(crate) mod parsed_tree;
pub(crate) mod php_graph;
pub(crate) mod python_graph;
pub(crate) mod receiver_analysis;
pub(crate) mod receiver_query;
pub(crate) mod receiver_sites;
mod reexport_seeds;
pub(crate) mod reference_site;
pub(crate) mod ruby_graph;
pub(crate) mod rust_graph;
pub(crate) mod scala_graph;
pub(crate) mod target_kind;
mod traits;
pub(crate) mod workspace_graph;

#[cfg(test)]
pub(crate) use call_relations::CallArgument;
pub(crate) use call_relations::{
    CallBindingCache, CallBindingStatus, CallDispatchBoundaryKind, CallDispatchTarget,
    CallRelationDiagnostic, CallRelationDiagnosticCode, CallRelationLimits, CallRelationResult,
    CallRelationService, CallSite, ExactCallLocation, bind_call_site_arguments,
    call_dispatch_equivalence_source, is_call_relation_unit, nearest_call_relation_unit,
};
pub use candidates::{
    ExplicitCandidateProvider, FallbackCandidateProvider, ImportGraphCandidateProvider,
    TextSearchCandidateProvider, default_provider,
};
pub use cpp_graph::CppUsageGraphStrategy;
pub use csharp_graph::CSharpUsageGraphStrategy;
pub use finder::{DEFAULT_MAX_FILES, DEFAULT_MAX_USAGES, QueryResult, UsageFinder};
pub use go_graph::GoUsageGraphStrategy;
pub(crate) use graph_core::{ImportEdge, ImportEdgeKind};
pub use java_graph::JavaUsageGraphStrategy;
pub use js_ts_graph::JsTsExportUsageGraphStrategy;
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
pub use traits::{CandidateFileProvider, UsageAnalyzer};

use crate::analyzer::{CodeUnit, IAnalyzer};

/// Convenience equivalent to [`crate::analyzer::IAnalyzer::find_usages`] for callers that
/// only hold a `&dyn IAnalyzer`.
pub fn find_usages(analyzer: &dyn IAnalyzer, overloads: &[CodeUnit]) -> FuzzyResult {
    UsageFinder::new().find_usages(analyzer, overloads, DEFAULT_MAX_FILES, DEFAULT_MAX_USAGES)
}
