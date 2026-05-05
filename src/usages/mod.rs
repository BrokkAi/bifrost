//! Find call sites and references for a [`crate::analyzer::CodeUnit`].
//!
//! The subsystem is a Rust port of brokk's `ai.brokk.analyzer.usages` package. JDT-driven
//! Java analysis and the LLM-based disambiguator are intentionally omitted — bifrost is a
//! tree-sitter-only codebase and the LLM layer belongs to the embedding host.
//!
//! Public entry point is [`UsageFinder`], which wires a [`CandidateFileProvider`] together
//! with a [`UsageAnalyzer`] strategy. The default fallback chain is:
//!
//! - [`ImportGraphCandidateProvider`] for the candidate file set, with
//!   [`TextSearchCandidateProvider`] as a substring-scan fallback.
//! - [`JsTsExportUsageGraphStrategy`] for JS/TS targets. When the graph cannot infer a
//!   seed it returns [`FuzzyResult::Failure`]; [`UsageFinder`] then routes the query to
//!   the regex analyzer instead.
//! - [`RegexUsageAnalyzer`] for everything else.

mod candidates;
mod finder;
mod js_ts_graph;
mod model;
mod regex_analyzer;
mod traits;

pub use candidates::{
    FallbackCandidateProvider, ImportGraphCandidateProvider, TextSearchCandidateProvider,
    default_provider,
};
pub use finder::{DEFAULT_MAX_FILES, DEFAULT_MAX_USAGES, QueryResult, UsageFinder};
pub use js_ts_graph::JsTsExportUsageGraphStrategy;
pub use model::{
    CONFIDENCE_THRESHOLD, ExportEntry, ExportIndex, FuzzyResult, ImportBinder, ImportBinding,
    ImportKind, ReceiverTargetRef, ReexportStar, ReferenceCandidate, ReferenceHit, ReferenceKind,
    ResolvedReceiverCandidate, UsageHit,
};
pub use regex_analyzer::RegexUsageAnalyzer;
pub use traits::{CandidateFileProvider, UsageAnalyzer};

use crate::analyzer::{CodeUnit, IAnalyzer};

/// Convenience equivalent to [`crate::analyzer::IAnalyzer::find_usages`] for callers that
/// only hold a `&dyn IAnalyzer`.
pub fn find_usages(analyzer: &dyn IAnalyzer, overloads: &[CodeUnit]) -> FuzzyResult {
    UsageFinder::new().find_usages(analyzer, overloads, DEFAULT_MAX_FILES, DEFAULT_MAX_USAGES)
}
