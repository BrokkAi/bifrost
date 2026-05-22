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
mod cpp_graph;
mod csharp_graph;
mod finder;
mod go_graph;
mod graph_core;
mod java_graph;
mod js_ts_graph;
mod local_inference;
mod model;
mod php_graph;
mod python_graph;
mod regex_analyzer;
mod rust_graph;
mod traits;

pub use candidates::{
    FallbackCandidateProvider, ImportGraphCandidateProvider, TextSearchCandidateProvider,
    default_provider,
};
pub use cpp_graph::CppUsageGraphStrategy;
pub use csharp_graph::CSharpUsageGraphStrategy;
pub use finder::{DEFAULT_MAX_FILES, DEFAULT_MAX_USAGES, QueryResult, UsageFinder};
pub use go_graph::GoUsageGraphStrategy;
pub use java_graph::JavaUsageGraphStrategy;
pub use js_ts_graph::JsTsExportUsageGraphStrategy;
pub use local_inference::{
    LocalBindingsSnapshot, LocalInferenceConfig, LocalInferenceEngine, SymbolResolution,
};
pub use model::{
    CONFIDENCE_THRESHOLD, ExportEntry, ExportIndex, FuzzyResult, ImportBinder, ImportBinding,
    ImportKind, ReceiverTargetRef, ReexportStar, ReferenceCandidate, ReferenceGraphResult,
    ReferenceHit, ReferenceKind, ResolvedReceiverCandidate, UsageHit,
};
pub use php_graph::PhpUsageGraphStrategy;
pub use python_graph::PythonExportUsageGraphStrategy;
pub use regex_analyzer::RegexUsageAnalyzer;
pub use rust_graph::RustExportUsageGraphStrategy;
pub use traits::{CandidateFileProvider, UsageAnalyzer};

use crate::analyzer::{CodeUnit, IAnalyzer};

/// Convenience equivalent to [`crate::analyzer::IAnalyzer::find_usages`] for callers that
/// only hold a `&dyn IAnalyzer`.
pub fn find_usages(analyzer: &dyn IAnalyzer, overloads: &[CodeUnit]) -> FuzzyResult {
    UsageFinder::new().find_usages(analyzer, overloads, DEFAULT_MAX_FILES, DEFAULT_MAX_USAGES)
}
