//! Versioned static-analysis policy authoring, loading, evaluation, and reporting.
//!
//! Internal implementation detail of `brokk-bifrost`; no stability guarantees --
//! depend on `brokk-bifrost` instead.

mod budget;
mod builtin;
mod canonical;
mod canonical_loaded;
mod catalog;
mod classification;
mod composition;
mod coordinator;
mod cvss;
mod definition;
mod evaluator;
mod finding;
mod finding_identity;
mod format;
mod future_evidence;
mod identity;
mod loading;
mod projection;
mod registry;
mod render;
mod report;
mod resolved;
mod retained;
pub mod schema;
mod scope;
mod selector_compiler;
mod semantic_identity;
mod source;
mod suppression;
mod taint_policy;
mod typestate_policy;
mod witness_projection;

#[cfg(test)]
mod adapter_seam_tests;

pub use brokk_bifrost_analysis::schema_version::{SchemaVersionOrigin, SchemaVersionResolution};
pub use brokk_bifrost_analysis::workspace_document::{WorkspaceDocumentError, WorkspacePathError};
pub use budget::*;
pub use builtin::*;
pub use canonical::InlineLocalSemanticProjectionError;
pub use catalog::*;
pub use classification::*;
pub use coordinator::*;
pub use cvss::*;
pub use definition::*;
pub use evaluator::*;
pub use finding::*;
pub use finding_identity::*;
pub use format::*;
pub use future_evidence::*;
pub use identity::*;
pub use registry::*;
pub use render::*;
pub use report::*;
pub use resolved::*;
pub use scope::*;
pub use source::rqlp_source_completion_at;
pub use source::*;
pub use suppression::*;
// The retained plan/report pair and its phase metrics are produced by the taint
// engine, not by policy. They are re-exported here because they are part of this
// crate's public authoring and reporting surface.
pub use brokk_bifrost_analysis::analyzer::taint::{
    ProductionTaintAnalysisResult, ProductionTaintPhaseMetrics,
};
