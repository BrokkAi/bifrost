//! Versioned static-analysis policy authoring, loading, evaluation, and reporting.

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
mod source;
mod suppression;
mod typestate_policy;

#[cfg(test)]
mod adapter_seam_tests;

pub use crate::schema_version::{SchemaVersionOrigin, SchemaVersionResolution};
pub use crate::workspace_document::{WorkspaceDocumentError, WorkspacePathError};
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
pub use source::rqlp_source_completion_at;
pub use source::*;
pub use suppression::*;
