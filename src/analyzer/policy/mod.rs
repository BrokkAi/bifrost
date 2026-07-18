//! Versioned static-analysis policy authoring, loading, evaluation, and reporting.

mod budget;
mod canonical;
mod canonical_loaded;
mod catalog;
mod classification;
mod composition;
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
mod report;
mod resolved;
mod retained;
pub mod schema;
mod source;

#[cfg(test)]
mod adapter_seam_tests;

pub use crate::schema_version::{SchemaInference, SchemaVersionOrigin, SchemaVersionResolution};
pub use budget::*;
pub use canonical::InlineLocalSemanticProjectionError;
pub use catalog::*;
pub use classification::*;
pub use composition::*;
pub use cvss::*;
pub use definition::*;
pub use evaluator::*;
pub use finding::*;
pub use finding_identity::*;
pub use format::*;
pub use future_evidence::*;
pub use identity::*;
pub use registry::*;
pub use report::*;
pub use resolved::*;
pub use retained::*;
pub use source::*;
