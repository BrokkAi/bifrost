//! Versioned static-analysis policy authoring, loading, evaluation, and reporting.

mod canonical;
mod canonical_loaded;
mod catalog;
mod composition;
mod definition;
mod format;
mod identity;
mod loading;
mod registry;
mod resolved;
pub mod schema;
mod source;

pub use crate::schema_version::{SchemaInference, SchemaVersionOrigin, SchemaVersionResolution};
pub use canonical::InlineLocalSemanticProjectionError;
pub use catalog::*;
pub use composition::*;
pub use definition::*;
pub use format::*;
pub use identity::*;
pub use registry::*;
pub use resolved::*;
pub use source::*;
