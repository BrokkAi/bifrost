//! Versioned static-analysis policy authoring, loading, evaluation, and reporting.

mod canonical;
mod definition;
mod format;
pub mod schema;
mod source;

pub use crate::schema_version::{SchemaInference, SchemaVersionOrigin, SchemaVersionResolution};
pub use canonical::InlineLocalSemanticProjectionError;
pub use definition::*;
pub use format::*;
pub use source::*;
