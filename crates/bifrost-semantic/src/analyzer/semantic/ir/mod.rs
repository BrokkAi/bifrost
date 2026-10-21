//! Immutable, language-neutral procedure semantics.
//!
//! The IR deliberately keeps dense IDs in hot rows.  A bare [`ValueId`] (or
//! any other procedure-local ID) is meaningful only together with its owning
//! procedure. Provider and oracle boundaries should therefore use
//! [`ProcedureHandle`] or [`ProcedureLocalHandle`], while validated artifact
//! internals can use the compact IDs directly. Artifact-nonretaining rows that
//! must reacquire their owner use [`ProcedureLocalLocator`], which verifies the
//! exact frozen artifact contents before interpreting a dense ID.

#[doc(hidden)]
pub mod artifact;
#[doc(hidden)]
pub mod model;
mod validation;

pub use crate::analyzer::semantic::ir::artifact::*;

pub use crate::analyzer::semantic::ir::model::*;

#[doc(hidden)]
pub use validation::measure_procedure_work;
