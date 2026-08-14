//! Immutable, language-neutral procedure semantics.
//!
//! The IR deliberately keeps dense IDs in hot rows.  A bare [`ValueId`] (or
//! any other procedure-local ID) is meaningful only together with its owning
//! procedure.  Provider and oracle boundaries should therefore use
//! [`ProcedureHandle`] or [`ProcedureLocalHandle`], while validated artifact
//! internals can use the compact IDs directly.

mod artifact;
mod model;
mod validation;

pub use artifact::*;
pub use model::*;

#[cfg(test)]
mod tests;
