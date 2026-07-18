//! Finite, deterministic composition of policy endpoint declarations.

mod common;
mod precedence;
mod taint;
mod typestate;

pub(crate) use common::validate_scanned_endpoint_collection;
pub use common::{CompositionError, CompositionLimits};
pub(crate) use precedence::{PrecedenceError, PrecedenceGraph};
pub use taint::{ComposedTaintPolicy, compose_taint_policy};
pub use typestate::{ComposedTypestatePolicy, compose_typestate_policy};
