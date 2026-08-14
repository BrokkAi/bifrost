//! Finite, deterministic composition of policy endpoint declarations.

mod common;
mod precedence;
mod taint;
mod typestate;

pub(crate) use common::validate_scanned_endpoint_collection;
pub(crate) use common::{CompositionError, CompositionLimits};
pub(crate) use precedence::{PrecedenceError, PrecedenceGraph};
pub(crate) use taint::compose_taint_policy;
pub(crate) use typestate::compose_typestate_policy;
