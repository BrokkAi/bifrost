//! The Rust selected-root demand engine.
//!
//! Production Rust prefix resolution runs here. Demand, outgoing and graph-stage
//! operations read the same published own-binding authority; their scheduling
//! and selected-content projections remain request-local.
//!
//! Three pieces: `inventory` indexes the immutable selected root halves and
//! answers "what does this one demand need"; `forward` prepares one caller's
//! source and drives the scheduler's provider protocol; `relations` holds the
//! published per-endpoint relations and the source that reads them.

pub(crate) mod forward;
#[doc(hidden)]
pub use forward::RUST_DEMAND_INSTALLER;
pub(crate) mod inventory;
pub(crate) mod relations;

#[doc(hidden)]
pub mod rows;
