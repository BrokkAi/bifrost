//! The Rust selected-root demand engine.
//!
//! Production Rust prefix resolution runs here. The eager whole-inventory
//! prefix compiler in `resolution_operation.rs` is retained only as the test
//! oracle the demand answers are certified against.
//!
//! Three pieces: `inventory` indexes the immutable selected root halves and
//! answers "what does this one demand need"; `forward` prepares one caller's
//! source and drives the scheduler's provider protocol; `relations` holds the
//! published per-endpoint relations and the source that reads them.

pub(crate) mod forward;
pub(crate) mod inventory;
pub(crate) mod relations;

pub(super) mod rows;
