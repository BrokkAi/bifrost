//! Inert storage-adjacent plumbing for a future analyzer backend.
//!
//! Issue #584 deliberately exposes only live-path validation. There is no
//! analyzer database, row store, hydration, or query backend in this module.

pub(crate) mod liveness;
