//! Rust's usage-graph reference resolution.
//!
//! [`resolver`] is the half both usage paths share: path and token-tree
//! resolution, associated-item lookup, graph seeds, and the visibility
//! predicates the scans filter targets with. It resolves through
//! [`crate::graph_support::RustUsageSource`] and a
//! [`resolver::RustDefinitionProvider`], never an analyzer handle.
//!
//! The two scan bodies -- the per-symbol forward scan (`rust_graph/extractor.rs`)
//! and the whole-workspace inverted pass (`rust_graph/inverted.rs`) -- are still
//! in `brokk-bifrost-analysis`, with the hit recorder they share. Both route
//! Rust receiver types through `get_definition/rust.rs`'s `RustTypeLookupCache`,
//! which is parked on `ResolutionSession`/`LimitedQueryRows`, so they follow
//! that file rather than this crate.

pub mod ast;
pub mod inverted;
pub mod resolver;
