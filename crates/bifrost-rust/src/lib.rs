//! Rust language knowledge for Bifrost.
//!
//! Internal implementation detail of `brokk-bifrost`; no stability guarantees --
//! depend on `brokk-bifrost` instead.
//!
//! This crate sits between [`brokk_bifrost_core`] and `brokk-bifrost-analysis`.
//! It holds Rust *language knowledge* -- cargo target routing, the declaration
//! walk, use-tree and visibility arithmetic, the structural spec, test
//! detection, the lexical scope and parse memo, the type hierarchy, and the
//! usage-graph resolution index -- as plain functions and data. It depends on
//! no other Bifrost crate than core, so nothing here may name `IAnalyzer`,
//! `TreeSitterAnalyzer`, or `RustAnalyzer`.
//!
//! Where analysis code would reach for an analyzer handle, the functions here
//! take `graph_support::RustAnalysisSource` (or `RustUsageSource` once the usage
//! index exists) -- a core [`brokk_bifrost_core::analyzer::CodeUnitIndex`] plus
//! the memoized per-file products Rust resolves through. `analyzer/rust/` in
//! `brokk-bifrost-analysis` keeps the shim: the `RustAnalyzer` newtype and its
//! seven lazy cells, the accessors that implement those two traits, the
//! `RustAdapter` forwarding shell, the SPI block, and the downcasts that produce
//! the arguments.

pub mod adapter;
pub mod cargo_routes;
pub mod declarations;
pub mod diagnostics;
pub mod field_roles;
pub mod graph;
pub mod graph_support;
pub mod hierarchy;
pub mod imports;
pub mod lexical_scope;
pub mod queries;
pub mod structural;
pub mod test_detection;
pub mod usage_index;
