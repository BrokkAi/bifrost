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
//! take `graph_support::RustSource` (or `RustFactSource` once the usage
//! index exists) -- a core [`brokk_bifrost_core::analyzer::CodeUnitIndex`] plus
//! the retained bounded indexes Rust resolves through. `analyzer/rust/` in
//! `brokk-bifrost-analysis` keeps the shim: the `RustAnalyzer` newtype and its
//! bounded indexes, the accessors that implement those two traits, the
//! `RustAdapter` forwarding shell, the SPI block, and the downcasts that produce
//! the arguments.

pub mod adapter;
pub mod cache;
pub mod cargo_manifest;
pub mod cargo_routes;
pub mod crate_naming;
mod declaration_properties;
pub mod declaration_types;
pub mod declarations;
pub mod diagnostics;
pub mod facts;
pub mod field_roles;
pub mod graph_support;
pub mod hierarchy;
pub mod hierarchy_source_context;
pub mod imports;
mod item_sources;
pub mod lexical_scope;
pub mod macro_matcher;
mod macro_source_capture;
pub mod ownership;
pub mod prelude;
pub mod proof;
pub mod queries;
mod resolution;
#[cfg(any(test, feature = "test-support"))]
pub mod resolution_spike_fixture;
pub mod selected_context;
pub mod structural;
pub mod syntax;
pub mod test_detection;
mod type_syntax;
pub mod usage;
pub mod usage_includes;
pub mod usage_queries;
pub mod usage_walks;

pub mod cfg;

#[cfg(test)]
mod producer_smoke_tests;
