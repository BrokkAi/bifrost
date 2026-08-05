//! Python language knowledge for Bifrost.
//!
//! Internal implementation detail of `brokk-bifrost`; no stability guarantees --
//! depend on `brokk-bifrost` instead.
//!
//! This crate sits between [`brokk_bifrost_core`] and `brokk-bifrost-analysis`.
//! It holds Python *language knowledge* -- module identity, the declaration
//! walk, import parsing and binding, the structural spec, test detection,
//! lexical scope bindings, the export/importer usage index, and the usage-graph
//! forward and inverted scans -- as plain functions and data. It depends on no
//! other Bifrost crate than core, so nothing here may name `IAnalyzer`,
//! `TreeSitterAnalyzer`, or `PythonAnalyzer`.
//!
//! Where analysis code would reach for an analyzer handle, the functions here
//! take [`graph_support::PythonAnalysisSource`] (or
//! [`graph_support::PythonUsageSource`] once the usage index exists) -- a core
//! [`brokk_bifrost_core::analyzer::CodeUnitIndex`] plus the memoized per-file
//! products Python resolves through. `analyzer/python/` in
//! `brokk-bifrost-analysis` keeps the shim: the `PythonAnalyzer` struct and its
//! six moka caches and two `OnceLock`s, the accessors that implement those two
//! traits, the `PythonAdapter` forwarding shell, the SPI block, and the
//! downcasts that produce the arguments.

pub mod adapter;
pub mod bindings;
pub mod clones;
pub mod declarations;
pub mod diagnostics;
pub mod graph;
pub mod graph_support;
pub mod imports;
pub mod queries;
pub mod structural;
pub mod syntax;
pub mod test_detection;
pub mod usage_index;
