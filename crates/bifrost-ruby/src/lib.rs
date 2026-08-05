//! Ruby language knowledge for Bifrost.
//!
//! Internal implementation detail of `brokk-bifrost`; no stability guarantees --
//! depend on `brokk-bifrost` instead.
//!
//! This crate sits between [`brokk_bifrost_core`] and `brokk-bifrost-analysis`.
//! It holds Ruby *language knowledge* -- the declaration walk, `require` /
//! `autoload` / Zeitwerk visibility, mixin and dispatch-mode facts, the
//! structural spec, test detection, semantic diagnostics, and the usage-graph
//! forward and inverted scans -- as plain functions and data. It depends on no
//! other Bifrost crate than core, so nothing here may name `IAnalyzer`,
//! `TreeSitterAnalyzer`, or `RubyAnalyzer`.
//!
//! Where analysis code would reach for an analyzer handle, the functions here
//! take [`graph_support::RubySource`] -- a core
//! [`brokk_bifrost_core::analyzer::CodeUnitIndex`] plus the memoized Ruby
//! products the language logic resolves through. `analyzer/ruby/` in
//! `brokk-bifrost-analysis` keeps the shim: the `RubyAnalyzer` struct with its
//! three moka caches, nine `OnceLock` cells and one `PoolSafeMemo`, the
//! accessors that satisfy those traits, the `RubyAdapter` forwarding shell, the
//! SPI block, and the downcasts that produce the arguments.

pub mod adapter;
pub mod declarations;
pub mod diagnostics;
pub mod graph;
pub mod graph_support;
pub mod hierarchy;
pub mod imports;
pub mod mixins;
pub mod queries;
pub mod structural;
pub mod syntax;
pub mod test_detection;
