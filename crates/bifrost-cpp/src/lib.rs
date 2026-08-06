//! C++ language knowledge for Bifrost.
//!
//! Internal implementation detail of `brokk-bifrost`; no stability guarantees --
//! depend on `brokk-bifrost` instead.
//!
//! This crate sits between [`brokk_bifrost_core`] and `brokk-bifrost-analysis`.
//! It holds C++ *language knowledge* -- the declaration walk with its
//! macro-sentinel error recovery, `#include` parsing and include-target
//! resolution, out-of-line member identity reconciliation, the structural spec,
//! test detection, clone normalization, compile-database ingestion and the
//! usage-graph scans -- as plain functions and data. It depends on no other
//! Bifrost crate than core, so nothing here may name `IAnalyzer`,
//! `TreeSitterAnalyzer`, or `CppAnalyzer`.
//!
//! Where analysis code would reach for an analyzer handle, the functions here
//! take a C++ source trait -- a core
//! [`brokk_bifrost_core::analyzer::CodeUnitIndex`] plus the memoized C++
//! products the language logic resolves through. `analyzer/cpp/` in
//! `brokk-bifrost-analysis` keeps the shim: the `CppAnalyzer` struct with its
//! five moka caches, three `OnceLock` cells, one `PoolSafeMemo` and six
//! `test-support` counters, the `CodeUnitIndex` impl carrying the #1134
//! reconciliation overlay, the `IAnalyzer` impl, the `CppAdapter` forwarding
//! shell, the SPI block, and the downcasts that produce the arguments.

pub mod adapter;
pub mod call_match;
pub mod clones;
pub mod compile_context;
pub mod declarations;
pub mod diagnostics;
pub mod graph;
pub mod graph_support;
pub mod hierarchy;
pub mod identity;
pub mod imports;
pub mod queries;
pub mod reconcile;
pub mod structural;
pub mod test_detection;
