//! C# language knowledge for Bifrost.
//!
//! Internal implementation detail of `brokk-bifrost`; no stability guarantees --
//! depend on `brokk-bifrost` instead.
//!
//! This crate sits between [`brokk_bifrost_core`] and `brokk-bifrost-analysis`.
//! It holds C# *language knowledge* -- namespace and `using` resolution, the
//! declaration walk, generic-arity and constructor name normalization, the
//! structural spec, test detection, the type hierarchy's attribute reasoning,
//! and the usage-graph forward and inverted scans -- as plain functions and
//! data. It depends on no other Bifrost crate than core, so nothing here may
//! name `IAnalyzer`, `TreeSitterAnalyzer`, or `CSharpAnalyzer`.
//!
//! Where analysis code would reach for an analyzer handle, the functions here
//! take [`graph_support::CSharpSource`] -- a core
//! [`brokk_bifrost_core::analyzer::CodeUnitIndex`] plus the memoized per-file
//! products C# resolves through. One tier is enough, unlike Rust's
//! `RustSource`/`RustUsageSource` split: no `OnceLock` in the C# memo
//! web re-enters the cell it is filling. `analyzer/csharp/` in
//! `brokk-bifrost-analysis` keeps the shim: the `CSharpAnalyzer` struct with its
//! six moka caches, six `OnceLock`s and two `PoolSafeMemo`s, the accessors that
//! implement that trait, the `CSharpAdapter` forwarding shell, the SPI block,
//! and the downcasts that produce the arguments.

pub mod adapter;
pub mod clones;
pub mod dead_code;
pub mod declarations;
pub mod diagnostics;
pub mod graph;
pub mod graph_support;
pub mod hierarchy;
pub mod imports;
pub mod queries;
pub mod structural;
pub mod syntax;
pub mod test_detection;
