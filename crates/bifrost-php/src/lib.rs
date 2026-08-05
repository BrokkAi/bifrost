//! PHP language knowledge for Bifrost.
//!
//! Internal implementation detail of `brokk-bifrost`; no stability guarantees --
//! depend on `brokk-bifrost` instead.
//!
//! This crate sits between [`brokk_bifrost_core`] and `brokk-bifrost-analysis`.
//! It holds PHP *language knowledge* -- the declaration walk, namespace and
//! `use`-alias resolution, composer PSR-4 autoload visibility, the structural
//! spec, test detection, clone normalization, semantic diagnostics, and the
//! usage-graph forward and inverted scans -- as plain functions and data. It
//! depends on no other Bifrost crate than core, so nothing here may name
//! `IAnalyzer`, `TreeSitterAnalyzer`, or `PhpAnalyzer`.
//!
//! Where analysis code would reach for an analyzer handle, the functions here
//! take [`graph_support::PhpAnalysisSource`] -- a core
//! [`brokk_bifrost_core::analyzer::CodeUnitIndex`] plus the memoized type
//! hierarchy PHP resolves supertypes through. `analyzer/php/` in
//! `brokk-bifrost-analysis` keeps the shim: the `PhpAnalyzer` struct with its
//! one moka cache, one `OnceLock` and the `Arc<PhpComposerAutoload>` it rebuilds
//! when `composer.json` changes, the accessors that satisfy those two core
//! traits, the `PhpAdapter` forwarding shell, the SPI block, and the downcasts
//! that produce the arguments.

pub mod adapter;
pub mod aliases;
pub mod clones;
pub mod composer;
pub mod declarations;
pub mod graph_support;
pub mod structural;
pub mod test_detection;
