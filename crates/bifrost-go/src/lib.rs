//! Go language knowledge for Bifrost.
//!
//! Internal implementation detail of `brokk-bifrost`; no stability guarantees --
//! depend on `brokk-bifrost` instead.
//!
//! This crate sits between [`brokk_bifrost_core`] and `brokk-bifrost-analysis`.
//! It holds Go *language knowledge* -- package identity, declaration and type
//! shapes, test detection, the structural spec, the type hierarchy, and the
//! usage-graph resolution index -- as plain functions and data. It depends on
//! no other Bifrost crate than core, so nothing here may name `IAnalyzer`,
//! `TreeSitterAnalyzer`, or `GoAnalyzer`.
//!
//! Where analysis code would reach for an analyzer handle, the functions here
//! take [`brokk_bifrost_core::analyzer::CodeUnitIndex`] (plus whichever core
//! capability trait the operation actually needs) and explicit Go side data --
//! a [`packages::GoWorkspacePathIndex`], a prepared file list, a package-clause
//! map. `analyzer/go/` in `brokk-bifrost-analysis` keeps the shim: the
//! `GoAnalyzer` newtype, the `GoAdapter` forwarding shell, the SPI block, and
//! the downcasts that produce those arguments.

pub mod adapter;
pub mod declarations;
pub mod packages;
pub mod queries;
pub mod structural;
pub mod test_detection;
