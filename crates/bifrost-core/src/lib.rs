//! Foundation types and utilities shared by every Bifrost crate.
//!
//! Internal implementation detail of `brokk-bifrost`; no stability guarantees --
//! depend on `brokk-bifrost` instead.
//!
//! This is the bottom of the workspace dependency graph: nothing here depends
//! on another Bifrost crate. It holds the analyzer's data model (`CodeUnit`,
//! `Language`, `ProjectFile`, `FqName`, the structural kind/role vocabulary and
//! the language-spec trait), the project/workspace file abstraction, and the
//! process-wide utilities every layer above needs (hashing, path
//! normalization, cancellation, the unified cache DB and its GC, git blob
//! identity, schema versioning).
//!
//! What is deliberately *not* here: anything that needs a grammar, an analyzer
//! handle, or a store. `IAnalyzer` and everything reachable from it stay in
//! `brokk-bifrost-analysis`, which re-exports every item below at its historical
//! path.

pub mod analyzer;
pub mod cache_db;
pub mod cache_gc;
pub mod cancellation;
pub mod compact_graph;
pub mod git_file;
pub mod gitblob;
pub mod hash;
pub mod path_normalization;
pub mod path_utils;
pub mod profiling;
pub mod schema_version;
pub mod text_utils;
pub mod util;

pub use cancellation::CancellationToken;
