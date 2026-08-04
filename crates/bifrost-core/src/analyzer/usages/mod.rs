//! The language-blind half of the usages framework.
//!
//! These are the products of usage analysis -- hits, references, import and
//! export bindings, receiver candidates, reference sites -- plus the pure
//! resolution helpers that operate on them. Nothing here needs an `IAnalyzer`,
//! a store, or a parsed-file cache, so a language crate can produce these types
//! without depending on `brokk-bifrost-analysis`.
//!
//! The drivers that do need an analyzer handle (the finder, the candidate
//! providers, the per-language graph strategies, the inverted-edge collector)
//! stay in `brokk-bifrost-analysis`, which re-exports every module here at its
//! historical path.

pub mod graph_core;
pub mod inverted_edges;
pub mod local_inference;
pub mod model;
pub mod outcome;
pub mod receiver_analysis;
pub mod reexport_seeds;
pub mod reference_site;
pub mod scan_scope;

pub use graph_core::{ImportEdge, ImportEdgeKind};
