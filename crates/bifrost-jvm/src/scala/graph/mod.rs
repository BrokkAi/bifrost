//! Scala's usage-graph language knowledge.
//!
//! The framework half of the graph -- the `UsageAnalyzer` strategy, the edge
//! resolvers and the whole-workspace walk's analyzer handle -- stays in
//! `brokk-bifrost-analysis`; the node predicates, the lexical type-namespace
//! walk and the local-binding seeds are pure and live here.

pub mod local;
pub mod namespace;
pub mod syntax;
