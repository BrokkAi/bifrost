//! Scala's usage-graph language knowledge.
//!
//! The framework half of the graph -- the `UsageAnalyzer` and
//! `UsageQueryResolver` strategy shells, the edge resolvers, the parallel
//! fan-out and the downcasts that produce the arguments -- stays in
//! `brokk-bifrost-analysis`. What lives here is the resolution itself: the node
//! predicates, the lexical type-namespace walk, the local-binding seeds, the
//! project type index [`inverted::ProjectTypes`] the per-file scans resolve
//! through, the per-file scans, and the target-shape analysis in
//! [`resolver`] that says which declarations a find-references query is really
//! asking about.

pub mod inverted;
pub mod local;
pub mod namespace;
pub mod query;
pub mod resolver;
pub mod syntax;
