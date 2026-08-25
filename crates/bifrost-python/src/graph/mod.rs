//! Python's usage-graph scans: the forward per-target scan
//! ([`extractor`]/[`hits`]) and the whole-workspace inverted per-file walk
//! ([`inverted`]), both resolving references through [`resolver`].
//!
//! No analyzer handle appears here. `brokk-bifrost-analysis` downcasts once and
//! hands over a [`PythonGraphSource`] plus the
//! [`PythonUsageSource`](crate::graph_support::PythonUsageSource) the memoized
//! Python products come from.

pub mod extractor;
pub mod hits;
pub mod inverted;
pub mod resolver;

use brokk_bifrost_core::analyzer::capabilities::{ImportAnalysisProvider, TypeHierarchyProvider};
use brokk_bifrost_core::analyzer::query_token::QueryToken;
use brokk_bifrost_core::analyzer::{CodeUnitIndex, RelationalDefinitionFrontier};

/// The *dispatching* analyzer's side of a Python usage-graph scan.
///
/// Deliberately not the Python analyzer: in a mixed workspace the query is
/// issued against a `MultiAnalyzer`, whose `definitions` merges every language's
/// shards and whose `get_ancestors` crosses language boundaries. The walks
/// depend on that reach, so this stays separate from the
/// [`PythonUsageSource`](crate::graph_support::PythonUsageSource) that answers
/// the Python-only questions.
///
#[derive(Clone, Copy)]
pub struct PythonGraphSource<'a> {
    pub index: &'a dyn CodeUnitIndex,
    pub hierarchy: Option<&'a dyn TypeHierarchyProvider>,
    pub imports: Option<&'a dyn ImportAnalysisProvider>,
    /// Request-local relational answers. Missing questions record themselves
    /// in the owning replay frontier and return the query shape's empty value.
    pub definitions: &'a dyn RelationalDefinitionFrontier,
    /// Proof that the request scope this per-query bundle serves is open
    /// (issue #2414 step 3).
    pub token: QueryToken<'a>,
}
