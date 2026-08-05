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
use brokk_bifrost_core::analyzer::{BoundedDefinitionLookup, CodeUnitIndex};

/// The *dispatching* analyzer's side of a Python usage-graph scan.
///
/// Deliberately not the Python analyzer: in a mixed workspace the query is
/// issued against a `MultiAnalyzer`, whose `definitions` merges every language's
/// shards and whose `get_ancestors` crosses language boundaries. The walks
/// depend on that reach, so this stays separate from the
/// [`PythonUsageSource`](crate::graph_support::PythonUsageSource) that answers
/// the Python-only questions.
///
/// `definitions` is a callback rather than a handle because the analyzer's
/// global definition index is built lazily on first access and only
/// [`resolver::resolve_receiver_type`]'s last fallback reaches it; returning a
/// handle would force the build at every scan.
#[derive(Clone, Copy)]
pub struct PythonGraphSource<'a> {
    pub index: &'a dyn CodeUnitIndex,
    pub hierarchy: Option<&'a dyn TypeHierarchyProvider>,
    pub imports: Option<&'a dyn ImportAnalysisProvider>,
    pub definitions: &'a DefinitionLookupAccess<'a>,
}

/// See [`PythonGraphSource::definitions`]: called with a consumer that reads the
/// analyzer's global definition index, so the index is only resolved when a
/// consumer actually runs.
pub type DefinitionLookupAccess<'a> =
    dyn Fn(&mut dyn FnMut(&dyn BoundedDefinitionLookup)) + Sync + 'a;
