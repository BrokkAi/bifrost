//! PHP's usage-graph scans: the forward per-target scan
//! ([`extractor`]/[`hits`]) and the whole-workspace inverted per-file walk
//! ([`inverted`]), both resolving references through [`resolver`] and the
//! shared PHP syntax helpers in [`syntax`].
//!
//! No analyzer handle appears here. `brokk-bifrost-analysis` downcasts once and
//! hands over a [`PhpGraphSource`] plus the
//! [`PhpAnalysisSource`](crate::graph_support::PhpAnalysisSource) the memoized
//! PHP products come from.

pub mod extractor;
pub mod hits;
pub mod inverted;
pub mod resolver;
pub mod syntax;

use brokk_bifrost_core::analyzer::{CodeUnit, CodeUnitIndex};

/// The *dispatching* analyzer's side of a PHP usage-graph scan.
///
/// Deliberately not the PHP analyzer: in a mixed workspace the query is issued
/// against a `MultiAnalyzer`, whose `definitions` merges every language's shards
/// and whose enclosing-unit lookup crosses language boundaries. The walks depend
/// on that reach, so this stays separate from the
/// [`PhpAnalysisSource`](crate::graph_support::PhpAnalysisSource) that answers
/// the PHP-only questions.
#[derive(Clone, Copy)]
pub struct PhpGraphSource<'a> {
    pub index: &'a dyn CodeUnitIndex,
    pub facts: &'a dyn PhpCallableFacts,
}

/// The two declared-return-type answers PHP reads out of the analyzer's
/// usage-facts index.
///
/// `UsageFactsIndex` is analysis-owned and its entries are `pub(crate)` there, so
/// the crate line is drawn at the answers rather than the index: a scan asks for
/// a declaration's or an fqn's return type and never sees the facts themselves.
pub trait PhpCallableFacts: Send + Sync {
    /// `usage_facts_index().fact_for_declaration(unit)`'s `return_type_fqn`.
    fn declaration_return_type_fqn(&self, unit: &CodeUnit) -> Option<String>;

    /// `usage_facts_index().callable_return_type(callable_fqn)`.
    fn callable_return_type_fqn(&self, callable_fqn: &str) -> Option<String>;
}
