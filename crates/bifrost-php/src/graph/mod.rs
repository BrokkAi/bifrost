//! PHP's usage-graph scans: the forward per-target scan
//! ([`extractor`]/[`hits`]) and the whole-workspace inverted per-file walk
//! ([`inverted`]), both resolving references through [`resolver`] and the
//! shared PHP syntax helpers in [`syntax`].
//!
//! No analyzer handle appears here. `brokk-bifrost-analysis` downcasts once and
//! hands over a [`PhpGraphSource`] plus the
//! [`PhpSource`](crate::graph_support::PhpSource) the memoized
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
/// [`PhpSource`](crate::graph_support::PhpSource) that answers
/// the PHP-only questions.
#[derive(Clone, Copy)]
pub struct PhpGraphSource<'a> {
    pub index: &'a dyn CodeUnitIndex,
    pub facts: &'a dyn PhpCallableFacts,
}

/// The two declared-return-type answers PHP reads from request-local callable
/// facts. The crate line is drawn at the answers: a scan asks about one reached
/// declaration or callable name and never owns analyzer storage.
pub trait PhpCallableFacts: Send + Sync {
    /// Resolve one declaration's return type.
    fn declaration_return_type_fqn(&self, unit: &CodeUnit) -> Option<String>;

    /// Resolve one callable name's unambiguous return type.
    fn callable_return_type_fqn(&self, callable_fqn: &str) -> Option<String>;
}
