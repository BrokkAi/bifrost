//! Ruby's usage-graph scans: the per-symbol forward scan
//! ([`extractor`]/[`hits`]) and the whole-workspace inverted per-file walk
//! ([`inverted`]), both resolving references through [`resolver`] -- the shared
//! Ruby resolution library the definition route also reads.
//!
//! No analyzer handle appears here. `brokk-bifrost-analysis` downcasts once and
//! hands over a [`RubyGraphSource`] plus the
//! [`RubySource`](crate::graph_support::RubySource) the memoized Ruby products
//! come from.

pub mod extractor;
pub mod hits;
pub mod inverted;
pub mod resolver;
pub mod syntax;

use brokk_bifrost_core::analyzer::query_token::QueryToken;
use brokk_bifrost_core::analyzer::{
    BoundedDefinitionLookup, CodeUnitIndex, DefinitionLookupAccess,
};

/// The *dispatching* analyzer's side of a Ruby usage-graph scan.
///
/// Deliberately not the Ruby analyzer, for the reason recorded on
/// `PythonGraphSource`: in a mixed workspace the query is issued against a
/// `MultiAnalyzer`, whose `definitions` can query every language's store and whose
/// enclosing-unit lookup crosses language boundaries. The walks depend on that
/// reach, so this stays separate from the
/// [`RubySource`](crate::graph_support::RubySource) that answers the Ruby-only
/// questions.
///
/// `definitions` is a callback rather than a handle because the analyzer's
/// global definition index is built lazily on first access and only the
/// factory-return inference in [`extractor`] reaches it; the diagnostics pass
/// builds a [`resolver::RubySemanticIndex`] and never touches it at all, so
/// returning a handle would force the build there too.
#[derive(Clone, Copy)]
pub struct RubyGraphSource<'a> {
    /// Proof that a request scope is open: the import accessors reached from
    /// this source cross the import tier's storage (issue #2423).
    pub token: QueryToken<'a>,
    pub index: &'a dyn CodeUnitIndex,
    pub definitions: &'a DefinitionLookupAccess<'a>,
}

impl RubyGraphSource<'_> {
    pub fn with_definitions<R>(&self, read: impl FnOnce(&dyn BoundedDefinitionLookup) -> R) -> R {
        let mut read = Some(read);
        let mut resolved = None;
        (self.definitions)(&mut |lookup| {
            if let Some(read) = read.take() {
                resolved = Some(read(lookup));
            }
        });
        resolved.expect("definition lookup access must invoke its consumer exactly once")
    }
}
