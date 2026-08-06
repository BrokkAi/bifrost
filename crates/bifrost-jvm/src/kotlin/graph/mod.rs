//! Kotlin's usage-graph scans: the per-symbol forward scan
//! ([`extractor`]/[`hits`]) and the whole-workspace inverted per-file walk
//! ([`inverted`]), both typing receivers through [`resolver`] -- the shared
//! Kotlin resolution library both usage paths read.
//!
//! No analyzer handle appears here. `brokk-bifrost-analysis` downcasts once and
//! hands over a [`KotlinGraphSource`].

pub mod extractor;
pub mod hits;
pub mod inverted;
pub mod resolver;

use brokk_bifrost_core::analyzer::capabilities::{
    ImportAnalysisProvider, TypeAliasProvider, TypeHierarchyProvider,
};
use brokk_bifrost_core::analyzer::{BoundedDefinitionLookup, CodeUnitIndex};

/// The *dispatching* analyzer's side of a Kotlin usage-graph scan.
///
/// Deliberately not the Kotlin analyzer, for the reason recorded on
/// `JavaGraphSource`: in a mixed workspace the query is issued against a
/// `MultiAnalyzer`, whose definition index merges every language's shards and
/// whose hierarchy answers cross language boundaries. Kotlin depends on that
/// reach as much as Java does -- the JVM realm is one candidate space (#1237),
/// so a Kotlin file naming a Java or Scala class next door resolves only
/// through the merged index.
#[derive(Clone, Copy)]
pub struct KotlinGraphSource<'a> {
    pub index: &'a dyn CodeUnitIndex,
    pub hierarchy: Option<&'a dyn TypeHierarchyProvider>,
    pub type_alias: Option<&'a dyn TypeAliasProvider>,
    pub imports: Option<&'a dyn ImportAnalysisProvider>,
    pub definitions: &'a DefinitionLookupAccess<'a>,
}

/// See [`KotlinGraphSource::definitions`]: called with a consumer that reads the
/// analyzer's global definition index, so the index -- a handle that borrows the
/// analyzer and merges one shard per delegate -- is only materialized when a
/// consumer actually runs.
pub type DefinitionLookupAccess<'a> =
    dyn Fn(&mut dyn FnMut(&dyn BoundedDefinitionLookup)) + Sync + 'a;

impl KotlinGraphSource<'_> {
    /// Run `read` against the dispatching analyzer's definition index.
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
