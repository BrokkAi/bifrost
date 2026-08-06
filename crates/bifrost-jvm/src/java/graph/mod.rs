//! Java's usage-graph scans: the per-symbol forward scan
//! ([`extractor`]/[`hits`]) and the whole-workspace inverted per-file walk
//! ([`inverted`]), both resolving references through [`resolver`] and
//! [`return_type`] -- the shared Java resolution library the definition route
//! also reads.
//!
//! No analyzer handle appears here. `brokk-bifrost-analysis` downcasts once and
//! hands over a [`JavaGraphSource`] plus the
//! [`JavaSource`](crate::java::graph_support::JavaSource) the memoized Java
//! products come from.

pub mod extractor;
pub mod hits;
pub mod inverted;
pub mod jvm_scala;
pub mod resolver;
pub mod return_type;

use brokk_bifrost_core::analyzer::capabilities::TypeHierarchyProvider;
use brokk_bifrost_core::analyzer::{BoundedDefinitionLookup, CodeUnitIndex, ProjectFile};

/// The *dispatching* analyzer's side of a Java usage-graph scan.
///
/// Deliberately not the Java analyzer, for the reason recorded on
/// `PythonGraphSource`: in a mixed workspace the query is issued against a
/// `MultiAnalyzer`, whose `definitions` merges every language's shards and whose
/// `get_ancestors` crosses language boundaries. Java depends on that reach
/// twice over -- the JVM realm is one candidate space (#1237), so a Java file
/// naming a Kotlin or Scala class next door resolves only through the merged
/// index -- so this stays separate from the
/// [`JavaSource`](crate::java::graph_support::JavaSource) that answers the
/// Java-only questions.
#[derive(Clone, Copy)]
pub struct JavaGraphSource<'a> {
    pub index: &'a dyn CodeUnitIndex,
    pub hierarchy: Option<&'a dyn TypeHierarchyProvider>,
    pub definitions: &'a DefinitionLookupAccess<'a>,
    pub import_statements: &'a ImportStatementAccess<'a>,
}

/// See [`JavaGraphSource::definitions`]: called with a consumer that reads the
/// analyzer's global definition index, so the index -- a handle that borrows the
/// analyzer and merges one shard per delegate -- is only materialized when a
/// consumer actually runs.
pub type DefinitionLookupAccess<'a> =
    dyn Fn(&mut dyn FnMut(&dyn BoundedDefinitionLookup)) + Sync + 'a;

/// See [`JavaGraphSource::import_statements`]: the raw `import` statement text
/// of a file, which `IAnalyzer` answers from persisted per-file state rather
/// than from the structured import facts.
pub type ImportStatementAccess<'a> = dyn Fn(&ProjectFile) -> Vec<String> + Sync + 'a;

impl JavaGraphSource<'_> {
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
