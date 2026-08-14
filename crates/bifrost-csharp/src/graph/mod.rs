//! C#'s usage-graph scans: the per-symbol forward scan
//! ([`extractor`]/[`hits`]) and the whole-workspace inverted per-file walk
//! ([`inverted`]), both resolving references through [`resolver`] -- the shared
//! C# resolution library the definition route also reads.
//!
//! No analyzer handle appears here. `brokk-bifrost-analysis` downcasts once and
//! hands over a [`CSharpGraphSource`] plus the
//! [`CSharpSource`](crate::graph_support::CSharpSource) the
//! memoized C# products come from.

pub mod extractor;
pub mod hits;
pub mod inverted;
pub mod resolver;

use crate::graph_support::CSharpSource;
use brokk_bifrost_core::analyzer::CodeUnitIndex;
use brokk_bifrost_core::analyzer::capabilities::TypeHierarchyProvider;

/// The *dispatching* analyzer's side of a C# usage-graph scan.
///
/// Deliberately not the C# analyzer, for the reason recorded on
/// `PythonGraphSource`: in a mixed workspace the query is issued against a
/// `MultiAnalyzer`, whose `definitions` merges every language's shards and whose
/// `get_ancestors` crosses language boundaries. The walks depend on that reach,
/// so this stays separate from the
/// [`CSharpSource`](crate::graph_support::CSharpSource) that
/// answers the C#-only questions.
///
/// Two fields rather than Python's four: the C# scans read the dispatching
/// analyzer only through `CodeUnitIndex` (`parent_of`, `ranges`,
/// `signature_metadata`, `enclosing_code_unit`, and `csharp_callable_arity`
/// beneath them) and, on the unbounded receiver-compatibility walk, through
/// `TypeHierarchyProvider`. C# reaches the workspace definition index through
/// `CSharpSource::usage_definitions` -- as it did before the move -- so
/// there is no lazy definitions callback here and no import provider.
#[derive(Clone, Copy)]
pub struct CSharpGraphSource<'a> {
    pub index: &'a dyn CodeUnitIndex,
    pub hierarchy: Option<&'a dyn TypeHierarchyProvider>,
}

impl<'a> CSharpGraphSource<'a> {
    /// The C# source standing in for the dispatching analyzer.
    ///
    /// For the resolution paths that only ever had the concrete C# analyzer in
    /// hand: they passed `&CSharpAnalyzer` where a `&dyn IAnalyzer` was wanted,
    /// and its `type_hierarchy_provider()` answered `Some(self)`, so both
    /// fields are the same object here too.
    pub fn from_source(source: &'a dyn CSharpSource) -> Self {
        Self {
            index: source,
            hierarchy: Some(source),
        }
    }
}
