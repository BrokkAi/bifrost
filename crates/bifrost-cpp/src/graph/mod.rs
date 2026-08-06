//! The C++ usage graph's language knowledge.
//!
//! The forward scan ([`extractor`] plus [`hits`]), the visibility/macro/include
//! resolver ([`resolver`]) and the whole-workspace inverted per-file walk
//! ([`inverted`]) are one body of code and crossed together: `extractor` glob
//! imports `resolver`, `hits` reads `extractor`'s scan context, and `inverted`
//! names forty items from the other two.
//!
//! No analyzer handle appears here. `brokk-bifrost-analysis` downcasts once and
//! hands over a [`CppGraphSource`] -- the *dispatching* analyzer's side of a
//! scan -- which carries the [`CppAnalysisSource`] the memoized C++ products
//! come from.

pub mod extractor;
pub mod hits;
pub mod inverted;
pub mod resolver;
pub mod syntax;

use crate::graph_support::CppAnalysisSource;
use brokk_bifrost_core::analyzer::capabilities::{TypeAliasProvider, TypeHierarchyProvider};
use brokk_bifrost_core::analyzer::model::SignatureMetadata;
use brokk_bifrost_core::analyzer::{CodeUnit, CodeUnitIndex, ProjectFile, Range};
use std::collections::BTreeSet;

/// The workspace-wide questions a C++ scan asks of the *dispatching* analyzer
/// rather than of the C++ analyzer.
///
/// Two of them have no core capability to sit on: `import_statements` is
/// `IAnalyzer`'s raw `#include` lines, and the workspace definition index is
/// reached through an analysis-side `DefinitionIndexHandle` that is built per
/// call and so cannot be borrowed as a `&dyn BoundedDefinitionLookup`. Both
/// stay the dispatching analyzer's job -- in a mixed workspace the query is
/// issued against a `MultiAnalyzer` whose shards span languages, and the C++
/// owner resolution depends on that reach.
pub trait CppWorkspaceSource {
    /// The raw import (`#include`) lines recorded for `file`.
    fn import_statements(&self, file: &ProjectFile) -> Vec<String>;

    /// Declarations in the workspace usage-definition index whose fq name is
    /// exactly `fqn`, across every shard.
    fn definitions_by_fqn(&self, fqn: &str) -> Vec<CodeUnit>;

    /// The same lookup as [`Self::definitions_by_fqn`], but yielding borrows of
    /// the shard-owned units rather than clones. The global-field linkage walk
    /// returns its peers to a caller that outlives the lookup, which is why the
    /// index is read shard-by-shard there.
    fn definition_peers_by_fqn(&self, fqn: &str) -> Vec<&CodeUnit>;
}

/// The workspace definition index, spelled so a call reads exactly as it did
/// against `IAnalyzer::global_usage_definition_index`.
#[derive(Clone, Copy)]
pub struct CppWorkspaceDefinitions<'a>(&'a dyn CppWorkspaceSource);

impl<'a> CppWorkspaceDefinitions<'a> {
    pub fn fqn(&self, fqn: &str) -> Vec<CodeUnit> {
        self.0.definitions_by_fqn(fqn)
    }

    pub fn peers(&self, fqn: &str) -> Vec<&'a CodeUnit> {
        self.0.definition_peers_by_fqn(fqn)
    }
}

/// The *dispatching* analyzer's side of a C++ usage-graph scan.
///
/// Deliberately not the C++ analyzer, for the reason recorded on
/// `PythonGraphSource` and `CSharpGraphSource`: in a mixed workspace the query
/// is issued against a `MultiAnalyzer`, whose `definitions` merges every
/// language's shards and whose provider accessors cross language boundaries.
/// The C++ analyzer that answers the C++-only questions rides along in
/// [`Self::cpp`], resolved once by the shim's `resolve_analyzer::<CppAnalyzer>`
/// downcast instead of once per call site as before the move; `None` is the
/// same answer that downcast's `else` arm gave.
#[derive(Clone, Copy)]
pub struct CppGraphSource<'a> {
    pub index: &'a dyn CodeUnitIndex,
    pub cpp: Option<&'a dyn CppAnalysisSource>,
    pub aliases: Option<&'a dyn TypeAliasProvider>,
    pub hierarchy: Option<&'a dyn TypeHierarchyProvider>,
    pub workspace: &'a dyn CppWorkspaceSource,
}

impl<'a> CppGraphSource<'a> {
    /// The C++ source standing in for the dispatching analyzer.
    ///
    /// For the four resolution paths that only ever had the concrete C++
    /// analyzer in hand: they passed `&CppAnalyzer` where a `&dyn IAnalyzer`
    /// was wanted, and its `type_alias_provider()`/`type_hierarchy_provider()`
    /// both answered `Some(self)`, so every field is the same object here too.
    pub fn from_source(source: &'a dyn CppAnalysisSource) -> Self {
        Self {
            index: source,
            cpp: Some(source),
            aliases: Some(source),
            hierarchy: Some(source),
            workspace: source,
        }
    }

    pub fn type_alias_provider(&self) -> Option<&'a dyn TypeAliasProvider> {
        self.aliases
    }

    pub fn type_hierarchy_provider(&self) -> Option<&'a dyn TypeHierarchyProvider> {
        self.hierarchy
    }

    pub fn import_statements(&self, file: &ProjectFile) -> Vec<String> {
        self.workspace.import_statements(file)
    }

    pub fn global_usage_definition_index(&self) -> CppWorkspaceDefinitions<'a> {
        CppWorkspaceDefinitions(self.workspace)
    }

    pub fn parent_of(&self, code_unit: &CodeUnit) -> Option<CodeUnit> {
        self.index.parent_of(code_unit)
    }

    pub fn ranges(&self, code_unit: &CodeUnit) -> Vec<Range> {
        self.index.ranges(code_unit)
    }

    pub fn enclosing_code_unit(&self, file: &ProjectFile, range: &Range) -> Option<CodeUnit> {
        self.index.enclosing_code_unit(file, range)
    }

    pub fn signature_metadata(&self, code_unit: &CodeUnit) -> Vec<SignatureMetadata> {
        self.index.signature_metadata(code_unit)
    }

    pub fn signatures(&self, code_unit: &CodeUnit) -> Vec<String> {
        self.index.signatures(code_unit)
    }

    pub fn get_source(&self, code_unit: &CodeUnit, include_comments: bool) -> Option<String> {
        self.index.get_source(code_unit, include_comments)
    }

    pub fn indexed_source(&self, file: &ProjectFile) -> Option<String> {
        self.index.indexed_source(file)
    }

    pub fn declarations(&self, file: &ProjectFile) -> BTreeSet<CodeUnit> {
        self.index.declarations(file)
    }

    pub fn direct_children(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        self.index.direct_children(code_unit)
    }

    pub fn definitions(&self, fq_name: &str) -> Box<dyn Iterator<Item = CodeUnit> + '_> {
        self.index.definitions(fq_name)
    }
}

/// [`crate::identity::cpp_callable_definitions_share_identity_evidence`] with
/// its header/implementation evidence root supplied from the graph source.
///
/// The searchtools consumers reach the same predicate through the shim wrapper
/// that owns the `resolve_analyzer` downcast; the scan already holds the
/// resolved C++ source, so it passes the include index in directly. A source
/// without a C++ analyzer answers `false`, exactly as the downcast's `else` arm
/// did.
pub fn callable_definitions_share_identity_evidence(
    analyzer: &CppGraphSource<'_>,
    left: &CodeUnit,
    right: &CodeUnit,
) -> bool {
    crate::identity::cpp_callable_definitions_share_identity_evidence(
        analyzer.index,
        left,
        right,
        |left_source, right_source| {
            let Some(implementation) =
                crate::identity::cpp_header_body_implementation_file(left_source, right_source)
            else {
                return false;
            };
            let Some(cpp) = analyzer.cpp else {
                return false;
            };
            crate::identity::cpp_header_body_files_are_related(
                left_source,
                right_source,
                &analyzer.import_statements(implementation),
                cpp.include_target_index(),
            )
        },
    )
}
