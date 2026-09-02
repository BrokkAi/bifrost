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
//! scan -- which carries the [`CppSource`] the memoized C++ products
//! come from.

pub mod extractor;
pub mod hits;
pub mod inverted;
pub mod resolver;
pub mod syntax;

use crate::graph_support::CppSource;
use brokk_bifrost_core::analyzer::capabilities::{TypeAliasProvider, TypeHierarchyProvider};
use brokk_bifrost_core::analyzer::fq_name::FqName;
use brokk_bifrost_core::analyzer::model::{CppFieldLinkage, SignatureMetadata};
use brokk_bifrost_core::analyzer::query_token::QueryToken;
use brokk_bifrost_core::analyzer::{CodeUnit, CodeUnitIndex, ProjectFile, Range};
use std::collections::BTreeSet;

/// The workspace-wide questions a C++ scan asks of the *dispatching* analyzer
/// rather than of the C++ analyzer.
///
/// `import_statements` is `IAnalyzer`'s raw `#include` lines. Definition reads
/// also stay the dispatching analyzer's job: the language crate can issue the
/// core relational request but cannot own SQLite, and a mixed workspace must
/// coordinate its language-local snapshots through `MultiAnalyzer`.
pub trait CppWorkspaceSource {
    /// The raw import (`#include`) lines recorded for `file`.
    fn import_statements(&self, file: &ProjectFile) -> Vec<String>;

    /// Exact lookup for a name already carried as extractor-owned segments.
    /// Results are owned because the relational store, not a generation-wide
    /// Rust map, owns the rows.
    fn definitions_by_name(&self, token: QueryToken<'_>, name: &FqName) -> Vec<CodeUnit>;

    /// Identifier-bounded candidates for a structurally segmented source path
    /// whose intermediate kinds are not known until resolution.
    fn definitions_by_identifier(&self, token: QueryToken<'_>, name: &FqName) -> Vec<CodeUnit>;
}

/// The workspace definition query surface, spelled so the C++ resolver does
/// not depend on the analysis crate's store implementation.
///
/// Carries the request scope's [`QueryToken`] alongside the source, so a
/// lookup made through it is proof-carrying without every C++ call site
/// re-threading the token (issue #2423 milestone B).
#[derive(Clone, Copy)]
pub struct CppWorkspaceDefinitions<'a>(&'a dyn CppWorkspaceSource, QueryToken<'a>);

impl<'a> CppWorkspaceDefinitions<'a> {
    pub fn exact(&self, name: &FqName) -> Vec<CodeUnit> {
        self.0.definitions_by_name(self.1, name)
    }

    pub fn identifier(&self, name: &FqName) -> Vec<CodeUnit> {
        self.0.definitions_by_identifier(self.1, name)
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
    pub cpp: Option<&'a dyn CppSource>,
    pub aliases: Option<&'a dyn TypeAliasProvider>,
    pub hierarchy: Option<&'a dyn TypeHierarchyProvider>,
    pub workspace: &'a dyn CppWorkspaceSource,
    /// Proof that the request scope this bundle serves is open. The bundle is
    /// a per-query object built at a query boundary, so the syntax accessors
    /// its resolution paths reach can take the proof from here rather than
    /// from ninety extra parameters (issue #2414 step 3).
    pub token: QueryToken<'a>,
}

impl<'a> CppGraphSource<'a> {
    /// The C++ source standing in for the dispatching analyzer.
    ///
    /// For the four resolution paths that only ever had the concrete C++
    /// analyzer in hand: they passed `&CppAnalyzer` where a `&dyn IAnalyzer`
    /// was wanted, and its `type_alias_provider()`/`type_hierarchy_provider()`
    /// both answered `Some(self)`, so every field is the same object here too.
    pub fn from_source(source: &'a dyn CppSource, token: QueryToken<'a>) -> Self {
        Self {
            index: source,
            cpp: Some(source),
            aliases: Some(source),
            hierarchy: Some(source),
            workspace: source,
            token,
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

    pub fn workspace_definitions(&self) -> CppWorkspaceDefinitions<'a> {
        CppWorkspaceDefinitions(self.workspace, self.token)
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

    pub fn cpp_field_linkage(&self, code_unit: &CodeUnit) -> Option<CppFieldLinkage> {
        self.cpp?.cpp_field_linkage(code_unit)
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

    /// Whether a reference written in `file` reads C++ source with C semantics
    /// (issue #1970). Without a C++ analyzer behind this source only the path
    /// evidence is available, which is exactly what
    /// [`resolver::is_c_source_file`] answered before headers gained a second
    /// reading.
    pub fn reference_uses_c_semantics(&self, file: &ProjectFile) -> bool {
        match self.cpp {
            Some(cpp) => resolver::reference_uses_c_semantics(cpp, file),
            None => resolver::is_c_source_file(file),
        }
    }

    /// [`crate::graph_support::CppSource::declarations_in_reading`], falling
    /// back to the single reading a bare index can serve.
    pub fn declarations_in_reading(
        &self,
        file: &ProjectFile,
        c_semantics: bool,
    ) -> BTreeSet<CodeUnit> {
        match self.cpp {
            Some(cpp) if c_semantics => cpp.declarations_in_reading(file, true),
            _ => self.index.declarations(file),
        }
    }

    /// [`crate::graph_support::CppSource::site_equivalent_units`], empty
    /// without a C++ analyzer.
    pub fn site_equivalent_units(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        match self.cpp {
            Some(cpp) => cpp.site_equivalent_units(code_unit),
            None => Vec::new(),
        }
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
            let Some(cpp) = analyzer.cpp else {
                return false;
            };
            crate::identity::cpp_header_body_files_are_related(
                cpp,
                analyzer.token,
                left_source,
                right_source,
            )
        },
    )
}

/// The structured-parameter variant of
/// [`callable_definitions_share_identity_evidence`].
///
/// Use this when the two declarations may differ in non-identity parameter
/// syntax, such as a default argument written only on the header prototype.
pub fn callable_definitions_share_identity_evidence_with_visibility(
    analyzer: &CppGraphSource<'_>,
    visibility: &resolver::VisibilityIndex<'_>,
    left: &CodeUnit,
    right: &CodeUnit,
) -> bool {
    crate::identity::cpp_callable_definitions_share_identity_evidence_with_visibility(
        analyzer,
        visibility,
        left,
        right,
        |left_source, right_source| {
            let Some(cpp) = analyzer.cpp else {
                return false;
            };
            crate::identity::cpp_header_body_files_are_related(
                cpp,
                analyzer.token,
                left_source,
                right_source,
            )
        },
    )
}
