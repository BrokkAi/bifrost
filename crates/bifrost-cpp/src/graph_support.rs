//! The analyzer-resident products C++'s language logic resolves through.
//!
//! `CppAnalyzer` owns five moka caches, three `Arc<OnceLock<..>>` cells and one
//! `PoolSafeMemo`; every one of them stays in `brokk-bifrost-analysis` because
//! `IAnalyzer::update`/`update_all` rebuild the analyzer wholesale through
//! `Self::from_inner`. What crosses the crate line is the *decision* that fills
//! each cell -- the builders in [`crate::hierarchy`], [`crate::identity`] and
//! [`crate::imports`] -- plus this trait, which is how a free function reaches
//! back for a memoized product without naming the analyzer type.
//!
//! The census found no re-entrancy among these accessors, so this is a single
//! tier rather than the two-tier split some fleet languages needed: the #1134
//! reconciliation reads `visible_type_units`, which reads `include_target_index`
//! and the supertrait's `import_statements`, and none of those reads back into
//! reconciliation.
//!
//! Three members are load-bearing beyond their signature:
//!
//! * [`CppSource::visible_type_units`] is the moka-cached include-closure
//!   class table. Its *builder* is [`crate::hierarchy::build_cpp_visible_type_units`];
//!   the cell and its `test-support` build counter stay analyzer-side, so this
//!   accessor is the only way the reconciler reaches a warm table.
//! * [`CppSource::raw_supertypes_of`] is
//!   `TreeSitterAnalyzer::raw_supertypes_of`, whose rows are crate-private to
//!   analysis; the analyzer hands the decoded base-specifier strings across.

use crate::compile_context::CppCompileContext;
use crate::graph::CppWorkspaceSource;
use crate::graph::resolver::SourceUsingIndex;
use crate::imports::IncludeTargetIndex;
use brokk_bifrost_core::analyzer::capabilities::{TypeAliasProvider, TypeHierarchyProvider};
use brokk_bifrost_core::analyzer::model::{CppFieldLinkage, CppTemplateMetadata};
use brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxTree;
use brokk_bifrost_core::analyzer::{CodeUnit, CodeUnitIndex, ProjectFile};
use std::collections::BTreeSet;
use std::sync::Arc;

pub trait CppSource:
    CodeUnitIndex + TypeAliasProvider + TypeHierarchyProvider + CppWorkspaceSource
{
    /// The workspace-wide `#include` resolution table, built once per analyzer
    /// generation from [`IncludeTargetIndex::build`].
    fn include_target_index(&self) -> &IncludeTargetIndex;

    /// The declared base specifiers of `code_unit`, as written
    /// (`TreeSitterAnalyzer::raw_supertypes_of`).
    fn raw_supertypes_of(&self, code_unit: &CodeUnit) -> Vec<String>;

    /// Every class-like or alias declaration reachable from `file` through its
    /// `#include` closure, memoized per file. See this module's note.
    fn visible_type_units(&self, file: &ProjectFile) -> Arc<Vec<CodeUnit>>;

    /// [`Self::visible_type_units`] under a caller's deadline.
    ///
    /// `None` means the include-closure walk stopped short. Nothing is
    /// memoized in that case: a truncated class table is indistinguishable
    /// from a file that simply sees fewer types, so every later base-specifier
    /// resolution reading it would silently lose ancestors.
    ///
    /// This is the shape issue #1748 needed. The closure walk is individually
    /// cheap -- a fraction of a millisecond to about 180 ms -- but the
    /// descendant-index build above it runs one per class in the workspace,
    /// which on a large tree is tens of thousands of them inside a single
    /// request that asked for thirty seconds.
    fn visible_type_units_while(
        &self,
        file: &ProjectFile,
        keep_going: &dyn Fn() -> bool,
    ) -> Option<Arc<Vec<CodeUnit>>>;

    /// The per-file structured using index (ordinary using declarations and
    /// using-directives with their guard environments), memoized per file.
    /// Built by [`crate::graph::extractor::build_source_using_index`], which is
    /// a pure function of the file's parsed content.
    ///
    /// Memoized on the analyzer rather than on `VisibilityIndex` because a
    /// fresh visibility index is built per usage query: rebuilding the index
    /// per query re-walked a 9.5 MB amalgamation's AST once per candidate
    /// (issue #1927).
    fn source_using_index(&self, file: &ProjectFile) -> Arc<SourceUsingIndex>;

    /// The indexed source of `file` (`TreeSitterAnalyzer::file_source`).
    fn file_source(&self, file: &ProjectFile) -> Option<String>;

    /// The parsed tree and its source backing for `file`, from the analyzer's
    /// query read cache.
    ///
    /// The single hottest member of this trait: the usage graph reaches it at
    /// 27 call sites. The cache is *not* rebuilt per call -- `VisibilityIndex`
    /// borrows the analyzer rather than cloning it precisely so this stays warm
    /// across a scan (#1175), so an implementor must forward to the same
    /// analyzer the query is running against.
    fn prepared_syntax(&self, file: &ProjectFile) -> Option<Arc<PreparedSyntaxTree>>;

    /// The persisted linkage fact for one C++ field, when the parser recorded
    /// it. A missing fact requires the resolver's syntax fallback.
    fn cpp_field_linkage(&self, code_unit: &CodeUnit) -> Option<CppFieldLinkage>;

    /// The cached result of a preprocessor-visible include-reachability walk.
    ///
    /// The reference language affects only `__cplusplus` guards. Callers pass
    /// that fact as a Boolean so cache keys do not retain the full reference
    /// path.
    fn cached_unconditional_include_reachability(
        &self,
        first: &ProjectFile,
        donor_source: &ProjectFile,
        reference_is_c: bool,
    ) -> Option<bool>;

    /// Store a completed preprocessor-visible include-reachability walk.
    fn cache_unconditional_include_reachability(
        &self,
        first: &ProjectFile,
        donor_source: &ProjectFile,
        reference_is_c: bool,
        reaches: bool,
    );

    /// The declaration's syntactic owner, which unlike
    /// [`CodeUnitIndex::parent_of`] never falls back to a definition-row lookup.
    fn structural_parent_of(&self, code_unit: &CodeUnit) -> Option<CodeUnit>;

    /// The persisted C++ template metadata side table's row for `code_unit`.
    fn template_metadata(&self, code_unit: &CodeUnit) -> Option<CppTemplateMetadata>;

    /// Whether a reference written in the header `file` reads the declarations
    /// it can see with C semantics: every workspace translation unit that
    /// provably compiles this header compiles it as C (issue #1970).
    ///
    /// Always false for a translation unit -- its own extension settles its
    /// dialect, which [`crate::graph::resolver::is_c_source_file`] answers
    /// without asking the analyzer. Both halves are combined by
    /// [`crate::graph::resolver::reference_uses_c_semantics`], the one helper
    /// resolution asks.
    ///
    /// A header both languages provably include reports false: forward
    /// resolution from it reports the C++ identity, and the site-equivalence
    /// union below is what keeps inverse in agreement.
    fn header_uses_c_semantics(&self, file: &ProjectFile) -> bool;

    /// The declarations of `file` as one of its two readings sees them.
    ///
    /// `c_semantics` false is the C++ reading, which is exactly
    /// [`CodeUnitIndex::declarations`]. True is the C reading: the stored
    /// `cpp:c` row-set when the blob has one, and otherwise the same C++
    /// row-set, because "no C rows" means the two readings agree.
    ///
    /// Candidate enumeration selects a reading here and nowhere else: include
    /// activation, preprocessor-guard compatibility, block-scope shadowing and
    /// ambiguity all run unchanged over whichever set comes back.
    fn declarations_in_reading(&self, file: &ProjectFile, c_semantics: bool) -> BTreeSet<CodeUnit>;

    /// The identities of the other reading that share `code_unit`'s
    /// declaration site -- the same source file and the same declaration byte
    /// range -- empty when the two readings agree about it.
    ///
    /// Keyed on the range, never on a name. Inverse results are unioned across
    /// these so a query against either identity of one declaration reports
    /// every reference found under both readings.
    fn site_equivalent_units(&self, code_unit: &CodeUnit) -> Vec<CodeUnit>;

    /// Every distinct `compile_commands.json` configuration governing `file`,
    /// empty when the workspace has no compile database entry naming it. The
    /// only analyzer-resident product [`crate::diagnostics`] needs.
    ///
    /// A file the build compiles in several configurations yields several
    /// contexts, because their include closures can disagree about a name.
    fn compile_contexts_for(&self, file: &ProjectFile) -> &[CppCompileContext];

    /// Count a precise-parent resolution against the analyzer's counter.
    ///
    /// Called from production code in [`crate::graph::resolver`], which is why
    /// it is on the trait at all; the counter itself stays on the analyzer.
    ///
    /// The default is a no-op because the two gates are not the same gate:
    /// Cargo turns this crate's `test-support` on for the whole build graph
    /// whenever `brokk-bifrost-analysis`'s dev-dependencies are in play, while
    /// the analyzer-side counter field is `#[cfg(any(test, feature =
    /// "test-support"))]` on *that* crate. The implementor overrides this
    /// exactly when it has a counter to record into -- which is the build the
    /// tests reading the counter run in.
    #[cfg(any(test, feature = "test-support"))]
    fn record_cpp_parent_resolution_for_test(&self) {}

    /// Count a class-declaration-strength parse. See
    /// [`Self::record_cpp_parent_resolution_for_test`].
    #[cfg(any(test, feature = "test-support"))]
    fn record_cpp_class_strength_parse_for_test(&self) {}

    /// Count a guard-ancestry inspection during a per-file using-index build.
    /// See [`Self::record_cpp_parent_resolution_for_test`].
    #[cfg(any(test, feature = "test-support"))]
    fn record_using_guard_context_inspection_for_test(&self) {}
}
