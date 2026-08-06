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
//! and `cpp_import_statements`, and none of those reads back into
//! reconciliation.
//!
//! Three members are load-bearing beyond their signature:
//!
//! * [`CppSource::visible_type_units`] is the moka-cached include-closure
//!   class table. Its *builder* is [`crate::hierarchy::build_cpp_visible_type_units`];
//!   the cell and its `test-support` build counter stay analyzer-side, so this
//!   accessor is the only way the reconciler reaches a warm table.
//! * [`CppSource::cpp_import_statements`] is `IAnalyzer::import_statements`,
//!   the raw `#include` lines. No core capability exposes it, so it is spelled
//!   out rather than inherited from a supertrait.
//! * [`CppSource::cpp_raw_supertypes_of`] is
//!   `TreeSitterAnalyzer::raw_supertypes_of`, whose rows are crate-private to
//!   analysis; the analyzer hands the decoded base-specifier strings across.

use crate::compile_context::CppCompileContext;
use crate::graph::CppWorkspaceSource;
use crate::imports::IncludeTargetIndex;
use brokk_bifrost_core::analyzer::capabilities::{TypeAliasProvider, TypeHierarchyProvider};
use brokk_bifrost_core::analyzer::model::CppTemplateMetadata;
use brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxTree;
use brokk_bifrost_core::analyzer::{CodeUnit, CodeUnitIndex, ProjectFile};
use std::sync::Arc;

pub trait CppSource:
    CodeUnitIndex + TypeAliasProvider + TypeHierarchyProvider + CppWorkspaceSource
{
    /// The workspace-wide `#include` resolution table, built once per analyzer
    /// generation from [`IncludeTargetIndex::build`].
    fn include_target_index(&self) -> &IncludeTargetIndex;

    /// The raw `#include` lines recorded for `file` (`IAnalyzer::import_statements`).
    fn cpp_import_statements(&self, file: &ProjectFile) -> Vec<String>;

    /// The declared base specifiers of `code_unit`, as written
    /// (`TreeSitterAnalyzer::raw_supertypes_of`).
    fn cpp_raw_supertypes_of(&self, code_unit: &CodeUnit) -> Vec<String>;

    /// Every class-like or alias declaration reachable from `file` through its
    /// `#include` closure, memoized per file. See this module's note.
    fn visible_type_units(&self, file: &ProjectFile) -> Arc<Vec<CodeUnit>>;

    /// The indexed source of `file` (`TreeSitterAnalyzer::file_source`).
    fn cpp_file_source(&self, file: &ProjectFile) -> Option<String>;

    /// The parsed tree and its source backing for `file`, from the analyzer's
    /// query read cache.
    ///
    /// The single hottest member of this trait: the usage graph reaches it at
    /// 27 call sites. The cache is *not* rebuilt per call -- `VisibilityIndex`
    /// borrows the analyzer rather than cloning it precisely so this stays warm
    /// across a scan (#1175), so an implementor must forward to the same
    /// analyzer the query is running against.
    fn prepared_syntax(&self, file: &ProjectFile) -> Option<Arc<PreparedSyntaxTree>>;

    /// The declaration's syntactic owner, which unlike
    /// [`CodeUnitIndex::parent_of`] never falls back to a definition-row lookup.
    fn structural_parent_of(&self, code_unit: &CodeUnit) -> Option<CodeUnit>;

    /// The persisted C++ template metadata side table's row for `code_unit`.
    fn template_metadata(&self, code_unit: &CodeUnit) -> Option<CppTemplateMetadata>;

    /// The `compile_commands.json` entry governing `file`, if the workspace has
    /// a compile database that names it. The only analyzer-resident product
    /// [`crate::diagnostics`] needs.
    fn compile_context_for(&self, file: &ProjectFile) -> Option<&CppCompileContext>;

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
}
