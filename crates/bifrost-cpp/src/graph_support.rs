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
//! * [`CppAnalysisSource::visible_type_units`] is the moka-cached include-closure
//!   class table. Its *builder* is [`crate::hierarchy::build_cpp_visible_type_units`];
//!   the cell and its `test-support` build counter stay analyzer-side, so this
//!   accessor is the only way the reconciler reaches a warm table.
//! * [`CppAnalysisSource::cpp_import_statements`] is `IAnalyzer::import_statements`,
//!   the raw `#include` lines. No core capability exposes it, so it is spelled
//!   out rather than inherited from a supertrait.
//! * [`CppAnalysisSource::cpp_raw_supertypes_of`] is
//!   `TreeSitterAnalyzer::raw_supertypes_of`, whose rows are crate-private to
//!   analysis; the analyzer hands the decoded base-specifier strings across.

use crate::imports::IncludeTargetIndex;
use brokk_bifrost_core::analyzer::capabilities::TypeAliasProvider;
use brokk_bifrost_core::analyzer::{CodeUnit, CodeUnitIndex, ProjectFile};
use std::sync::Arc;

pub trait CppAnalysisSource: CodeUnitIndex + TypeAliasProvider {
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
}
