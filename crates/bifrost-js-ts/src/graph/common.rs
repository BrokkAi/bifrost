//! The two workspace projections the JS/TS graph reads off a declaration index.
//!
//! Both were `pub(crate)` in `analyzer/usages/common.rs` and are three lines
//! each over core's `language_for_file`; they are here rather than imported so
//! the graph band depends on nothing but core.

use brokk_bifrost_core::analyzer::common::language_for_file;
use brokk_bifrost_core::analyzer::{CodeUnit, CodeUnitIndex, Language, ProjectFile};

/// `target`'s language when `filter` accepts it, `Language::None` otherwise.
pub fn language_for_target_filtered(
    target: &CodeUnit,
    filter: impl FnOnce(Language) -> bool,
) -> Language {
    let language = language_for_file(target.source());
    if filter(language) {
        language
    } else {
        Language::None
    }
}

/// The analyzed files of `language`, sorted for a deterministic scan order.
pub fn analyzed_files_for_language(
    analyzer: &dyn CodeUnitIndex,
    language: Language,
) -> Vec<ProjectFile> {
    let mut files: Vec<ProjectFile> = analyzer
        .analyzed_files()
        .into_iter()
        .filter(|file| language_for_file(file) == language)
        .collect();
    files.sort();
    files
}
