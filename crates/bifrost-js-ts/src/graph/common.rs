//! Language selection for JS/TS graph targets.

use brokk_bifrost_core::analyzer::common::language_for_file;
use brokk_bifrost_core::analyzer::{CodeUnit, Language};

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
