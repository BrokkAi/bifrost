//! Grammar selection for a JS/TS source file.
//!
//! TypeScript is the only language whose grammar depends on the file path --
//! `.tsx` needs `LANGUAGE_TSX`, everything else `LANGUAGE_TYPESCRIPT` -- and the
//! decision itself is core ([`LanguageDialect::for_path`]). Before the
//! extraction this was `js_ts_tree_sitter_language_for_file` in
//! `analyzer/usages/parsed_tree.rs`, a JS/TS-named free function in a framework
//! file that routed the same question through the analysis-side grammar
//! registry; all eight of its call sites moved here, so it is answered directly
//! from the two grammar crates instead.

use brokk_bifrost_core::analyzer::model::LanguageDialect;
use brokk_bifrost_core::analyzer::{Language, ProjectFile};
use tree_sitter::Language as TreeSitterLanguage;

/// The tree-sitter grammar for a specific JS/TS source file, or `None` when
/// `language` is neither dialect.
pub fn js_ts_tree_sitter_language_for_file(
    file: &ProjectFile,
    language: Language,
) -> Option<TreeSitterLanguage> {
    match LanguageDialect::for_path(language, file.rel_path()) {
        LanguageDialect::TypeScriptTsx => Some(tree_sitter_typescript::LANGUAGE_TSX.into()),
        LanguageDialect::Standard(Language::TypeScript) => {
            Some(tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
        }
        LanguageDialect::Standard(Language::JavaScript) => {
            Some(tree_sitter_javascript::LANGUAGE.into())
        }
        LanguageDialect::Standard(_) => None,
    }
}

/// The default grammar for a JS/TS language, ignoring any per-path dialect.
///
/// Used where the scan has a `Language` but no particular file yet.
pub fn tree_sitter_language_for(language: Language) -> Option<TreeSitterLanguage> {
    match language {
        Language::JavaScript => Some(tree_sitter_javascript::LANGUAGE.into()),
        Language::TypeScript => Some(tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into()),
        _ => None,
    }
}
