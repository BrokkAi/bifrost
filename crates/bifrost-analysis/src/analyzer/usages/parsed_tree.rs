pub(crate) use brokk_bifrost_core::analyzer::usages::parsed_tree::{
    ParsedTreeFile, parse_tree_sitter_file, parse_tree_sitter_source,
};

use crate::analyzer::{Language, ProjectFile};
use tree_sitter::Language as TreeSitterLanguage;

/// The tree-sitter grammar for a specific JS/TS source file.
pub(crate) fn js_ts_tree_sitter_language_for_file(
    file: &ProjectFile,
    language: Language,
) -> Option<TreeSitterLanguage> {
    match language {
        Language::JavaScript | Language::TypeScript => {
            crate::analyzer::parser_language_for_path(language, file.rel_path())
        }
        _ => None,
    }
}
