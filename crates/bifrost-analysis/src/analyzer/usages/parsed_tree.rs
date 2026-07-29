use crate::analyzer::{Language, ProjectFile};
use crate::text_utils::compute_line_starts;
use tree_sitter::{Language as TreeSitterLanguage, Parser, Tree};

pub(crate) struct ParsedTreeFile {
    pub(crate) source: String,
    pub(crate) tree: Tree,
    pub(crate) line_starts: Vec<usize>,
}

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

/// Parse a single file into source + tree + line starts, or `None` if the file is
/// unreadable or empty. Used by the inverted edge builders to parse on demand
/// inside the per-file parallel walk so each tree can be dropped right after.
pub(crate) fn parse_tree_sitter_file(
    file: &ProjectFile,
    language: &TreeSitterLanguage,
) -> Option<ParsedTreeFile> {
    let source = file.read_to_string().ok()?;
    parse_tree_sitter_source(source, language)
}

pub(crate) fn parse_tree_sitter_source(
    source: String,
    language: &TreeSitterLanguage,
) -> Option<ParsedTreeFile> {
    if source.is_empty() {
        return None;
    }
    let mut parser = Parser::new();
    parser.set_language(language).ok()?;
    let tree = parser.parse(source.as_str(), None)?;
    let line_starts = compute_line_starts(&source);
    Some(ParsedTreeFile {
        source,
        tree,
        line_starts,
    })
}
