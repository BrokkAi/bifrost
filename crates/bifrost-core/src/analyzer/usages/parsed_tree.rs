//! On-demand parsing for scans that own their tree for one file at a time.
//!
//! A `ProjectFile`, a tree-sitter grammar and `compute_line_starts` are all this
//! needs, so it sits beside the rest of the language-blind usages framework and
//! a language crate can parse a file without depending on
//! `brokk-bifrost-analysis`.

use crate::analyzer::ProjectFile;
use crate::text_utils::compute_line_starts;
use tree_sitter::{Language as TreeSitterLanguage, Parser, Tree};

pub struct ParsedTreeFile {
    pub source: String,
    pub tree: Tree,
    pub line_starts: Vec<usize>,
}

/// Parse a single file into source + tree + line starts, or `None` if the file is
/// unreadable or empty. Used by the inverted edge builders to parse on demand
/// inside the per-file parallel walk so each tree can be dropped right after.
pub fn parse_tree_sitter_file(
    file: &ProjectFile,
    language: &TreeSitterLanguage,
) -> Option<ParsedTreeFile> {
    let source = file.read_to_string().ok()?;
    parse_tree_sitter_source(source, language)
}

pub fn parse_tree_sitter_source(
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
