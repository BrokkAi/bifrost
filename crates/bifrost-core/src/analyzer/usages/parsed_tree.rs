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

/// A grammar plus the optional pre-parse that decides which bytes of a file the
/// parser may read.
///
/// Most languages parse the whole file, so [`ParseSpec::whole`] is the common
/// form. C# is different: its grammar cannot represent a preprocessor directive
/// inside a declaration, so C# hides directive lines and inactive conditional
/// branches through tree-sitter included ranges (issue #1803). The pre-parse
/// travels with the grammar so that a scan cannot parse a file differently from
/// the declaration walk. Node offsets are unaffected: included ranges select
/// bytes of the original source, they do not move them.
#[derive(Clone, Copy)]
pub struct ParseSpec<'a> {
    language: &'a TreeSitterLanguage,
    included_ranges: Option<IncludedRangesFn>,
}

/// A language's pre-parse: the byte ranges of a source the parser may read, or
/// `None` when that source needs no restriction.
pub type IncludedRangesFn = fn(&str) -> Option<Vec<tree_sitter::Range>>;

impl<'a> ParseSpec<'a> {
    /// Parse every byte of the file.
    pub fn whole(language: &'a TreeSitterLanguage) -> Self {
        Self {
            language,
            included_ranges: None,
        }
    }

    /// Parse only the ranges `included_ranges` computes for the source. The
    /// function returns `None` when the file needs no restriction.
    pub fn restricted(language: &'a TreeSitterLanguage, included_ranges: IncludedRangesFn) -> Self {
        Self {
            language,
            included_ranges: Some(included_ranges),
        }
    }

    pub fn language(&self) -> &'a TreeSitterLanguage {
        self.language
    }

    /// Parse `source` under this spec.
    pub fn parse(&self, source: &str) -> Option<Tree> {
        let mut parser = Parser::new();
        parser.set_language(self.language).ok()?;
        if let Some(ranges) = self.included_ranges.and_then(|compute| compute(source)) {
            parser.set_included_ranges(&ranges).ok()?;
        }
        parser.parse(source, None)
    }
}

/// Parse a single file into source + tree + line starts, or `None` if the file is
/// unreadable or empty. Used by the inverted edge builders to parse on demand
/// inside the per-file parallel walk so each tree can be dropped right after.
pub fn parse_tree_sitter_file(file: &ProjectFile, spec: ParseSpec<'_>) -> Option<ParsedTreeFile> {
    let source = file.read_to_string().ok()?;
    parse_tree_sitter_source(source, spec)
}

pub fn parse_tree_sitter_source(source: String, spec: ParseSpec<'_>) -> Option<ParsedTreeFile> {
    if source.is_empty() {
        return None;
    }
    let tree = spec.parse(source.as_str())?;
    let line_starts = compute_line_starts(&source);
    Some(ParsedTreeFile {
        source,
        tree,
        line_starts,
    })
}
