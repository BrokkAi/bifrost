//! The language-blind half of the analyzer's shared helpers.
//!
//! Everything here is decided by a path extension or a byte range, so none of
//! it needs a grammar, an analyzer handle, or a store. The language-aware rest
//! of `analyzer::common` stays in `brokk-bifrost-analysis` and re-exports these
//! at their original paths.

use tree_sitter::Node;

use crate::analyzer::{CodeUnit, Language, ProjectFile};

pub fn language_for_target(target: &CodeUnit) -> Language {
    language_for_file(target.source())
}

pub fn language_for_file(file: &ProjectFile) -> Language {
    file.rel_path()
        .extension()
        .and_then(|ext| ext.to_str())
        .map(Language::from_extension)
        .unwrap_or(Language::None)
}

/// Verbatim source text spanned by `node`, or `""` when the byte range is not a
/// valid `str` boundary (adversarial or partially-parsed input).
///
/// This is the single "slice a node's bytes" primitive. It replaces the
/// per-language `source.get(node.byte_range()).unwrap_or("")` copies and the
/// panicking `&source[node.byte_range()]` slicers (bad ranges now yield `""`
/// instead of panicking). Use [`node_source_text_trimmed`] when surrounding
/// whitespace must be dropped, and `node_ident_text` when a language sigil
/// (`r#`, `@`) must be normalized off identifier tokens; the latter is
/// per-language and lives in `brokk-bifrost-analysis`.
pub fn node_source_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    source.get(node.byte_range()).unwrap_or("")
}

/// [`node_source_text`] with leading/trailing whitespace trimmed. Trimming is
/// load-bearing on the usages side, where a "name" node can span a compound
/// token whose canonical text is the trimmed inner identifier; declaration-side
/// callers that must preserve exact spans use [`node_source_text`] instead.
pub fn node_source_text_trimmed<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    node_source_text(node, source).trim()
}
