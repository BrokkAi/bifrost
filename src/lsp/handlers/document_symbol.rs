use std::path::Path;

use lsp_types::{
    DocumentSymbol, DocumentSymbolParams, DocumentSymbolResponse, Range as LspRange, SymbolKind,
};

use crate::analyzer::{
    CodeUnit, CodeUnitType, IAnalyzer, ProjectFile, Range as ByteRange, WorkspaceAnalyzer,
};
use crate::lsp::conversion::{byte_range_to_lsp_range, uri_to_path};
use crate::text_utils::compute_line_starts;

/// Build the documentSymbol response for a request URI. Returns `None` when
/// the URI does not map into the active project root, or when the file is
/// not analyzed by any of the workspace's per-language analyzers.
pub fn handle(
    workspace: &WorkspaceAnalyzer,
    project_root: &Path,
    params: &DocumentSymbolParams,
) -> Option<DocumentSymbolResponse> {
    let uri = &params.text_document.uri;
    let abs_path = uri_to_path(uri)?;
    let rel_path = abs_path.strip_prefix(project_root).ok()?;
    let project_file = ProjectFile::new(project_root.to_path_buf(), rel_path.to_path_buf());

    let analyzer = workspace.analyzer();

    // Read the file once for line-start info; rendering is fast after that.
    let content = project_file.read_to_string().ok()?;
    let line_starts = compute_line_starts(&content);

    let symbols: Vec<DocumentSymbol> = analyzer
        .top_level_declarations(&project_file)
        .filter(|cu| !cu.is_anonymous())
        .map(|cu| build_symbol(analyzer, cu, &content, &line_starts))
        .collect();

    Some(DocumentSymbolResponse::Nested(symbols))
}

fn build_symbol(
    analyzer: &dyn IAnalyzer,
    code_unit: &CodeUnit,
    content: &str,
    line_starts: &[usize],
) -> DocumentSymbol {
    let range = primary_range(analyzer, code_unit, content);
    let lsp_range = byte_range_to_lsp_range(content, line_starts, &range);
    let selection_range = identifier_selection_range(code_unit, content, line_starts, &range)
        .unwrap_or(lsp_range);

    let children: Vec<DocumentSymbol> = analyzer
        .direct_children(code_unit)
        .filter(|child| !child.is_anonymous())
        .map(|child| build_symbol(analyzer, child, content, line_starts))
        .collect();

    #[allow(deprecated)] // `deprecated` field is present on lsp-types DocumentSymbol.
    DocumentSymbol {
        name: code_unit.identifier().to_string(),
        detail: code_unit.signature().map(str::to_string),
        kind: map_kind(code_unit.kind()),
        tags: None,
        deprecated: None,
        range: lsp_range,
        selection_range,
        children: if children.is_empty() {
            None
        } else {
            Some(children)
        },
    }
}

fn primary_range(analyzer: &dyn IAnalyzer, code_unit: &CodeUnit, content: &str) -> ByteRange {
    // Prefer the analyzer's recorded range; fall back to the whole file if the
    // analyzer has no range info (synthetic units, modules, etc.).
    analyzer
        .ranges(code_unit)
        .iter()
        .min()
        .copied()
        .unwrap_or(ByteRange {
            start_byte: 0,
            end_byte: content.len(),
            start_line: 0,
            end_line: line_count(content),
        })
}

fn identifier_selection_range(
    code_unit: &CodeUnit,
    content: &str,
    line_starts: &[usize],
    fallback: &ByteRange,
) -> Option<LspRange> {
    // Search for the identifier within the unit's range so the editor's
    // "select symbol" gesture lands on the name rather than the whole body.
    // Match must be word-boundary aware — a raw `find` returns the wrong
    // span for short identifiers (e.g. method `s` matches `class`) or
    // identifiers that are a prefix of a longer word in the body
    // (e.g. method `foo` matches the first three bytes of `foofoo`).
    let slice = content.get(fallback.start_byte..fallback.end_byte)?;
    let name = code_unit.identifier();
    if name.is_empty() {
        return None;
    }
    let offset = find_word(slice, name)?;
    let abs_start = fallback.start_byte + offset;
    let abs_end = abs_start + name.len();
    let range = ByteRange {
        start_byte: abs_start,
        end_byte: abs_end,
        start_line: 0,
        end_line: 0,
    };
    Some(byte_range_to_lsp_range(content, line_starts, &range))
}

/// Find the first occurrence of `needle` in `haystack` that is bounded on
/// both sides by a non-identifier byte (or buffer edge).
fn find_word(haystack: &str, needle: &str) -> Option<usize> {
    let needle_bytes = needle.as_bytes();
    let bytes = haystack.as_bytes();
    if needle_bytes.is_empty() || needle_bytes.len() > bytes.len() {
        return None;
    }
    let mut start = 0;
    while let Some(rel) = haystack[start..].find(needle) {
        let candidate = start + rel;
        let before_ok = candidate == 0 || !is_ident_byte(bytes[candidate - 1]);
        let after_idx = candidate + needle_bytes.len();
        let after_ok = after_idx >= bytes.len() || !is_ident_byte(bytes[after_idx]);
        if before_ok && after_ok {
            return Some(candidate);
        }
        // Advance past this candidate's first byte so we don't loop forever.
        start = candidate + 1;
    }
    None
}

fn is_ident_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn map_kind(kind: CodeUnitType) -> SymbolKind {
    match kind {
        CodeUnitType::Class => SymbolKind::CLASS,
        CodeUnitType::Function => SymbolKind::FUNCTION,
        CodeUnitType::Field => SymbolKind::FIELD,
        CodeUnitType::Module => SymbolKind::MODULE,
    }
}

fn line_count(content: &str) -> usize {
    if content.is_empty() {
        0
    } else {
        compute_line_starts(content).len().saturating_sub(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_word_skips_substring_match_inside_longer_identifier() {
        // The naive `find` would return offset 0 (the `foo` prefix of
        // `foofoo`); find_word must skip ahead to the standalone `foo`.
        assert_eq!(find_word("foofoo + foo;", "foo"), Some(9));
    }

    #[test]
    fn find_word_skips_substring_match_in_keyword() {
        // Method named `s` should not select the `s` in `class`.
        assert_eq!(find_word("class Demo { void s() {} }", "s"), Some(18));
    }

    #[test]
    fn find_word_returns_none_when_no_word_match_exists() {
        assert_eq!(find_word("foofoo", "foo"), None);
        assert_eq!(find_word("classify", "class"), None);
    }

    #[test]
    fn find_word_anchors_at_buffer_edges() {
        assert_eq!(find_word("foo", "foo"), Some(0));
        assert_eq!(find_word("a foo", "foo"), Some(2));
        assert_eq!(find_word("foo bar", "foo"), Some(0));
    }
}
