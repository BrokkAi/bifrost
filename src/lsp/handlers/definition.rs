use std::path::Path;

use lsp_types::{GotoDefinitionParams, GotoDefinitionResponse, Location, Uri};

use crate::analyzer::{
    CodeUnit, IAnalyzer, ProjectFile, Range as ByteRange, WorkspaceAnalyzer,
};
use crate::lsp::conversion::{
    byte_range_to_lsp_range, path_to_uri_string, position_to_byte_offset, uri_to_path,
};
use crate::text_utils::compute_line_starts;

/// Resolve `textDocument/definition`. Strategy:
/// 1. Read the file at `uri` and find the identifier under the cursor.
/// 2. Look up the analyzer's `definitions(fq_name)` for the bare identifier
///    (this hits top-level symbols whose fq_name *is* the identifier).
/// 3. Fall back to `search_definitions(^ident$, false)` for any short-name
///    match anywhere in the workspace.
///
/// This is a best-effort lookup — bifrost is a tree-sitter index, not a type
/// checker, so name shadowing and overload resolution are handled by ranking
/// rather than analysis.
pub fn handle(
    workspace: &WorkspaceAnalyzer,
    project_root: &Path,
    params: &GotoDefinitionParams,
) -> Option<GotoDefinitionResponse> {
    let uri = &params.text_document_position_params.text_document.uri;
    let abs_path = uri_to_path(uri)?;
    let rel_path = abs_path.strip_prefix(project_root).ok()?;
    let project_file = ProjectFile::new(project_root.to_path_buf(), rel_path.to_path_buf());

    let content = project_file.read_to_string().ok()?;
    let line_starts = compute_line_starts(&content);
    let byte_offset = position_to_byte_offset(
        &content,
        &line_starts,
        &params.text_document_position_params.position,
    );
    let identifier = identifier_at_offset(&content, byte_offset)?;

    let analyzer = workspace.analyzer();
    let candidates = resolve_candidates(analyzer, identifier);
    if candidates.is_empty() {
        return None;
    }

    let mut locations = Vec::with_capacity(candidates.len());
    for cu in candidates {
        if let Some(loc) = code_unit_location(analyzer, &cu) {
            locations.push(loc);
        }
    }
    if locations.is_empty() {
        return None;
    }
    Some(GotoDefinitionResponse::Array(locations))
}

fn resolve_candidates(analyzer: &dyn IAnalyzer, identifier: &str) -> Vec<CodeUnit> {
    let direct: Vec<CodeUnit> = analyzer.get_definitions(identifier);
    if !direct.is_empty() {
        return direct;
    }
    let pattern = format!(r"^{}$", regex::escape(identifier));
    analyzer
        .search_definitions(&pattern, false)
        .into_iter()
        .filter(|cu| cu.identifier() == identifier)
        .collect()
}

fn identifier_at_offset(content: &str, offset: usize) -> Option<&str> {
    let bytes = content.as_bytes();
    if bytes.is_empty() {
        return None;
    }
    let mut start = offset.min(bytes.len());
    let mut end = offset.min(bytes.len());

    // If the cursor is just past an identifier, step back one byte so the
    // search anchors inside the word.
    if start == bytes.len() && start > 0 && is_ident_byte(bytes[start - 1]) {
        start -= 1;
        end = start;
    }
    if start >= bytes.len() || !is_ident_byte(bytes[start]) {
        // Cursor isn't on an identifier byte — try one character back.
        if start == 0 {
            return None;
        }
        start -= 1;
        end = start;
        if !is_ident_byte(bytes[start]) {
            return None;
        }
    }

    while start > 0 && is_ident_byte(bytes[start - 1]) {
        start -= 1;
    }
    while end < bytes.len() && is_ident_byte(bytes[end]) {
        end += 1;
    }
    content.get(start..end)
}

fn is_ident_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn code_unit_location(analyzer: &dyn IAnalyzer, code_unit: &CodeUnit) -> Option<Location> {
    let abs_path = code_unit.source().abs_path();
    let body = std::fs::read_to_string(&abs_path).ok()?;
    let line_starts = compute_line_starts(&body);
    let range = analyzer.ranges(code_unit).iter().min().copied().unwrap_or(ByteRange {
        start_byte: 0,
        end_byte: body.len(),
        start_line: 0,
        end_line: 0,
    });
    let lsp_range = byte_range_to_lsp_range(&body, &line_starts, &range);
    let uri: Uri = path_to_uri_string(&abs_path).parse().ok()?;
    Some(Location {
        uri,
        range: lsp_range,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifier_at_offset_finds_word_under_cursor() {
        let content = "let foo_bar = baz123;";
        // Cursor inside `foo_bar`.
        assert_eq!(identifier_at_offset(content, 5), Some("foo_bar"));
        // Cursor just after the identifier (still on the underscore boundary).
        assert_eq!(identifier_at_offset(content, 11), Some("foo_bar"));
        // Cursor inside `baz123`.
        assert_eq!(identifier_at_offset(content, 16), Some("baz123"));
        // Cursor on whitespace.
        assert_eq!(identifier_at_offset(content, 3), Some("foo_bar"));
        // Cursor at semicolon.
        assert_eq!(identifier_at_offset(content, 20), Some("baz123"));
    }

    #[test]
    fn identifier_at_offset_handles_empty_or_no_word() {
        assert_eq!(identifier_at_offset("", 0), None);
        assert_eq!(identifier_at_offset("   ", 1), None);
    }
}
