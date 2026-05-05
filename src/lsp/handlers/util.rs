use std::path::Path;

use crate::analyzer::ProjectFile;
use crate::lsp::conversion::uri_to_path;
use lsp_types::Uri;

/// Resolve an LSP `Uri` to a [`ProjectFile`] inside `project_root`. Returns
/// `None` for non-`file:` URIs or paths outside the project.
pub fn project_file_for_uri(project_root: &Path, uri: &Uri) -> Option<ProjectFile> {
    let abs_path = uri_to_path(uri)?;
    let rel_path = abs_path.strip_prefix(project_root).ok()?;
    Some(ProjectFile::new(
        project_root.to_path_buf(),
        rel_path.to_path_buf(),
    ))
}

/// Extract the alphanumeric/underscore identifier surrounding `offset` in
/// `content`. Returns `None` if neither the byte at `offset` nor the byte
/// immediately before it is part of an identifier.
pub fn identifier_at_offset(content: &str, offset: usize) -> Option<&str> {
    let bytes = content.as_bytes();
    if bytes.is_empty() {
        return None;
    }
    let mut start = offset.min(bytes.len());
    let mut end = offset.min(bytes.len());

    if start == bytes.len() && start > 0 && is_ident_byte(bytes[start - 1]) {
        start -= 1;
        end = start;
    }
    if start >= bytes.len() || !is_ident_byte(bytes[start]) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifier_at_offset_finds_word_under_cursor() {
        let content = "let foo_bar = baz123;";
        assert_eq!(identifier_at_offset(content, 5), Some("foo_bar"));
        assert_eq!(identifier_at_offset(content, 11), Some("foo_bar"));
        assert_eq!(identifier_at_offset(content, 16), Some("baz123"));
    }

    #[test]
    fn identifier_at_offset_handles_empty_or_no_word() {
        assert_eq!(identifier_at_offset("", 0), None);
        assert_eq!(identifier_at_offset("   ", 1), None);
    }
}
