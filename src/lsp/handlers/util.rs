use std::path::Path;

use crate::analyzer::ProjectFile;
use crate::lsp::conversion::uri_to_path;
use crate::text_utils::{compute_line_starts, find_line_index_for_offset};
use lsp_types::Uri;

/// Resolve an LSP `Uri` to a [`ProjectFile`] inside `project_root`. Returns
/// `None` for non-`file:` URIs or paths outside the project, logging a
/// single-line stderr warning so users debugging "why is my LSP request
/// returning empty" can see the cause.
pub fn project_file_for_uri(project_root: &Path, uri: &Uri) -> Option<ProjectFile> {
    let abs_path = match uri_to_path(uri) {
        Some(path) => path,
        None => {
            eprintln!(
                "[bifrost-lsp] ignoring non-file URI: {} (only file:// is supported)",
                uri.as_str()
            );
            return None;
        }
    };
    // Canonicalize so Windows extended-length paths (`\\?\C:\…` produced by
    // FilesystemProject's canonicalize) line up with the URI-decoded path
    // (`C:/…`). Fall back to the as-is path when canonicalize fails — for
    // example, didChangeWatchedFiles DELETED events reference paths that no
    // longer exist on disk.
    let canonical = abs_path.canonicalize().unwrap_or_else(|_| abs_path.clone());
    let rel_path = match canonical.strip_prefix(project_root) {
        Ok(rel) => rel.to_path_buf(),
        Err(_) => match abs_path.strip_prefix(project_root) {
            Ok(rel) => rel.to_path_buf(),
            Err(_) => {
                eprintln!(
                    "[bifrost-lsp] ignoring path outside project root: {} (root: {})",
                    abs_path.display(),
                    project_root.display()
                );
                return None;
            }
        },
    };
    Some(ProjectFile::new(project_root.to_path_buf(), rel_path))
}

/// Extract the alphanumeric/underscore identifier surrounding `offset` in
/// `content`. Returns `None` if neither the byte at `offset` nor the byte
/// immediately before it is part of an identifier.
pub fn identifier_at_offset(content: &str, offset: usize) -> Option<&str> {
    let (start, end) = identifier_span_at_offset(content, offset)?;
    content.get(start..end)
}

/// Like [`identifier_at_offset`] but returns the byte span `(start, end)`
/// inside `content` instead of the slice. Useful for callers that need the
/// range as a value (e.g. LSP hover wants to return the highlight range).
pub fn identifier_span_at_offset(content: &str, offset: usize) -> Option<(usize, usize)> {
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
    if start == end {
        return None;
    }
    Some((start, end))
}

fn is_ident_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// Lift the contiguous block of comment-like lines that ends immediately
/// before the line containing `decl_start_byte`. The returned string has
/// comment markers stripped so it can be embedded directly inside hover
/// markdown. Returns `None` when there is no leading comment block, or the
/// block is whitespace-only after stripping.
///
/// "Comment-like" covers the leading-comment shapes the issue called out:
/// `///` and `//!` (Rust), `//` (C-family), `/** … */` (Javadoc/JSDoc/PHPDoc
/// /Scaladoc), `/* … */`, and `#` (Python). Rust attributes (`#[…]`) are
/// intentionally NOT consumed — they aren't doc comments, and including them
/// would corrupt the markdown.
pub fn extract_leading_doc_comment(content: &str, decl_start_byte: usize) -> Option<String> {
    let line_starts = compute_line_starts(content);
    let line_index = find_line_index_for_offset(&line_starts, decl_start_byte);
    if line_index == 0 {
        return None;
    }

    let mut comment_lines: Vec<&str> = Vec::new();
    for li in (0..line_index).rev() {
        let line_start = line_starts[li];
        let line_end = line_starts.get(li + 1).copied().unwrap_or(content.len());
        let raw = &content[line_start..line_end];
        let trimmed = raw.trim_end_matches(['\n', '\r']);
        let stripped = trimmed.trim_start();

        if stripped.is_empty() || !is_doc_comment_line(stripped) {
            break;
        }
        comment_lines.push(trimmed);
    }

    if comment_lines.is_empty() {
        return None;
    }
    comment_lines.reverse();

    let cleaned: Vec<String> = comment_lines
        .iter()
        .map(|line| clean_comment_line(line))
        .collect();
    let joined = cleaned.join("\n").trim().to_string();
    if joined.is_empty() {
        None
    } else {
        Some(joined)
    }
}

fn is_doc_comment_line(stripped: &str) -> bool {
    stripped.starts_with("///")
        || stripped.starts_with("//!")
        || stripped.starts_with("//")
        || stripped.starts_with("/**")
        || stripped.starts_with("/*!")
        || stripped.starts_with("/*")
        || stripped.starts_with("*/")
        || stripped.starts_with('*')
        // Python `#` comments. Skip `#[` so Rust attributes are not consumed.
        || (stripped.starts_with('#') && !stripped.starts_with("#["))
}

fn clean_comment_line(line: &str) -> String {
    let trimmed = line.trim_start();
    let body = if let Some(rest) = trimmed.strip_prefix("///") {
        rest
    } else if let Some(rest) = trimmed.strip_prefix("//!") {
        rest
    } else if let Some(rest) = trimmed.strip_prefix("//") {
        rest
    } else if let Some(rest) = trimmed.strip_prefix("/**") {
        rest.strip_suffix("*/").unwrap_or(rest)
    } else if let Some(rest) = trimmed.strip_prefix("/*!") {
        rest.strip_suffix("*/").unwrap_or(rest)
    } else if let Some(rest) = trimmed.strip_prefix("/*") {
        rest.strip_suffix("*/").unwrap_or(rest)
    } else if let Some(rest) = trimmed.strip_prefix("*/") {
        rest
    } else if let Some(rest) = trimmed.strip_prefix("* ") {
        rest
    } else if let Some(rest) = trimmed.strip_prefix('*') {
        rest
    } else if let Some(rest) = trimmed.strip_prefix('#') {
        rest
    } else {
        trimmed
    };
    body.trim().to_string()
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

    #[test]
    fn extract_doc_comment_handles_rust_triple_slash() {
        let content = "/// Returns the answer.\n/// Always 42.\nfn answer() -> i32 { 42 }\n";
        let decl_start = content.find("fn answer").expect("decl");
        let doc = extract_leading_doc_comment(content, decl_start).expect("doc");
        assert_eq!(doc, "Returns the answer.\nAlways 42.");
    }

    #[test]
    fn extract_doc_comment_handles_javadoc_block() {
        let content =
            "    /**\n     * The class A.\n     * Important.\n     */\n    public class A {}\n";
        let decl_start = content.find("public class A").expect("decl");
        let doc = extract_leading_doc_comment(content, decl_start).expect("doc");
        assert_eq!(doc, "The class A.\nImportant.");
    }

    #[test]
    fn extract_doc_comment_handles_python_hash() {
        let content = "# Helper module.\n# Used by tests.\ndef foo():\n    pass\n";
        let decl_start = content.find("def foo").expect("decl");
        let doc = extract_leading_doc_comment(content, decl_start).expect("doc");
        assert_eq!(doc, "Helper module.\nUsed by tests.");
    }

    #[test]
    fn extract_doc_comment_returns_none_when_no_comment() {
        let content = "fn foo() {}\n";
        assert!(extract_leading_doc_comment(content, 0).is_none());
        let content2 = "let x = 1;\nfn bar() {}\n";
        let decl = content2.find("fn bar").unwrap();
        assert!(extract_leading_doc_comment(content2, decl).is_none());
    }

    #[test]
    fn extract_doc_comment_skips_rust_attributes() {
        // `#[derive(...)]` is an attribute, not a doc comment — must be ignored.
        let content = "#[derive(Debug)]\nstruct S {}\n";
        let decl_start = content.find("struct S").expect("decl");
        assert!(extract_leading_doc_comment(content, decl_start).is_none());
    }

    #[test]
    fn extract_doc_comment_stops_at_blank_line() {
        // A blank gap between the comment block and the declaration breaks
        // the association — the comment is documenting something else.
        let content = "// Old comment.\n\nfn current() {}\n";
        let decl_start = content.find("fn current").expect("decl");
        assert!(extract_leading_doc_comment(content, decl_start).is_none());
    }

    #[test]
    fn extract_doc_comment_handles_single_line_block() {
        let content = "/** Single-line block doc. */\npublic void foo() {}\n";
        let decl_start = content.find("public void foo").expect("decl");
        let doc = extract_leading_doc_comment(content, decl_start).expect("doc");
        assert_eq!(doc, "Single-line block doc.");
    }
}
