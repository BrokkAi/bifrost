use crate::analyzer::{CodeUnit, Project, ProjectFile, Range as ByteRange};
use crate::lsp::conversion::{byte_range_to_lsp_range, uri_to_path};
use crate::text_utils::{compute_line_starts, find_line_index_for_offset};
use lsp_types::{Range as LspRange, Uri};

/// Resolve an LSP `Uri` to a [`ProjectFile`], read its contents (consulting
/// `project.read_source` so unsaved overlays win over disk), and compute the
/// line-start index — the prologue used by every per-file handler. Returns
/// `None` if the URI doesn't map into the project, or the file cannot be read.
pub fn read_document_for_uri(
    project: &dyn Project,
    uri: &Uri,
) -> Option<(ProjectFile, String, Vec<usize>)> {
    let project_file = project_file_for_uri(project, uri)?;
    let content = project.read_source(&project_file).ok()?;
    let line_starts = compute_line_starts(&content);
    Some((project_file, content, line_starts))
}

/// Resolve an LSP `Uri` to a [`ProjectFile`] that belongs to `project`.
/// Returns `None` for non-`file:` URIs or paths outside the project, logging
/// a single-line stderr warning so users debugging "why is my LSP request
/// returning empty" can see the cause.
pub fn project_file_for_uri(project: &dyn Project, uri: &Uri) -> Option<ProjectFile> {
    let abs_path = path_for_file_uri(uri)?;
    // Canonicalize so Windows extended-length paths (`\\?\C:\…` produced by
    // FilesystemProject's canonicalize) line up with the URI-decoded path
    // (`C:/…`). Fall back to the as-is path when canonicalize fails — for
    // example, didChangeWatchedFiles DELETED events reference paths that no
    // longer exist on disk.
    let canonical = abs_path.canonicalize().unwrap_or_else(|_| abs_path.clone());
    if let Some(file) = project.file_by_abs_path(&canonical) {
        return Some(file);
    }
    if let Some(file) = project.file_by_abs_path(&abs_path) {
        return Some(file);
    }
    eprintln!(
        "[bifrost-lsp] ignoring path outside project: {} (root: {})",
        abs_path.display(),
        project.root().display()
    );
    None
}

/// Resolve a URI to a project path even when the file no longer exists on disk.
/// This is reserved for watched-file delete events: normal document handlers
/// should use [`project_file_for_uri`] so they only read files that currently
/// belong to the project.
pub(crate) fn project_file_for_uri_allow_missing(
    project: &dyn Project,
    uri: &Uri,
) -> Option<ProjectFile> {
    let abs_path = path_for_file_uri(uri)?;
    if let Some(file) = project.file_by_abs_path_allow_missing(&abs_path) {
        return Some(file);
    }
    eprintln!(
        "[bifrost-lsp] ignoring path outside project: {} (root: {})",
        abs_path.display(),
        project.root().display()
    );
    None
}

fn path_for_file_uri(uri: &Uri) -> Option<std::path::PathBuf> {
    match uri_to_path(uri) {
        Some(path) => Some(path),
        None => {
            eprintln!(
                "[bifrost-lsp] ignoring non-file URI: {} (only file:// is supported)",
                uri.as_str()
            );
            None
        }
    }
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

/// Extract the identifier prefix that ends at `offset` (the byte position of
/// the cursor). Walks backward while bytes match [`is_ident_byte`]; does NOT
/// walk forward past the cursor. Used by `textDocument/completion`, where the
/// suffix to the right of the cursor belongs to the identifier the user is
/// currently typing over and must not be consumed.
///
/// Returns `None` when there is no identifier byte immediately before `offset`
/// (cursor after whitespace, after `(`, at file start) OR when `offset` lies
/// past the end of `content`. The past-EOF rejection is important: callers
/// must clamp their offsets via `position_to_byte_offset` first, and a
/// degenerate offset must not produce a fabricated prefix from the trailing
/// bytes of the buffer.
pub fn identifier_prefix_before_offset(content: &str, offset: usize) -> Option<&str> {
    let bytes = content.as_bytes();
    if offset > bytes.len() {
        return None;
    }
    let end = offset;
    let mut start = end;
    while start > 0 && is_ident_byte(bytes[start - 1]) {
        start -= 1;
    }
    if start == end {
        return None;
    }
    content.get(start..end)
}

pub(super) fn is_ident_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// Find the first occurrence of `needle` in `haystack` that is bounded on
/// both sides by a non-identifier byte (or buffer edge). Used by handlers to
/// locate a symbol identifier inside a larger span (declaration body,
/// signature) without matching substrings inside other identifiers.
pub(super) fn find_word(haystack: &str, needle: &str) -> Option<usize> {
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

/// Locate the identifier of `code_unit` inside `fallback`'s byte span and
/// return its position as an `LspRange`. Returns `None` when the identifier
/// cannot be found word-bounded inside the span — callers fall back to the
/// full span in that case. Word-boundary matching matters here: a raw `find`
/// returns the wrong span for short identifiers (e.g. method `s` matches the
/// `s` in `class`) or identifiers that are a prefix of a longer word in the
/// body (e.g. method `foo` matches the first three bytes of `foofoo`).
pub(super) fn identifier_selection_range(
    code_unit: &CodeUnit,
    content: &str,
    line_starts: &[usize],
    fallback: &ByteRange,
) -> Option<LspRange> {
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

        if stripped.is_empty() {
            break;
        }
        if is_doc_comment_line(stripped) {
            comment_lines.push(trimmed);
            continue;
        }
        // A Rust outer attribute (`#[…]`) sits between the doc comment and
        // the declaration — skip it so docs above attributes still get
        // surfaced, but never lift the attribute itself into hover markdown.
        if is_rust_outer_attribute_line(stripped) {
            continue;
        }
        break;
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

/// True for a single-line Rust outer attribute (e.g. `#[derive(Debug)]`,
/// `#[cfg(test)]`). Multi-line attributes split across lines are intentionally
/// not handled — they're rare in practice and would require bracket-depth
/// tracking to consume safely.
fn is_rust_outer_attribute_line(stripped: &str) -> bool {
    stripped.starts_with("#[") && stripped.trim_end().ends_with(']')
}

fn is_doc_comment_line(stripped: &str) -> bool {
    // Bare `//` is too noisy (license headers, TODOs, commented-out code), so
    // require the explicit doc-comment prefixes `///` and `//!`.
    stripped.starts_with("///")
        || stripped.starts_with("//!")
        || stripped.starts_with("/**")
        || stripped.starts_with("/*!")
        || stripped.starts_with("/*")
        // Javadoc continuations: bare `*`, `* ...`, or the closing `*/`.
        // Anything else starting with `*` (e.g. `*ptr;`, `*= 2;`) is code.
        || stripped == "*"
        || stripped == "*/"
        || stripped.starts_with("* ")
        // Python `#` comments. Skip `#[` (Rust outer attribute) and `#!`
        // (Rust inner attribute `#![...]` and Unix shebangs).
        || (stripped.starts_with('#')
            && !stripped.starts_with("#[")
            && !stripped.starts_with("#!"))
}

fn clean_comment_line(line: &str) -> String {
    let trimmed = line.trim_start();
    let body = if let Some(rest) = trimmed.strip_prefix("///") {
        rest
    } else if let Some(rest) = trimmed.strip_prefix("//!") {
        rest
    } else if let Some(rest) = trimmed.strip_prefix("/**") {
        rest.strip_suffix("*/").unwrap_or(rest)
    } else if let Some(rest) = trimmed.strip_prefix("/*!") {
        rest.strip_suffix("*/").unwrap_or(rest)
    } else if let Some(rest) = trimmed.strip_prefix("/*") {
        rest.strip_suffix("*/").unwrap_or(rest)
    } else if trimmed == "*/" {
        ""
    } else if let Some(rest) = trimmed.strip_prefix("* ") {
        rest
    } else if trimmed == "*" {
        ""
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
    fn identifier_prefix_before_offset_walks_backward_only() {
        let content = "let foo_bar = baz123;";
        // Cursor after "foo" (inside `foo_bar`): prefix is "foo", NOT "foo_bar".
        // Completion must not consume the suffix the user is overwriting.
        assert_eq!(identifier_prefix_before_offset(content, 7), Some("foo"));
        // Cursor at end of "foo_bar".
        assert_eq!(
            identifier_prefix_before_offset(content, 11),
            Some("foo_bar")
        );
        // Cursor sits on whitespace following an identifier.
        assert_eq!(identifier_prefix_before_offset(content, 12), None);
        // Cursor at file start.
        assert_eq!(identifier_prefix_before_offset(content, 0), None);
        // Empty content.
        assert_eq!(identifier_prefix_before_offset("", 0), None);
        // Offset past EOF is rejected — callers must clamp first.
        assert_eq!(identifier_prefix_before_offset("abc", 99), None);
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
    fn extract_doc_comment_skips_attribute_between_doc_and_decl() {
        // Regression: `/// docs` followed by `#[derive(Debug)]` followed by
        // `struct S` must surface "docs". Previously the scan stopped at the
        // attribute line and dropped the doc comment entirely.
        let content = "/// First line.\n/// Second line.\n#[derive(Debug, Clone)]\nstruct S {}\n";
        let decl_start = content.find("struct S").expect("decl");
        let doc = extract_leading_doc_comment(content, decl_start).expect("doc");
        assert_eq!(doc, "First line.\nSecond line.");
    }

    #[test]
    fn extract_doc_comment_skips_multiple_attribute_lines() {
        let content = "/// docs\n#[derive(Debug)]\n#[allow(unused)]\nstruct S {}\n";
        let decl_start = content.find("struct S").expect("decl");
        let doc = extract_leading_doc_comment(content, decl_start).expect("doc");
        assert_eq!(doc, "docs");
    }

    #[test]
    fn extract_doc_comment_attribute_without_doc_returns_none() {
        // Attributes alone (no preceding doc comment) must not produce hover
        // text — the attribute itself is never lifted into markdown.
        let content = "#[derive(Debug)]\n#[allow(unused)]\nstruct S {}\n";
        let decl_start = content.find("struct S").expect("decl");
        assert!(extract_leading_doc_comment(content, decl_start).is_none());
    }

    #[test]
    fn extract_doc_comment_skips_rust_inner_attributes() {
        // `#![allow(...)]` is an inner attribute, not a doc comment.
        let content = "#![allow(dead_code)]\nstruct S {}\n";
        let decl_start = content.find("struct S").expect("decl");
        assert!(extract_leading_doc_comment(content, decl_start).is_none());
    }

    #[test]
    fn extract_doc_comment_skips_python_shebang() {
        let content = "#!/usr/bin/env python\ndef foo():\n    pass\n";
        let decl_start = content.find("def foo").expect("decl");
        assert!(extract_leading_doc_comment(content, decl_start).is_none());
    }

    #[test]
    fn extract_doc_comment_skips_bare_double_slash() {
        // Plain `//` lines (license headers, TODOs, commented-out code) must
        // not be lifted into hover — only `///` and `//!` are doc comments.
        let content =
            "// SPDX-License-Identifier: MIT\n// Copyright 2026.\npub fn first_function() {}\n";
        let decl_start = content.find("pub fn first_function").expect("decl");
        assert!(extract_leading_doc_comment(content, decl_start).is_none());
    }

    #[test]
    fn extract_doc_comment_skips_pointer_deref() {
        // A C-style `*ptr;` line must not be treated as a Javadoc continuation.
        let content = "*ptr_value;\nint bar() { return 0; }\n";
        let decl_start = content.find("int bar").expect("decl");
        assert!(extract_leading_doc_comment(content, decl_start).is_none());
    }

    #[test]
    fn extract_doc_comment_stops_at_blank_line() {
        // A blank gap between the comment block and the declaration breaks
        // the association — the comment is documenting something else.
        let content = "/// Old comment.\n\nfn current() {}\n";
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
