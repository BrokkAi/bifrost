use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::analyzer::common::language_for_file;
use crate::analyzer::usages::get_definition::{
    DefinitionLookupRequest, DefinitionLookupStatus, parse_tree_for_language,
    resolve_definition_batch_with_source,
};
use crate::analyzer::{CodeUnit, IAnalyzer, Language, Project, ProjectFile, Range as ByteRange};
use crate::lsp::conversion::{
    byte_range_to_lsp_range, path_to_uri_string, position_to_byte_offset, uri_to_path,
};
use crate::text_utils::{compute_line_starts, find_line_index_for_offset};
pub(crate) use crate::text_utils::{
    find_word, identifier_at_offset, identifier_prefix_before_offset, identifier_span_at_offset,
};
use lsp_types::{Location, Position, Range as LspRange, Uri};
use tree_sitter::Node;

const MAX_DOC_COMMENT_SOURCE_BYTES: u64 = 1_000_000;

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

pub(super) struct BroadSymbolTarget {
    pub(super) content: String,
    pub(super) line_starts: Vec<usize>,
    pub(super) start_byte: usize,
    pub(super) end_byte: usize,
    pub(super) candidates: Vec<CodeUnit>,
}

pub(super) fn broad_symbol_target_at_position(
    analyzer: &dyn IAnalyzer,
    project: &dyn Project,
    uri: &Uri,
    position: &Position,
) -> Option<BroadSymbolTarget> {
    let (file, content, line_starts) = read_document_for_uri(project, uri)?;
    let byte_offset = position_to_byte_offset(&content, &line_starts, position);
    let (start_byte, end_byte) = identifier_span_at_offset(&content, byte_offset)?;
    let selected = ByteRange {
        start_byte,
        end_byte,
        start_line: 0,
        end_line: 0,
    };
    let candidates =
        selected_code_unit_declaration_at_cursor(analyzer, &file, &content, &selected, |_| true)
            .map(|declaration| vec![declaration])
            .or_else(|| {
                resolved_reference_candidates(
                    analyzer,
                    &file,
                    Arc::new(content.clone()),
                    start_byte,
                    end_byte,
                )
            })?;

    Some(BroadSymbolTarget {
        content,
        line_starts,
        start_byte,
        end_byte,
        candidates,
    })
}

pub(super) fn selected_code_unit_declaration_at_cursor(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    content: &str,
    cursor_range: &ByteRange,
    predicate: impl Fn(&CodeUnit) -> bool,
) -> Option<CodeUnit> {
    let code_unit = analyzer.enclosing_code_unit(file, cursor_range)?;
    if code_unit.source() != file || !predicate(&code_unit) {
        return None;
    }
    let selection = code_unit_declaration_name_range(analyzer, file, content, &code_unit)?;
    (cursor_range.start_byte >= selection.start_byte
        && cursor_range.start_byte < selection.end_byte)
        .then_some(code_unit)
}

fn code_unit_declaration_name_range(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    content: &str,
    code_unit: &CodeUnit,
) -> Option<ByteRange> {
    let declaration_range = analyzer.ranges(code_unit).iter().min().copied()?;
    let language = language_for_file(file);
    let tree = parse_tree_for_language(file, language, content)?;
    let declaration_node = node_for_exact_range(tree.root_node(), &declaration_range)?;
    let name_node = declaration_name_node(declaration_node, code_unit.identifier(), content)?;
    Some(node_byte_range(name_node))
}

fn node_for_exact_range<'tree>(root: Node<'tree>, range: &ByteRange) -> Option<Node<'tree>> {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.start_byte() == range.start_byte && node.end_byte() == range.end_byte {
            return Some(node);
        }
        if node.start_byte() > range.start_byte || node.end_byte() < range.end_byte {
            continue;
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if child.start_byte() <= range.start_byte && child.end_byte() >= range.end_byte {
                stack.push(child);
            }
        }
    }
    None
}

fn declaration_name_node<'tree>(
    declaration_node: Node<'tree>,
    identifier: &str,
    content: &str,
) -> Option<Node<'tree>> {
    let mut stack = vec![declaration_node];
    while let Some(node) = stack.pop() {
        if let Some(name) = node.child_by_field_name("name")
            && let Some(identifier_node) = matching_identifier_node(name, identifier, content)
        {
            return Some(identifier_node);
        }
        for field in ["declarator", "declaration", "definition"] {
            if let Some(child) = node.child_by_field_name(field) {
                stack.push(child);
            }
        }
    }
    None
}

fn matching_identifier_node<'tree>(
    root: Node<'tree>,
    identifier: &str,
    content: &str,
) -> Option<Node<'tree>> {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.utf8_text(content.as_bytes()).ok()? == identifier {
            return Some(node);
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            stack.push(child);
        }
    }
    None
}

fn node_byte_range(node: Node<'_>) -> ByteRange {
    ByteRange {
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
        start_line: node.start_position().row,
        end_line: node.end_position().row,
    }
}

fn resolved_reference_candidates(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    content: Arc<String>,
    start_byte: usize,
    end_byte: usize,
) -> Option<Vec<CodeUnit>> {
    let outcome = resolve_definition_batch_with_source(
        analyzer,
        vec![DefinitionLookupRequest {
            file: file.clone(),
            line: None,
            column: None,
            start_byte: Some(start_byte),
            end_byte: Some(end_byte),
        }],
        file.clone(),
        content,
    )
    .into_iter()
    .next()?;
    if outcome.status != DefinitionLookupStatus::Resolved || outcome.definitions.is_empty() {
        return None;
    }
    Some(outcome.definitions)
}

#[derive(Default)]
pub(super) struct FileContentCache {
    files: HashMap<PathBuf, FileContent>,
}

pub(super) struct FileContent {
    pub(super) body: String,
    pub(super) line_starts: Vec<usize>,
}

impl FileContentCache {
    pub(super) fn read_project<'a>(
        &'a mut self,
        project: &dyn Project,
        file: &ProjectFile,
    ) -> Option<&'a FileContent> {
        self.read_with(file.abs_path(), || project.read_source(file).ok())
    }

    pub(super) fn read_disk<'a>(&'a mut self, path: &Path) -> Option<&'a FileContent> {
        self.read_with(path.to_path_buf(), || std::fs::read_to_string(path).ok())
    }

    pub(super) fn read_disk_or_empty<'a>(&'a mut self, path: &Path) -> &'a FileContent {
        let key = path.to_path_buf();
        if !self.files.contains_key(&key) {
            let body = std::fs::read_to_string(path).unwrap_or_default();
            let line_starts = compute_line_starts(&body);
            self.files
                .insert(key.clone(), FileContent { body, line_starts });
        }
        self.files.get(&key).expect("cache entry inserted")
    }

    fn read_with(
        &mut self,
        key: PathBuf,
        read: impl FnOnce() -> Option<String>,
    ) -> Option<&FileContent> {
        if !self.files.contains_key(&key) {
            let body = read()?;
            let line_starts = compute_line_starts(&body);
            self.files
                .insert(key.clone(), FileContent { body, line_starts });
        }
        self.files.get(&key)
    }
}

pub(super) fn resolve_identifier_candidates(
    analyzer: &dyn IAnalyzer,
    identifier: &str,
) -> Vec<CodeUnit> {
    let direct: Vec<CodeUnit> = analyzer.get_definitions(identifier);
    if !direct.is_empty() {
        return direct;
    }
    let pattern = short_name_pattern(identifier);
    analyzer
        .search_definitions(&pattern, false)
        .into_iter()
        .filter(|cu| cu.identifier() == identifier)
        .collect()
}

pub(super) fn code_unit_location(
    analyzer: &dyn IAnalyzer,
    project: &dyn Project,
    code_unit: &CodeUnit,
) -> Option<Location> {
    let body = project.read_source(code_unit.source()).ok()?;
    let line_starts = compute_line_starts(&body);
    let range = analyzer
        .ranges(code_unit)
        .iter()
        .min()
        .copied()
        .unwrap_or(ByteRange {
            start_byte: 0,
            end_byte: body.len(),
            start_line: 0,
            end_line: 0,
        });
    let lsp_range = byte_range_to_lsp_range(&body, &line_starts, &range);
    let uri: Uri = path_to_uri_string(&code_unit.source().abs_path())
        .parse()
        .ok()?;
    Some(Location {
        uri,
        range: lsp_range,
    })
}

fn short_name_pattern(identifier: &str) -> String {
    format!(r"\b{}\b", regex::escape(identifier))
}

/// Resolve an LSP `Uri` to a [`ProjectFile`] that belongs to `project`.
/// Returns `None` for non-`file:` URIs or paths outside the project, logging
/// a single-line stderr warning so users debugging "why is my LSP request
/// returning empty" can see the cause.
pub fn project_file_for_uri(project: &dyn Project, uri: &Uri) -> Option<ProjectFile> {
    let abs_path = path_for_file_uri(uri)?;
    if let Some(file) = project_file_for_abs_path(project, &abs_path) {
        return Some(file);
    }
    eprintln!(
        "[bifrost-lsp] ignoring path outside project: {} (root: {})",
        abs_path.display(),
        project.root().display()
    );
    None
}

pub(crate) fn project_file_for_abs_path(
    project: &dyn Project,
    abs_path: &std::path::Path,
) -> Option<ProjectFile> {
    // Canonicalize so Windows extended-length paths (`\\?\C:\…` produced by
    // FilesystemProject's canonicalize) line up with the URI-decoded path
    // (`C:/…`). Fall back to the as-is path when canonicalize fails — for
    // example, didChangeWatchedFiles DELETED events reference paths that no
    // longer exist on disk.
    let canonical = abs_path
        .canonicalize()
        .unwrap_or_else(|_| abs_path.to_path_buf());
    if let Some(file) = project.file_by_abs_path(&canonical) {
        return Some(file);
    }
    if let Some(file) = project.file_by_abs_path(abs_path) {
        return Some(file);
    }
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
    if let Some(canonical) = canonicalize_existing_prefix(&abs_path)
        && canonical != abs_path
        && let Some(file) = project.file_by_abs_path_allow_missing(&canonical)
    {
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

fn canonicalize_existing_prefix(path: &std::path::Path) -> Option<std::path::PathBuf> {
    let mut current = path;
    let mut suffix = std::path::PathBuf::new();

    loop {
        if let Ok(canonical) = current.canonicalize() {
            return Some(canonical.join(suffix));
        }

        let name = current.file_name()?;
        let mut new_suffix = std::path::PathBuf::from(name);
        new_suffix.push(suffix);
        suffix = new_suffix;
        current = current.parent()?;
    }
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
#[cfg(test)]
fn extract_leading_doc_comment(content: &str, decl_start_byte: usize) -> Option<String> {
    extract_leading_doc_comment_impl(content, decl_start_byte, false)
}

fn extract_leading_doc_comment_impl(
    content: &str,
    decl_start_byte: usize,
    allow_bare_double_slash: bool,
) -> Option<String> {
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
        if is_doc_comment_line(stripped, allow_bare_double_slash) {
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

/// Read the candidate's source file and lift any contiguous block of
/// comment-like lines that immediately precedes the declaration. Returns
/// `None` if the file can't be read, the candidate has no recorded range, the
/// source file is too large for an interactive LSP request, or no doc comment
/// is present.
pub fn leading_doc_comment_for_code_unit(
    analyzer: &dyn IAnalyzer,
    candidate: &CodeUnit,
) -> Option<String> {
    let decl_range = analyzer.ranges(candidate).iter().min().copied()?;
    let path = candidate.source().abs_path();
    if std::fs::metadata(&path).ok()?.len() > MAX_DOC_COMMENT_SOURCE_BYTES {
        return None;
    }
    let source = std::fs::read_to_string(path).ok()?;
    let allow_bare_double_slash = language_for_file(candidate.source()) == Language::Go;
    extract_leading_doc_comment_impl(&source, decl_range.start_byte, allow_bare_double_slash)
}

/// True for a single-line Rust outer attribute (e.g. `#[derive(Debug)]`,
/// `#[cfg(test)]`). Multi-line attributes split across lines are intentionally
/// not handled — they're rare in practice and would require bracket-depth
/// tracking to consume safely.
fn is_rust_outer_attribute_line(stripped: &str) -> bool {
    stripped.starts_with("#[") && stripped.trim_end().ends_with(']')
}

fn is_doc_comment_line(stripped: &str, allow_bare_double_slash: bool) -> bool {
    // Bare `//` is too noisy (license headers, TODOs, commented-out code), so
    // require the explicit doc-comment prefixes `///` and `//!`.
    stripped.starts_with("///")
        || stripped.starts_with("//!")
        || (allow_bare_double_slash
            && stripped.starts_with("//")
            && !stripped.starts_with("///")
            && !stripped.starts_with("//!"))
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
    } else if let Some(rest) = trimmed.strip_prefix("//") {
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
    fn extract_doc_comment_rejects_bare_double_slash_by_default() {
        let content = "// Helper function.\nvoid foo() {}\n";
        let decl_start = content.find("void foo").expect("decl");
        assert_eq!(extract_leading_doc_comment(content, decl_start), None);
    }

    #[test]
    fn extract_doc_comment_allows_bare_double_slash_when_requested() {
        let content = "// Helper function.\n// Used by Go docs.\nfunc foo() {}\n";
        let decl_start = content.find("func foo").expect("decl");
        let doc = extract_leading_doc_comment_impl(content, decl_start, true).expect("doc");
        assert_eq!(doc, "Helper function.\nUsed by Go docs.");
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
