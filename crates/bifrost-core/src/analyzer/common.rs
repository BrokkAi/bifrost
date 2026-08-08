//! The language-blind half of the analyzer's shared helpers.
//!
//! Everything here is decided by a path extension or a byte range, so none of
//! it needs a grammar, an analyzer handle, or a store. The language-aware rest
//! of `analyzer::common` stays in `brokk-bifrost-analysis` and re-exports these
//! at their original paths.

use tree_sitter::Node;

use crate::analyzer::structural::facts::Span;
use crate::analyzer::{CodeUnit, Language, ProjectFile};
use crate::cancellation::CancellationToken;

/// The byte span a tree-sitter node covers, in the shared structural span
/// shape. Adapters use this to record token anchors (e.g. an import's binder
/// token) on parser-derived models.
pub fn node_span(node: Node<'_>) -> Span {
    Span {
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
    }
}

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

/// Whether no analyzable language claims this file's extension.
///
/// This is the eligibility rule for include-driven language inference (#1837):
/// an analyzer may adopt a workspace file its own sources reference only when
/// the static extension registry leaves that file unowned, so inference can
/// never take a file away from the language whose extension list names it.
/// A file with no extension at all qualifies, because no extension list can
/// name it.
///
/// [`Language::is_source_extension`] is the whole registry, reference-only
/// sibling extensions included, so a `.vue` or `.razor` file stays unclaimable
/// even though no analyzer parses it directly.
pub fn has_unclaimed_extension(file: &ProjectFile) -> bool {
    match file.rel_path().extension().and_then(|ext| ext.to_str()) {
        Some(extension) => !Language::is_source_extension(extension),
        None => true,
    }
}

/// Default longest single line a source file may contain before tree-sitter parsing is
/// skipped. Minified/generated single-line bundles (committed webpack output, mermaid.min.js,
/// etc.) have 16KB+ lines and otherwise both livelock the parser and explode downstream
/// consumers (e.g. the semantic indexer extracting thousands of bogus chunks). Hand-written
/// and normally-formatted generated source stays far below this, so the cap is effectively
/// invisible to real code. 16000 is comfortably above any human-authored line while still
/// catching moderately-sized minified bundles that a higher cap would let through.
pub const DEFAULT_MAX_LINE_LENGTH: usize = 16_000;

/// Longest single line a source file may contain before tree-sitter parsing is skipped.
/// Defaults to [`DEFAULT_MAX_LINE_LENGTH`]; `BIFROST_MAX_LINE_LENGTH` overrides it, and an
/// explicit `0` disables the limit entirely (parse everything, at your own risk).
pub fn max_line_length_limit() -> Option<usize> {
    match std::env::var("BIFROST_MAX_LINE_LENGTH") {
        Ok(v) => match v.trim().parse::<usize>() {
            Ok(0) => None,
            Ok(n) => Some(n),
            Err(_) => Some(DEFAULT_MAX_LINE_LENGTH),
        },
        Err(_) => Some(DEFAULT_MAX_LINE_LENGTH),
    }
}

/// Whether `source` must NOT be handed to tree-sitter: it is binary (contains NUL
/// bytes) or pathological for the parser (a line longer than the configured cap).
/// Centralizes the "is this safe to parse?" decision for every parse site so no
/// consumer livelocks on adversarial input.
pub fn is_unparseable_source(source: &str) -> bool {
    if source.as_bytes().contains(&0) {
        return true;
    }
    match max_line_length_limit() {
        Some(limit) => source.lines().any(|line| line.len() > limit),
        None => false,
    }
}

/// `text` with every whitespace run collapsed to a single space and the ends
/// trimmed.
///
/// Used to render a multi-line source header (a class or callable signature)
/// as one stable line.
pub fn collapse_whitespace(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for token in text.split_whitespace() {
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(token);
    }
    out
}

/// Verbatim source text spanned by `node`, or `""` when the byte range is not a
/// valid `str` boundary (adversarial or partially-parsed input).
///
/// This is the single "slice a node's bytes" primitive. It replaces the
/// per-language `source.get(node.byte_range()).unwrap_or("")` copies and the
/// panicking `&source[node.byte_range()]` slicers (bad ranges now yield `""`
/// instead of panicking). Use [`node_source_text_trimmed`] when surrounding
/// whitespace must be dropped, and [`node_ident_text`] when a language sigil
/// (`r#`, `@`) must be normalized off identifier tokens.
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

/// Per-language identifier sigil: which tree-sitter node kinds are single
/// identifier tokens, and the escape/sigil `prefix` (`r#` in Rust, `@` in C#)
/// to strip from those tokens so identity text (short/fq names) and
/// reference/member text agree on the canonical spelling.
///
/// Stripping is gated on `is_identifier_kind`: the sigil is only removed from
/// genuine identifier leaf nodes, never from spans where the same character is
/// meaningful (C# `@"..."` verbatim strings, attribute markers, larger token
/// runs). See [`node_ident_text`].
///
/// The mechanism is language-blind and lives here; each sigil constant is
/// language knowledge and lives with its language (Rust's in
/// `brokk-bifrost-rust`, C#'s still in `brokk-bifrost-analysis`).
pub struct IdentifierSigil {
    pub is_identifier_kind: fn(&str) -> bool,
    pub prefix: &'static str,
}

/// Node text with a language identifier sigil normalized off.
///
/// Slices `node`'s source (empty on a bad range), optionally trims, then strips
/// `sigil.prefix` iff `node`'s kind satisfies `sigil.is_identifier_kind`. This
/// is the one place the sigil-normalization invariant lives; the per-surface
/// (declaration / graph / get-definition) copies delegate here so they cannot
/// drift out of agreement.
pub fn node_ident_text<'a>(
    node: Node<'_>,
    source: &'a str,
    trim: bool,
    sigil: &IdentifierSigil,
) -> &'a str {
    let raw = source.get(node.byte_range()).unwrap_or("");
    let text = if trim { raw.trim() } else { raw };
    if (sigil.is_identifier_kind)(node.kind()) {
        text.strip_prefix(sigil.prefix).unwrap_or(text)
    } else {
        text
    }
}

/// Parse only `[start, end)` of `source` as `language`, confining the parser to
/// that region via tree-sitter included ranges. Every node keeps its original
/// byte offset and line/column position, exactly like the historical
/// "padded copy" technique (issues #941/#1015), but without materializing an
/// O(file) whitespace prefix or making the lexer walk it -- on a large file with
/// a region near the end that padding turned each recovery reparse into seconds
/// of whitespace lexing (issue #1309's cold-start profile).
///
/// Returns `None` for an empty or invalid region (out of bounds, or not on
/// char boundaries), mirroring the padded implementations' refusal to build a
/// reparse for nothing.
pub fn parse_source_region(
    language: &tree_sitter::Language,
    source: &str,
    start: usize,
    end: usize,
) -> Option<tree_sitter::Tree> {
    parse_source_region_with_cancellation(language, source, start, end, None)
}

/// Cancellation-aware form of [`parse_source_region`].
pub fn parse_source_region_with_cancellation(
    language: &tree_sitter::Language,
    source: &str,
    start: usize,
    end: usize,
    cancellation: Option<&CancellationToken>,
) -> Option<tree_sitter::Tree> {
    if start >= end
        || end > source.len()
        || !source.is_char_boundary(start)
        || !source.is_char_boundary(end)
        || cancellation.is_some_and(CancellationToken::is_cancelled)
    {
        return None;
    }
    let bytes = source.as_bytes();
    let start_point = advance_ts_point(bytes, tree_sitter::Point { row: 0, column: 0 }, 0, start);
    let end_point = advance_ts_point(bytes, start_point, start, end);
    parse_source_range_with_cancellation(
        language,
        source,
        tree_sitter::Range {
            start_byte: start,
            end_byte: end,
            start_point,
            end_point,
        },
        cancellation,
    )
}

/// Parse one parser-provided source range without recomputing its points.
pub fn parse_source_range_with_cancellation(
    language: &tree_sitter::Language,
    source: &str,
    range: tree_sitter::Range,
    cancellation: Option<&CancellationToken>,
) -> Option<tree_sitter::Tree> {
    if range.start_byte >= range.end_byte
        || range.end_byte > source.len()
        || !source.is_char_boundary(range.start_byte)
        || !source.is_char_boundary(range.end_byte)
        || cancellation.is_some_and(CancellationToken::is_cancelled)
    {
        return None;
    }
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(language).ok()?;
    parser.set_included_ranges(&[range]).ok()?;
    if let Some(cancellation) = cancellation {
        let mut read = |offset: usize, _| &source.as_bytes()[offset..];
        let mut progress = |_: &tree_sitter::ParseState| cancellation.is_cancelled();
        parser.parse_with_options(
            &mut read,
            None,
            Some(tree_sitter::ParseOptions::new().progress_callback(&mut progress)),
        )
    } else {
        parser.parse(source, None)
    }
}

/// Advance `point` across `bytes[from..to]`. Tree-sitter columns count bytes.
fn advance_ts_point(
    bytes: &[u8],
    point: tree_sitter::Point,
    from: usize,
    to: usize,
) -> tree_sitter::Point {
    let slice = &bytes[from..to];
    match slice.iter().rposition(|&b| b == b'\n') {
        None => tree_sitter::Point {
            row: point.row,
            column: point.column + slice.len(),
        },
        Some(last_newline) => tree_sitter::Point {
            row: point.row + slice.iter().filter(|&&b| b == b'\n').count(),
            column: slice.len() - last_newline - 1,
        },
    }
}
