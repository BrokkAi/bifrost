pub use brokk_bifrost_core::analyzer::common::{language_for_file, language_for_target};
pub(crate) use brokk_bifrost_core::analyzer::common::{node_source_text, node_source_text_trimmed};

use crate::analyzer::{CodeUnit, Language, ProjectFile};
use std::path::Path;
use tree_sitter::Node;

/// Default longest single line a source file may contain before tree-sitter parsing is
/// skipped. Minified/generated single-line bundles (committed webpack output, mermaid.min.js,
/// etc.) have 16KB+ lines and otherwise both livelock the parser and explode downstream
/// consumers (e.g. the semantic indexer extracting thousands of bogus chunks). Hand-written
/// and normally-formatted generated source stays far below this, so the cap is effectively
/// invisible to real code. 16000 is comfortably above any human-authored line while still
/// catching moderately-sized minified bundles that a higher cap would let through.
pub(crate) const DEFAULT_MAX_LINE_LENGTH: usize = 16_000;

/// Longest single line a source file may contain before tree-sitter parsing is skipped.
/// Defaults to [`DEFAULT_MAX_LINE_LENGTH`]; `BIFROST_MAX_LINE_LENGTH` overrides it, and an
/// explicit `0` disables the limit entirely (parse everything, at your own risk).
pub(crate) fn max_line_length_limit() -> Option<usize> {
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
pub(crate) fn parse_source_region(
    language: &tree_sitter::Language,
    source: &str,
    start: usize,
    end: usize,
) -> Option<tree_sitter::Tree> {
    if start >= end
        || end > source.len()
        || !source.is_char_boundary(start)
        || !source.is_char_boundary(end)
    {
        return None;
    }
    let bytes = source.as_bytes();
    let start_point = advance_ts_point(bytes, tree_sitter::Point { row: 0, column: 0 }, 0, start);
    let end_point = advance_ts_point(bytes, start_point, start, end);
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(language).ok()?;
    parser
        .set_included_ranges(&[tree_sitter::Range {
            start_byte: start,
            end_byte: end,
            start_point,
            end_point,
        }])
        .ok()?;
    parser.parse(source, None)
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

pub(crate) fn rebase_project_file_to_root(file: &ProjectFile, root: &Path) -> Option<ProjectFile> {
    if file.root() == root {
        return Some(file.clone());
    }
    let abs_path = file.abs_path();
    let rel = if let Ok(rel) = abs_path.strip_prefix(root) {
        rel.to_path_buf()
    } else {
        let canonical_abs = abs_path.canonicalize().ok()?;
        let canonical_root = root.canonicalize().ok()?;
        canonical_abs
            .strip_prefix(canonical_root)
            .ok()?
            .to_path_buf()
    };
    Some(ProjectFile::new(root.to_path_buf(), rel))
}

pub(crate) fn display_symbol_name(language: Language, symbol: &str) -> String {
    crate::analyzer::languages::language_support(language).map_or_else(
        || symbol.to_string(),
        |support| support.display_symbol_name(symbol),
    )
}

pub fn display_symbol_for_target(target: &CodeUnit) -> String {
    display_symbol_name(language_for_target(target), &target.fq_name())
}

/// The display symbol of the code unit's enclosing scope (the receiver/declaring type for
/// a method, the outer type for a nested type), or `None` for a top-level declaration.
///
/// Methods are not always lexically nested in their type (Go receivers, Rust `impl`,
/// C++ out-of-line definitions), so consumers can't reliably reconstruct the parent from
/// line spans. The hierarchy is encoded in `short_name` (members after `.`, nested types
/// via `$`), so we strip the last segment and re-qualify with the package.
pub(crate) fn display_parent_symbol_for_target(target: &CodeUnit) -> Option<String> {
    let short_storage;
    let short = if language_for_target(target) == Language::TypeScript {
        short_storage = target
            .short_name()
            .strip_suffix("$static")
            .unwrap_or(target.short_name())
            .to_string();
        short_storage.as_str()
    } else {
        target.short_name()
    };
    let cut = short.rfind(['.', '$'])?; // fqname-M4: parent-of on the raw short_name string; runs on targets whose fq is not threaded to this display helper
    let parent_short = &short[..cut];
    if parent_short.is_empty() {
        return None;
    }
    let package = target.package_name();
    let parent_fq = if package.is_empty() {
        parent_short.to_string()
    } else {
        format!("{package}.{parent_short}")
    };
    Some(display_symbol_name(language_for_target(target), &parent_fq))
}

pub fn display_identifier_for_target(target: &CodeUnit) -> String {
    let display_name = display_symbol_name(language_for_target(target), target.short_name());
    display_name
        .rsplit('.')
        .next()
        .unwrap_or(&display_name)
        .to_string()
}

pub fn source_identifier_for_target(target: &CodeUnit) -> &str {
    let identifier = target.identifier();
    crate::analyzer::languages::language_support(language_for_target(target))
        .map_or(identifier, |support| support.source_identifier(identifier))
}

pub(crate) fn is_valid_rename_identifier(language: Language, name: &str) -> bool {
    is_identifier_text(name) && !is_reserved_identifier(language, name)
}

fn is_identifier_text(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first == '_' || first.is_alphabetic()) && chars.all(|ch| ch == '_' || ch.is_alphanumeric())
}

fn is_reserved_identifier(language: Language, name: &str) -> bool {
    let Some(parser_language) = super::parser_language_for(language) else {
        return false;
    };
    (0..parser_language.node_kind_count()).any(|id| {
        let Ok(id) = u16::try_from(id) else {
            return false;
        };
        !parser_language.node_kind_is_named(id)
            && parser_language.node_kind_for_id(id) == Some(name)
    })
}

/// Whether `kind` is one of tree-sitter-rust's identifier leaf node kinds.
/// `identifier`, `field_identifier`, `type_identifier`, and
/// `shorthand_field_identifier` are all grammar aliases of the exact same
/// lexical rule (`/(r#)?[_\p{XID_Start}][_\p{XID_Continue}]*/`), so any of
/// them can carry the `r#` raw-identifier escape prefix verbatim in their
/// token text. Compound path nodes (`scoped_identifier`,
/// `scoped_type_identifier`) are deliberately excluded: callers read those by
/// walking to their constituent identifier-kind children (the `path`/`name`
/// fields), never by string-splitting the whole node text, so each segment's
/// text is normalized individually when it is itself read as one of the leaf
/// kinds above.
pub(crate) fn rust_identifier_like_node_kind(kind: &str) -> bool {
    matches!(
        kind,
        "identifier" | "field_identifier" | "type_identifier" | "shorthand_field_identifier"
    )
}

/// Strip the `r#` raw-identifier escape prefix, if present.
///
/// `r#` is escape syntax, not part of the identifier's canonical name — this
/// is how rustc/rust-analyzer treat raw identifiers, and it is the single
/// normalization rule declaration short_names/fq_names and reference/member
/// text must agree on for a raw-identifier declaration (`r#type`) and its
/// plain spelling (`type`) to resolve to the same symbol. Apply this only to
/// text already known to be a single identifier token (e.g. gated by
/// [`rust_identifier_like_node_kind`]) — never as a blanket string replace
/// over a larger span, where the two characters `r#` could legitimately
/// appear inside a string literal or doc comment that must not change.
pub(crate) fn strip_raw_identifier_prefix(text: &str) -> &str {
    text.strip_prefix("r#").unwrap_or(text)
}

/// One unit of pending skeleton-rendering work.
enum SkeletonWork {
    /// Emit `unit`'s signatures, then enqueue its children.
    Render { unit: CodeUnit, indent: String },
    /// Emit the trailing `[...]` elision marker and/or closing brace that
    /// follow a unit's children.
    Close {
        indent: String,
        child_indent: String,
        elide: bool,
        close_brace: bool,
    },
}

/// Render `code_unit`'s skeleton — its signature, then its children indented
/// beneath it, closing class-like units with `}`.
///
/// `header_only` keeps just the field children and marks the elided remainder
/// with `[...]`.
///
/// Shared by the language analyzers that override `direct_children` (to hide
/// synthetic units) and therefore cannot use the engine's own renderer, which
/// reads `TreeSitterAnalyzer::direct_children` directly. Dispatching through
/// `&dyn IAnalyzer` here means each analyzer's overrides still apply.
///
/// Iterative rather than recursive: declaration nesting is attacker-controlled
/// (a generated or hostile source file can nest types thousands deep), so a
/// recursive walk risks exhausting the native stack.
pub(crate) fn render_skeleton(
    analyzer: &dyn crate::analyzer::IAnalyzer,
    code_unit: &CodeUnit,
    header_only: bool,
) -> String {
    let mut out = String::new();
    let mut stack = vec![SkeletonWork::Render {
        unit: code_unit.clone(),
        indent: String::new(),
    }];

    while let Some(work) = stack.pop() {
        match work {
            SkeletonWork::Render { unit, indent } => {
                for signature in analyzer.signatures(&unit) {
                    if signature.is_empty() {
                        continue;
                    }
                    for line in signature.lines() {
                        out.push_str(&indent);
                        out.push_str(line);
                        out.push('\n');
                    }
                }

                let all_children = analyzer.direct_children(&unit);
                let all_child_count = all_children.len();
                let is_class = unit.is_class();
                let children: Vec<CodeUnit> = if header_only {
                    all_children
                        .into_iter()
                        .filter(CodeUnit::is_field)
                        .collect()
                } else {
                    all_children
                };

                if children.is_empty() && !is_class {
                    continue;
                }
                let child_indent = format!("{indent}  ");
                // Pushed before the children so it pops after them. The
                // elision marker compares against the pre-filter child count,
                // so it fires exactly when `header_only` dropped something.
                stack.push(SkeletonWork::Close {
                    indent,
                    child_indent: child_indent.clone(),
                    elide: header_only && all_child_count > children.len(),
                    close_brace: is_class,
                });
                for child in children.into_iter().rev() {
                    stack.push(SkeletonWork::Render {
                        unit: child,
                        indent: child_indent.clone(),
                    });
                }
            }
            SkeletonWork::Close {
                indent,
                child_indent,
                elide,
                close_brace,
            } => {
                if elide {
                    out.push_str(&child_indent);
                    out.push_str("[...]\n");
                }
                if close_brace {
                    out.push_str(&indent);
                    out.push_str("}\n");
                }
            }
        }
    }

    out
}

/// `text` with every whitespace run collapsed to a single space and the ends
/// trimmed.
///
/// Used to render a multi-line source header (a class or callable signature)
/// as one stable line.
pub(crate) fn collapse_whitespace(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for token in text.split_whitespace() {
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(token);
    }
    out
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
pub(crate) struct IdentifierSigil {
    pub(crate) is_identifier_kind: fn(&str) -> bool,
    pub(crate) prefix: &'static str,
}

/// tree-sitter-rust raw-identifier normalization (`r#type` -> `type`), gated to
/// the identifier leaf kinds (see [`rust_identifier_like_node_kind`]).
pub(crate) const RUST_IDENTIFIER_SIGIL: IdentifierSigil = IdentifierSigil {
    is_identifier_kind: rust_identifier_like_node_kind,
    prefix: "r#",
};

/// Whether `kind` is tree-sitter-c-sharp's identifier leaf kind. C# spells its
/// verbatim-identifier escape as a leading `@` (`@class`), carried verbatim in
/// the `identifier` token text; no other node kind carries an `@` that denotes
/// an identifier (verbatim strings are `verbatim_string_literal`, interpolated
/// strings and attributes are their own kinds), so gating here keeps the sigil
/// strip off those spans.
fn csharp_identifier_like_node_kind(kind: &str) -> bool {
    kind == "identifier"
}

/// tree-sitter-c-sharp verbatim-identifier normalization (`@class` -> `class`),
/// gated to the identifier leaf kind. This is the same normalization the
/// declaration side already applies when building short/fq names, shared here so
/// the reference/get-definition side agrees (previously it did not — issue-1128
/// class inconsistency).
pub(crate) const CSHARP_IDENTIFIER_SIGIL: IdentifierSigil = IdentifierSigil {
    is_identifier_kind: csharp_identifier_like_node_kind,
    prefix: "@",
};

/// Node text with a language identifier sigil normalized off.
///
/// Slices `node`'s source (empty on a bad range), optionally trims, then strips
/// `sigil.prefix` iff `node`'s kind satisfies `sigil.is_identifier_kind`. This
/// is the one place the sigil-normalization invariant lives; the per-surface
/// (declaration / graph / get-definition) copies delegate here so they cannot
/// drift out of agreement.
pub(crate) fn node_ident_text<'a>(
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

pub(crate) fn is_scala_object_like(target: &CodeUnit) -> bool {
    language_for_target(target) == Language::Scala && (target.is_class() || target.is_module()) && {
        // A `.`-joined short_name segment "ending in `$`" is exactly a
        // Scala companion-object segment: Scala's only `$`-spelling is
        // the `Companion` kind's trailing suffix on its own segment text
        // (never a join, and Scala never emits `Nested`), so walking the
        // unit's structured `fq()` for a `Companion` segment reproduces
        // the string check exactly without re-splitting the rendered name.
        let interner = crate::analyzer::fq_name::segment_interner();
        target
            .fq()
            .segments()
            .iter()
            .any(|&id| interner.resolve(id).1 == crate::analyzer::fq_name::SegmentKind::Companion)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DEFAULT_MAX_LINE_LENGTH, display_symbol_name, is_unparseable_source,
        is_valid_rename_identifier,
    };
    use crate::analyzer::Language;

    #[test]
    fn minified_and_binary_sources_are_unparseable_by_default() {
        // Assumes BIFROST_MAX_LINE_LENGTH is unset (the normal test environment), so the
        // default cap applies. A single line past the cap = minified bundle = skip.
        let minified = format!("var x=1;{}", "a".repeat(DEFAULT_MAX_LINE_LENGTH + 1));
        assert!(is_unparseable_source(&minified));

        // Normal multi-line source stays parseable.
        let normal: String = (0..2000).map(|i| format!("let v{i} = {i};\n")).collect();
        assert!(!is_unparseable_source(&normal));

        // NUL bytes => binary => unparseable regardless of line length.
        assert!(is_unparseable_source("fn main() {\0}"));
    }

    #[test]
    fn display_symbol_name_normalizes_scala_and_csharp_user_facing_names() {
        assert_eq!(
            "ai.brokk.ir.PrimOp.AsClockOp",
            display_symbol_name(Language::Scala, "ai.brokk.ir$.PrimOp$.AsClockOp$")
        );
        assert_eq!(
            "N.Outer.Inner.Method",
            display_symbol_name(Language::CSharp, "N.Outer$Inner.Method")
        );
    }

    #[test]
    fn rename_identifier_validation_uses_language_grammar_keywords() {
        assert!(is_valid_rename_identifier(Language::Java, "renamed_1"));
        assert!(is_valid_rename_identifier(Language::Java, "café"));
        assert!(!is_valid_rename_identifier(Language::Java, ""));
        assert!(!is_valid_rename_identifier(Language::Java, "1renamed"));
        assert!(!is_valid_rename_identifier(Language::Java, "renamed-name"));
        assert!(!is_valid_rename_identifier(Language::Java, "class"));
        assert!(!is_valid_rename_identifier(Language::Cpp, "namespace"));
        assert!(!is_valid_rename_identifier(Language::Python, "def"));
        assert!(!is_valid_rename_identifier(Language::Rust, "fn"));
    }
}
