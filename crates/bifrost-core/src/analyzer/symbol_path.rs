//! Splitting a client-typed symbol selector into path segments.
//!
//! This is the one place a `Foo::bar` / `Foo.bar` / `pkg/Type+Method` selector
//! is turned into segments, and the one place a segment is normalized back to
//! the spelling the declaration index uses. Both halves are pure string work
//! over [`Language`]; nothing here reads a tree, an analyzer, or a store.
//!
//! It lives in core rather than in a language crate because the operation is
//! inherently multi-language: one selector string is split by the same
//! delimiter rules regardless of language, and only the per-segment
//! normalization differs. The language crates that resolve Rust use-paths and
//! Go selectors sit above core and cannot each own a private copy without
//! reintroducing exactly the source-text mini-parsers the project forbids.

use crate::analyzer::Language;

/// Split a client-typed symbol selector into path segments, normalizing each
/// segment to the spelling the declaration index uses.
///
/// Delimiters are `::`, `.`, `\`, `/` and `+`; a leading `\` run is dropped.
/// C++ `operator` tokens are kept whole so `operator==` does not split.
pub fn parse_symbol_path(language: Language, value: &str) -> Vec<String> {
    let trimmed = value.trim().trim_start_matches('\\');
    let mut segments = Vec::new();
    let mut current = String::new();
    let mut chars = trimmed.char_indices().peekable();

    while let Some((index, ch)) = chars.next() {
        let rest = &trimmed[index..];
        if language == Language::Cpp
            && let Some(operator) = cpp_operator_token(rest, current.is_empty())
        {
            current.push_str(operator);
            for _ in operator.chars().skip(1) {
                chars.next();
            }
            continue;
        }

        if rest.starts_with("::") {
            flush_segment(language, &mut current, &mut segments);
            chars.next();
            continue;
        }

        if matches!(ch, '.' | '\\' | '/' | '+') {
            flush_segment(language, &mut current, &mut segments);
            continue;
        }

        current.push(ch);
    }
    flush_segment(language, &mut current, &mut segments);

    segments
}

fn cpp_operator_token(value: &str, at_segment_start: bool) -> Option<&str> {
    if !at_segment_start || !value.starts_with("operator") {
        return None;
    }

    let suffix = &value["operator".len()..];
    if suffix.starts_with("()") {
        return Some(&value[.."operator()".len()]);
    }

    let mut end = "operator".len();
    for (offset, ch) in suffix.char_indices() {
        if offset == 0 && ch.is_whitespace() {
            break;
        }
        if offset > 0 && is_symbol_path_delimiter_at(&suffix[offset..]) {
            break;
        }
        end = "operator".len() + offset + ch.len_utf8();
    }
    Some(&value[..end])
}

fn is_symbol_path_delimiter_at(value: &str) -> bool {
    value.starts_with("::")
        || value
            .chars()
            .next()
            .is_some_and(|ch| matches!(ch, '.' | '\\' | '/' | '+'))
}

fn flush_segment(language: Language, current: &mut String, segments: &mut Vec<String>) {
    let trimmed = current.trim();
    if !trimmed.is_empty() {
        segments.push(normalized_client_symbol_segment(language, trimmed));
    }
    current.clear();
}

fn normalized_client_symbol_segment(language: Language, segment: &str) -> String {
    // This normalizes client-provided symbol selector text, not Go source.
    // Go declaration extraction already uses tree-sitter receiver nodes and
    // indexes pointer receiver methods canonically as `Type.Method`.
    if language == Language::Go {
        return normalized_go_client_symbol_segment(segment);
    }

    // Rust declarations are indexed under the canonical (un-escaped) name --
    // `r#` is raw-identifier escape syntax, not part of the identifier
    // (#1128) -- so a client-typed segment carrying the escape (`r#type`,
    // copy-pasted from an old display or from source) must alias to the
    // same canonical segment (`type`) the index uses. Only the identifier's
    // own `r#` prefix is stripped; this operates on one already-flushed
    // selector segment, never a larger path or arbitrary text.
    if language == Language::Rust {
        return strip_raw_identifier_prefix(segment).to_string();
    }

    segment.to_string()
}

/// Strip the `r#` raw-identifier escape prefix, if present.
///
/// `r#` is escape syntax, not part of the identifier's canonical name -- this
/// is how rustc/rust-analyzer treat raw identifiers, and it is the single
/// normalization rule declaration short_names/fq_names and reference/member
/// text must agree on for a raw-identifier declaration (`r#type`) and its
/// plain spelling (`type`) to resolve to the same symbol. Apply this only to
/// text already known to be a single identifier token -- never as a blanket
/// string replace over a larger span, where the two characters `r#` could
/// legitimately appear inside a string literal or doc comment that must not
/// change.
pub fn strip_raw_identifier_prefix(text: &str) -> &str {
    text.strip_prefix("r#").unwrap_or(text)
}

/// Normalize one Go client-typed selector segment to the receiver-type
/// spelling the declaration index uses (`(*T) M` and `(T) M` both index as
/// `T.M`).
pub fn normalized_go_client_symbol_segment(segment: &str) -> String {
    let receiver = segment.trim();
    let receiver = go_receiver_type_segment(receiver).unwrap_or(receiver);
    let base = receiver
        .split_once('[')
        .map(|(base, _)| base.trim())
        .unwrap_or(receiver);

    if base.is_empty() {
        segment.to_string()
    } else {
        base.to_string()
    }
}

fn go_receiver_type_segment(segment: &str) -> Option<&str> {
    let inner = segment.strip_prefix('(')?.strip_suffix(')')?.trim();
    let receiver = inner.strip_prefix('*').unwrap_or(inner).trim();
    if receiver.is_empty() {
        return None;
    }

    let Some(type_start) = receiver.find(char::is_whitespace) else {
        return Some(receiver);
    };

    let receiver_type = receiver[type_start..].trim();
    if receiver_type.is_empty() {
        return None;
    }
    Some(receiver_type.strip_prefix('*').unwrap_or(receiver_type))
}
