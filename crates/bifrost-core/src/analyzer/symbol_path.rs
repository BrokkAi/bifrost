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
use crate::analyzer::fq_name::{FqName, SegmentInterner, SegmentKind};

/// Split a client-typed symbol selector into path segments, normalizing each
/// segment to the spelling the declaration index uses.
///
/// Delimiters are `::`, `.`, `\`, `/` and `+`; a leading `\` run is dropped.
/// C++ `operator` tokens are kept whole so `operator==` does not split.
/// In the languages that quote identifiers with backticks
/// ([`backtick_quotes_identifiers`]) a backtick opens a quoted run in which
/// every delimiter is literal, so Scala's `` scalaz.`zio.ZIO` `` is two
/// segments and not four.
pub fn parse_symbol_path(language: Language, value: &str) -> Vec<String> {
    // Emptiness is decided after normalization, not before it: a Rust segment
    // typed as nothing but the raw-identifier escape (`r#`) normalizes to
    // nothing, and a segment is by definition a non-empty run. Emitting it
    // would put an empty component in the string path and, via
    // `parse_symbol_path_fq`, an empty segment text into the interner, which
    // rejects it.
    symbol_path_segments(language, value)
        .into_iter()
        .map(|segment| normalized_client_symbol_segment(language, segment))
        .filter(|segment| !segment.is_empty())
        .collect()
}

/// The same split as [`parse_symbol_path`], before per-language segment
/// normalization: each segment is a trimmed, non-empty subslice of `value`.
///
/// A consumer that only needs to *read* one component -- the leading name of a
/// source type text, say -- takes it from here instead of writing its own
/// `split('.')`, which is what put four segments in a backtick-quoted Scala
/// name (#2219).
pub fn symbol_path_segments(language: Language, value: &str) -> Vec<&str> {
    let text = value.trim().trim_start_matches('\\');
    let mut segments = Vec::new();
    // The byte range of the run in progress. Every segment is a contiguous
    // subslice of `text`: nothing here rewrites a character, it only decides
    // where a run ends.
    let mut run: Option<(usize, usize)> = None;
    let mut chars = text.char_indices().peekable();
    let mut inside_backticks = false;

    while let Some((index, ch)) = chars.next() {
        let rest = &text[index..];

        if backtick_quotes_identifiers(language) {
            if inside_backticks {
                // Inside the quoted run every delimiter is part of the name.
                // An unterminated run therefore ends at the end of the input:
                // one forward pass, no lookahead, and the run always carries at
                // least its opening backtick, so it can never flush an empty
                // segment.
                extend_run(&mut run, index, ch.len_utf8());
                inside_backticks = ch != '`';
                continue;
            }
            // A backtick quotes a whole identifier, so it only opens a run at a
            // segment boundary; anywhere else it is an ordinary character.
            if ch == '`' && run.is_none_or(|(start, end)| text[start..end].trim().is_empty()) {
                extend_run(&mut run, index, ch.len_utf8());
                inside_backticks = true;
                continue;
            }
        }

        if language == Language::Cpp
            && let Some(operator) = cpp_operator_token(rest, run.is_none())
        {
            extend_run(&mut run, index, operator.len());
            for _ in operator.chars().skip(1) {
                chars.next();
            }
            continue;
        }

        if rest.starts_with("::") {
            flush_run(text, &mut run, &mut segments);
            chars.next();
            continue;
        }

        if matches!(ch, '.' | '\\' | '/' | '+') {
            flush_run(text, &mut run, &mut segments);
            continue;
        }

        extend_run(&mut run, index, ch.len_utf8());
    }
    flush_run(text, &mut run, &mut segments);

    segments
}

fn extend_run(run: &mut Option<(usize, usize)>, index: usize, len: usize) {
    match run {
        Some((_, end)) => *end = index + len,
        None => *run = Some((index, index + len)),
    }
}

fn flush_run<'a>(text: &'a str, run: &mut Option<(usize, usize)>, segments: &mut Vec<&'a str>) {
    let Some((start, end)) = run.take() else {
        return;
    };
    let segment = text[start..end].trim();
    if !segment.is_empty() {
        segments.push(segment);
    }
}

/// Whether a backtick quotes an identifier in this language's grammar.
///
/// Scala and Kotlin both let any identifier be written `` `like this` ``, and
/// both let the quoted text carry characters the splitter otherwise reads as
/// delimiters: Scala allows a `.` (scalaz spells a class `` `zio.ZIO` ``),
/// Kotlin allows a space (routine in test method names). No other supported
/// language gives the backtick that meaning -- Go spells raw strings with it
/// and C# spells generic arity with it (`Dictionary`2`) -- so quoting must not
/// be applied to them.
fn backtick_quotes_identifiers(language: Language) -> bool {
    matches!(language, Language::Scala | Language::Kotlin)
}

/// Strip the surrounding backticks from a backtick-quoted identifier.
///
/// Kotlin's declaration walk indexes the quoted name *without* its backticks
/// (`kotlin_identifier_text`), so a selector segment must drop them too or the
/// declaration is unreachable by the only spelling source can write. Scala's
/// walk keeps them -- an indexed `` `zio.ZIO` `` carries the backticks in its
/// interned segment text -- so Scala must not call this.
pub fn strip_backtick_quotes(text: &str) -> &str {
    text.strip_prefix('`')
        .and_then(|text| text.strip_suffix('`'))
        .unwrap_or(text)
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

    // Kotlin indexes a backtick-quoted declaration under the bare name (the
    // backticks are quoting syntax, not part of it), so the selector segment
    // has to shed them to name the same segment text. Scala indexes the quoted
    // spelling verbatim, so its segment is left exactly as typed.
    if language == Language::Kotlin {
        return strip_backtick_quotes(segment).to_string();
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

/// The structured sibling of [`parse_symbol_path`]: split a client-supplied
/// qualified-name path into an [`FqName`], reusing the exact same splitter and
/// per-language segment normalization. Every segment is interned with
/// [`SegmentKind::Unknown`] -- a user types a spelling, not a kind, so input
/// segments carry no kind claim and are matched kind-insensitively against
/// extracted names. Because `Unknown` renders with an ordinary `.` join, the
/// returned `FqName` renders (via `display`/`display_native`) to exactly the
/// canonical `.`-joined spelling that [`parse_symbol_path`]`.join(".")`
/// produces, which is what the string-keyed `definitions` index is keyed by.
/// See the M2 Decision Log in `.agents/plans/fqname-interned-segments.md`.
pub fn parse_symbol_path_fq(language: Language, value: &str, interner: &SegmentInterner) -> FqName {
    let mut fq = FqName::new();
    for segment in parse_symbol_path(language, value) {
        fq.push(interner.intern(&segment, SegmentKind::Unknown));
    }
    fq
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::fq_name::segment_interner;

    /// A segment that is nothing but the Rust raw-identifier escape normalizes
    /// away, and a segment is a non-empty run by definition. Both spellings of
    /// the split must agree on dropping it: the string one so the joined name
    /// has no empty component, the structured one because
    /// `SegmentInterner::intern` rejects an empty segment text. This is
    /// reachable from the MCP input edge, where the selector is whatever a
    /// client typed.
    #[test]
    fn a_segment_that_normalizes_away_is_dropped_by_both_spellings() {
        assert_eq!(
            parse_symbol_path(Language::Rust, "r#"),
            Vec::<String>::new()
        );
        assert_eq!(
            parse_symbol_path(Language::Rust, "krate::r#::r#type"),
            vec!["krate".to_string(), "type".to_string()]
        );

        let fq = parse_symbol_path_fq(Language::Rust, "krate::r#::r#type", segment_interner());
        assert_eq!(fq.display(segment_interner()), "krate.type");
        assert!(parse_symbol_path_fq(Language::Rust, "r#", segment_interner()).is_empty());
    }

    /// Issue #2219. A Scala backtick-quoted name may contain a `.` (scalaz
    /// spells a class `` `zio.ZIO` ``). The declaration walk interns the quoted
    /// spelling verbatim, so the selector must produce that one segment and not
    /// the two nonexistent segments `zio` and `ZIO`.
    #[test]
    fn a_scala_backtick_quoted_name_containing_a_dot_is_one_segment() {
        assert_eq!(
            parse_symbol_path(Language::Scala, "scalaz.`zio.ZIO`"),
            vec!["scalaz".to_string(), "`zio.ZIO`".to_string()]
        );
        assert_eq!(
            parse_symbol_path(Language::Scala, "scalaz.`zio.ZIO`.run"),
            vec![
                "scalaz".to_string(),
                "`zio.ZIO`".to_string(),
                "run".to_string()
            ]
        );

        // A quoted name without a dot, and an unquoted name, keep splitting the
        // way they always did.
        assert_eq!(
            parse_symbol_path(Language::Scala, "scalaz.`Plain`"),
            vec!["scalaz".to_string(), "`Plain`".to_string()]
        );
        assert_eq!(
            parse_symbol_path(Language::Scala, "zio.ZIO"),
            vec!["zio".to_string(), "ZIO".to_string()]
        );
    }

    /// The rendering direction of the same name: an `FqName` parsed from the
    /// selector renders back to the byte-identical selector, which is the
    /// #1189 round trip for a segment that carries a delimiter inside it.
    #[test]
    fn a_scala_backtick_quoted_name_round_trips_through_fq_name() {
        let selector = "scalaz.`zio.ZIO`";
        let fq = parse_symbol_path_fq(Language::Scala, selector, segment_interner());
        assert_eq!(fq.len(), 2);
        assert_eq!(fq.display(segment_interner()), selector);
        assert_eq!(
            fq.display_native(Language::Scala, segment_interner()),
            selector
        );
        assert_eq!(
            parse_symbol_path_fq(
                Language::Scala,
                &fq.display(segment_interner()),
                segment_interner()
            ),
            fq
        );
    }

    /// Kotlin quotes identifiers the same way, and allows a space inside the
    /// quotes (routine in test method names). The quoted run is one segment --
    /// and, because Kotlin's declaration walk indexes the bare name, the
    /// segment normalizes to that bare name.
    #[test]
    fn a_kotlin_backtick_quoted_name_is_one_segment_without_its_quotes() {
        assert_eq!(
            parse_symbol_path(Language::Kotlin, "pkg.`my test`"),
            vec!["pkg".to_string(), "my test".to_string()]
        );
        assert_eq!(
            parse_symbol_path(Language::Kotlin, "pkg.Suite.`resolves a name`"),
            vec![
                "pkg".to_string(),
                "Suite".to_string(),
                "resolves a name".to_string()
            ]
        );
        assert_eq!(
            parse_symbol_path(Language::Kotlin, "pkg.Suite"),
            vec!["pkg".to_string(), "Suite".to_string()]
        );
    }

    /// An unterminated quoted run ends at the end of the input. The rule is one
    /// forward pass with no lookahead, and the run always carries at least its
    /// own opening backtick, so it can never flush an empty segment; falling
    /// back to plain splitting would instead re-shred exactly the name the
    /// quotes were protecting.
    #[test]
    fn an_unterminated_backtick_run_reaches_the_end_of_the_input() {
        assert_eq!(
            parse_symbol_path(Language::Scala, "scalaz.`zio.ZIO"),
            vec!["scalaz".to_string(), "`zio.ZIO".to_string()]
        );
        assert_eq!(
            parse_symbol_path(Language::Scala, "`"),
            vec!["`".to_string()]
        );
        // Kotlin's normalization only sheds a *matched* pair, so an
        // unterminated run keeps its opening backtick rather than emptying.
        assert_eq!(
            parse_symbol_path(Language::Kotlin, "pkg.`my test"),
            vec!["pkg".to_string(), "`my test".to_string()]
        );
        // A quoted run that is empty normalizes away in Kotlin, and
        // `flush_segment` drops it rather than interning an empty segment.
        assert_eq!(
            parse_symbol_path(Language::Kotlin, "pkg.``.Suite"),
            vec!["pkg".to_string(), "Suite".to_string()]
        );
    }

    /// Only Scala and Kotlin give the backtick that meaning. Every other
    /// language splits a stray backtick exactly the way it did before #2219 --
    /// it is an ordinary character carried inside whatever segment it lands in.
    #[test]
    fn other_languages_split_a_stray_backtick_as_an_ordinary_character() {
        assert_eq!(
            parse_symbol_path(Language::Cpp, "ns::`zio.ZIO`::run"),
            vec![
                "ns".to_string(),
                "`zio".to_string(),
                "ZIO`".to_string(),
                "run".to_string()
            ]
        );
        assert_eq!(
            parse_symbol_path(Language::Go, "pkg/`zio.ZIO`"),
            vec!["pkg".to_string(), "`zio".to_string(), "ZIO`".to_string()]
        );
        assert_eq!(
            parse_symbol_path(Language::Python, "mod.`zio.ZIO`"),
            vec!["mod".to_string(), "`zio".to_string(), "ZIO`".to_string()]
        );
        // C# spells generic arity with a backtick; quoting it would fuse the
        // arity marker into the following segment.
        assert_eq!(
            parse_symbol_path(Language::CSharp, "System.Collections.Dictionary`2.Add"),
            vec![
                "System".to_string(),
                "Collections".to_string(),
                "Dictionary`2".to_string(),
                "Add".to_string()
            ]
        );
    }
}
