//! The vocabulary of one symbol-search request pattern.
//!
//! `searchtools::search_symbols` classifies a request to decide how to rank a
//! declaration, and compares the request with a declaration's names after
//! [`normalize_symbol_name_for_search`] folds every language's qualified-name
//! separator to `.`. The candidate matcher in
//! [`crate::analyzer::SearchSymbolPatternBatch`] has to accept the same
//! spellings or it drops the declarations scoring ranks first (#8697), so both
//! halves read the classification and the separator set from here.

/// How a request pattern is interpreted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchPatternKind {
    /// One name component. Matched against identifiers, short names, and
    /// short-name components.
    LiteralIdentifier,
    /// A qualified name spelled with the separators of some language:
    /// `App\Models\User`, `Outer$Inner`, `ns::C`, `pkg/Thing`, `Outer+Inner`.
    LiteralQualified,
    /// A regular expression, or a pattern whose wildcards make it one.
    RegexLike,
}

/// Classify `pattern` from its characters alone.
///
/// A pattern carrying any character that only means something to a regular
/// expression (`*`, `?`, a group or class delimiter, an alternation, an anchor,
/// or a space) is a regex request. Everything else that carries a
/// qualified-name separator names a qualified declaration; the rest names one
/// component.
pub fn classify_search_pattern(pattern: &str) -> SearchPatternKind {
    if pattern.is_empty() || pattern.chars().any(regex_only_character) {
        return SearchPatternKind::RegexLike;
    }

    if pattern.contains("::") || pattern.chars().any(is_qualified_name_separator) {
        SearchPatternKind::LiteralQualified
    } else {
        SearchPatternKind::LiteralIdentifier
    }
}

/// Characters that make a pattern a regular expression rather than a name.
fn regex_only_character(ch: char) -> bool {
    matches!(
        ch,
        '*' | '?' | '[' | ']' | '(' | ')' | '{' | '}' | '|' | '^' | ' '
    )
}

/// Characters that spell a joined qualified name in some language: C++ and
/// Rust `::`, Java and Scala `$`, C# `+`, PHP `\`, the `/` of a path-anchored
/// selector, and `.`.
///
/// `:` is a separator only as part of `::`; the pair is read before this
/// single-character test.
pub fn is_qualified_name_separator(ch: char) -> bool {
    matches!(ch, '.' | '/' | '\\' | '$' | '+')
}

/// Fold every qualified-name separator to `.` and ASCII case to lower case, so
/// one comparison covers every language's spelling of the same declaration.
pub fn normalize_symbol_name_for_search(symbol: &str) -> String {
    let mut out = String::with_capacity(symbol.len());
    let mut chars = symbol.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            ':' if chars.peek() == Some(&':') => {
                chars.next();
                out.push('.');
            }
            ch if is_qualified_name_separator(ch) => out.push('.'),
            _ => out.push(ch.to_ascii_lowercase()),
        }
    }
    out
}

/// Drop the global qualifier that spells an explicitly fully qualified name:
/// the leading `::` of C++ `::ns::Widget` and the leading `\` of PHP
/// `\App\Models\User`. No stored name starts with a separator, so the
/// qualifier names the root namespace and contributes nothing to a match.
///
/// A leading `::` is always the qualifier. A leading `\` is the qualifier only
/// when the rest is a backslash-joined name whose every backslash joins two
/// components and whose last segment is longer than one letter:
/// `\ADetail\.Outer\z`, `\AFoo\z` and `\bfoo\b` are regular expressions whose
/// escapes must keep their meaning, and `\AFoo` reads as an anchored regex, not
/// as the global name `AFoo`.
pub fn strip_global_qualifier(pattern: &str) -> &str {
    if let Some(rest) = pattern.strip_prefix("::")
        && rest.chars().next().is_some_and(is_name_component_character)
    {
        return rest;
    }
    if let Some(rest) = pattern.strip_prefix('\\') {
        let chars: Vec<char> = rest.chars().collect();
        let backslashes: Vec<usize> = (0..chars.len())
            .filter(|index| chars[*index] == '\\')
            .collect();
        // A rest that ends in a one-letter segment (`AFoo\z`, `bfoo\b`) reads
        // as a regex that opens and closes with an escape, not as a rooted
        // name whose last member is `z` or `b`.
        let ends_in_one_letter_segment = chars.len() >= 2 && chars[chars.len() - 2] == '\\';
        if chars
            .first()
            .is_some_and(|ch| is_name_component_character(*ch))
            && !backslashes.is_empty()
            && backslashes
                .iter()
                .all(|index| is_interior_separator_run(&chars, *index, 1))
            && !ends_in_one_letter_segment
        {
            return rest;
        }
    }
    pattern
}

/// The regular expression matching one qualified-name separator run: every
/// separator character, one or more of them. A run is one join rather than
/// several, because a language may decorate a segment boundary with its own
/// sigil: a Scala companion chain is stored as `Fiber$.Promise$.Unsafe`, and
/// `Fiber.Promise.Unsafe` names the same declaration.
const QUALIFIED_NAME_SEPARATOR_RUN: &str = r"[.:/$\\+]+";

/// Translate a literal qualified request into the regular expression its
/// spelling describes, or `None` when the pattern is not one.
///
/// A request that joins name components with a separator the classifier
/// accepts names the declaration whose stored spelling uses any other
/// separator, and the request's own. Compiling the request as it stands instead
/// reads the separators as regex syntax: `\M` does not compile at all, `$`
/// becomes an anchor, `::` matches only itself, and `.` and `+` become a
/// wildcard and a quantifier. This makes every non-separator character literal
/// and lets each separator run match the spellings the language adapters store.
///
/// A separator that does not join two components is the spelling of an
/// identifier, not a path: `Foo$` and `$L` name the Java or Scala identifier
/// that carries the sigil, and `foo.$` keeps its end anchor. Those patterns are
/// left to the ordinary matcher, which already treats a trailing sigil as
/// identifier text (#1127). A leading global qualifier is dropped first
/// ([`strip_global_qualifier`]), so `::ns::Widget` and `\App\Models\User`
/// reach the same declarations as `ns::Widget` and `App\Models\User`.
pub fn qualified_search_pattern_regex(pattern: &str) -> Option<String> {
    if classify_search_pattern(pattern) != SearchPatternKind::LiteralQualified {
        return None;
    }
    let unrooted = strip_global_qualifier(pattern);
    let rooted = unrooted.len() != pattern.len();

    let chars: Vec<char> = unrooted.chars().collect();
    // A backslash inside a literal qualified name always joins two components.
    // Any other backslash is regular-expression escape syntax (`\A`, `\z`,
    // `\.`), so the request is an explicit regex whose anchors must keep their
    // meaning: `\ADetail\.Outer$Inner\.run\z` selects one declaration by an
    // anchored name, not by a spelling. Leave those patterns to the ordinary
    // matcher.
    if (0..chars.len())
        .any(|index| chars[index] == '\\' && !is_interior_separator_run(&chars, index, 1))
    {
        return None;
    }
    // Likewise a `$` that is not identifier text is an explicit end anchor:
    // `pkg.Foo.$` asks for a name ending one character after `Foo`, as it does
    // without the qualified prefix.
    if (0..chars.len()).any(|index| chars[index] == '$' && !sigil_is_identifier_text(&chars, index))
    {
        return None;
    }

    let mut out = String::with_capacity(pattern.len() + 8);
    let mut literal = String::new();
    let mut joined_components = false;
    let mut index = 0;
    while index < chars.len() {
        let run = separator_run(&chars, index);
        if run == 0 {
            literal.push(chars[index]);
            index += 1;
            continue;
        }
        if is_interior_separator_run(&chars, index, run) {
            joined_components = true;
            out.push_str(&regex::escape(&literal));
            literal.clear();
            out.push_str(QUALIFIED_NAME_SEPARATOR_RUN);
        } else {
            literal.extend(&chars[index..index + run]);
        }
        index += run;
    }
    // A rooted single name (`::Widget`) is still a qualified request: its
    // qualifier is gone, and what remains is matched literally.
    if !joined_components && !rooted {
        return None;
    }
    out.push_str(&regex::escape(&literal));
    Some(out)
}

/// Escape the anchor metacharacters that are identifier text in `pattern`,
/// so a `$` or `^` inside a Java, Scala or JavaScript identifier matches
/// itself instead of an anchor that can never match there (#1127).
pub(crate) fn escape_sigil_anchors(pattern: &str) -> String {
    let chars: Vec<char> = pattern.chars().collect();
    let mut escaped = String::with_capacity(pattern.len());
    for (index, ch) in chars.iter().enumerate() {
        if matches!(ch, '$' | '^') && sigil_is_identifier_text(&chars, index) {
            escaped.push('\\');
        }
        escaped.push(*ch);
    }
    escaped
}

/// Whether the `$` or `^` at `index` is identifier text rather than an
/// anchor. A `$` beside a word character, or a `^` after one, is an anchor
/// that can never match there, so the request means the sigil itself.
fn sigil_is_identifier_text(chars: &[char], index: usize) -> bool {
    let prev_is_word = index > 0
        && (chars[index - 1].is_alphanumeric() || matches!(chars[index - 1], '_' | '$' | '^'));
    let next_is_word = chars
        .get(index + 1)
        .is_some_and(|next| next.is_alphanumeric() || matches!(next, '_' | '$'));
    match chars[index] {
        '$' => prev_is_word || next_is_word,
        '^' => prev_is_word,
        other => unreachable!("not an anchor metacharacter: {other:?}"),
    }
}

/// The length of the separator run starting at `index`, or zero when the
/// character there is ordinary identifier or name text. The run is maximal:
/// `::` counts as one separator, and adjacent separators such as the `$.` of
/// a Scala companion chain (`Fiber$.Promise`) are one join.
fn separator_run(chars: &[char], index: usize) -> usize {
    let mut end = index;
    while end < chars.len() {
        if chars[end] == ':' && chars.get(end + 1) == Some(&':') {
            end += 2;
        } else if is_qualified_name_separator(chars[end]) {
            end += 1;
        } else {
            break;
        }
    }
    end - index
}

/// Whether a separator run joins two name components. `a:$b` is not a join at
/// `$`: the `:` before it is not a component, so the run stays identifier text.
fn is_interior_separator_run(chars: &[char], start: usize, run: usize) -> bool {
    let before = start.checked_sub(1).and_then(|index| chars.get(index));
    let after = chars.get(start + run);
    before.is_some_and(|ch| is_name_component_character(*ch))
        && after.is_some_and(|ch| is_name_component_character(*ch))
}

fn is_name_component_character(ch: char) -> bool {
    !is_qualified_name_separator(ch) && ch != ':'
}

#[cfg(test)]
mod tests {
    use super::qualified_search_pattern_regex;
    use brokk_bifrost_test_macros::hardwon;

    fn translate(pattern: &str) -> Option<String> {
        qualified_search_pattern_regex(pattern)
    }

    #[test]
    #[hardwon("#8697: a PHP backslash-qualified request was reported as invalid regex")]
    fn a_backslash_qualified_name_matches_the_stored_dot_spelling() {
        assert_eq!(
            translate(r"App\Models\User").as_deref(),
            Some(r"App[.:/$\\+]+Models[.:/$\\+]+User")
        );
    }

    /// An explicitly fully qualified name drops its global qualifier: no
    /// stored name starts with a separator.
    #[test]
    #[hardwon("#8697: a rooted `::` or `\\` request kept its qualifier as name text")]
    fn a_global_qualifier_is_dropped() {
        for (pattern, expected) in [
            (r"\App\Models\User", r"App[.:/$\\+]+Models[.:/$\\+]+User"),
            ("::a::b::Widget", r"a[.:/$\\+]+b[.:/$\\+]+Widget"),
            ("::Widget", "Widget"),
            // A rooted PHP name with a lower-case first segment.
            (r"\yii\base\Widget", r"yii[.:/$\\+]+base[.:/$\\+]+Widget"),
        ] {
            assert_eq!(translate(pattern).as_deref(), Some(expected), "{pattern}");
        }
    }

    /// Only a separator that joins two components is a path boundary.
    #[test]
    #[hardwon("#1127: a trailing dollar sigil is identifier text, not a qualified-name join")]
    fn a_boundary_separator_is_identifier_text() {
        for pattern in ["Foo$", "$L", "$$animate", "foo.$"] {
            assert_eq!(
                translate(pattern),
                None,
                "{pattern} must keep its ordinary matcher semantics"
            );
        }
    }

    /// A request with a join keeps its boundary separators literal instead of
    /// letting `+` and `.` be a quantifier and a wildcard.
    #[test]
    #[hardwon("#8697: an operator name kept its trailing plus literal inside a qualified request")]
    fn a_boundary_separator_stays_literal_beside_a_join() {
        assert_eq!(
            translate("S::operator+").as_deref(),
            Some(r"S[.:/$\\+]+operator\+")
        );
        assert_eq!(translate("A.B.").as_deref(), Some(r"A[.:/$\\+]+B\."));
    }

    /// A backslash that is not a namespace separator is regex escape syntax,
    /// so the request keeps its anchors and its escaped dots.
    #[test]
    #[hardwon("#8697: an anchored regex was read as a qualified name and lost its anchors")]
    fn an_escaped_regular_expression_keeps_its_regex_reading() {
        for pattern in [
            r"\ADetail\.Outer$Inner\.run\z",
            r"\AFirst\.Device\.run\z",
            r"App\.Models",
            r"A\\B",
            // A leading backslash that is not a PHP global qualifier.
            r"\AFoo",
            r"\App\.Models",
            // An end anchor after a qualified prefix.
            "pkg.Foo.$",
            // A leading escape paired with a closing one-letter escape.
            r"\AFoo\z",
            r"\bfoo\b",
        ] {
            assert_eq!(translate(pattern), None, "{pattern}");
        }
    }
}
