//! Code-aware BM25 tokenization and grounded-string query reduction.
//!
//! This module is a direct Rust port of the brokkbench prototype's
//! `analysis/bm25/{bm25_tokenizer.py,bm25_retrieval.py}` helpers.

use std::collections::HashSet;
use std::sync::LazyLock;

use regex::Regex;

use super::MAX_QUERY_TOKENS;

static IDENTIFIER_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[^\W_]+(?:[-_][^\W_]+)*").expect("valid identifier regex"));
static QUOTED_SPAN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?s)"([^"]*)"|'([^']*)'|`([^`]*)`"#).expect("valid quoted-span regex")
});
static CALL_SUFFIX_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(?P<head>.+?)\([^()]*\)$").expect("valid call-suffix regex"));
static TOKEN_BOUNDARY_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[^A-Za-z0-9.]+").expect("valid token-boundary regex"));

const SURROUNDING_TRIM_CHARS: &str = "\"'`[]{}()<>,;:!?";

/// Tokenize text with the prototype's `code-subtoken-v1` BM25 tokenizer.
///
/// This ports `bm25_tokenizer.py:tokenize()` exactly: find identifier-like
/// spans, split on `-`/`_`, split camelCase and letter/digit boundaries, emit
/// the lowercased whole identifier plus subtokens, and skip single-letter
/// alphabetic subtokens.
pub fn tokenize(text: &str) -> Vec<String> {
    if text.is_empty() {
        return Vec::new();
    }

    let mut tokens = Vec::new();
    for matched in IDENTIFIER_RE.find_iter(text) {
        tokens.extend(identifier_tokens(matched.as_str()));
    }
    tokens
}

/// Return the prototype's FTS5 ingestion text: tokenized terms joined by spaces.
pub fn fts_text(text: &str) -> String {
    tokenize(text).join(" ")
}

/// Repo-observed path and symbol suffixes used by grounded-string reduction.
///
/// This mirrors the prototype's `RepoEntityUniverse`: path membership is based
/// on slash suffixes and symbol membership is based on dotted suffix chains.
pub struct RepoEntityUniverse {
    path_suffixes: HashSet<String>,
    symbol_suffixes: HashSet<String>,
}

impl RepoEntityUniverse {
    /// Build a universe from repository-relative paths and dotted symbol names.
    pub fn new<'a>(
        paths: impl IntoIterator<Item = &'a str>,
        symbols: impl IntoIterator<Item = &'a str>,
    ) -> Self {
        let mut path_suffixes = HashSet::new();
        let mut symbol_suffixes = HashSet::new();

        for path in paths {
            path_suffixes.extend(slash_suffixes(path));
        }
        for symbol in symbols {
            symbol_suffixes.extend(dotted_suffixes(symbol));
        }

        Self {
            path_suffixes,
            symbol_suffixes,
        }
    }

    /// Return whether `candidate` matches a repo path by slash suffix.
    pub fn is_repo_path(&self, candidate: &str) -> bool {
        self.path_suffixes
            .contains(candidate.trim_matches(['.', '/']))
    }

    /// Return whether `candidate` matches a repo symbol after prototype normalization.
    pub fn is_repo_symbol(&self, candidate: &str) -> bool {
        let dotted_chain = normalize_symbol_candidate(candidate);
        !dotted_chain.is_empty() && self.symbol_suffixes.contains(&dotted_chain)
    }
}

/// Extract repo-grounded words and quoted spans from a prompt.
///
/// This is the prototype's grounded-strings variant: repo path/symbol matches
/// found by whitespace splitting plus every non-empty quoted span.
pub fn grounded_prompt_text(prompt: &str, universe: &RepoEntityUniverse) -> String {
    let mut grounded_terms = Vec::new();

    for raw_word in prompt.split_whitespace() {
        let candidate = trim_grounding_candidate(strip_trailing_call_suffix(raw_word));
        if candidate.is_empty() {
            continue;
        }
        if universe.is_repo_path(candidate) || universe.is_repo_symbol(candidate) {
            grounded_terms.push(candidate.to_owned());
        }
    }

    grounded_terms.extend(extract_quoted_spans(prompt));
    grounded_terms.join(" ")
}

/// Build an FTS5 MATCH query from tokens using the prototype's quoting rules.
///
/// Tokens are deduplicated in first-seen order, capped at `super::MAX_QUERY_TOKENS`,
/// escaped by doubling internal double quotes, and OR-joined. Returns `None`
/// when no token survives deduplication/capping.
pub fn build_match_query(tokens: &[String]) -> Option<String> {
    let mut seen: HashSet<&str> = HashSet::new();
    let mut ordered = Vec::new();

    for token in tokens {
        let token = token.as_str();
        if !seen.insert(token) {
            continue;
        }
        ordered.push(token);
        if ordered.len() >= MAX_QUERY_TOKENS {
            break;
        }
    }

    if ordered.is_empty() {
        return None;
    }

    Some(
        ordered
            .into_iter()
            .map(|token| format!("\"{}\"", token.replace('"', "\"\"")))
            .collect::<Vec<_>>()
            .join(" OR "),
    )
}

fn identifier_tokens(identifier: &str) -> Vec<String> {
    let mut subtokens = Vec::new();
    let mut whole_parts = Vec::new();

    for piece in identifier.split(['-', '_']) {
        if piece.is_empty() {
            continue;
        }

        let split_parts = split_camel_and_digits(piece);
        for part in &split_parts {
            if !part.is_empty() {
                whole_parts.push(part.to_lowercase());
            }
        }

        for part in split_parts {
            if part.is_empty() {
                continue;
            }
            let lowered = part.to_lowercase();
            if lowered.chars().count() == 1 && lowered.chars().all(char::is_alphabetic) {
                continue;
            }
            subtokens.push(lowered);
        }
    }

    if whole_parts.is_empty() {
        return Vec::new();
    }

    let whole = whole_parts.concat();
    if subtokens.len() == 1 && subtokens[0] == whole {
        return vec![whole];
    }
    if subtokens.is_empty() {
        return vec![whole];
    }

    let mut tokens = Vec::with_capacity(subtokens.len() + 1);
    tokens.push(whole);
    tokens.extend(subtokens);
    tokens
}

fn split_camel_and_digits(piece: &str) -> Vec<&str> {
    if piece.is_empty() {
        return Vec::new();
    }

    let mut parts = Vec::new();
    let mut start = 0;
    let char_indices: Vec<(usize, char)> = piece.char_indices().collect();

    for index in 1..char_indices.len() {
        let (_, prev_char) = char_indices[index - 1];
        let (byte_index, char_) = char_indices[index];

        let acronym_end = prev_char.is_uppercase()
            && char_.is_uppercase()
            && matches!(char_indices.get(index + 1), Some((_, next)) if next.is_lowercase());
        let boundary = prev_char.is_numeric() != char_.is_numeric()
            || (prev_char.is_lowercase() && char_.is_uppercase())
            || acronym_end;

        if boundary {
            parts.push(&piece[start..byte_index]);
            start = byte_index;
        }
    }

    parts.push(&piece[start..]);
    parts
}

fn slash_suffixes(path: &str) -> Vec<String> {
    let parts: Vec<&str> = path.split('/').filter(|part| !part.is_empty()).collect();
    (0..parts.len())
        .map(|index| parts[index..].join("/"))
        .collect()
}

fn dotted_suffixes(symbol: &str) -> Vec<String> {
    let parts: Vec<&str> = symbol.split('.').filter(|part| !part.is_empty()).collect();
    (0..parts.len())
        .map(|index| parts[index..].join("."))
        .collect()
}

fn normalize_symbol_candidate(token: &str) -> String {
    TOKEN_BOUNDARY_RE
        .split(token)
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(".")
}

fn trim_grounding_candidate(token: &str) -> &str {
    token.trim_matches(|c| SURROUNDING_TRIM_CHARS.contains(c))
}

fn strip_trailing_call_suffix(token: &str) -> &str {
    match CALL_SUFFIX_RE.captures(token) {
        Some(captures) => captures.name("head").map_or(token, |head| head.as_str()),
        None => token,
    }
}

fn extract_quoted_spans(prompt: &str) -> Vec<String> {
    let mut spans = Vec::new();
    for captures in QUOTED_SPAN_RE.captures_iter(prompt) {
        for index in 1..=3 {
            if let Some(group) = captures.get(index) {
                spans.push(group.as_str().to_owned());
                break;
            }
        }
    }
    spans.into_iter().filter(|span| !span.is_empty()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emits_whole_identifier_and_subtokens_for_common_code_shapes() {
        let text = "getUserConfig snake_case kebab-case HTMLParser2 xValue x foo.bar";
        assert_eq!(
            tokenize(text),
            vec![
                "getuserconfig",
                "get",
                "user",
                "config",
                "snakecase",
                "snake",
                "case",
                "kebabcase",
                "kebab",
                "case",
                "htmlparser2",
                "html",
                "parser",
                "2",
                "xvalue",
                "value",
                "x",
                "foo",
                "bar",
            ]
        );
    }

    #[test]
    fn digits_and_single_character_split_fragments_follow_contract() {
        assert_eq!(
            tokenize("A1Version v2 x1"),
            vec!["a1version", "1", "version", "v2", "2", "x1", "1",]
        );
    }

    #[test]
    fn unicode_text_is_lowercased_and_does_not_crash() {
        assert_eq!(
            tokenize("StraßeÜbergrößE Καλημέρα κόσμε ПриветМир 变量名"),
            vec![
                "straßeübergröße",
                "straße",
                "übergröß",
                "καλημέρα",
                "κόσμε",
                "приветмир",
                "привет",
                "мир",
                "变量名",
            ]
        );
    }

    #[test]
    fn binaryish_and_empty_inputs_are_safe() {
        let binaryish: String = (0u8..=255).map(char::from).collect();
        let tokens = tokenize(&binaryish);
        assert!(tokens.iter().all(|token| !token.is_empty()));
        assert!(tokenize("").is_empty());
    }

    #[test]
    fn fts_text_joins_tokens_with_spaces() {
        assert_eq!(fts_text("getUserConfig"), "getuserconfig get user config");
    }

    #[test]
    fn build_match_query_dedupes_preserves_order_and_caps() {
        let tokens = vec![
            "a".to_owned(),
            "b".to_owned(),
            "a".to_owned(),
            "c".to_owned(),
            "d".to_owned(),
        ];
        assert_eq!(
            build_match_query(&tokens),
            Some("\"a\" OR \"b\" OR \"c\" OR \"d\"".to_owned())
        );

        let capped: Vec<String> = (0..(MAX_QUERY_TOKENS + 1))
            .map(|index| format!("tok{index}"))
            .collect();
        let query = build_match_query(&capped).expect("non-empty query");
        assert!(query.contains("\"tok0\""));
        assert!(query.contains(&format!("\"tok{}\"", MAX_QUERY_TOKENS - 1)));
        assert!(!query.contains(&format!("\"tok{MAX_QUERY_TOKENS}\"")));
    }

    #[test]
    fn build_match_query_returns_none_for_empty_input() {
        assert_eq!(build_match_query(&[]), None);
    }

    #[test]
    fn repo_entity_universe_tracks_path_suffixes_and_dotted_symbols() {
        let universe = RepoEntityUniverse::new(
            ["a/b/c.py", "x/y/z.py"],
            ["pkg.outer.inner", "__chunkless_file_summary__"],
        );

        assert!(universe.is_repo_path("a/b/c.py"));
        assert!(universe.is_repo_path("b/c.py"));
        assert!(universe.is_repo_path("c.py"));
        assert!(universe.is_repo_path("./z.py"));
        assert!(universe.is_repo_symbol("pkg.outer.inner"));
        assert!(universe.is_repo_symbol("outer.inner"));
        assert!(universe.is_repo_symbol("inner"));
        assert!(!universe.is_repo_symbol("__chunkless_file_summary__"));
        assert!(!universe.is_repo_path("ignored/path.py"));
    }

    #[test]
    fn grounded_prompt_text_keeps_repo_symbol_and_drops_non_repo_lookalike() {
        let universe = RepoEntityUniverse::new([], ["foo.bar"]);
        assert_eq!(
            grounded_prompt_text("touch foo.bar and fake.bar", &universe),
            "foo.bar"
        );
    }

    #[test]
    fn grounded_prompt_text_matches_path_suffix_pkg_mod_py() {
        let universe = RepoEntityUniverse::new(["src/pkg/mod.py"], []);
        assert_eq!(
            grounded_prompt_text("fix pkg/mod.py soon", &universe),
            "pkg/mod.py"
        );
    }

    #[test]
    fn grounded_prompt_text_strips_trailing_call_suffix() {
        let universe = RepoEntityUniverse::new([], ["foo.bar"]);
        assert_eq!(
            grounded_prompt_text("update foo.bar(baz) today", &universe),
            "foo.bar"
        );
    }

    #[test]
    fn grounded_prompt_text_adds_quoted_content() {
        let universe = RepoEntityUniverse::new([], []);
        assert_eq!(
            grounded_prompt_text(r#"unknown "literal-value" and `backtick-value`"#, &universe),
            "literal-value backtick-value"
        );
    }
}
