use crate::analyzer::common::language_for_target as code_unit_language;
use crate::analyzer::csharp::strip_csharp_generic_arity;
use crate::analyzer::{CodeUnit, GO_MODULE_SCOPE_SEGMENT, IAnalyzer, Language};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone)]
pub(crate) enum CodeUnitResolution {
    Resolved(Vec<CodeUnit>),
    Ambiguous(Vec<CodeUnit>),
    NotFound,
}

pub(crate) fn resolve_codeunit_fuzzy(analyzer: &dyn IAnalyzer, input: &str) -> CodeUnitResolution {
    resolve_codeunit_fuzzy_with(analyzer, input, |_| true)
}

/// Resolve the deepest indexed symbol that encloses an unresolved descendant
/// selector. This lets callers associate a newly-added member with its
/// already-indexed owner without guessing at language-specific separators.
pub(crate) fn resolve_enclosing_codeunits(analyzer: &dyn IAnalyzer, input: &str) -> Vec<CodeUnit> {
    let trimmed = strip_trailing_call_suffix(input.trim());
    if trimmed.is_empty() {
        return Vec::new();
    }

    let mut best_depth = 0;
    let mut matches = BTreeMap::new();
    for language in analyzer.languages() {
        for query_path in query_symbol_interpretations(language, &trimmed) {
            if query_path.len() < 2 {
                continue;
            }
            for depth in (1..query_path.len()).rev() {
                if depth < best_depth {
                    break;
                }
                let owner_path = &query_path[..depth];
                let pattern = suffix_search_pattern(language, owner_path);
                if pattern.is_empty() {
                    continue;
                }

                let mut found_at_depth = false;
                for candidate in analyzer.search_definitions(&pattern, false) {
                    if code_unit_language(&candidate) != language
                        || !codeunit_lookup_aliases(&candidate)
                            .iter()
                            .any(|alias| alias == owner_path || path_ends_with(alias, owner_path))
                    {
                        continue;
                    }
                    if depth > best_depth {
                        best_depth = depth;
                        matches.clear();
                    }
                    insert_match(&mut matches, &candidate);
                    found_at_depth = true;
                }
                if found_at_depth {
                    break;
                }
            }
        }
    }

    match resolution_from_matches(analyzer, matches, |_| true) {
        Some(CodeUnitResolution::Resolved(units) | CodeUnitResolution::Ambiguous(units)) => units,
        Some(CodeUnitResolution::NotFound) | None => Vec::new(),
    }
}

/// Exact, non-fuzzy definition lookup for a fully-qualified name. Returns the
/// matching definitions verbatim (empty if none). Used to short-circuit before
/// file-pattern resolution so canonical names containing `/` (e.g. Go import
/// paths) are never misread as filesystem paths.
pub(crate) fn resolve_codeunit_exact(analyzer: &dyn IAnalyzer, input: &str) -> Vec<CodeUnit> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    let matches: Vec<_> = analyzer.definitions(trimmed).collect();
    let exact: Vec<_> = matches
        .iter()
        .filter(|unit| unit.fq_name() == trimmed)
        .cloned()
        .collect();
    if exact.is_empty() { matches } else { exact }
}

pub(crate) fn resolve_codeunit_fuzzy_with(
    analyzer: &dyn IAnalyzer,
    input: &str,
    include: impl Copy + Fn(&CodeUnit) -> bool,
) -> CodeUnitResolution {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return CodeUnitResolution::NotFound;
    }

    // Bare (single-segment) queries must see same-named members. Otherwise
    // stage 1 (exact) silently returns a lone top-level namesake the instant it
    // finds one, hiding same-terminal-name members and never reaching the
    // one-vs-many ambiguity decision (#1057). Gather the union of the exact
    // top-level hits and the identifier-indexed members, then let
    // `resolution_from_matches` decide Resolved (one distinct declaration) vs
    // Ambiguous (several) with the same fq-keying and type/constructor
    // preference used by the later stages. Non-bare (qualified/anchored)
    // queries are untouched: they already reach members via the suffix stages.
    if let Some(leaf) = bare_query_leaf(analyzer, trimmed)
        && let Some(resolved) = bare_name_resolution(analyzer, trimmed, &leaf, include)
    {
        return resolved;
    }

    if let Some(resolved) = exact_resolution(analyzer, trimmed, include) {
        return resolved;
    }

    let stripped = strip_trailing_call_suffix(trimmed);
    if stripped != trimmed
        && let Some(resolved) = exact_resolution(analyzer, &stripped, include)
    {
        return resolved;
    }

    if let Some(resolved) = suffix_resolution_from_index(analyzer, trimmed, include) {
        return resolved;
    }
    if stripped != trimmed
        && let Some(resolved) = suffix_resolution_from_index(analyzer, &stripped, include)
    {
        return resolved;
    }

    let declarations = analyzer.get_all_declarations();
    let mut full_matches = BTreeMap::new();
    let mut suffix_matches = BTreeMap::new();
    let query_inputs = if stripped == trimmed {
        vec![trimmed]
    } else {
        vec![trimmed, stripped.as_str()]
    };
    let mut query_paths_by_language: BTreeMap<Language, BTreeSet<Vec<String>>> = BTreeMap::new();

    for candidate in &declarations {
        let language = code_unit_language(candidate);
        let query_paths = query_paths_by_language.entry(language).or_insert_with(|| {
            query_inputs
                .iter()
                .flat_map(|query| query_symbol_interpretations(language, query))
                .collect()
        });
        if query_paths.is_empty() {
            continue;
        }
        collect_fuzzy_matches(
            analyzer,
            candidate,
            include,
            query_paths,
            &mut full_matches,
            &mut suffix_matches,
        );
    }

    resolution_from_matches(analyzer, full_matches, include)
        .or_else(|| resolution_from_matches(analyzer, suffix_matches, include))
        .unwrap_or(CodeUnitResolution::NotFound)
}

/// Whether `input` is a bare (single-segment) terminal name in every language
/// in play — the queries that must see same-named members instead of silently
/// resolving a lone top-level namesake (#1057). Exposed so the `get_symbol_sources`
/// surface, which otherwise short-circuits on an exact fully-qualified hit, can
/// route bare names through the member-aware fuzzy resolver while keeping
/// qualified names on their exact-first path.
pub(crate) fn is_bare_symbol_query(analyzer: &dyn IAnalyzer, input: &str) -> bool {
    let trimmed = input.trim();
    !trimmed.is_empty() && bare_query_leaf(analyzer, trimmed).is_some()
}

/// A query is "bare" when, for every language in play, all of its structured
/// interpretations are a single terminal segment (no `.`/`::`/`/`/`+`
/// structure). Returns that shared terminal leaf so the caller can gather
/// same-named members from the identifier index; returns `None` (fall through
/// to the normal staged resolution) for qualified queries or when the
/// languages disagree on the leaf. Derived entirely from the existing
/// structured interpretation helpers — no string hand-parsing.
fn bare_query_leaf(analyzer: &dyn IAnalyzer, trimmed: &str) -> Option<String> {
    let languages = analyzer.languages();
    let all_single_segment = languages.iter().all(|&language| {
        let paths = query_symbol_interpretations(language, trimmed);
        !paths.is_empty() && paths.iter().all(|path| path.len() == 1)
    });
    if !all_single_segment {
        return None;
    }

    let leaves: BTreeSet<String> = languages
        .iter()
        .filter_map(|&language| symbol_selector_leaf(language, trimmed))
        .collect();
    (leaves.len() == 1)
        .then(|| leaves.into_iter().next())
        .flatten()
}

/// Union of (a) exact top-level definitions of the bare query and (b) every
/// declaration whose terminal identifier equals `leaf` (members included, via
/// the indexed identifier lookup), keyed by fq-name exactly as stages 2-3.
/// Yields `Resolved` for one distinct declaration and `Ambiguous` for several;
/// returns `None` when the union is empty so the caller falls through to the
/// existing stages and NotFound handling is untouched.
fn bare_name_resolution(
    analyzer: &dyn IAnalyzer,
    trimmed: &str,
    leaf: &str,
    include: impl Copy + Fn(&CodeUnit) -> bool,
) -> Option<CodeUnitResolution> {
    let mut matches = BTreeMap::new();
    for definition in analyzer.definitions(trimmed) {
        if include(&definition) {
            insert_match(&mut matches, &definition);
        }
    }
    for candidate in analyzer.lookup_candidates_by_identifier(leaf) {
        if include(&candidate) && candidate.identifier() == leaf {
            insert_match(&mut matches, &candidate);
        }
    }
    resolution_from_matches(analyzer, matches, include)
}

pub(crate) fn strip_trailing_call_suffix(symbol: &str) -> String {
    if !symbol.ends_with(')') {
        return symbol.to_string();
    }

    let Some(open_paren) = symbol.rfind('(') else {
        return symbol.to_string();
    };
    if !symbol[open_paren + 1..symbol.len() - 1].contains(')') {
        let prefix = &symbol[..open_paren];
        if prefix
            .chars()
            .last()
            .map(|ch| ch.is_alphanumeric() || ch == '_')
            .unwrap_or(false)
        {
            return prefix.to_string();
        }
    }

    symbol.to_string()
}

fn exact_resolution(
    analyzer: &dyn IAnalyzer,
    symbol: &str,
    include: impl Copy + Fn(&CodeUnit) -> bool,
) -> Option<CodeUnitResolution> {
    let definitions = matching_definitions(analyzer, symbol, include);
    (!definitions.is_empty()).then_some(CodeUnitResolution::Resolved(definitions))
}

fn matching_definitions(
    analyzer: &dyn IAnalyzer,
    symbol: &str,
    include: impl Copy + Fn(&CodeUnit) -> bool,
) -> Vec<CodeUnit> {
    analyzer
        .definitions(symbol)
        .filter(|code_unit| include(code_unit))
        .collect()
}

fn suffix_resolution_from_index(
    analyzer: &dyn IAnalyzer,
    symbol: &str,
    include: impl Copy + Fn(&CodeUnit) -> bool,
) -> Option<CodeUnitResolution> {
    let mut exact_matches = BTreeMap::new();
    let mut exact_suffix_matches = BTreeMap::new();
    let query_paths_by_language: BTreeMap<_, BTreeSet<_>> = analyzer
        .languages()
        .into_iter()
        .map(|language| (language, query_symbol_interpretations(language, symbol)))
        .collect();
    for candidate in analyzer.lookup_candidates_by_short_name(symbol) {
        let language = code_unit_language(&candidate);
        let Some(query_paths) = query_paths_by_language.get(&language) else {
            continue;
        };
        if !include(&candidate) {
            continue;
        }
        collect_fuzzy_matches(
            analyzer,
            &candidate,
            include,
            query_paths,
            &mut exact_matches,
            &mut exact_suffix_matches,
        );
    }
    if let Some(CodeUnitResolution::Resolved(matches)) =
        unique_resolution_from_matches(analyzer, exact_matches, include)
    {
        return Some(CodeUnitResolution::Resolved(matches));
    }

    let mut full_matches = BTreeMap::new();
    let mut suffix_matches = BTreeMap::new();
    for language in analyzer.languages() {
        let query_paths = query_symbol_interpretations(language, symbol);
        if query_paths.iter().all(|path| path.len() < 2) {
            continue;
        }

        for query_path in &query_paths {
            let pattern = suffix_search_pattern(language, query_path);
            if pattern.is_empty() {
                continue;
            }
            for candidate in analyzer.search_definitions(&pattern, false) {
                if code_unit_language(&candidate) != language || !include(&candidate) {
                    continue;
                }
                collect_fuzzy_matches(
                    analyzer,
                    &candidate,
                    include,
                    &query_paths,
                    &mut full_matches,
                    &mut suffix_matches,
                );
            }
        }
    }

    if !full_matches.is_empty() {
        return unique_resolution_from_matches(analyzer, full_matches, include);
    }
    unique_resolution_from_matches(analyzer, suffix_matches, include)
}

fn unique_resolution_from_matches(
    analyzer: &dyn IAnalyzer,
    matches: BTreeMap<String, CodeUnit>,
    include: impl Copy + Fn(&CodeUnit) -> bool,
) -> Option<CodeUnitResolution> {
    (matches.len() == 1)
        .then(|| resolution_from_matches(analyzer, matches, include))
        .flatten()
}

fn suffix_search_pattern(language: Language, query_path: &[String]) -> String {
    let Some((last, prefix)) = query_path.split_last() else {
        return String::new();
    };
    if prefix.is_empty() {
        return String::new();
    }

    let delimiter = r"(?:\.|::|/|\\|\+|\$)";
    let mut pattern = String::from("(?:^|");
    pattern.push_str(delimiter);
    pattern.push(')');
    for segment in prefix {
        pattern.push_str(&regex::escape(segment));
        pattern.push_str(r"\$?");
        pattern.push_str(delimiter);
        if language == Language::Go {
            pattern.push_str(r"(?:");
            pattern.push_str(&regex::escape(GO_MODULE_SCOPE_SEGMENT));
            pattern.push_str(r"\$?");
            pattern.push_str(delimiter);
            pattern.push_str(r")?");
        }
    }
    pattern.push_str(&regex::escape(last));
    pattern.push_str(r"\$?");
    pattern.push('$');
    pattern
}

fn collect_fuzzy_matches(
    analyzer: &dyn IAnalyzer,
    candidate: &CodeUnit,
    include: impl Copy + Fn(&CodeUnit) -> bool,
    query_paths: &BTreeSet<Vec<String>>,
    full_matches: &mut BTreeMap<String, CodeUnit>,
    suffix_matches: &mut BTreeMap<String, CodeUnit>,
) {
    if !include(candidate) {
        return;
    }

    let candidate_paths = codeunit_lookup_aliases(candidate);
    if candidate_paths.is_empty() {
        return;
    }

    let full_match = candidate_paths
        .iter()
        .any(|candidate_path| query_paths.contains(candidate_path));
    if full_match {
        insert_match(full_matches, candidate);
        return;
    }

    let suffix_match = query_paths.iter().any(|query_path| {
        candidate_paths
            .iter()
            .any(|candidate_path| path_ends_with(candidate_path, query_path))
    });
    if suffix_match {
        let definitions = matching_definitions(analyzer, &candidate.fq_name(), include);
        if definitions.is_empty() {
            insert_match(suffix_matches, candidate);
        } else {
            for definition in definitions {
                insert_match(suffix_matches, &definition);
            }
        }
    }
}

fn insert_match(matches: &mut BTreeMap<String, CodeUnit>, candidate: &CodeUnit) {
    matches
        .entry(candidate.fq_name())
        .or_insert_with(|| candidate.clone());
}

fn resolution_from_matches(
    analyzer: &dyn IAnalyzer,
    mut matches: BTreeMap<String, CodeUnit>,
    include: impl Copy + Fn(&CodeUnit) -> bool,
) -> Option<CodeUnitResolution> {
    prefer_types_over_their_owner_named_constructors(analyzer, &mut matches);

    match matches.len() {
        0 => None,
        1 => {
            let fq_name = matches.keys().next().expect("one match").clone();
            let definitions = matching_definitions(analyzer, &fq_name, include);
            if definitions.is_empty() {
                Some(CodeUnitResolution::Resolved(
                    matches.into_values().collect(),
                ))
            } else {
                Some(CodeUnitResolution::Resolved(definitions))
            }
        }
        _ => {
            // Like the `len == 1` arm above, each surviving key in `matches`
            // holds only the single first-inserted representative for its fq
            // name (see `insert_match`'s dedup-by-fq behavior). But a bare
            // name's fq bucket can itself contain multiple independent
            // declarations across files (e.g. several top-level
            // `const Input = ...` arrow functions in different modules, all
            // with empty package -> fq == short_name; see #1087). Re-expand
            // every remaining key to its full set of declarations via
            // `matching_definitions`, falling back to the stored
            // representative when the lookup comes up empty, exactly as the
            // `len == 1` arm does, so ambiguous results surface every
            // candidate instead of silently collapsing cross-file
            // duplicates down to one representative per fq.
            //
            // This expansion must run *after*
            // `prefer_types_over_their_owner_named_constructors` has already
            // pruned constructor-shaped functions above, not before: that
            // filter reasons about one representative CodeUnit per fq key in
            // the dedup'd map (owner/identifier checks against a single
            // `unit`), so it needs the deduplicated shape to stay correct.
            // Expanding first would turn `matches` into a multi-valued
            // collection the filter isn't written to consume, and would risk
            // re-introducing declarations the filter meant to drop before
            // ambiguity was ever computed.
            let mut expanded = Vec::with_capacity(matches.len());
            for (fq_name, representative) in matches {
                let definitions = matching_definitions(analyzer, &fq_name, include);
                if definitions.is_empty() {
                    expanded.push(representative);
                } else {
                    expanded.extend(definitions);
                }
            }
            Some(CodeUnitResolution::Ambiguous(expanded))
        }
    }
}

/// A bare type name can also suffix-match that type's owner-named constructor
/// (`pkg.Type` and `pkg.Type.Type`). Prefer the type when both declarations are
/// present, while leaving an explicitly repeated constructor selector and
/// ambiguity between independently declared types untouched.
fn prefer_types_over_their_owner_named_constructors(
    analyzer: &dyn IAnalyzer,
    matches: &mut BTreeMap<String, CodeUnit>,
) {
    let competing_types: BTreeSet<_> = matches
        .values()
        .filter(|unit| unit.is_class())
        .map(CodeUnit::fq_name)
        .collect();
    if competing_types.is_empty() {
        return;
    }

    matches.retain(|_, unit| {
        if !unit.is_function()
            || !matches!(
                code_unit_language(unit),
                Language::Java | Language::CSharp | Language::Cpp
            )
        {
            return true;
        }

        let Some(owner) = analyzer.parent_of(unit) else {
            return true;
        };
        !(owner.is_class()
            && unit.identifier() == owner.identifier()
            && competing_types.contains(&owner.fq_name()))
    });
}

fn codeunit_lookup_aliases(code_unit: &CodeUnit) -> BTreeSet<Vec<String>> {
    let mut paths = BTreeSet::new();
    let language = code_unit_language(code_unit);
    insert_path_variants(&mut paths, language, &code_unit.fq_name());
    insert_path_variants(&mut paths, language, code_unit.short_name());
    insert_path_variants(&mut paths, language, code_unit.identifier());
    paths
}

fn query_symbol_interpretations(language: Language, input: &str) -> BTreeSet<Vec<String>> {
    let mut paths = BTreeSet::new();
    insert_path_variants(&mut paths, language, input);
    if language == Language::CSharp {
        let normalized: Vec<_> = parse_symbol_path(language, input)
            .into_iter()
            .map(|segment| strip_csharp_generic_arity(&segment).to_string())
            .collect();
        if !normalized.is_empty() && normalized.iter().all(|segment| !segment.is_empty()) {
            paths.insert(normalized);
        }
    }
    paths
}

pub(crate) fn symbol_selector_leaf(language: Language, input: &str) -> Option<String> {
    // A leaf containing whitespace (e.g. the untouched `struct git_refdb`
    // primary reading, kept alongside its tag-stripped variant per #1019) can
    // never be a real indexed identifier, so it cannot be *the* canonical
    // terminal name and must not spoil cross-variant agreement here.
    let leaves: BTreeSet<_> = query_symbol_interpretations(language, input)
        .into_iter()
        .filter_map(|path| path.into_iter().next_back())
        .filter(|leaf| !leaf.contains(char::is_whitespace))
        .collect();
    (leaves.len() == 1)
        .then(|| leaves.into_iter().next())
        .flatten()
}

fn insert_path_variants(paths: &mut BTreeSet<Vec<String>>, language: Language, value: &str) {
    for variant in symbol_path_variants(language, value) {
        if !variant.is_empty() {
            paths.insert(variant);
        }
    }
}

fn symbol_path_variants(language: Language, value: &str) -> Vec<Vec<String>> {
    let primary = if language == Language::Go {
        go_receiver_declaration_selector(value)
            .map(|selector| parse_symbol_path(language, &selector))
            .unwrap_or_else(|| parse_symbol_path(language, value))
    } else {
        parse_symbol_path(language, value)
    };
    if primary.is_empty() {
        return Vec::new();
    }

    let mut variants = vec![primary.clone()];
    let scala_normalized: Vec<_> = primary
        .iter()
        .map(|segment| segment.trim_end_matches('$').to_string())
        .collect();
    if scala_normalized != primary && scala_normalized.iter().all(|segment| !segment.is_empty()) {
        variants.push(scala_normalized);
    }

    let dollar_split = split_segments_on_dollar(&primary);
    if dollar_split != primary {
        variants.push(dollar_split);
    }

    // C# generic arity: indexed names carry `Type`1`, but nobody types
    // arity — the query side already strips it
    // (query_symbol_interpretations), so aliases must offer the
    // arity-free form too or generic types are unaddressable (#1063).
    // Strip from *every* variant, not just the primary: a nested generic
    // member (`Ns.Outer$Inner`1.Method`) displays as
    // `Ns.Outer.Inner.Method`, so the arity-free dollar-split form must
    // exist too (xunit/MudBlazor tier-3 more-specific-fails).
    if language == Language::CSharp {
        let arity_free: Vec<Vec<String>> = variants
            .iter()
            .map(|variant| {
                variant
                    .iter()
                    .map(|segment| strip_csharp_generic_arity(segment).to_string())
                    .collect::<Vec<_>>()
            })
            .filter(|normalized| {
                !normalized.is_empty() && normalized.iter().all(|segment| !segment.is_empty())
            })
            .collect();
        for normalized in arity_free {
            if !variants.contains(&normalized) {
                variants.push(normalized);
            }
        }
    }

    // C/C++ elaborated-type-specifier tags: agents naturally spell C/C++ type
    // references the way a use site requires them (`struct git_refdb`, `enum
    // Color`, `union Value`), but Bifrost indexes the bare type identifier.
    // Offer the tag-stripped spelling as an additional variant so `struct Foo`,
    // `file::struct Foo`, and `file#struct Foo` resolve/ambiguate exactly like
    // the keyword-free `Foo` (#1019).
    if language == Language::Cpp {
        let normalized: Vec<_> = primary
            .iter()
            .map(|segment| strip_cpp_tag_keyword(segment).to_string())
            .collect();
        if normalized != primary && normalized.iter().all(|segment| !segment.is_empty()) {
            variants.push(normalized);
        }
    }

    if language == Language::TypeScript
        && let Some(ts_static) = trim_trailing_static_member_segment(&primary)
    {
        variants.push(ts_static);
    }

    variants
}

/// Strip a leading C/C++ elaborated-type-specifier keyword (`struct`, `enum`,
/// `union`, `class`) from a symbol-selector segment, repeatedly (so `enum
/// class Color` also normalizes to `Color`). No real C/C++ identifier can
/// contain an embedded space, so this only ever fires on client-provided tag
/// syntax, never on an indexed name (#1019).
fn strip_cpp_tag_keyword(segment: &str) -> &str {
    let mut current = segment;
    loop {
        let Some(rest) = ["struct", "enum", "union", "class"]
            .into_iter()
            .find_map(|keyword| current.strip_prefix(keyword))
        else {
            return current;
        };
        if !rest.starts_with(char::is_whitespace) {
            return current;
        }
        let rest = rest.trim_start();
        if rest.is_empty() {
            return current;
        }
        current = rest;
    }
}

fn trim_trailing_static_member_segment(segments: &[String]) -> Option<Vec<String>> {
    let (last, prefix) = segments.split_last()?;
    let member = last.strip_suffix("$static")?;
    if member.is_empty() {
        return None;
    }

    let mut variant = prefix.to_vec();
    variant.push(member.to_string());
    Some(variant)
}

fn split_segments_on_dollar(segments: &[String]) -> Vec<String> {
    segments
        .iter()
        .flat_map(|segment| {
            segment
                .split('$')
                .filter(|part| !part.is_empty())
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        })
        .collect()
}

fn parse_symbol_path(language: Language, value: &str) -> Vec<String> {
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

    segment.to_string()
}

fn normalized_go_client_symbol_segment(segment: &str) -> String {
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

fn go_receiver_declaration_selector(value: &str) -> Option<String> {
    let trimmed = value.trim();
    let receiver_end = trimmed.find(')')?;
    let receiver = trimmed.get(..=receiver_end)?;
    let method = trimmed.get(receiver_end + 1..)?.trim();
    let method = method.strip_prefix('.').unwrap_or(method).trim();
    if method.is_empty() || method.chars().any(char::is_whitespace) {
        return None;
    }

    let (prefix, receiver) = receiver
        .rsplit_once(".(")
        .map(|(prefix, receiver)| (Some(prefix), format!("({receiver}")))
        .unwrap_or((None, receiver.to_string()));
    let receiver_type = normalized_go_client_symbol_segment(&receiver);
    if receiver_type == receiver {
        return None;
    }
    Some(match prefix {
        Some(prefix) => format!("{prefix}.{receiver_type}.{method}"),
        None => format!("{receiver_type}.{method}"),
    })
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

fn path_ends_with(candidate: &[String], query: &[String]) -> bool {
    if query.is_empty() {
        return false;
    }

    let mut candidate_index = candidate.len();
    let mut query_index = query.len();
    while query_index > 0 {
        if candidate_index == 0 {
            return false;
        }
        candidate_index -= 1;
        if candidate[candidate_index] == query[query_index - 1] {
            query_index -= 1;
        } else if candidate[candidate_index] != GO_MODULE_SCOPE_SEGMENT {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csharp_generic_member_alias_includes_arity_free_form() {
        let variants = symbol_path_variants(Language::CSharp, "Ns.Top`1.Go");
        assert!(
            variants
                .iter()
                .any(|v| v == &vec!["Ns".to_string(), "Top".to_string(), "Go".to_string()]),
            "arity-free member variant must be offered: {variants:?}"
        );
    }

    #[test]
    fn csharp_nested_generic_member_alias_includes_dollar_split_arity_free_form() {
        let variants = symbol_path_variants(Language::CSharp, "Ns.Outer$Inner`1.Method");
        assert!(
            variants.iter().any(|v| v
                == &vec![
                    "Ns".to_string(),
                    "Outer".to_string(),
                    "Inner".to_string(),
                    "Method".to_string()
                ]),
            "nested arity-free member variant must be offered: {variants:?}"
        );
    }
}
