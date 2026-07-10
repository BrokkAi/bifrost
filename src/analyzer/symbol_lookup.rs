use crate::analyzer::common::language_for_target as code_unit_language;
use crate::analyzer::{CodeUnit, IAnalyzer, Language};
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
                let pattern = suffix_search_pattern(owner_path);
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

fn resolve_codeunit_fuzzy_with(
    analyzer: &dyn IAnalyzer,
    input: &str,
    include: impl Copy + Fn(&CodeUnit) -> bool,
) -> CodeUnitResolution {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return CodeUnitResolution::NotFound;
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
    let mut full_matches = BTreeMap::new();
    let mut suffix_matches = BTreeMap::new();
    for language in analyzer.languages() {
        let query_paths = query_symbol_interpretations(language, symbol);
        if query_paths.iter().all(|path| path.len() < 2) {
            continue;
        }

        for query_path in &query_paths {
            let pattern = suffix_search_pattern(query_path);
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

fn suffix_search_pattern(query_path: &[String]) -> String {
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
    matches: BTreeMap<String, CodeUnit>,
    include: impl Copy + Fn(&CodeUnit) -> bool,
) -> Option<CodeUnitResolution> {
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
        _ => Some(CodeUnitResolution::Ambiguous(
            matches.into_values().collect(),
        )),
    }
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
    paths
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

    if language == Language::TypeScript
        && let Some(ts_static) = trim_trailing_static_member_segment(&primary)
    {
        variants.push(ts_static);
    }

    variants
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
    !query.is_empty()
        && query.len() <= candidate.len()
        && candidate[candidate.len() - query.len()..] == *query
}
