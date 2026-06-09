use crate::analyzer::common::language_for_target as code_unit_language;
use crate::analyzer::{CodeUnit, IAnalyzer, Language};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone)]
pub(crate) enum CodeUnitResolution {
    Resolved(Vec<CodeUnit>),
    Ambiguous(Vec<String>),
    NotFound,
}

pub(crate) fn resolve_codeunit_fuzzy(analyzer: &dyn IAnalyzer, input: &str) -> CodeUnitResolution {
    resolve_codeunit_fuzzy_with(analyzer, input, |_| true)
}

pub(crate) fn resolve_typeish_codeunit_fuzzy(
    analyzer: &dyn IAnalyzer,
    input: &str,
) -> CodeUnitResolution {
    resolve_codeunit_fuzzy_with(analyzer, input, |code_unit| {
        code_unit.is_class() || code_unit.is_module()
    })
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

    let declarations = analyzer.get_all_declarations();
    let mut full_matches = BTreeMap::new();
    let mut suffix_matches = BTreeMap::new();
    let query_inputs = if stripped == trimmed {
        vec![trimmed]
    } else {
        vec![trimmed, stripped.as_str()]
    };

    for candidate in &declarations {
        let query_paths: BTreeSet<Vec<String>> = query_inputs
            .iter()
            .flat_map(|query| query_symbol_interpretations(code_unit_language(candidate), query))
            .collect();
        if query_paths.is_empty() {
            continue;
        }
        collect_fuzzy_matches(
            analyzer,
            candidate,
            include,
            &query_paths,
            &mut full_matches,
            &mut suffix_matches,
        );
        if candidate.is_class() || candidate.is_module() {
            for member in analyzer.get_members_in_class(candidate) {
                collect_fuzzy_matches(
                    analyzer,
                    &member,
                    include,
                    &query_paths,
                    &mut full_matches,
                    &mut suffix_matches,
                );
            }
        }
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
        .cloned()
        .collect()
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
        _ => Some(CodeUnitResolution::Ambiguous(matches.into_keys().collect())),
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
    let primary = parse_symbol_path(language, value);
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

    variants
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
            flush_segment(&mut current, &mut segments);
            chars.next();
            continue;
        }

        if matches!(ch, '.' | '\\' | '/' | '+') {
            flush_segment(&mut current, &mut segments);
            continue;
        }

        current.push(ch);
    }
    flush_segment(&mut current, &mut segments);

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

fn flush_segment(current: &mut String, segments: &mut Vec<String>) {
    let trimmed = current.trim();
    if !trimmed.is_empty() {
        segments.push(trimmed.to_string());
    }
    current.clear();
}

fn path_ends_with(candidate: &[String], query: &[String]) -> bool {
    !query.is_empty()
        && query.len() <= candidate.len()
        && candidate[candidate.len() - query.len()..] == *query
}
