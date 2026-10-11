//! TypeScript type-text normalization and the type-vs-value candidate spaces.
//!
//! A TypeScript reference sits in either the value space or the type space, and
//! which declarations can answer it differs by space. These predicates and the
//! annotation-text readers above them are the whole of that vocabulary; they
//! moved out of `usages/get_definition/js_ts.rs` so the JS/TS usage graph can
//! name them without importing the definition route, which the route then
//! imports back (issue: the js_ts crate extraction, Js-1).

use crate::providers::JsTsSource;
use brokk_bifrost_core::analyzer::CodeUnit;
use tree_sitter::Node;

pub fn ts_type_annotation_text(node: Node<'_>, source: &str) -> String {
    ts_clean_type_text(source.get(node.start_byte()..node.end_byte()).unwrap_or(""))
}

pub fn ts_clean_type_text(text: &str) -> String {
    text.trim()
        .trim_start_matches(':')
        .trim()
        .trim_end_matches(';')
        .trim()
        .to_string()
}

pub fn jsts_value_space_candidates(
    host: &dyn JsTsSource,
    candidates: Vec<CodeUnit>,
) -> Vec<CodeUnit> {
    retain_matching_candidates_or_all(candidates, |candidate| {
        !jsts_unit_is_type_only(host, candidate)
    })
}

pub fn jsts_type_space_candidates(
    host: &dyn JsTsSource,
    candidates: Vec<CodeUnit>,
) -> Vec<CodeUnit> {
    retain_matching_candidates_or_all(candidates, |candidate| {
        jsts_unit_is_type_only(host, candidate)
    })
}

fn retain_matching_candidates_or_all(
    candidates: Vec<CodeUnit>,
    mut matches: impl FnMut(&CodeUnit) -> bool,
) -> Vec<CodeUnit> {
    let matching: Vec<_> = candidates
        .iter()
        .filter(|candidate| matches(candidate))
        .cloned()
        .collect();
    if matching.is_empty() {
        candidates
    } else {
        matching
    }
}

/// The type-alias question goes through [`JsTsSource::is_type_alias`]
/// rather than `IAnalyzer::type_alias_provider`: both spellings read the same
/// TypeScript declaration index for a TypeScript unit, and both answer `false`
/// for a JavaScript one (JavaScript has no `TypeAliasProvider`), but only the
/// host spelling keeps this file off `IAnalyzer`.
pub fn jsts_unit_is_type_only(host: &dyn JsTsSource, unit: &CodeUnit) -> bool {
    if host.is_type_alias(unit) {
        return true;
    }
    host.source_facts(unit.source()).is_some_and(|source| {
        source.facts.declarations.iter().any(|declaration| {
            declaration.is_interface
                && source
                    .declaration_units
                    .get(&declaration.declaration)
                    .is_some_and(|units| units.contains(unit))
        })
    })
}
