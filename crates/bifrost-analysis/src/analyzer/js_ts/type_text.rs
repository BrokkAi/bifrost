//! TypeScript type-text normalization and the type-vs-value candidate spaces.
//!
//! A TypeScript reference sits in either the value space or the type space, and
//! which declarations can answer it differs by space. These predicates and the
//! annotation-text readers above them are the whole of that vocabulary; they
//! moved out of `usages/get_definition/js_ts.rs` so the JS/TS usage graph can
//! name them without importing the definition route, which the route then
//! imports back (issue: the js_ts crate extraction, Js-1).

use crate::analyzer::CodeUnit;
use crate::analyzer::js_ts::providers::JsTsAnalyzerHost;
use tree_sitter::Node;

pub(crate) fn ts_type_annotation_text(node: Node<'_>, source: &str) -> String {
    ts_clean_type_text(source.get(node.start_byte()..node.end_byte()).unwrap_or(""))
}

pub(crate) fn ts_clean_type_text(text: &str) -> String {
    text.trim()
        .trim_start_matches(':')
        .trim()
        .trim_end_matches(';')
        .trim()
        .to_string()
}

pub(crate) fn jsts_value_space_candidates(
    host: &dyn JsTsAnalyzerHost,
    candidates: Vec<CodeUnit>,
) -> Vec<CodeUnit> {
    let value_candidates: Vec<_> = candidates
        .iter()
        .filter(|candidate| !jsts_unit_is_type_only(host, candidate))
        .cloned()
        .collect();
    if value_candidates.is_empty() {
        candidates
    } else {
        value_candidates
    }
}

pub(crate) fn jsts_type_space_candidates(
    host: &dyn JsTsAnalyzerHost,
    candidates: Vec<CodeUnit>,
) -> Vec<CodeUnit> {
    let type_candidates: Vec<_> = candidates
        .iter()
        .filter(|candidate| jsts_unit_is_type_only(host, candidate))
        .cloned()
        .collect();
    if type_candidates.is_empty() {
        candidates
    } else {
        type_candidates
    }
}

/// The type-alias question goes through [`JsTsAnalyzerHost::js_ts_is_type_alias`]
/// rather than `IAnalyzer::type_alias_provider`: both spellings read the same
/// TypeScript declaration index for a TypeScript unit, and both answer `false`
/// for a JavaScript one (JavaScript has no `TypeAliasProvider`), but only the
/// host spelling keeps this file off `IAnalyzer`.
pub(crate) fn jsts_unit_is_type_only(host: &dyn JsTsAnalyzerHost, unit: &CodeUnit) -> bool {
    if host.js_ts_is_type_alias(unit) {
        return true;
    }
    unit.signature().is_some_and(jsts_signature_is_type_only)
        || host
            .signatures(unit)
            .iter()
            .any(|signature| jsts_signature_is_type_only(signature))
}

fn jsts_signature_is_type_only(signature: &str) -> bool {
    let signature = signature.trim_start();
    signature.starts_with("interface ")
        || signature.starts_with("export interface ")
        || signature.starts_with("declare interface ")
        || signature.starts_with("export declare interface ")
        || signature.starts_with("type ")
        || signature.starts_with("export type ")
        || signature.starts_with("declare type ")
        || signature.starts_with("export declare type ")
}
