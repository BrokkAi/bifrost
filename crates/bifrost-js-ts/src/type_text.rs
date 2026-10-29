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

/// Read a named type's base through grammar fields, without treating type
/// arguments, object members or function parameters as the receiver's name.
/// Type queries stay with their dedicated value-space resolver.
pub fn ts_named_type_identifier<'source>(
    mut node: Node<'_>,
    source: &'source str,
) -> Option<&'source str> {
    loop {
        node = match node.kind() {
            "type_identifier" | "identifier" | "predefined_type" => {
                return source
                    .get(node.start_byte()..node.end_byte())
                    .map(str::trim);
            }
            "type_annotation" | "parenthesized_type" | "readonly_type" | "array_type" => {
                node.named_child(0)?
            }
            "generic_type" => node.child_by_field_name("name")?,
            "nested_type_identifier" => crate::syntax::nested_type_identifier_parts(node)?.0,
            _ => return None,
        };
    }
}

#[cfg(test)]
mod quicksilver_grammar_tests {
    use super::*;

    #[test]
    fn annotation_and_named_type_grammar_boundary() {
        for (source, expected) in [
            ("let value: Token;", Some("Token")),
            ("let value: Box<Token>;", Some("Box")),
            ("let value: (Token);", Some("Token")),
            ("let value: readonly Token[];", Some("Token")),
            ("let value: typeof namespace.Member;", None),
            ("let value: First | Second;", None),
            ("let value: {field: Token};", None),
            ("let value: (x: First)=>Second;", None),
        ] {
            let tree = crate::test_support::parse_typescript(source);
            assert!(!tree.root_node().has_error());
            let declarator = tree
                .root_node()
                .named_child(0)
                .unwrap()
                .named_child(0)
                .unwrap();
            let annotation = declarator.child_by_field_name("type").unwrap();
            let bare = annotation.named_child(0).unwrap();
            assert_eq!(
                ts_type_annotation_text(annotation, source),
                crate::syntax::slice(bare, source)
            );
            assert_eq!(
                ts_named_type_identifier(annotation, source),
                expected,
                "{source}: {}",
                annotation.to_sexp()
            );
        }
    }
}
