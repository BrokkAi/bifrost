use crate::analyzer::cognitive_complexity;
use crate::analyzer::tree_sitter_analyzer::lookup_suffix_candidates;
use crate::analyzer::{CodeUnit, Language, LanguageAdapter, ProjectFile, SignatureMetadata};
use std::sync::LazyLock;
use tree_sitter::Node;
use tree_sitter::Tree;

use super::declarations::parse_csharp_file;
use super::tests::csharp_contains_tests;
use super::{
    csharp_normalize_full_name, csharp_signature_arity, csharp_signature_return_type,
    csharp_source_identifier, strip_csharp_generic_arity,
};

static CSHARP_COGNITIVE_CONFIG: LazyLock<cognitive_complexity::Config> =
    LazyLock::new(|| cognitive_complexity::Config {
        if_types: &["if_statement"],
        loop_types: &[
            "for_statement",
            "foreach_statement",
            "while_statement",
            "do_statement",
        ],
        catch_types: &["catch_clause"],
        conditional_types: &["conditional_expression"],
        case_types: &["switch_section", "switch_expression_arm"],
        binary_types: &["binary_expression"],
        logical_operators: &["&&", "||"],
        jump_types: &["goto_statement"],
        named_function_boundary_types: &[
            "method_declaration",
            "constructor_declaration",
            "local_function_statement",
            "accessor_declaration",
            "operator_declaration",
            "conversion_operator_declaration",
            "destructor_declaration",
        ],
        anonymous_function_types: &["lambda_expression", "anonymous_method_expression"],
        case_increment_predicate: Some(csharp_case_increment),
        jump_predicate: Some(|_| true),
        ..cognitive_complexity::Config::empty()
    });

fn csharp_case_increment(node: Node<'_>, _source: &str) -> u32 {
    if node.kind() == "switch_expression_arm" {
        let pattern = node.named_child(0);
        let mut cursor = node.walk();
        let guarded = node
            .named_children(&mut cursor)
            .any(|child| child.kind() == "when_clause");
        return u32::from(guarded || !pattern.is_some_and(csharp_is_irrefutable_pattern));
    }

    let mut count = 0u32;
    for index in 0..node.child_count() {
        let Some(child) = node.child(index) else {
            continue;
        };
        if child.kind() != "case" {
            continue;
        }

        let mut pattern = None;
        let mut guarded = false;
        for label_index in index + 1..node.child_count() {
            let Some(label_child) = node.child(label_index) else {
                continue;
            };
            if label_child.kind() == ":" {
                break;
            }
            if label_child.kind() == "when_clause" {
                guarded = true;
            } else if label_child.is_named() && pattern.is_none() {
                pattern = Some(label_child);
            }
        }
        if guarded || !pattern.is_some_and(csharp_is_irrefutable_pattern) {
            count = count.saturating_add(1);
        }
    }
    count
}

fn csharp_is_irrefutable_pattern(mut pattern: Node<'_>) -> bool {
    while pattern.kind() == "parenthesized_pattern" {
        let Some(inner) = pattern.named_child(0) else {
            return false;
        };
        pattern = inner;
    }
    matches!(pattern.kind(), "discard" | "var_pattern")
        || (pattern.kind() == "declaration_pattern"
            && pattern
                .child_by_field_name("type")
                .is_some_and(|ty| ty.kind() == "implicit_type"))
}

#[derive(Debug, Clone, Default)]
pub(super) struct CSharpAdapter;

impl LanguageAdapter for CSharpAdapter {
    fn language(&self) -> Language {
        Language::CSharp
    }

    fn query_directory(&self) -> &'static str {
        "resources/treesitter/c_sharp"
    }

    fn file_extension(&self) -> &'static str {
        "cs"
    }

    fn normalize_full_name(&self, fq_name: &str) -> String {
        csharp_normalize_full_name(fq_name)
    }

    fn simple_type_name(&self, unit: &CodeUnit) -> String {
        csharp_source_identifier(unit).to_string()
    }

    fn persist_content_stable_lookup_keys(&self) -> bool {
        true
    }

    fn lookup_candidate_short_names(&self, normalized_fq_name: &str) -> Vec<String> {
        let mut candidates = lookup_suffix_candidates(normalized_fq_name, &[".", "::"]);
        if let Some((owner, leaf)) = normalized_fq_name.rsplit_once('.') {
            let source_leaf = strip_csharp_generic_arity(leaf);
            if source_leaf != leaf {
                candidates.extend(lookup_suffix_candidates(
                    &format!("{owner}.{source_leaf}"),
                    &[".", "::"],
                ));
            }
        }
        let base_candidates = candidates.clone();
        for candidate in base_candidates {
            candidates.extend(csharp_nested_owner_short_name_candidates(&candidate));
        }
        candidates.sort();
        candidates.dedup();
        candidates
    }

    fn callable_arity(
        &self,
        signature: &str,
        metadata: Option<&SignatureMetadata>,
    ) -> Option<usize> {
        metadata
            .and_then(SignatureMetadata::callable_arity)
            .map(|arity| arity.total())
            .or_else(|| Some(csharp_signature_arity(Some(signature))))
    }

    fn callable_return_type_text<'a>(&self, signature: &'a str) -> Option<&'a str> {
        let declaration_head = signature
            .split(['(', '{', ';', '='])
            .next()
            .unwrap_or(signature)
            .trim_end();
        let name = declaration_head.split_whitespace().last()?;
        let return_type = csharp_signature_return_type(signature, name)?;
        signature.find(&return_type).map(|start| {
            let end = start + return_type.len();
            &signature[start..end]
        })
    }

    fn contains_tests(
        &self,
        _file: &ProjectFile,
        source: &str,
        tree: &Tree,
        _parsed: &crate::analyzer::tree_sitter_analyzer::ParsedFile,
    ) -> bool {
        csharp_contains_tests(tree.root_node(), source)
    }

    fn extract_call_receiver(&self, reference: &str) -> Option<String> {
        let trimmed = reference.trim();
        let before_args = trimmed
            .split_once('(')
            .map(|(head, _)| head)
            .unwrap_or(trimmed);
        before_args
            .rsplit_once('.')
            .map(|(receiver, _)| receiver.to_string())
    }

    fn parse_file(
        &self,
        file: &ProjectFile,
        source: &str,
        tree: &Tree,
    ) -> crate::analyzer::tree_sitter_analyzer::ParsedFile {
        parse_csharp_file(file, source, tree)
    }

    fn cognitive_complexity_config(&self) -> Option<&'static cognitive_complexity::Config> {
        Some(&CSHARP_COGNITIVE_CONFIG)
    }
}

fn csharp_nested_owner_short_name_candidates(normalized: &str) -> Vec<String> {
    let parts: Vec<_> = normalized
        .split('.')
        .filter(|part| !part.is_empty())
        .collect();
    if parts.len() < 2 {
        return Vec::new();
    }

    let separator_count = parts.len() - 1;
    if separator_count > 8 {
        let mut encoded = parts[..separator_count].join("$");
        encoded.push('.');
        encoded.push_str(parts[separator_count]);
        return vec![encoded];
    }

    let mut out = Vec::new();
    for mask in 1..(1_usize << separator_count) {
        let mut encoded = String::new();
        for (index, part) in parts.iter().enumerate() {
            if index > 0 {
                encoded.push(if (mask & (1 << (index - 1))) != 0 {
                    '$'
                } else {
                    '.'
                });
            }
            encoded.push_str(part);
        }
        out.push(encoded);
    }
    out
}
