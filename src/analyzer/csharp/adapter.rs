use crate::analyzer::tree_sitter_analyzer::lookup_suffix_candidates;
use crate::analyzer::{Language, LanguageAdapter, ProjectFile, SignatureMetadata};
use tree_sitter::{Language as TsLanguage, Tree};

use super::declarations::parse_csharp_file;
use super::tests::csharp_contains_tests;
use super::{csharp_normalize_full_name, csharp_signature_arity, csharp_signature_return_type};

#[derive(Debug, Clone, Default)]
pub(super) struct CSharpAdapter;

impl LanguageAdapter for CSharpAdapter {
    fn language(&self) -> Language {
        Language::CSharp
    }

    fn query_directory(&self) -> &'static str {
        "resources/treesitter/c_sharp"
    }

    fn parser_language(&self) -> TsLanguage {
        tree_sitter_c_sharp::LANGUAGE.into()
    }

    fn file_extension(&self) -> &'static str {
        "cs"
    }

    fn structural_spec(&self) -> Option<&'static dyn crate::analyzer::structural::StructuralSpec> {
        Some(&super::structural::CSHARP_STRUCTURAL_SPEC)
    }

    fn normalize_full_name(&self, fq_name: &str) -> String {
        csharp_normalize_full_name(fq_name)
    }

    fn lookup_candidate_short_names(&self, normalized_fq_name: &str) -> Vec<String> {
        let mut candidates = lookup_suffix_candidates(normalized_fq_name, &[".", "::"]);
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
        _metadata: Option<&SignatureMetadata>,
    ) -> Option<usize> {
        Some(csharp_signature_arity(Some(signature)))
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
