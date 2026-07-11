use crate::analyzer::tree_sitter_analyzer::lookup_suffix_candidates;
use crate::analyzer::{CodeUnit, Language, LanguageAdapter, ProjectFile, SignatureMetadata};
use tree_sitter::{Language as TsLanguage, Tree};

use super::declarations::parse_scala_file;
use super::tests::scala_contains_tests;
use super::{
    scala_member_signature_arity, scala_normalize_full_name, scala_signature_return_type,
    scala_simple_type_name,
};

#[derive(Debug, Clone, Default)]
pub(crate) struct ScalaAdapter;

impl LanguageAdapter for ScalaAdapter {
    fn language(&self) -> Language {
        Language::Scala
    }

    fn query_directory(&self) -> &'static str {
        "resources/treesitter/scala"
    }

    fn parser_language(&self) -> TsLanguage {
        tree_sitter_scala::LANGUAGE.into()
    }

    fn file_extension(&self) -> &'static str {
        "scala"
    }

    fn structural_spec(&self) -> Option<&'static dyn crate::analyzer::structural::StructuralSpec> {
        Some(&super::structural::SCALA_STRUCTURAL_SPEC)
    }

    fn normalize_full_name(&self, fq_name: &str) -> String {
        scala_normalize_full_name(fq_name)
    }

    fn lookup_candidate_short_names(&self, normalized_fq_name: &str) -> Vec<String> {
        let mut candidates = lookup_suffix_candidates(normalized_fq_name, &["."]);
        let base_candidates = candidates.clone();
        for candidate in base_candidates {
            candidates.extend(scala_object_encoded_short_name_candidates(&candidate));
        }
        candidates.sort();
        candidates.dedup();
        candidates
    }

    fn simple_type_name(&self, unit: &CodeUnit) -> String {
        scala_simple_type_name(unit)
    }

    fn callable_arity(
        &self,
        signature: &str,
        _metadata: Option<&SignatureMetadata>,
    ) -> Option<usize> {
        scala_member_signature_arity(signature)
    }

    fn callable_return_type_text<'a>(&self, signature: &'a str) -> Option<&'a str> {
        scala_signature_return_type(signature)
    }

    fn preferred_type_candidate<'a>(&self, candidates: &'a [CodeUnit]) -> Option<&'a CodeUnit> {
        candidates
            .iter()
            .find(|unit| !unit.short_name().ends_with('$'))
            .or_else(|| candidates.first())
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

    fn contains_tests(
        &self,
        _file: &ProjectFile,
        source: &str,
        tree: &Tree,
        _parsed: &crate::analyzer::tree_sitter_analyzer::ParsedFile,
    ) -> bool {
        scala_contains_tests(tree.root_node(), source)
    }

    fn parse_file(
        &self,
        file: &ProjectFile,
        source: &str,
        tree: &Tree,
    ) -> crate::analyzer::tree_sitter_analyzer::ParsedFile {
        parse_scala_file(file, source, tree)
    }
}

fn scala_object_encoded_short_name_candidates(normalized: &str) -> Vec<String> {
    const MAX_OBJECT_ENCODING_SEGMENTS: usize = 8;

    let parts: Vec<_> = normalized
        .split('.')
        .filter(|part| !part.is_empty())
        .collect();
    if parts.is_empty() {
        return Vec::new();
    }
    if parts.len() > MAX_OBJECT_ENCODING_SEGMENTS {
        return Vec::new();
    }

    let variant_count = 1_usize << parts.len();
    let mut out = Vec::new();
    for mask in 1..variant_count {
        let mut encoded = Vec::with_capacity(parts.len());
        for (index, part) in parts.iter().enumerate() {
            if (mask & (1 << index)) != 0 {
                encoded.push(format!("{part}$"));
            } else {
                encoded.push((*part).to_string());
            }
        }
        out.push(encoded.join("."));
    }
    out
}
