use crate::analyzer::{CodeUnit, Language, LanguageAdapter, ProjectFile, SignatureMetadata};
use tree_sitter::{Language as TsLanguage, Tree};

use super::declarations::parse_scala_file;
use super::tests::scala_contains_tests;
use super::{
    scala_member_signature_arity, scala_normalize_full_name, scala_signature_return_type,
    scala_simple_type_name,
};

#[derive(Debug, Clone, Default)]
pub(super) struct ScalaAdapter;

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
        _tree: &Tree,
        _parsed: &crate::analyzer::tree_sitter_analyzer::ParsedFile,
    ) -> bool {
        scala_contains_tests(source)
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
