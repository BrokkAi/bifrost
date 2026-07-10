use crate::analyzer::{Language, LanguageAdapter, ProjectFile, SignatureMetadata};
use tree_sitter::{Language as TsLanguage, Tree};

use super::declarations::parse_csharp_file;
use super::tests::csharp_contains_tests;
use super::{csharp_normalize_full_name, csharp_signature_arity, csharp_signature_return_type};

#[derive(Debug, Clone, Default)]
pub(super) struct CSharpAdapter;

impl crate::analyzer::StorageLanguageAdapter for CSharpAdapter {}

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
        _tree: &Tree,
        _parsed: &crate::analyzer::tree_sitter_analyzer::ParsedFile,
    ) -> bool {
        csharp_contains_tests(source)
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
