use crate::analyzer::{Language, LanguageAdapter, ProjectFile, SignatureMetadata};
use tree_sitter::Tree;

use super::declarations::parse_kotlin_file;

#[derive(Debug, Clone, Default)]
pub(crate) struct KotlinAdapter;

impl LanguageAdapter for KotlinAdapter {
    fn language(&self) -> Language {
        Language::Kotlin
    }

    fn query_directory(&self) -> &'static str {
        "resources/treesitter/kotlin"
    }

    fn file_extension(&self) -> &'static str {
        "kt"
    }

    fn callable_arity(
        &self,
        signature: &str,
        metadata: Option<&SignatureMetadata>,
    ) -> Option<usize> {
        metadata
            .and_then(SignatureMetadata::callable_arity)
            .map(|arity| arity.total())
            .or_else(|| kotlin_signature_arity(signature))
    }

    fn callable_return_type_text<'a>(&self, signature: &'a str) -> Option<&'a str> {
        // The return type is everything after the last top-level `:` that
        // follows the parameter list (`fun f(x: Int): List<Int>`).
        let close = signature.rfind(')')?;
        let after_parameters = &signature[close + 1..];
        let (_, return_type) = after_parameters.split_once(':')?;
        let return_type = return_type.trim();
        (!return_type.is_empty()).then_some(return_type)
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
        parse_kotlin_file(file, source, tree)
    }
}

/// Best-effort arity from a rendered signature when metadata is absent:
/// the number of top-level commas in the first balanced parameter list.
fn kotlin_signature_arity(signature: &str) -> Option<usize> {
    let open = signature.find('(')?;
    let mut depth = 0usize;
    let mut arguments = 0usize;
    let mut saw_content = false;
    let mut previous = ' ';
    for character in signature[open..].chars() {
        match character {
            '(' | '[' | '<' => depth += 1,
            // `->` in a function-type parameter is not a closing bracket.
            '>' if previous == '-' => saw_content = true,
            ')' | ']' | '>' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(arguments + usize::from(saw_content));
                }
            }
            ',' if depth == 1 => arguments += 1,
            character if !character.is_whitespace() => saw_content = true,
            _ => {}
        }
        previous = character;
    }
    None
}
