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
        // The return type follows the `:` after the *parameter list's* closing
        // paren. `rfind(')')` would land inside the return type itself for a
        // function type (`fun f(): (Int) -> String`), so the list is located by
        // a balanced forward scan.
        let after_parameters = &signature[kotlin_parameter_list_end(signature)?..];
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

/// The byte offset just past the callable's parameter list in a rendered
/// signature, or `None` when there is no balanced list.
///
/// The scan starts at the parameter list rather than the first `(` in the
/// string: a signature may open with annotation arguments
/// (`@Suppress("A", "B") fun f(x: Int)`), whose commas belong to the
/// annotation, not the callable.
fn kotlin_parameter_list_end(signature: &str) -> Option<usize> {
    kotlin_scan_parameter_list(signature).map(|(_, end)| end)
}

/// Best-effort arity from a rendered signature when structured metadata is
/// absent: the number of top-level commas in the callable's parameter list.
fn kotlin_signature_arity(signature: &str) -> Option<usize> {
    kotlin_scan_parameter_list(signature).map(|(arity, _)| arity)
}

/// Scan the callable's parameter list, returning `(arity, end_offset)`.
fn kotlin_scan_parameter_list(signature: &str) -> Option<(usize, usize)> {
    let open = kotlin_parameter_list_start(signature)?;
    let mut depth = 0usize;
    let mut arguments = 0usize;
    let mut saw_content = false;
    let mut previous = ' ';
    for (offset, character) in signature[open..].char_indices() {
        match character {
            '(' | '[' | '<' => depth += 1,
            // `->` in a function-type parameter is not a closing bracket.
            '>' if previous == '-' => saw_content = true,
            ')' | ']' | '>' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    let arity = arguments + usize::from(saw_content);
                    return Some((arity, open + offset + character.len_utf8()));
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

/// The offset of the `(` that opens the callable's own parameter list,
/// skipping any leading annotation argument lists.
fn kotlin_parameter_list_start(signature: &str) -> Option<usize> {
    let mut search_from = 0usize;
    loop {
        let open = signature[search_from..].find('(')? + search_from;
        // An annotation's arguments are attached directly to an `@name`; the
        // callable's list is the first one that is not.
        let head = signature[..open].trim_end();
        let attached_to_annotation = head
            .rsplit(|character: char| character.is_whitespace())
            .next()
            .is_some_and(|token| token.starts_with('@'));
        if !attached_to_annotation {
            return Some(open);
        }
        let Some(close) = kotlin_balanced_close(signature, open) else {
            return Some(open);
        };
        search_from = close;
    }
}

/// The offset just past the `)` matching the `(` at `open`.
fn kotlin_balanced_close(signature: &str, open: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (offset, character) in signature[open..].char_indices() {
        match character {
            '(' => depth += 1,
            ')' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(open + offset + character.len_utf8());
                }
            }
            _ => {}
        }
    }
    None
}
