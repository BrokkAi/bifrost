//! Language selection for JS/TS graph targets.

use crate::syntax::slice;
use brokk_bifrost_core::analyzer::common::language_for_file;
use brokk_bifrost_core::analyzer::{CodeUnit, Language};
use tree_sitter::Node;

pub(crate) fn enclosing_function_scope<'tree>(mut node: Node<'tree>) -> Option<Node<'tree>> {
    loop {
        if matches!(
            node.kind(),
            "function_declaration"
                | "generator_function_declaration"
                | "generator_function"
                | "function_expression"
                | "arrow_function"
                | "method_definition"
        ) {
            return Some(node);
        }
        node = node.parent()?;
    }
}

pub(crate) fn simple_identifier_text<'a>(node: Node<'_>, source: &'a str) -> Option<&'a str> {
    match node.kind() {
        "identifier" | "type_identifier" => {
            let text = slice(node, source);
            (!text.is_empty()).then_some(text)
        }
        _ => None,
    }
}

/// `target`'s language when `filter` accepts it, `Language::None` otherwise.
pub fn language_for_target_filtered(
    target: &CodeUnit,
    filter: impl FnOnce(Language) -> bool,
) -> Language {
    let language = language_for_file(target.source());
    if filter(language) {
        language
    } else {
        Language::None
    }
}
