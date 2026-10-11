//! Generic declaration-modifier predicates for RQL.
//!
//! Modifier words are read from the parser's modifier nodes. The relation is
//! deliberately independent of libraries and frameworks: a policy can select
//! an ordinary declaration by `static` or `abstract`, while each language
//! adapter supplies only its grammar's declaration node shape.

use crate::analyzer::usages::get_definition::parse_tree_for_language;
use crate::analyzer::{Language, ProjectFile, Range};
use crate::query::DeclarationModifier;
use brokk_bifrost_core::analyzer::tree_walk::{children_iter, named_children_iter, node_range};
use tree_sitter::Node;

/// Return exact declaration ranges carrying the requested source modifier.
/// Unsupported language or declaration shapes produce no ranges; they do not
/// become positive matches through source-text heuristics.
pub(super) fn matches_for_file(
    file: &ProjectFile,
    source: &str,
    language: Language,
    modifier: DeclarationModifier,
) -> Vec<Range> {
    let Some(tree) = parse_tree_for_language(file, language, source) else {
        return Vec::new();
    };
    let expected = modifier.label();
    let mut pending = vec![tree.root_node()];
    let mut ranges = Vec::new();
    while let Some(node) = pending.pop() {
        if is_modifier_owner(node, language) && has_modifier(node, source, expected) {
            ranges.push(node_range(node));
        }
        pending.extend(named_children_iter(node));
    }
    ranges.sort_by_key(|range| (range.start_byte, range.end_byte));
    ranges.dedup();
    ranges
}

fn is_modifier_owner(node: Node<'_>, language: Language) -> bool {
    match language {
        Language::CSharp => matches!(
            node.kind(),
            "method_declaration"
                | "constructor_declaration"
                | "class_declaration"
                | "struct_declaration"
                | "interface_declaration"
                | "enum_declaration"
                | "record_declaration"
        ),
        Language::Java => matches!(
            node.kind(),
            "method_declaration"
                | "constructor_declaration"
                | "class_declaration"
                | "interface_declaration"
                | "enum_declaration"
                | "record_declaration"
                | "annotation_type_declaration"
        ),
        Language::JavaScript | Language::TypeScript => matches!(
            node.kind(),
            "method_definition"
                | "method_signature"
                | "abstract_method_signature"
                | "field_definition"
                | "public_field_definition"
        ),
        _ => false,
    }
}

fn has_modifier(node: Node<'_>, source: &str, expected: &str) -> bool {
    if expected == "abstract" && node.kind() == "abstract_method_signature" {
        return true;
    }
    let modifiers = node
        .child_by_field_name("modifiers")
        .or_else(|| named_children_iter(node).find(|child| child.kind() == "modifiers"));
    let Some(modifiers) = modifiers else {
        return children_iter(node).any(|child| {
            child.kind() == expected
                || (child.kind() == "modifier" && node_text(child, source) == Some(expected))
        });
    };
    children_iter(modifiers).any(|modifier| {
        modifier.kind() == expected
            || (modifier.kind() == "modifier" && node_text(modifier, source) == Some(expected))
    })
}

fn node_text<'a>(node: Node<'_>, source: &'a str) -> Option<&'a str> {
    source.get(node.byte_range())
}
