use tree_sitter::Node;

use crate::analyzer::{Language, ProjectFile, Range};

use super::parse_tree_for_language;
use crate::analyzer::common::language_for_file;

pub(crate) fn call_reference_ranges(
    file: &ProjectFile,
    source: &str,
    search_range: &Range,
    limit: usize,
) -> Vec<Range> {
    let language = language_for_file(file);
    let Some(tree) = parse_tree_for_language(file, language, source) else {
        return Vec::new();
    };
    collect_call_reference_ranges(tree.root_node(), language, search_range, limit)
}

pub(crate) fn is_call_reference_range(
    file: &ProjectFile,
    source: &str,
    start_byte: usize,
    end_byte: usize,
) -> bool {
    let language = language_for_file(file);
    let Some(tree) = parse_tree_for_language(file, language, source) else {
        return false;
    };
    let Some(node) = tree
        .root_node()
        .named_descendant_for_byte_range(start_byte, end_byte)
    else {
        return false;
    };
    is_call_reference_candidate(node, language)
}

fn collect_call_reference_ranges(
    root: Node<'_>,
    language: Language,
    search_range: &Range,
    limit: usize,
) -> Vec<Range> {
    let mut out = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if out.len() >= limit {
            break;
        }
        if node.end_byte() <= search_range.start_byte || node.start_byte() >= search_range.end_byte
        {
            continue;
        }
        if is_nested_callable_node(node, search_range) {
            continue;
        }
        if node.child_count() == 0 {
            if is_call_reference_candidate(node, language)
                && node.start_byte() >= search_range.start_byte
                && node.end_byte() <= search_range.end_byte
                && node.start_byte() < node.end_byte()
            {
                out.push(Range {
                    start_byte: node.start_byte(),
                    end_byte: node.end_byte(),
                    start_line: node.start_position().row,
                    end_line: node.end_position().row,
                });
            }
            continue;
        }
        let mut cursor = node.walk();
        let mut children: Vec<_> = node.named_children(&mut cursor).collect();
        children.reverse();
        for child in children {
            stack.push(child);
        }
    }
    out.sort_by_key(|range| (range.start_byte, range.end_byte));
    out.dedup_by_key(|range| (range.start_byte, range.end_byte));
    out
}

fn is_nested_callable_node(node: Node<'_>, search_range: &Range) -> bool {
    node.start_byte() > search_range.start_byte
        && node.end_byte() < search_range.end_byte
        && matches!(
            node.kind(),
            "function_declaration"
                | "function_definition"
                | "method_declaration"
                | "constructor_declaration"
                | "method_definition"
                | "function_expression"
                | "arrow_function"
                | "lambda_expression"
                | "lambda"
                | "func_literal"
                | "class_declaration"
                | "interface_declaration"
                | "enum_declaration"
                | "record_declaration"
                | "class_definition"
                | "struct_declaration"
                | "union_declaration"
                | "trait_item"
                | "impl_item"
                | "object_definition"
        )
}

fn is_call_reference_candidate(node: Node<'_>, language: Language) -> bool {
    if !is_reference_candidate_kind(node.kind()) {
        return false;
    }
    match language {
        Language::Java => java_call_reference_candidate(node),
        Language::Go => go_call_reference_candidate(node),
        Language::Cpp => cpp_call_reference_candidate(node),
        Language::JavaScript | Language::TypeScript => jsts_call_reference_candidate(node),
        Language::Python => python_call_reference_candidate(node),
        Language::Rust => rust_call_reference_candidate(node),
        Language::Php => php_call_reference_candidate(node),
        Language::Scala => scala_call_reference_candidate(node),
        Language::CSharp => csharp_call_reference_candidate(node),
        Language::Ruby | Language::None => false,
    }
}

fn is_reference_candidate_kind(kind: &str) -> bool {
    matches!(
        kind,
        "identifier"
            | "type_identifier"
            | "field_identifier"
            | "property_identifier"
            | "constant"
            | "scope_resolution"
            | "simple_identifier"
            | "scoped_identifier"
            | "namespace_identifier"
            | "variable_name"
            | "name"
            | "simple_name"
            | "identifier_token"
    )
}

fn java_call_reference_candidate(node: Node<'_>) -> bool {
    let mut current = node;
    while let Some(parent) = current.parent() {
        match parent.kind() {
            "method_invocation" if parent.child_by_field_name("name") == Some(current) => {
                return true;
            }
            "object_creation_expression" if parent.child_by_field_name("type") == Some(current) => {
                return true;
            }
            "scoped_type_identifier" | "generic_type" => current = parent,
            _ => return false,
        }
    }
    false
}

fn go_call_reference_candidate(node: Node<'_>) -> bool {
    match node.parent() {
        Some(parent)
            if parent.kind() == "call_expression"
                && parent.child_by_field_name("function") == Some(node) =>
        {
            true
        }
        Some(parent)
            if parent.kind() == "selector_expression"
                && parent.child_by_field_name("field") == Some(node) =>
        {
            parent.parent().is_some_and(|grandparent| {
                grandparent.kind() == "call_expression"
                    && grandparent.child_by_field_name("function") == Some(parent)
            })
        }
        _ => false,
    }
}

fn cpp_call_reference_candidate(node: Node<'_>) -> bool {
    let mut current = node;
    while let Some(parent) = current.parent() {
        match parent.kind() {
            "call_expression" if parent.child_by_field_name("function") == Some(current) => {
                return true;
            }
            "new_expression" if parent.start_byte() <= node.start_byte() => return true,
            "qualified_identifier" | "field_expression" => current = parent,
            _ => return false,
        }
    }
    false
}

fn jsts_call_reference_candidate(node: Node<'_>) -> bool {
    let mut current = node;
    while let Some(parent) = current.parent() {
        match parent.kind() {
            "call_expression" | "new_expression"
                if parent.child_by_field_name("function") == Some(current) =>
            {
                return true;
            }
            "member_expression"
            | "subscript_expression"
            | "identifier"
            | "property_identifier"
            | "nested_identifier"
            | "qualified_identifier" => current = parent,
            _ => return false,
        }
    }
    false
}

fn python_call_reference_candidate(node: Node<'_>) -> bool {
    let mut current = node;
    while let Some(parent) = current.parent() {
        match parent.kind() {
            "call" if parent.child_by_field_name("function") == Some(current) => return true,
            "attribute" if parent.child_by_field_name("attribute") == Some(current) => {
                current = parent;
            }
            _ => return false,
        }
    }
    false
}

fn rust_call_reference_candidate(node: Node<'_>) -> bool {
    let mut current = node;
    while let Some(parent) = current.parent() {
        match parent.kind() {
            "call_expression" if parent.child_by_field_name("function") == Some(current) => {
                return true;
            }
            "scoped_identifier" | "field_expression" => current = parent,
            _ => return false,
        }
    }
    false
}

fn php_call_reference_candidate(node: Node<'_>) -> bool {
    let mut current = node;
    while let Some(parent) = current.parent() {
        match parent.kind() {
            "function_call_expression"
            | "member_call_expression"
            | "scoped_call_expression"
            | "object_creation_expression" => return true,
            "member_access_expression"
            | "scoped_property_access_expression"
            | "qualified_name"
            | "namespace_name" => current = parent,
            _ => return false,
        }
    }
    false
}

fn scala_call_reference_candidate(node: Node<'_>) -> bool {
    let mut current = node;
    while let Some(parent) = current.parent() {
        match parent.kind() {
            "call_expression" if parent.child_by_field_name("function") == Some(current) => {
                return true;
            }
            "field_expression" | "stable_identifier" | "stable_type_identifier" => current = parent,
            _ => return false,
        }
    }
    false
}

fn csharp_call_reference_candidate(node: Node<'_>) -> bool {
    let mut current = node;
    while let Some(parent) = current.parent() {
        match parent.kind() {
            "invocation_expression" if parent.child_by_field_name("function") == Some(current) => {
                return true;
            }
            "object_creation_expression" if parent.child_by_field_name("type") == Some(current) => {
                return true;
            }
            "member_access_expression" | "qualified_name" => current = parent,
            _ => return false,
        }
    }
    false
}
