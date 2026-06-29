use tree_sitter::{Node, Tree};

use crate::analyzer::{Language, ProjectFile, Range};

use super::parse_tree_for_language;
use crate::analyzer::common::language_for_file;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CallSignatureContext {
    pub(crate) callee_range: Range,
    pub(crate) active_parameter: u32,
}

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

pub(crate) fn is_call_reference_range_in_tree(
    tree: &Tree,
    language: Language,
    start_byte: usize,
    end_byte: usize,
) -> bool {
    let Some(node) = tree
        .root_node()
        .named_descendant_for_byte_range(start_byte, end_byte)
    else {
        return false;
    };
    is_call_reference_candidate(node, language)
}

pub(crate) fn call_signature_context(
    file: &ProjectFile,
    source: &str,
    byte_offset: usize,
) -> Option<CallSignatureContext> {
    let language = language_for_file(file);
    let tree = parse_tree_for_language(file, language, source)?;
    find_innermost_call_signature_context(tree.root_node(), language, source, byte_offset)
}

fn find_innermost_call_signature_context(
    root: Node<'_>,
    language: Language,
    source: &str,
    byte_offset: usize,
) -> Option<CallSignatureContext> {
    let mut best: Option<(usize, CallSignatureContext)> = None;
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.start_byte() > byte_offset || node.end_byte() < byte_offset {
            continue;
        }
        if let Some(context) = call_signature_context_for_node(node, language, source, byte_offset)
        {
            let width = node.end_byte().saturating_sub(node.start_byte());
            if best.is_none_or(|(best_width, _)| width < best_width) {
                best = Some((width, context));
            }
        }
        let mut cursor = node.walk();
        let mut children: Vec<_> = node.named_children(&mut cursor).collect();
        children.reverse();
        for child in children {
            stack.push(child);
        }
    }
    best.map(|(_, context)| context)
}

fn call_signature_context_for_node(
    node: Node<'_>,
    language: Language,
    source: &str,
    byte_offset: usize,
) -> Option<CallSignatureContext> {
    if !is_call_expression_node(node, language) {
        return None;
    }
    let argument_nodes = argument_nodes_for_call(node);
    let [arguments] = argument_nodes.as_slice() else {
        return None;
    };
    let arguments = *arguments;
    if byte_offset < arguments.start_byte() || byte_offset > arguments.end_byte() {
        return None;
    }
    let callee = callee_node_for_call(node, language)?;
    if callee_argument_gap_has_completed_call(callee, arguments, source) {
        return None;
    }
    if is_call_expression_node(callee, language) || contains_call_expression_node(callee, language)
    {
        return None;
    }
    let callee_reference = call_reference_leaf(callee, language)?;
    Some(CallSignatureContext {
        callee_range: node_range(callee_reference),
        active_parameter: active_parameter(arguments, byte_offset),
    })
}

fn is_call_expression_node(node: Node<'_>, language: Language) -> bool {
    match language {
        Language::Java => matches!(
            node.kind(),
            "method_invocation" | "object_creation_expression"
        ),
        Language::Go => node.kind() == "call_expression",
        Language::Cpp => matches!(node.kind(), "call_expression" | "new_expression"),
        Language::JavaScript | Language::TypeScript => {
            matches!(node.kind(), "call_expression" | "new_expression")
        }
        Language::Python => node.kind() == "call",
        Language::Rust => node.kind() == "call_expression",
        Language::Php => matches!(
            node.kind(),
            "function_call_expression"
                | "member_call_expression"
                | "scoped_call_expression"
                | "object_creation_expression"
        ),
        Language::Scala => node.kind() == "call_expression",
        Language::CSharp => matches!(
            node.kind(),
            "invocation_expression" | "object_creation_expression"
        ),
        Language::Ruby | Language::None => false,
    }
}

fn callee_node_for_call<'tree>(node: Node<'tree>, language: Language) -> Option<Node<'tree>> {
    match language {
        Language::Java => node
            .child_by_field_name("name")
            .or_else(|| node.child_by_field_name("type")),
        Language::JavaScript | Language::TypeScript if node.kind() == "new_expression" => node
            .child_by_field_name("constructor")
            .or_else(|| node.child_by_field_name("function")),
        Language::CSharp => node
            .child_by_field_name("function")
            .or_else(|| node.child_by_field_name("type")),
        _ => node
            .child_by_field_name("function")
            .or_else(|| node.child_by_field_name("name"))
            .or_else(|| node.child_by_field_name("type"))
            .or_else(|| first_named_child_not_arguments(node)),
    }
}

fn arguments_node_for_call(node: Node<'_>) -> Option<Node<'_>> {
    argument_nodes_for_call(node).into_iter().next()
}

fn argument_nodes_for_call(node: Node<'_>) -> Vec<Node<'_>> {
    let mut nodes = Vec::new();
    if let Some(arguments) = node
        .child_by_field_name("arguments")
        .or_else(|| node.child_by_field_name("argument"))
    {
        nodes.push(arguments);
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if matches!(
            child.kind(),
            "arguments"
                | "argument"
                | "argument_list"
                | "argument_clause"
                | "arguments_list"
                | "block"
        ) && !nodes.contains(&child)
        {
            nodes.push(child);
        }
    }
    nodes
}

fn first_named_child_not_arguments(node: Node<'_>) -> Option<Node<'_>> {
    let arguments = arguments_node_for_call(node);
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|child| Some(*child) != arguments)
}

fn call_reference_leaf(node: Node<'_>, language: Language) -> Option<Node<'_>> {
    if node.child_count() == 0 {
        return is_call_reference_candidate(node, language).then_some(node);
    }
    let mut best = None;
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if current.child_count() == 0 && is_call_reference_candidate(current, language) {
            best = Some(current);
            continue;
        }
        let mut cursor = current.walk();
        let mut children: Vec<_> = current.named_children(&mut cursor).collect();
        children.reverse();
        for child in children {
            stack.push(child);
        }
    }
    best
}

fn contains_call_expression_node(node: Node<'_>, language: Language) -> bool {
    let mut stack = Vec::new();
    let mut cursor = node.walk();
    stack.extend(node.named_children(&mut cursor));
    while let Some(current) = stack.pop() {
        if is_call_expression_node(current, language) {
            return true;
        }
        let mut cursor = current.walk();
        stack.extend(current.named_children(&mut cursor));
    }
    false
}

fn callee_argument_gap_has_completed_call(
    callee: Node<'_>,
    arguments: Node<'_>,
    source: &str,
) -> bool {
    if callee.end_byte() >= arguments.start_byte() {
        return false;
    }
    source
        .get(callee.end_byte()..arguments.start_byte())
        .is_some_and(|gap| gap.contains(')'))
}

fn active_parameter(arguments: Node<'_>, byte_offset: usize) -> u32 {
    let mut active = 0;
    let mut cursor = arguments.walk();
    for child in arguments.named_children(&mut cursor) {
        if child.end_byte() < byte_offset {
            active += 1;
        }
    }
    active
}

fn node_range(node: Node<'_>) -> Range {
    Range {
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
        start_line: node.start_position().row,
        end_line: node.end_position().row,
    }
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
            "call_expression" if parent.child_by_field_name("function") == Some(current) => {
                return true;
            }
            "new_expression"
                if parent.child_by_field_name("function") == Some(current)
                    || parent.child_by_field_name("constructor") == Some(current) =>
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

#[cfg(test)]
mod tests {
    use std::env;

    use super::call_signature_context;
    use crate::analyzer::ProjectFile;

    fn file(name: &str) -> ProjectFile {
        ProjectFile::new(env::temp_dir().join("bifrost-signature-help"), name)
    }

    fn offset_after(source: &str, needle: &str) -> usize {
        source.find(needle).expect("needle exists") + needle.len()
    }

    #[test]
    fn signature_context_counts_active_parameter_after_comma() {
        let source =
            "class A { int target(int left, int right) { return 0; } void f() { target(1, 2); } }";
        let context = call_signature_context(&file("A.java"), source, offset_after(source, "1, "))
            .expect("signature context");

        assert_eq!(context.active_parameter, 1);
        assert_eq!(
            &source[context.callee_range.start_byte..context.callee_range.end_byte],
            "target"
        );
    }

    #[test]
    fn signature_context_prefers_innermost_call() {
        let source = "function inner(value: number) { return value; }\nfunction outer(value: number) { return value; }\nouter(inner(1));\n";
        let context = call_signature_context(
            &file("sample.ts"),
            source,
            offset_after(source, "outer(inner("),
        )
        .expect("signature context");

        assert_eq!(
            &source[context.callee_range.start_byte..context.callee_range.end_byte],
            "inner"
        );
        assert_eq!(context.active_parameter, 0);
    }

    #[test]
    fn signature_context_handles_empty_argument_list() {
        let source = "fn target() {}\nfn caller() { target(); }\n";
        let context = call_signature_context(
            &file("lib.rs"),
            source,
            offset_after(source, "caller() { target("),
        )
        .expect("signature context");

        assert_eq!(
            &source[context.callee_range.start_byte..context.callee_range.end_byte],
            "target"
        );
        assert_eq!(context.active_parameter, 0);
    }

    #[test]
    fn signature_context_handles_scala_brace_argument_block() {
        let source =
            "object App {\n  def target(value: Int): Int = value\n  val result = target { 1 }\n}\n";
        let context = call_signature_context(
            &file("App.scala"),
            source,
            offset_after(source, "target { "),
        )
        .expect("signature context");

        assert_eq!(
            &source[context.callee_range.start_byte..context.callee_range.end_byte],
            "target"
        );
        assert_eq!(context.active_parameter, 0);
    }

    #[test]
    fn signature_context_rejects_higher_order_call_callee() {
        let source = "function factory() { return (value: number) => value; }\nconst result = factory()(1);\n";
        let context = call_signature_context(
            &file("sample.ts"),
            source,
            offset_after(source, "factory()("),
        );

        assert_eq!(context, None);
    }
}
