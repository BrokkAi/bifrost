use tree_sitter::{Node, Tree};

use crate::analyzer::{Language, ProjectFile, Range};

use super::{parse_tree_for_language, scala::scala_postfix_method_node};
use crate::analyzer::common::language_for_file;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CallSignatureContext {
    pub(crate) callee_range: Range,
    pub(crate) active_parameter: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum CallSyntaxKind {
    Function,
    Method,
    Constructor,
    Super,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct CallArgumentSyntax {
    pub(crate) range: Range,
    pub(crate) name: Option<String>,
    pub(crate) position: Option<usize>,
    pub(crate) spread: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct CallSiteSyntax {
    pub(crate) range: Range,
    pub(crate) callee_range: Range,
    pub(crate) receiver: Option<Range>,
    pub(crate) arguments: Vec<CallArgumentSyntax>,
    pub(crate) kind: CallSyntaxKind,
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

pub(crate) fn call_site_syntax_for_reference(
    tree: &Tree,
    language: Language,
    source: &str,
    start_byte: usize,
    end_byte: usize,
) -> Option<CallSiteSyntax> {
    let mut current = tree
        .root_node()
        .named_descendant_for_byte_range(start_byte, end_byte)?;
    if language == Language::Ruby && ruby_bare_call_identifier(current) {
        let range = node_range(current);
        return Some(CallSiteSyntax {
            range,
            callee_range: range,
            receiver: None,
            arguments: Vec::new(),
            kind: CallSyntaxKind::Function,
        });
    }
    let call = loop {
        if is_call_expression_node(current, language)
            || (language == Language::Scala
                && matches!(current.kind(), "infix_expression" | "postfix_expression"))
        {
            break current;
        }
        current = current.parent()?;
    };

    let callee = if language == Language::Scala && call.kind() == "infix_expression" {
        call.child_by_field_name("operator")?
    } else if language == Language::Scala && call.kind() == "postfix_expression" {
        scala_postfix_method_node(call)?
    } else {
        call_reference_leaf(callee_node_for_call(call, language)?, language)?
    };
    if start_byte < callee.start_byte() || end_byte > callee.end_byte() {
        return None;
    }

    let receiver_node = receiver_node_for_call(call, callee, language);
    let receiver = receiver_node.map(node_range);
    let arguments = call_arguments(call, language, source);
    let kind = if matches!(call.kind(), "object_creation_expression" | "new_expression") {
        CallSyntaxKind::Constructor
    } else if callee.kind() == "super" || receiver_node.is_some_and(|node| node.kind() == "super") {
        CallSyntaxKind::Super
    } else if receiver.is_some() {
        CallSyntaxKind::Method
    } else {
        CallSyntaxKind::Function
    };
    Some(CallSiteSyntax {
        range: node_range(call),
        callee_range: node_range(callee),
        receiver,
        arguments,
        kind,
    })
}

fn receiver_node_for_call<'tree>(
    call: Node<'tree>,
    callee: Node<'tree>,
    language: Language,
) -> Option<Node<'tree>> {
    for field in ["object", "receiver"] {
        if let Some(receiver) = call.child_by_field_name(field) {
            return Some(receiver);
        }
    }

    let receiver_fields: &[&str] = match language {
        Language::Go => &["operand"],
        Language::Cpp => &["argument", "object"],
        Language::JavaScript | Language::TypeScript | Language::Python => &["object"],
        Language::Rust => &["value"],
        Language::Php => &["object"],
        Language::Scala => &["left", "object"],
        Language::CSharp => &["expression"],
        Language::Ruby => &["receiver"],
        Language::Java | Language::None => &[],
    };
    let mut current = callee;
    while let Some(parent) = current.parent() {
        if parent == call {
            break;
        }
        for field in receiver_fields {
            if let Some(receiver) = parent.child_by_field_name(field)
                && receiver != current
            {
                return Some(receiver);
            }
        }
        current = parent;
    }
    None
}

fn call_arguments(call: Node<'_>, language: Language, source: &str) -> Vec<CallArgumentSyntax> {
    if language == Language::Scala && call.kind() == "infix_expression" {
        return call
            .child_by_field_name("right")
            .map(|argument| CallArgumentSyntax {
                range: node_range(argument),
                name: None,
                position: Some(0),
                spread: false,
            })
            .into_iter()
            .collect();
    }
    if language == Language::Scala && call.kind() == "postfix_expression" {
        return Vec::new();
    }

    let mut arguments = Vec::new();
    let mut position = 0;
    for container in argument_nodes_for_call(call, language) {
        let mut cursor = container.walk();
        for argument in container.named_children(&mut cursor) {
            let name_node = named_argument_name(argument, language);
            let value = named_argument_value(argument, language).unwrap_or(argument);
            let name = name_node.and_then(|name| source.get(name.byte_range()).map(str::to_owned));
            let argument_position = if name.is_none() {
                let current = position;
                position += 1;
                Some(current)
            } else {
                None
            };
            arguments.push(CallArgumentSyntax {
                range: node_range(value),
                name,
                position: argument_position,
                spread: is_spread_argument(argument.kind()),
            });
        }
    }
    arguments.sort_by_key(|argument| (argument.range.start_byte, argument.range.end_byte));
    arguments.dedup_by_key(|argument| (argument.range.start_byte, argument.range.end_byte));
    arguments
}

fn named_argument_name(node: Node<'_>, language: Language) -> Option<Node<'_>> {
    if !matches!(
        node.kind(),
        "keyword_argument"
            | "named_argument"
            | "pair"
            | "hash_pair"
            | "argument"
            | "assignment_expression"
    ) {
        return None;
    }
    node.child_by_field_name("name")
        .or_else(|| node.child_by_field_name("key"))
        .or_else(|| {
            (language == Language::Scala && node.kind() == "assignment_expression")
                .then(|| node.child_by_field_name("left"))
                .flatten()
        })
}

fn named_argument_value(node: Node<'_>, language: Language) -> Option<Node<'_>> {
    let name = named_argument_name(node, language)?;
    node.child_by_field_name("value")
        .or_else(|| node.child_by_field_name("expression"))
        .or_else(|| node.child_by_field_name("right"))
        .or_else(|| {
            let mut cursor = node.walk();
            node.named_children(&mut cursor)
                .find(|child| *child != name && !matches!(child.kind(), "reference_modifier"))
        })
}

fn is_spread_argument(kind: &str) -> bool {
    matches!(
        kind,
        "spread_element"
            | "splat_argument"
            | "hash_splat_argument"
            | "list_splat"
            | "dictionary_splat"
            | "spread_argument"
    )
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
    if language == Language::Scala
        && let Some(context) = scala_call_signature_context_for_node(node, byte_offset)
    {
        return Some(context);
    }
    if !is_call_expression_node(node, language) {
        return None;
    }
    let argument_nodes = argument_nodes_for_call(node, language);
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
        Language::Ruby => node.kind() == "call",
        Language::None => false,
    }
}

fn scala_call_signature_context_for_node(
    node: Node<'_>,
    byte_offset: usize,
) -> Option<CallSignatureContext> {
    match node.kind() {
        "infix_expression" => {
            let operator = node.child_by_field_name("operator")?;
            let right = node.child_by_field_name("right")?;
            if byte_offset < right.start_byte() || byte_offset > right.end_byte() {
                return None;
            }
            Some(CallSignatureContext {
                callee_range: node_range(operator),
                active_parameter: 0,
            })
        }
        "postfix_expression" => {
            let method = scala_postfix_method_node(node)?;
            if byte_offset < method.start_byte() || byte_offset > method.end_byte() {
                return None;
            }
            Some(CallSignatureContext {
                callee_range: node_range(method),
                active_parameter: 0,
            })
        }
        _ => None,
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
        Language::Ruby => node.child_by_field_name("method"),
        _ => node
            .child_by_field_name("function")
            .or_else(|| node.child_by_field_name("name"))
            .or_else(|| node.child_by_field_name("type"))
            .or_else(|| first_named_child_not_arguments(node, language)),
    }
}

fn arguments_node_for_call(node: Node<'_>, language: Language) -> Option<Node<'_>> {
    argument_nodes_for_call(node, language).into_iter().next()
}

fn argument_nodes_for_call(node: Node<'_>, language: Language) -> Vec<Node<'_>> {
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
            && !(language == Language::Ruby && matches!(child.kind(), "block" | "do_block"))
        {
            nodes.push(child);
        }
    }
    nodes
}

fn first_named_child_not_arguments(node: Node<'_>, language: Language) -> Option<Node<'_>> {
    let arguments = arguments_node_for_call(node, language);
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
                | "method"
                | "singleton_method"
                | "module"
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
        Language::Ruby => ruby_call_reference_candidate(node),
        Language::None => false,
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

fn ruby_call_reference_candidate(node: Node<'_>) -> bool {
    if ruby_bare_call_identifier(node) {
        return true;
    }
    let mut current = node;
    while let Some(parent) = current.parent() {
        match parent.kind() {
            "call" if parent.child_by_field_name("method") == Some(current) => return true,
            "scope_resolution" if parent.child_by_field_name("name") == Some(current) => {
                current = parent;
            }
            _ => return false,
        }
    }
    false
}

fn ruby_bare_call_identifier(node: Node<'_>) -> bool {
    node.kind() == "identifier"
        && node
            .parent()
            .is_some_and(|parent| parent.kind() == "body_statement")
}

#[cfg(test)]
mod tests {
    use std::env;

    use super::{call_signature_context, call_site_syntax_for_reference};
    use crate::analyzer::usages::get_definition::parse_tree_for_language;
    use crate::analyzer::{Language, ProjectFile};

    fn file(name: &str) -> ProjectFile {
        ProjectFile::new(env::temp_dir().join("bifrost-signature-help"), name)
    }

    fn offset_after(source: &str, needle: &str) -> usize {
        source.find(needle).expect("needle exists") + needle.len()
    }

    #[test]
    fn ruby_bare_call_has_a_structured_call_site() {
        let source = "def target; end\ndef caller; target; end\n";
        let file = file("sample.rb");
        let tree = parse_tree_for_language(&file, Language::Ruby, source).expect("Ruby parse");
        let start = source.rfind("target").expect("call target");
        let site = call_site_syntax_for_reference(
            &tree,
            Language::Ruby,
            source,
            start,
            start + "target".len(),
        )
        .unwrap_or_else(|| panic!("bare Ruby call site: {}", tree.root_node().to_sexp()));
        assert_eq!(
            &source[site.callee_range.start_byte..site.callee_range.end_byte],
            "target"
        );
        assert_eq!(
            &source[site.range.start_byte..site.range.end_byte],
            "target"
        );
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
    fn signature_context_handles_ruby_bare_call() {
        let source = "def target(left, right)\nend\n\ntarget(1, 2)\n";
        let context = call_signature_context(
            &file("sample.rb"),
            source,
            offset_after(source, "target(1, "),
        )
        .expect("signature context");

        assert_eq!(
            &source[context.callee_range.start_byte..context.callee_range.end_byte],
            "target"
        );
        assert_eq!(context.active_parameter, 1);
    }

    #[test]
    fn signature_context_handles_ruby_receiver_call() {
        let source = "user.target(1, 2)\n";
        let context = call_signature_context(
            &file("sample.rb"),
            source,
            offset_after(source, "target(1, "),
        )
        .expect("signature context");

        assert_eq!(
            &source[context.callee_range.start_byte..context.callee_range.end_byte],
            "target"
        );
        assert_eq!(context.active_parameter, 1);
    }

    #[test]
    fn signature_context_handles_ruby_parenthesized_call_with_block() {
        let source = "target(1, 2) { |item| item }\n";
        let context = call_signature_context(
            &file("sample.rb"),
            source,
            offset_after(source, "target(1, "),
        )
        .expect("signature context");

        assert_eq!(
            &source[context.callee_range.start_byte..context.callee_range.end_byte],
            "target"
        );
        assert_eq!(context.active_parameter, 1);
    }

    #[test]
    fn signature_context_handles_ruby_command_call_with_block() {
        let source = "target 1, 2 do |item|\n  item\nend\n";
        let context = call_signature_context(
            &file("sample.rb"),
            source,
            offset_after(source, "target 1, "),
        )
        .expect("signature context");

        assert_eq!(
            &source[context.callee_range.start_byte..context.callee_range.end_byte],
            "target"
        );
        assert_eq!(context.active_parameter, 1);
    }

    #[test]
    fn signature_context_prefers_innermost_ruby_call() {
        let source = "outer(inner(1), 2)\n";
        let context =
            call_signature_context(&file("sample.rb"), source, offset_after(source, "inner("))
                .expect("signature context");

        assert_eq!(
            &source[context.callee_range.start_byte..context.callee_range.end_byte],
            "inner"
        );
        assert_eq!(context.active_parameter, 0);
    }

    #[test]
    fn signature_context_handles_scala_infix_call() {
        let source = "object App {\n  class Box { def combine(value: Int): Int = value }\n  val box = new Box\n  val result = box combine 1\n}\n";
        let context = call_signature_context(
            &file("App.scala"),
            source,
            offset_after(source, "box combine "),
        )
        .expect("signature context");

        assert_eq!(
            &source[context.callee_range.start_byte..context.callee_range.end_byte],
            "combine"
        );
        assert_eq!(context.active_parameter, 0);
    }

    #[test]
    fn signature_context_handles_scala_postfix_call() {
        let source = "object App {\n  class Box { def ready: Boolean = true }\n  val box = new Box\n  val result = box ready\n}\n";
        let context = call_signature_context(
            &file("App.scala"),
            source,
            offset_after(source, "box ready"),
        )
        .expect("signature context");

        assert_eq!(
            &source[context.callee_range.start_byte..context.callee_range.end_byte],
            "ready"
        );
        assert_eq!(context.active_parameter, 0);
    }

    #[test]
    fn signature_context_handles_scala_postfix_operator_call() {
        let source = "object App {\n  class Box { def ! : Boolean = true }\n  val box = new Box\n  val result = box !\n}\n";
        let context =
            call_signature_context(&file("App.scala"), source, offset_after(source, "box !"))
                .expect("signature context");

        assert_eq!(
            &source[context.callee_range.start_byte..context.callee_range.end_byte],
            "!"
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
