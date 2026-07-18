use crate::analyzer::scala::scala_type_lookup_segments;
use crate::analyzer::{CallableArity, ImportInfo, scala_parenthesized_arity};
use crate::hash::{HashMap, HashSet};
use tree_sitter::{Node, Parser};

#[derive(Default)]
pub(crate) struct ScalaSourceFacts {
    pub(crate) callable_alternatives_by_range:
        HashMap<(usize, usize), ScalaCallableSourceAlternative>,
    pub(crate) stable_owner_ranges: HashSet<(usize, usize)>,
}

#[derive(Clone)]
pub(crate) struct ScalaCallableSourceAlternative {
    pub(crate) shape: Vec<CallableArity>,
    pub(crate) extension_receiver_type_path: Option<Vec<String>>,
    pub(crate) return_type_path: Option<Vec<String>>,
}

pub(crate) fn scala_source_facts(source: &str) -> Option<ScalaSourceFacts> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_scala::LANGUAGE.into())
        .ok()?;
    let tree = parser.parse(source, None)?;
    let mut facts = ScalaSourceFacts::default();
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "function_definition" | "function_declaration" => {
                let mut cursor = node.walk();
                let shape = node
                    .named_children(&mut cursor)
                    .filter(|child| child.kind() == "parameters")
                    .map(callable_arity_for_parameters)
                    .collect();
                facts.callable_alternatives_by_range.insert(
                    (node.start_byte(), node.end_byte()),
                    ScalaCallableSourceAlternative {
                        shape,
                        extension_receiver_type_path: enclosing_extension_receiver_type_path(
                            node, source,
                        ),
                        return_type_path: node
                            .child_by_field_name("return_type")
                            .map(|return_type| scala_type_lookup_segments(return_type, source))
                            .filter(|segments| !segments.is_empty()),
                    },
                );
            }
            "class_definition" => {
                let mut cursor = node.walk();
                let lists = node
                    .named_children(&mut cursor)
                    .filter(|child| child.kind() == "class_parameters")
                    .map(callable_arity_for_parameters)
                    .collect::<Vec<_>>();
                if !lists.is_empty() {
                    facts.callable_alternatives_by_range.insert(
                        (node.start_byte(), node.end_byte()),
                        ScalaCallableSourceAlternative {
                            shape: lists,
                            extension_receiver_type_path: None,
                            return_type_path: None,
                        },
                    );
                }
            }
            "object_definition" | "enum_definition" => {
                facts
                    .stable_owner_ranges
                    .insert((node.start_byte(), node.end_byte()));
            }
            _ => {}
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    Some(facts)
}

/// Return the parser-derived lookup paths of every direct alternative in a
/// Scala 3 union type. Tree-sitter represents `A | B` as an `infix_type`; only
/// the `|` operator is flattened, so unrelated infix/compound type syntax is
/// never reinterpreted as a union.
pub(crate) fn scala_union_type_alternative_paths(
    node: Node<'_>,
    source: &str,
) -> Option<Vec<Vec<String>>> {
    if !is_union_type(node, source) {
        return None;
    }

    let mut alternatives = Vec::new();
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if is_union_type(current, source) {
            stack.push(current.child_by_field_name("right")?);
            stack.push(current.child_by_field_name("left")?);
            continue;
        }
        let path = scala_type_lookup_segments(current, source);
        if path.is_empty() {
            return None;
        }
        alternatives.push(path);
    }
    (!alternatives.is_empty()).then_some(alternatives)
}

fn is_union_type(node: Node<'_>, source: &str) -> bool {
    node.kind() == "infix_type"
        && node
            .child_by_field_name("operator")
            .is_some_and(|operator| node_text(operator, source).trim() == "|")
}

fn enclosing_extension_receiver_type_path(node: Node<'_>, source: &str) -> Option<Vec<String>> {
    let mut current = node.parent();
    while let Some(ancestor) = current {
        if ancestor.kind() == "extension_definition" {
            let parameters = ancestor.child_by_field_name("parameters")?;
            let mut cursor = parameters.walk();
            return parameters
                .named_children(&mut cursor)
                .find(|parameter| matches!(parameter.kind(), "parameter" | "class_parameter"))
                .and_then(|parameter| parameter.child_by_field_name("type"))
                .map(|type_node| scala_type_lookup_segments(type_node, source))
                .filter(|segments| !segments.is_empty());
        }
        if matches!(
            ancestor.kind(),
            "function_definition" | "function_declaration"
        ) {
            return None;
        }
        current = ancestor.parent();
    }
    None
}

fn callable_arity_for_parameters(parameters: Node<'_>) -> CallableArity {
    let mut total = 0usize;
    let mut required = 0usize;
    let mut repeated = false;
    let mut cursor = parameters.walk();
    for parameter in parameters.named_children(&mut cursor) {
        if !matches!(parameter.kind(), "parameter" | "class_parameter") {
            continue;
        }
        total += 1;
        let is_repeated = parameter
            .child_by_field_name("type")
            .is_some_and(contains_repeated_parameter_type);
        repeated |= is_repeated;
        if parameter.child_by_field_name("default_value").is_none() && !is_repeated {
            required += 1;
        }
    }
    CallableArity::new(required, total, repeated)
}

fn contains_repeated_parameter_type(node: Node<'_>) -> bool {
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if current.kind() == "repeated_parameter_type" {
            return true;
        }
        let mut cursor = current.walk();
        stack.extend(current.named_children(&mut cursor));
    }
    false
}

pub(super) fn parenthesized_arity(source: &str) -> Option<usize> {
    scala_parenthesized_arity(source)
}

pub(crate) fn scala_import_path(info: &ImportInfo) -> Option<String> {
    let trimmed = info
        .raw_snippet
        .trim()
        .strip_prefix("import ")
        .unwrap_or(info.raw_snippet.trim())
        .trim();
    if trimmed.is_empty() {
        return None;
    }
    if info.is_wildcard {
        return Some(
            trimmed
                .trim_end_matches(".*")
                .trim_end_matches("._")
                .to_string(),
        );
    }
    Some(
        trimmed
            .split_once(" as ")
            .map(|(path, _)| path)
            .or_else(|| trimmed.split_once(" => ").map(|(path, _)| path))
            .unwrap_or(trimmed)
            .trim()
            .to_string(),
    )
}

pub(crate) fn is_identifier_node(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "identifier" | "type_identifier" | "operator_identifier"
    )
}

pub(crate) fn is_type_like_reference(node: Node<'_>, source: &str) -> bool {
    node.kind() == "type_identifier"
        || is_constructor_like_reference(node, source)
        || parent_kind(node).is_some_and(|kind| {
            matches!(
                kind,
                "type" | "generic_type" | "parameterized_type" | "extends_clause"
            )
        })
}

pub(crate) fn is_scala_object_reference(node: Node<'_>) -> bool {
    is_singleton_type_reference(node)
        || is_stable_type_qualifier(node)
        || is_extractor_reference(node)
        || is_infix_pattern_operator(node)
        || is_field_expression_value(node)
        || is_bare_term_reference(node)
}

pub(crate) fn is_scala_class_reference(node: Node<'_>, source: &str) -> bool {
    is_type_like_reference(node, source)
        && !is_singleton_type_reference(node)
        && !is_stable_type_qualifier(node)
        && !is_extractor_reference(node)
        && !is_infix_pattern_operator(node)
        && !node.parent().is_some_and(|parent| {
            parent.kind() == "call_expression"
                && parent.child_by_field_name("function") == Some(node)
        })
}

fn is_singleton_type_reference(node: Node<'_>) -> bool {
    node.parent()
        .is_some_and(|parent| parent.kind() == "singleton_type")
}

fn is_stable_type_qualifier(node: Node<'_>) -> bool {
    node.parent().is_some_and(|parent| {
        parent.kind() == "stable_type_identifier"
            && parent.child_by_field_name("name") != Some(node)
    })
}

fn is_extractor_reference(node: Node<'_>) -> bool {
    node.parent().is_some_and(|parent| {
        parent.kind() == "case_class_pattern"
            && parent
                .named_child(0)
                .is_some_and(|constructor| constructor == node)
    })
}

fn is_infix_pattern_operator(node: Node<'_>) -> bool {
    node.parent().is_some_and(|parent| {
        parent.kind() == "infix_pattern" && parent.child_by_field_name("operator") == Some(node)
    })
}

pub(crate) fn is_terminal_stable_field_reference(node: Node<'_>) -> bool {
    let Some(field) = node.parent().filter(|parent| {
        parent.kind() == "field_expression" && parent.child_by_field_name("field") == Some(node)
    }) else {
        return false;
    };
    !field.parent().is_some_and(|parent| {
        parent.kind() == "call_expression" && parent.child_by_field_name("function") == Some(field)
    })
}

/// Resolve a stable object path from its tree-sitter structure. The root and
/// each child segment are resolved independently so callers never infer object
/// identity by splitting source text.
pub(crate) fn resolve_stable_object_expression<T>(
    mut node: Node<'_>,
    source: &str,
    mut resolve_root: impl FnMut(&str) -> Option<T>,
    mut resolve_child: impl FnMut(&T, &str) -> Option<T>,
) -> Option<T> {
    let mut fields = Vec::new();
    while node.kind() == "field_expression" {
        fields.push(node.child_by_field_name("field")?);
        node = node.child_by_field_name("value")?;
    }
    if !matches!(node.kind(), "identifier" | "type_identifier") {
        return None;
    }
    let root = node_text(node, source).trim();
    if root.is_empty() {
        return None;
    }
    let mut resolved = resolve_root(root)?;
    for field in fields.into_iter().rev() {
        let field = node_text(field, source).trim();
        if field.is_empty() {
            return None;
        }
        resolved = resolve_child(&resolved, field)?;
    }
    Some(resolved)
}

fn is_bare_term_reference(node: Node<'_>) -> bool {
    if node.kind() != "identifier" {
        return false;
    }
    let Some(parent) = node.parent() else {
        return false;
    };
    match parent.kind() {
        "class_definition"
        | "object_definition"
        | "trait_definition"
        | "enum_definition"
        | "function_declaration"
        | "parameter"
        | "class_parameter"
        | "type_parameters"
        | "import_declaration"
        | "stable_type_identifier"
        | "singleton_type"
        | "case_class_pattern"
        | "infix_pattern" => false,
        "function_definition" => parent.child_by_field_name("body") == Some(node),
        "val_definition" | "var_definition" => parent.child_by_field_name("pattern") != Some(node),
        "field_expression" => parent.child_by_field_name("field") != Some(node),
        _ => true,
    }
}

pub(crate) fn is_field_expression_value(node: Node<'_>) -> bool {
    node.parent().is_some_and(|parent| {
        parent.kind() == "field_expression" && parent.child_by_field_name("value") == Some(node)
    })
}

pub(crate) fn is_constructor_like_reference(node: Node<'_>, source: &str) -> bool {
    let prefix = source[..node.start_byte()].trim_end();
    prefix.ends_with("new")
        || parent_kind(node).is_some_and(|kind| matches!(kind, "call_expression" | "type"))
}

pub(crate) fn parent_kind(node: Node<'_>) -> Option<&str> {
    node.parent().map(|parent| parent.kind())
}

pub(crate) fn has_ancestor_kind(node: Node<'_>, kind: &str) -> bool {
    let mut current = node.parent();
    while let Some(parent) = current {
        if parent.kind() == kind {
            return true;
        }
        current = parent.parent();
    }
    false
}

pub(crate) fn field_expression_for_member(node: Node<'_>) -> Option<Node<'_>> {
    let parent = node.parent()?;
    if parent.kind() == "field_expression" && parent.child_by_field_name("field") == Some(node) {
        Some(parent)
    } else {
        None
    }
}

pub(crate) fn has_member_qualifier(node: Node<'_>) -> bool {
    field_expression_for_member(node).is_some()
}

pub(crate) fn member_qualifier_node(node: Node<'_>) -> Option<Node<'_>> {
    field_expression_for_member(node)?.child_by_field_name("value")
}

pub(crate) fn member_qualifier(node: Node<'_>, source: &str) -> Option<String> {
    member_qualifier_node(node)
        .map(|value| {
            node_text(value, source)
                .trim()
                .trim_end_matches('$')
                .to_string()
        })
        .filter(|qualifier| !qualifier.is_empty())
}

pub(crate) fn is_owner_qualified_this(qualifier: Node<'_>, source: &str) -> bool {
    qualifier.kind() == "field_expression"
        && qualifier
            .child_by_field_name("field")
            .is_some_and(|field| node_text(field, source).trim() == "this")
}

pub(crate) fn stable_type_qualifier(node: Node<'_>, source: &str) -> Option<String> {
    let parent = node.parent()?;
    if parent.kind() != "stable_type_identifier" || parent.end_byte() != node.end_byte() {
        return None;
    }
    let prefix = source[parent.start_byte()..node.start_byte()]
        .trim()
        .trim_end_matches('.')
        .trim_end_matches('$')
        .to_string();
    (!prefix.is_empty()).then_some(prefix)
}

pub(crate) fn call_arity_for_reference(node: Node<'_>) -> Option<usize> {
    call_arities_for_reference(node).and_then(|arities| arities.first().copied())
}

pub(crate) fn call_arities_for_reference(node: Node<'_>) -> Option<Vec<usize>> {
    let parent = node.parent()?;
    if parent.kind() == "infix_expression" && parent.child_by_field_name("operator") == Some(node) {
        return Some(vec![1]);
    }
    let mut expression = field_expression_for_member(node).unwrap_or(node);
    if expression.parent().is_some_and(|generic| {
        generic.kind() == "generic_function"
            && generic.child_by_field_name("function") == Some(expression)
    }) {
        expression = expression.parent()?;
    }
    let mut arities = Vec::new();
    if let Some(instance) = expression
        .parent()
        .filter(|parent| parent.kind() == "instance_expression")
    {
        let arguments = instance.child_by_field_name("arguments").or_else(|| {
            let mut cursor = instance.walk();
            instance
                .named_children(&mut cursor)
                .find(|child| child.kind() == "arguments")
        })?;
        let mut cursor = arguments.walk();
        arities.push(arguments.named_children(&mut cursor).count());
        expression = instance;
    }
    while let Some(call) = expression.parent() {
        if call.kind() != "call_expression"
            || call.child_by_field_name("function") != Some(expression)
        {
            break;
        }
        let arguments = call.child_by_field_name("arguments")?;
        let mut cursor = arguments.walk();
        arities.push(arguments.named_children(&mut cursor).count());
        expression = call;
    }
    (!arities.is_empty()).then_some(arities)
}

pub(crate) fn infix_receiver_for_operator(node: Node<'_>) -> Option<Node<'_>> {
    let parent = node.parent()?;
    (parent.kind() == "infix_expression" && parent.child_by_field_name("operator") == Some(node))
        .then(|| parent.child_by_field_name("left"))
        .flatten()
}

pub(crate) fn named_argument_invocation_owner(node: Node<'_>) -> Option<Node<'_>> {
    let assignment = node.parent()?;
    if assignment.kind() != "assignment_expression"
        || assignment.child_by_field_name("left") != Some(node)
    {
        return None;
    }
    let arguments = assignment.parent()?;
    if arguments.kind() != "arguments" {
        return None;
    }
    let invocation = arguments.parent()?;
    match invocation.kind() {
        "call_expression" => invocation.child_by_field_name("function"),
        "instance_expression" => {
            let mut cursor = invocation.walk();
            invocation.named_children(&mut cursor).find(|child| {
                matches!(
                    child.kind(),
                    "type_identifier" | "stable_type_identifier" | "generic_type"
                )
            })
        }
        _ => None,
    }
}

pub(crate) fn terminal_invocation_owner_name(node: Node<'_>) -> Option<Node<'_>> {
    match node.kind() {
        "identifier" | "type_identifier" => Some(node),
        "generic_function" => node
            .child_by_field_name("function")
            .and_then(terminal_invocation_owner_name),
        "generic_type" => node
            .child_by_field_name("type")
            .and_then(terminal_invocation_owner_name),
        "field_expression" => node
            .child_by_field_name("field")
            .and_then(terminal_invocation_owner_name),
        "stable_type_identifier" => {
            let mut cursor = node.walk();
            node.named_children(&mut cursor)
                .last()
                .and_then(terminal_invocation_owner_name)
        }
        _ => None,
    }
}

pub(crate) fn is_assignment_lhs(node: Node<'_>) -> bool {
    node.parent().is_some_and(|parent| {
        parent.kind() == "assignment_expression" && parent.child_by_field_name("left") == Some(node)
    })
}

pub(crate) fn node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    &source[node.byte_range()]
}
