use super::*;

pub(super) fn declaration_container_kind(node: Node<'_>) -> Option<DeclarationSegmentKind> {
    match node.kind() {
        "internal_module" => Some(DeclarationSegmentKind::Namespace),
        "class"
        | "class_declaration"
        | "abstract_class_declaration"
        | "interface_declaration"
        | "enum_declaration"
        | "type_alias_declaration" => Some(DeclarationSegmentKind::Type),
        _ => None,
    }
}

pub(super) fn declaration_container_name(source: &str, node: Node<'_>) -> Option<Box<str>> {
    node.child_by_field_name("name")
        .and_then(|name| nonempty_node_text(source, name))
        .map(Box::<str>::from)
        .or_else(|| enclosing_binding(source, node).map(|binding| binding.name))
}

struct EnclosingBinding {
    name: Box<str>,
}

pub(super) fn callable_name(source: &str, node: Node<'_>) -> Option<Box<str>> {
    if matches!(node.kind(), "field_definition" | "public_field_definition") {
        let name = node
            .child_by_field_name("name")
            .or_else(|| node.child_by_field_name("property"))?;
        if name.kind() == "computed_property_name" {
            return None;
        }
        return nonempty_node_text(source, name).map(Box::<str>::from);
    }

    if let Some(name) = node
        .child_by_field_name("name")
        .and_then(|name| nonempty_node_text(source, name))
        .map(Box::<str>::from)
    {
        return Some(name);
    }

    enclosing_binding(source, node).map(|binding| binding.name)
}

fn enclosing_binding(source: &str, node: Node<'_>) -> Option<EnclosingBinding> {
    let mut value = node;
    loop {
        let parent = value.parent()?;
        match parent.kind() {
            "parenthesized_expression" => {
                if first_named_child(parent).is_some_and(|child| child.id() == value.id()) {
                    value = parent;
                    continue;
                }
                return None;
            }
            "as_expression" | "satisfies_expression" | "non_null_expression" | "type_assertion" => {
                if first_named_child(parent).is_some_and(|child| child.id() == value.id()) {
                    value = parent;
                    continue;
                }
                return None;
            }
            "variable_declarator" => {
                if !field_matches(parent, "value", value) {
                    return None;
                }
                let name = parent.child_by_field_name("name")?;
                return simple_binding_name(source, name).map(|name| EnclosingBinding { name });
            }
            "assignment_expression" => {
                if !field_matches(parent, "right", value) {
                    return None;
                }
                let left = parent.child_by_field_name("left")?;
                return assignment_binding(source, left);
            }
            "pair" => {
                if !field_matches(parent, "value", value) {
                    return None;
                }
                let key = parent.child_by_field_name("key")?;
                return simple_binding_name(source, key).map(|name| EnclosingBinding { name });
            }
            "public_field_definition" | "field_definition" => {
                if !field_matches(parent, "value", value) {
                    return None;
                }
                let name = parent
                    .child_by_field_name("name")
                    .or_else(|| parent.child_by_field_name("property"))?;
                return simple_binding_name(source, name).map(|name| EnclosingBinding { name });
            }
            _ => return None,
        }
    }
}

fn assignment_binding(source: &str, left: Node<'_>) -> Option<EnclosingBinding> {
    if left.kind() == "identifier" {
        return simple_binding_name(source, left).map(|name| EnclosingBinding { name });
    }
    if left.kind() == "member_expression" {
        let property = left.child_by_field_name("property")?;
        return simple_binding_name(source, property).map(|name| EnclosingBinding { name });
    }
    None
}

fn field_matches(parent: Node<'_>, field: &str, child: Node<'_>) -> bool {
    parent
        .child_by_field_name(field)
        .is_some_and(|candidate| candidate.id() == child.id())
}

fn simple_binding_name(source: &str, node: Node<'_>) -> Option<Box<str>> {
    matches!(
        node.kind(),
        "identifier" | "property_identifier" | "private_property_identifier" | "type_identifier"
    )
    .then(|| nonempty_node_text(source, node))
    .flatten()
    .map(Box::<str>::from)
}

fn nonempty_node_text<'source>(source: &'source str, node: Node<'_>) -> Option<&'source str> {
    node_text(source, node).filter(|text| !text.is_empty())
}

pub(super) fn callable_shape<'tree>(
    node: Node<'tree>,
) -> Option<(
    ProcedureKind,
    DeclarationSegmentKind,
    Node<'tree>,
    ProcedureProperties,
)> {
    let (kind, segment_kind, body, generator, is_static) = match node.kind() {
        "function_declaration" | "function_expression" => (
            ProcedureKind::Function,
            DeclarationSegmentKind::Function,
            node.child_by_field_name("body")?,
            false,
            false,
        ),
        "generator_function_declaration" | "generator_function" => (
            ProcedureKind::Function,
            DeclarationSegmentKind::Function,
            node.child_by_field_name("body")?,
            true,
            false,
        ),
        "arrow_function" => (
            ProcedureKind::Lambda,
            DeclarationSegmentKind::Lambda,
            node.child_by_field_name("body")?,
            false,
            false,
        ),
        "method_definition" => (
            ProcedureKind::Method,
            DeclarationSegmentKind::Method,
            node.child_by_field_name("body")?,
            has_child_kind(node, "*"),
            has_child_kind(node, "static") || has_child_kind(node, "static get"),
        ),
        "class_static_block" => (
            ProcedureKind::Initializer,
            DeclarationSegmentKind::Initializer,
            node.child_by_field_name("body")?,
            false,
            true,
        ),
        "field_definition" | "public_field_definition" => (
            ProcedureKind::Initializer,
            DeclarationSegmentKind::Initializer,
            node.child_by_field_name("value")?,
            false,
            has_child_kind(node, "static"),
        ),
        _ => return None,
    };
    let mut cursor = node.walk();
    let is_async = node
        .children(&mut cursor)
        .any(|child| child.kind() == "async");
    Some((
        kind,
        segment_kind,
        body,
        ProcedureProperties {
            is_async,
            is_generator: generator,
            is_static,
            is_synthetic: false,
            invocation: if generator {
                ProcedureInvocationKind::Deferred
            } else {
                ProcedureInvocationKind::Immediate
            },
            ..ProcedureProperties::default()
        },
    ))
}

pub(super) fn callable_child_belongs_to_procedure(callable: Node<'_>, child: Node<'_>) -> bool {
    match callable.kind() {
        "field_definition" | "public_field_definition" => field_matches(callable, "value", child),
        "method_definition" => !field_matches(callable, "name", child),
        _ => true,
    }
}

pub(super) fn class_definition_expressions<'tree>(
    class: Node<'tree>,
    cancellation: &CancellationToken,
) -> Result<Vec<Node<'tree>>, LoweringCancelled> {
    let mut expressions = Vec::new();
    let mut cursor = class.walk();
    for child in class.named_children(&mut cursor) {
        if cancellation.is_cancelled() {
            return Err(LoweringCancelled);
        }
        match child.kind() {
            "class_heritage" => {
                let heritage_children = named_children(child);
                if heritage_children
                    .iter()
                    .any(|heritage| heritage.kind() == "extends_clause")
                {
                    for extends_clause in heritage_children
                        .into_iter()
                        .filter(|heritage| heritage.kind() == "extends_clause")
                    {
                        if cancellation.is_cancelled() {
                            return Err(LoweringCancelled);
                        }
                        expressions.extend(children_by_field_name(extends_clause, "value"));
                    }
                } else if let Some(value) = heritage_children.into_iter().next() {
                    expressions.push(value);
                }
            }
            "class_body" => {
                for member in named_children(child) {
                    if cancellation.is_cancelled() {
                        return Err(LoweringCancelled);
                    }
                    let name = member
                        .child_by_field_name("name")
                        .or_else(|| member.child_by_field_name("property"));
                    if let Some(name) = name.filter(|name| name.kind() == "computed_property_name")
                    {
                        expressions.push(name);
                    }
                }
            }
            _ => {}
        }
    }
    Ok(expressions)
}

pub(super) fn named_children(node: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).collect()
}

pub(super) fn default_parameter_values(node: Node<'_>) -> Vec<Node<'_>> {
    let Some(parameters) = node.child_by_field_name("parameters") else {
        return Vec::new();
    };
    named_children(parameters)
        .into_iter()
        .filter_map(|parameter| match parameter.kind() {
            "required_parameter" | "optional_parameter" => parameter.child_by_field_name("value"),
            "assignment_pattern" => parameter.child_by_field_name("right"),
            _ => None,
        })
        .collect()
}

pub(super) fn has_nested_parameter_defaults(node: Node<'_>) -> bool {
    let Some(parameters) = node.child_by_field_name("parameters") else {
        return false;
    };
    for parameter in named_children(parameters) {
        let binding = match parameter.kind() {
            "required_parameter" | "optional_parameter" => parameter.child_by_field_name("pattern"),
            "assignment_pattern" => parameter.child_by_field_name("left"),
            _ => Some(parameter),
        };
        let Some(binding) = binding else {
            continue;
        };
        let mut stack = vec![binding];
        while let Some(current) = stack.pop() {
            if current.kind() == "assignment_pattern" {
                return true;
            }
            stack.extend(named_children(current));
        }
    }
    false
}

pub(super) fn declaration_initializers(node: Node<'_>) -> Vec<Node<'_>> {
    named_children(node)
        .into_iter()
        .filter(|child| child.kind() == "variable_declarator")
        .filter_map(|declarator| declarator.child_by_field_name("value"))
        .collect()
}

pub(super) fn abrupt_dependencies(node: Node<'_>) -> Vec<Node<'_>> {
    match node.kind() {
        "statement_block" | "program" => named_children(node)
            .into_iter()
            .filter(|child| child.kind() != "comment")
            .collect(),
        "if_statement" => {
            let mut children = Vec::with_capacity(2);
            if let Some(consequence) = node.child_by_field_name("consequence") {
                children.push(consequence);
            }
            if let Some(alternative) = node.child_by_field_name("alternative") {
                children.push(if alternative.kind() == "else_clause" {
                    first_named_child(alternative).unwrap_or(alternative)
                } else {
                    alternative
                });
            }
            children
        }
        "try_statement" => {
            let mut children = Vec::with_capacity(3);
            if let Some(body) = node.child_by_field_name("body") {
                children.push(body);
            }
            if let Some(handler) = node
                .child_by_field_name("handler")
                .and_then(|handler| handler.child_by_field_name("body"))
            {
                children.push(handler);
            }
            if let Some(finalizer) = node
                .child_by_field_name("finalizer")
                .and_then(|finalizer| finalizer.child_by_field_name("body"))
            {
                children.push(finalizer);
            }
            children
        }
        "labeled_statement" => node.child_by_field_name("body").into_iter().collect(),
        "else_clause" => first_named_child(node).into_iter().collect(),
        "export_statement" => node
            .child_by_field_name("declaration")
            .into_iter()
            .collect(),
        _ => Vec::new(),
    }
}

pub(super) fn first_named_child(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).next()
}

pub(super) fn required_field<'tree>(
    node: Node<'tree>,
    field: &str,
) -> Result<Node<'tree>, TsLoweringError> {
    node.child_by_field_name(field)
        .ok_or_else(|| missing_field(node, field))
}

pub(super) fn missing_field(node: Node<'_>, field: &str) -> TsLoweringError {
    TsLoweringError::Invalid(format!(
        "{} node at bytes {}..{} is missing structured field {field}",
        node.kind(),
        node.start_byte(),
        node.end_byte()
    ))
}

pub(super) fn node_range(node: Node<'_>) -> Range {
    Range {
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
        start_line: node.start_position().row + 1,
        end_line: node.end_position().row + 1,
    }
}

pub(super) fn js_ts_local_scope(node: Node<'_>) -> Option<(usize, usize)> {
    let is_var = node
        .parent()
        .is_some_and(|parent| parent.kind() == "variable_declaration");
    let mut current = node.parent();
    while let Some(parent) = current {
        let is_scope = if is_var {
            matches!(
                parent.kind(),
                "program"
                    | "function_declaration"
                    | "generator_function_declaration"
                    | "function_expression"
                    | "generator_function"
                    | "arrow_function"
                    | "method_definition"
                    | "class_static_block"
            )
        } else {
            matches!(
                parent.kind(),
                "program"
                    | "statement_block"
                    | "for_statement"
                    | "for_in_statement"
                    | "switch_body"
                    | "catch_clause"
            )
        };
        if is_scope {
            return Some((parent.start_byte(), parent.end_byte()));
        }
        current = parent.parent();
    }
    None
}

pub(super) fn body_contains_free_this(
    body: Node<'_>,
    cancellation: &CancellationToken,
) -> Result<bool, LoweringCancelled> {
    let mut found = false;
    try_walk_named_tree_preorder(body, true, |node| {
        if cancellation.is_cancelled() {
            return Err(LoweringCancelled);
        }
        if is_js_ts_nested_execution_boundary(node, body) {
            return Ok(WalkControl::SkipChildren);
        }
        if node.kind() == "this" {
            found = true;
            return Ok(WalkControl::Break);
        }
        Ok(WalkControl::Continue)
    })?;
    Ok(found)
}

pub(super) fn expression_value_kind(node: Node<'_>) -> SemanticValueKind {
    match node.kind() {
        kind if is_callable_kind(kind) => SemanticValueKind::Callable,
        "number" | "string" | "template_string" | "true" | "false" | "null" | "undefined" => {
            SemanticValueKind::Constant
        }
        _ => SemanticValueKind::Temporary,
    }
}

pub(super) fn is_callable_kind(kind: &str) -> bool {
    matches!(
        kind,
        "function_declaration"
            | "function_expression"
            | "generator_function_declaration"
            | "generator_function"
            | "arrow_function"
            | "method_definition"
    )
}

pub(super) fn is_js_ts_nested_execution_boundary(node: Node<'_>, traversal_root: Node<'_>) -> bool {
    if is_callable_kind(node.kind()) && node.kind() != "method_definition" {
        return true;
    }
    if node.kind() == "class_static_block" {
        return true;
    }
    node.parent().is_some_and(|parent| {
        (parent.kind() == "method_definition"
            && !(node.id() == traversal_root.id() && field_matches(parent, "body", node))
            && !field_matches(parent, "name", node))
            || (matches!(
                parent.kind(),
                "field_definition" | "public_field_definition"
            ) && field_matches(parent, "value", node))
    })
}

pub(super) fn is_runtime_leaf(kind: &str) -> bool {
    matches!(
        kind,
        "identifier"
            | "property_identifier"
            | "private_property_identifier"
            | "statement_identifier"
            | "type_identifier"
            | "jsx_identifier"
            | "jsx_namespace_name"
            | "jsx_text"
            | "html_character_reference"
            | "string"
            | "string_fragment"
            | "escape_sequence"
            | "number"
            | "regex"
            | "true"
            | "false"
            | "null"
            | "undefined"
            | "this"
            | "super"
            | "meta_property"
            | "optional_chain"
            | "comment"
    )
}

pub(super) fn has_child_kind(node: Node<'_>, kind: &str) -> bool {
    let mut cursor = node.walk();
    node.children(&mut cursor).any(|child| child.kind() == kind)
}

pub(super) fn short_circuit_operator(node: Node<'_>) -> Option<&'static str> {
    let mut cursor = node.walk();
    node.children(&mut cursor)
        .find_map(|child| match child.kind() {
            "&&" => Some("&&"),
            "||" => Some("||"),
            "??" => Some("??"),
            _ => None,
        })
}

/// Whether an expression belongs to one continuous optional-chain spine.
/// Only callee/object and transparent TypeScript wrappers are followed: an
/// argument, computed key, or parenthesized expression starts an independent
/// evaluation region and therefore cannot propagate a nullish skip outward.
pub(super) fn continuous_optional_chain(mut node: Node<'_>) -> bool {
    loop {
        if has_child_kind(node, "?.")
            || node.child_by_field_name("optional_chain").is_some()
            || has_child_kind(node, "optional_chain")
        {
            return true;
        }
        node = match node.kind() {
            "call_expression" => match node.child_by_field_name("function") {
                Some(function) => function,
                None => return false,
            },
            "member_expression" | "subscript_expression" => {
                match node.child_by_field_name("object") {
                    Some(object) => object,
                    None => return false,
                }
            }
            "non_null_expression"
            | "as_expression"
            | "satisfies_expression"
            | "type_assertion"
            | "instantiation_expression" => match node
                .child_by_field_name("expression")
                .or_else(|| first_named_child(node))
            {
                Some(expression) => expression,
                None => return false,
            },
            // Parentheses deliberately terminate propagation. `(value?.x).y`
            // attempts `.y` even when the nested chain produces undefined.
            _ => return false,
        };
    }
}

pub(super) fn logical_assignment_operator(node: Node<'_>) -> Option<&'static str> {
    let operator = node.child_by_field_name("operator")?;
    match operator.kind() {
        "&&=" => Some("&&="),
        "||=" => Some("||="),
        "??=" => Some("??="),
        _ => None,
    }
}

pub(super) fn operation_can_throw_implicitly(node: Node<'_>) -> bool {
    match node.kind() {
        "unary_expression"
        | "update_expression"
        | "binary_expression"
        | "augmented_assignment_expression"
        | "template_string" => true,
        "assignment_expression" => node.child_by_field_name("left").is_some_and(|left| {
            matches!(left.kind(), "member_expression" | "subscript_expression")
        }),
        _ => false,
    }
}

pub(super) const fn completion_label(kind: CompletionKind) -> &'static str {
    match kind {
        CompletionKind::Normal => "normal",
        CompletionKind::Return => "return",
        CompletionKind::Throw => "throw",
        CompletionKind::Break => "break",
        CompletionKind::Continue => "continue",
        CompletionKind::Yield => "yield",
    }
}
