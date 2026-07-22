use super::*;

pub(super) fn declaration_container_kind(node: Node<'_>) -> Option<DeclarationSegmentKind> {
    match node.kind() {
        "class_declaration"
        | "interface_declaration"
        | "enum_declaration"
        | "record_declaration"
        | "annotation_type_declaration" => Some(DeclarationSegmentKind::Type),
        "class_body"
            if node
                .parent()
                .is_some_and(|parent| parent.kind() == "object_creation_expression") =>
        {
            Some(DeclarationSegmentKind::Type)
        }
        _ => None,
    }
}

pub(super) fn declaration_container_name(source: &str, node: Node<'_>) -> Option<Box<str>> {
    node.child_by_field_name("name")
        .and_then(|name| nonempty_node_text(source, name))
        .map(Box::<str>::from)
}

pub(super) fn callable_name(source: &str, node: Node<'_>) -> Option<Box<str>> {
    node.child_by_field_name("name")
        .and_then(|name| nonempty_node_text(source, name))
        .map(Box::<str>::from)
        .or_else(|| enclosing_variable_name(source, node))
}

fn enclosing_variable_name(source: &str, node: Node<'_>) -> Option<Box<str>> {
    let parent = node.parent()?;
    if parent.kind() != "variable_declarator" || !field_matches(parent, "value", node) {
        return None;
    }
    parent
        .child_by_field_name("name")
        .and_then(|name| nonempty_node_text(source, name))
        .map(Box::<str>::from)
}

pub(super) fn callable_shape<'tree>(
    node: Node<'tree>,
) -> Option<(
    ProcedureKind,
    DeclarationSegmentKind,
    Node<'tree>,
    ProcedureProperties,
)> {
    let (kind, segment_kind, body, is_static) = match node.kind() {
        "method_declaration" => (
            ProcedureKind::Method,
            DeclarationSegmentKind::Method,
            node.child_by_field_name("body")?,
            has_modifier(node, "static"),
        ),
        "constructor_declaration" => (
            ProcedureKind::Constructor,
            DeclarationSegmentKind::Constructor,
            node.child_by_field_name("body")?,
            false,
        ),
        "compact_constructor_declaration" => (
            ProcedureKind::Constructor,
            DeclarationSegmentKind::Constructor,
            node.child_by_field_name("body")?,
            false,
        ),
        "lambda_expression" => (
            ProcedureKind::Lambda,
            DeclarationSegmentKind::Lambda,
            node.child_by_field_name("body")?,
            false,
        ),
        "static_initializer" => (
            ProcedureKind::Initializer,
            DeclarationSegmentKind::Initializer,
            first_named_child(node)?,
            true,
        ),
        "block"
            if node
                .parent()
                .is_some_and(|parent| parent.kind() == "class_body") =>
        {
            (
                ProcedureKind::Initializer,
                DeclarationSegmentKind::Initializer,
                node,
                false,
            )
        }
        "variable_declarator"
            if node.parent().is_some_and(|parent| {
                matches!(parent.kind(), "field_declaration" | "constant_declaration")
            }) =>
        {
            let field = node.parent().expect("guarded field-declaration parent");
            (
                ProcedureKind::Initializer,
                DeclarationSegmentKind::Initializer,
                node.child_by_field_name("value")?,
                field.kind() == "constant_declaration" || has_modifier(field, "static"),
            )
        }
        "enum_constant" => (
            ProcedureKind::Initializer,
            DeclarationSegmentKind::Initializer,
            node,
            true,
        ),
        _ => return None,
    };
    let dispatch_extensibility = if kind == ProcedureKind::Constructor
        || is_static
        || has_modifier(node, "private")
        || has_modifier(node, "final")
        || enclosing_type_is_final(node)
    {
        DispatchExtensibility::Closed
    } else {
        DispatchExtensibility::Open
    };
    Some((
        kind,
        segment_kind,
        body,
        ProcedureProperties {
            is_async: false,
            is_generator: false,
            is_static,
            is_synthetic: false,
            invocation: ProcedureInvocationKind::Immediate,
            dispatch_extensibility,
        },
    ))
}

fn enclosing_type_is_final(node: Node<'_>) -> bool {
    let mut current = node.parent();
    while let Some(parent) = current {
        if matches!(parent.kind(), "class_declaration" | "record_declaration") {
            return parent.kind() == "record_declaration" || has_modifier(parent, "final");
        }
        current = parent.parent();
    }
    false
}

fn has_modifier(node: Node<'_>, modifier: &str) -> bool {
    node.child_by_field_name("modifiers")
        .or_else(|| {
            named_children(node)
                .into_iter()
                .find(|child| child.kind() == "modifiers")
        })
        .is_some_and(|modifiers| {
            let mut cursor = modifiers.walk();
            modifiers
                .children(&mut cursor)
                .any(|child| child.kind() == modifier)
        })
}

fn field_matches(parent: Node<'_>, field: &str, child: Node<'_>) -> bool {
    parent
        .child_by_field_name(field)
        .is_some_and(|candidate| candidate.id() == child.id())
}

fn nonempty_node_text<'source>(source: &'source str, node: Node<'_>) -> Option<&'source str> {
    node_text(source, node).filter(|text| !text.is_empty())
}

pub(super) fn java_switch_arms(body: Node<'_>) -> Vec<JavaSwitchArm<'_>> {
    named_children(body)
        .into_iter()
        .filter_map(|node| {
            let kind = match node.kind() {
                "switch_block_statement_group" => JavaSwitchArmKind::Group,
                "switch_rule" => JavaSwitchArmKind::Rule,
                _ => return None,
            };
            let children = named_children(node);
            let labels = children
                .iter()
                .copied()
                .filter(|child| child.kind() == "switch_label")
                .collect::<Vec<_>>();
            let body = children
                .into_iter()
                .filter(|child| child.kind() != "switch_label")
                .collect::<Vec<_>>();
            Some(JavaSwitchArm {
                node,
                labels,
                body,
                kind,
            })
        })
        .collect()
}

pub(super) fn switch_label_is_default(label: Node<'_>) -> bool {
    let mut cursor = label.walk();
    label
        .children(&mut cursor)
        .any(|child| child.kind() == "default")
}

pub(super) fn switch_label_has_pattern(label: Node<'_>) -> bool {
    named_children(label)
        .into_iter()
        .any(|child| child.kind() == "pattern" || child.kind().ends_with("_pattern"))
}

pub(super) fn switch_label_guard(label: Node<'_>) -> Option<Node<'_>> {
    named_children(label)
        .into_iter()
        .find(|child| child.kind() == "guard")
        .and_then(first_named_child)
}

pub(super) fn object_creation_qualifier(node: Node<'_>) -> Option<Node<'_>> {
    let type_node = node.child_by_field_name("type");
    let arguments = node.child_by_field_name("arguments");
    named_children(node).into_iter().find(|child| {
        type_node.is_none_or(|candidate| candidate.id() != child.id())
            && arguments.is_none_or(|candidate| candidate.id() != child.id())
            && child.kind() != "class_body"
            && !is_annotation_kind(child.kind())
            && !is_type_syntax(child.kind())
    })
}

pub(super) fn method_reference_qualifier(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    let separator = node
        .children(&mut cursor)
        .find(|child| child.kind() == "::")?;
    named_children(node).into_iter().rfind(|child| {
        child.end_byte() <= separator.start_byte()
            && !is_type_syntax(child.kind())
            && child.kind() != "type_arguments"
            && !is_annotation_kind(child.kind())
    })
}

pub(super) fn has_child_kind(node: Node<'_>, kind: &str) -> bool {
    let mut cursor = node.walk();
    node.children(&mut cursor).any(|child| child.kind() == kind)
}

pub(super) fn runtime_expression_children(node: Node<'_>) -> Vec<Node<'_>> {
    let fields: &[&str] = match node.kind() {
        "field_access" => &["object"],
        "array_access" => &["array", "index"],
        "assignment_expression" | "binary_expression" => &["left", "right"],
        "unary_expression" => &["operand"],
        "cast_expression" => &["value"],
        "instanceof_expression" => &["left"],
        "array_creation_expression" => &["dimensions", "value"],
        _ => &[],
    };
    if !fields.is_empty() {
        let mut result = Vec::new();
        for field in fields {
            for child in children_by_field_name(node, field) {
                if is_type_syntax(child.kind()) || is_annotation_kind(child.kind()) {
                    continue;
                }
                if !result
                    .iter()
                    .any(|existing: &Node<'_>| existing.id() == child.id())
                {
                    result.push(child);
                }
            }
        }
        result.sort_by_key(Node::start_byte);
        return result;
    }

    named_children(node)
        .into_iter()
        .filter(|child| {
            !is_type_syntax(child.kind())
                && !is_annotation_kind(child.kind())
                && !matches!(child.kind(), "modifiers" | "class_body")
        })
        .collect()
}

pub(super) fn first_runtime_named_child(node: Node<'_>) -> Option<Node<'_>> {
    named_children(node).into_iter().find(|child| {
        !is_type_syntax(child.kind())
            && !is_annotation_kind(child.kind())
            && child.kind() != "modifiers"
    })
}

fn is_type_syntax(kind: &str) -> bool {
    matches!(
        kind,
        "type_identifier"
            | "scoped_type_identifier"
            | "generic_type"
            | "array_type"
            | "integral_type"
            | "floating_point_type"
            | "boolean_type"
            | "void_type"
            | "wildcard"
            | "type_arguments"
            | "type_parameters"
            | "annotated_type"
            | "dimensions"
    )
}

fn is_annotation_kind(kind: &str) -> bool {
    matches!(kind, "annotation" | "marker_annotation")
}

pub(super) fn named_children(node: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .filter(|child| !is_comment_kind(child.kind()))
        .collect()
}

pub(super) fn first_named_child(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|child| !is_comment_kind(child.kind()))
}

fn is_comment_kind(kind: &str) -> bool {
    matches!(kind, "line_comment" | "block_comment" | "comment")
}

pub(super) fn required_field<'tree>(
    node: Node<'tree>,
    field: &str,
) -> Result<Node<'tree>, JavaLoweringError> {
    node.child_by_field_name(field)
        .ok_or_else(|| missing_field(node, field))
}

pub(super) fn missing_field(node: Node<'_>, field: &str) -> JavaLoweringError {
    JavaLoweringError::Invalid(format!(
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

pub(super) fn is_java_nested_execution_boundary(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "lambda_expression"
            | "method_declaration"
            | "constructor_declaration"
            | "compact_constructor_declaration"
            | "class_declaration"
            | "interface_declaration"
            | "enum_declaration"
            | "record_declaration"
            | "annotation_type_declaration"
            | "class_body"
    )
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
        if is_java_nested_execution_boundary(node) {
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

pub(super) fn java_local_scope(node: Node<'_>) -> Option<(usize, usize)> {
    let mut current = node.parent();
    while let Some(parent) = current {
        if matches!(
            parent.kind(),
            "block"
                | "constructor_body"
                | "for_statement"
                | "enhanced_for_statement"
                | "switch_block_statement_group"
                | "switch_rule"
                | "catch_clause"
        ) {
            return Some((parent.start_byte(), parent.end_byte()));
        }
        if is_java_nested_execution_boundary(parent) {
            return Some((parent.start_byte(), parent.end_byte()));
        }
        current = parent.parent();
    }
    None
}

pub(super) fn expression_value_kind(node: Node<'_>) -> SemanticValueKind {
    match node.kind() {
        "lambda_expression" | "method_reference" => SemanticValueKind::Callable,
        "decimal_integer_literal"
        | "hex_integer_literal"
        | "octal_integer_literal"
        | "binary_integer_literal"
        | "decimal_floating_point_literal"
        | "hex_floating_point_literal"
        | "true"
        | "false"
        | "character_literal"
        | "string_literal"
        | "null_literal" => SemanticValueKind::Constant,
        _ => SemanticValueKind::Temporary,
    }
}

pub(super) fn binary_operator(node: Node<'_>) -> Option<&'static str> {
    match node.child_by_field_name("operator")?.kind() {
        "&&" => Some("&&"),
        "||" => Some("||"),
        _ => None,
    }
}

pub(super) fn operation_can_throw_implicitly(node: Node<'_>) -> bool {
    match node.kind() {
        "unary_expression"
        | "update_expression"
        | "binary_expression"
        | "cast_expression"
        | "template_expression" => true,
        "assignment_expression" => node
            .child_by_field_name("left")
            .is_some_and(|left| matches!(left.kind(), "field_access" | "array_access")),
        "array_creation_expression" => true,
        _ => false,
    }
}

pub(super) fn is_runtime_leaf(kind: &str) -> bool {
    matches!(
        kind,
        "identifier"
            | "decimal_integer_literal"
            | "hex_integer_literal"
            | "octal_integer_literal"
            | "binary_integer_literal"
            | "decimal_floating_point_literal"
            | "hex_floating_point_literal"
            | "character_literal"
            | "string_literal"
            | "null_literal"
            | "true"
            | "false"
            | "this"
            | "super"
            | "class_literal"
            | "comment"
            | "line_comment"
            | "block_comment"
    )
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
