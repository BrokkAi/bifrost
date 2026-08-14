use tree_sitter::Node;

#[derive(Clone)]
pub struct QualifiedCallableValue<'tree> {
    pub qualified: Node<'tree>,
    pub global: bool,
    pub owner_components: Vec<Node<'tree>>,
    pub member: Node<'tree>,
}

/// Recognize an explicit address-of qualified callable value such as
/// `&Owner::method` or `&namespace::Owner::method`.
///
/// The returned nodes come exclusively from the C++ grammar's named fields. In
/// particular, a nested namespace/type owner remains a structured subtree rather
/// than being reconstructed from source text.
pub fn explicit_qualified_callable_value(node: Node<'_>) -> Option<QualifiedCallableValue<'_>> {
    if node.kind() != "pointer_expression" || node.child_by_field_name("operator")?.kind() != "&" {
        return None;
    }
    let qualified = node.child_by_field_name("argument")?;
    qualified_callable_value_from_node(qualified)
}

/// Recognize a qualified callable used as an expression value.
///
/// Calls use their own arity-aware path. Address-of expressions use the
/// explicit path above. This arm covers structured values such as
/// `bind(Owner::method)` and `callback = namespace::function`.
pub fn qualified_callable_value(node: Node<'_>) -> Option<QualifiedCallableValue<'_>> {
    if let Some(value) = explicit_qualified_callable_value(node) {
        return Some(value);
    }
    if node.kind() != "qualified_identifier" {
        return None;
    }
    if crate::graph::resolver::is_declaration_name(node) {
        return None;
    }
    if node.parent().is_some_and(|parent| {
        parent.child_by_field_name("type") == Some(node)
            || (parent.kind() == "call_expression"
                && parent.child_by_field_name("function") == Some(node))
            || (parent.kind() == "pointer_expression"
                && parent.child_by_field_name("argument") == Some(node))
            || matches!(
                parent.kind(),
                "qualified_identifier" | "scoped_identifier" | "scoped_type_identifier"
            )
    }) {
        return None;
    }
    qualified_callable_value_from_node(node)
}

fn qualified_callable_value_from_node(qualified: Node<'_>) -> Option<QualifiedCallableValue<'_>> {
    if qualified.kind() != "qualified_identifier" {
        return None;
    }
    let mut components = Vec::new();
    let global = qualified.child_by_field_name("scope").is_none()
        && qualified.child(0).is_some_and(|child| child.kind() == "::");
    append_qualified_components(qualified, &mut components)?;
    let member = components.pop()?;
    if components.is_empty() {
        return None;
    }
    Some(QualifiedCallableValue {
        qualified,
        global,
        owner_components: components,
        member,
    })
}

fn append_qualified_components<'tree>(node: Node<'tree>, out: &mut Vec<Node<'tree>>) -> Option<()> {
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        match current.kind() {
            "identifier" | "namespace_identifier" | "type_identifier" | "operator_name" => {
                out.push(current)
            }
            "qualified_identifier" | "scoped_identifier" => {
                stack.push(current.child_by_field_name("name")?);
                if let Some(scope) = current.child_by_field_name("scope") {
                    stack.push(scope);
                } else if current.child(0).is_none_or(|child| child.kind() != "::") {
                    return None;
                }
            }
            "template_type" | "template_function" => {
                stack.push(current.child_by_field_name("name")?);
            }
            "nested_namespace_specifier" => {
                for index in (0..current.named_child_count()).rev() {
                    stack.push(current.named_child(index)?);
                }
            }
            _ => return None,
        }
    }
    Some(())
}
