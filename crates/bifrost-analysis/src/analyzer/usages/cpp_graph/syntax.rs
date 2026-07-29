use tree_sitter::Node;

#[derive(Clone)]
pub(super) struct ExplicitQualifiedCallableValue<'tree> {
    pub(super) qualified: Node<'tree>,
    pub(super) global: bool,
    pub(super) owner_components: Vec<Node<'tree>>,
    pub(super) member: Node<'tree>,
}

/// Recognize an explicit address-of qualified callable value such as
/// `&Owner::method` or `&namespace::Owner::method`.
///
/// The returned nodes come exclusively from the C++ grammar's named fields. In
/// particular, a nested namespace/type owner remains a structured subtree rather
/// than being reconstructed from source text.
pub(super) fn explicit_qualified_callable_value(
    node: Node<'_>,
) -> Option<ExplicitQualifiedCallableValue<'_>> {
    if node.kind() != "pointer_expression" || node.child_by_field_name("operator")?.kind() != "&" {
        return None;
    }
    let qualified = node.child_by_field_name("argument")?;
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
    Some(ExplicitQualifiedCallableValue {
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
            "identifier" | "namespace_identifier" | "type_identifier" => out.push(current),
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
