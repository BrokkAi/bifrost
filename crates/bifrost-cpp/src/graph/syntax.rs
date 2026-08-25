use crate::graph::resolver::{
    cpp_name_component_nodes, cpp_type_name_components, is_globally_qualified_cpp_name,
    is_nested_type_node, qualified_owner_components,
};
use std::ops::Range;
use tree_sitter::{Node, Parser};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MacroReplacementTypeReference {
    pub components: Vec<String>,
    pub component_ranges: Vec<Range<usize>>,
    pub global: bool,
}

/// Recover type-bearing syntax hidden inside an object-like macro replacement.
///
/// Tree-sitter deliberately keeps the replacement of `#define NAME value` as
/// one opaque `preproc_arg`. Reparse that exact byte slice as a C++ expression
/// and return only references proven by the resulting tree: ordinary type
/// nodes and the owner prefixes of qualified values such as `Owner::member`.
/// Every returned range is mapped back to the original file.
pub fn object_macro_replacement_type_references(
    node: Node<'_>,
    source: &str,
) -> Vec<MacroReplacementTypeReference> {
    if node.kind() != "preproc_arg"
        || !node.parent().is_some_and(|parent| {
            parent.kind() == "preproc_def"
                && parent
                    .child_by_field_name("value")
                    .is_some_and(|value| value == node)
        })
    {
        return Vec::new();
    }
    let Some(replacement) = source.get(node.start_byte()..node.end_byte()) else {
        return Vec::new();
    };
    const PREFIX: &str = "void __bifrost_macro_reference() { ";
    let synthetic = format!("{PREFIX}{replacement}; }}");
    let mut parser = Parser::new();
    if parser
        .set_language(&tree_sitter_cpp::LANGUAGE.into())
        .is_err()
    {
        return Vec::new();
    }
    let Some(tree) = parser.parse(&synthetic, None) else {
        return Vec::new();
    };
    if tree.root_node().has_error() {
        return Vec::new();
    }

    let mut references = Vec::new();
    let mut stack = vec![tree.root_node()];
    while let Some(current) = stack.pop() {
        let structured = if matches!(
            current.kind(),
            "type_identifier" | "scoped_type_identifier" | "template_type"
        ) && !is_nested_type_node(current)
        {
            cpp_type_name_components(current, &synthetic)
                .zip(cpp_name_component_nodes(current))
                .map(|(components, nodes)| {
                    (components, nodes, is_globally_qualified_cpp_name(current))
                })
        } else if current.kind() == "qualified_identifier"
            && !current.parent().is_some_and(|parent| {
                matches!(
                    parent.kind(),
                    "qualified_identifier" | "scoped_identifier" | "scoped_type_identifier"
                )
            })
        {
            qualified_owner_components(current, &synthetic)
                .map(|owner| (owner.names, owner.nodes, owner.global))
        } else {
            None
        };
        if let Some((components, component_nodes, global)) = structured {
            let component_ranges = component_nodes
                .into_iter()
                .map(|component| {
                    let start = component.start_byte().checked_sub(PREFIX.len())?;
                    let end = component.end_byte().checked_sub(PREFIX.len())?;
                    (end <= replacement.len())
                        .then_some(node.start_byte() + start..node.start_byte() + end)
                })
                .collect::<Option<Vec<_>>>();
            if let Some(component_ranges) = component_ranges
                && component_ranges.len() == components.len()
            {
                let reference = MacroReplacementTypeReference {
                    components,
                    component_ranges,
                    global,
                };
                if !references.contains(&reference) {
                    references.push(reference);
                }
            }
        }
        for index in (0..current.named_child_count()).rev() {
            if let Some(child) = current.named_child(index) {
                stack.push(child);
            }
        }
    }
    references
}

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

#[cfg(test)]
mod tests {
    use super::*;

    fn references(source: &str) -> Vec<MacroReplacementTypeReference> {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_cpp::LANGUAGE.into())
            .expect("C++ grammar");
        let tree = parser.parse(source, None).expect("macro fixture tree");
        let value = tree
            .root_node()
            .named_child(0)
            .and_then(|definition| definition.child_by_field_name("value"))
            .expect("macro replacement");
        object_macro_replacement_type_references(value, source)
    }

    #[test]
    fn object_macro_replacement_reparse_preserves_type_ranges() {
        let source = "#define SETTINGS (*api::SettingsImpl::GetInstance())\n";
        let references = references(source);
        let reference = references
            .iter()
            .find(|reference| reference.components == ["api", "SettingsImpl"])
            .expect("qualified callable owner");
        let rendered = reference
            .component_ranges
            .iter()
            .map(|range| &source[range.clone()])
            .collect::<Vec<_>>();
        assert_eq!(rendered, ["api", "SettingsImpl"]);
    }

    #[test]
    fn macro_reparse_ignores_function_like_and_non_code_text() {
        let function_like = "#define SETTINGS(Type) (*Type::GetInstance())\n";
        assert!(references(function_like).is_empty());

        let text = "#define SETTINGS \"SettingsImpl::GetInstance()\"\n";
        assert!(references(text).is_empty());
    }
}
