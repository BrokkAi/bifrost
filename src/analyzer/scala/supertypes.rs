use tree_sitter::Node;

pub(super) fn extract_scala_supertypes(declaration: Node<'_>, source: &str) -> Vec<String> {
    let Some(extends_clause) = declaration.child_by_field_name("extend") else {
        return Vec::new();
    };
    direct_parent_type_nodes(extends_clause)
        .into_iter()
        .map(|parent| node_text(parent, source).to_string())
        .collect()
}

fn direct_parent_type_nodes(extends_clause: Node<'_>) -> Vec<Node<'_>> {
    let mut parents = Vec::new();
    let mut cursor = extends_clause.walk();
    for child in extends_clause.named_children(&mut cursor) {
        collect_parent_type_roots(child, &mut parents);
    }
    parents
}

fn collect_parent_type_roots<'tree>(node: Node<'tree>, parents: &mut Vec<Node<'tree>>) {
    match node.kind() {
        "arguments" | "annotation" | "structural_type" | "tuple_type" | "named_tuple_type"
        | "wildcard" => {}
        "type_identifier"
        | "stable_type_identifier"
        | "generic_type"
        | "projected_type"
        | "applied_constructor_type"
        | "singleton_type" => parents.push(node),
        "compound_type" | "annotated_type" => {
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                collect_parent_type_roots(child, parents);
            }
        }
        _ => {
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                collect_parent_type_roots(child, parents);
            }
        }
    }
}

fn node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    &source[node.byte_range()]
}
