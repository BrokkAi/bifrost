use serde::{Deserialize, Serialize};
use tree_sitter::Node;

pub(super) struct ScalaSupertypeFact {
    pub(super) raw: String,
    pub(super) lookup_path: ScalaSupertypeLookupPath,
}

/// Parser-derived path used to resolve a Scala supertype without reparsing its
/// display text. Keeping the segments structured is important for nested
/// owners such as `Outer.Base`, where the first and last identifiers carry
/// different resolution semantics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ScalaSupertypeLookupPath {
    segments: Vec<String>,
}

impl ScalaSupertypeLookupPath {
    pub(crate) fn segments(&self) -> &[String] {
        &self.segments
    }

    pub(super) fn encode(&self) -> String {
        serde_json::to_string(self).expect("Scala supertype lookup path is serializable")
    }

    pub(crate) fn decode(value: &str) -> Option<Self> {
        serde_json::from_str(value).ok()
    }
}

pub(super) fn extract_scala_supertypes(
    declaration: Node<'_>,
    source: &str,
) -> Vec<ScalaSupertypeFact> {
    let Some(extends_clause) = declaration.child_by_field_name("extend") else {
        return Vec::new();
    };
    direct_parent_type_nodes(extends_clause)
        .into_iter()
        .filter_map(|parent| {
            let lookup_node = supertype_lookup_node(parent)?;
            Some(ScalaSupertypeFact {
                raw: node_text(parent, source).to_string(),
                lookup_path: ScalaSupertypeLookupPath {
                    segments: scala_type_lookup_segments(lookup_node, source),
                },
            })
        })
        .filter(|fact| !fact.lookup_path.segments.is_empty())
        .collect()
}

pub(crate) fn scala_type_lookup_segments(node: Node<'_>, source: &str) -> Vec<String> {
    let mut segments = Vec::new();
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        match current.kind() {
            "identifier" | "operator_identifier" | "type_identifier" => {
                let segment = node_text(current, source).trim();
                if !segment.is_empty() {
                    segments.push(segment.to_string());
                }
            }
            "type_arguments" | "arguments" | "annotation" | "structural_type" => {}
            _ => {
                let mut cursor = current.walk();
                let mut children = current.named_children(&mut cursor).collect::<Vec<_>>();
                children.reverse();
                stack.extend(children);
            }
        }
    }
    segments
}

fn supertype_lookup_node(node: Node<'_>) -> Option<Node<'_>> {
    match node.kind() {
        "type_identifier" | "stable_type_identifier" | "projected_type" | "singleton_type" => {
            Some(node)
        }
        "generic_type" | "applied_constructor_type" | "annotated_type" => {
            let mut cursor = node.walk();
            node.named_children(&mut cursor)
                .filter(|child| {
                    !matches!(
                        child.kind(),
                        "type_arguments" | "arguments" | "annotation" | "structural_type"
                    )
                })
                .find_map(supertype_lookup_node)
        }
        _ => {
            let mut cursor = node.walk();
            node.named_children(&mut cursor)
                .find_map(supertype_lookup_node)
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use tree_sitter::Parser;

    fn facts_for(source: &str, class_name: &str) -> Vec<(String, String)> {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_scala::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let mut stack = vec![tree.root_node()];
        while let Some(node) = stack.pop() {
            if node.kind() == "class_definition"
                && node
                    .child_by_field_name("name")
                    .is_some_and(|name| node_text(name, source).trim() == class_name)
            {
                return extract_scala_supertypes(node, source)
                    .into_iter()
                    .map(|fact| (fact.raw, fact.lookup_path.segments.join(".")))
                    .collect();
            }
            let mut cursor = node.walk();
            let mut children = node.named_children(&mut cursor).collect::<Vec<_>>();
            children.reverse();
            stack.extend(children);
        }
        Vec::new()
    }

    #[test]
    fn generic_supertype_keeps_display_and_structured_constructor_path() {
        assert_eq!(
            facts_for("class Child extends pkg.Base[Int]", "Child"),
            vec![("pkg.Base[Int]".to_string(), "pkg.Base".to_string())]
        );
    }

    #[test]
    fn compound_supertypes_preserve_source_order() {
        assert_eq!(
            facts_for("class Child extends Base with ImportedTrait", "Child"),
            vec![
                ("Base".to_string(), "Base".to_string()),
                ("ImportedTrait".to_string(), "ImportedTrait".to_string()),
            ]
        );
    }
}
