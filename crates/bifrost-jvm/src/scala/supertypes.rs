use serde::{Deserialize, Serialize};
use tree_sitter::Node;

use brokk_bifrost_core::analyzer::common::node_source_text as node_text;
use brokk_bifrost_core::analyzer::model::StructuredImportScope;

pub(crate) struct ScalaSupertypeFact {
    pub(crate) raw: String,
    pub(crate) lookup_path: ScalaSupertypeLookupPath,
}

/// Parser-derived path used to resolve a Scala supertype without reparsing its
/// display text. Keeping the segments structured is important for nested
/// owners such as `Outer.Base`, where the first and last identifiers carry
/// different resolution semantics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScalaSupertypeLookupPath {
    segments: Vec<String>,
    /// Parser-established package scopes at the owner declaration, ordered
    /// outermost to innermost. Sequential clauses retain each intermediate
    /// scope; one dotted clause retains only its complete package.
    #[serde(default)]
    package_prefixes: Vec<String>,
    /// Parser-derived enclosing lexical scopes at the owner declaration.
    #[serde(default)]
    lexical_scopes: Vec<StructuredImportScope>,
}

impl ScalaSupertypeLookupPath {
    pub fn segments(&self) -> &[String] {
        &self.segments
    }

    pub fn package_prefixes(&self) -> &[String] {
        &self.package_prefixes
    }

    pub fn lexical_scopes(&self) -> &[StructuredImportScope] {
        &self.lexical_scopes
    }

    pub(crate) fn set_package_prefixes(&mut self, package_prefixes: &[String]) {
        self.package_prefixes = package_prefixes.to_vec();
    }

    pub(crate) fn set_lexical_scopes(&mut self, lexical_scopes: &[StructuredImportScope]) {
        self.lexical_scopes = lexical_scopes.to_vec();
    }

    pub(crate) fn encode(&self) -> String {
        serde_json::to_string(self).expect("Scala supertype lookup path is serializable")
    }

    pub fn decode(value: &str) -> Option<Self> {
        serde_json::from_str(value).ok()
    }
}

pub(crate) fn extract_scala_supertypes(
    declaration: Node<'_>,
    source: &str,
) -> Vec<ScalaSupertypeFact> {
    supertype_facts(scala_supertype_lookup_nodes(declaration), source)
}

pub(crate) fn extract_scala_instance_supertypes(
    instance: Node<'_>,
    source: &str,
) -> Vec<ScalaSupertypeFact> {
    supertype_facts(scala_instance_supertype_lookup_nodes(instance), source)
}

fn scala_instance_supertype_lookup_nodes(instance: Node<'_>) -> Vec<(Node<'_>, Node<'_>)> {
    assert_eq!(instance.kind(), "instance_expression");
    let mut parents = Vec::new();
    let mut cursor = instance.walk();
    for child in instance.named_children(&mut cursor) {
        if matches!(
            child.kind(),
            "arguments" | "template_body" | "block" | "indented_block"
        ) {
            continue;
        }
        collect_parent_type_roots(child, &mut parents);
    }
    parents
        .into_iter()
        .filter_map(|parent| supertype_lookup_node(parent).map(|lookup| (parent, lookup)))
        .collect()
}

fn supertype_facts(nodes: Vec<(Node<'_>, Node<'_>)>, source: &str) -> Vec<ScalaSupertypeFact> {
    nodes
        .into_iter()
        .map(|(parent, lookup_node)| ScalaSupertypeFact {
            raw: node_text(parent, source).to_string(),
            lookup_path: ScalaSupertypeLookupPath {
                segments: scala_type_lookup_segments(lookup_node, source),
                package_prefixes: Vec::new(),
                lexical_scopes: Vec::new(),
            },
        })
        .filter(|fact| !fact.lookup_path.segments.is_empty())
        .collect()
}

/// Return the owner-qualified parser-local path of the enum declaration that a
/// parameterized enum case implicitly extends. The `case` token belongs to
/// `enum_case_definitions`, outside the `full_enum_case` node, so derive this
/// relationship from the parser-owned ancestor chain instead of reconstructing
/// it from source text.
pub(crate) fn scala_full_enum_case_owner_supertype(
    declaration: Node<'_>,
    source: &str,
) -> Option<ScalaSupertypeFact> {
    if declaration.kind() != "full_enum_case" {
        return None;
    }
    let mut segments = Vec::new();
    let mut ancestor = declaration.parent();
    while let Some(node) = ancestor {
        if matches!(
            node.kind(),
            "class_definition" | "object_definition" | "trait_definition" | "enum_definition"
        ) {
            let name = node.child_by_field_name("name")?;
            let name = node_text(name, source).trim();
            if name.is_empty() {
                return None;
            }
            segments.push(name.to_string());
        }
        ancestor = node.parent();
    }
    if segments.is_empty() {
        return None;
    }
    segments.reverse();
    Some(ScalaSupertypeFact {
        raw: segments.join("."),
        lookup_path: ScalaSupertypeLookupPath {
            segments,
            package_prefixes: Vec::new(),
            lexical_scopes: Vec::new(),
        },
    })
}

/// Direct parser-owned supertype roots and their lookup nodes for a Scala
/// template declaration. Local classes and objects are intentionally absent
/// from the declaration index, so usage analysis needs the same structured AST
/// facts without inventing a source-text parser.
pub fn scala_supertype_lookup_nodes(declaration: Node<'_>) -> Vec<(Node<'_>, Node<'_>)> {
    if declaration.kind() == "instance_expression" {
        return scala_instance_supertype_lookup_nodes(declaration);
    }
    let Some(extends_clause) = declaration.child_by_field_name("extend") else {
        return Vec::new();
    };
    direct_parent_type_nodes(extends_clause)
        .into_iter()
        .filter_map(|parent| supertype_lookup_node(parent).map(|lookup| (parent, lookup)))
        .collect()
}

/// Parser-owned bounds from a Scala self-type constraint. The first named
/// child is the self binder; the remaining named child is its optional type
/// annotation, whose compound roots each contribute an inherited member edge.
pub(crate) fn scala_self_type_lookup_nodes(self_type: Node<'_>) -> Vec<(Node<'_>, Node<'_>)> {
    assert_eq!(self_type.kind(), "self_type");
    let mut parents = Vec::new();
    let mut cursor = self_type.walk();
    for child in self_type.named_children(&mut cursor).skip(1) {
        collect_parent_type_roots(child, &mut parents);
    }
    parents
        .into_iter()
        .filter_map(|parent| supertype_lookup_node(parent).map(|lookup| (parent, lookup)))
        .collect()
}

pub fn scala_type_lookup_segments(node: Node<'_>, source: &str) -> Vec<String> {
    scala_type_lookup_segments_with(
        node,
        source,
        |node, source| node_text(node, source).to_string(),
        || true,
    )
    .unwrap_or_default()
}

/// Collect parser-owned path segments using the caller's text and walk-budget
/// hooks. The shared traversal preserves language-specific source-slice rules.
pub fn scala_type_lookup_segments_with(
    node: Node<'_>,
    source: &str,
    mut text_of: impl FnMut(Node<'_>, &str) -> String,
    mut step: impl FnMut() -> bool,
) -> Option<Vec<String>> {
    let mut segments = Vec::new();
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if !step() {
            return None;
        }
        match current.kind() {
            "identifier" | "operator_identifier" | "type_identifier" => {
                let segment = text_of(current, source);
                let segment = segment.trim();
                if !segment.is_empty() {
                    segments.push(segment.to_string());
                }
            }
            "type_arguments" | "arguments" | "annotation" | "structural_type" => {}
            _ => {
                let mut cursor = current.walk();
                let mut children = Vec::new();
                for child in current.named_children(&mut cursor) {
                    if !step() {
                        return None;
                    }
                    children.push(child);
                }
                children.reverse();
                stack.extend(children);
            }
        }
    }
    (!segments.is_empty()).then_some(segments)
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
    use brokk_bifrost_core::analyzer::tree_walk::{WalkControl, walk_named_tree_preorder};

    walk_named_tree_preorder(node, true, |node| match node.kind() {
        "arguments" | "annotation" | "structural_type" | "tuple_type" | "named_tuple_type"
        | "wildcard" => WalkControl::SkipChildren,
        "type_identifier"
        | "stable_type_identifier"
        | "generic_type"
        | "projected_type"
        | "applied_constructor_type"
        | "singleton_type" => {
            parents.push(node);
            WalkControl::SkipChildren
        }
        _ => WalkControl::Continue,
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use tree_sitter::Parser;

    fn facts_for(source: &str, class_name: &str) -> Vec<(String, String)> {
        let mut parser = Parser::new();
        parser
            .set_language(&crate::scala::language::LANGUAGE.into())
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
    #[brokk_bifrost_test_macros::hardwon(
        "#6942: collect_parent_type_roots recursion depth followed source nesting"
    )]
    fn collect_parent_type_roots_deep_infix_types_are_stack_safe() {
        let depth = 3000;
        let source = format!("type Deep = A{}", " & A".repeat(depth));
        let mut parser = Parser::new();
        parser
            .set_language(&crate::scala::language::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(&source, None).unwrap();
        assert!(!tree.root_node().has_error());
        let ty = tree
            .root_node()
            .named_child(0)
            .unwrap()
            .child_by_field_name("type")
            .unwrap();
        let mut inner = ty;
        let mut wrappers = 0;
        while inner.kind() == "infix_type" {
            wrappers += 1;
            inner = inner.child_by_field_name("left").unwrap();
        }
        assert_eq!(wrappers, depth);
        eprintln!("collect_parent_type_roots: parsed {wrappers} infix wrappers");
        std::thread::scope(|scope| {
            std::thread::Builder::new()
                .stack_size(128 * 1024)
                .spawn_scoped(scope, || {
                    let mut parents = Vec::new();
                    collect_parent_type_roots(ty, &mut parents);
                    assert_eq!(parents.len(), depth + 1);
                    assert!(
                        parents
                            .windows(2)
                            .all(|pair| pair[0].start_byte() < pair[1].start_byte())
                    );
                })
                .unwrap()
                .join()
                .unwrap();
        });
    }

    #[test]
    fn constructor_applied_generic_supertype_keeps_parent_before_mixin() {
        assert_eq!(
            facts_for(
                "class Child[A](start: Int) extends Base[Child[A], A](start, 1) with Mixin[A]",
                "Child",
            ),
            vec![
                ("Base[Child[A], A]".to_string(), "Base".to_string()),
                ("Mixin[A]".to_string(), "Mixin".to_string()),
            ]
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
    #[test]
    fn anonymous_instance_supertypes_preserve_constructor_and_mixins() {
        let source = "val value = new pkg.Base[Int](1) with First with other.Second {}";
        let mut parser = Parser::new();
        parser
            .set_language(&crate::scala::language::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let mut stack = vec![tree.root_node()];
        let instance = loop {
            let node = stack.pop().expect("instance expression");
            if node.kind() == "instance_expression" {
                break node;
            }
            let mut cursor = node.walk();
            let mut children = node.named_children(&mut cursor).collect::<Vec<_>>();
            children.reverse();
            stack.extend(children);
        };
        let facts = extract_scala_instance_supertypes(instance, source)
            .into_iter()
            .map(|fact| (fact.raw, fact.lookup_path.segments.join(".")))
            .collect::<Vec<_>>();
        assert_eq!(
            facts,
            vec![
                ("pkg.Base[Int](1)".to_string(), "pkg.Base".to_string()),
                ("First".to_string(), "First".to_string()),
                ("other.Second".to_string(), "other.Second".to_string()),
            ]
        );
    }
}
