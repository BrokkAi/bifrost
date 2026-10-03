//! Source-owned Python declaration properties captured by the primary producer.

use brokk_bifrost_core::analyzer::model::{
    StructuredTypeIdentity, StructuredTypeIdentityBuilder, StructuredTypeName,
};
use brokk_bifrost_core::analyzer::python_facts::{
    PythonAnnotationReferenceFact, PythonAnnotationReferenceName,
};
use brokk_bifrost_core::analyzer::source_facts::PrimarySourceFactCollector;
use tree_sitter::Node;

/// Capture the bounded name candidates used to resolve one return annotation.
///
/// The rows are a flat preorder walk. An attribute row owns the candidate
/// rows produced by its children, so a consumer that resolves the attribute
/// can skip those descendants while retaining them as fallback candidates.
pub(crate) fn python_annotation_references(
    annotation: Node<'_>,
    source: &str,
    source_facts: &mut PrimarySourceFactCollector<'_>,
) -> Vec<PythonAnnotationReferenceFact> {
    let mut references = Vec::new();
    match annotation.kind() {
        "identifier" => {
            push_annotation_reference(
                &mut references,
                source_facts,
                annotation,
                PythonAnnotationReferenceName::Lexical(
                    crate::declarations::py_node_text(annotation, source).to_string(),
                ),
                0,
            );
        }
        "attribute" => {
            push_annotation_reference(
                &mut references,
                source_facts,
                annotation,
                python_attribute_reference_name(annotation, source),
                0,
            );
        }
        "string" => {
            let Some(content) = python_string_content(annotation) else {
                return references;
            };
            push_annotation_reference(
                &mut references,
                source_facts,
                content,
                PythonAnnotationReferenceName::Lexical(
                    crate::declarations::py_node_text(content, source).to_string(),
                ),
                1,
            );
        }
        _ => {
            enum Work<'tree> {
                Enter(Node<'tree>),
                Exit(usize),
            }
            let mut stack = vec![Work::Enter(annotation)];
            while let Some(work) = stack.pop() {
                match work {
                    Work::Exit(index) => references[index].subtree_end = references.len(),
                    Work::Enter(node) => match node.kind() {
                        "generic_type" | "subscript" => {
                            // Generic arguments do not name the returned class.
                            // Reuse the primary runtime-owner interpretation so
                            // Optional and unions retain their existing meaning.
                            if let Some(owner) = runtime_annotation_node(node, source) {
                                stack.push(Work::Enter(owner));
                            }
                        }
                        "member_type" => {
                            push_annotation_reference(
                                &mut references,
                                source_facts,
                                node,
                                python_attribute_reference_name(node, source),
                                1,
                            );
                        }
                        "identifier" => {
                            push_annotation_reference(
                                &mut references,
                                source_facts,
                                node,
                                PythonAnnotationReferenceName::Lexical(
                                    crate::declarations::py_node_text(node, source).to_string(),
                                ),
                                1,
                            );
                        }
                        "attribute" => {
                            let index = push_annotation_reference(
                                &mut references,
                                source_facts,
                                node,
                                python_attribute_reference_name(node, source),
                                1,
                            );
                            stack.push(Work::Exit(index));
                            let mut cursor = node.walk();
                            let mut children: Vec<_> = node.named_children(&mut cursor).collect();
                            children.reverse();
                            stack.extend(children.into_iter().map(Work::Enter));
                        }
                        "string" => {
                            if let Some(content) = python_string_content(node) {
                                push_annotation_reference(
                                    &mut references,
                                    source_facts,
                                    content,
                                    PythonAnnotationReferenceName::Lexical(
                                        crate::declarations::py_node_text(content, source)
                                            .to_string(),
                                    ),
                                    2,
                                );
                            }
                        }
                        _ => {
                            let mut cursor = node.walk();
                            let mut children: Vec<_> = node.named_children(&mut cursor).collect();
                            children.reverse();
                            stack.extend(children.into_iter().map(Work::Enter));
                        }
                    },
                }
            }
        }
    }
    references
}

fn push_annotation_reference(
    references: &mut Vec<PythonAnnotationReferenceFact>,
    source_facts: &mut PrimarySourceFactCollector<'_>,
    node: Node<'_>,
    name: PythonAnnotationReferenceName,
    lookup_depth: u8,
) -> usize {
    let index = references.len();
    references.push(PythonAnnotationReferenceFact {
        occurrence: source_facts.intern_node(node),
        name,
        subtree_end: index + 1,
        lookup_depth,
    });
    index
}

fn python_attribute_reference_name(node: Node<'_>, source: &str) -> PythonAnnotationReferenceName {
    python_nominal_path(node, source)
        .map(PythonAnnotationReferenceName::Qualified)
        .unwrap_or(PythonAnnotationReferenceName::Unavailable)
}

fn python_string_content(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|child| child.kind() == "string_content")
}

/// The nominal runtime class admitted by Python's return-annotation inference.
/// Generic containers retain their base; Optional and type wrappers select their
/// argument. Unsupported syntax remains absent rather than a guessed type name.
pub(crate) fn python_return_type_identity(
    annotation: Node<'_>,
    source: &str,
) -> Option<StructuredTypeIdentity> {
    let mut node = runtime_annotation_node(annotation, source)?;
    let embedded;
    if node.kind() == "string" {
        embedded = crate::syntax::python_deferred_annotation_tree(node, source, None)?;
        node = runtime_annotation_node(embedded.root_node(), source)?;
    }
    let path = python_nominal_path(node, source)?;
    let mut builder = StructuredTypeIdentityBuilder::default();
    let root = builder.named(StructuredTypeName::new(path, Vec::new(), false)?)?;
    builder.finish(root)
}

fn python_nominal_path(node: Node<'_>, source: &str) -> Option<Vec<String>> {
    let mut path = Vec::new();
    let mut pending = vec![node];
    while let Some(node) = pending.pop() {
        match node.kind() {
            "identifier" => path.push(crate::declarations::py_node_text(node, source).to_string()),
            "attribute" => {
                pending.push(node.child_by_field_name("attribute")?);
                pending.push(node.child_by_field_name("object")?);
            }
            "member_type" => {
                let mut cursor = node.walk();
                let children: Vec<_> = node.named_children(&mut cursor).collect();
                pending.extend(children.into_iter().rev());
            }
            _ => return None,
        }
    }
    Some(path)
}

fn runtime_annotation_node<'tree>(mut node: Node<'tree>, source: &str) -> Option<Node<'tree>> {
    loop {
        node = match node.kind() {
            "module" | "expression_statement" | "type" => {
                if node.named_child_count() != 1 {
                    return None;
                }
                node.named_child(0)?
            }
            "generic_type" => {
                let base = node.named_child(0)?;
                if is_runtime_wrapper(base, source) {
                    node.named_child(1)?.named_child(0)?
                } else if is_union_name(base, source) {
                    sole_non_none_member(node.named_child(1)?)?
                } else {
                    base
                }
            }
            "subscript" => {
                let base = node.child_by_field_name("value")?;
                if is_runtime_wrapper(base, source) {
                    node.child_by_field_name("subscript")?
                } else if is_union_name(base, source) {
                    sole_non_none_member(node)?
                } else {
                    base
                }
            }
            // `Optional[X]` is defined as `Union[X, None]`, and PEP 604 spells
            // the same thing `X | None`. A union with one non-`None` member
            // therefore has that member's runtime owner; a union with two of
            // them has no single owner and is refused here.
            "union_type" => sole_non_none_member(node)?,
            "binary_operator"
                if node
                    .child_by_field_name("operator")
                    .is_some_and(|operator| operator.kind() == "|") =>
            {
                sole_non_none_member(node)?
            }
            "identifier" | "attribute" | "member_type" | "string" => return Some(node),
            _ => return None,
        };
    }
}

/// The one member of a union that is not `None`, if there is exactly one.
///
/// The grammar spells the members as the named children of a `union_type`, a
/// `binary_operator` over `|`, or a `Union[...]` argument list, so one walk
/// over the named children covers every form.
fn sole_non_none_member<'tree>(node: Node<'tree>) -> Option<Node<'tree>> {
    let mut cursor = node.walk();
    let mut members = node
        .named_children(&mut cursor)
        .filter(|member| !annotation_is_none(*member));
    let member = members.next()?;
    members.next().is_none().then_some(member)
}

/// Whether an annotation member is the `None` literal, including the `type`
/// wrapper the grammar puts around a `Union[...]` argument.
fn annotation_is_none(mut node: Node<'_>) -> bool {
    while node.kind() == "type" && node.named_child_count() == 1 {
        node = node.named_child(0).expect("one named annotation child");
    }
    node.kind() == "none"
}

/// Whether an annotation base names `typing.Union`.
fn is_union_name(node: Node<'_>, source: &str) -> bool {
    let text = |node| crate::declarations::py_node_text(node, source);
    match node.kind() {
        "identifier" => text(node) == "Union",
        "attribute" => {
            let (Some(object), Some(attribute)) = (
                node.child_by_field_name("object"),
                node.child_by_field_name("attribute"),
            ) else {
                return false;
            };
            object.kind() == "identifier"
                && attribute.kind() == "identifier"
                && text(object) == "typing"
                && text(attribute) == "Union"
        }
        _ => false,
    }
}

fn is_runtime_wrapper(node: Node<'_>, source: &str) -> bool {
    let text = |node| crate::declarations::py_node_text(node, source);
    match node.kind() {
        "identifier" => matches!(text(node), "Optional" | "type" | "Type"),
        "attribute" => {
            let (Some(object), Some(attribute)) = (
                node.child_by_field_name("object"),
                node.child_by_field_name("attribute"),
            ) else {
                return false;
            };
            object.kind() == "identifier"
                && attribute.kind() == "identifier"
                && text(object) == "typing"
                && matches!(text(attribute), "Optional" | "Type")
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn return_annotations_preserve_qualified_generic_and_quoted_runtime_owners() {
        for (annotation, expected) in [
            ("models.Manager[A, B]", Some(vec!["models", "Manager"])),
            ("typing.Optional[models.User]", Some(vec!["models", "User"])),
            ("type[models.User]", Some(vec!["models", "User"])),
            ("\"models.User\"", Some(vec!["models", "User"])),
            ("models.User | None", Some(vec!["models", "User"])),
            ("Union[models.User, None]", Some(vec!["models", "User"])),
            ("models.User | models.Group", None),
            ("\"models.User[\"", None),
        ] {
            let source = format!("def create() -> {annotation}:\n    pass\n");
            let tree = crate::declarations::parse_python_tree(&source).expect("Python tree");
            let function = tree.root_node().named_child(0).expect("function");
            let annotation = function
                .child_by_field_name("return_type")
                .expect("annotation");
            let identity = python_return_type_identity(annotation, &source);
            let path = identity
                .as_ref()
                .and_then(StructuredTypeIdentity::nominal_name)
                .map(|name| name.path().iter().map(String::as_str).collect::<Vec<_>>());
            assert_eq!(path, expected, "{source}");
        }
    }
}
