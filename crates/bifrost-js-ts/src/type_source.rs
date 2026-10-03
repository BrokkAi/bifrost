//! Flat declaration type syntax captured while the primary tree is live.

use brokk_bifrost_core::analyzer::js_ts_facts::{JsTsSourceTypeId, JsTsTypeFact, JsTsTypeShape};
use brokk_bifrost_core::analyzer::source_facts::PrimarySourceFactCollector;
use brokk_bifrost_core::hash::HashMap;
use tree_sitter::Node;

#[derive(Default)]
pub(crate) struct JsTsTypeCollector {
    by_node: HashMap<usize, JsTsSourceTypeId>,
}

impl JsTsTypeCollector {
    pub fn capture(
        &mut self,
        root: Node<'_>,
        source: &str,
        occurrences: &mut PrimarySourceFactCollector<'_>,
        facts: &mut Vec<JsTsTypeFact>,
    ) -> JsTsSourceTypeId {
        let mut pending = vec![(root, false)];
        while let Some((node, exit)) = pending.pop() {
            if self.by_node.contains_key(&node.id()) {
                continue;
            }
            if !exit {
                pending.push((node, true));
                let start = pending.len();
                let mut cursor = node.walk();
                pending.extend(node.named_children(&mut cursor).map(|child| (child, false)));
                pending[start..].reverse();
                continue;
            }
            let id = |child: Node<'_>| {
                *self
                    .by_node
                    .get(&child.id())
                    .expect("type children precede owners")
            };
            let children = || {
                let mut cursor = node.walk();
                node.named_children(&mut cursor).map(id).collect::<Vec<_>>()
            };
            let shape = match node.kind() {
                "type_identifier"
                | "identifier"
                | "property_identifier"
                | "nested_type_identifier"
                | "member_expression" => {
                    let mut path = Vec::new();
                    let mut current = node;
                    while let Some((owner, name)) =
                        crate::syntax::nested_type_identifier_parts(current).or_else(|| {
                            (current.kind() == "member_expression")
                                .then(|| {
                                    Some((
                                        current.child_by_field_name("object")?,
                                        current.child_by_field_name("property")?,
                                    ))
                                })
                                .flatten()
                        })
                    {
                        path.push(crate::syntax::slice(name, source).trim().to_string());
                        current = owner;
                    }
                    if matches!(
                        current.kind(),
                        "type_identifier" | "identifier" | "property_identifier"
                    ) {
                        path.push(crate::syntax::slice(current, source).trim().to_string());
                        path.reverse();
                        JsTsTypeShape::Named(path)
                    } else {
                        JsTsTypeShape::Unknown
                    }
                }
                "generic_type" => node
                    .child_by_field_name("name")
                    .map(|base| {
                        let arguments = node
                            .child_by_field_name("type_arguments")
                            .map(|arguments| {
                                let mut cursor = arguments.walk();
                                arguments.named_children(&mut cursor).map(id).collect()
                            })
                            .unwrap_or_default();
                        JsTsTypeShape::Generic {
                            base: id(base),
                            arguments,
                        }
                    })
                    .unwrap_or(JsTsTypeShape::Unknown),
                "type_annotation" | "parenthesized_type" | "readonly_type" => node
                    .named_child(0)
                    .map(|child| JsTsTypeShape::Wrapped(id(child)))
                    .unwrap_or(JsTsTypeShape::Unknown),
                "union_type" => JsTsTypeShape::Union(children()),
                "intersection_type" => JsTsTypeShape::Intersection(children()),
                "type_query" => node
                    .named_child(0)
                    .map(|child| JsTsTypeShape::Query(id(child)))
                    .unwrap_or(JsTsTypeShape::Unknown),
                "array_type" => node
                    .named_child(0)
                    .map(|child| JsTsTypeShape::Array(id(child)))
                    .unwrap_or(JsTsTypeShape::Unknown),
                "tuple_type" => JsTsTypeShape::Tuple(children()),
                "function_type"
                | "constructor_type"
                | "method_signature"
                | "call_signature"
                | "construct_signature" => {
                    let parameters = node
                        .child_by_field_name("parameters")
                        .map(|parameters| {
                            let mut cursor = parameters.walk();
                            parameters
                                .named_children(&mut cursor)
                                .filter(|parameter| {
                                    matches!(
                                        parameter.kind(),
                                        "required_parameter" | "optional_parameter"
                                    )
                                })
                                .map(|parameter| parameter.child_by_field_name("type").map(id))
                                .collect()
                        })
                        .unwrap_or_default();
                    let result = node
                        .child_by_field_name("return_type")
                        .or_else(|| node.child_by_field_name("type"))
                        .map(id);
                    JsTsTypeShape::Function { parameters, result }
                }
                "object_type" | "interface_body" => {
                    let mut cursor = node.walk();
                    let members = node
                        .named_children(&mut cursor)
                        .filter_map(|member| {
                            let name = member.child_by_field_name("name")?;
                            let value =
                                if matches!(member.kind(), "method_signature" | "call_signature") {
                                    member
                                } else {
                                    member.child_by_field_name("type")?
                                };
                            Some((
                                crate::syntax::slice(name, source).trim().to_string(),
                                id(value),
                            ))
                        })
                        .collect();
                    JsTsTypeShape::Object(members)
                }
                "predefined_type" | "literal_type"
                    if matches!(
                        crate::syntax::slice(node, source).trim(),
                        "null" | "undefined" | "never"
                    ) =>
                {
                    JsTsTypeShape::NoReceiver
                }
                _ => JsTsTypeShape::Unknown,
            };
            let type_id =
                JsTsSourceTypeId::try_from_index(facts.len()).expect("JS/TS type ids fit u32");
            facts.push(JsTsTypeFact {
                occurrence: occurrences.intern_node(node),
                shape,
            });
            assert!(self.by_node.insert(node.id(), type_id).is_none());
        }
        self.by_node[&root.id()]
    }
}
