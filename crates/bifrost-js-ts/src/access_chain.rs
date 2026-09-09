//! Bounded structural access chains for imported JS/TS member reads.
//!
//! A chain is complete only when its root is an identifier and every segment is
//! either a dot member or a string-literal subscript. The returned nodes and
//! ranges let import resolution and usage extraction require the exact endpoint
//! instead of treating an owner read as a read of every member it exposes.

use crate::syntax::{slice, static_member_property};
use brokk_bifrost_core::analyzer::Range;
use brokk_bifrost_core::analyzer::usages::reference_site::node_range;
use tree_sitter::Node;

pub const MAX_IMPORT_MEMBER_CHAIN_SEGMENTS: usize = 64;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImportMemberChainOwner<'tree> {
    pub property: Node<'tree>,
    pub range: Range,
    pub name: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JsTsImportedMemberChain<'tree> {
    pub root: Node<'tree>,
    pub members: Vec<ImportMemberChainOwner<'tree>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum JsTsImportedMemberChainResolution<'tree> {
    Exact(JsTsImportedMemberChain<'tree>),
    Dynamic { range: Range },
    Unsupported { reason: &'static str, range: Range },
    ExceededBudget { limit: &'static str },
}

impl JsTsImportedMemberChain<'_> {
    pub fn root_name<'source>(&self, source: &'source str) -> &'source str {
        slice(self.root, source)
    }

    pub fn endpoint(&self) -> Option<&ImportMemberChainOwner<'_>> {
        self.members.last()
    }

    pub fn member(&self, name: &str) -> Option<&ImportMemberChainOwner<'_>> {
        self.members.iter().find(|member| member.name == name)
    }

    pub fn contains_member(&self, name: &str) -> bool {
        self.member(name).is_some()
    }
}

pub fn resolve_import_member_chain<'tree>(
    expression: Node<'tree>,
    source: &str,
) -> JsTsImportedMemberChainResolution<'tree> {
    let mut members = Vec::new();
    let mut current = expression;

    loop {
        if current.kind() == "identifier" {
            if slice(current, source).is_empty() {
                return JsTsImportedMemberChainResolution::Unsupported {
                    reason: "empty_chain_root",
                    range: node_range(current),
                };
            }
            members.reverse();
            return JsTsImportedMemberChainResolution::Exact(JsTsImportedMemberChain {
                root: current,
                members,
            });
        }

        if members.len() == MAX_IMPORT_MEMBER_CHAIN_SEGMENTS {
            return JsTsImportedMemberChainResolution::ExceededBudget {
                limit: "MAX_IMPORT_MEMBER_CHAIN_SEGMENTS",
            };
        }

        if !matches!(current.kind(), "member_expression" | "subscript_expression") {
            return JsTsImportedMemberChainResolution::Unsupported {
                reason: "chain_root_is_not_identifier",
                range: node_range(current),
            };
        }

        let Some(object) = current.child_by_field_name("object") else {
            return JsTsImportedMemberChainResolution::Unsupported {
                reason: "missing_member_object",
                range: node_range(current),
            };
        };

        let Some((property, name)) = static_member_property(current, source) else {
            return JsTsImportedMemberChainResolution::Dynamic {
                range: member_property_range(current),
            };
        };
        if property.kind() == "private_property_identifier" {
            return JsTsImportedMemberChainResolution::Unsupported {
                reason: "private_property_segment",
                range: node_range(property),
            };
        }

        members.push(ImportMemberChainOwner {
            property,
            range: node_range(property),
            name,
        });
        current = object;
    }
}

fn member_property_range(member: Node<'_>) -> Range {
    member
        .child_by_field_name(if member.kind() == "subscript_expression" {
            "index"
        } else {
            "property"
        })
        .map(node_range)
        .unwrap_or_else(|| node_range(member))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tree_sitter::{Parser, Tree};

    fn parse_javascript(source: &str) -> Tree {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_javascript::LANGUAGE.into())
            .expect("JavaScript grammar");
        parser.parse(source, None).expect("JavaScript tree")
    }

    fn find_member_expression<'tree>(root: Node<'tree>, source: &str, text: &str) -> Node<'tree> {
        let mut stack = vec![root];
        while let Some(node) = stack.pop() {
            if node.kind() == "member_expression" && slice(node, source) == text {
                return node;
            }
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                stack.push(child);
            }
        }
        panic!("missing member expression `{text}`");
    }

    fn find_expression<'tree>(root: Node<'tree>, source: &str, text: &str) -> Node<'tree> {
        let mut stack = vec![root];
        while let Some(node) = stack.pop() {
            if slice(node, source) == text {
                return node;
            }
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                stack.push(child);
            }
        }
        panic!("missing expression `{text}`");
    }

    #[test]
    fn dotted_chain_preserves_root_and_ordered_members() {
        let source = "const result = mapping.aliasToReal.each;";
        let tree = parse_javascript(source);
        let expression =
            find_member_expression(tree.root_node(), source, "mapping.aliasToReal.each");

        let JsTsImportedMemberChainResolution::Exact(chain) =
            resolve_import_member_chain(expression, source)
        else {
            panic!("dotted access should be exact");
        };

        assert_eq!(chain.root_name(source), "mapping");
        assert_eq!(
            chain
                .members
                .iter()
                .map(|member| member.name.as_str())
                .collect::<Vec<_>>(),
            ["aliasToReal", "each"]
        );
        assert_eq!(chain.endpoint().expect("endpoint").name, "each");
        assert!(chain.contains_member("aliasToReal"));
    }

    #[test]
    fn static_string_subscript_decodes_exact_member() {
        let source = "const result = mapping.aliasToReal['__'];";
        let tree = parse_javascript(source);
        let expression = find_expression(tree.root_node(), source, "mapping.aliasToReal['__']");

        let JsTsImportedMemberChainResolution::Exact(chain) =
            resolve_import_member_chain(expression, source)
        else {
            panic!("string subscript should be exact");
        };

        assert_eq!(chain.endpoint().expect("endpoint").name, "__");
        assert_eq!(
            chain.endpoint().expect("endpoint").property.kind(),
            "string_fragment"
        );
    }

    #[test]
    fn dynamic_subscript_is_typed_and_never_exact() {
        let source = "const result = mapping.aliasToReal[name];";
        let tree = parse_javascript(source);
        let expression = find_expression(tree.root_node(), source, "mapping.aliasToReal[name]");

        let JsTsImportedMemberChainResolution::Dynamic { range } =
            resolve_import_member_chain(expression, source)
        else {
            panic!("computed access should be dynamic");
        };

        assert_eq!(
            range.start_byte,
            source.find("[name]").expect("subscript") + 1
        );
        assert_eq!(range.end_byte, range.start_byte + "name".len());
    }

    #[test]
    fn private_and_non_identifier_chains_fail_closed() {
        let private_source =
            "class Box { #inner = {}; read(other) { return other.#inner.value; } }";
        let private_tree = parse_javascript(private_source);
        let private_expression =
            find_expression(private_tree.root_node(), private_source, "other.#inner");
        assert_eq!(
            resolve_import_member_chain(private_expression, private_source),
            JsTsImportedMemberChainResolution::Unsupported {
                reason: "private_property_segment",
                range: node_range(
                    private_expression
                        .child_by_field_name("property")
                        .expect("private property")
                ),
            }
        );

        let call_source = "const result = getMapping().value;";
        let call_tree = parse_javascript(call_source);
        let call_expression =
            find_member_expression(call_tree.root_node(), call_source, "getMapping().value");
        assert!(matches!(
            resolve_import_member_chain(call_expression, call_source),
            JsTsImportedMemberChainResolution::Unsupported { .. }
        ));
    }

    #[test]
    fn oversize_chain_reports_budget_without_truncation() {
        let access = ".member";
        let access_count = MAX_IMPORT_MEMBER_CHAIN_SEGMENTS + 1;
        let mut source = String::from("const result = mapping");
        for _ in 0..access_count {
            source.push_str(access);
        }
        source.push(';');
        let tree = parse_javascript(&source);
        let expression = find_member_expression(
            tree.root_node(),
            &source,
            source
                .trim_end_matches(';')
                .trim_start_matches("const result = "),
        );

        assert_eq!(
            resolve_import_member_chain(expression, &source),
            JsTsImportedMemberChainResolution::ExceededBudget {
                limit: "MAX_IMPORT_MEMBER_CHAIN_SEGMENTS"
            }
        );
    }
}
