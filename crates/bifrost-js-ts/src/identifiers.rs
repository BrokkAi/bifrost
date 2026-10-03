use super::model::node_text;
use brokk_bifrost_core::analyzer::tree_walk::{WalkControl, walk_named_tree_preorder};
use brokk_bifrost_core::hash::HashSet;
use tree_sitter::Node;

pub fn collect_js_ts_identifiers(node: Node<'_>, source: &str, identifiers: &mut HashSet<String>) {
    walk_named_tree_preorder(node, true, |node| {
        collect_js_ts_identifier(node, source, identifiers);
        WalkControl::Continue
    });
}

pub(crate) fn collect_js_ts_identifier(
    node: Node<'_>,
    source: &str,
    identifiers: &mut HashSet<String>,
) {
    match node.kind() {
        "identifier" | "type_identifier" | "property_identifier" => {
            let text = node_text(node, source).trim();
            if !text.is_empty() {
                identifiers.insert(text.to_string());
            }
        }
        "jsx_opening_element" | "jsx_self_closing_element" => {
            if let Some(mut name) = node.child_by_field_name("name") {
                while name.kind() == "member_expression" {
                    let Some(property) = name.child_by_field_name("property") else {
                        break;
                    };
                    name = property;
                }
                let text = node_text(name, source).trim();
                if !text.is_empty() {
                    identifiers.insert(text.to_string());
                }
            }
        }
        _ => {}
    }
}
