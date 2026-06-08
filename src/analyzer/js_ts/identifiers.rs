use super::model::node_text;
use crate::analyzer::tree_sitter_analyzer::{WalkControl, walk_named_tree_preorder};
use crate::hash::HashSet;
use tree_sitter::Node;

pub(crate) fn collect_js_ts_identifiers(
    node: Node<'_>,
    source: &str,
    identifiers: &mut HashSet<String>,
) {
    walk_named_tree_preorder(node, true, |node| {
        match node.kind() {
            "identifier" | "type_identifier" | "property_identifier" => {
                let text = node_text(node, source).trim();
                if !text.is_empty() {
                    identifiers.insert(text.to_string());
                }
            }
            "jsx_opening_element" | "jsx_self_closing_element" => {
                if let Some(name) = node.child_by_field_name("name") {
                    let text = node_text(name, source)
                        .trim()
                        .split('.')
                        .next_back()
                        .unwrap_or("");
                    if !text.is_empty() {
                        identifiers.insert(text.to_string());
                    }
                }
            }
            _ => {}
        }
        WalkControl::Continue
    });
}
