use super::model::node_text;
use brokk_bifrost_core::analyzer::tree_walk::{WalkControl, walk_named_tree_preorder};
use brokk_bifrost_core::hash::HashSet;
use std::collections::BTreeSet;
use tree_sitter::{Language, Node, Parser};

pub fn extract_js_ts_type_identifiers(source: &str, language: Language) -> BTreeSet<String> {
    let mut parser = Parser::new();
    parser
        .set_language(&language)
        .expect("failed to load JS/TS parser");
    let Some(tree) = parser.parse(source, None) else {
        return BTreeSet::new();
    };
    let mut identifiers = HashSet::default();
    collect_js_ts_identifiers(tree.root_node(), source, &mut identifiers);
    identifiers.into_iter().collect()
}

pub(crate) fn es_named_exported_roots(root: Node<'_>, source: &str) -> HashSet<String> {
    let mut roots = HashSet::default();
    for index in 0..root.named_child_count() {
        let Some(child) = root.named_child(index) else {
            continue;
        };
        if child.kind() != "export_statement" || child.child_by_field_name("source").is_some() {
            continue;
        }
        let mut cursor = child.walk();
        for export_child in child.named_children(&mut cursor) {
            collect_js_ts_export_clause_roots(export_child, source, &mut roots);
        }
    }
    roots
}

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
            if let Some(text) = trimmed_identifier_text(node, source) {
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
                if let Some(text) = trimmed_identifier_text(name, source) {
                    identifiers.insert(text.to_string());
                }
            }
        }
        _ => {}
    }
}

pub(crate) fn trimmed_identifier_text<'source>(
    node: Node<'_>,
    source: &'source str,
) -> Option<&'source str> {
    let text = node_text(node, source).trim();
    (!text.is_empty()).then_some(text)
}

pub(crate) fn collect_js_ts_export_identifier(
    node: Node<'_>,
    source: &str,
    roots: &mut HashSet<String>,
) {
    if matches!(
        node.kind(),
        "identifier" | "type_identifier" | "property_identifier" | "shorthand_property_identifier"
    ) && let Some(name) = trimmed_identifier_text(node, source)
    {
        roots.insert(name.to_string());
    }
}

pub(crate) fn collect_js_ts_export_clause_roots(
    node: Node<'_>,
    source: &str,
    roots: &mut HashSet<String>,
) {
    match node.kind() {
        "export_clause" => {
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                collect_js_ts_export_clause_roots(child, source, roots);
            }
        }
        "export_specifier" => {
            let name = node
                .child_by_field_name("name")
                .or_else(|| node.named_child(0));
            if let Some(name) = name {
                collect_js_ts_export_identifier(name, source, roots);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::{collect_js_ts_identifiers, extract_js_ts_type_identifiers};
    use crate::javascript::extract_js_type_identifiers;
    use brokk_bifrost_core::hash::HashSet;
    use std::collections::BTreeSet;
    use tree_sitter::Parser;

    #[test]
    fn identifier_projection_matches_named_grammar_nodes() {
        let ts = "interface Holder<T> { value: T; } type Result = Holder<string>; const holder: Holder<number> = make(); holder.value;";
        let expected: BTreeSet<String> = ["Holder", "T", "value", "Result", "holder", "make"]
            .into_iter()
            .map(str::to_string)
            .collect();
        assert_eq!(
            extract_js_ts_type_identifiers(ts, tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into()),
            expected
        );

        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
            .unwrap();
        let tree = parser.parse(ts, None).unwrap();
        let mut collected = HashSet::default();
        collect_js_ts_identifiers(tree.root_node(), ts, &mut collected);
        assert_eq!(collected.into_iter().collect::<BTreeSet<_>>(), expected);

        let js = "const π = source.value; function render(item) { return item.name; }";
        let expected_js: BTreeSet<String> = ["π", "source", "value", "render", "item", "name"]
            .into_iter()
            .map(str::to_string)
            .collect();
        assert_eq!(extract_js_type_identifiers(js), expected_js);
    }
}
