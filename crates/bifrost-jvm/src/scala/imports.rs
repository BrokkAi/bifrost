//! Scala's structured import and export parsing.
//!
//! Every function here reads a tree-sitter node and produces a core
//! [`ImportInfo`], [`ScalaExportInfo`] or [`StructuredImportScope`]; the
//! analyzer-facing half -- `ScalaAnalyzer`'s import resolution and its
//! `ImportAnalysisProvider` impl -- stays in `brokk-bifrost-analysis`.

use brokk_bifrost_core::analyzer::CodeUnit;
use brokk_bifrost_core::analyzer::model::{
    ImportInfo, ScalaExportInfo, ScalaExportSelector, StructuredImportPath, StructuredImportScope,
};
use tree_sitter::Node;

pub fn scala_import_infos_from_node(node: Node<'_>, source: &str) -> Vec<ImportInfo> {
    scala_import_infos_from_node_with_prefixes(node, source, &[])
}

pub fn scala_import_infos_from_node_with_prefixes(
    node: Node<'_>,
    source: &str,
    lexical_prefixes: &[String],
) -> Vec<ImportInfo> {
    if node.kind() != "import_declaration" {
        return Vec::new();
    }
    let mut path_cursor = node.walk();
    let base_path_nodes = node
        .children_by_field_name("path", &mut path_cursor)
        .filter(Node::is_named)
        .collect::<Vec<_>>();
    let base_path = base_path_nodes
        .iter()
        .map(|segment| scala_node_text(*segment, source).to_string())
        .collect::<Vec<_>>();
    if base_path.is_empty() {
        return Vec::new();
    }
    let lexical_scopes = scala_lexical_scope_path(node);

    let mut infos = Vec::new();
    let mut cursor = node.walk();
    let direct_children = node.named_children(&mut cursor).collect::<Vec<_>>();
    if let Some(selectors) = direct_children
        .iter()
        .find(|child| child.kind() == "namespace_selectors")
    {
        let mut selector_cursor = selectors.walk();
        for selector in selectors.named_children(&mut selector_cursor) {
            if let Some(info) = scala_import_selector_info(
                selector,
                &base_path,
                lexical_prefixes,
                &lexical_scopes,
                node.start_byte(),
                source,
            ) {
                infos.push(info);
            }
        }
        return infos;
    }

    if let Some(selector) = direct_children.iter().find(|child| {
        matches!(
            child.kind(),
            "namespace_wildcard" | "as_renamed_identifier" | "arrow_renamed_identifier"
        )
    }) {
        return scala_import_selector_info(
            *selector,
            &base_path,
            lexical_prefixes,
            &lexical_scopes,
            node.start_byte(),
            source,
        )
        .into_iter()
        .collect();
    }

    let identifier = base_path.last().cloned();
    // A plain `import a.b.C` binds its last path segment's own token.
    let binder_span = base_path_nodes
        .last()
        .copied()
        .map(brokk_bifrost_core::analyzer::common::node_span);
    vec![ImportInfo {
        raw_snippet: render_scala_import(&base_path, false, None),
        is_wildcard: false,
        identifier,
        alias: None,
        path: Some(StructuredImportPath {
            segments: base_path,
            kind: None,
            lexical_prefixes: lexical_prefixes.to_vec(),
            lexical_scopes,
            declaration_start_byte: node.start_byte(),
        }),
        binder_span,
    }]
}

pub fn scala_export_info_from_node(node: Node<'_>, source: &str) -> Option<ScalaExportInfo> {
    if node.kind() != "export_declaration" {
        return None;
    }
    let mut path_cursor = node.walk();
    let mut owner_path = node
        .children_by_field_name("path", &mut path_cursor)
        .filter(Node::is_named)
        .map(|segment| scala_node_text(segment, source).to_string())
        .collect::<Vec<_>>();
    if owner_path.is_empty() {
        return None;
    }

    let mut selectors = Vec::new();
    let mut cursor = node.walk();
    let direct_children = node.named_children(&mut cursor).collect::<Vec<_>>();
    if let Some(namespace_selectors) = direct_children
        .iter()
        .find(|child| child.kind() == "namespace_selectors")
    {
        let mut selector_cursor = namespace_selectors.walk();
        for selector in namespace_selectors.named_children(&mut selector_cursor) {
            if let Some(selector) = scala_export_selector(selector, source) {
                selectors.push(selector);
            }
        }
    } else if let Some(selector) = direct_children.iter().find(|child| {
        matches!(
            child.kind(),
            "namespace_wildcard" | "as_renamed_identifier" | "arrow_renamed_identifier"
        )
    }) {
        selectors.push(scala_export_selector(*selector, source)?);
    } else {
        let source_name = owner_path.pop()?;
        selectors.push(ScalaExportSelector::Named {
            visible_name: Some(source_name.clone()),
            source_name,
        });
    }

    (!selectors.is_empty()).then_some(ScalaExportInfo {
        owner_path,
        selectors,
        declaration_start_byte: node.start_byte(),
    })
}

fn scala_export_selector(node: Node<'_>, source: &str) -> Option<ScalaExportSelector> {
    match node.kind() {
        "namespace_wildcard" => {
            let given = (0..node.child_count()).any(|index| {
                node.child(index)
                    .is_some_and(|child| !child.is_named() && child.kind() == "given")
            });
            Some(if given {
                ScalaExportSelector::GivenWildcard
            } else {
                ScalaExportSelector::Wildcard
            })
        }
        "identifier" | "operator_identifier" | "type_identifier" => {
            let source_name = scala_node_text(node, source).to_string();
            Some(ScalaExportSelector::Named {
                visible_name: Some(source_name.clone()),
                source_name,
            })
        }
        "as_renamed_identifier" | "arrow_renamed_identifier" => {
            let name = node.child_by_field_name("name")?;
            let alias = node.child_by_field_name("alias")?;
            let source_name = scala_node_text(name, source).to_string();
            let visible_name =
                (alias.kind() != "wildcard").then(|| scala_node_text(alias, source).to_string());
            Some(ScalaExportSelector::Named {
                source_name,
                visible_name,
            })
        }
        _ => None,
    }
}

fn scala_import_selector_info(
    selector: Node<'_>,
    base_path: &[String],
    lexical_prefixes: &[String],
    lexical_scopes: &[StructuredImportScope],
    declaration_start_byte: usize,
    source: &str,
) -> Option<ImportInfo> {
    if selector.kind() == "namespace_wildcard" {
        return Some(ImportInfo {
            raw_snippet: render_scala_import(base_path, true, None),
            is_wildcard: true,
            identifier: None,
            alias: None,
            path: Some(StructuredImportPath {
                segments: base_path.to_vec(),
                kind: None,
                lexical_prefixes: lexical_prefixes.to_vec(),
                lexical_scopes: lexical_scopes.to_vec(),
                declaration_start_byte,
            }),
            binder_span: None,
        });
    }

    // The bound name is spelled by the rename's alias token, or by the plain
    // selector token itself.
    let (name, alias, binder_node) = match selector.kind() {
        "identifier" | "operator_identifier" | "type_identifier" => (
            scala_node_text(selector, source).to_string(),
            None,
            selector,
        ),
        "as_renamed_identifier" | "arrow_renamed_identifier" => {
            let name = selector.child_by_field_name("name")?;
            let alias = selector.child_by_field_name("alias")?;
            if alias.kind() == "wildcard" {
                return None;
            }
            (
                scala_node_text(name, source).to_string(),
                Some(scala_node_text(alias, source).to_string()),
                alias,
            )
        }
        _ => return None,
    };
    let mut path = base_path.to_vec();
    path.push(name.clone());
    Some(ImportInfo {
        raw_snippet: render_scala_import(&path, false, alias.as_deref()),
        is_wildcard: false,
        identifier: Some(alias.clone().unwrap_or(name)),
        alias,
        path: Some(StructuredImportPath {
            segments: path,
            kind: None,
            lexical_prefixes: lexical_prefixes.to_vec(),
            lexical_scopes: lexical_scopes.to_vec(),
            declaration_start_byte,
        }),
        binder_span: Some(brokk_bifrost_core::analyzer::common::node_span(binder_node)),
    })
}

pub fn scala_lexical_scope_path(node: Node<'_>) -> Vec<StructuredImportScope> {
    let mut scopes = Vec::new();
    let mut current = node.parent();
    while let Some(parent) = current {
        if is_scala_lexical_scope(parent.kind()) {
            scopes.push(StructuredImportScope {
                start_byte: parent.start_byte(),
                end_byte: parent.end_byte(),
            });
        }
        current = parent.parent();
    }
    scopes.reverse();
    scopes
}

pub fn scala_lexical_scope_path_checked(
    node: Node<'_>,
    mut inspect: impl FnMut(Node<'_>) -> bool,
) -> Option<Vec<StructuredImportScope>> {
    let mut scopes = Vec::new();
    let mut current = node.parent();
    while let Some(parent) = current {
        if !inspect(parent) {
            return None;
        }
        if is_scala_lexical_scope(parent.kind()) {
            scopes.push(StructuredImportScope {
                start_byte: parent.start_byte(),
                end_byte: parent.end_byte(),
            });
        }
        current = parent.parent();
    }
    scopes.reverse();
    Some(scopes)
}

pub fn scala_lexical_scope_path_at(root: Node<'_>, byte: usize) -> Vec<StructuredImportScope> {
    let end = byte.saturating_add(1).min(root.end_byte());
    let node = root
        .descendant_for_byte_range(byte.min(end), end)
        .unwrap_or(root);
    scala_lexical_scope_path(node)
}

fn is_scala_lexical_scope(kind: &str) -> bool {
    matches!(
        kind,
        "package_clause"
            | "template_body"
            | "block"
            | "indented_block"
            | "function_definition"
            | "class_definition"
            | "object_definition"
            | "trait_definition"
            | "enum_definition"
            | "extension_definition"
    )
}

fn render_scala_import(path: &[String], wildcard: bool, alias: Option<&str>) -> String {
    let mut rendered = format!("import {}", path.join("."));
    if wildcard {
        rendered.push_str(".*");
    } else if let Some(alias) = alias {
        rendered.push_str(" as ");
        rendered.push_str(alias);
    }
    rendered
}

fn scala_node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    &source[node.byte_range()]
}

pub fn is_scala_importable_top_level(unit: &CodeUnit) -> bool {
    if unit.short_name().contains('.') {
        return false;
    }
    unit.is_class() || unit.is_function() || unit.is_field()
}

pub fn is_scala_importable_direct_member(unit: &CodeUnit) -> bool {
    unit.is_class() || unit.is_function() || unit.is_field()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tree_sitter::Parser;

    fn parsed_export(source: &str) -> ScalaExportInfo {
        let mut parser = Parser::new();
        parser
            .set_language(&crate::scala::language::LANGUAGE.into())
            .expect("Scala parser");
        let tree = parser.parse(source, None).expect("Scala syntax tree");
        let mut stack = vec![tree.root_node()];
        while let Some(node) = stack.pop() {
            if node.kind() == "export_declaration" {
                return scala_export_info_from_node(node, source).expect("structured export");
            }
            let mut cursor = node.walk();
            stack.extend(node.named_children(&mut cursor));
        }
        panic!("missing export declaration in {source:?}");
    }

    #[test]
    fn scala_export_parser_preserves_selector_semantics() {
        let export = parsed_export(
            "object Facade { export Core.{dropped as _, original as renamed, kept, *} }",
        );
        assert_eq!(export.owner_path, ["Core"]);
        assert_eq!(
            export.selectors,
            [
                ScalaExportSelector::Named {
                    source_name: "dropped".to_string(),
                    visible_name: None,
                },
                ScalaExportSelector::Named {
                    source_name: "original".to_string(),
                    visible_name: Some("renamed".to_string()),
                },
                ScalaExportSelector::Named {
                    source_name: "kept".to_string(),
                    visible_name: Some("kept".to_string()),
                },
                ScalaExportSelector::Wildcard,
            ]
        );
    }

    #[test]
    fn scala_export_parser_distinguishes_given_from_ordinary_wildcard() {
        let given = parsed_export("object Facade { export Core.given }");
        assert_eq!(given.selectors, [ScalaExportSelector::GivenWildcard]);
        let ordinary = parsed_export("object Facade { export Core.* }");
        assert_eq!(ordinary.selectors, [ScalaExportSelector::Wildcard]);
    }
}
