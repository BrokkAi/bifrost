//! C#'s `using`-directive parsing.
//!
//! `analyzer/csharp/imports.rs` in `brokk-bifrost-analysis` keeps the
//! `ImportAnalysisProvider` impl and the memo cells behind it; what a `using`
//! directive *says* -- namespace, static-member target, or alias -- is decided
//! here, from the directive node and its raw snippet.

use brokk_bifrost_core::analyzer::model::ImportInfo;
use tree_sitter::Node;

use crate::syntax::{csharp_type_node_identity, csharp_using_directive_is_static};

pub fn csharp_using_namespace(raw: &str) -> Option<String> {
    let trimmed = raw.trim().trim_end_matches(';').trim();
    let rest = trimmed
        .strip_prefix("global ")
        .unwrap_or(trimmed)
        .strip_prefix("using ")?
        .trim();
    if rest.starts_with("static ") || rest.contains('=') || rest.is_empty() {
        return None;
    }
    Some(rest.to_string())
}

pub fn csharp_import_info(raw: String) -> ImportInfo {
    let identifier = csharp_using_namespace(&raw)
        .and_then(|namespace| namespace.rsplit('.').next().map(str::to_string));
    ImportInfo {
        raw_snippet: raw,
        is_wildcard: true,
        identifier,
        alias: None,
        path: None,
        binder_span: None,
    }
}

pub fn csharp_import_info_from_using_directive(
    node: Node<'_>,
    source: &str,
    raw: String,
) -> Option<ImportInfo> {
    if csharp_using_namespace(&raw).is_some() {
        return Some(csharp_import_info(raw));
    }
    if csharp_using_directive_is_static(node) {
        let mut cursor = node.walk();
        let target = node
            .named_children(&mut cursor)
            .find(|child| {
                matches!(
                    child.kind(),
                    "identifier" | "qualified_name" | "alias_qualified_name" | "generic_name"
                )
            })
            .map(|target| csharp_type_node_identity(target, source))?;
        return (!target.is_empty()).then_some(ImportInfo {
            raw_snippet: raw,
            is_wildcard: false,
            identifier: Some(target),
            alias: None,
            path: None,
            binder_span: None,
        });
    }
    csharp_using_alias_from_node(node, source).map(|(alias, target)| ImportInfo {
        raw_snippet: raw,
        is_wildcard: false,
        identifier: Some(target),
        alias: Some(alias),
        path: None,
        binder_span: None,
    })
}

pub fn csharp_static_using_from_import(import: &ImportInfo) -> Option<&str> {
    if !import.is_wildcard && import.alias.is_none() {
        import.identifier.as_deref()
    } else {
        None
    }
}

pub fn csharp_using_alias_from_import(import: &ImportInfo) -> Option<(String, String)> {
    Some((import.alias.clone()?, import.identifier.clone()?))
}

pub fn csharp_using_alias_from_node(node: Node<'_>, source: &str) -> Option<(String, String)> {
    let alias_node = node.child_by_field_name("name")?;
    let alias = node_text(alias_node, source).trim().to_string();
    if alias.is_empty() {
        return None;
    }
    let mut cursor = node.walk();
    let target_node = node.named_children(&mut cursor).find(|child| {
        child.start_byte() >= alias_node.end_byte() && child.id() != alias_node.id()
    })?;
    let target = csharp_type_node_identity(target_node, source);
    (!target.is_empty()).then_some((alias, target))
}

fn node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    node.utf8_text(source.as_bytes()).unwrap_or("")
}
