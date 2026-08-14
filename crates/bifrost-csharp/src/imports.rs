//! C#'s `using`-directive parsing.
//!
//! `analyzer/csharp/imports.rs` in `brokk-bifrost-analysis` keeps the
//! `ImportAnalysisProvider` impl and the memo cells behind it; what a `using`
//! directive *says* -- namespace, static-member target, or alias -- is decided
//! here, from the directive node.
//!
//! Every answer comes from the syntax tree. This module used to re-read the
//! raw snippet with `strip_prefix("global ")` / `strip_prefix("using ")` and a
//! `contains('=')` test to tell the three forms apart; the parser already
//! distinguishes them, so each form now records its own
//! `StructuredImportPathKind` and its own `is_global` flag, and consumers read
//! those instead of re-deriving them from text.

use brokk_bifrost_core::analyzer::common::node_span;
use brokk_bifrost_core::analyzer::model::{
    ImportInfo, StructuredImportPath, StructuredImportPathKind,
};
use tree_sitter::Node;

use crate::syntax::{
    csharp_type_node_segments, csharp_using_directive_is_global, csharp_using_directive_is_static,
    csharp_using_directive_namespace_node,
};

/// The namespace a plain `using` directive imports, from its structured path.
///
/// A plain `using System.Text;` is the only form that names a namespace: a
/// `using static` names a type and a `using A = X;` names an alias target, and
/// each records its own `path_kind`. The value is the path's segments rejoined
/// with '.', which is the spelling the parser saw.
pub fn csharp_using_namespace(import: &ImportInfo) -> Option<String> {
    let path = import.path.as_ref()?;
    (path.kind == Some(StructuredImportPathKind::Namespace))
        .then(|| path.render_segments("."))
        .filter(|namespace| !namespace.is_empty())
}

pub fn csharp_import_info_from_using_directive(
    node: Node<'_>,
    source: &str,
    raw: String,
) -> Option<ImportInfo> {
    let is_global = csharp_using_directive_is_global(node);
    let declaration_start_byte = node.start_byte();
    let structured_path = |segments: Vec<String>, kind: StructuredImportPathKind| {
        StructuredImportPath {
            segments,
            kind: Some(kind),
            // A C# using directive sits at file or namespace level, and the
            // namespace it sits in is already each unit's own package, so there
            // is no prefix or enclosing block extent to record here.
            lexical_prefixes: Vec::new(),
            lexical_scopes: Vec::new(),
            declaration_start_byte,
        }
    };

    if let Some(target) = csharp_using_directive_namespace_node(node) {
        let segments = csharp_type_node_segments(target, source);
        if segments.is_empty() {
            return None;
        }
        // A plain `using` imports every name under the namespace, so it binds
        // no single token, and its `identifier` is the namespace's own tail.
        let identifier = segments.last().cloned();
        return Some(ImportInfo {
            raw_snippet: raw,
            is_wildcard: true,
            is_global,
            identifier,
            alias: None,
            path: Some(structured_path(
                segments,
                StructuredImportPathKind::Namespace,
            )),
            binder_span: None,
        });
    }

    if csharp_using_directive_is_static(node) {
        let mut cursor = node.walk();
        let target = node.named_children(&mut cursor).find(|child| {
            matches!(
                child.kind(),
                "identifier" | "qualified_name" | "alias_qualified_name" | "generic_name"
            )
        })?;
        let segments = csharp_type_node_segments(target, source);
        if segments.is_empty() {
            return None;
        }
        return Some(ImportInfo {
            raw_snippet: raw,
            is_wildcard: false,
            is_global,
            identifier: Some(segments.join(".")),
            alias: None,
            path: Some(structured_path(
                segments,
                StructuredImportPathKind::StaticMember,
            )),
            binder_span: None,
        });
    }

    let alias_node = node.child_by_field_name("name")?;
    let alias = node_text(alias_node, source).trim();
    if alias.is_empty() {
        return None;
    }
    let mut cursor = node.walk();
    let target_node = node.named_children(&mut cursor).find(|child| {
        child.start_byte() >= alias_node.end_byte() && child.id() != alias_node.id()
    })?;
    let segments = csharp_type_node_segments(target_node, source);
    if segments.is_empty() {
        return None;
    }
    // `using A = X.Y;` binds exactly one name, spelled by the alias token.
    Some(ImportInfo {
        raw_snippet: raw,
        is_wildcard: false,
        is_global,
        identifier: Some(segments.join(".")),
        alias: Some(alias.to_string()),
        path: Some(structured_path(
            segments,
            StructuredImportPathKind::ImportFrom,
        )),
        binder_span: Some(node_span(alias_node)),
    })
}

/// The type a `using static` directive imports, from its structured path.
pub fn csharp_static_using_from_import(import: &ImportInfo) -> Option<&str> {
    let path = import.path.as_ref()?;
    (path.kind == Some(StructuredImportPathKind::StaticMember))
        .then_some(import.identifier.as_deref())
        .flatten()
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
    let target = csharp_type_node_segments(target_node, source).join(".");
    (!target.is_empty()).then_some((alias, target))
}

fn node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    node.utf8_text(source.as_bytes()).unwrap_or("")
}
