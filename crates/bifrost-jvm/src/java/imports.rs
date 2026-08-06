//! What a Java `import` declaration says.
//!
//! The parser-derived reading of an `import_declaration` node and the four
//! questions the resolvers ask of the resulting [`ImportInfo`]. The caching, the
//! reverse import index and the same-package reference index stay in
//! `analyzer/java/imports.rs` because they read the analyzer's own cells; the
//! resolution built on top of these helpers is in
//! [`crate::java::graph_support`].

use brokk_bifrost_core::analyzer::common::node_span;
use brokk_bifrost_core::analyzer::model::{
    ImportInfo, StructuredImportPath, StructuredImportPathKind,
};
use tree_sitter::Node;

use crate::java::declarations::node_text;

pub fn parse_import_info(node: Node<'_>, source: &str, raw: String) -> ImportInfo {
    let mut segments = Vec::new();
    let mut last_segment_node = None;
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if matches!(current.kind(), "identifier" | "type_identifier") {
            segments.push(node_text(current, source).to_owned());
            last_segment_node = Some(current);
            continue;
        }
        for index in (0..current.named_child_count()).rev() {
            if let Some(child) = current.named_child(index) {
                stack.push(child);
            }
        }
    }
    let mut is_wildcard = false;
    let mut is_static = false;
    for child in node.children(&mut node.walk()) {
        match child.kind() {
            "asterisk" => is_wildcard = true,
            "static" => is_static = true,
            _ => {}
        }
    }
    let identifier = (!is_wildcard).then(|| segments.last().cloned()).flatten();
    let kind = if is_static {
        StructuredImportPathKind::StaticMember
    } else {
        StructuredImportPathKind::Namespace
    };
    // Java has no import aliases, so the token that spells the bound name is
    // always the path's last segment; a wildcard binds no single name.
    let binder_span = (!is_wildcard)
        .then(|| last_segment_node.map(node_span))
        .flatten();

    ImportInfo {
        raw_snippet: raw,
        is_wildcard,
        identifier,
        alias: None,
        path: (!segments.is_empty()).then_some(StructuredImportPath {
            segments,
            kind: Some(kind),
            lexical_prefixes: Vec::new(),
            lexical_scopes: Vec::new(),
            declaration_start_byte: node.start_byte(),
        }),
        binder_span,
    }
}

/// The parser-derived path of a non-static import, or `None` for a static
/// import (or a malformed declaration that produced no segments). For an
/// on-demand (`.*`) import the segments name the package; the asterisk is
/// not a segment.
pub fn non_static_import_path(import: &ImportInfo) -> Option<&StructuredImportPath> {
    let path = import.path.as_ref()?;
    (path.kind != Some(StructuredImportPathKind::StaticMember)).then_some(path)
}

/// The parser-derived path of a static import, or `None` otherwise.
pub fn static_import_path(import: &ImportInfo) -> Option<&StructuredImportPath> {
    let path = import.path.as_ref()?;
    (path.kind == Some(StructuredImportPathKind::StaticMember)).then_some(path)
}

/// The package prefix an import makes visible: every segment for an
/// on-demand (`.*`) import, every segment but the terminal member or type
/// name otherwise. `None` when no package segments remain.
pub fn import_package(import: &ImportInfo) -> Option<String> {
    let path = import.path.as_ref()?;
    if import.is_wildcard {
        return Some(path.render_segments("."));
    }
    let (_, package) = path.segments.split_last()?;
    (!package.is_empty()).then(|| package.join("."))
}
