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

/// Collect the qualified name owned directly by a package or import
/// declaration. The walk accepts only Java qualified-identifier AST shapes,
/// so annotations and recovery nodes cannot become route segments.
pub(crate) fn directive_path_segments<'tree, 'source>(
    node: Node<'tree>,
    source: &'source str,
) -> Option<Vec<(Node<'tree>, &'source str)>> {
    debug_assert!(matches!(
        node.kind(),
        "package_declaration" | "import_declaration"
    ));
    let mut cursor = node.walk();
    let mut path_nodes = node.named_children(&mut cursor).filter(|child| {
        !child.is_extra() && matches!(child.kind(), "identifier" | "scoped_identifier")
    });
    let path = path_nodes.next()?;
    if path_nodes.next().is_some() {
        return None;
    }
    if path.is_error() || path.is_missing() || path.has_error() {
        return None;
    }

    let mut segments = Vec::new();
    let mut stack = vec![path];
    while let Some(current) = stack.pop() {
        if current.is_error() || current.is_missing() {
            return None;
        }
        match current.kind() {
            "identifier" => {
                let spelling = node_text(current, source).trim();
                if spelling.is_empty() {
                    return None;
                }
                segments.push((current, spelling));
            }
            "scoped_identifier" => {
                let mut cursor = current.walk();
                let mut children = current
                    .named_children(&mut cursor)
                    .filter(|child| !child.is_extra())
                    .collect::<Vec<_>>();
                if children.len() != 2 {
                    return None;
                }
                while let Some(child) = children.pop() {
                    if !matches!(child.kind(), "identifier" | "scoped_identifier") {
                        return None;
                    }
                    stack.push(child);
                }
            }
            _ => return None,
        }
    }
    (!segments.is_empty()).then_some(segments)
}

/// The structured interpretation of one Java package declaration shared by
/// display identity and native resolution. A malformed path remains attached
/// to its declaration so native admission can retain its existing gap.
pub(crate) struct JavaPackageSyntax<'tree, 'source> {
    pub(crate) node: Node<'tree>,
    pub(crate) segments: Option<Vec<(Node<'tree>, &'source str)>>,
}

pub(crate) fn parse_package_syntax<'tree, 'source>(
    node: Node<'tree>,
    source: &'source str,
) -> JavaPackageSyntax<'tree, 'source> {
    assert_eq!(node.kind(), "package_declaration");
    JavaPackageSyntax {
        node,
        segments: directive_path_segments(node, source),
    }
}

/// The one structured interpretation of a Java import declaration shared by
/// the canonical source projection and native resolution lowering.
pub(crate) struct JavaImportSyntax<'tree, 'source> {
    pub(crate) segments: Option<Vec<(Node<'tree>, &'source str)>>,
    pub(crate) is_wildcard: bool,
    pub(crate) is_static: bool,
}

/// Read an import declaration's path and direct modifier tokens once.
pub(crate) fn parse_import_syntax<'tree, 'source>(
    node: Node<'tree>,
    source: &'source str,
) -> JavaImportSyntax<'tree, 'source> {
    let segments = directive_path_segments(node, source);
    let mut is_wildcard = false;
    let mut is_static = false;
    for child in node.children(&mut node.walk()) {
        match child.kind() {
            "asterisk" => is_wildcard = true,
            "static" => is_static = true,
            _ => {}
        }
    }
    JavaImportSyntax {
        segments,
        is_wildcard,
        is_static,
    }
}

impl<'tree, 'source> JavaImportSyntax<'tree, 'source> {
    pub(crate) fn to_import_info(&self, node: Node<'tree>, raw: String) -> ImportInfo {
        let last_segment_node = self
            .segments
            .as_ref()
            .and_then(|segments| segments.last().map(|(segment, _)| *segment));
        let segments = self
            .segments
            .as_ref()
            .map(|segments| {
                segments
                    .iter()
                    .map(|(_, spelling)| (*spelling).to_owned())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let identifier = (!self.is_wildcard)
            .then(|| segments.last().cloned())
            .flatten();
        let kind = if self.is_static {
            StructuredImportPathKind::StaticMember
        } else {
            StructuredImportPathKind::Namespace
        };
        // Java has no import aliases, so the token that spells the bound name
        // is always the path's last segment; a wildcard binds no single name.
        let binder_span = (!self.is_wildcard)
            .then(|| last_segment_node.map(node_span))
            .flatten();

        ImportInfo {
            raw_snippet: raw,
            is_wildcard: self.is_wildcard,
            is_global: false,
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
}

pub fn parse_import_info(node: Node<'_>, source: &str, raw: String) -> ImportInfo {
    parse_import_syntax(node, source).to_import_info(node, raw)
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
