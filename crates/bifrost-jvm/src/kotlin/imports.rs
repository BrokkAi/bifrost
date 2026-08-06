//! Kotlin structured imports (#1237).
//!
//! Issue #1236 recorded a Kotlin file's `import` lines as display strings only.
//! This module turns them into structured facts — a dotted path, whether the
//! import is a star import, and the name it binds — so nothing downstream has
//! to recover that structure by scanning text.
//!
//! Kotlin's import forms are small and entirely file-scoped: there is no
//! `import` inside a block, no static/instance distinction, and no selector
//! list. A header is exactly one of
//!
//! ```text
//! import a.b.C          binds C
//! import a.b.C as D     binds D
//! import a.b.*          binds every name a.b exports
//! ```
//!
//! where the path may name a package member (`a.b.C`), a nested type
//! (`a.b.Outer.Inner`), or a member of an object, companion, or enum
//! (`a.b.Registry.register`). A star import likewise widens either a package or
//! a single object-like owner.
//!
//! Kotlin/JS and Kotlin/Native default imports are deliberately not modelled:
//! see [`KOTLIN_DEFAULT_IMPORT_PACKAGES`].
//!
//! `KotlinAnalyzer`'s own import resolution -- the caches, the star-import
//! widening and the `ImportAnalysisProvider` impl -- stays in
//! `analyzer/kotlin/imports.rs`, because both halves read the analyzer's
//! memoized products.

use brokk_bifrost_core::analyzer::CodeUnit;
use brokk_bifrost_core::analyzer::model::{ImportInfo, StructuredImportPath};
use brokk_bifrost_core::analyzer::tree_walk::{
    first_named_child_of_kind as first_named_child, named_children,
};
use tree_sitter::Node;

use crate::kotlin::declarations::kotlin_identifier_text;

/// The packages every Kotlin/JVM file imports without writing an `import` line.
///
/// The first eight are Kotlin's platform-independent defaults; `java.lang` and
/// `kotlin.jvm` are added only on Kotlin/JVM. Kotlin/JS (`kotlin.js`) and
/// Kotlin/Native (`kotlin.native`) add their own, and this issue targets
/// Kotlin/JVM only — a name that would resolve solely through a Kotlin/JS or
/// Kotlin/Native default import stays unresolved rather than being guessed at,
/// because guessing would claim a resolution the target platform may not have.
pub const KOTLIN_DEFAULT_IMPORT_PACKAGES: &[&str] = &[
    "kotlin",
    "kotlin.annotation",
    "kotlin.collections",
    "kotlin.comparisons",
    "kotlin.io",
    "kotlin.ranges",
    "kotlin.sequences",
    "kotlin.text",
    "java.lang",
    "kotlin.jvm",
];

/// Read one `import_header` node into a structured [`ImportInfo`], or `None`
/// when the header carries no usable path.
///
/// The path segments come from the `identifier` node's own `simple_identifier`
/// children, one per dotted component, so a malformed or oddly-spaced header
/// cannot smear two segments into one.
pub fn kotlin_import_info_from_node(node: Node<'_>, source: &str) -> Option<ImportInfo> {
    if node.kind() != "import_header" {
        return None;
    }
    let identifier = first_named_child(node, "identifier")?;
    let segment_nodes: Vec<Node<'_>> = named_children(identifier)
        .into_iter()
        .filter(|child| child.kind() == "simple_identifier")
        .filter(|segment| !kotlin_identifier_text(*segment, source).is_empty())
        .collect();
    let segments: Vec<String> = segment_nodes
        .iter()
        .map(|segment| kotlin_identifier_text(*segment, source).to_string())
        .collect();
    if segments.is_empty() {
        return None;
    }

    let is_wildcard = first_named_child(node, "wildcard_import").is_some();
    let alias_node = first_named_child(node, "import_alias")
        .and_then(|alias| first_named_child(alias, "type_identifier"));
    let alias = alias_node
        .map(|name| kotlin_identifier_text(name, source).to_string())
        .filter(|name| !name.is_empty());
    // The bound name is spelled by the alias token when renamed, and by the
    // path's last segment token otherwise; a star import binds no single name.
    let binder_span = (!is_wildcard)
        .then(|| {
            alias
                .is_some()
                .then_some(alias_node)
                .flatten()
                .or_else(|| segment_nodes.last().copied())
        })
        .flatten()
        .map(brokk_bifrost_core::analyzer::common::node_span);
    // A star import binds no single name, so it has no bound identifier; every
    // other form binds its alias when renamed and its last segment otherwise.
    let identifier = (!is_wildcard)
        .then(|| {
            alias
                .clone()
                .or_else(|| segments.last().cloned())
                .filter(|name| !name.is_empty())
        })
        .flatten();

    Some(ImportInfo {
        raw_snippet: render_kotlin_import(&segments, is_wildcard, alias.as_deref()),
        is_wildcard,
        identifier,
        alias,
        path: Some(StructuredImportPath {
            segments,
            kind: None,
            // Kotlin imports are file-scoped: they always sit at the top level
            // of the file, never inside a package clause or a declaration, so
            // there is no lexical prefix or enclosing scope to record.
            lexical_prefixes: Vec::new(),
            lexical_scopes: Vec::new(),
            declaration_start_byte: node.start_byte(),
        }),
        binder_span,
    })
}

/// Render the import back to canonical Kotlin source from its structured
/// parts, so `raw_snippet` is a faithful display of what was parsed rather
/// than a slice whose formatting consumers might try to re-parse.
fn render_kotlin_import(segments: &[String], is_wildcard: bool, alias: Option<&str>) -> String {
    let mut rendered = format!("import {}", segments.join("."));
    if is_wildcard {
        rendered.push_str(".*");
    } else if let Some(alias) = alias {
        rendered.push_str(" as ");
        rendered.push_str(alias);
    }
    rendered
}

/// The dotted path an import names, or `None` when the parser recorded no
/// structured path.
pub fn kotlin_import_path(import: &ImportInfo) -> Option<String> {
    let path = import.path.as_ref()?;
    (!path.segments.is_empty()).then(|| path.render_segments("."))
}

/// Whether a declaration is one a star import over its package would bind.
///
/// Kotlin packages export top-level types, functions, and properties alike, so
/// this is not restricted to classes the way a type-only import would be. A
/// dotted short name means the declaration is nested inside another one, which
/// a package-level star import does not reach.
pub fn is_kotlin_importable_top_level(unit: &CodeUnit) -> bool {
    !unit.is_synthetic() && !unit.short_name().contains('.')
}

#[cfg(test)]
mod tests {
    use super::*;
    use tree_sitter::Parser;

    fn parsed_imports(source: &str) -> Vec<ImportInfo> {
        let mut parser = Parser::new();
        parser
            .set_language(&crate::kotlin::language::LANGUAGE.into())
            .expect("load Kotlin grammar");
        let tree = parser.parse(source, None).expect("parse Kotlin source");
        let mut infos = Vec::new();
        let mut stack = vec![tree.root_node()];
        while let Some(node) = stack.pop() {
            if node.kind() == "import_header" {
                if let Some(info) = kotlin_import_info_from_node(node, source) {
                    infos.push(info);
                }
                continue;
            }
            let mut children = named_children(node);
            children.reverse();
            stack.extend(children);
        }
        infos.sort_by_key(|info| {
            info.path
                .as_ref()
                .map(|path| path.declaration_start_byte)
                .unwrap_or(0)
        });
        infos
    }

    #[test]
    fn kotlin_import_forms_carry_structured_paths_and_bound_names() {
        let infos = parsed_imports(
            "package app\n\
             \n\
             import lib.Service\n\
             import lib.Service as Renamed\n\
             import lib.nested.*\n\
             import lib.Registry.register\n",
        );

        let paths: Vec<String> = infos
            .iter()
            .map(|info| kotlin_import_path(info).expect("structured path"))
            .collect();
        assert_eq!(
            paths,
            vec![
                "lib.Service".to_string(),
                "lib.Service".to_string(),
                "lib.nested".to_string(),
                "lib.Registry.register".to_string(),
            ]
        );

        let bound: Vec<Option<&str>> = infos
            .iter()
            .map(|info| info.identifier.as_deref())
            .collect();
        assert_eq!(
            bound,
            vec![Some("Service"), Some("Renamed"), None, Some("register")]
        );

        assert_eq!(infos[1].alias.as_deref(), Some("Renamed"));
        assert!(infos[2].is_wildcard);
        assert!(!infos[0].is_wildcard && !infos[3].is_wildcard);

        let rendered: Vec<&str> = infos.iter().map(|info| info.raw_snippet.as_str()).collect();
        assert_eq!(
            rendered,
            vec![
                "import lib.Service",
                "import lib.Service as Renamed",
                "import lib.nested.*",
                "import lib.Registry.register",
            ]
        );
    }

    #[test]
    fn kotlin_import_segments_survive_backtick_quoting() {
        let infos = parsed_imports("import lib.`odd name`.Service\n");
        assert_eq!(
            infos[0].path.as_ref().map(|path| path.segments.clone()),
            Some(vec![
                "lib".to_string(),
                "odd name".to_string(),
                "Service".to_string()
            ]),
            "backticks are quoting syntax, not part of a segment's name"
        );
    }
}
