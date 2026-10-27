#[cfg(test)]
use brokk_bifrost_core::analyzer::source_facts::{SourceFactRows, SourceOccurrenceId};
use std::path::Path;
#[cfg(test)]
use tree_sitter::{Parser, Tree};

pub fn write_fixture_file(root: &Path, relative: &str, contents: &str) {
    let path = root.join(relative);
    std::fs::create_dir_all(path.parent().expect("fixture path parent"))
        .expect("create fixture directories");
    std::fs::write(path, contents).expect("write fixture");
}

#[cfg(test)]
pub(crate) fn occurrence_text<'source>(
    source: &'source str,
    rows: &SourceFactRows,
    occurrence: SourceOccurrenceId,
) -> &'source str {
    let range = rows.occurrence(occurrence).range;
    &source[range.start_byte..range.end_byte]
}

#[cfg(test)]
pub(crate) fn parse_rust(source: &str) -> Tree {
    crate::lexical_scope::parse_rust_tree(source).expect("Rust tree")
}

#[cfg(test)]
pub(crate) fn parse_rust_fixture(
    source: &str,
) -> brokk_bifrost_core::analyzer::parsed_file::ParsedFile {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_rust::LANGUAGE.into())
        .expect("Rust fixture grammar");
    let tree = parser.parse(source, None).expect("Rust fixture tree");
    let temp = tempfile::tempdir().expect("temporary workspace");
    let root = temp.path().canonicalize().expect("canonical root");
    let file = brokk_bifrost_core::analyzer::ProjectFile::new(root, "src/lib.rs");
    crate::declarations::parse_rust_file(&file, source, &tree)
}

// Shared grammar-boundary fixture. Escapes keep this file ASCII; all table
// coordinates refer to the decoded UTF-8 source, including the leading comment.
#[cfg(test)]
pub(crate) const PATH_GRAMMAR_SOURCE: &str = concat!(
    "// \u{03bb} keeps spans in bytes.\n",
    "#[cfg(test)]\n",
    "use crate::{self, r#type as Alias, nest::{self as Here, \u{0394} as _, *}};\n",
    "use ::dep::r#mod;\n",
    "fn paths<'a>(a: &T, b: &mut T, c: &&mut T, d: &'a mut \u{0394}) {\n",
    "    ::dep::r#mod(); crate::item(); self::item(); super::item();\n",
    "    a::Type::<T>::method::<U>();\n",
    "    let x: crate::Wrap<self::Inner<T>>;\n",
    "    let y = &value; let z = &mut *value;\n",
    "}\n",
);

// Select by independently specified kind and byte range, never by source search.
#[cfg(test)]
pub(crate) fn grammar_node<'tree>(
    root: tree_sitter::Node<'tree>,
    kind: &str,
    start: usize,
    end: usize,
    text: &str,
) -> tree_sitter::Node<'tree> {
    assert_eq!(&PATH_GRAMMAR_SOURCE[start..end], text);
    let mut pending = vec![root];
    while let Some(node) = pending.pop() {
        if node.kind() == kind && node.byte_range() == (start..end) {
            return node;
        }
        let mut cursor = node.walk();
        pending.extend(node.named_children(&mut cursor));
    }
    panic!("missing grammar node {kind} {start}..{end}: {text:?}");
}
