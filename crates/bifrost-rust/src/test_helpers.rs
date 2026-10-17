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
