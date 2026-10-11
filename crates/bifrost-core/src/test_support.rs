use crate::analyzer::ProjectFile;
use crate::analyzer::source_facts::{SourceFactRows, SourceOccurrenceId};
use std::path::Path;
use tree_sitter::Node;

pub fn sqlite_error(code: i32) -> rusqlite::Error {
    rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(code), None)
}

#[doc(hidden)]
pub fn wait_for_nonzero_count(mut waiting_count: impl FnMut() -> usize, message: &str) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while waiting_count() == 0 {
        assert!(std::time::Instant::now() < deadline, "{message}");
        std::thread::yield_now();
    }
}

/// Recursively visit every node in source-order preorder for shallow test fixtures.
pub fn walk_tree_preorder_reference<'tree>(root: Node<'tree>, mut visit: impl FnMut(Node<'tree>)) {
    fn visit_subtree<'tree>(node: Node<'tree>, visit: &mut impl FnMut(Node<'tree>)) {
        visit(node);
        for index in 0..node.child_count() {
            if let Some(child) = node.child(index) {
                visit_subtree(child, visit);
            }
        }
    }

    visit_subtree(root, &mut visit);
}

pub fn occurrence_text<'source>(
    source: &'source str,
    rows: &SourceFactRows,
    occurrence: SourceOccurrenceId,
) -> &'source str {
    let range = rows.occurrence(occurrence).range;
    &source[range.start_byte..range.end_byte]
}

pub fn assert_deep_clone_preparation(
    normalized_tokens: &[String],
    ast_signature: &str,
    depth: usize,
) {
    for delimiter in ["(", ")"] {
        let token = format!("OP:{delimiter}");
        let signature = format!("N:{delimiter}");
        assert_eq!(
            normalized_tokens
                .iter()
                .filter(|value| value.as_str() == token)
                .count(),
            depth
        );
        assert_eq!(ast_signature.matches(&signature).count(), depth);
    }
}

pub fn write_file(root: &Path, rel_path: &str, contents: &str) -> ProjectFile {
    let file = ProjectFile::new(root.to_path_buf(), rel_path);
    file.write(contents).expect("write fixture file");
    file
}
