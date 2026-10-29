//! Declaration index candidate sets, ordering and row merging.

use super::{CodeUnit, CodeUnitType, ProjectFile, TreeSitterAnalyzer};
use crate::analyzer::Language;
use crate::analyzer::store::StoreLanguageAdapter;
use crate::analyzer::tree_sitter_analyzer::{LanguageAdapter, ParsedFile};
use crate::hash::HashSet;

struct TestAdapter;

impl StoreLanguageAdapter for TestAdapter {
    fn language(&self) -> Language {
        Language::Python
    }
}

impl LanguageAdapter for TestAdapter {
    fn query_directory(&self) -> &'static str {
        "python"
    }

    fn file_extension(&self) -> &'static str {
        "py"
    }

    fn extract_call_receiver(&self, _reference: &str) -> Option<String> {
        None
    }

    fn parse_file(
        &self,
        _file: &ProjectFile,
        _source: &str,
        _tree: &tree_sitter::Tree,
    ) -> ParsedFile {
        unimplemented!()
    }
}

fn file(path: &str) -> ProjectFile {
    let root = if cfg!(windows) {
        r"C:\workspace"
    } else {
        "/workspace"
    };
    ProjectFile::new(root, path)
}

fn unit(path: &str, name: &str) -> CodeUnit {
    CodeUnit::new(file(path), CodeUnitType::Class, "pkg", name)
}

#[test]
fn workspace_declaration_merge_is_order_independent_and_unique() {
    let alpha = unit("src/alpha.rs", "Alpha");
    let beta = unit("src/beta.rs", "Beta");
    let shadowed = unit("src/dirty.rs", "Old");
    let replacement = unit("src/dirty.rs", "New");
    let mut authoritative: HashSet<ProjectFile> = crate::hash::set_with_capacity(1);
    authoritative.insert(file("src/dirty.rs"));

    let merge = |persisted: Vec<CodeUnit>, overlay: Vec<CodeUnit>| {
        TreeSitterAnalyzer::<TestAdapter>::merge_workspace_declaration_rows(
            persisted.into_iter().map(|unit| (unit, ())).collect(),
            &authoritative,
            overlay.into_iter().map(|unit| (unit, ())),
        )
        .into_iter()
        .map(|(unit, ())| unit)
        .collect::<Vec<_>>()
    };

    let expected = vec![alpha.clone(), beta.clone(), replacement.clone()];
    assert_eq!(
        merge(
            vec![beta.clone(), shadowed, alpha.clone()],
            vec![replacement.clone()]
        ),
        expected
    );
    assert_eq!(
        merge(
            vec![alpha.clone(), beta.clone()],
            vec![replacement.clone(), beta.clone()]
        ),
        expected
    );
    assert_eq!(
        merge(vec![beta.clone(), alpha.clone()], vec![beta, replacement]),
        expected
    );
}
