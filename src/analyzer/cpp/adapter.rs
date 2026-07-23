use super::declarations::{CppVisitor, collect_cpp_identifiers, recover_quoted_includes};
use super::tests::cpp_contains_tests;
use super::*;
use crate::analyzer::LanguageAdapter;
use tree_sitter::Tree;

#[derive(Debug, Clone, Default)]
pub struct CppAdapter;

impl LanguageAdapter for CppAdapter {
    fn language(&self) -> Language {
        Language::Cpp
    }

    fn query_directory(&self) -> &'static str {
        "resources/treesitter/cpp"
    }

    fn file_extension(&self) -> &'static str {
        "cpp"
    }

    fn contains_tests(
        &self,
        _file: &ProjectFile,
        source: &str,
        _tree: &Tree,
        _parsed: &crate::analyzer::tree_sitter_analyzer::ParsedFile,
    ) -> bool {
        cpp_contains_tests(source)
    }

    fn extract_call_receiver(&self, reference: &str) -> Option<String> {
        let trimmed = reference.trim();
        let before_args = trimmed
            .split_once('(')
            .map(|(head, _)| head)
            .unwrap_or(trimmed);
        before_args
            .rsplit_once("::")
            .or_else(|| before_args.rsplit_once('.'))
            .map(|(receiver, _)| receiver.to_string())
    }

    fn parse_file(
        &self,
        file: &ProjectFile,
        source: &str,
        tree: &Tree,
    ) -> crate::analyzer::tree_sitter_analyzer::ParsedFile {
        let mut parsed = crate::analyzer::tree_sitter_analyzer::ParsedFile::new(String::new());
        let root = tree.root_node();
        collect_cpp_identifiers(root, source, &mut parsed.type_identifiers);
        let mut visitor = CppVisitor {
            file,
            source,
            parsed: &mut parsed,
            recovered_class_sibling_scopes: HashMap::default(),
            consumed_fragment_regions: Vec::new(),
        };
        visitor.visit_container(root, "", None, None, None);
        recover_quoted_includes(source, &mut parsed);
        parsed
    }
}
