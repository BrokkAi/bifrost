use super::declarations::{CppVisitor, collect_cpp_identifiers, recover_quoted_includes};
use super::tests::cpp_contains_tests;
use super::*;
use crate::analyzer::LanguageAdapter;
use crate::analyzer::cognitive_complexity;
use std::sync::LazyLock;
use tree_sitter::{Node, Tree};

static CPP_COGNITIVE_CONFIG: LazyLock<cognitive_complexity::Config> =
    LazyLock::new(|| cognitive_complexity::Config {
        if_types: &["if_statement"],
        loop_types: &["for_statement", "while_statement", "do_statement"],
        catch_types: &["catch_clause"],
        conditional_types: &["conditional_expression"],
        case_types: &["case_statement"],
        binary_types: &["binary_expression"],
        logical_operators: &["&&", "||", "and", "or"],
        jump_types: &["break_statement", "continue_statement"],
        named_function_boundary_types: &["function_definition"],
        anonymous_function_types: &["lambda_expression"],
        else_clause_types: &["else_clause"],
        default_case_predicate: Some(cpp_is_default_case),
        ..cognitive_complexity::Config::empty()
    });

fn cpp_is_default_case(node: Node<'_>, _source: &str) -> bool {
    node.child_by_field_name("value").is_none()
}

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
        visitor.visit_container(root, "", None, None, None, Vec::new());
        recover_quoted_includes(source, &mut parsed);
        parsed
    }

    fn cognitive_complexity_config(&self) -> Option<&'static cognitive_complexity::Config> {
        Some(&CPP_COGNITIVE_CONFIG)
    }
}
