use super::declarations::{
    PythonVisitor, collect_python_identifiers, module_code_unit,
    python_is_decorated_function_boundary, python_module_name,
};
use super::syntax::PythonOverloadDecoratorBindings;
use super::tests::python_source_contains_tests;
use super::*;
use crate::analyzer::cognitive_complexity;
use crate::analyzer::{LanguageAdapter, Range};
use crate::text_utils::compute_line_starts;
use std::sync::LazyLock;
use tree_sitter::Tree;
/// Tree-sitter node-kind mapping used by the cognitive-complexity scorer
/// for Python. Mirrors `ai.brokk.analyzer.python.CognitiveComplexityAnalysis`.
static PYTHON_COGNITIVE_CONFIG: LazyLock<cognitive_complexity::Config> =
    LazyLock::new(|| cognitive_complexity::Config {
        if_types: &["if_statement"],
        alternate_if_types: &["elif_clause"],
        loop_types: &["for_statement", "while_statement"],
        catch_types: &["except_clause"],
        conditional_types: &["conditional_expression"],
        case_types: &["case_clause"],
        binary_types: &["boolean_operator"],
        logical_operators: &["and", "or"],
        named_function_boundary_types: &["function_definition"],
        anonymous_function_types: &["lambda"],
        named_function_boundary_predicate: Some(python_is_decorated_function_boundary),
        ..cognitive_complexity::Config::empty()
    });

#[derive(Debug, Clone, Default)]
pub struct PythonAdapter;

impl LanguageAdapter for PythonAdapter {
    fn language(&self) -> Language {
        Language::Python
    }

    fn query_directory(&self) -> &'static str {
        "resources/treesitter/python"
    }

    fn file_extension(&self) -> &'static str {
        "py"
    }

    fn storage_content_qualifier(&self, _code_unit: &CodeUnit, _content_qualifier: &str) -> String {
        String::new()
    }

    fn persisted_content_qualifier_supports_substring_search(&self) -> bool {
        false
    }

    fn storage_file_content_qualifier(&self, _package_name: &str) -> String {
        String::new()
    }

    fn hydrate_content_qualifier(&self, _content_qualifier: &str, file: &ProjectFile) -> String {
        python_module_name(file)
    }

    fn should_persist_code_unit(&self, code_unit: &CodeUnit) -> bool {
        !code_unit.is_file_scope() && !code_unit.is_module()
    }

    fn synthesize_hydrated_units(
        &self,
        file: &ProjectFile,
        source: &str,
        state: &mut crate::analyzer::tree_sitter_analyzer::FileState,
    ) {
        let module_fq = python_module_name(file);
        let Some(module) = module_code_unit(file, &module_fq) else {
            return;
        };
        state.top_level_declarations.insert(0, module.clone());
        state.declarations.insert(module.clone());
        state.ranges.entry(module.clone()).or_default().push(Range {
            start_byte: 0,
            end_byte: source.len(),
            start_line: 1,
            end_line: compute_line_starts(source).len(),
        });
        let module_children: Vec<_> = state
            .top_level_declarations
            .iter()
            .filter(|unit| !unit.is_module() && !unit.is_file_scope())
            .filter(|unit| !unit.short_name().contains(['.', '$']))
            .cloned()
            .collect();
        if !module_children.is_empty() {
            state.children.insert(module, module_children);
        }
    }

    fn path_synthetic_module_unit(&self, file: &ProjectFile) -> Option<CodeUnit> {
        module_code_unit(file, &python_module_name(file))
    }

    fn has_path_synthetic_module_units(&self) -> bool {
        true
    }

    fn contains_tests(
        &self,
        _file: &ProjectFile,
        source: &str,
        _tree: &Tree,
        _parsed: &crate::analyzer::tree_sitter_analyzer::ParsedFile,
    ) -> bool {
        python_source_contains_tests(source)
    }

    fn extract_call_receiver(&self, reference: &str) -> Option<String> {
        let trimmed = reference.trim();
        let before_args = trimmed
            .split_once('(')
            .map(|(head, _)| head)
            .unwrap_or(trimmed);
        before_args
            .rsplit_once('.')
            .map(|(receiver, _)| receiver.to_string())
    }

    fn parse_file(
        &self,
        file: &ProjectFile,
        source: &str,
        tree: &Tree,
    ) -> crate::analyzer::tree_sitter_analyzer::ParsedFile {
        let module_fq = python_module_name(file);
        let mut parsed = crate::analyzer::tree_sitter_analyzer::ParsedFile::new(module_fq.clone());
        let root = tree.root_node();

        collect_python_identifiers(root, source, &mut parsed.type_identifiers);

        let module_code_unit = module_code_unit(file, &module_fq);
        if let Some(module) = module_code_unit.clone() {
            parsed.add_code_unit(module, root, source, None, None);
        }

        let overload_decorators = PythonOverloadDecoratorBindings::collect(root, source);
        let mut visitor = PythonVisitor {
            file,
            source,
            package_name: &module_fq,
            parsed: &mut parsed,
            module: module_code_unit,
            overload_decorators: &overload_decorators,
        };
        visitor.visit_container(root, &[], 0);

        parsed
    }

    fn cognitive_complexity_config(&self) -> Option<&'static cognitive_complexity::Config> {
        Some(&PYTHON_COGNITIVE_CONFIG)
    }
}
