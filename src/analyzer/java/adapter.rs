use super::declarations::{
    collect_type_identifiers, determine_package_name, extract_java_call_receiver,
    is_java_anonymous_structure, module_code_unit, node_text, normalize_java_full_name,
    visit_class_like,
};
use super::imports::parse_import_info;
use super::tests::java_source_contains_tests;
use super::*;
use crate::analyzer::LanguageAdapter;
use crate::analyzer::cognitive_complexity;
use std::sync::LazyLock;
use tree_sitter::{Language as TsLanguage, Node, Tree};

/// Tree-sitter node-kind mapping used by the cognitive-complexity scorer
/// for Java. Mirrors `ai.brokk.analyzer.java.CognitiveComplexityAnalysis`.
static JAVA_COGNITIVE_CONFIG: LazyLock<cognitive_complexity::Config> =
    LazyLock::new(|| cognitive_complexity::Config {
        if_types: &["if_statement"],
        loop_types: &[
            "for_statement",
            "enhanced_for_statement",
            "while_statement",
            "do_statement",
        ],
        catch_types: &["catch_clause"],
        conditional_types: &["ternary_expression"],
        case_types: &["switch_label", "switch_rule"],
        binary_types: &["binary_expression"],
        logical_operators: &["&&", "||"],
        jump_types: &["break_statement", "continue_statement"],
        anonymous_function_types: &["lambda_expression"],
        default_case_predicate: Some(java_is_default_switch_label),
        ..cognitive_complexity::Config::empty()
    });

fn java_is_default_switch_label(node: Node<'_>, source: &str) -> bool {
    let Some(text) = source.get(node.start_byte()..node.end_byte()) else {
        return false;
    };
    text.trim_start().starts_with("default")
}

#[derive(Debug, Clone, Default)]
pub struct JavaAdapter;

impl LanguageAdapter for JavaAdapter {
    fn language(&self) -> Language {
        Language::Java
    }

    fn query_directory(&self) -> &'static str {
        "resources/treesitter/java"
    }

    fn parser_language(&self) -> TsLanguage {
        tree_sitter_java::LANGUAGE.into()
    }

    fn file_extension(&self) -> &'static str {
        "java"
    }

    fn normalize_full_name(&self, fq_name: &str) -> String {
        normalize_java_full_name(fq_name)
    }

    fn is_anonymous_structure(&self, fq_name: &str) -> bool {
        is_java_anonymous_structure(fq_name)
    }

    fn extract_call_receiver(&self, reference: &str) -> Option<String> {
        extract_java_call_receiver(reference)
    }

    fn contains_tests(
        &self,
        _file: &ProjectFile,
        source: &str,
        _tree: &Tree,
        _parsed: &crate::analyzer::tree_sitter_analyzer::ParsedFile,
    ) -> bool {
        java_source_contains_tests(source)
    }

    fn parse_file(
        &self,
        file: &ProjectFile,
        source: &str,
        tree: &Tree,
    ) -> crate::analyzer::tree_sitter_analyzer::ParsedFile {
        let root = tree.root_node();
        let package_name = determine_package_name(root, source);
        let mut parsed =
            crate::analyzer::tree_sitter_analyzer::ParsedFile::new(package_name.clone());
        collect_type_identifiers(root, source, &mut parsed.type_identifiers);
        let module_code_unit =
            (!package_name.is_empty()).then(|| module_code_unit(file, &package_name));

        if let Some(module) = &module_code_unit {
            parsed.top_level_declarations.push(module.clone());
            parsed.declarations.insert(module.clone());
            parsed.add_signature(module.clone(), format!("package {};", package_name));
        }

        for index in 0..root.named_child_count() {
            let Some(child) = root.named_child(index) else {
                continue;
            };

            match child.kind() {
                "import_declaration" => {
                    let raw = node_text(child, source).trim().to_string();
                    parsed.import_statements.push(raw.clone());
                    parsed.imports.push(parse_import_info(raw));
                }
                "class_declaration"
                | "interface_declaration"
                | "enum_declaration"
                | "record_declaration"
                | "annotation_type_declaration" => {
                    let class_code_unit = visit_class_like(
                        file,
                        source,
                        child,
                        &package_name,
                        None,
                        None,
                        &mut parsed,
                    );
                    if let (Some(module), Some(class_code_unit)) =
                        (&module_code_unit, class_code_unit)
                    {
                        parsed.add_child(module.clone(), class_code_unit);
                    }
                }
                _ => {}
            }
        }

        parsed
    }

    fn cognitive_complexity_config(&self) -> Option<&'static cognitive_complexity::Config> {
        Some(&JAVA_COGNITIVE_CONFIG)
    }
}
