use super::declarations::{
    collect_type_identifiers, determine_package_name, extract_java_call_receiver,
    is_java_anonymous_structure, module_code_unit, node_text, normalize_java_full_name,
    visit_class_like,
};
use super::imports::parse_import_info;
use super::tests::java_source_contains_tests;
use super::*;
use crate::analyzer::cognitive_complexity;
use crate::analyzer::{LanguageAdapter, SignatureMetadata};
use std::sync::LazyLock;
use tree_sitter::{Language as TsLanguage, Node, Parser, Tree};

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

    fn callable_arity(
        &self,
        _signature: &str,
        metadata: Option<&SignatureMetadata>,
    ) -> Option<usize> {
        metadata.map(|metadata| metadata.parameters().len())
    }

    fn callable_return_type_text<'a>(&self, signature: &'a str) -> Option<&'a str> {
        java_signature_return_type_text(signature)
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
        tree: &Tree,
        _parsed: &crate::analyzer::tree_sitter_analyzer::ParsedFile,
    ) -> bool {
        java_source_contains_tests(tree.root_node(), source)
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

        for index in 0..root.named_child_count() {
            let Some(child) = root.named_child(index) else {
                continue;
            };

            match child.kind() {
                "package_declaration" => {
                    if let Some(module) = &module_code_unit {
                        parsed.add_code_unit(
                            module.clone(),
                            child,
                            source,
                            None,
                            Some(module.clone()),
                        );
                        parsed.add_signature(module.clone(), format!("package {};", package_name));
                    }
                }
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

    fn structural_spec(&self) -> Option<&'static dyn crate::analyzer::structural::StructuralSpec> {
        Some(&super::structural::JAVA_STRUCTURAL_SPEC)
    }
}

fn java_signature_return_type_text(signature: &str) -> Option<&str> {
    let prefix = "class __BifrostSignature { ";
    let source = format!("{prefix}{signature}; }}");
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_java::LANGUAGE.into())
        .ok()?;
    let tree = parser.parse(source.as_str(), None)?;
    let declaration = find_signature_declaration(tree.root_node())?;
    let type_node = declaration.child_by_field_name("type")?;
    signature_slice(
        signature,
        prefix.len(),
        type_node.start_byte(),
        type_node.end_byte(),
    )
}

fn find_signature_declaration(root: Node<'_>) -> Option<Node<'_>> {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if matches!(node.kind(), "method_declaration" | "field_declaration") {
            return Some(node);
        }
        for index in (0..node.named_child_count()).rev() {
            if let Some(child) = node.named_child(index) {
                stack.push(child);
            }
        }
    }
    None
}

fn signature_slice(
    signature: &str,
    offset: usize,
    start_byte: usize,
    end_byte: usize,
) -> Option<&str> {
    let start = start_byte.checked_sub(offset)?;
    let end = end_byte.checked_sub(offset)?;
    signature.get(start..end).map(str::trim)
}
