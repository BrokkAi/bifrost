use crate::analyzer::{CodeUnit, ProjectFile};
use tree_sitter::Node;

pub(crate) fn node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    crate::analyzer::common::node_source_text(node, source)
}

pub(crate) fn module_code_unit(file: &ProjectFile) -> CodeUnit {
    CodeUnit::new(
        file.clone(),
        crate::analyzer::CodeUnitType::Module,
        "",
        file.rel_path()
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("module"),
    )
}

pub(crate) fn trim_statement(text: &str) -> String {
    text.trim().trim_end_matches(';').trim().to_string()
}
