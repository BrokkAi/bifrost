use std::path::Path;

use lsp_types::{
    Diagnostic, DiagnosticSeverity, DocumentDiagnosticParams, DocumentDiagnosticReport,
    DocumentDiagnosticReportResult, FullDocumentDiagnosticReport,
    RelatedFullDocumentDiagnosticReport,
};
use tree_sitter::{Language as TsLanguage, Node, Parser};

use crate::analyzer::Language;
use crate::lsp::conversion::byte_range_to_lsp_range;
use crate::lsp::handlers::util::project_file_for_uri;
use crate::text_utils::compute_line_starts;

const DIAGNOSTIC_SOURCE: &str = "bifrost-tree-sitter";

/// Pull-model diagnostic provider. Reparse the file with the appropriate
/// tree-sitter grammar and surface every `ERROR` / `MISSING` node as an LSP
/// Diagnostic. Returns an empty report for unsupported languages so editors
/// don't see a stale "method not found" or stale diagnostics.
pub fn handle(
    project_root: &Path,
    params: &DocumentDiagnosticParams,
) -> DocumentDiagnosticReportResult {
    let report = match build_report(project_root, params) {
        Some(items) => FullDocumentDiagnosticReport {
            result_id: None,
            items,
        },
        None => FullDocumentDiagnosticReport {
            result_id: None,
            items: Vec::new(),
        },
    };
    DocumentDiagnosticReportResult::Report(DocumentDiagnosticReport::Full(
        RelatedFullDocumentDiagnosticReport {
            related_documents: None,
            full_document_diagnostic_report: report,
        },
    ))
}

fn build_report(project_root: &Path, params: &DocumentDiagnosticParams) -> Option<Vec<Diagnostic>> {
    let project_file = project_file_for_uri(project_root, &params.text_document.uri)?;
    let extension = project_file
        .rel_path()
        .extension()
        .and_then(|ext| ext.to_str())?;
    let language = Language::from_extension(extension);
    let ts_language = ts_language_for(language)?;

    let content = project_file.read_to_string().ok()?;
    let mut parser = Parser::new();
    parser.set_language(&ts_language).ok()?;
    let tree = parser.parse(&content, None)?;

    let line_starts = compute_line_starts(&content);
    let mut diagnostics = Vec::new();
    walk_for_errors(tree.root_node(), &content, &line_starts, &mut diagnostics);
    Some(diagnostics)
}

fn walk_for_errors(node: Node, content: &str, line_starts: &[usize], out: &mut Vec<Diagnostic>) {
    if node.is_error() || node.is_missing() {
        let byte_range = crate::analyzer::Range {
            start_byte: node.start_byte(),
            end_byte: node.end_byte().max(node.start_byte()),
            start_line: node.start_position().row,
            end_line: node.end_position().row,
        };
        let lsp_range = byte_range_to_lsp_range(content, line_starts, &byte_range);
        let message = if node.is_missing() {
            format!("missing {}", node.kind())
        } else {
            "syntax error".to_string()
        };
        out.push(Diagnostic {
            range: lsp_range,
            severity: Some(DiagnosticSeverity::ERROR),
            code: None,
            code_description: None,
            source: Some(DIAGNOSTIC_SOURCE.to_string()),
            message,
            related_information: None,
            tags: None,
            data: None,
        });
        // Don't recurse into ERROR nodes — every descendant would also be
        // marked as an error and explode the diagnostic list.
        if node.is_error() {
            return;
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_for_errors(child, content, line_starts, out);
    }
}

fn ts_language_for(language: Language) -> Option<TsLanguage> {
    Some(match language {
        Language::Java => tree_sitter_java::LANGUAGE.into(),
        Language::Go => tree_sitter_go::LANGUAGE.into(),
        Language::Cpp => tree_sitter_cpp::LANGUAGE.into(),
        Language::JavaScript => tree_sitter_javascript::LANGUAGE.into(),
        Language::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
        Language::Python => tree_sitter_python::LANGUAGE.into(),
        Language::Rust => tree_sitter_rust::LANGUAGE.into(),
        Language::Php => tree_sitter_php::LANGUAGE_PHP.into(),
        Language::Scala => tree_sitter_scala::LANGUAGE.into(),
        Language::CSharp => tree_sitter_c_sharp::LANGUAGE.into(),
        Language::None => return None,
    })
}
