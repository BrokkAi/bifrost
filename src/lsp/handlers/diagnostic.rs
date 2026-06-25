use lsp_types::{
    Diagnostic, DiagnosticSeverity, DocumentDiagnosticParams, DocumentDiagnosticReport,
    DocumentDiagnosticReportResult, FullDocumentDiagnosticReport,
    RelatedFullDocumentDiagnosticReport, Uri,
};
use tree_sitter::{Language as TsLanguage, Parser};

use crate::analyzer::common::language_for_file;
use crate::analyzer::tree_sitter_analyzer::collect_parse_errors;
use crate::analyzer::{Language, ParseError, ParseErrorKind, Project, WorkspaceAnalyzer};
use crate::lsp::conversion::byte_range_to_lsp_range;
use crate::lsp::handlers::util::project_file_for_uri;
use crate::text_utils::compute_line_starts;

const DIAGNOSTIC_SOURCE: &str = "bifrost-tree-sitter";

/// Pull-model diagnostic provider. Surfaces tree-sitter `ERROR` / `MISSING`
/// nodes as LSP Diagnostics. Tries the analyzer's cached parse-error list
/// first (populated during `analyze_file`); falls back to a fresh parse only
/// when the analyzer has no state for the file — e.g. when `FileState` was
/// hydrated from the persisted baseline this session and not yet re-parsed,
/// or when the file's language isn't loaded into the workspace.
pub fn handle(
    workspace: &WorkspaceAnalyzer,
    project: &dyn Project,
    params: &DocumentDiagnosticParams,
) -> DocumentDiagnosticReportResult {
    let items = collect(workspace, project, &params.text_document.uri);
    DocumentDiagnosticReportResult::Report(DocumentDiagnosticReport::Full(
        RelatedFullDocumentDiagnosticReport {
            related_documents: None,
            full_document_diagnostic_report: FullDocumentDiagnosticReport {
                result_id: None,
                items,
            },
        },
    ))
}

/// Build the diagnostic items for a document URI. Shared between the pull-model
/// `handle` and the push-model `publishDiagnostics` emitter so both paths
/// surface the same parse errors. Returns an empty vec for unsupported
/// languages, missing files, or URIs outside the project root.
pub fn collect(workspace: &WorkspaceAnalyzer, project: &dyn Project, uri: &Uri) -> Vec<Diagnostic> {
    build_report(workspace, project, uri).unwrap_or_default()
}

fn build_report(
    workspace: &WorkspaceAnalyzer,
    project: &dyn Project,
    uri: &Uri,
) -> Option<Vec<Diagnostic>> {
    let project_file = project_file_for_uri(project, uri)?;
    let language = language_for_file(&project_file);
    let ts_language = ts_language_for(language)?;

    // The cached byte offsets and `content` come from independent reads, but
    // they describe the same snapshot: `server.rs` always calls
    // `workspace.update(&{file})` immediately before `publish_diagnostics`,
    // and LSP request handling is single-threaded, so no concurrent edit can
    // race between the two reads.
    let content = project.read_source(&project_file).ok()?;
    let line_starts = compute_line_starts(&content);

    let errors: Vec<ParseError> = match workspace.analyzer().parse_errors(&project_file) {
        Some(cached) => cached,
        None => {
            // Analyzer has no cached errors for this file (hydrated baseline,
            // or file outside the loaded language set). Parse fresh and walk
            // for errors using the SAME helper the analyzer uses, so the two
            // paths can't drift on recursion / clamp semantics.
            let mut parser = Parser::new();
            parser.set_language(&ts_language).ok()?;
            let tree = parser.parse(&content, None)?;
            let mut errors = Vec::new();
            collect_parse_errors(tree.root_node(), &mut errors);
            errors
        }
    };

    Some(
        errors
            .into_iter()
            .map(|err| parse_error_to_diagnostic(err, &content, &line_starts))
            .collect(),
    )
}

/// Render a cached [`ParseError`] into the LSP `Diagnostic` shape. Both the
/// cached path and the fallback path funnel through this function so the
/// message text and severity stay in lockstep — see the contract on
/// [`crate::analyzer::IAnalyzer::parse_errors`] for the `Some` / `None`
/// semantics that decide which path is taken.
fn parse_error_to_diagnostic(
    error: ParseError,
    content: &str,
    line_starts: &[usize],
) -> Diagnostic {
    let lsp_range = byte_range_to_lsp_range(content, line_starts, &error.range);
    let message = match &error.kind {
        ParseErrorKind::Error => "syntax error".to_string(),
        ParseErrorKind::Missing(kind) => format!("missing {kind}"),
    };
    Diagnostic {
        range: lsp_range,
        severity: Some(DiagnosticSeverity::ERROR),
        code: None,
        code_description: None,
        source: Some(DIAGNOSTIC_SOURCE.to_string()),
        message,
        related_information: None,
        tags: None,
        data: None,
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
        Language::Ruby => tree_sitter_ruby::LANGUAGE.into(),
        Language::None => return None,
    })
}
