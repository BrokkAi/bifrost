use brokk_bifrost_analysis::code_quality::{UnusedImportCertainty, unused_imports_for_file};
use lsp_types::{
    Diagnostic, DiagnosticSeverity, DiagnosticTag, DocumentDiagnosticParams,
    DocumentDiagnosticReport, DocumentDiagnosticReportResult, FullDocumentDiagnosticReport,
    NumberOrString, RelatedFullDocumentDiagnosticReport, Uri,
};
use tree_sitter::Parser;

use crate::analyzer::common::language_for_file;
use crate::analyzer::tree_sitter_analyzer::collect_parse_errors;
use crate::analyzer::{
    ParseError, ParseErrorKind, Project, ProjectFile, SemanticDiagnostic, WorkspaceAnalyzer,
};
use crate::lsp::conversion::byte_range_to_lsp_range;
use crate::lsp::handlers::util::project_file_for_uri;
use crate::text_utils::compute_line_starts;

const DIAGNOSTIC_SOURCE: &str = "bifrost-tree-sitter";
/// The `source` and `code` an unused-import hint carries. Both are stable
/// wire values: a client filters or suppresses on them.
const UNUSED_IMPORT_SOURCE: &str = "bifrost-unused-imports";
const UNUSED_IMPORT_CODE: &str = "unused-import";

/// Pull-model diagnostic provider. Surfaces tree-sitter `ERROR` / `MISSING`
/// nodes as LSP Diagnostics. Tries the analyzer's cached parse-error list
/// first (populated during `analyze_file`); falls back to a fresh parse only
/// when the analyzer has no fresh parse-error state for the file — e.g. when
/// the file was hydrated from the blob store this session and not yet
/// re-parsed, or when the file's language isn't loaded into the workspace.
pub fn handle(
    workspace: &WorkspaceAnalyzer,
    project: &dyn Project,
    params: &DocumentDiagnosticParams,
    include_semantic_diagnostics: bool,
) -> DocumentDiagnosticReportResult {
    let items = collect(
        workspace,
        project,
        &params.text_document.uri,
        include_semantic_diagnostics,
    );
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
/// surface the same configuration-gated diagnostics. Returns an empty vec for
/// unsupported languages, missing files, or URIs outside the project root.
pub fn collect(
    workspace: &WorkspaceAnalyzer,
    project: &dyn Project,
    uri: &Uri,
    include_semantic_diagnostics: bool,
) -> Vec<Diagnostic> {
    build_report(workspace, project, uri, include_semantic_diagnostics).unwrap_or_default()
}

fn build_report(
    workspace: &WorkspaceAnalyzer,
    project: &dyn Project,
    uri: &Uri,
    include_semantic_diagnostics: bool,
) -> Option<Vec<Diagnostic>> {
    let project_file = project_file_for_uri(project, uri)?;
    let language = language_for_file(&project_file);
    let ts_language = crate::analyzer::parser_language_for(language)?;

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

    let mut diagnostics: Vec<_> = errors
        .into_iter()
        .map(|err| parse_error_to_diagnostic(err, &content, &line_starts))
        .collect();
    if diagnostics.is_empty() {
        // Both of these read the file's derived facts, which describe a
        // syntax tree the file does not currently have while it holds a parse
        // error. A file that parses is the precondition for either.
        if include_semantic_diagnostics {
            diagnostics.extend(
                workspace
                    .analyzer()
                    .semantic_diagnostics(&project_file, &content)
                    .into_iter()
                    .map(|diagnostic| {
                        semantic_diagnostic_to_lsp(diagnostic, &content, &line_starts)
                    }),
            );
        }
        diagnostics.extend(unused_import_diagnostics(
            workspace,
            &project_file,
            &content,
            &line_starts,
        ));
    }
    Some(diagnostics)
}

/// The file's provably unreferenced imports, as `Unnecessary`-tagged hints.
///
/// Only [`UnusedImportCertainty::Unreferenced`] findings are published. A
/// finding whose certainty names an ambient use the derivation could not rule
/// out (a JSX file, whose factory name is a build setting) is evidence for a
/// consumer that reads certainty, not a claim to grey out a line in an editor.
///
/// `DiagnosticTag::Unnecessary` is the LSP's own tag for exactly this: a
/// client renders the tagged range faded instead of underlining it, which is
/// why the severity is `HINT` rather than `WARNING`. A wrong hint costs a user
/// a greyed-out line; a wrong warning costs them a problem-list entry.
fn unused_import_diagnostics(
    workspace: &WorkspaceAnalyzer,
    project_file: &ProjectFile,
    content: &str,
    line_starts: &[usize],
) -> Vec<Diagnostic> {
    unused_imports_for_file(workspace.analyzer(), project_file)
        .findings
        .into_iter()
        .filter(|finding| finding.certainty == UnusedImportCertainty::Unreferenced)
        .map(|finding| Diagnostic {
            range: byte_range_to_lsp_range(content, line_starts, &finding.range),
            severity: Some(DiagnosticSeverity::HINT),
            code: Some(NumberOrString::String(UNUSED_IMPORT_CODE.to_string())),
            code_description: None,
            source: Some(UNUSED_IMPORT_SOURCE.to_string()),
            message: format!("unused import `{}`", finding.local_name),
            related_information: None,
            tags: Some(vec![DiagnosticTag::UNNECESSARY]),
            data: None,
        })
        .collect()
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

fn semantic_diagnostic_to_lsp(
    diagnostic: SemanticDiagnostic,
    content: &str,
    line_starts: &[usize],
) -> Diagnostic {
    Diagnostic {
        range: byte_range_to_lsp_range(content, line_starts, &diagnostic.range),
        severity: Some(DiagnosticSeverity::ERROR),
        code: Some(NumberOrString::String(diagnostic.kind.to_string())),
        code_description: None,
        source: Some(diagnostic.source.to_string()),
        message: diagnostic.message,
        related_information: None,
        tags: None,
        data: None,
    }
}
