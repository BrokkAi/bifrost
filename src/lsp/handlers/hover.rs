use std::path::Path;

use lsp_types::{Hover, HoverContents, HoverParams, MarkupContent, MarkupKind};

use crate::analyzer::{CodeUnit, IAnalyzer, Language, WorkspaceAnalyzer};
use crate::lsp::conversion::position_to_byte_offset;
use crate::lsp::handlers::util::{identifier_at_offset, project_file_for_uri};
use crate::text_utils::compute_line_starts;

/// Resolve `textDocument/hover` for the symbol under the cursor. Returns the
/// analyzer's skeleton header (signature plus enclosing context) wrapped in a
/// fenced code block; `None` if the cursor isn't on a known symbol.
pub fn handle(
    workspace: &WorkspaceAnalyzer,
    project_root: &Path,
    params: &HoverParams,
) -> Option<Hover> {
    let uri = &params.text_document_position_params.text_document.uri;
    let project_file = project_file_for_uri(project_root, uri)?;

    let content = project_file.read_to_string().ok()?;
    let line_starts = compute_line_starts(&content);
    let byte_offset = position_to_byte_offset(
        &content,
        &line_starts,
        &params.text_document_position_params.position,
    );
    let identifier = identifier_at_offset(&content, byte_offset)?;

    let analyzer = workspace.analyzer();
    let candidate = pick_candidate(analyzer, identifier)?;
    let skeleton = analyzer
        .get_skeleton_header(&candidate)
        .or_else(|| analyzer.get_skeleton(&candidate))?;
    let language_tag = language_for_path(candidate.source().rel_path());

    let value = format!("```{language_tag}\n{}\n```", skeleton.trim_end());
    Some(Hover {
        contents: HoverContents::Markup(MarkupContent {
            kind: MarkupKind::Markdown,
            value,
        }),
        range: None,
    })
}

fn pick_candidate(analyzer: &dyn IAnalyzer, identifier: &str) -> Option<CodeUnit> {
    let direct: Vec<CodeUnit> = analyzer.get_definitions(identifier);
    if let Some(first) = direct.into_iter().next() {
        return Some(first);
    }
    let pattern = format!(r"^{}$", regex::escape(identifier));
    analyzer
        .search_definitions(&pattern, false)
        .into_iter()
        .find(|cu| cu.identifier() == identifier)
}

fn language_for_path(rel_path: &Path) -> &'static str {
    let extension = rel_path
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or("");
    match Language::from_extension(extension) {
        Language::Java => "java",
        Language::Go => "go",
        Language::Cpp => "cpp",
        Language::JavaScript => "javascript",
        Language::TypeScript => "typescript",
        Language::Python => "python",
        Language::Rust => "rust",
        Language::Php => "php",
        Language::Scala => "scala",
        Language::CSharp => "csharp",
        Language::None => "",
    }
}
