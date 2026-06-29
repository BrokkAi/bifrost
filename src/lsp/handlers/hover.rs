use std::path::Path;

use lsp_types::{Hover, HoverContents, HoverParams, MarkupContent, MarkupKind};

use crate::analyzer::{Language, Project, Range as ByteRange, WorkspaceAnalyzer};
use crate::lsp::conversion::byte_range_to_lsp_range;
use crate::lsp::handlers::util::{
    broad_symbol_target_at_position, leading_doc_comment_for_code_unit,
};

/// Resolve `textDocument/hover` for the symbol under the cursor. Returns the
/// analyzer's skeleton header (signature plus enclosing context) wrapped in a
/// fenced code block; `None` if the cursor isn't on a known symbol.
pub fn handle(
    workspace: &WorkspaceAnalyzer,
    project: &dyn Project,
    params: &HoverParams,
) -> Option<Hover> {
    let uri = &params.text_document_position_params.text_document.uri;
    let analyzer = workspace.analyzer();
    let target = broad_symbol_target_at_position(
        analyzer,
        project,
        uri,
        &params.text_document_position_params.position,
    )?;
    let candidate = target.candidates.into_iter().next()?;
    let skeleton = analyzer
        .get_skeleton_header(&candidate)
        .or_else(|| analyzer.get_skeleton(&candidate))?;
    let language_tag = language_for_path(candidate.source().rel_path());

    let highlight_range = byte_range_to_lsp_range(
        &target.content,
        &target.line_starts,
        &ByteRange {
            start_byte: target.start_byte,
            end_byte: target.end_byte,
            start_line: 0,
            end_line: 0,
        },
    );

    let mut value = format!("```{language_tag}\n{}\n```", skeleton.trim_end());
    if let Some(doc) = leading_doc_comment_for_code_unit(analyzer, &candidate) {
        value.push_str("\n\n---\n\n");
        value.push_str(&doc);
    }

    Some(Hover {
        contents: HoverContents::Markup(MarkupContent {
            kind: MarkupKind::Markdown,
            value,
        }),
        range: Some(highlight_range),
    })
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
        Language::Ruby => "ruby",
        Language::None => "",
    }
}
