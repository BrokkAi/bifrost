use std::path::Path;

use lsp_types::{Hover, HoverContents, HoverParams, MarkupContent, MarkupKind};

use crate::analyzer::{
    CodeUnit, IAnalyzer, Language, Project, Range as ByteRange, WorkspaceAnalyzer,
};
use crate::lsp::conversion::{byte_range_to_lsp_range, position_to_byte_offset};
use crate::lsp::handlers::util::{
    extract_leading_doc_comment, identifier_span_at_offset, read_document_for_uri,
    resolve_first_identifier_candidate,
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
    let (_, content, line_starts) = read_document_for_uri(project, uri)?;
    let byte_offset = position_to_byte_offset(
        &content,
        &line_starts,
        &params.text_document_position_params.position,
    );
    let (start_byte, end_byte) = identifier_span_at_offset(&content, byte_offset)?;
    let identifier = &content[start_byte..end_byte];

    let analyzer = workspace.analyzer();
    let candidate = pick_candidate(analyzer, identifier)?;
    let skeleton = analyzer
        .get_skeleton_header(&candidate)
        .or_else(|| analyzer.get_skeleton(&candidate))?;
    let language_tag = language_for_path(candidate.source().rel_path());

    let highlight_range = byte_range_to_lsp_range(
        &content,
        &line_starts,
        &ByteRange {
            start_byte,
            end_byte,
            start_line: 0,
            end_line: 0,
        },
    );

    let mut value = format!("```{language_tag}\n{}\n```", skeleton.trim_end());
    if let Some(doc) = leading_doc_comment(analyzer, &candidate) {
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

/// Read the candidate's source file and lift any contiguous block of
/// comment-like lines that immediately precedes the declaration. Returns
/// `None` if the file can't be read, the candidate has no recorded range, or
/// no doc comment is present.
fn leading_doc_comment(analyzer: &dyn IAnalyzer, candidate: &CodeUnit) -> Option<String> {
    let decl_range = analyzer.ranges(candidate).iter().min().copied()?;
    let source = candidate.source().read_to_string().ok()?;
    extract_leading_doc_comment(&source, decl_range.start_byte)
}

fn pick_candidate(analyzer: &dyn IAnalyzer, identifier: &str) -> Option<CodeUnit> {
    resolve_first_identifier_candidate(analyzer, identifier)
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
