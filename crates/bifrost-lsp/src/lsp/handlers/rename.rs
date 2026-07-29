use lsp_types::{
    PrepareRenameResponse, RenameParams, TextDocumentPositionParams, TextEdit, Uri, WorkspaceEdit,
};

use crate::analyzer::{Project, Range as ByteRange, WorkspaceAnalyzer};
use crate::lsp::conversion::{
    byte_range_to_lsp_range, path_to_uri_string, position_to_byte_offset,
};
use crate::lsp::handlers::util::read_document_for_uri;
use crate::symbol_rename::RenameSelection;

pub fn prepare(
    workspace: &WorkspaceAnalyzer,
    project: &dyn Project,
    params: &TextDocumentPositionParams,
) -> Option<PrepareRenameResponse> {
    let (file, content, line_starts) = read_document_for_uri(project, &params.text_document.uri)?;
    let byte_offset = position_to_byte_offset(&content, &line_starts, &params.position);
    let prepared = crate::symbol_rename::prepare_rename(
        workspace.analyzer(),
        project,
        file,
        RenameSelection::ByteOffset(byte_offset),
    )
    .ok()?;

    Some(PrepareRenameResponse::RangeWithPlaceholder {
        range: byte_range_to_lsp_range(
            &content,
            &line_starts,
            &ByteRange {
                start_byte: prepared.start_byte,
                end_byte: prepared.end_byte,
                start_line: 0,
                end_line: 0,
            },
        ),
        placeholder: prepared.placeholder,
    })
}

pub fn handle(
    workspace: &WorkspaceAnalyzer,
    project: &dyn Project,
    params: &RenameParams,
) -> Option<WorkspaceEdit> {
    let uri = &params.text_document_position.text_document.uri;
    let (file, content, line_starts) = read_document_for_uri(project, uri)?;
    let byte_offset = position_to_byte_offset(
        &content,
        &line_starts,
        &params.text_document_position.position,
    );
    let result = crate::symbol_rename::rename_symbol(
        workspace.analyzer(),
        project,
        file,
        RenameSelection::ByteOffset(byte_offset),
        &params.new_name,
    )
    .ok()?;

    let mut changes = Vec::new();
    for file_edits in result.files {
        let body = project.read_source(&file_edits.file).ok()?;
        let line_starts = crate::text_utils::compute_line_starts(&body);
        let uri: Uri = path_to_uri_string(&file_edits.file.abs_path())
            .parse()
            .ok()?;
        let edits = file_edits
            .edits
            .into_iter()
            .map(|edit| {
                let range = byte_range_to_lsp_range(
                    &body,
                    &line_starts,
                    &ByteRange {
                        start_byte: edit.start_byte,
                        end_byte: edit.end_byte,
                        start_line: 0,
                        end_line: 0,
                    },
                );
                TextEdit::new(range, edit.new_text)
            })
            .collect();
        changes.push((uri, edits));
    }

    Some(workspace_edit_from_changes(changes))
}

#[allow(clippy::mutable_key_type)]
fn workspace_edit_from_changes(changes: Vec<(Uri, Vec<TextEdit>)>) -> WorkspaceEdit {
    WorkspaceEdit::new(changes.into_iter().collect())
}
