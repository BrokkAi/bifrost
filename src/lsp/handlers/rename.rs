use std::collections::HashMap;
use std::ffi::OsStr;
use std::path::PathBuf;
use std::sync::Arc;

use lsp_types::{
    PrepareRenameResponse, RenameParams, TextDocumentPositionParams, TextEdit, Uri, WorkspaceEdit,
};

use crate::analyzer::common::{is_valid_rename_identifier, language_for_file};
use crate::analyzer::usages::get_definition::{
    DefinitionLookupRequest, DefinitionLookupStatus, resolve_definition_batch_with_source,
};
use crate::analyzer::usages::{DEFAULT_MAX_FILES, DEFAULT_MAX_USAGES, FuzzyResult, UsageFinder};
use crate::analyzer::{
    CodeUnit, CodeUnitType, IAnalyzer, Language, Project, ProjectFile, Range as ByteRange,
    WorkspaceAnalyzer,
};
use crate::lsp::conversion::{
    byte_range_to_lsp_range, path_to_uri_string, position_to_byte_offset,
};
use crate::lsp::handlers::util::{
    identifier_selection_range, identifier_span_at_offset, read_document_for_uri,
};
use crate::text_utils::compute_line_starts;

const RENAME_CONFIDENCE_THRESHOLD: f64 = 1.0;

pub fn prepare(
    workspace: &WorkspaceAnalyzer,
    project: &dyn Project,
    params: &TextDocumentPositionParams,
) -> Option<PrepareRenameResponse> {
    let (_, content, line_starts) = read_document_for_uri(project, &params.text_document.uri)?;
    let byte_offset = position_to_byte_offset(&content, &line_starts, &params.position);
    let (start, end) = identifier_span_at_offset(&content, byte_offset)?;
    let identifier = content.get(start..end)?;

    let analyzer = workspace.analyzer();
    let target = resolve_rename_target(
        analyzer,
        project,
        RenameCursor {
            uri: &params.text_document.uri,
            content: &content,
            line_starts: &line_starts,
            start,
            end,
            identifier,
        },
    )?;
    if !can_rename_target(&target) {
        return None;
    }

    Some(PrepareRenameResponse::RangeWithPlaceholder {
        range: byte_range_to_lsp_range(
            &content,
            &line_starts,
            &ByteRange {
                start_byte: start,
                end_byte: end,
                start_line: 0,
                end_line: 0,
            },
        ),
        placeholder: identifier.to_string(),
    })
}

pub fn handle(
    workspace: &WorkspaceAnalyzer,
    project: &dyn Project,
    params: &RenameParams,
) -> Option<WorkspaceEdit> {
    let uri = &params.text_document_position.text_document.uri;
    let (_, content, line_starts) = read_document_for_uri(project, uri)?;
    let byte_offset = position_to_byte_offset(
        &content,
        &line_starts,
        &params.text_document_position.position,
    );
    let (start, end) = identifier_span_at_offset(&content, byte_offset)?;
    let old_name = content.get(start..end)?;

    let analyzer = workspace.analyzer();
    let target = resolve_rename_target(
        analyzer,
        project,
        RenameCursor {
            uri,
            content: &content,
            line_starts: &line_starts,
            start,
            end,
            identifier: old_name,
        },
    )?;
    if !can_rename_target(&target) {
        return None;
    }
    if !can_rename_to(&target, &params.new_name) {
        return None;
    }

    let query = UsageFinder::new().query(
        analyzer,
        std::slice::from_ref(&target),
        DEFAULT_MAX_FILES,
        DEFAULT_MAX_USAGES,
    );
    if query.candidate_files_truncated {
        return None;
    }
    let hits = match query.result {
        FuzzyResult::Success { hits_by_overload } => hits_by_overload
            .into_values()
            .flat_map(|hits| hits.into_iter())
            .collect::<Vec<_>>(),
        FuzzyResult::Ambiguous { .. }
        | FuzzyResult::Failure { .. }
        | FuzzyResult::TooManyCallsites { .. } => return None,
    };
    if hits
        .iter()
        .any(|hit| hit.confidence < RENAME_CONFIDENCE_THRESHOLD)
    {
        return None;
    }

    let mut cache = FileContentCache::default();
    let mut edits_by_file: HashMap<ProjectFile, Vec<EditCandidate>> = HashMap::new();

    for hit in hits {
        let edit = edit_for_byte_range(
            project,
            &mut cache,
            &hit.file,
            hit.start_offset,
            hit.end_offset,
            old_name,
            &params.new_name,
        )?;
        edits_by_file.entry(hit.file).or_default().push(edit);
    }

    {
        let edit = declaration_edit(
            analyzer,
            project,
            &mut cache,
            &target,
            old_name,
            &params.new_name,
        )?;
        edits_by_file
            .entry(target.source().clone())
            .or_default()
            .push(edit);
    }

    let mut changes = Vec::new();
    for (file, edits) in edits_by_file {
        let edits = prepare_file_edits(edits)?;
        if edits.is_empty() {
            continue;
        }
        let uri: Uri = path_to_uri_string(&file.abs_path()).parse().ok()?;
        changes.push((uri, edits.into_iter().map(|edit| edit.text_edit).collect()));
    }
    Some(workspace_edit_from_changes(changes))
}

fn resolve_rename_target(
    analyzer: &dyn IAnalyzer,
    project: &dyn Project,
    cursor: RenameCursor<'_>,
) -> Option<CodeUnit> {
    let (file, _, _) = read_document_for_uri(project, cursor.uri)?;
    if let Some(target) = declaration_target_at_span(analyzer, &file, &cursor) {
        return Some(target);
    }

    let mut outcomes = resolve_definition_batch_with_source(
        analyzer,
        vec![DefinitionLookupRequest {
            file: file.clone(),
            line: None,
            column: None,
            start_byte: Some(cursor.start),
            end_byte: Some(cursor.end),
        }],
        file,
        Arc::new(cursor.content.to_string()),
    );
    let outcome = outcomes.pop()?;
    if outcome.status != DefinitionLookupStatus::Resolved || outcome.definitions.len() != 1 {
        return None;
    }
    let target = outcome.definitions.into_iter().next()?;
    (target.identifier() == cursor.identifier).then_some(target)
}

fn declaration_target_at_span(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    cursor: &RenameCursor<'_>,
) -> Option<CodeUnit> {
    let mut matches = analyzer
        .get_declarations(file)
        .into_iter()
        .filter(|code_unit| code_unit.identifier() == cursor.identifier)
        .filter(|code_unit| {
            analyzer.ranges(code_unit).iter().any(|range| {
                identifier_selection_range(code_unit, cursor.content, cursor.line_starts, range)
                    .map(|selection| {
                        let selection_start = position_to_byte_offset(
                            cursor.content,
                            cursor.line_starts,
                            &selection.start,
                        );
                        let selection_end = position_to_byte_offset(
                            cursor.content,
                            cursor.line_starts,
                            &selection.end,
                        );
                        selection_start == cursor.start && selection_end == cursor.end
                    })
                    .unwrap_or(false)
            })
        })
        .collect::<Vec<_>>();
    if matches.len() == 1 {
        matches.pop()
    } else {
        None
    }
}

struct RenameCursor<'a> {
    uri: &'a Uri,
    content: &'a str,
    line_starts: &'a [usize],
    start: usize,
    end: usize,
    identifier: &'a str,
}

fn can_rename_target(target: &CodeUnit) -> bool {
    !is_file_coupled_java_class(target)
}

fn is_file_coupled_java_class(target: &CodeUnit) -> bool {
    language_for_file(target.source()) == Language::Java
        && target.kind() == CodeUnitType::Class
        && target
            .source()
            .rel_path()
            .file_stem()
            .and_then(OsStr::to_str)
            .is_some_and(|stem| stem == target.identifier())
}

fn declaration_edit(
    analyzer: &dyn IAnalyzer,
    project: &dyn Project,
    cache: &mut FileContentCache,
    code_unit: &CodeUnit,
    old_name: &str,
    new_name: &str,
) -> Option<EditCandidate> {
    let file = code_unit.source();
    let entry = cache.ensure(project, file)?;
    let range = analyzer.ranges(code_unit).iter().min().copied()?;
    let selection = identifier_selection_range(code_unit, &entry.body, &entry.line_starts, &range)?;
    let start = position_to_byte_offset(&entry.body, &entry.line_starts, &selection.start);
    let end = position_to_byte_offset(&entry.body, &entry.line_starts, &selection.end);
    edit_for_byte_range(project, cache, file, start, end, old_name, new_name)
}

fn edit_for_byte_range(
    project: &dyn Project,
    cache: &mut FileContentCache,
    file: &ProjectFile,
    start_byte: usize,
    end_byte: usize,
    old_name: &str,
    new_name: &str,
) -> Option<EditCandidate> {
    let entry = cache.ensure(project, file)?;
    if entry.body.get(start_byte..end_byte)? != old_name {
        return None;
    }
    let range = byte_range_to_lsp_range(
        &entry.body,
        &entry.line_starts,
        &ByteRange {
            start_byte,
            end_byte,
            start_line: 0,
            end_line: 0,
        },
    );
    Some(EditCandidate {
        abs_path: file.abs_path(),
        start_byte,
        end_byte,
        text_edit: TextEdit::new(range, new_name.to_string()),
    })
}

fn prepare_file_edits(mut edits: Vec<EditCandidate>) -> Option<Vec<EditCandidate>> {
    edits.sort_by(|a, b| {
        a.start_byte
            .cmp(&b.start_byte)
            .then_with(|| a.end_byte.cmp(&b.end_byte))
            .then_with(|| a.abs_path.cmp(&b.abs_path))
    });
    edits.dedup_by(|a, b| a.start_byte == b.start_byte && a.end_byte == b.end_byte);
    for pair in edits.windows(2) {
        if pair[1].start_byte < pair[0].end_byte {
            return None;
        }
    }
    Some(edits)
}

fn can_rename_to(target: &CodeUnit, name: &str) -> bool {
    is_valid_rename_identifier(language_for_file(target.source()), name)
}

#[allow(clippy::mutable_key_type)]
fn workspace_edit_from_changes(changes: Vec<(Uri, Vec<TextEdit>)>) -> WorkspaceEdit {
    WorkspaceEdit::new(changes.into_iter().collect())
}

#[derive(Default)]
struct FileContentCache {
    by_path: HashMap<PathBuf, FileContent>,
}

impl FileContentCache {
    fn ensure(&mut self, project: &dyn Project, file: &ProjectFile) -> Option<&FileContent> {
        let abs_path = file.abs_path();
        if !self.by_path.contains_key(&abs_path) {
            let body = project.read_source(file).ok()?;
            let line_starts = compute_line_starts(&body);
            self.by_path
                .insert(abs_path.clone(), FileContent { body, line_starts });
        }
        self.by_path.get(&abs_path)
    }
}

struct FileContent {
    body: String,
    line_starts: Vec<usize>,
}

struct EditCandidate {
    abs_path: PathBuf,
    start_byte: usize,
    end_byte: usize,
    text_edit: TextEdit,
}

#[cfg(test)]
mod tests {
    use super::*;
    use lsp_types::{Position, Range as LspRange};

    fn edit(start: u32, end: u32) -> EditCandidate {
        EditCandidate {
            abs_path: std::path::Path::new("/tmp/Test.java").to_path_buf(),
            start_byte: start as usize,
            end_byte: end as usize,
            text_edit: TextEdit::new(
                LspRange {
                    start: Position {
                        line: 0,
                        character: start,
                    },
                    end: Position {
                        line: 0,
                        character: end,
                    },
                },
                "Renamed".to_string(),
            ),
        }
    }

    #[test]
    fn prepare_file_edits_dedups_exact_matches() {
        let edits = prepare_file_edits(vec![edit(2, 3), edit(2, 3)]).expect("safe edits");
        assert_eq!(edits.len(), 1);
    }

    #[test]
    fn prepare_file_edits_rejects_overlaps() {
        assert!(prepare_file_edits(vec![edit(2, 5), edit(4, 6)]).is_none());
    }
}
