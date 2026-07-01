use std::collections::HashMap;
use std::ffi::OsStr;
use std::path::PathBuf;
use std::sync::Arc;

use crate::analyzer::common::{is_valid_rename_identifier, language_for_file};
use crate::analyzer::usages::get_definition::{
    DefinitionLookupRequest, DefinitionLookupStatus, byte_offset_for_character_column,
    resolve_definition_batch_with_source,
};
use crate::analyzer::usages::{
    DEFAULT_MAX_FILES, DEFAULT_MAX_USAGES, FuzzyResult, UsageFinder, UsageHitKind,
};
use crate::analyzer::{
    CodeUnit, CodeUnitType, IAnalyzer, Language, Project, ProjectFile, Range as ByteRange,
};
use crate::text_utils::{
    compute_line_starts, find_line_index_for_offset, find_word, identifier_span_at_offset,
};

const RENAME_CONFIDENCE_THRESHOLD: f64 = 1.0;
pub(crate) const MAX_RENAME_IDENTIFIER_BYTES: usize = 256;

#[derive(Debug, Clone, Copy)]
pub(crate) enum RenameSelection {
    ByteOffset(usize),
    ByteRange { start: usize, end: usize },
    LineColumn { line: usize, column: usize },
}

#[derive(Debug, Clone)]
pub(crate) struct RenameFailure {
    pub(crate) kind: &'static str,
    pub(crate) message: String,
}

#[derive(Debug, Clone)]
pub(crate) struct PreparedRename {
    pub(crate) start_byte: usize,
    pub(crate) end_byte: usize,
    pub(crate) placeholder: String,
}

#[derive(Debug, Clone)]
pub(crate) struct RenameEdit {
    pub(crate) start_byte: usize,
    pub(crate) end_byte: usize,
    pub(crate) new_text: String,
}

#[derive(Debug, Clone)]
pub(crate) struct RenameFileEdits {
    pub(crate) file: ProjectFile,
    pub(crate) edits: Vec<RenameEdit>,
}

#[derive(Debug, Clone)]
pub(crate) struct RenameResult {
    pub(crate) target: CodeUnit,
    pub(crate) old_name: String,
    pub(crate) files: Vec<RenameFileEdits>,
}

pub(crate) fn prepare_rename(
    analyzer: &dyn IAnalyzer,
    project: &dyn Project,
    file: ProjectFile,
    selection: RenameSelection,
) -> Result<PreparedRename, RenameFailure> {
    let source = read_source(project, &file)?;
    let line_starts = compute_line_starts(&source);
    let cursor = rename_cursor_for_selection(file, source, line_starts, selection)?;
    let target = resolve_rename_target(analyzer, cursor.as_ref())?;
    if !can_rename_target(&target) {
        return Err(RenameFailure {
            kind: "unsupported",
            message: unsupported_target_message(&target),
        });
    }

    Ok(PreparedRename {
        start_byte: cursor.start,
        end_byte: cursor.end,
        placeholder: cursor.identifier.to_string(),
    })
}

pub(crate) fn rename_symbol(
    analyzer: &dyn IAnalyzer,
    project: &dyn Project,
    file: ProjectFile,
    selection: RenameSelection,
    new_name: &str,
) -> Result<RenameResult, RenameFailure> {
    let source = read_source(project, &file)?;
    let line_starts = compute_line_starts(&source);
    let cursor = rename_cursor_for_selection(file, source, line_starts, selection)?;
    let old_name = cursor.identifier.to_string();
    let target = resolve_rename_target(analyzer, cursor.as_ref())?;
    if !can_rename_target(&target) {
        return Err(RenameFailure {
            kind: "unsupported",
            message: unsupported_target_message(&target),
        });
    }
    if !can_rename_to(&target, new_name) {
        let message = if new_name.len() > MAX_RENAME_IDENTIFIER_BYTES {
            format!(
                "replacement identifier exceeds {MAX_RENAME_IDENTIFIER_BYTES} bytes for {:?}",
                language_for_file(target.source())
            )
        } else {
            format!(
                "`{new_name}` is not a valid identifier for {:?}",
                language_for_file(target.source())
            )
        };
        return Err(RenameFailure {
            kind: "invalid_name",
            message,
        });
    }

    let query = UsageFinder::new().query(
        analyzer,
        std::slice::from_ref(&target),
        DEFAULT_MAX_FILES,
        DEFAULT_MAX_USAGES,
    );
    if query.candidate_files_truncated {
        return Err(RenameFailure {
            kind: "too_many_files",
            message: "rename candidate files exceeded the enumeration limit".to_string(),
        });
    }
    let hits = match query.result {
        FuzzyResult::Success { hits_by_overload } => hits_by_overload
            .into_values()
            .flat_map(|hits| hits.into_iter())
            .filter(|hit| hit.kind != UsageHitKind::Import)
            .collect::<Vec<_>>(),
        FuzzyResult::Ambiguous { .. } => {
            return Err(RenameFailure {
                kind: "ambiguous",
                message: "rename target resolved to ambiguous usage candidates".to_string(),
            });
        }
        FuzzyResult::Failure { .. } => {
            return Err(RenameFailure {
                kind: "not_found",
                message: "rename usages could not be resolved".to_string(),
            });
        }
        FuzzyResult::TooManyCallsites { .. } => {
            return Err(RenameFailure {
                kind: "too_many_callsites",
                message: "rename target has too many call sites to edit safely".to_string(),
            });
        }
    };
    if hits
        .iter()
        .any(|hit| hit.confidence < RENAME_CONFIDENCE_THRESHOLD)
    {
        return Err(RenameFailure {
            kind: "low_confidence",
            message: "rename would include at least one low-confidence usage".to_string(),
        });
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
            &old_name,
            new_name,
        )?;
        edits_by_file.entry(hit.file).or_default().push(edit);
    }

    let edit = declaration_edit(analyzer, project, &mut cache, &target, &old_name, new_name)?;
    edits_by_file
        .entry(target.source().clone())
        .or_default()
        .push(edit);

    let mut files = Vec::new();
    for (file, edits) in edits_by_file {
        let edits = prepare_file_edits(edits)?;
        if edits.is_empty() {
            continue;
        }
        files.push(RenameFileEdits {
            file,
            edits: edits
                .into_iter()
                .map(|edit| RenameEdit {
                    start_byte: edit.start_byte,
                    end_byte: edit.end_byte,
                    new_text: edit.new_text,
                })
                .collect(),
        });
    }
    files.sort_by(|left, right| left.file.rel_path().cmp(right.file.rel_path()));

    Ok(RenameResult {
        target,
        old_name,
        files,
    })
}

pub(crate) fn line_column_for_byte_offset(
    source: &str,
    line_starts: &[usize],
    offset: usize,
) -> (usize, usize) {
    let line_index = find_line_index_for_offset(line_starts, offset);
    let line_start = line_starts.get(line_index).copied().unwrap_or(0);
    let column = source
        .get(line_start..offset)
        .map(|slice| slice.chars().count() + 1)
        .unwrap_or(1);
    (line_index + 1, column)
}

fn read_source(project: &dyn Project, file: &ProjectFile) -> Result<String, RenameFailure> {
    project.read_source(file).map_err(|err| RenameFailure {
        kind: "read_failed",
        message: format!("failed to read `{}`: {err}", file.rel_path().display()),
    })
}

fn rename_cursor_for_selection(
    file: ProjectFile,
    content: String,
    line_starts: Vec<usize>,
    selection: RenameSelection,
) -> Result<RenameCursor, RenameFailure> {
    let byte_offset = match selection {
        RenameSelection::ByteOffset(offset) => {
            validate_byte_point(&content, offset)?;
            offset
        }
        RenameSelection::ByteRange { start, end } => {
            validate_byte_range(&content, start, end)?;
            start
        }
        RenameSelection::LineColumn { line, column } => {
            if line == 0 || line > line_starts.len() {
                return Err(RenameFailure {
                    kind: "invalid_location",
                    message: format!(
                        "line {line} is outside 1..={} for this file",
                        line_starts.len()
                    ),
                });
            }
            if column == 0 {
                return Err(RenameFailure {
                    kind: "invalid_location",
                    message: "column must be 1-based".to_string(),
                });
            }
            let line_start = line_starts[line - 1];
            let line_end = line_starts.get(line).copied().unwrap_or(content.len());
            byte_offset_for_character_column(&content, line_start, line_end, line, column).map_err(
                |message| RenameFailure {
                    kind: "invalid_location",
                    message,
                },
            )?
        }
    };
    let (start, end) =
        identifier_span_at_offset(&content, byte_offset).ok_or_else(|| RenameFailure {
            kind: "not_found",
            message: "no identifier at rename location".to_string(),
        })?;
    if let RenameSelection::ByteRange {
        start: selected_start,
        end: selected_end,
    } = selection
        && (selected_start != start || selected_end != end)
    {
        return Err(RenameFailure {
            kind: "invalid_location",
            message: "byte range must select exactly one identifier".to_string(),
        });
    }
    let identifier = content
        .get(start..end)
        .ok_or_else(|| RenameFailure {
            kind: "invalid_location",
            message: "identifier range is not valid UTF-8".to_string(),
        })?
        .to_string();

    Ok(RenameCursor {
        file,
        content,
        line_starts,
        start,
        end,
        identifier,
    })
}

fn validate_byte_point(content: &str, offset: usize) -> Result<(), RenameFailure> {
    if offset > content.len() {
        return Err(RenameFailure {
            kind: "invalid_location",
            message: format!("start_byte {offset} is outside {} byte file", content.len()),
        });
    }
    if !content.is_char_boundary(offset) {
        return Err(RenameFailure {
            kind: "invalid_location",
            message: format!("start_byte {offset} does not align to a UTF-8 character boundary"),
        });
    }
    Ok(())
}

fn validate_byte_range(content: &str, start: usize, end: usize) -> Result<(), RenameFailure> {
    validate_byte_point(content, start)?;
    if start >= end || end > content.len() {
        return Err(RenameFailure {
            kind: "invalid_location",
            message: format!(
                "invalid byte range [{start}, {end}) for {} byte file",
                content.len()
            ),
        });
    }
    if !content.is_char_boundary(end) {
        return Err(RenameFailure {
            kind: "invalid_location",
            message: format!("end_byte {end} does not align to a UTF-8 character boundary"),
        });
    }
    Ok(())
}

fn resolve_rename_target(
    analyzer: &dyn IAnalyzer,
    cursor: RenameCursorRef<'_>,
) -> Result<CodeUnit, RenameFailure> {
    if let Some(target) = declaration_target_at_span(analyzer, &cursor) {
        return Ok(target);
    }

    let mut outcomes = resolve_definition_batch_with_source(
        analyzer,
        vec![DefinitionLookupRequest {
            file: cursor.file.clone(),
            line: None,
            column: None,
            start_byte: Some(cursor.start),
            end_byte: Some(cursor.end),
        }],
        cursor.file.clone(),
        Arc::new(cursor.content.to_string()),
    );
    let Some(outcome) = outcomes.pop() else {
        return Err(RenameFailure {
            kind: "not_found",
            message: "no definition resolved at rename location".to_string(),
        });
    };
    if outcome.status != DefinitionLookupStatus::Resolved {
        return Err(RenameFailure {
            kind: "not_found",
            message: "no definition resolved at rename location".to_string(),
        });
    }
    if outcome.definitions.len() != 1 {
        return Err(RenameFailure {
            kind: "ambiguous",
            message: "rename location resolves to multiple definitions".to_string(),
        });
    }
    let target = outcome
        .definitions
        .into_iter()
        .next()
        .expect("definition count checked");
    if target.identifier() != cursor.identifier {
        return Err(RenameFailure {
            kind: "not_found",
            message: "resolved definition identifier does not match selected token".to_string(),
        });
    }
    Ok(target)
}

fn declaration_target_at_span(
    analyzer: &dyn IAnalyzer,
    cursor: &RenameCursorRef<'_>,
) -> Option<CodeUnit> {
    let mut matches = analyzer
        .get_declarations(cursor.file)
        .into_iter()
        .filter(|code_unit| code_unit.identifier() == cursor.identifier)
        .filter(|code_unit| {
            analyzer.ranges(code_unit).iter().any(|range| {
                identifier_selection_byte_range(code_unit, cursor.content, range)
                    .map(|selection| {
                        selection.start_byte == cursor.start && selection.end_byte == cursor.end
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

struct RenameCursor {
    file: ProjectFile,
    content: String,
    line_starts: Vec<usize>,
    start: usize,
    end: usize,
    identifier: String,
}

impl RenameCursor {
    fn as_ref(&self) -> RenameCursorRef<'_> {
        RenameCursorRef {
            file: &self.file,
            content: &self.content,
            line_starts: &self.line_starts,
            start: self.start,
            end: self.end,
            identifier: &self.identifier,
        }
    }
}

struct RenameCursorRef<'a> {
    file: &'a ProjectFile,
    content: &'a str,
    #[allow(dead_code)]
    line_starts: &'a [usize],
    start: usize,
    end: usize,
    identifier: &'a str,
}

fn can_rename_target(target: &CodeUnit) -> bool {
    !is_file_coupled_java_class(target)
}

fn unsupported_target_message(target: &CodeUnit) -> String {
    if is_file_coupled_java_class(target) {
        format!(
            "`{}` is a Java class coupled to its filename; file rename edits are not supported yet",
            target.fq_name()
        )
    } else {
        format!("`{}` cannot be renamed", target.fq_name())
    }
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
) -> Result<EditCandidate, RenameFailure> {
    let file = code_unit.source();
    let entry = cache.ensure(project, file)?;
    let range = analyzer
        .ranges(code_unit)
        .iter()
        .min()
        .copied()
        .ok_or_else(|| RenameFailure {
            kind: "not_found",
            message: format!("`{}` has no declaration range", code_unit.fq_name()),
        })?;
    let selection =
        identifier_selection_byte_range(code_unit, &entry.body, &range).ok_or_else(|| {
            RenameFailure {
                kind: "not_found",
                message: format!(
                    "could not find identifier `{}` inside declaration range",
                    code_unit.identifier()
                ),
            }
        })?;
    edit_for_byte_range(
        project,
        cache,
        file,
        selection.start_byte,
        selection.end_byte,
        old_name,
        new_name,
    )
}

fn edit_for_byte_range(
    project: &dyn Project,
    cache: &mut FileContentCache,
    file: &ProjectFile,
    start_byte: usize,
    end_byte: usize,
    old_name: &str,
    new_name: &str,
) -> Result<EditCandidate, RenameFailure> {
    let entry = cache.ensure(project, file)?;
    if entry.body.get(start_byte..end_byte) != Some(old_name) {
        return Err(RenameFailure {
            kind: "stale_location",
            message: format!(
                "expected `{old_name}` at `{}` bytes [{start_byte}, {end_byte})",
                file.rel_path().display()
            ),
        });
    }
    Ok(EditCandidate {
        abs_path: file.abs_path(),
        start_byte,
        end_byte,
        new_text: new_name.to_string(),
    })
}

fn identifier_selection_byte_range(
    code_unit: &CodeUnit,
    content: &str,
    fallback: &ByteRange,
) -> Option<ByteRange> {
    let slice = content.get(fallback.start_byte..fallback.end_byte)?;
    let name = code_unit.identifier();
    if name.is_empty() {
        return None;
    }
    let offset = find_word(slice, name)?;
    let abs_start = fallback.start_byte + offset;
    let abs_end = abs_start + name.len();
    Some(ByteRange {
        start_byte: abs_start,
        end_byte: abs_end,
        start_line: 0,
        end_line: 0,
    })
}

fn prepare_file_edits(mut edits: Vec<EditCandidate>) -> Result<Vec<EditCandidate>, RenameFailure> {
    edits.sort_by(|a, b| {
        a.start_byte
            .cmp(&b.start_byte)
            .then_with(|| a.end_byte.cmp(&b.end_byte))
            .then_with(|| a.abs_path.cmp(&b.abs_path))
    });
    edits.dedup_by(|a, b| a.start_byte == b.start_byte && a.end_byte == b.end_byte);
    for pair in edits.windows(2) {
        if pair[1].start_byte < pair[0].end_byte {
            return Err(RenameFailure {
                kind: "overlapping_edits",
                message: "rename produced overlapping edits".to_string(),
            });
        }
    }
    Ok(edits)
}

fn can_rename_to(target: &CodeUnit, name: &str) -> bool {
    if name.len() > MAX_RENAME_IDENTIFIER_BYTES {
        return false;
    }
    is_valid_rename_identifier(language_for_file(target.source()), name)
}

#[derive(Default)]
struct FileContentCache {
    by_path: HashMap<PathBuf, FileContent>,
}

impl FileContentCache {
    fn ensure(
        &mut self,
        project: &dyn Project,
        file: &ProjectFile,
    ) -> Result<&FileContent, RenameFailure> {
        let abs_path = file.abs_path();
        if !self.by_path.contains_key(&abs_path) {
            let body = project.read_source(file).map_err(|err| RenameFailure {
                kind: "read_failed",
                message: format!("failed to read `{}`: {err}", file.rel_path().display()),
            })?;
            let line_starts = compute_line_starts(&body);
            self.by_path
                .insert(abs_path.clone(), FileContent { body, line_starts });
        }
        self.by_path.get(&abs_path).ok_or_else(|| RenameFailure {
            kind: "read_failed",
            message: format!("failed to cache `{}`", file.rel_path().display()),
        })
    }
}

struct FileContent {
    body: String,
    #[allow(dead_code)]
    line_starts: Vec<usize>,
}

#[derive(Debug)]
struct EditCandidate {
    abs_path: PathBuf,
    start_byte: usize,
    end_byte: usize,
    new_text: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn edit(start: u32, end: u32) -> EditCandidate {
        EditCandidate {
            abs_path: std::path::Path::new("/tmp/Test.java").to_path_buf(),
            start_byte: start as usize,
            end_byte: end as usize,
            new_text: "renamed".to_string(),
        }
    }

    #[test]
    fn prepare_file_edits_sorts_and_deduplicates() {
        let edits = prepare_file_edits(vec![edit(10, 12), edit(1, 3), edit(10, 12)]).unwrap();

        assert_eq!(
            edits
                .into_iter()
                .map(|edit| (edit.start_byte, edit.end_byte))
                .collect::<Vec<_>>(),
            vec![(1, 3), (10, 12)]
        );
    }

    #[test]
    fn prepare_file_edits_rejects_overlaps() {
        let err = prepare_file_edits(vec![edit(1, 4), edit(3, 6)]).unwrap_err();

        assert_eq!(err.kind, "overlapping_edits");
    }
}
