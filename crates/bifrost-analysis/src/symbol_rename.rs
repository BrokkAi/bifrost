use std::collections::HashMap;
use std::ffi::OsStr;
use std::path::PathBuf;
use std::sync::Arc;

use crate::analyzer::common::{
    is_valid_rename_identifier, language_for_file, source_identifier_for_target,
};
use crate::analyzer::usages::get_definition::{
    DefinitionLookupOutcome, DefinitionLookupRequest, DefinitionLookupStatus,
    byte_offset_for_character_column, resolve_definition_batch_with_source,
};
use crate::analyzer::usages::{
    DEFAULT_MAX_FILES, DEFAULT_MAX_USAGES, FuzzyResult, QueryResult, UsageFinder, UsageHit,
    UsageProof, UsageQueryCompletion,
};
use crate::analyzer::{
    CodeUnit, CodeUnitType, IAnalyzer, Language, Project, ProjectFile, Range as ByteRange,
};
use crate::text_utils::{
    compute_line_starts, find_line_index_for_offset, find_word, identifier_span_at_offset,
};

const RENAME_CONFIDENCE_THRESHOLD: f64 = 1.0;
pub const MAX_RENAME_IDENTIFIER_BYTES: usize = 256;

#[derive(Debug, Clone, Copy)]
pub enum RenameSelection {
    ByteOffset(usize),
    LineColumn { line: usize, column: usize },
}

#[derive(Debug, Clone)]
pub struct RenameFailure {
    pub kind: &'static str,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct PreparedRename {
    pub start_byte: usize,
    pub end_byte: usize,
    pub placeholder: String,
}

#[derive(Debug, Clone)]
pub struct RenameEdit {
    pub start_byte: usize,
    pub end_byte: usize,
    pub new_text: String,
}

#[derive(Debug, Clone)]
pub struct RenameFileEdits {
    pub file: ProjectFile,
    pub edits: Vec<RenameEdit>,
}

#[derive(Debug, Clone)]
pub struct RenameResult {
    pub target: CodeUnit,
    pub old_name: String,
    pub files: Vec<RenameFileEdits>,
}

/// One language-owned authority for edit discovery and capture validation.
/// Target selection and identifier validation happen before this boundary.
pub(crate) trait RenameProvider: Send + Sync {
    fn rename(
        &self,
        analyzer: &dyn IAnalyzer,
        project: &dyn Project,
        target: &CodeUnit,
        new_name: &str,
    ) -> Result<RenameResult, RenameFailure>;
}

fn rename_usage_hits(query: QueryResult) -> Result<Vec<UsageHit>, RenameFailure> {
    if query.completion != UsageQueryCompletion::Complete
        || query.candidate_files_truncated
        || query.source_bytes_truncated
    {
        return Err(RenameFailure {
            kind: if query.completion == UsageQueryCompletion::Cancelled {
                "cancelled"
            } else if query.candidate_files_truncated
                || query.completion == UsageQueryCompletion::CandidateFilesBudgetExhausted
            {
                "too_many_files"
            } else {
                "incomplete_analysis"
            },
            message: format!(
                "rename requires complete usage execution: completion={:?}, candidate_files_truncated={}, source_bytes_truncated={}, result={:?}",
                query.completion,
                query.candidate_files_truncated,
                query.source_bytes_truncated,
                query.result,
            ),
        });
    }
    let hits = match query.result {
        FuzzyResult::Success {
            hits_by_overload,
            unproven_by_overload,
            unproven_total_by_overload,
        } => {
            if unproven_by_overload.values().any(|hits| !hits.is_empty())
                || unproven_total_by_overload.values().any(|total| *total != 0)
            {
                return Err(RenameFailure {
                    kind: "ambiguous",
                    message: format!(
                        "rename cannot omit uncertain references: hits_by_overload={hits_by_overload:?}, unproven_by_overload={unproven_by_overload:?}, unproven_total_by_overload={unproven_total_by_overload:?}",
                    ),
                });
            }
            hits_by_overload
                .into_values()
                .flatten()
                .filter(UsageHit::is_lsp_reference_site)
                .collect::<Vec<_>>()
        }
        result @ FuzzyResult::Ambiguous { .. } => {
            return Err(RenameFailure {
                kind: "ambiguous",
                message: format!(
                    "rename target resolved to ambiguous usage candidates: {result:?}"
                ),
            });
        }
        result @ FuzzyResult::Incomplete { .. } => {
            return Err(RenameFailure {
                kind: "incomplete_analysis",
                message: format!("rename requires complete reference enumeration: {result:?}"),
            });
        }
        result @ FuzzyResult::Failure { .. } => {
            return Err(RenameFailure {
                kind: "not_found",
                message: format!("rename usages could not be resolved: {result:?}"),
            });
        }
        result @ FuzzyResult::TooManyCallsites { .. } => {
            return Err(RenameFailure {
                kind: "too_many_callsites",
                message: format!(
                    "rename target has too many call sites to edit safely: {result:?}"
                ),
            });
        }
    };
    if hits
        .iter()
        .any(|hit| hit.proof != UsageProof::Proven || hit.confidence < RENAME_CONFIDENCE_THRESHOLD)
    {
        return Err(RenameFailure {
            kind: "low_confidence",
            message: format!("rename requires proven high-confidence references: {hits:?}"),
        });
    }
    Ok(hits)
}

pub fn prepare_rename(
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

pub fn rename_symbol(
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

    if let Some(provider) =
        crate::analyzer::languages::language_support(language_for_file(target.source()))
            .and_then(|support| support.rename_provider())
    {
        return provider.rename(analyzer, project, &target, new_name);
    }

    let query = UsageFinder::new().query(
        analyzer,
        std::slice::from_ref(&target),
        DEFAULT_MAX_FILES,
        DEFAULT_MAX_USAGES,
    );
    let hits = rename_usage_hits(query)?;

    let mut cache = FileContentCache::default();
    let mut edits_by_file: HashMap<ProjectFile, Vec<EditCandidate>> = HashMap::new();

    for hit in hits {
        let entry = cache.ensure(project, &hit.file)?;
        let (start_byte, end_byte) =
            if entry.body.get(hit.start_offset..hit.end_offset) == Some(old_name.as_str()) {
                (hit.start_offset, hit.end_offset)
            } else {
                let slice = entry
                    .body
                    .get(hit.start_offset..hit.end_offset)
                    .ok_or_else(|| RenameFailure {
                        kind: "stale_location",
                        message: "usage range no longer exists in source".to_string(),
                    })?;
                let offset = find_word(slice, &old_name).ok_or_else(|| RenameFailure {
                    kind: "stale_location",
                    message: format!("expected `{old_name}` inside resolved usage range"),
                })?;
                let start = hit.start_offset + offset;
                (start, start + old_name.len())
            };
        let edit = edit_for_byte_range(
            project, &mut cache, &hit.file, start_byte, end_byte, &old_name, new_name,
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

    let result = RenameResult {
        target,
        old_name,
        files,
    };
    Ok(result)
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
            message: "rename location is outside the file".to_string(),
        });
    }
    if !content.is_char_boundary(offset) {
        return Err(RenameFailure {
            kind: "invalid_location",
            message: "rename location does not align to a UTF-8 character boundary".to_string(),
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
        Arc::from(cursor.content),
    );
    let outcome = outcomes
        .pop()
        .expect("a one-request definition batch answers with one outcome");
    if outcome.status != DefinitionLookupStatus::Resolved {
        return Err(unresolved_definition_failure(&outcome));
    }
    // A local, parameter or other lexical binding resolves to exactly one
    // lexical definition and no workspace `CodeUnit`. Rename edits only
    // workspace declarations, so this is an unsupported target, not an
    // ambiguity: the definition answer at the same location is one binding.
    if let Some(lexical) = &outcome.lexical_definition {
        return Err(lexical_binding_failure(lexical));
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
    if source_identifier_for_target(&target) != cursor.identifier {
        return Err(RenameFailure {
            kind: "not_found",
            message: "resolved definition identifier does not match selected token".to_string(),
        });
    }
    Ok(target)
}

/// The rename failure for a location that resolves to one lexical binding.
fn lexical_binding_failure(
    lexical: &crate::analyzer::lexical_definitions::LexicalDefinition,
) -> RenameFailure {
    RenameFailure {
        kind: "unsupported",
        message: format!(
            "`{}` resolves to a {}; rename does not support lexical bindings yet",
            lexical.identifier,
            lexical.kind.label()
        ),
    }
}

/// The rename failure for a definition lookup that did not resolve.
///
/// The definition status contract says an exhausted budget, a cancellation and
/// an incomplete answer are not proven absence, so every one of them has to
/// arrive at the caller as itself. Collapsing them into `not_found` both lost
/// the reason and earned the caller the "move to an identifier token and
/// retry" advice that only a genuine miss deserves, which turned a budget
/// exhaustion into an invitation to hunt for a better token.
///
/// The failure therefore carries the status as its kind, in the same shape
/// `rename_usage_hits` already uses for cancelled and incomplete usage
/// execution, and the message carries the lookup's own diagnostics so the
/// reason survives the hand-off. `Ambiguous` is included by the same rule
/// rather than by exception: an ambiguous location has no unique authority to
/// rename, and `DefinitionLookupStatus::carries_definitions` already refuses
/// to let it stand in for one.
fn unresolved_definition_failure(outcome: &DefinitionLookupOutcome) -> RenameFailure {
    debug_assert_ne!(
        outcome.status,
        DefinitionLookupStatus::Resolved,
        "a resolved lookup is not a rename failure"
    );
    RenameFailure {
        kind: outcome.status.as_str(),
        message: format!(
            "rename requires one resolved definition at the rename location: status={}, \
             definitions={:?}, diagnostics={:?}",
            outcome.status.as_str(),
            outcome.definitions,
            outcome.diagnostics,
        ),
    }
}

fn declaration_target_at_span(
    analyzer: &dyn IAnalyzer,
    cursor: &RenameCursorRef<'_>,
) -> Option<CodeUnit> {
    let mut matches = analyzer
        .declarations(cursor.file)
        .into_iter()
        .filter(|code_unit| source_identifier_for_target(code_unit) == cursor.identifier)
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
        let (line, column) =
            line_column_for_byte_offset(&entry.body, &entry.line_starts, start_byte);
        return Err(RenameFailure {
            kind: "stale_location",
            message: format!(
                "expected `{old_name}` at `{}:{line}:{column}`",
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
    let name = source_identifier_for_target(code_unit);
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
    use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverBudgetLimit;
    use std::collections::BTreeSet;

    fn usage_query(result: FuzzyResult, completion: UsageQueryCompletion) -> QueryResult {
        QueryResult {
            completion,
            candidate_files: Default::default(),
            candidate_files_truncated: false,
            source_bytes_truncated: false,
            scanned_source_bytes: 0,
            candidate_files_sample: None,
            result,
            proof_authority: Default::default(),
            graph_failure: None,
        }
    }

    #[test]
    fn rename_requires_complete_execution_and_proven_reference_inventory() {
        let file = ProjectFile::new(std::env::temp_dir(), "target.rs");
        let target = CodeUnit::new(file.clone(), CodeUnitType::Function, "", "target");
        let proven = UsageHit::new(file.clone(), 0, 0, 6, target.clone(), 1.0, "target");
        let mut uncertain = UsageHit::new(file, 1, 10, 16, target.clone(), 1.0, "target");
        uncertain.proof = UsageProof::Unproven;
        for (candidates, total) in [
            (BTreeSet::from([uncertain.clone()]), 1),
            (BTreeSet::from([uncertain.clone().into_import()]), 0),
            (BTreeSet::new(), 1),
        ] {
            let result = FuzzyResult::Success {
                hits_by_overload: [(target.clone(), BTreeSet::from([proven.clone()]))]
                    .into_iter()
                    .collect(),
                unproven_by_overload: [(target.clone(), candidates)].into_iter().collect(),
                unproven_total_by_overload: [(target.clone(), total)].into_iter().collect(),
            };
            let failure =
                rename_usage_hits(usage_query(result, UsageQueryCompletion::Complete)).unwrap_err();
            assert_eq!(failure.kind, "ambiguous");
            assert!(failure.message.contains("unproven_total_by_overload"));
        }
        // Confidence alone does not certify a proof, even if a producer places
        // an uncertain hit in the nominally proven bucket.
        let result = FuzzyResult::success(target.clone(), BTreeSet::from([uncertain]));
        assert_eq!(
            rename_usage_hits(usage_query(result, UsageQueryCompletion::Complete))
                .unwrap_err()
                .kind,
            "low_confidence"
        );
        let result = FuzzyResult::success(target, BTreeSet::from([proven.clone()]));
        assert_eq!(
            rename_usage_hits(usage_query(result, UsageQueryCompletion::Complete)).unwrap(),
            vec![proven]
        );
        assert!(
            rename_usage_hits(usage_query(
                FuzzyResult::empty_success(),
                UsageQueryCompletion::Complete
            ))
            .unwrap()
            .is_empty()
        );
        for (completion, kind) in [
            (UsageQueryCompletion::Cancelled, "cancelled"),
            (
                UsageQueryCompletion::CandidateFilesBudgetExhausted,
                "too_many_files",
            ),
            (
                UsageQueryCompletion::SourceBytesBudgetExhausted,
                "incomplete_analysis",
            ),
        ] {
            assert_eq!(
                rename_usage_hits(usage_query(FuzzyResult::empty_success(), completion))
                    .unwrap_err()
                    .kind,
                kind
            );
        }
    }

    fn unresolved_outcome(status: DefinitionLookupStatus) -> DefinitionLookupOutcome {
        DefinitionLookupOutcome {
            modeled_definitions: Vec::new(),
            status,
            reference: None,
            definitions: Vec::new(),
            lexical_definition: None,
            diagnostics: vec![
                crate::analyzer::usages::get_definition::DefinitionLookupDiagnostic {
                    claim: None,
                    kind: "receiver_budget_exhausted".to_string(),
                    message: "bounded resolution stopped at its scope-node budget".to_string(),
                },
            ],
        }
    }

    /// Every inconclusive definition status reaches the caller as itself.
    ///
    /// Exhaustion, cancellation and incompleteness are not proven absence, so
    /// none of them may arrive as `not_found`: that is the one kind the
    /// navigation surface answers with "move to an identifier token and
    /// retry", advice that is wrong for every status here.
    #[test]
    fn an_unresolved_definition_keeps_its_status_and_diagnostics() {
        for (status, kind) in [
            (
                DefinitionLookupStatus::ExceededBudget(ReceiverBudgetLimit::ScopeNodes),
                "exceeded_budget",
            ),
            (DefinitionLookupStatus::Cancelled, "cancelled"),
            (DefinitionLookupStatus::Unavailable, "unavailable"),
            (DefinitionLookupStatus::Incomplete, "incomplete"),
            (DefinitionLookupStatus::Ambiguous, "ambiguous"),
            (DefinitionLookupStatus::NoDefinition, "no_definition"),
            (
                DefinitionLookupStatus::UnresolvableImportBoundary,
                "unresolvable_import_boundary",
            ),
            (DefinitionLookupStatus::NotFound, "not_found"),
        ] {
            let failure = unresolved_definition_failure(&unresolved_outcome(status));

            assert_eq!(failure.kind, kind, "status {status:?}");
            assert!(
                failure.message.contains(kind),
                "status {status:?} must name itself: {}",
                failure.message
            );
            assert!(
                failure
                    .message
                    .contains("bounded resolution stopped at its scope-node budget"),
                "status {status:?} must carry its diagnostics: {}",
                failure.message
            );
        }
    }

    /// An ambiguous location has no unique authority, so it is a refusal and
    /// never an edit, and it is not reported as an absence either.
    #[test]
    fn an_ambiguous_definition_refuses_the_rename_without_claiming_absence() {
        let failure =
            unresolved_definition_failure(&unresolved_outcome(DefinitionLookupStatus::Ambiguous));

        assert_eq!(failure.kind, "ambiguous");
        assert_ne!(failure.kind, "not_found");
    }

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
