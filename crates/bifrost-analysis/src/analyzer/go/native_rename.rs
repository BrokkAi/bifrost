//! Test-support Go rename from selected inverse edges.
//!
//! Edits are collected only from complete, proven native inverse rows. A
//! frozen project overlay supplies the counterfactual source world; the same
//! selected Go inverse operation must produce the same proven binding sites
//! after the edit before the edit set is returned.

use super::GoAnalyzer;
use super::selected_reverse::{GoSelectedReverseOutcome, go_selected_inverse_for};
use crate::CancellationToken;
use crate::analyzer::CodeUnitIndex;
use crate::analyzer::OverlayProject;
use crate::analyzer::structural::reference_edges::{EdgeCompleteness, EdgeDerivationResult};
use crate::analyzer::usages::{DEFAULT_MAX_FILES, DEFAULT_MAX_USAGES, UsageProof};
use crate::analyzer::{CodeUnit, IAnalyzer, Language, Project, ProjectFile, resolve_analyzer};
use crate::symbol_rename::{
    MAX_RENAME_IDENTIFIER_BYTES, RenameEdit, RenameFailure, RenameFileEdits, RenameResult,
};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// Native Go rename preparation. It remains outside Go production dispatch.
pub struct GoNativeRenameProvider;

impl crate::symbol_rename::RenameProvider for GoNativeRenameProvider {
    fn rename(
        &self,
        analyzer: &dyn IAnalyzer,
        project: &dyn Project,
        target: &CodeUnit,
        new_name: &str,
    ) -> Result<RenameResult, RenameFailure> {
        let go = resolve_analyzer::<GoAnalyzer>(analyzer)
            .ok_or_else(|| failure("incomplete_analysis", "selected Go analyzer is unavailable"))?;
        native_go_rename(go, project, target, new_name, &CancellationToken::default())
    }
}

struct CounterfactualFile {
    hypothetical: String,
    edits: Box<[RenameEdit]>,
}

impl CounterfactualFile {
    fn hypothetical_range_to_original(
        &self,
        start_byte: usize,
        end_byte: usize,
    ) -> Option<(usize, usize)> {
        let mut delta = 0_i128;
        for edit in &self.edits {
            let hypothetical_start = usize::try_from(edit.start_byte as i128 + delta).ok()?;
            let hypothetical_end = hypothetical_start.checked_add(edit.new_text.len())?;
            if start_byte == hypothetical_start && end_byte == hypothetical_end {
                return Some((edit.start_byte, edit.end_byte));
            }
            if end_byte <= hypothetical_start {
                break;
            }
            if start_byte < hypothetical_end {
                return None;
            }
            delta +=
                edit.new_text.len() as i128 - edit.end_byte.checked_sub(edit.start_byte)? as i128;
        }
        Some((
            usize::try_from(start_byte as i128 - delta).ok()?,
            usize::try_from(end_byte as i128 - delta).ok()?,
        ))
    }
}

/// Test-support entry point for running Go's native rename implementation
/// without registering it in production language dispatch.
pub fn go_native_rename(
    analyzer: &dyn IAnalyzer,
    project: &dyn Project,
    target: &CodeUnit,
    new_name: &str,
    cancellation: &CancellationToken,
) -> Result<RenameResult, RenameFailure> {
    let go = resolve_analyzer::<GoAnalyzer>(analyzer)
        .ok_or_else(|| failure("incomplete_analysis", "selected Go analyzer is unavailable"))?;
    native_go_rename(go, project, target, new_name, cancellation)
}

fn native_go_rename(
    go: &GoAnalyzer,
    project: &dyn Project,
    target: &CodeUnit,
    new_name: &str,
    cancellation: &CancellationToken,
) -> Result<RenameResult, RenameFailure> {
    use crate::analyzer::common::is_valid_rename_identifier;

    if target.source().declaration_language() != Language::Go {
        return Err(failure(
            "unsupported",
            "native Go rename requires a Go declaration",
        ));
    }
    if new_name.len() > MAX_RENAME_IDENTIFIER_BYTES
        || !is_valid_rename_identifier(Language::Go, new_name)
    {
        return Err(failure("invalid_name", "invalid Go replacement identifier"));
    }
    if cancellation.is_cancelled() {
        return Err(failure("cancelled", "native Go rename was cancelled"));
    }
    let generation = project.analysis_generation();
    let original = match go_selected_inverse_for(go, target, cancellation) {
        GoSelectedReverseOutcome::Ready(answer) => answer,
        outcome => {
            return Err(failure(
                "incomplete_analysis",
                format!("native Go inverse selection failed: {outcome:?}"),
            ));
        }
    };
    require_complete_proven(&original, "original")?;
    if original.edges.len() > DEFAULT_MAX_USAGES {
        return Err(failure(
            "too_many_callsites",
            format!(
                "native Go rename exceeds the usage limit: {}",
                original.edges.len()
            ),
        ));
    }

    let target_source = project
        .read_source(target.source())
        .map_err(|error| failure("incomplete_analysis", error.to_string()))?;
    if !go
        .inner
        .source_matches_selected_native_content(target.source(), &target_source)
    {
        return Err(failure(
            "incomplete_analysis",
            "native Go rename target source differs from selected content",
        ));
    }
    let declaration = crate::analyzer::declaration_range::code_unit_declaration_name_range(
        go,
        target.source(),
        &target_source,
        target,
    )
    .ok_or_else(|| {
        failure(
            "incomplete_analysis",
            "native Go rename target has no structured declaration name",
        )
    })?;
    let mut edits_by_file = BTreeMap::<ProjectFile, (String, Vec<RenameEdit>)>::new();
    for edge in &original.edges {
        let file = edge.site.file.clone();
        if !edits_by_file.contains_key(&file) {
            if edits_by_file.len() >= DEFAULT_MAX_FILES {
                return Err(failure(
                    "too_many_files",
                    "native Go rename exceeds the file limit",
                ));
            }
            let source = project
                .read_source(&file)
                .map_err(|error| failure("incomplete_analysis", error.to_string()))?;
            if !go
                .inner
                .source_matches_selected_native_content(&file, &source)
            {
                return Err(failure(
                    "incomplete_analysis",
                    format!("native Go rename source differs from selected content: {file}"),
                ));
            }
            edits_by_file.insert(file.clone(), (source, Vec::new()));
        }
        let (source, edits) = edits_by_file
            .get_mut(&file)
            .expect("selected Go rename source was admitted");
        let spelling = source
            .get(edge.site.range.start_byte..edge.site.range.end_byte)
            .ok_or_else(|| {
                failure(
                    "incomplete_analysis",
                    format!(
                        "native Go inverse range is outside {file}: {:?}",
                        edge.site.range
                    ),
                )
            })?;
        // References through a type alias bind to the target while retaining
        // the alias's spelling. They belong to the binding comparison, but
        // renaming the underlying declaration must leave that spelling alone.
        if spelling == target.identifier() {
            edits.push(RenameEdit {
                start_byte: edge.site.range.start_byte,
                end_byte: edge.site.range.end_byte,
                new_text: new_name.to_owned(),
            });
        }
    }
    if !edits_by_file.contains_key(target.source()) {
        if edits_by_file.len() >= DEFAULT_MAX_FILES {
            return Err(failure(
                "too_many_files",
                "native Go rename exceeds the file limit",
            ));
        }
        edits_by_file.insert(target.source().clone(), (target_source.clone(), Vec::new()));
    }
    let declaration_source = &edits_by_file
        .get(target.source())
        .expect("target source was admitted")
        .0;
    if declaration_source.get(declaration.start_byte..declaration.end_byte)
        != Some(target.identifier())
    {
        return Err(failure(
            "incomplete_analysis",
            "native Go declaration range does not contain its structured identifier",
        ));
    }
    edits_by_file
        .get_mut(target.source())
        .expect("target source was admitted")
        .1
        .push(RenameEdit {
            start_byte: declaration.start_byte,
            end_byte: declaration.end_byte,
            new_text: new_name.to_owned(),
        });

    let counterfactual_files =
        build_counterfactual_files(edits_by_file, target.identifier(), new_name)?;
    let result = RenameResult {
        target: target.clone(),
        old_name: target.identifier().to_owned(),
        files: counterfactual_files
            .iter()
            .filter_map(|(file, contents)| {
                (!contents.edits.is_empty()).then_some(RenameFileEdits {
                    file: file.clone(),
                    edits: contents.edits.to_vec(),
                })
            })
            .collect(),
    };

    let hypothetical_go = counterfactual_analyzer(go, &counterfactual_files)?;
    let original_parent = go.parent_of(target);
    let hypothetical_target =
        find_counterfactual_target(&hypothetical_go, target, original_parent.as_ref(), new_name)?;
    let hypothetical =
        match go_selected_inverse_for(&hypothetical_go, &hypothetical_target, cancellation) {
            GoSelectedReverseOutcome::Ready(answer) => answer,
            outcome => {
                return Err(failure(
                    "incomplete_analysis",
                    format!("counterfactual Go inverse selection failed: {outcome:?}"),
                ));
            }
        };
    require_complete_proven(&hypothetical, "counterfactual")?;
    let original_sites = inverse_site_positions(&original, None)?;
    let hypothetical_sites = inverse_site_positions(&hypothetical, Some(&counterfactual_files))?;
    if original_sites != hypothetical_sites {
        return Err(failure(
            "capture_or_rebinding",
            format!(
                "Go rename changes selected binding sites: original={original_sites:?}, counterfactual={hypothetical_sites:?}"
            ),
        ));
    }
    if cancellation.is_cancelled() || project.analysis_generation() != generation {
        return Err(failure(
            "incomplete_analysis",
            "native Go rename was cancelled or selected generation changed",
        ));
    }
    Ok(result)
}

fn build_counterfactual_files(
    edits_by_file: BTreeMap<ProjectFile, (String, Vec<RenameEdit>)>,
    old_name: &str,
    new_name: &str,
) -> Result<BTreeMap<ProjectFile, CounterfactualFile>, RenameFailure> {
    let mut files = BTreeMap::new();
    for (file, (original, mut edits)) in edits_by_file {
        edits.sort_by_key(|edit| (edit.start_byte, edit.end_byte));
        edits.dedup_by_key(|edit| (edit.start_byte, edit.end_byte));
        if edits
            .windows(2)
            .any(|pair| pair[1].start_byte < pair[0].end_byte)
        {
            return Err(failure(
                "incomplete_analysis",
                "native Go rename edits overlap",
            ));
        }
        for edit in &edits {
            if edit.new_text != new_name
                || original.get(edit.start_byte..edit.end_byte) != Some(old_name)
            {
                return Err(failure(
                    "incomplete_analysis",
                    format!(
                        "native Go rename edit is not an exact identifier replacement: {edit:?}"
                    ),
                ));
            }
        }
        let mut hypothetical = original.clone();
        for edit in edits.iter().rev() {
            hypothetical.replace_range(edit.start_byte..edit.end_byte, &edit.new_text);
        }
        files.insert(
            file,
            CounterfactualFile {
                hypothetical,
                edits: edits.into_boxed_slice(),
            },
        );
    }
    Ok(files)
}

fn counterfactual_analyzer(
    go: &GoAnalyzer,
    files: &BTreeMap<ProjectFile, CounterfactualFile>,
) -> Result<GoAnalyzer, RenameFailure> {
    let overlay = Arc::new(OverlayProject::new(go.inner.shared_project()));
    for (file, contents) in files {
        if !overlay.set(file.abs_path().to_path_buf(), contents.hypothetical.clone()) {
            return Err(failure(
                "incomplete_analysis",
                format!("cannot mount Go rename overlay for {file}"),
            ));
        }
    }
    let project: Arc<dyn Project> = Arc::new(overlay.snapshot());
    Ok(go.clone_with_project(project))
}

fn find_counterfactual_target(
    go: &GoAnalyzer,
    target: &CodeUnit,
    original_parent: Option<&CodeUnit>,
    new_name: &str,
) -> Result<CodeUnit, RenameFailure> {
    let mut matches = go
        .get_all_declarations()
        .into_iter()
        .filter(|candidate| {
            candidate.identifier() == new_name
                && candidate.kind() == target.kind()
                && candidate.package_name() == target.package_name()
                && go.parent_of(candidate).as_ref() == original_parent
        })
        .collect::<Vec<_>>();
    matches.sort();
    matches.dedup();
    match matches.as_slice() {
        [candidate] => Ok(candidate.clone()),
        _ => Err(failure(
            "capture_or_rebinding",
            format!("counterfactual Go target is absent or ambiguous: {matches:?}"),
        )),
    }
}

fn require_complete_proven(
    result: &EdgeDerivationResult,
    world: &str,
) -> Result<(), RenameFailure> {
    if result.completeness != EdgeCompleteness::Complete
        || result
            .edges
            .iter()
            .any(|edge| edge.proof != UsageProof::Proven)
    {
        return Err(failure(
            "incomplete_analysis",
            format!("{world} Go inverse evidence is incomplete or unproven: {result:?}"),
        ));
    }
    Ok(())
}

fn inverse_site_positions(
    result: &EdgeDerivationResult,
    counterfactual_files: Option<&BTreeMap<ProjectFile, CounterfactualFile>>,
) -> Result<BTreeSet<(ProjectFile, usize, usize)>, RenameFailure> {
    let mut positions = BTreeSet::new();
    for edge in &result.edges {
        let range = match counterfactual_files.and_then(|files| files.get(&edge.site.file)) {
            Some(file) => file
                .hypothetical_range_to_original(
                    edge.site.range.start_byte,
                    edge.site.range.end_byte,
                )
                .ok_or_else(|| {
                    failure(
                        "incomplete_analysis",
                        format!(
                            "counterfactual Go inverse range overlaps an edit: {:?}",
                            edge.site
                        ),
                    )
                })?,
            None => (edge.site.range.start_byte, edge.site.range.end_byte),
        };
        positions.insert((edge.site.file.clone(), range.0, range.1));
    }
    Ok(positions)
}

fn failure(kind: &'static str, message: impl Into<String>) -> RenameFailure {
    RenameFailure {
        kind,
        message: message.into(),
    }
}
