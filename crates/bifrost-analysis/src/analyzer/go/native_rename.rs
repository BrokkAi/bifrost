//! Go rename from selected inverse edges.
//!
//! Edits are collected only from complete, proven native inverse rows. A
//! saved-state query over selected scopes, imports and package summaries
//! rejects captures and rebindings before returning the edit set.

use super::GoAnalyzer;
use super::selected_reverse::{GoSelectedReverseOutcome, go_selected_inverse_for_rename_original};
use crate::CancellationToken;
use crate::analyzer::resolution::seam_profile::{GoRenamePhase, go_rename_phase};
use crate::analyzer::structural::reference_edges::{EdgeCompleteness, EdgeDerivationResult};
use crate::analyzer::usages::{DEFAULT_MAX_FILES, DEFAULT_MAX_USAGES, UsageProof};
use crate::analyzer::{CodeUnit, IAnalyzer, Language, Project, ProjectFile, resolve_analyzer};
use crate::symbol_rename::{
    MAX_RENAME_IDENTIFIER_BYTES, RenameEdit, RenameFailure, RenameFileEdits, RenameResult,
};
use std::collections::BTreeMap;

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

/// Test-support entry point for running Go's native rename implementation
/// without registering it in production language dispatch.
#[cfg(any(test, feature = "test-support"))]
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
    let (original, conflict) =
        match go_selected_inverse_for_rename_original(go, target, new_name, cancellation) {
            (GoSelectedReverseOutcome::Ready(answer), conflict) => (answer, conflict),
            (GoSelectedReverseOutcome::Unavailable(reason), _) => {
                return Err(failure("incomplete_analysis", reason));
            }
            (GoSelectedReverseOutcome::Stale(reason), _) => {
                return Err(failure("incomplete_analysis", reason));
            }
            (GoSelectedReverseOutcome::Cancelled, _) => {
                return Err(failure("cancelled", "native Go rename was cancelled"));
            }
            (GoSelectedReverseOutcome::StoreError(reason), _) => {
                return Err(failure("incomplete_analysis", reason));
            }
        };
    if let Some(conflict) = conflict {
        return Err(failure("capture_or_rebinding", conflict));
    }
    let edit_assembly_phase = go_rename_phase(GoRenamePhase::EditAssembly);
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

    let rename_files = build_rename_files(edits_by_file, target.identifier(), new_name)?;
    let result = RenameResult {
        target: target.clone(),
        old_name: target.identifier().to_owned(),
        files: rename_files,
    };
    drop(edit_assembly_phase);
    if cancellation.is_cancelled() || project.analysis_generation() != generation {
        return Err(failure(
            "incomplete_analysis",
            "native Go rename was cancelled or selected generation changed",
        ));
    }
    Ok(result)
}

fn build_rename_files(
    edits_by_file: BTreeMap<ProjectFile, (String, Vec<RenameEdit>)>,
    old_name: &str,
    new_name: &str,
) -> Result<Vec<RenameFileEdits>, RenameFailure> {
    let mut files = Vec::new();
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
        if !edits.is_empty() {
            files.push(RenameFileEdits { file, edits });
        }
    }
    Ok(files)
}

fn require_complete_proven(
    result: &EdgeDerivationResult,
    world: &str,
) -> Result<(), RenameFailure> {
    require_complete_inventory(result, world)?;
    if result
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

fn require_complete_inventory(
    result: &EdgeDerivationResult,
    world: &str,
) -> Result<(), RenameFailure> {
    if result.completeness != EdgeCompleteness::Complete {
        return Err(failure(
            "incomplete_analysis",
            format!("{world} Go inverse inventory is incomplete: {result:?}"),
        ));
    }
    Ok(())
}

fn failure(kind: &'static str, message: impl Into<String>) -> RenameFailure {
    RenameFailure {
        kind,
        message: message.into(),
    }
}
