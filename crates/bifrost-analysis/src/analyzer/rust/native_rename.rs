//! Native Rust rename preparation from exact selected inverse evidence.
//!
//! Original and counterfactual selected binding worlds certify capture safety.
//! Diagnostic comparisons call this implementation; they do not supply edits.
//! The production Rust language support registers this exact provider.

use super::RustAnalyzer;
use super::selected_projection::rust_selected_workspace_identity_gap;
use crate::analyzer::resolution::{ResolutionCompletion, SelectedSemanticLocator};
use crate::analyzer::store::resolution_operation::{
    SelectedResolutionLocated, SelectedResolutionOperationInput,
    SelectedResolutionOperationOpenOutcome, SelectedResolutionOperationOutcome,
    SelectedRustBindingDefinition, SelectedRustBindingDefinitionOutcome, SelectedRustBindingWorld,
    SelectedRustCallerReferenceOutcome,
};
use crate::analyzer::store::resolution_publication::{
    ResolutionContentPublicationOutcome, SelectedResolutionOverlayInputsOutcome,
};
use crate::analyzer::store::resolution_selection::{
    SelectedResolutionContentMountRequest, SelectedResolutionLanguage,
    SelectedResolutionOverlayMask,
};
use crate::analyzer::store::{WorkspaceFileRow, WorkspaceSnapshots};
use crate::analyzer::structural::reference_edges::EdgeCompleteness;
use crate::analyzer::usages::UsageProof;
use crate::analyzer::{CodeUnit, IAnalyzer, Language, Project, ProjectFile};
use crate::path_utils::rel_path_string;
use crate::symbol_rename::{RenameEdit, RenameResult};
use brokk_bifrost_core::analyzer::resolution_facts::{ResolutionNamespace, ResolutionSiteKind};
use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};

pub(super) struct RustNativeRenameProvider;

impl crate::symbol_rename::RenameProvider for RustNativeRenameProvider {
    fn rename(
        &self,
        analyzer: &dyn IAnalyzer,
        project: &dyn Project,
        target: &CodeUnit,
        new_name: &str,
    ) -> Result<RenameResult, crate::symbol_rename::RenameFailure> {
        let rust =
            crate::analyzer::resolve_analyzer::<RustAnalyzer>(analyzer).ok_or_else(|| {
                crate::symbol_rename::RenameFailure {
                    kind: "incomplete_analysis",
                    message: "selected Rust analyzer is unavailable".into(),
                }
            })?;
        native_rust_rename(
            rust,
            project,
            target,
            new_name,
            &crate::CancellationToken::default(),
        )
        .map_err(|message| crate::symbol_rename::RenameFailure {
            kind: "incomplete_analysis",
            message,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct RustRenamePosition {
    pub(super) file: ProjectFile,
    pub(super) start_byte: usize,
    pub(super) end_byte: usize,
    namespace: ResolutionNamespace,
    site_kind: ResolutionSiteKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RustRenamePositionState {
    definitions: Vec<SelectedRustBindingDefinition>,
    completion: ResolutionCompletion,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum RustRenameSafetyOutcome {
    Safe,
    CapturedOrRebound {
        positions: BTreeSet<RustRenamePosition>,
    },
    Indeterminate(String),
}

struct RustCounterfactualFile {
    original: String,
    hypothetical: String,
    edits: Box<[RenameEdit]>,
}

pub(super) enum RustBindingTargetProof<'a> {
    Current(&'a CodeUnit),
    Established(SelectedRustBindingDefinition),
}

#[derive(Debug)]
pub(super) enum RustBindingWorldOutcome {
    Ready(SelectedRustBindingWorld),
    Unavailable(String),
    Stale(String),
    Cancelled,
    StoreError(String),
}

impl RustCounterfactualFile {
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

#[cfg(test)]
pub(super) fn selected_rust_binding_world(
    rust: &RustAnalyzer,
    snapshots: &WorkspaceSnapshots,
    target: RustBindingTargetProof<'_>,
    masks: &[SelectedResolutionOverlayMask],
    content_mounts: Vec<SelectedResolutionContentMountRequest>,
    cancellation: &crate::CancellationToken,
) -> RustBindingWorldOutcome {
    selected_rust_binding_world_with_candidates(
        rust,
        snapshots,
        target,
        masks,
        content_mounts,
        cancellation,
        &[],
        &[],
    )
}

#[allow(clippy::too_many_arguments)]
fn selected_rust_binding_world_with_candidates(
    rust: &RustAnalyzer,
    snapshots: &WorkspaceSnapshots,
    target: RustBindingTargetProof<'_>,
    masks: &[SelectedResolutionOverlayMask],
    content_mounts: Vec<SelectedResolutionContentMountRequest>,
    cancellation: &crate::CancellationToken,
    seeds: &[SelectedSemanticLocator],
    names: &[String],
) -> RustBindingWorldOutcome {
    if !cancellation.is_cancelled()
        && let Some(detail) = rust_selected_workspace_identity_gap(rust)
    {
        return RustBindingWorldOutcome::Unavailable(detail);
    }
    let languages = [SelectedResolutionLanguage::new("rust", Language::Rust)];
    let input = SelectedResolutionOperationInput::new(
        rust.inner.project(),
        rust.inner.workspace_id(),
        snapshots,
        &languages,
        masks,
    )
    .with_content_mounts(content_mounts.clone());
    let operation = match rust
        .inner
        .analyzer_store()
        .open_selected_resolution_operation(input, cancellation)
    {
        Ok(SelectedResolutionOperationOpenOutcome::Ready(operation)) => *operation,
        Ok(SelectedResolutionOperationOpenOutcome::Unavailable(reason)) => {
            return RustBindingWorldOutcome::Unavailable(format!(
                "selected operation unavailable: {reason:?}"
            ));
        }
        Ok(SelectedResolutionOperationOpenOutcome::Stale(reason)) => {
            return RustBindingWorldOutcome::Stale(format!("selected operation stale: {reason:?}"));
        }
        Ok(SelectedResolutionOperationOpenOutcome::Cancelled) => {
            return RustBindingWorldOutcome::Cancelled;
        }
        Err(error) => {
            return RustBindingWorldOutcome::StoreError(error.to_string());
        }
    };
    let target = match target {
        RustBindingTargetProof::Current(target) => {
            match operation.locate_rust_binding_definition(target, cancellation) {
                Ok(SelectedRustBindingDefinitionOutcome::Found(definition)) => definition,
                Ok(SelectedRustBindingDefinitionOutcome::Missing) => {
                    return RustBindingWorldOutcome::Unavailable(format!(
                        "selected Rust binding target has no native definition: {target:?}"
                    ));
                }
                Ok(SelectedRustBindingDefinitionOutcome::Cancelled) => {
                    return RustBindingWorldOutcome::Cancelled;
                }
                Err(error) => {
                    return RustBindingWorldOutcome::StoreError(error.to_string());
                }
            }
        }
        RustBindingTargetProof::Established(definition) => definition,
    };
    let candidates =
        match operation.rust_row_binding_candidates(&target, names, seeds, cancellation) {
            Ok(Some(candidates)) => candidates,
            Ok(None) => {
                return RustBindingWorldOutcome::Unavailable(
                    "selected rename candidate has no persisted crate route".into(),
                );
            }
            Err(error) => return RustBindingWorldOutcome::StoreError(error.to_string()),
        };
    let mut sites = Vec::new();
    let mut completion = ResolutionCompletion::Complete;
    for (root, locator) in candidates {
        if cancellation.is_cancelled() {
            return RustBindingWorldOutcome::Cancelled;
        }
        let point_input = SelectedResolutionOperationInput::new(
            rust.inner.project(),
            rust.inner.workspace_id(),
            snapshots,
            &languages,
            masks,
        )
        .with_content_mounts(content_mounts.clone());
        let point = match rust
            .inner
            .analyzer_store()
            .open_selected_resolution_operation(point_input, cancellation)
        {
            Ok(SelectedResolutionOperationOpenOutcome::Ready(point)) => *point,
            Ok(SelectedResolutionOperationOpenOutcome::Cancelled) => {
                return RustBindingWorldOutcome::Cancelled;
            }
            Ok(SelectedResolutionOperationOpenOutcome::Unavailable(reason)) => {
                return RustBindingWorldOutcome::Unavailable(format!(
                    "selected rename point open: {reason:?}"
                ));
            }
            Ok(SelectedResolutionOperationOpenOutcome::Stale(reason)) => {
                return RustBindingWorldOutcome::Stale(format!(
                    "selected rename point open: {reason:?}"
                ));
            }
            Err(error) => return RustBindingWorldOutcome::StoreError(error.to_string()),
        };
        match point.resolve_rust_binding_site_for_caller(&root, &locator, cancellation) {
            Ok(SelectedRustCallerReferenceOutcome::Operation(
                SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Found(
                    answers,
                )),
            )) => {
                for answer in answers {
                    if let Some((_, enumeration)) = answer.enumeration {
                        completion = completion.combine(&enumeration);
                    }
                    completion = completion.combine(answer.projection.completion());
                    sites.push(answer.projection);
                }
            }
            Ok(SelectedRustCallerReferenceOutcome::Operation(
                SelectedResolutionOperationOutcome::Cancelled(_),
            )) => return RustBindingWorldOutcome::Cancelled,
            Ok(SelectedRustCallerReferenceOutcome::UnsupportedCallerProfile) => {
                return RustBindingWorldOutcome::Unavailable(
                    "selected rename point has no caller profile".into(),
                );
            }
            Ok(SelectedRustCallerReferenceOutcome::Operation(
                SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Missing),
            )) => {
                return RustBindingWorldOutcome::Unavailable(format!(
                    "selected rename reference is missing: {locator:?}"
                ));
            }
            Ok(SelectedRustCallerReferenceOutcome::Operation(
                SelectedResolutionOperationOutcome::Unavailable(reason),
            )) => {
                return RustBindingWorldOutcome::Unavailable(format!(
                    "selected rename point: {reason:?}"
                ));
            }
            Ok(SelectedRustCallerReferenceOutcome::Operation(
                SelectedResolutionOperationOutcome::Stale(reason),
            )) => {
                return RustBindingWorldOutcome::Stale(format!(
                    "selected rename point: {reason:?}"
                ));
            }
            Err(error) => return RustBindingWorldOutcome::StoreError(error.to_string()),
        }
    }
    match operation.finish_rust_row_binding_world(target, sites, completion, cancellation) {
        Ok(SelectedResolutionOperationOutcome::Native(world)) => {
            RustBindingWorldOutcome::Ready(world)
        }
        Ok(SelectedResolutionOperationOutcome::Unavailable(reason)) => {
            RustBindingWorldOutcome::Unavailable(format!(
                "selected binding world unavailable: {reason:?}"
            ))
        }
        Ok(SelectedResolutionOperationOutcome::Stale(reason)) => {
            RustBindingWorldOutcome::Stale(format!("selected binding world stale: {reason:?}"))
        }
        Ok(SelectedResolutionOperationOutcome::Cancelled(_)) => RustBindingWorldOutcome::Cancelled,
        Err(error) => RustBindingWorldOutcome::StoreError(error.to_string()),
    }
}

fn rust_binding_world_failure_detail(result: RustBindingWorldOutcome) -> String {
    match result {
        RustBindingWorldOutcome::Ready(_) => {
            unreachable!("a ready Rust binding world is not a failure")
        }
        RustBindingWorldOutcome::Unavailable(detail) => detail,
        RustBindingWorldOutcome::Stale(detail) => detail,
        RustBindingWorldOutcome::Cancelled => "selected binding world cancelled".to_string(),
        RustBindingWorldOutcome::StoreError(detail) => detail,
    }
}

fn rust_counterfactual_files(
    project: &dyn Project,
    result: &RenameResult,
    new_name: &str,
) -> Result<BTreeMap<ProjectFile, RustCounterfactualFile>, String> {
    let mut files = BTreeMap::new();
    for file_edits in &result.files {
        let original = project
            .read_source(&file_edits.file)
            .map_err(|error| error.to_string())?;
        let mut edits = file_edits.edits.clone();
        edits.sort_by_key(|edit| (edit.start_byte, edit.end_byte));
        if edits
            .windows(2)
            .any(|pair| pair[1].start_byte < pair[0].end_byte)
        {
            return Err("rename edits overlap".to_string());
        }
        for edit in &edits {
            if edit.new_text != new_name
                || original.get(edit.start_byte..edit.end_byte) != Some(result.old_name.as_str())
            {
                return Err(format!(
                    "rename edit is not an exact {:?} -> {:?} identifier replacement: {edit:?}",
                    result.old_name, new_name
                ));
            }
        }
        let mut hypothetical = original.clone();
        for edit in edits.iter().rev() {
            hypothetical.replace_range(edit.start_byte..edit.end_byte, &edit.new_text);
        }
        if files
            .insert(
                file_edits.file.clone(),
                RustCounterfactualFile {
                    original,
                    hypothetical,
                    edits: edits.into_boxed_slice(),
                },
            )
            .is_some()
        {
            return Err(format!(
                "rename repeated file {}",
                file_edits.file.rel_path().display()
            ));
        }
    }
    Ok(files)
}

fn rust_rename_position_states(
    project: &dyn Project,
    world: &SelectedRustBindingWorld,
    counterfactual_files: &BTreeMap<ProjectFile, RustCounterfactualFile>,
    old_name: &str,
    new_name: &str,
    hypothetical: bool,
) -> Result<BTreeMap<RustRenamePosition, RustRenamePositionState>, String> {
    let mut source_cache = BTreeMap::new();
    let mut states = BTreeMap::new();
    for site in world.sites() {
        let Some(metadata) = site.metadata() else {
            return Err(format!(
                "selected Rust reference in {} has no source position",
                site.file().rel_path().display()
            ));
        };
        let source = match source_cache.entry(site.file().clone()) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                let source = match counterfactual_files.get(site.file()) {
                    Some(file) if hypothetical => file.hypothetical.clone(),
                    Some(file) => file.original.clone(),
                    None => project
                        .read_source(site.file())
                        .map_err(|error| error.to_string())?,
                };
                entry.insert(source)
            }
        };
        let spelling = source
            .get(metadata.start_byte()..metadata.end_byte())
            .ok_or_else(|| {
                format!(
                    "selected Rust reference range is outside {}",
                    site.file().rel_path().display()
                )
            })?;
        if spelling != old_name && spelling != new_name {
            continue;
        }
        let (start_byte, end_byte) = if hypothetical {
            counterfactual_files
                .get(site.file())
                .map(|file| {
                    file.hypothetical_range_to_original(metadata.start_byte(), metadata.end_byte())
                })
                .unwrap_or(Some((metadata.start_byte(), metadata.end_byte())))
                .ok_or_else(|| {
                    format!(
                        "hypothetical Rust reference overlaps a rename edit in {}",
                        site.file().rel_path().display()
                    )
                })?
        } else {
            (metadata.start_byte(), metadata.end_byte())
        };
        let mut definitions = site.definitions().to_vec();
        definitions.sort();
        let position = RustRenamePosition {
            file: site.file().clone(),
            start_byte,
            end_byte,
            namespace: metadata.namespace(),
            site_kind: metadata.site_kind(),
        };
        let state = RustRenamePositionState {
            definitions,
            completion: site.completion().clone(),
        };
        if states.insert(position.clone(), state).is_some() {
            return Err(format!(
                "selected Rust binding world repeated position {position:?}"
            ));
        }
    }
    Ok(states)
}

fn validate_original_rename_positions(
    rust: &RustAnalyzer,
    result: &RenameResult,
    counterfactual_files: &BTreeMap<ProjectFile, RustCounterfactualFile>,
    world: &SelectedRustBindingWorld,
    states: &BTreeMap<RustRenamePosition, RustRenamePositionState>,
) -> Result<(), String> {
    let target_file = counterfactual_files
        .get(result.target.source())
        .ok_or_else(|| "rename omitted its target file".to_string())?;
    let declaration = crate::analyzer::declaration_range::code_unit_declaration_name_range(
        rust,
        result.target.source(),
        &target_file.original,
        &result.target,
    )
    .ok_or_else(|| "rename target has no structured declaration range".to_string())?;
    let mut found_declaration = false;
    for file_edits in &result.files {
        for edit in &file_edits.edits {
            if file_edits.file == *result.target.source()
                && edit.start_byte == declaration.start_byte
                && edit.end_byte == declaration.end_byte
            {
                if found_declaration {
                    return Err("rename repeated its target declaration edit".to_string());
                }
                found_declaration = true;
                continue;
            }
            let matching = states
                .iter()
                .filter(|(position, _)| {
                    position.file == file_edits.file
                        && position.start_byte == edit.start_byte
                        && position.end_byte == edit.end_byte
                })
                .collect::<Vec<_>>();
            if matching.is_empty() {
                return Err(format!(
                    "Rust rename edit has no native reference position: file={}, edit={edit:?}",
                    file_edits.file.rel_path().display()
                ));
            }
            let definitions = matching
                .iter()
                .flat_map(|(_, state)| &state.definitions)
                .collect::<BTreeSet<_>>();
            if matching
                .iter()
                .any(|(_, state)| state.completion != ResolutionCompletion::Complete)
                || definitions.len() != 1
                || definitions.first().copied() != Some(world.target())
            {
                return Err(format!(
                    "Rust rename edit is not a complete native reference to the selected target: alternatives={matching:?}, target={:?}",
                    world.target()
                ));
            }
        }
    }
    if !found_declaration {
        return Err("rename omitted its target declaration edit".to_string());
    }
    Ok(())
}

fn rust_rename_overlay_inputs(
    rust: &RustAnalyzer,
    snapshots: &WorkspaceSnapshots,
    counterfactual_files: &BTreeMap<ProjectFile, RustCounterfactualFile>,
    hypothetical: bool,
    cancellation: &crate::CancellationToken,
) -> crate::analyzer::store::Result<SelectedResolutionOverlayInputsOutcome> {
    let overridden_paths = counterfactual_files
        .keys()
        .collect::<crate::hash::HashSet<_>>();
    let mut content_mounts = match rust
        .inner
        .selected_rust_resolution_overlay_inputs_excluding(
            snapshots,
            &overridden_paths,
            cancellation,
        )? {
        SelectedResolutionOverlayInputsOutcome::Ready { content_mounts, .. } => content_mounts,
        outcome => return Ok(outcome),
    };
    let owner = snapshots
        .get("rust")
        .expect("ordinary overlay admission checked the Rust snapshot");
    for (file, counterfactual) in counterfactual_files {
        let path = rel_path_string(file);
        let source = if hypothetical {
            counterfactual.hypothetical.clone()
        } else {
            counterfactual.original.clone()
        };
        let witness = match rust.inner.selected_rust_counterfactual_publication(
            owner,
            file,
            source,
            cancellation,
        )? {
            ResolutionContentPublicationOutcome::Ready(content) => content.into_parts().0,
            ResolutionContentPublicationOutcome::Cancelled => {
                return Ok(SelectedResolutionOverlayInputsOutcome::Cancelled);
            }
            ResolutionContentPublicationOutcome::Stale(stale) => {
                return Ok(SelectedResolutionOverlayInputsOutcome::Stale(stale));
            }
            ResolutionContentPublicationOutcome::Unavailable(unavailable) => {
                return Ok(SelectedResolutionOverlayInputsOutcome::Unavailable(
                    unavailable,
                ));
            }
        };
        let oid = witness.blob_oid();
        content_mounts.push(
            SelectedResolutionContentMountRequest::new(
                witness,
                WorkspaceFileRow {
                    rel_path: path,
                    blob_oid: oid,
                },
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
            )
            .with_counterfactual_base_content_digest(
                brokk_bifrost_core::analyzer::canonical_hash::sha256_bytes(
                    counterfactual.original.as_bytes(),
                ),
            ),
        );
    }
    content_mounts.sort_by(|left, right| {
        left.persisted_relative_path()
            .cmp(right.persisted_relative_path())
    });
    let masks = content_mounts
        .iter()
        .map(|mount| {
            SelectedResolutionOverlayMask::replacement("rust", mount.persisted_relative_path())
        })
        .collect();
    Ok(SelectedResolutionOverlayInputsOutcome::Ready {
        masks,
        content_mounts,
    })
}

pub(super) fn validate_selected_rust_rename(
    rust: &RustAnalyzer,
    project: &dyn Project,
    result: &RenameResult,
    new_name: &str,
    cancellation: &crate::CancellationToken,
) -> RustRenameSafetyOutcome {
    let snapshots = rust.inner.selected_workspace_snapshots();
    let counterfactual_files = match rust_counterfactual_files(project, result, new_name) {
        Ok(files) => files,
        Err(reason) => return RustRenameSafetyOutcome::Indeterminate(reason),
    };
    let (original_masks, original_content_mounts) = match rust_rename_overlay_inputs(
        rust,
        snapshots.as_ref(),
        &counterfactual_files,
        false,
        cancellation,
    ) {
        Ok(SelectedResolutionOverlayInputsOutcome::Ready {
            masks,
            content_mounts,
        }) => (masks, content_mounts),
        Ok(outcome) => {
            return RustRenameSafetyOutcome::Indeterminate(format!(
                "original Rust content admission: {outcome:?}"
            ));
        }
        Err(error) => return RustRenameSafetyOutcome::Indeterminate(error.to_string()),
    };
    let names = [result.old_name.clone(), new_name.to_owned()];
    let original = match selected_rust_binding_world_with_candidates(
        rust,
        snapshots.as_ref(),
        RustBindingTargetProof::Current(&result.target),
        &original_masks,
        original_content_mounts,
        cancellation,
        &[],
        &names,
    ) {
        RustBindingWorldOutcome::Ready(world) => world,
        failure => {
            return RustRenameSafetyOutcome::Indeterminate(rust_binding_world_failure_detail(
                failure,
            ));
        }
    };
    let (hypothetical_masks, hypothetical_content_mounts) = match rust_rename_overlay_inputs(
        rust,
        snapshots.as_ref(),
        &counterfactual_files,
        true,
        cancellation,
    ) {
        Ok(SelectedResolutionOverlayInputsOutcome::Ready {
            masks,
            content_mounts,
        }) => (masks, content_mounts),
        Ok(outcome) => {
            return RustRenameSafetyOutcome::Indeterminate(format!(
                "hypothetical Rust content admission: {outcome:?}"
            ));
        }
        Err(error) => return RustRenameSafetyOutcome::Indeterminate(error.to_string()),
    };
    let seeds = original
        .sites()
        .iter()
        .filter_map(|site| {
            site.metadata().map(|metadata| {
                SelectedSemanticLocator::new(
                    "rust",
                    rel_path_string(site.file()),
                    metadata.site(),
                    crate::analyzer::resolution::LoweredSemanticRole::Reference,
                )
            })
        })
        .collect::<Vec<_>>();
    let hypothetical = match selected_rust_binding_world_with_candidates(
        rust,
        snapshots.as_ref(),
        RustBindingTargetProof::Established(original.target().clone()),
        &hypothetical_masks,
        hypothetical_content_mounts,
        cancellation,
        &seeds,
        &names,
    ) {
        RustBindingWorldOutcome::Ready(world) => world,
        failure => {
            return RustRenameSafetyOutcome::Indeterminate(rust_binding_world_failure_detail(
                failure,
            ));
        }
    };
    let original_states = match rust_rename_position_states(
        project,
        &original,
        &counterfactual_files,
        &result.old_name,
        new_name,
        false,
    ) {
        Ok(states) => states,
        Err(reason) => return RustRenameSafetyOutcome::Indeterminate(reason),
    };
    if let Err(reason) = validate_original_rename_positions(
        rust,
        result,
        &counterfactual_files,
        &original,
        &original_states,
    ) {
        return RustRenameSafetyOutcome::Indeterminate(reason);
    }
    let hypothetical_states = match rust_rename_position_states(
        project,
        &hypothetical,
        &counterfactual_files,
        &result.old_name,
        new_name,
        true,
    ) {
        Ok(states) => states,
        Err(reason) => return RustRenameSafetyOutcome::Indeterminate(reason),
    };
    let positions = original_states
        .keys()
        .chain(hypothetical_states.keys())
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut changed = BTreeSet::new();
    for position in positions {
        let (Some(original), Some(hypothetical)) = (
            original_states.get(&position),
            hypothetical_states.get(&position),
        ) else {
            return RustRenameSafetyOutcome::Indeterminate(format!(
                "counterfactual Rust rename changed the structured reference inventory at {position:?}"
            ));
        };
        if original.definitions == hypothetical.definitions {
            continue;
        }
        if original.completion != ResolutionCompletion::Complete
            || hypothetical.completion != ResolutionCompletion::Complete
        {
            return RustRenameSafetyOutcome::Indeterminate(format!(
                "counterfactual Rust rename changed an open binding at {position:?}: original={original:?}, hypothetical={hypothetical:?}"
            ));
        }
        changed.insert(position);
    }
    if !changed.is_empty() {
        return RustRenameSafetyOutcome::CapturedOrRebound { positions: changed };
    }
    let complete = original.completion() == &ResolutionCompletion::Complete
        && hypothetical.completion() == &ResolutionCompletion::Complete
        && original_states
            .values()
            .chain(hypothetical_states.values())
            .all(|state| state.completion == ResolutionCompletion::Complete);
    if complete {
        RustRenameSafetyOutcome::Safe
    } else {
        RustRenameSafetyOutcome::Indeterminate(format!(
            "counterfactual binding classes agree but selected evidence is open: original={:?}, hypothetical={:?}",
            original.completion(),
            hypothetical.completion(),
        ))
    }
}

/// Native-only rename preparation. Declaration metadata supplies the target,
/// native inverse evidence supplies edits, and two selected binding worlds
/// certify capture safety. No incumbent usage query supplies candidate sites.
pub(super) fn native_rust_rename(
    rust: &RustAnalyzer,
    project: &dyn Project,
    target: &CodeUnit,
    new_name: &str,
    cancellation: &crate::CancellationToken,
) -> Result<RenameResult, String> {
    use super::selected_reverse::{RustSelectedReverseOutcome, with_rust_selected_reverse_queries};
    use crate::analyzer::common::is_valid_rename_identifier;
    use crate::analyzer::usages::{DEFAULT_MAX_FILES, DEFAULT_MAX_USAGES};
    use crate::symbol_rename::{MAX_RENAME_IDENTIFIER_BYTES, RenameFileEdits};

    if new_name.len() > MAX_RENAME_IDENTIFIER_BYTES
        || !is_valid_rename_identifier(Language::Rust, new_name)
    {
        return Err("invalid Rust replacement identifier".to_owned());
    }
    let generation = project.analysis_generation();
    let selected = with_rust_selected_reverse_queries(rust, cancellation, |queries| {
        let Some(mut answers) = queries.inverse_for(std::slice::from_ref(target))? else {
            return Ok(None);
        };
        assert_eq!(answers.len(), 1);
        let answer = answers.pop().expect("one requested rename target");
        if answer.completeness != EdgeCompleteness::Complete
            || answer
                .edges
                .iter()
                .any(|edge| edge.proof != UsageProof::Proven)
        {
            return Err(crate::analyzer::store::StoreError::new(format!(
                "native rename reference evidence is incomplete or ambiguous: {answer:?}"
            )));
        }
        if answer.edges.len() > DEFAULT_MAX_USAGES {
            return Err(crate::analyzer::store::StoreError::new(
                "native rename exceeds the usage limit",
            ));
        }
        let mut files = BTreeMap::<ProjectFile, (String, Vec<RenameEdit>)>::new();
        let mut ranges = answer
            .edges
            .into_iter()
            .map(|edge| (edge.site.file, edge.site.range))
            .collect::<Vec<_>>();
        let target_source = project.read_source(target.source())?;
        let declaration = crate::analyzer::declaration_range::code_unit_declaration_name_range(
            rust,
            target.source(),
            &target_source,
            target,
        )
        .ok_or_else(|| {
            crate::analyzer::store::StoreError::new(
                "native rename target has no canonical declaration name",
            )
        })?;
        ranges.push((target.source().clone(), declaration));
        for (file, range) in ranges {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            if !files.contains_key(&file) {
                if files.len() >= DEFAULT_MAX_FILES {
                    return Err(crate::analyzer::store::StoreError::new(
                        "native rename exceeds the file limit",
                    ));
                }
                let source = project.read_source(&file)?;
                if !rust
                    .inner
                    .source_matches_selected_native_content(&file, &source)
                {
                    return Err(crate::analyzer::store::StoreError::new(format!(
                        "native rename source changed: {file}"
                    )));
                }
                files.insert(file.clone(), (source, Vec::new()));
            }
            let (source, edits) = files.get_mut(&file).expect("rename source was admitted");
            let spelling = source
                .get(range.start_byte..range.end_byte)
                .ok_or_else(|| {
                    crate::analyzer::store::StoreError::new(format!(
                        "native rename range is outside {file}: {range:?}"
                    ))
                })?;
            // Aliased references bind the target but their independent local
            // spelling must not be renamed with the declaration.
            if spelling != target.identifier() {
                continue;
            }
            edits.push(RenameEdit {
                start_byte: range.start_byte,
                end_byte: range.end_byte,
                new_text: new_name.to_owned(),
            });
        }
        let files = files
            .into_iter()
            .filter_map(|(file, (_, mut edits))| {
                edits.sort_by_key(|edit| (edit.start_byte, edit.end_byte));
                edits.dedup_by_key(|edit| (edit.start_byte, edit.end_byte));
                (!edits.is_empty()).then_some(RenameFileEdits { file, edits })
            })
            .collect();
        Ok(Some(RenameResult {
            target: target.clone(),
            old_name: target.identifier().to_owned(),
            files,
        }))
    });
    let result = match selected {
        RustSelectedReverseOutcome::Ready(Some(result)) => result,
        failure => {
            return Err(format!(
                "native rename reference selection failed: {failure:?}"
            ));
        }
    };
    let safety = validate_selected_rust_rename(rust, project, &result, new_name, cancellation);
    if cancellation.is_cancelled() || project.analysis_generation() != generation {
        return Err("native rename cancelled or selected generation changed".to_owned());
    }
    match safety {
        RustRenameSafetyOutcome::Safe => Ok(result),
        failure => Err(format!(
            "native rename cannot certify capture safety: {failure:?}"
        )),
    }
}
