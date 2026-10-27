//! Native Rust rename preparation from exact selected inverse evidence.
//!
//! Original and counterfactual selected binding worlds certify capture safety.
//! Diagnostic comparisons call this implementation; they do not supply edits.
//! The production Rust language support registers this exact provider.

use crate::analyzer::rust::RustAnalyzer;
use brokk_bifrost_analysis::analyzer::rename::exact::{
    ExactRenameEditIssue, ExactRenameHooks, RenameAssemblyIssue, RenameAssemblyLimits,
    RenameSourceIssue, assemble_exact_rename, check_exact_rename_edits, check_rename_authority,
};

use crate::analyzer::rust::selected_projection::rust_selected_workspace_identity_gap;

use brokk_bifrost_analysis::analyzer::rename::RenameEdit;

use brokk_bifrost_analysis::analyzer::rename::RenameResult;

use brokk_bifrost_analysis::analyzer::resolution::model::ResolutionCompletion;

use brokk_bifrost_analysis::analyzer::resolution::local_identity::SelectedSemanticLocator;

use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionLocated;

use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperationInput;

use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperationOpenOutcome;

use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperationOutcome;

use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedRustBindingDefinition;

use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedRustBindingDefinitionOutcome;

use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedRustBindingWorld;

use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedRustCallerReferenceOutcome;

use brokk_bifrost_analysis::analyzer::store::resolution_publication::ResolutionContentPublicationOutcome;

use brokk_bifrost_analysis::analyzer::store::resolution_publication::SelectedResolutionOverlayInputsOutcome;

use brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionContentMountRequest;

use brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionLanguage;

use brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionOverlayMask;

use brokk_bifrost_analysis::analyzer::store::WorkspaceFileRow;

use brokk_bifrost_analysis::analyzer::store::WorkspaceSnapshots;

use brokk_bifrost_core::analyzer::model::CodeUnit;

use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;

use brokk_bifrost_core::analyzer::model::Language;

use brokk_bifrost_core::analyzer::project::Project;

use brokk_bifrost_core::analyzer::model::ProjectFile;

use brokk_bifrost_core::analyzer::resolution_facts::{ResolutionNamespace, ResolutionSiteKind};
use brokk_bifrost_core::path_utils::rel_path_string;
use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};

#[doc(hidden)]
pub struct RustNativeRenameProvider;

impl brokk_bifrost_analysis::analyzer::rename::RenameProvider for RustNativeRenameProvider {
    fn rename(
        &self,
        analyzer: &dyn IAnalyzer,
        project: &dyn Project,
        target: &CodeUnit,
        new_name: &str,
    ) -> Result<RenameResult, brokk_bifrost_analysis::analyzer::rename::RenameFailure> {
        let rust =
            brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer::<RustAnalyzer>(
                analyzer,
            )
            .ok_or_else(|| {
                brokk_bifrost_analysis::analyzer::rename::RenameFailure {
                    kind: "incomplete_analysis",
                    message: "selected Rust analyzer is unavailable".into(),
                }
            })?;
        native_rust_rename(
            rust,
            project,
            target,
            new_name,
            &brokk_bifrost_core::cancellation::CancellationToken::default(),
        )
        .map_err(
            |message| brokk_bifrost_analysis::analyzer::rename::RenameFailure {
                kind: "incomplete_analysis",
                message,
            },
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[doc(hidden)]
pub struct RustRenamePosition {
    pub(crate) file: ProjectFile,
    pub(crate) start_byte: usize,
    pub(crate) end_byte: usize,
    namespace: ResolutionNamespace,
    site_kind: ResolutionSiteKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RustRenamePositionState {
    definitions: Vec<SelectedRustBindingDefinition>,
    completion: ResolutionCompletion,
}

#[derive(Debug, PartialEq, Eq)]
#[doc(hidden)]
pub enum RustRenameSafetyOutcome {
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

#[doc(hidden)]
pub enum RustBindingTargetProof<'a> {
    Current(&'a CodeUnit),
    Established(SelectedRustBindingDefinition),
}

#[derive(Debug)]
#[doc(hidden)]
pub enum RustBindingWorldOutcome {
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

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn selected_rust_binding_world(
    rust: &RustAnalyzer,
    snapshots: &WorkspaceSnapshots,
    target: RustBindingTargetProof<'_>,
    masks: &[SelectedResolutionOverlayMask],
    content_mounts: Vec<SelectedResolutionContentMountRequest>,
    cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
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
    cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
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
        check_exact_rename_edits(&original, &edits, &result.old_name, new_name).map_err(
            |issue| match issue {
                ExactRenameEditIssue::Overlap => "rename edits overlap".to_owned(),
                ExactRenameEditIssue::InexactReplacement(edit) => format!(
                    "rename edit is not an exact {:?} -> {:?} identifier replacement: {edit:?}",
                    result.old_name, new_name
                ),
            },
        )?;
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
    let declaration =
        brokk_bifrost_analysis::analyzer::declaration_range::code_unit_declaration_name_range(
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
    cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
) -> brokk_bifrost_analysis::analyzer::store::Result<SelectedResolutionOverlayInputsOutcome> {
    let overridden_paths = counterfactual_files
        .keys()
        .collect::<brokk_bifrost_core::hash::HashSet<_>>();
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

pub(crate) fn validate_selected_rust_rename(
    rust: &RustAnalyzer,
    project: &dyn Project,
    result: &RenameResult,
    new_name: &str,
    cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
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
                    brokk_bifrost_analysis::analyzer::resolution::fact_lowering::LoweredSemanticRole::Reference,
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
#[doc(hidden)]
pub fn native_rust_rename(
    rust: &RustAnalyzer,
    project: &dyn Project,
    target: &CodeUnit,
    new_name: &str,
    cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
) -> Result<RenameResult, String> {
    use crate::analyzer::rust::selected_reverse::RustSelectedReverseOutcome;

    use crate::analyzer::rust::selected_reverse::with_rust_selected_reverse_queries;

    use brokk_bifrost_analysis::analyzer::common::is_valid_rename_identifier;

    use brokk_bifrost_analysis::analyzer::rename::MAX_RENAME_IDENTIFIER_BYTES;

    use brokk_bifrost_analysis::analyzer::usages::finder::DEFAULT_MAX_FILES;

    use brokk_bifrost_analysis::analyzer::usages::finder::DEFAULT_MAX_USAGES;

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
        let assembled = assemble_exact_rename(
            rust,
            project,
            target,
            new_name,
            &answer,
            RenameAssemblyLimits {
                max_usages: DEFAULT_MAX_USAGES,
                max_files: DEFAULT_MAX_FILES,
            },
            cancellation,
            &RustRenameHooks(rust),
        )
        .map_err(rename_assembly_failure)?;
        Ok(assembled.map(|assembled| assembled.result))
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
    if check_rename_authority(project, generation, cancellation).is_err() {
        return Err("native rename cancelled or selected generation changed".to_owned());
    }
    match safety {
        RustRenameSafetyOutcome::Safe => Ok(result),
        failure => Err(format!(
            "native rename cannot certify capture safety: {failure:?}"
        )),
    }
}

struct RustRenameHooks<'a>(&'a RustAnalyzer);

impl ExactRenameHooks for RustRenameHooks<'_> {
    type FileState = ();

    fn admit_source(&self, file: &ProjectFile, source: &str) -> Result<(), RenameSourceIssue> {
        if !self
            .0
            .inner
            .source_matches_selected_native_content(file, source)
        {
            return Err(RenameSourceIssue::ContentChanged);
        }
        Ok(())
    }
}

fn rename_assembly_failure(
    issue: RenameAssemblyIssue<'_>,
) -> brokk_bifrost_analysis::analyzer::store::StoreError {
    use brokk_bifrost_analysis::analyzer::store::StoreError;
    let message = match issue {
        RenameAssemblyIssue::IncompleteInventory(result)
        | RenameAssemblyIssue::UnprovenInventory(result) => {
            format!("native rename reference evidence is incomplete or ambiguous: {result:?}")
        }
        RenameAssemblyIssue::TooManyUsages(_) => "native rename exceeds the usage limit".into(),
        RenameAssemblyIssue::TooManyFiles => "native rename exceeds the file limit".into(),
        RenameAssemblyIssue::ReadSource(error) => return error.into(),
        RenameAssemblyIssue::Source {
            file,
            issue: RenameSourceIssue::ContentChanged,
        } => format!("native rename source changed: {file}"),
        RenameAssemblyIssue::Source {
            issue: RenameSourceIssue::ParseFailed,
            ..
        }
        | RenameAssemblyIssue::MissingReferenceName(_) => {
            unreachable!("Rust rename uses exact inverse ranges without parsing")
        }
        RenameAssemblyIssue::MissingDeclarationName => {
            "native rename target has no canonical declaration name".into()
        }
        RenameAssemblyIssue::RangeOutsideSource { file, range } => {
            format!("native rename range is outside {file}: {range:?}")
        }
        RenameAssemblyIssue::DeclarationSpellingMismatch => {
            "native rename declaration range does not contain its structured identifier".into()
        }
        RenameAssemblyIssue::Edit(ExactRenameEditIssue::Overlap) => {
            "native rename edits overlap".into()
        }
        RenameAssemblyIssue::Edit(ExactRenameEditIssue::InexactReplacement(edit)) => {
            format!("native rename edit is not an exact identifier replacement: {edit:?}")
        }
    };
    StoreError::new(message)
}
