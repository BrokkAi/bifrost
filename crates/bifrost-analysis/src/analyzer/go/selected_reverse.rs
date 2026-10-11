//! Selected Go reverse references. Candidate names come from the sealed
//! reference-lookup identity index and Go package rows; summary rows confirm
//! name candidates, keyed receiver anchors confirm member accesses, the native
//! point path handles unknown receiver types, and the selected Go forward
//! context handles only the remaining fallback causes.

use super::GoAnalyzer;
use crate::CancellationToken;
use crate::analyzer::go::native_points::{
    GoNativePointRequest, GoNativePointRequestOpen, GoPointBindingInitializer,
};
use crate::analyzer::languages::BoundedReceiverQuery;
use crate::analyzer::resolution::seam_profile::{GoRenamePhase, go_rename_phase};
use crate::analyzer::resolution::{FactReferenceSiteMetadata, ResolutionCompletion};
use crate::analyzer::store::resolution_operation::go_receiver_anchor::{
    GoReceiverAnchorMember, GoReceiverTypeAnchor,
};
use crate::analyzer::store::resolution_operation::go_reverse_rows::{
    GoReverseBindingTarget, GoReverseCandidate, GoReverseCandidateOutcome, GoReverseConfirmed,
    GoReverseMemberConfirmation,
};
use crate::analyzer::store::resolution_operation::{
    SelectedResolutionContextMetrics, SelectedResolutionOperation,
    SelectedResolutionOperationInput, SelectedResolutionOperationOpenOutcome,
    SelectedResolutionOperationOutcome,
};
use crate::analyzer::store::resolution_publication::SelectedResolutionOverlayInputsOutcome;
use crate::analyzer::store::resolution_selection::SelectedResolutionLanguage;
use crate::analyzer::store::{Result, StoreError};
use crate::analyzer::structural::EdgeProvenance;
use crate::analyzer::structural::SiteClass;
use crate::analyzer::structural::reference_edges::{
    EdgeCompleteness, EdgeDerivationResult, EdgeIncompleteReason, EdgeSite, ReferenceEdgeRow,
    ReferenceSiteClassifier, classify_owner_relation,
};
use crate::analyzer::usages::{UsageHitKind, UsageProof};
use crate::analyzer::{
    CodeUnit, CodeUnitIndex, IAnalyzer, Language, ProjectFile, Range, resolve_analyzer,
};
use crate::hash::HashMap;
use crate::text_utils::{compute_line_starts, find_line_index_for_offset};
use brokk_bifrost_core::analyzer::go_facts::GoSourceTypeShape;
use brokk_bifrost_core::analyzer::resolution_facts::{
    ResolutionCallableReceiverOrigin, ResolutionNamespace, ResolutionSiteKind,
};
use std::sync::Arc;

#[derive(Debug)]
pub enum GoSelectedReverseOutcome<T> {
    Ready(T),
    Unavailable(String),
    Stale(String),
    Cancelled,
    StoreError(String),
}

/// Resolve one target against the selected Go package/import inventory.
pub fn go_selected_inverse_for(
    go: &GoAnalyzer,
    target: &CodeUnit,
    cancellation: &CancellationToken,
) -> GoSelectedReverseOutcome<EdgeDerivationResult> {
    go_selected_inverse_for_with_test_inclusion(go, target, true, cancellation)
}

pub(crate) fn go_selected_inverse_for_with_test_inclusion(
    go: &GoAnalyzer,
    target: &CodeUnit,
    include_tests: bool,
    cancellation: &CancellationToken,
) -> GoSelectedReverseOutcome<EdgeDerivationResult> {
    match go_selected_inverse_for_inner(go, target, include_tests, cancellation, false, None) {
        Ok(outcome) => outcome,
        Err(error) => GoSelectedReverseOutcome::StoreError(error.to_string()),
    }
}

pub(crate) fn go_selected_inverse_for_rename_original(
    go: &GoAnalyzer,
    target: &CodeUnit,
    new_name: &str,
    cancellation: &CancellationToken,
) -> (
    GoSelectedReverseOutcome<EdgeDerivationResult>,
    Option<String>,
) {
    let mut conflict = None;
    let outcome = match go_selected_inverse_for_inner(
        go,
        target,
        true,
        cancellation,
        true,
        Some((new_name, &mut conflict)),
    ) {
        Ok(outcome) => outcome,
        Err(error) => GoSelectedReverseOutcome::StoreError(error.to_string()),
    };
    (outcome, conflict)
}

fn go_selected_inverse_for_inner(
    go: &GoAnalyzer,
    target: &CodeUnit,
    include_tests: bool,
    cancellation: &CancellationToken,
    record_initial_rename_phases: bool,
    rename_check: Option<(&str, &mut Option<String>)>,
) -> Result<GoSelectedReverseOutcome<EdgeDerivationResult>> {
    if cancellation.is_cancelled() {
        return Ok(GoSelectedReverseOutcome::Cancelled);
    }
    let snapshots = go.inner.selected_workspace_snapshots();
    let Some(snapshot) = snapshots.get("go") else {
        return Ok(GoSelectedReverseOutcome::Unavailable(
            "the workspace has no selected Go snapshot".into(),
        ));
    };
    let Some(profile) = go.native_context_profile() else {
        return Ok(GoSelectedReverseOutcome::Unavailable(
            "the Go package/import profile is unavailable".into(),
        ));
    };
    let Some(context) = go
        .inner
        .analyzer_store()
        .selected_go_context(snapshot, &profile)?
    else {
        return Ok(GoSelectedReverseOutcome::Unavailable(
            "the selected Go package/import publication is unavailable".into(),
        ));
    };
    let (masks, content_mounts) = match go
        .inner
        .selected_resolution_overlay_inputs(snapshots.as_ref(), cancellation)?
    {
        SelectedResolutionOverlayInputsOutcome::Ready {
            masks,
            content_mounts,
        } => (masks, content_mounts),
        SelectedResolutionOverlayInputsOutcome::Unavailable(reason) => {
            return Ok(GoSelectedReverseOutcome::Unavailable(format!("{reason:?}")));
        }
        SelectedResolutionOverlayInputsOutcome::Stale(reason) => {
            return Ok(GoSelectedReverseOutcome::Stale(format!("{reason:?}")));
        }
        SelectedResolutionOverlayInputsOutcome::Cancelled => {
            return Ok(GoSelectedReverseOutcome::Cancelled);
        }
    };
    let languages = [SelectedResolutionLanguage::new("go", Language::Go)];
    let input = SelectedResolutionOperationInput::new(
        go.inner.project(),
        go.inner.workspace_id(),
        snapshots.as_ref(),
        &languages,
        &masks,
    )
    .with_content_mounts(content_mounts);
    let mut operation = match go
        .inner
        .analyzer_store()
        .open_selected_resolution_operation(input, cancellation)?
    {
        SelectedResolutionOperationOpenOutcome::Ready(operation) => *operation,
        SelectedResolutionOperationOpenOutcome::Unavailable(reason) => {
            return Ok(GoSelectedReverseOutcome::Unavailable(format!("{reason:?}")));
        }
        SelectedResolutionOperationOpenOutcome::Stale(reason) => {
            return Ok(GoSelectedReverseOutcome::Stale(format!("{reason:?}")));
        }
        SelectedResolutionOperationOpenOutcome::Cancelled => {
            return Ok(GoSelectedReverseOutcome::Cancelled);
        }
    };
    let generation = go.inner.project().analysis_generation();
    let candidate_phase =
        record_initial_rename_phases.then(|| go_rename_phase(GoRenamePhase::CandidateEnumeration));
    let candidates = match operation.go_reverse_candidate_sites(
        target,
        context.context_id,
        include_tests,
        &profile,
        cancellation,
    )? {
        GoReverseCandidateOutcome::Ready(candidates) => candidates,
        GoReverseCandidateOutcome::Unavailable(reason) => {
            return Ok(GoSelectedReverseOutcome::Unavailable(reason));
        }
        GoReverseCandidateOutcome::Cancelled => {
            return Ok(GoSelectedReverseOutcome::Cancelled);
        }
    };
    let rename_context = candidates.rename_context();
    drop(candidate_phase);
    let mut context_metrics = SelectedResolutionContextMetrics;
    let confirmation_phase =
        record_initial_rename_phases.then(|| go_rename_phase(GoRenamePhase::Confirmation));
    let mut point_request = None;
    let confirmed = match operation.confirm_go_reverse_candidates(
        context.context_id,
        candidates,
        cancellation,
        &mut context_metrics,
        |operation, candidate, metadata| {
            confirm_go_reverse_member_access(
                go,
                operation,
                context.context_id,
                &mut point_request,
                candidate,
                metadata,
                cancellation,
            )
        },
    )? {
        SelectedResolutionOperationOutcome::Native(confirmed) => confirmed,
        SelectedResolutionOperationOutcome::Unavailable(reason) => {
            return Ok(GoSelectedReverseOutcome::Unavailable(format!("{reason:?}")));
        }
        SelectedResolutionOperationOutcome::Stale(reason) => {
            return Ok(GoSelectedReverseOutcome::Stale(format!("{reason:?}")));
        }
        SelectedResolutionOperationOutcome::Cancelled(_) => {
            return Ok(GoSelectedReverseOutcome::Cancelled);
        }
    };
    drop(confirmation_phase);
    if let Some((new_name, conflict)) = rename_check {
        let references = confirmed
            .references
            .iter()
            .filter_map(|reference| {
                let metadata = reference.answer.site_metadata()?;
                if !metadata.unqualified() {
                    return None;
                }
                let site = reference.locator.source_site()?;
                let source = go.indexed_source(&ProjectFile::new(
                    go.inner.project().root(),
                    reference.locator.relative_path(),
                ))?;
                (source.get(metadata.start_byte()..metadata.end_byte())
                    == Some(target.identifier()))
                .then_some((reference.locator.relative_path(), site))
            })
            .map(|(relative_path, site)| {
                let mount = operation
                    .mount_table()
                    .mount_for_path("go", relative_path)?
                    .ok_or_else(|| {
                        StoreError::new(format!(
                            "selected Go rename reference has no mount: {relative_path}"
                        ))
                    })?;
                Ok((mount.ordinal().get(), site.get()))
            })
            .collect::<Result<Vec<_>>>()?;
        let capture_phase = go_rename_phase(GoRenamePhase::CaptureCheck);
        *conflict = operation.go_rename_conflict(
            &rename_context,
            target,
            &references,
            new_name,
            cancellation,
        )?;
        drop(capture_phase);
    }
    if go.inner.project().analysis_generation() != generation {
        return Ok(GoSelectedReverseOutcome::Stale(
            "Go selected reverse query crossed an analyzer generation".into(),
        ));
    }
    let answer = project_confirmed_references(go, target, generation, confirmed, cancellation)?;
    if go.inner.project().analysis_generation() != generation {
        return Ok(GoSelectedReverseOutcome::Stale(
            "Go selected reverse projection crossed an analyzer generation".into(),
        ));
    }
    Ok(GoSelectedReverseOutcome::Ready(answer))
}

fn confirm_go_reverse_member_access<'a>(
    go: &'a GoAnalyzer,
    operation: &SelectedResolutionOperation<'_, '_>,
    context_id: i64,
    point_request: &mut Option<Box<GoNativePointRequest<'a>>>,
    candidate: &GoReverseCandidate,
    metadata: FactReferenceSiteMetadata,
    cancellation: &CancellationToken,
) -> Result<crate::analyzer::usages::get_definition::BoundedResolution<GoReverseMemberConfirmation>>
{
    use crate::analyzer::usages::get_definition::BoundedResolution;
    use crate::analyzer::usages::receiver_analysis::ReceiverAnalysisWork;

    if cancellation.is_cancelled() {
        return Ok(BoundedResolution::Cancelled {
            work: ReceiverAnalysisWork::default(),
        });
    }

    let file = ProjectFile::new(go.inner.project().root(), candidate.locator.relative_path());
    let source = go.indexed_source(&file).ok_or_else(|| {
        StoreError::new(format!(
            "selected Go member reference has no indexed source: {file}"
        ))
    })?;
    if !go
        .inner
        .source_matches_selected_native_content(&file, &source)
    {
        return Err(StoreError::new(format!(
            "selected Go member reference source changed before point confirmation: {file}"
        )));
    }
    let start_byte = metadata.start_byte();
    let end_byte = metadata.end_byte();
    let text = source.get(start_byte..end_byte).ok_or_else(|| {
        StoreError::new(format!(
            "selected Go member reference range is outside indexed source: {file} {start_byte}..{end_byte}"
        ))
    })?;
    let line_starts = compute_line_starts(&source);
    let site = crate::analyzer::usages::get_definition::ResolvedReferenceSite {
        path: candidate.locator.relative_path().to_owned(),
        text: text.to_owned(),
        range: Range {
            start_byte,
            end_byte,
            start_line: find_line_index_for_offset(&line_starts, start_byte) + 1,
            end_line: find_line_index_for_offset(&line_starts, end_byte.saturating_sub(1)) + 1,
        },
        focus_start_byte: start_byte,
        focus_end_byte: end_byte,
    };
    let tree = crate::analyzer::usages::get_definition::parse_go_tree(&source);
    let receiver_member = match tree.as_ref() {
        Some(tree) => resolve_go_reverse_receiver_anchor_member(
            operation,
            context_id,
            candidate,
            &site,
            tree,
            &source,
            cancellation,
        )?,
        None => GoReceiverAnchorMember::Unknown,
    };
    if cancellation.is_cancelled() {
        return Ok(BoundedResolution::Cancelled {
            work: ReceiverAnalysisWork::default(),
        });
    }
    match receiver_member {
        GoReceiverAnchorMember::Known { member, .. } => {
            return Ok(BoundedResolution::Complete {
                value: GoReverseMemberConfirmation::ReceiverAnchor(member),
                work: ReceiverAnalysisWork::default(),
            });
        }
        GoReceiverAnchorMember::Unknown => {
            crate::analyzer::resolution::seam_profile::record_go_reverse_member_access_unknown();
        }
    }
    if point_request.is_none() {
        match GoNativePointRequest::open(go, go.semantic_model_overlay(), cancellation)? {
            GoNativePointRequestOpen::Ready(request) => *point_request = Some(request),
            GoNativePointRequestOpen::Unavailable { .. } => {
                return Ok(BoundedResolution::Complete {
                    value: GoReverseMemberConfirmation::Point(None),
                    work: ReceiverAnalysisWork::default(),
                });
            }
            GoNativePointRequestOpen::Cancelled => {
                return Ok(BoundedResolution::Cancelled {
                    work: ReceiverAnalysisWork::default(),
                });
            }
        }
    }
    let query = BoundedReceiverQuery {
        analyzer: go,
        file: &file,
        source: &source,
        tree: tree.as_ref(),
        site: &site,
        budget: crate::analyzer::usages::receiver_analysis::INTERACTIVE_TYPE_LOOKUP_BUDGET,
        cancellation: Some(cancellation),
    };
    Ok(
        match point_request
            .as_mut()
            .expect("member point request was opened")
            .resolve_definition_answer(query)
        {
            BoundedResolution::Complete { value, work } => BoundedResolution::Complete {
                value: GoReverseMemberConfirmation::Point(value.map(Box::new)),
                work,
            },
            BoundedResolution::Exceeded { limit, work } => {
                BoundedResolution::Exceeded { limit, work }
            }
            BoundedResolution::Cancelled { work } => BoundedResolution::Cancelled { work },
        },
    )
}

fn resolve_go_reverse_receiver_anchor_member(
    operation: &SelectedResolutionOperation<'_, '_>,
    context_id: i64,
    candidate: &GoReverseCandidate,
    site: &crate::analyzer::usages::get_definition::ResolvedReferenceSite,
    tree: &tree_sitter::Tree,
    source: &str,
    cancellation: &CancellationToken,
) -> Result<GoReceiverAnchorMember> {
    if cancellation.is_cancelled() {
        return Ok(GoReceiverAnchorMember::Unknown);
    }
    let Some(anchor) =
        crate::analyzer::go::native_points::go_point_receiver_anchor(site, tree, source)
    else {
        return Ok(GoReceiverAnchorMember::Unknown);
    };
    let path = candidate.locator.relative_path();
    if let Some(binding) = anchor.binding.as_ref() {
        if let Some(initializer) = binding.initializer.as_ref() {
            return resolve_go_reverse_binding_initializer_member(
                operation,
                context_id,
                candidate,
                path,
                initializer,
                &binding.member_name,
                cancellation,
            );
        }
        let Some((package_id, source_role, binding_anchor)) = operation
            .go_point_binding_type_anchor(
                context_id,
                path,
                binding.declaration_start_byte,
                binding.declaration_end_byte,
                &binding.member_name,
                cancellation,
            )?
        else {
            return Ok(GoReceiverAnchorMember::Unknown);
        };
        if package_id != candidate.package_id || source_role != candidate.source_role {
            return Ok(GoReceiverAnchorMember::Unknown);
        }
        let first_member = operation.resolve_go_receiver_anchor_member(
            context_id,
            package_id,
            &source_role,
            &binding_anchor,
            cancellation,
        )?;
        let Some(followup_member_name) = binding.followup_member_name.as_ref() else {
            return Ok(first_member);
        };
        debug_assert_eq!(followup_member_name, &anchor.member_name);
        let GoReceiverAnchorMember::Known { member, .. } = first_member else {
            return Ok(GoReceiverAnchorMember::Unknown);
        };
        let field_anchor = GoReceiverTypeAnchor::field_type(member, anchor.member_name.clone());
        return operation.resolve_go_receiver_anchor_member(
            context_id,
            package_id,
            &source_role,
            &field_anchor,
            cancellation,
        );
    }
    let (package_id, source_role, selected_anchor): (i64, String, GoReceiverTypeAnchor) =
        if let Some(owner_type_name) = anchor.owner_type_name.as_deref() {
            let Some((package_id, source_role, selected_anchor)) = operation
                .go_point_receiver_type_anchor(
                    context_id,
                    path,
                    anchor.kind,
                    owner_type_name,
                    &anchor.name,
                    &anchor.member_name,
                    cancellation,
                )?
            else {
                return Ok(GoReceiverAnchorMember::Unknown);
            };
            (package_id, source_role, selected_anchor)
        } else {
            let Some((call_start, call_end)) = anchor.owner_call_reference else {
                return Ok(GoReceiverAnchorMember::Unknown);
            };
            let Some(call_reference) =
                operation.go_point_call_reference_at(path, call_start, call_end, cancellation)?
            else {
                return Ok(GoReceiverAnchorMember::Unknown);
            };
            let Some((package_id, source_role, call_anchor)) = operation
                .go_point_callable_result_anchor(context_id, path, call_reference, cancellation)?
            else {
                return Ok(GoReceiverAnchorMember::Unknown);
            };
            let Some(call_types) = operation.go_receiver_anchor_types(
                context_id,
                package_id,
                &source_role,
                &call_anchor,
                cancellation,
            )?
            else {
                return Ok(GoReceiverAnchorMember::Unknown);
            };
            let Some(owner_type_name) =
                operation.go_point_type_name(call_types.receiver_type.identity(), cancellation)?
            else {
                return Ok(GoReceiverAnchorMember::Unknown);
            };
            let Some((member_package_id, member_source_role, selected_anchor)) = operation
                .go_point_receiver_type_anchor(
                    context_id,
                    path,
                    anchor.kind,
                    &owner_type_name,
                    &anchor.name,
                    &anchor.member_name,
                    cancellation,
                )?
            else {
                return Ok(GoReceiverAnchorMember::Unknown);
            };
            if package_id != member_package_id || source_role != member_source_role {
                return Ok(GoReceiverAnchorMember::Unknown);
            }
            (member_package_id, member_source_role, selected_anchor)
        };
    if package_id != candidate.package_id || source_role != candidate.source_role {
        return Ok(GoReceiverAnchorMember::Unknown);
    }
    operation.resolve_go_receiver_anchor_member(
        context_id,
        package_id,
        &source_role,
        &selected_anchor,
        cancellation,
    )
}

fn resolve_go_reverse_binding_initializer_member(
    operation: &SelectedResolutionOperation<'_, '_>,
    context_id: i64,
    candidate: &GoReverseCandidate,
    path: &str,
    initializer: &GoPointBindingInitializer,
    target_member: &str,
    cancellation: &CancellationToken,
) -> Result<GoReceiverAnchorMember> {
    match initializer {
        GoPointBindingInitializer::CallResult {
            function_start_byte,
            function_end_byte,
        } => {
            let Some(call_reference) = operation.go_point_call_reference_at(
                path,
                *function_start_byte,
                *function_end_byte,
                cancellation,
            )?
            else {
                return Ok(GoReceiverAnchorMember::Unknown);
            };
            let Some((package_id, source_role, call_anchor)) = operation
                .go_point_callable_result_anchor(context_id, path, call_reference, cancellation)?
            else {
                return Ok(GoReceiverAnchorMember::Unknown);
            };
            if package_id != candidate.package_id || source_role != candidate.source_role {
                return Ok(GoReceiverAnchorMember::Unknown);
            }
            let selected_anchor = GoReceiverTypeAnchor {
                member_name: target_member.to_owned(),
                ..call_anchor
            };
            operation.resolve_go_receiver_anchor_member(
                context_id,
                package_id,
                &source_role,
                &selected_anchor,
                cancellation,
            )
        }
        GoPointBindingInitializer::FieldChain {
            root_declaration_start_byte,
            root_declaration_end_byte,
            member_names,
        } => {
            let Some(first_member) = member_names.first() else {
                return Ok(GoReceiverAnchorMember::Unknown);
            };
            let Some((package_id, source_role, root_anchor)) = operation
                .go_point_binding_type_anchor(
                    context_id,
                    path,
                    *root_declaration_start_byte,
                    *root_declaration_end_byte,
                    first_member,
                    cancellation,
                )?
            else {
                return Ok(GoReceiverAnchorMember::Unknown);
            };
            if package_id != candidate.package_id || source_role != candidate.source_role {
                return Ok(GoReceiverAnchorMember::Unknown);
            }
            let mut resolved = operation.resolve_go_receiver_anchor_member(
                context_id,
                package_id,
                &source_role,
                &root_anchor,
                cancellation,
            )?;
            for member_name in member_names.iter().skip(1) {
                let GoReceiverAnchorMember::Known { member, .. } = resolved else {
                    return Ok(GoReceiverAnchorMember::Unknown);
                };
                let field_anchor = GoReceiverTypeAnchor::field_type(member, member_name.clone());
                resolved = operation.resolve_go_receiver_anchor_member(
                    context_id,
                    package_id,
                    &source_role,
                    &field_anchor,
                    cancellation,
                )?;
            }
            let GoReceiverAnchorMember::Known { member, .. } = resolved else {
                return Ok(GoReceiverAnchorMember::Unknown);
            };
            let field_anchor = GoReceiverTypeAnchor::field_type(member, target_member.to_owned());
            operation.resolve_go_receiver_anchor_member(
                context_id,
                package_id,
                &source_role,
                &field_anchor,
                cancellation,
            )
        }
    }
}

fn project_confirmed_references(
    go: &GoAnalyzer,
    target: &CodeUnit,
    generation: u64,
    confirmed: GoReverseConfirmed,
    cancellation: &CancellationToken,
) -> Result<EdgeDerivationResult> {
    let mut reasons = Vec::new();
    if !confirmed.candidate_inventory_complete {
        reasons.push(EdgeIncompleteReason::InverseIndexReferenceEnumerationIncomplete);
    }
    if confirmed.completion != ResolutionCompletion::Complete {
        reasons.push(EdgeIncompleteReason::InverseIndexResolutionIncomplete);
    }
    let mut selected_aliases = Vec::new();
    for reference in &confirmed.references {
        let Some(metadata) = reference.answer.site_metadata() else {
            continue;
        };
        if metadata.site_kind() != ResolutionSiteKind::TypeReference
            || metadata.namespace() != ResolutionNamespace::Type
            || !reference
                .answer
                .binding()
                .targets()
                .contains(&confirmed.target)
        {
            continue;
        }
        selected_aliases.extend(qualified_alias_owners_for_reference(go, reference, target)?);
    }
    let mut files = HashMap::<ProjectFile, GoSelectedReferenceFile<'_>>::default();
    let mut edges = Vec::new();
    for reference in confirmed.references {
        if cancellation.is_cancelled() {
            return Err(StoreError::new("Go selected reverse query was cancelled"));
        }
        let answer = reference.answer;
        let Some(metadata) = answer.site_metadata() else {
            push_reason(
                &mut reasons,
                EdgeIncompleteReason::InverseIndexMetadataIncomplete,
            );
            continue;
        };
        let directly_bound = answer.binding().targets().contains(&confirmed.target);
        // Go aliases bind to their declaration spelling, while their selected
        // type frontier carries the aliased named type identity. Count that
        // only for a structured type-reference site; a value whose receiver
        // happens to have this type is not a reference to the type name.
        let transparent_type_alias = metadata.site_kind() == ResolutionSiteKind::TypeReference
            && metadata.namespace() == ResolutionNamespace::Type
            && (answer
                .projected_frontiers()
                .iter()
                .flat_map(|frontier| frontier.possible_values())
                .any(|value| value.ty().identity() == confirmed.target)
                || reference
                    .binding_targets
                    .iter()
                    .any(|alias| selected_aliases.contains(alias)));
        if !directly_bound && !transparent_type_alias {
            continue;
        }
        let file = ProjectFile::new(go.inner.project().root(), reference.locator.relative_path());
        if !files.contains_key(&file) {
            let source = go.indexed_source(&file).ok_or_else(|| {
                StoreError::new(format!(
                    "selected Go reference has no indexed source: {file}"
                ))
            })?;
            if !go
                .inner
                .source_matches_selected_native_content(&file, &source)
            {
                return Err(StoreError::new(format!(
                    "selected Go reference source changed before projection: {file}"
                )));
            }
            files.insert(
                file.clone(),
                GoSelectedReferenceFile::new(go, &file, &source),
            );
        }
        let projected_file = files.get(&file).expect("selected Go source was projected");
        let owner = reference.owner;
        if answer
            .reference_owner()
            .is_some_and(|owner| owner.is_some())
            && owner.is_none()
        {
            push_reason(
                &mut reasons,
                EdgeIncompleteReason::InverseIndexMetadataIncomplete,
            );
        }
        let owner_relation = classify_owner_relation(go, owner.as_ref(), target);
        let reference_kind = projected_file.classifier.as_ref().and_then(|classifier| {
            classifier.classify_reference_kind(metadata.start_byte(), metadata.end_byte(), target)
        });
        let ast_id = projected_file
            .classifier
            .as_ref()
            .and_then(|classifier| classifier.ast_id(metadata.start_byte(), metadata.end_byte()));
        if projected_file.classifier.is_none() {
            push_reason(
                &mut reasons,
                EdgeIncompleteReason::InverseIndexMetadataIncomplete,
            );
        }
        edges.push(ReferenceEdgeRow {
            site: EdgeSite {
                file,
                range: projected_file.range(metadata.start_byte(), metadata.end_byte()),
                ast_id,
                enclosing: owner,
            },
            target: target.clone(),
            reference_kind,
            proof: if directly_bound
                && answer.binding().targets().len() == 1
                && answer.binding().completion() == &ResolutionCompletion::Complete
            {
                UsageProof::Proven
            } else {
                UsageProof::Unproven
            },
            ambiguous_candidate: false,
            usage_kind: go_selected_usage_kind(
                metadata,
                owner_relation,
                target,
                projected_file
                    .is_receiver_type_reference(metadata.start_byte(), metadata.end_byte()),
            ),
            site_class: SiteClass::UseSite,
            owner_relation,
            provenance: EdgeProvenance::Inverse,
            generation,
        });
    }
    Ok(EdgeDerivationResult {
        edges,
        completeness: if reasons.is_empty() {
            EdgeCompleteness::Complete
        } else {
            EdgeCompleteness::Incomplete { reasons }
        },
        provenance: EdgeProvenance::Inverse,
        generation,
    })
}

/// A direct `type Alias = pkg.Target` reference can be forward-confirmed at
/// the alias declaration even when the importing package's selected context
/// cannot project the alias type frontier. Keep that structured proof local to
/// this reverse query, then admit references that the selected forward pass
/// binds to that exact alias declaration.
fn qualified_alias_owners_for_reference(
    go: &GoAnalyzer,
    reference: &crate::analyzer::store::resolution_operation::go_reverse_rows::GoReverseConfirmedReference,
    target: &CodeUnit,
) -> Result<Vec<GoReverseBindingTarget>> {
    let Some(metadata) = reference.answer.site_metadata() else {
        return Ok(Vec::new());
    };
    let file = ProjectFile::new(go.inner.project().root(), reference.locator.relative_path());
    let Some(source) = go.indexed_source(&file) else {
        return Ok(Vec::new());
    };
    if !go
        .inner
        .source_matches_selected_native_content(&file, &source)
    {
        return Err(StoreError::new(format!(
            "selected Go alias source changed before reverse projection: {file}"
        )));
    }
    let Some(facts) = go
        .inner
        .canonical_go_source_facts(&file, &go.memo_caches.source_facts)
    else {
        return Ok(Vec::new());
    };
    let mut owners = Vec::new();
    for alias in &facts.facts.aliases {
        let Some(target_type) = alias.target else {
            continue;
        };
        let target_type = &facts.facts.types[target_type.index()];
        let GoSourceTypeShape::Named(name) = &target_type.shape else {
            continue;
        };
        if name.path().len() != 2
            || name.path().get(1).map(String::as_str) != Some(target.identifier())
        {
            continue;
        }
        let target_range = facts.source.occurrence(target_type.occurrence).range;
        if metadata.start_byte() < target_range.start_byte
            || metadata.end_byte() > target_range.end_byte
        {
            continue;
        }
        let declaration = facts.source.declaration(alias.declaration);
        let name = declaration
            .name
            .expect("a Go type alias declaration has a source name");
        owners.push(GoReverseBindingTarget::Lexical {
            source_file: file.clone(),
            name_range: facts.source.occurrence(name).range,
        });
        if let Some(units) = facts.declaration_units.get(&alias.declaration) {
            owners.extend(units.iter().cloned().map(GoReverseBindingTarget::Unit));
        }
    }
    Ok(owners)
}

fn push_reason(reasons: &mut Vec<EdgeIncompleteReason>, reason: EdgeIncompleteReason) {
    if !reasons.contains(&reason) {
        reasons.push(reason);
    }
}

struct GoSelectedReferenceFile<'analyzer> {
    source_len: usize,
    line_starts: Box<[usize]>,
    receiver_type_references: Box<[(usize, usize)]>,
    classifier: Option<ReferenceSiteClassifier<'analyzer>>,
}

impl<'analyzer> GoSelectedReferenceFile<'analyzer> {
    fn new(go: &'analyzer GoAnalyzer, file: &ProjectFile, source: &str) -> Self {
        Self {
            source_len: source.len(),
            line_starts: compute_line_starts(source).into_boxed_slice(),
            receiver_type_references: go_receiver_type_reference_ranges(source),
            classifier: ReferenceSiteClassifier::new(go, file),
        }
    }

    fn is_receiver_type_reference(&self, start_byte: usize, end_byte: usize) -> bool {
        self.receiver_type_references
            .binary_search(&(start_byte, end_byte))
            .is_ok()
    }

    fn range(&self, start_byte: usize, end_byte: usize) -> Range {
        assert!(
            start_byte <= end_byte && end_byte <= self.source_len,
            "selected Go reference range must fit indexed source: {start_byte}..{end_byte} of {}",
            self.source_len,
        );
        Range {
            start_byte,
            end_byte,
            start_line: find_line_index_for_offset(&self.line_starts, start_byte) + 1,
            end_line: find_line_index_for_offset(&self.line_starts, end_byte.saturating_sub(1)) + 1,
        }
    }
}

pub(super) fn go_receiver_type_reference_ranges(source: &str) -> Box<[(usize, usize)]> {
    let Some(tree) = crate::analyzer::usages::get_definition::parse_go_tree(source) else {
        return Box::new([]);
    };
    let mut pending = vec![tree.root_node()];
    let mut ranges = Vec::new();
    while let Some(node) = pending.pop() {
        if node.kind() == "method_declaration"
            && let Some(receiver) = node.child_by_field_name("receiver")
        {
            let mut receiver_cursor = receiver.walk();
            for parameter in receiver.named_children(&mut receiver_cursor) {
                if parameter.kind() != "parameter_declaration" {
                    continue;
                }
                let Some(type_node) = parameter.child_by_field_name("type") else {
                    continue;
                };
                let mut type_nodes = vec![type_node];
                while let Some(type_node) = type_nodes.pop() {
                    if matches!(type_node.kind(), "identifier" | "type_identifier") {
                        ranges.push((type_node.start_byte(), type_node.end_byte()));
                    }
                    let mut type_cursor = type_node.walk();
                    type_nodes.extend(type_node.named_children(&mut type_cursor));
                }
            }
        }
        let mut cursor = node.walk();
        pending.extend(node.named_children(&mut cursor));
    }
    ranges.sort_unstable();
    ranges.dedup();
    ranges.into_boxed_slice()
}

fn go_selected_usage_kind(
    metadata: crate::analyzer::resolution::FactReferenceSiteMetadata,
    owner_relation: crate::analyzer::structural::OwnerRelation,
    target: &CodeUnit,
    receiver_type_reference: bool,
) -> UsageHitKind {
    if metadata.site_kind() == ResolutionSiteKind::ImportDeclaration {
        UsageHitKind::Import
    } else if (receiver_type_reference
        && metadata.site_kind() == ResolutionSiteKind::TypeReference
        && metadata.namespace() == ResolutionNamespace::Type)
        || metadata.callable_receiver_origin()
            == Some(ResolutionCallableReceiverOrigin::CurrentInstance)
        || (owner_relation == crate::analyzer::structural::OwnerRelation::SelfReference
            && target.is_function())
        || (metadata.namespace() == ResolutionNamespace::Value
            && matches!(
                metadata.site_kind(),
                ResolutionSiteKind::ValueReference | ResolutionSiteKind::MemberReference
            )
            && owner_relation == crate::analyzer::structural::OwnerRelation::SelfReference)
    {
        UsageHitKind::SelfReceiver
    } else {
        UsageHitKind::Reference
    }
}

/// A generation-bound lazy facade. It retains the analyzer, not a workspace
/// sized inverse map; each target's SQL candidates and source projections die
/// with that target request.
pub struct GoNativeSelectedReferenceIndex {
    generation: u64,
    go: Box<GoAnalyzer>,
    cancellation: CancellationToken,
}

impl crate::analyzer::structural::reference_edges::SelectedInverseReferenceIndex
    for GoNativeSelectedReferenceIndex
{
    fn generation(&self) -> u64 {
        self.generation
    }

    fn inverse_for(&self, target: &CodeUnit) -> EdgeDerivationResult {
        if self.go.inner.project().analysis_generation() != self.generation {
            return incomplete_inverse(
                self.generation,
                EdgeIncompleteReason::InverseIndexResolutionIncomplete,
            );
        }
        match go_selected_inverse_for(&self.go, target, &self.cancellation) {
            GoSelectedReverseOutcome::Ready(answer) => answer,
            GoSelectedReverseOutcome::Unavailable(detail) => {
                eprintln!("selected Go inverse query unavailable: {detail}");
                incomplete_inverse(
                    self.generation,
                    EdgeIncompleteReason::InverseIndexTargetUncovered,
                )
            }
            GoSelectedReverseOutcome::Stale(detail) => {
                eprintln!("selected Go inverse query stale: {detail}");
                incomplete_inverse(
                    self.generation,
                    EdgeIncompleteReason::InverseIndexResolutionIncomplete,
                )
            }
            GoSelectedReverseOutcome::Cancelled => {
                incomplete_inverse(self.generation, EdgeIncompleteReason::Cancelled)
            }
            GoSelectedReverseOutcome::StoreError(detail) => {
                eprintln!("selected Go inverse query failed: {detail}");
                incomplete_inverse(
                    self.generation,
                    EdgeIncompleteReason::InverseIndexResolutionIncomplete,
                )
            }
        }
    }
}

fn incomplete_inverse(generation: u64, reason: EdgeIncompleteReason) -> EdgeDerivationResult {
    EdgeDerivationResult {
        edges: Vec::new(),
        completeness: EdgeCompleteness::Incomplete {
            reasons: vec![reason],
        },
        provenance: EdgeProvenance::Inverse,
        generation,
    }
}

pub struct GoNativeSelectedInverseProvider;

impl crate::analyzer::structural::reference_edges::SelectedInverseReferenceProvider
    for GoNativeSelectedInverseProvider
{
    fn build_selected_inverse_index(
        &self,
        analyzer: &dyn IAnalyzer,
        cancellation: Option<&CancellationToken>,
    ) -> crate::analyzer::structural::reference_edges::SelectedInverseIndexOutcome {
        use crate::analyzer::structural::reference_edges::SelectedInverseIndexOutcome;
        let Some(go) = resolve_analyzer::<GoAnalyzer>(analyzer) else {
            return SelectedInverseIndexOutcome::Unavailable(
                "the workspace has no Go analyzer".into(),
            );
        };
        let token = cancellation.cloned().unwrap_or_default();
        if token.is_cancelled() {
            return SelectedInverseIndexOutcome::Cancelled;
        }
        match selected_go_context_id(go) {
            Ok(Some(_)) => {
                SelectedInverseIndexOutcome::Ready(Arc::new(GoNativeSelectedReferenceIndex {
                    generation: go.inner.project().analysis_generation(),
                    go: Box::new(go.clone()),
                    cancellation: token,
                }))
            }
            Ok(None) => SelectedInverseIndexOutcome::Unavailable(
                "the selected Go package/import publication is unavailable".into(),
            ),
            Err(error) => SelectedInverseIndexOutcome::StoreError(error.to_string()),
        }
    }
}

fn selected_go_context_id(go: &GoAnalyzer) -> Result<Option<i64>> {
    let snapshots = go.inner.selected_workspace_snapshots();
    let Some(snapshot) = snapshots.get("go") else {
        return Ok(None);
    };
    let Some(profile) = go.native_context_profile() else {
        return Ok(None);
    };
    Ok(go
        .inner
        .analyzer_store()
        .selected_go_context(snapshot, &profile)?
        .map(|context| context.context_id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::CodeUnitIndex;
    use crate::analyzer::go::native_usages::GoNativeUsageStrategy;
    use crate::hash::HashSet;
    use crate::inline_project::{BuiltInlineTestProject, InlineTestProject};
    use crate::path_utils::rel_path_string;
    use std::collections::BTreeSet;

    const MODEL: &str = "model/model.go";
    const CLIENT: &str = "client/client.go";
    const NAMED: &str = "named/use.go";
    const DOT: &str = "dot/use.go";
    const EXTERNAL: &str = "model/external_test.go";

    const MODEL_SOURCE: &str = r#"package model

type Widget struct { Name string }

func (w Widget) Run() {}

func NewWidget() Widget { return Widget{} }

func NeverUsed() {}
func privateHelper() {}

func samePackage(w Widget) {
	_ = w.Name
	w.Run()
	_ = NewWidget()
	privateHelper()
}
"#;

    const CLIENT_SOURCE: &str = r#"package client

import alias "example.test/native/model"

func useAlias(w alias.Widget) {
	_ = w.Name
	w.Run()
	_ = alias.NewWidget()
}

func shadow() {
	NewWidget := func() int { return 1 }
	_ = NewWidget()
}
"#;

    const DOT_SOURCE: &str = r#"package dot

import . "example.test/native/model"

func useDot(w Widget) {
	_ = w.Name
	w.Run()
	_ = NewWidget()
}
"#;

    const NAMED_SOURCE: &str = r#"package named

import "example.test/native/model"

func useNamed(w model.Widget) {
	_ = w.Name
	w.Run()
	_ = model.NewWidget()
}
"#;

    const EXTERNAL_SOURCE: &str = r#"package model_test

import model "example.test/native/model"

func externalTest() {
	_ = model.Widget{}
	_ = model.NewWidget()
}
"#;

    fn fixture() -> (BuiltInlineTestProject, GoAnalyzer) {
        let fixture = InlineTestProject::with_language(Language::Go)
            .file("go.mod", "module example.test/native\n\ngo 1.22\n")
            .file(MODEL, MODEL_SOURCE)
            .file(CLIENT, CLIENT_SOURCE)
            .file(NAMED, NAMED_SOURCE)
            .file(DOT, DOT_SOURCE)
            .file(EXTERNAL, EXTERNAL_SOURCE)
            .build();
        let analyzer = GoAnalyzer::new(fixture.project_dyn());
        persist_selected_go_sources(&analyzer);
        (fixture, analyzer)
    }

    fn persist_selected_go_sources(analyzer: &GoAnalyzer) {
        for file in analyzer.get_analyzed_files() {
            assert!(
                analyzer
                    .inner
                    .write_live_file_to_store_for_test(&file)
                    .is_some(),
                "persist Go resolution facts for {file}"
            );
        }
        analyzer
            .refresh_source_inventory()
            .expect("publish and reconcile the Go fixture's final source-inventory generation");
        let context_id = selected_go_context_id(analyzer)
            .expect("read selected Go package context")
            .expect("selected Go package context");
        reconcile_go_summaries(analyzer, context_id);
    }

    fn reconcile_go_summaries(analyzer: &GoAnalyzer, context_id: i64) {
        let snapshot = analyzer
            .selected_snapshot_for_test()
            .expect("selected Go snapshot");
        let profile = analyzer
            .native_context_profile()
            .expect("selected Go native context profile");
        let report = analyzer
            .inner
            .analyzer_store()
            .reconcile_unit_summaries(
                &snapshot,
                crate::analyzer::store::go_unit_summaries::GoUnitSummaries {
                    context_id,
                    profile,
                },
                &crate::CancellationToken::new(),
            )
            .expect("reconcile summaries for the selected Go native context");
        assert!(
            report.failed.is_empty(),
            "selected Go native summary derivation must succeed: {:?}",
            report.failed
        );
    }

    fn target(analyzer: &GoAnalyzer, fixture: &BuiltInlineTestProject, name: &str) -> CodeUnit {
        target_at(analyzer, fixture, MODEL, name)
    }

    fn target_at(
        analyzer: &GoAnalyzer,
        fixture: &BuiltInlineTestProject,
        path: &str,
        name: &str,
    ) -> CodeUnit {
        analyzer
            .declarations(&fixture.file(path))
            .into_iter()
            .find(|unit| unit.identifier() == name)
            .unwrap_or_else(|| panic!("missing Go declaration {name} in {path}"))
    }

    fn transitive_fixture(files: &[(&str, &str)]) -> (BuiltInlineTestProject, GoAnalyzer) {
        let mut builder = InlineTestProject::with_language(Language::Go)
            .file("go.mod", "module example.test/transitive\n\ngo 1.22\n");
        for (path, source) in files {
            builder = builder.file(*path, *source);
        }
        let fixture = builder.build();
        let analyzer = GoAnalyzer::new(fixture.project_dyn());
        persist_selected_go_sources(&analyzer);
        (fixture, analyzer)
    }

    fn inverse(analyzer: &GoAnalyzer, target: &CodeUnit) -> EdgeDerivationResult {
        match go_selected_inverse_for(analyzer, target, &CancellationToken::new()) {
            GoSelectedReverseOutcome::Ready(answer) => answer,
            outcome => panic!("selected Go inverse query failed: {outcome:?}"),
        }
    }

    fn edge_paths(answer: &EdgeDerivationResult) -> HashSet<String> {
        answer
            .edges
            .iter()
            .map(|edge| rel_path_string(&edge.site.file))
            .collect()
    }

    fn usage_hits(
        result: crate::analyzer::usages::FuzzyResult,
    ) -> (BTreeSet<crate::analyzer::usages::UsageHit>, bool) {
        use crate::analyzer::usages::FuzzyResult;

        let (hits_by_overload, unproven_by_overload, incomplete) = match result {
            FuzzyResult::Success {
                hits_by_overload,
                unproven_by_overload,
                ..
            } => (hits_by_overload, unproven_by_overload, false),
            FuzzyResult::Incomplete {
                hits_by_overload,
                unproven_by_overload,
                ..
            } => (hits_by_overload, unproven_by_overload, true),
            outcome => panic!("Go usage query produced no hit inventory: {outcome:?}"),
        };
        (
            hits_by_overload
                .into_values()
                .chain(unproven_by_overload.into_values())
                .flatten()
                .collect(),
            incomplete,
        )
    }

    fn assert_transitive_member_is_point_confirmed(
        answer: &EdgeDerivationResult,
        target: &CodeUnit,
        expected_path: &str,
        scenario: &str,
    ) {
        let candidates = crate::analyzer::store::resolution_operation::go_reverse_rows::
            last_go_reverse_candidate_paths_for_test();
        assert!(
            candidates.iter().any(|path| path == expected_path),
            "{scenario} must reach the recursive candidate set for {expected_path}: {candidates:?}"
        );
        let qualified_imports = crate::analyzer::store::resolution_operation::go_reverse_rows::
            last_go_reverse_qualified_imports_for_test();
        assert!(
            qualified_imports.is_empty(),
            "{scenario} is a receiver member path, not a package import route: {qualified_imports:?}"
        );
        let edge = answer
            .edges
            .iter()
            .find(|edge| edge.site.file.rel_path() == expected_path)
            .unwrap_or_else(|| panic!("point resolution must confirm {scenario}: {answer:#?}"));
        assert!(
            edge.target == *target && edge.proof == UsageProof::Proven,
            "point resolution must prove the requested declaration for {scenario}: {edge:#?}"
        );
        assert_eq!(answer.completeness, EdgeCompleteness::Complete);
    }

    #[test]
    fn selected_go_inverse_composes_package_peers_aliases_dot_imports_and_external_tests() {
        let (fixture, analyzer) = fixture();
        for (name, expected_paths) in [
            ("Widget", &[MODEL, CLIENT, NAMED, DOT, EXTERNAL][..]),
            ("Name", &[MODEL, CLIENT, NAMED, DOT][..]),
            ("Run", &[MODEL, CLIENT, NAMED, DOT][..]),
            ("NewWidget", &[MODEL, CLIENT, NAMED, DOT, EXTERNAL][..]),
        ] {
            let target = target(&analyzer, &fixture, name);
            let answer = inverse(&analyzer, &target);
            let paths = edge_paths(&answer);
            for expected in expected_paths {
                if *expected == EXTERNAL && !paths.contains(*expected) {
                    assert!(
                        matches!(
                            &answer.completeness,
                            EdgeCompleteness::Incomplete { reasons }
                                if reasons.contains(&EdgeIncompleteReason::InverseIndexResolutionIncomplete)
                        ),
                        "an unavailable external test package context must be reported as incomplete: {answer:#?}"
                    );
                    continue;
                }
                assert!(
                    paths.contains(*expected),
                    "{name} should have a confirmed edge from {expected}; answer={answer:#?}"
                );
            }
            assert!(
                answer.edges.iter().all(|edge| edge.target == target),
                "forward confirmation must publish only the exact target: {answer:#?}"
            );
            assert!(
                !answer.edges.iter().any(|edge| {
                    edge.site.file == fixture.file(CLIENT)
                        && edge.site.range.start_byte == CLIENT_SOURCE.find("NewWidget :=").unwrap()
                }),
                "the local NewWidget shadow must not bind to the package function: {answer:#?}"
            );
        }

        let private_target = target(&analyzer, &fixture, "privateHelper");
        let private_answer = inverse(&analyzer, &private_target);
        assert!(
            private_answer
                .edges
                .iter()
                .any(|edge| edge.site.file == fixture.file(MODEL)),
            "an unexported Go declaration remains visible in its package: {private_answer:#?}"
        );
        assert!(
            private_answer
                .edges
                .iter()
                .all(|edge| edge.site.file == fixture.file(MODEL)),
            "an unexported Go declaration is invisible outside its package: {private_answer:#?}"
        );
    }

    #[test]
    fn selected_go_inverse_includes_internal_test_package_variants() {
        const PROVIDER: &str = "package pkg\n\nfunc New() int { return 1 }\n";
        const INTERNAL_TEST: &str = r#"package pkg

import "testing"

func TestNew(t *testing.T) { _ = New() }
"#;
        let (fixture, analyzer) =
            transitive_fixture(&[("pkg/pkg.go", PROVIDER), ("pkg/pkg_test.go", INTERNAL_TEST)]);
        let target = target_at(&analyzer, &fixture, "pkg/pkg.go", "New");
        let answer = inverse(&analyzer, &target);
        let candidates = crate::analyzer::store::resolution_operation::go_reverse_rows::
            last_go_reverse_candidate_paths_for_test();
        assert!(
            candidates.iter().any(|path| path == "pkg/pkg_test.go"),
            "internal Go test package must be seeded as a same-package candidate: {candidates:?}"
        );
        assert!(
            answer
                .edges
                .iter()
                .any(|edge| edge.site.file == fixture.file("pkg/pkg_test.go")),
            "internal test call must resolve to its package declaration: {answer:#?}"
        );
        assert_eq!(
            answer.completeness,
            EdgeCompleteness::Complete,
            "the named testing import cannot hide another workspace reference: {answer:#?}"
        );
    }

    #[brokk_bifrost_test_macros::hardwon(
        "46bd3b03ff7f: reverse summary skipped a cross-file name ending at package scope"
    )]
    #[test]
    fn selected_go_inverse_confirms_cross_file_package_scope_names() {
        const PROVIDER: &str = "package pkg\n\nfunc Target() {}\n";
        const CALLER: &str = "package pkg\n\nfunc use() { Target() }\n";
        let (fixture, analyzer) =
            transitive_fixture(&[("pkg/provider.go", PROVIDER), ("pkg/caller.go", CALLER)]);
        let target = target_at(&analyzer, &fixture, "pkg/provider.go", "Target");

        let answer = inverse(&analyzer, &target);

        assert!(
            answer.edges.iter().any(
                |edge| edge.site.file == fixture.file("pkg/caller.go") && edge.target == target
            ),
            "a same-package name reaches the caller file's package Scope: {answer:#?}"
        );
    }

    #[brokk_bifrost_test_macros::hardwon(
        "22f2f70ef463: unresolved default imports hid their selected file-scope binder"
    )]
    #[test]
    fn selected_go_inverse_uses_default_import_binder_without_provider() {
        const APP: &str = r#"package app

import "example.test/transitive/missing"

type Widget struct { Widget int }

func use() {
	_ = Widget{Widget: 1}
	_ = missing.Widget{}
}
"#;

        let (fixture, analyzer) = transitive_fixture(&[("app/app.go", APP)]);
        let target = target_at(&analyzer, &fixture, "app/app.go", "Widget");
        crate::analyzer::store::resolution_operation::go_reverse_rows::
            reset_go_reverse_qualified_imports_for_test();

        let answer = inverse(&analyzer, &target);
        let imports = crate::analyzer::store::resolution_operation::go_reverse_rows::
            last_go_reverse_qualified_imports_for_test();

        assert!(
            imports
                .iter()
                .any(|(_, _, import_id)| *import_id == Some(0)),
            "the unresolved default import still has a selected binder row: {imports:?}"
        );
        let type_start = APP.find("Widget{").expect("composite literal type");
        assert!(
            answer.edges.iter().any(|edge| {
                edge.site.file == fixture.file("app/app.go")
                    && edge.site.range.start_byte == type_start
            }),
            "the composite-literal type remains a reference to Widget: {answer:#?}"
        );
        let key_start = APP.find("Widget:").expect("composite key");
        assert!(
            !answer.edges.iter().any(|edge| {
                edge.site.file == fixture.file("app/app.go")
                    && edge.site.range.start_byte == key_start
            }),
            "a composite-literal key is not a name reference to the package type: {answer:#?}"
        );
        let imported_start =
            APP.find("missing.Widget").expect("qualified missing name") + "missing.".len();
        assert!(
            !answer.edges.iter().any(|edge| {
                edge.site.file == fixture.file("app/app.go")
                    && edge.site.range.start_byte == imported_start
            }),
            "an unresolved external package does not bind to the local Widget: {answer:#?}"
        );
    }

    #[test]
    fn selected_go_inverse_confirms_generic_imported_function_calls() {
        use crate::analyzer::usages::get_definition::{
            CallSyntaxKind, call_site_syntax_for_reference,
        };

        const LIB: &str = "package lib\n\nfunc New[T any]() *T { return new(T) }\n";
        const APP: &str = "package app\n\nimport \"example.test/transitive/lib\"\n\nfunc use() { _ = lib.New[int]() }\n";
        let (fixture, analyzer) = transitive_fixture(&[("lib/lib.go", LIB), ("app/app.go", APP)]);
        let target = target_at(&analyzer, &fixture, "lib/lib.go", "New");

        let answer = inverse(&analyzer, &target);
        let candidate_paths =
            crate::analyzer::store::resolution_operation::go_reverse_rows::
                last_go_reverse_candidate_paths_for_test();
        assert!(
            candidate_paths.iter().any(|path| path == "app/app.go"),
            "the structured imported call must enter forward confirmation: {candidate_paths:?}"
        );

        let edge = answer
            .edges
            .iter()
            .find(|edge| edge.site.file == fixture.file("app/app.go") && edge.target == target)
            .expect("the generic imported call must be forward-confirmed");
        assert_eq!(
            edge.reference_kind,
            Some(brokk_bifrost_core::analyzer::usages::model::ReferenceKind::MethodCall),
            "generic selector calls retain their call classification: {edge:#?}"
        );
        let facts = analyzer
            .structural_fact_providers()
            .into_iter()
            .find_map(|provider| provider.structural_facts(&edge.site.file))
            .expect("imported generic call has structural facts");
        let syntax = call_site_syntax_for_reference(
            &facts,
            edge.site.range.start_byte,
            edge.site.range.end_byte,
        )
        .expect("imported generic reference maps to its call syntax");
        assert_eq!(syntax.kind, CallSyntaxKind::Method);
        assert_eq!(
            answer.completeness,
            EdgeCompleteness::Complete,
            "the fixture has a complete package inventory with no build constraints, and the generic imported function binding is exact: {answer:#?}"
        );
    }

    #[brokk_bifrost_test_macros::hardwon(
        "c9cfd997855a: member point confirmation proves methods reached through imported results"
    )]
    #[test]
    fn selected_go_inverse_follows_intermediate_package_for_methods() {
        const A: &str = r#"package a

type T struct{}

func (T) Method() {}
"#;
        const B: &str = r#"package b

import "example.test/transitive/a"

func Get() a.T { return a.T{} }
"#;
        const C: &str = r#"package c

import "example.test/transitive/b"

func use() {
	x := b.Get()
	x.Method()
}
"#;

        let (fixture, analyzer) =
            transitive_fixture(&[("a/a.go", A), ("b/b.go", B), ("c/c.go", C)]);
        let target = target_at(&analyzer, &fixture, "a/a.go", "Method");
        crate::analyzer::store::resolution_operation::go_reverse_rows::
            reset_go_reverse_qualified_imports_for_test();
        let answer = inverse(&analyzer, &target);
        assert_transitive_member_is_point_confirmed(
            &answer,
            &target,
            "c/c.go",
            "a method reached through b.Get",
        );
    }

    #[brokk_bifrost_test_macros::hardwon(
        "c9cfd997855a: member point confirmation proves methods reached through imported types"
    )]
    #[test]
    fn selected_go_inverse_follows_intermediate_package_for_promoted_members() {
        const A: &str = r#"package a

type T struct{}

func (T) Method() {}
"#;
        const B: &str = r#"package b

import "example.test/transitive/a"

type S struct { a.T }
"#;
        const C: &str = r#"package c

import "example.test/transitive/b"

func use(s b.S) {
	s.Method()
}
"#;

        let (fixture, analyzer) =
            transitive_fixture(&[("a/a.go", A), ("b/b.go", B), ("c/c.go", C)]);
        let target = target_at(&analyzer, &fixture, "a/a.go", "Method");
        crate::analyzer::store::resolution_operation::go_reverse_rows::
            reset_go_reverse_qualified_imports_for_test();
        let answer = inverse(&analyzer, &target);
        assert_transitive_member_is_point_confirmed(
            &answer,
            &target,
            "c/c.go",
            "a promoted method reached through b.S",
        );
    }

    #[brokk_bifrost_test_macros::hardwon(
        "800772caaffe: a qualified Go type alias needs summary evidence for its target"
    )]
    #[test]
    fn selected_go_inverse_follows_intermediate_package_for_type_aliases() {
        const A: &str = r#"package a

type T struct { Value int }
"#;
        const B: &str = r#"package b

import "example.test/transitive/a"

type T = a.T
"#;
        const C: &str = r#"package c

import "example.test/transitive/b"

var value b.T
"#;

        let (fixture, analyzer) =
            transitive_fixture(&[("a/a.go", A), ("b/b.go", B), ("c/c.go", C)]);
        let target = target_at(&analyzer, &fixture, "a/a.go", "T");
        crate::analyzer::store::resolution_operation::go_reverse_rows::
            reset_go_reverse_alias_fallbacks_for_test();
        let answer = inverse(&analyzer, &target);
        let definition_plan = crate::analyzer::store::resolution_operation::go_reverse_rows::
            last_go_reverse_definition_plan_for_test();
        eprintln!("selected Go alias-definition EXPLAIN QUERY PLAN: {definition_plan:#?}");
        assert!(
            definition_plan
                .iter()
                .any(|detail| detail.contains("semantic")),
            "alias lexical projection must plan its populated semantic-site lookup: {definition_plan:#?}"
        );
        assert!(
            definition_plan
                .iter()
                .any(|detail| detail.contains("bridge")),
            "alias lexical projection must plan its populated source-declaration bridge lookup: {definition_plan:#?}"
        );
        assert!(
            definition_plan
                .iter()
                .any(|detail| detail.contains("declaration")),
            "alias lexical projection must plan its populated declaration-name lookup: {definition_plan:#?}"
        );
        let candidates = crate::analyzer::store::resolution_operation::go_reverse_rows::
            last_go_reverse_candidate_paths_for_test();
        assert!(
            candidates.iter().any(|path| path == "c/c.go"),
            "the transitive importer C must supply the type-alias candidate: {candidates:?}"
        );
        assert!(
            edge_paths(&answer).contains("c/c.go"),
            "the b.T type alias reference must be confirmed against a.T: {answer:#?}"
        );
        assert!(
            answer
                .edges
                .iter()
                .any(|edge| edge.site.file == fixture.file("c/c.go") && edge.target == target)
        );
        assert_eq!(
            crate::analyzer::store::resolution_operation::go_reverse_rows::
                last_go_reverse_alias_fallbacks_for_test(),
            0,
            "the live alias summaries must resolve this chain without forward fallback"
        );
        assert!(
            answer.edges.iter().all(|edge| edge.target == target),
            "publish only the selected a.T declaration: {answer:#?}"
        );
    }

    #[test]
    fn incomplete_go_package_inventory_never_publishes_complete_absence() {
        let (fixture, analyzer) = fixture();
        let snapshots = analyzer.inner.selected_workspace_snapshots();
        let snapshot = snapshots.get("go").expect("selected Go snapshot");
        let profile = analyzer.native_context_profile().expect("Go profile");
        let context = analyzer
            .inner
            .analyzer_store()
            .selected_go_context(snapshot, &profile)
            .unwrap()
            .expect("selected Go package context");
        let store = analyzer.inner.analyzer_store();
        crate::analyzer::store::resolution_operation::go_reverse_rows::
            mark_go_context_incomplete_for_test(store, context.context_id)
            .unwrap();

        let unused = target(&analyzer, &fixture, "NeverUsed");
        let answer = inverse(&analyzer, &unused);
        assert!(
            answer.edges.is_empty(),
            "the target has no reference sites: {answer:#?}"
        );
        assert!(
            matches!(answer.completeness, EdgeCompleteness::Incomplete { .. }),
            "an incomplete Go package publication cannot authorize an empty result: {answer:#?}"
        );
    }

    #[test]
    fn selected_go_reverse_inventory_ignores_unrelated_incomplete_imports() {
        const MODEL_SOURCE: &str = "package model\ntype Widget struct{}\nfunc NeverUsed() {}\n";
        const CLIENT_SOURCE: &str = r#"package client

import (
	. "fmt"
	. "example.test/transitive/model"
)

func use() {
	_ = Widget{}
	_ = Sprintf(1)
}
"#;
        let (fixture, analyzer) = transitive_fixture(&[
            ("model/model.go", MODEL_SOURCE),
            ("client/client.go", CLIENT_SOURCE),
        ]);
        let unused = target_at(&analyzer, &fixture, "model/model.go", "NeverUsed");
        let answer = inverse(&analyzer, &unused);
        assert!(
            answer.edges.iter().all(|edge| edge.target == unused),
            "reverse results remain target-specific: {answer:#?}"
        );
        assert_eq!(
            answer.completeness,
            EdgeCompleteness::Complete,
            "an unavailable fmt provider cannot hide references to the selected workspace package: {answer:#?}"
        );

        let context_id = selected_go_context_id(&analyzer)
            .unwrap()
            .expect("selected Go package context");
        let updated = crate::analyzer::store::resolution_operation::go_reverse_rows::mark_go_import_incomplete_for_test(
            analyzer.inner.analyzer_store(),
            context_id,
            "fmt",
        )
        .unwrap();
        assert_eq!(
            updated, 1,
            "the external dot import is present in inventory"
        );
        reconcile_go_summaries(&analyzer, context_id);
        let answer = inverse(&analyzer, &unused);
        assert_eq!(
            answer.completeness,
            EdgeCompleteness::Complete,
            "an unavailable external dot provider cannot hide references to the selected workspace package: {answer:#?}"
        );

        let updated = crate::analyzer::store::resolution_operation::go_reverse_rows::mark_go_import_incomplete_for_test(
            analyzer.inner.analyzer_store(),
            context_id,
            "example.test/transitive/model",
        )
        .unwrap();
        assert_eq!(updated, 1, "the target dot import is present in inventory");
        reconcile_go_summaries(&analyzer, context_id);
        let removed = crate::analyzer::store::resolution_operation::go_reverse_rows::mark_go_unit_summary_unavailable_for_test(
            analyzer.inner.analyzer_store(),
            context_id,
            crate::analyzer::store::go_unit_summaries::go_unit_key(
                "example.test/transitive/model",
                "",
                "go",
            ),
        )
        .unwrap();
        assert_eq!(removed, 1, "the selected target summary was withdrawn");
        let answer = inverse(&analyzer, &unused);
        assert!(
            matches!(answer.completeness, EdgeCompleteness::Incomplete { .. }),
            "a missing selected provider summary keeps reverse absence open: {answer:#?}"
        );
    }

    #[test]
    fn selected_go_strategy_uses_confirmed_inverse_sites_for_forward_usages() {
        use crate::analyzer::usages::UsageAnalyzer;

        let (fixture, analyzer) = fixture();
        let target = target(&analyzer, &fixture, "NewWidget");
        let admitted = analyzer
            .get_analyzed_files()
            .into_iter()
            .collect::<HashSet<_>>();
        let result = GoNativeUsageStrategy::new().find_usages(
            &analyzer,
            std::slice::from_ref(&target),
            &admitted,
            100,
        );
        let (hits, incomplete) = usage_hits(result);
        let hit_paths = hits
            .iter()
            .map(|hit| rel_path_string(&hit.file))
            .collect::<HashSet<_>>();
        assert!(hit_paths.contains(CLIENT), "{hits:#?}");
        assert!(hit_paths.contains(NAMED), "{hits:#?}");
        assert!(hit_paths.contains(DOT), "{hits:#?}");
        if !hit_paths.contains(EXTERNAL) {
            assert!(
                incomplete,
                "an unavailable external test package must not produce a complete absence: {hits:#?}"
            );
        }
        assert!(!hits.iter().any(|hit| {
            hit.file == fixture.file(CLIENT)
                && hit.start_offset == CLIENT_SOURCE.find("NewWidget :=").unwrap()
        }));
    }

    #[test]
    fn selected_go_usage_matches_incumbent_on_the_real_store_fixture() {
        use crate::analyzer::usages::{GoUsageGraphStrategy, UsageAnalyzer};

        let (_fixture, analyzer) = fixture();
        let admitted = analyzer
            .get_analyzed_files()
            .into_iter()
            .collect::<HashSet<_>>();
        for name in ["Widget", "Name", "Run", "NewWidget"] {
            let target = target(&analyzer, &_fixture, name);
            let legacy = GoUsageGraphStrategy::new().find_usages(
                &analyzer,
                std::slice::from_ref(&target),
                &admitted,
                100,
            );
            let native = GoNativeUsageStrategy::new().find_usages(
                &analyzer,
                std::slice::from_ref(&target),
                &admitted,
                100,
            );
            let (legacy, _) = usage_hits(legacy);
            let (native, native_incomplete) = usage_hits(native);
            let signatures = |hits: BTreeSet<crate::analyzer::usages::UsageHit>| {
                hits.into_iter()
                    .map(|hit| {
                        (
                            hit.file.rel_path().to_path_buf(),
                            hit.start_offset,
                            hit.end_offset,
                            hit.kind,
                        )
                    })
                    .collect::<BTreeSet<_>>()
            };
            let legacy = signatures(legacy);
            let native = signatures(native);
            let sites = |signatures: &BTreeSet<(
                std::path::PathBuf,
                usize,
                usize,
                crate::analyzer::usages::UsageHitKind,
            )>| {
                signatures
                    .iter()
                    .map(|(path, start, end, _)| (path.clone(), *start, *end))
                    .collect::<BTreeSet<_>>()
            };
            let legacy_sites = sites(&legacy);
            let native_sites = sites(&native);
            let legacy_only = legacy_sites.difference(&native_sites).collect::<Vec<_>>();
            let native_only = native_sites.difference(&legacy_sites).collect::<Vec<_>>();
            if !legacy_only.is_empty() || !native_only.is_empty() {
                assert!(
                    matches!(name, "Widget" | "NewWidget")
                        && native_incomplete
                        && native_only.is_empty()
                        && legacy_only
                            .iter()
                            .all(|(path, ..)| path.as_path() == std::path::Path::new(EXTERNAL)),
                    "source-adjudicate incumbent/native difference for {name}: legacy-only={legacy_only:?}, native-only={native_only:?}, incomplete={native_incomplete}"
                );
            }
            let native_kinds = native
                .iter()
                .map(|(path, start, end, kind)| ((path.clone(), *start, *end), *kind))
                .collect::<HashMap<_, _>>();
            let kind_differences = legacy
                .iter()
                .filter_map(|(path, start, end, legacy_kind)| {
                    native_kinds
                        .get(&(path.clone(), *start, *end))
                        .filter(|native_kind| *native_kind != legacy_kind)
                        .map(|native_kind| (path.clone(), *start, *end, *legacy_kind, *native_kind))
                })
                .collect::<BTreeSet<_>>();
            if !kind_differences.is_empty() {
                let receiver_site = MODEL_SOURCE
                    .find("func (w Widget)")
                    .expect("Go method receiver")
                    + "func (w ".len();
                assert_eq!(
                    name, "Widget",
                    "unexpected incumbent/native usage-kind difference: {kind_differences:?}"
                );
                assert_eq!(
                    kind_differences,
                    BTreeSet::from([(
                        std::path::PathBuf::from(MODEL),
                        receiver_site,
                        receiver_site + "Widget".len(),
                        crate::analyzer::usages::UsageHitKind::SelfReceiver,
                        crate::analyzer::usages::UsageHitKind::Reference,
                    )]),
                    "source-adjudicate Go's receiver-type kind difference"
                );
            }
        }
    }

    #[test]
    fn selected_go_inverse_provider_is_available_through_test_support_only() {
        use crate::analyzer::structural::reference_edges::{
            SelectedInverseIndexOutcome, SelectedInverseReferenceProvider,
        };

        let (fixture, analyzer) = fixture();
        let target = target(&analyzer, &fixture, "NewWidget");
        let index =
            match GoNativeSelectedInverseProvider.build_selected_inverse_index(&analyzer, None) {
                SelectedInverseIndexOutcome::Ready(index) => index,
                SelectedInverseIndexOutcome::Unavailable(reason) => {
                    panic!("Go test-support inverse provider unavailable: {reason}")
                }
                SelectedInverseIndexOutcome::Stale(reason) => {
                    panic!("Go test-support inverse provider stale: {reason}")
                }
                SelectedInverseIndexOutcome::Cancelled => {
                    panic!("Go test-support inverse provider cancelled")
                }
                SelectedInverseIndexOutcome::StoreError(reason) => {
                    panic!("Go test-support inverse provider failed: {reason}")
                }
            };
        assert_eq!(
            index.generation(),
            analyzer.inner.project().analysis_generation()
        );
        let answer = index.inverse_for(&target);
        assert!(
            answer
                .edges
                .iter()
                .any(|edge| edge.site.file == fixture.file(CLIENT)),
            "the lazy selected inverse index must answer from real-store rows: {answer:#?}"
        );
    }

    #[test]
    fn selected_go_reverse_reader_seeks_shared_identity_and_recursive_import_indexes() {
        let (fixture, analyzer) = fixture();
        let snapshots = analyzer.inner.selected_workspace_snapshots();
        let snapshot = snapshots.get("go").expect("selected Go snapshot");
        let profile = analyzer.native_context_profile().expect("Go profile");
        let context = analyzer
            .inner
            .analyzer_store()
            .selected_go_context(snapshot, &profile)
            .unwrap()
            .expect("selected Go package context");
        let store = analyzer.inner.analyzer_store();
        crate::analyzer::store::resolution_operation::go_reverse_rows::
            seed_go_reverse_plan_decoys_for_test(
                store,
                context.context_id,
                CLIENT,
                512,
            )
            .unwrap();
        store.refresh_planner_statistics().unwrap();

        let target = target(&analyzer, &fixture, "NewWidget");
        let answer = inverse(&analyzer, &target);
        assert!(!answer.edges.is_empty(), "{answer:#?}");
        let plan = crate::analyzer::store::resolution_operation::go_reverse_rows::
            last_go_reverse_candidate_plan_for_test();
        eprintln!("selected Go reverse candidate EXPLAIN QUERY PLAN: {plan:#?}");
        assert!(
            plan.iter()
                .any(|detail| detail.contains("resolution_reference_lookup_identities_identity")),
            "candidate sites must seek the shared reference identity index: {plan:#?}"
        );
        assert!(
            plan.iter().any(|detail| detail.contains("RECURSIVE STEP")),
            "exported-name discovery must execute a recursive importer closure: {plan:#?}"
        );
        assert!(
            plan.iter()
                .any(|detail| detail.contains("idx_go_package_imports_target")),
            "recursive importer discovery must seek the selected target-package index: {plan:#?}"
        );
        assert!(
            plan.iter()
                .any(|detail| detail.contains("resolution_qualified_routes_source_lookup")),
            "qualified terminal names must seek the selected route index: {plan:#?}"
        );
        assert!(
            plan.iter()
                .any(|detail| detail.contains("resolution_paths_root_terminal")),
            "prefixed root names must seek the selected root-terminal index: {plan:#?}"
        );
        assert!(
            plan.iter().all(|detail| !detail.contains("SCAN versions")),
            "candidate discovery must avoid workspace-wide version scans: {plan:#?}"
        );
        assert!(
            plan.iter().all(|detail| !detail.contains("SCAN members")),
            "candidate discovery must seek package files from visible packages: {plan:#?}"
        );
    }

    #[test]
    fn selected_go_native_incoming_calls_are_exactly_inverse_call_sites() {
        use crate::analyzer::QueryScope;
        use crate::analyzer::usages::UsageProofAuthority;
        use crate::analyzer::usages::call_relations::{CallRelationLimits, CallRelationService};
        use crate::analyzer::usages::get_definition::call_site_syntax_for_reference;

        let (fixture, analyzer) = fixture();
        let target = target(&analyzer, &fixture, "NewWidget");
        let selected = inverse(&analyzer, &target);
        let selected_complete = selected.completeness == EdgeCompleteness::Complete;

        let mut expected = BTreeSet::new();
        for edge in &selected.edges {
            let facts = analyzer
                .structural_fact_providers()
                .into_iter()
                .find_map(|provider| provider.structural_facts(&edge.site.file))
                .expect("real Go source has structural facts");
            if let Some(syntax) = call_site_syntax_for_reference(
                &facts,
                edge.site.range.start_byte,
                edge.site.range.end_byte,
            ) {
                expected.insert((
                    edge.site.file.clone(),
                    syntax.range.start_byte,
                    syntax.range.end_byte,
                ));
            }
        }

        let limits = CallRelationLimits {
            max_files: 64,
            max_source_bytes: 4 * 1024 * 1024,
            max_candidates: 256,
        };
        let native = super::super::native_call_relations::go_native_incoming_calls(
            &analyzer, &target, limits, None,
        );
        assert_eq!(native.proof_authority, UsageProofAuthority::Native);
        assert!(!native.cancelled && !native.truncated, "{native:#?}");
        assert_eq!(
            native.diagnostics.len(),
            if selected_complete { 0 } else { 2 },
            "the call projection carries the selected inverse inventory status: {native:#?}"
        );
        assert!(
            native.diagnostics.iter().all(|diagnostic| {
                diagnostic.reason_kind.as_deref() == Some("native_call_inventory_incomplete")
            }),
            "{native:#?}"
        );
        let actual = native
            .sites
            .iter()
            .map(|site| {
                (
                    site.file.clone(),
                    site.range.start_byte,
                    site.range.end_byte,
                )
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(
            actual, expected,
            "native projection must preserve exactly the confirmed call rows"
        );

        let scope = crate::analyzer::AnalyzerQueryScope::new(&analyzer);
        let incumbent =
            CallRelationService::incoming_bounded(&analyzer, scope.token(), &target, limits, None);
        let incumbent_sites = incumbent
            .sites
            .iter()
            .map(|site| {
                (
                    site.file.clone(),
                    site.range.start_byte,
                    site.range.end_byte,
                )
            })
            .collect::<BTreeSet<_>>();
        let legacy_only = incumbent_sites
            .difference(&actual)
            .cloned()
            .collect::<BTreeSet<_>>();
        let native_only = actual
            .difference(&incumbent_sites)
            .cloned()
            .collect::<BTreeSet<_>>();
        let external_call = EXTERNAL_SOURCE
            .find("model.NewWidget()")
            .expect("external-test qualified call");
        let external_call_site = (
            fixture.file(EXTERNAL),
            external_call,
            external_call + "model.NewWidget()".len(),
        );
        assert!(
            incumbent_sites.contains(&external_call_site),
            "the incumbent recognizes the external-test package's qualified call"
        );
        assert!(
            actual.contains(&external_call_site),
            "the selected inverse projection confirms the external-test package's qualified call"
        );
        assert!(
            legacy_only.is_empty(),
            "incumbent-only calls: {legacy_only:?}"
        );
        assert!(
            native_only.is_empty(),
            "unexpected native-only calls: {native_only:?}"
        );
        assert!(
            selected_complete,
            "the live unit summaries include the external test package and confirm the same complete call-site set as the incumbent: {selected:#?}"
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#2771: qualified Go type-prefix candidates skipped the file import binder lookup"
    )]
    fn selected_go_inverse_reads_import_binders_for_type_prefix_candidates() {
        const LIB: &str = "package lib\ntype Widget struct{}\n";
        const APP: &str =
            "package app\nimport library \"example.test/transitive/lib\"\nvar _ library.Widget\n";
        let (fixture, analyzer) = transitive_fixture(&[("lib/lib.go", LIB), ("app/app.go", APP)]);
        let target = target_at(&analyzer, &fixture, "lib/lib.go", "Widget");
        crate::analyzer::store::resolution_operation::go_reverse_rows::
            reset_go_reverse_qualified_imports_for_test();

        let answer = inverse(&analyzer, &target);
        let imports = crate::analyzer::store::resolution_operation::go_reverse_rows::
            last_go_reverse_qualified_imports_for_test();

        assert_eq!(
            answer.completeness,
            EdgeCompleteness::Complete,
            "{answer:#?}"
        );
        assert!(
            answer
                .edges
                .iter()
                .any(|edge| edge.site.file == fixture.file("app/app.go")),
            "the imported type reference is confirmed: {answer:#?}"
        );
        assert_eq!(
            imports.len(),
            1,
            "the type-prefix candidate uses one import binder: {imports:?}"
        );
        assert!(
            imports[0].2.is_some(),
            "the type-prefix path reaches its source import row: {imports:?}"
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "f389fce9693d: qualified reverse binding must select the binder named at the file Scope endpoint"
    )]
    fn selected_go_inverse_selects_the_qualified_import_by_spelling() {
        const LIB: &str = "package lib\ntype Widget struct{}\n";
        const AUX: &str = "package auxiliary\nvar Marker int\n";
        const APP: &str = "package app\nimport (\n library \"example.test/transitive/lib\"\n support \"example.test/transitive/auxiliary\"\n)\ntype Container struct { library *library.Widget }\ntype localLibrary struct { Widget int }\nvar _ = support.Marker\nfunc use() { var item *library.Widget; var library localLibrary; _ = item; _ = library.Widget }\n";
        let (fixture, analyzer) = transitive_fixture(&[
            ("lib/lib.go", LIB),
            ("auxiliary/auxiliary.go", AUX),
            ("app/app.go", APP),
        ]);
        let target = target_at(&analyzer, &fixture, "lib/lib.go", "Widget");
        crate::analyzer::store::resolution_operation::go_reverse_rows::
            reset_go_reverse_qualified_imports_for_test();

        let answer = inverse(&analyzer, &target);
        let imports = crate::analyzer::store::resolution_operation::go_reverse_rows::
            last_go_reverse_qualified_imports_for_test();

        assert_eq!(
            answer.completeness,
            EdgeCompleteness::Complete,
            "{answer:#?}"
        );
        let qualified_widget_starts = APP
            .match_indices("library.Widget")
            .map(|(start, _)| start + "library.".len())
            .collect::<Vec<_>>();
        assert_eq!(qualified_widget_starts.len(), 3);
        for &imported_type_start in &qualified_widget_starts[..2] {
            assert!(
                answer.edges.iter().any(|edge| {
                    edge.site.file == fixture.file("app/app.go")
                        && edge.site.range.start_byte == imported_type_start
                }),
                "the import remains visible before a later local declaration: {answer:#?}"
            );
        }
        assert!(
            !answer.edges.iter().any(|edge| {
                edge.site.file == fixture.file("app/app.go")
                    && edge.site.range.start_byte == qualified_widget_starts[2]
            }),
            "a local value shadow keeps its member out of package import confirmation: {answer:#?}"
        );
        assert_eq!(
            imports.len(),
            2,
            "only qualified package type sites may select the named import: {imports:?}"
        );
        assert!(
            imports.iter().all(|import| import.2 == Some(0)),
            "the qualifier spelling selects the first source import row: {imports:?}"
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "22f2f70ef463: complete conditional-file summaries must not make Go rename incomplete"
    )]
    fn selected_go_native_rename_confirms_qualified_multifile_inventory() {
        let fixture = InlineTestProject::with_language(Language::Go)
            .file("go.mod", "module example.test/rename\n\ngo 1.22\n")
            .file("provider/api.go", "package provider\nfunc Helper() {}\n")
            .file("provider/other.go", "package provider\nfunc SamePackage() { Helper() }\n")
            .file(
                "client/one.go",
                "package client\nimport pkg \"example.test/rename/provider\"\nfunc One() { pkg.Helper() }\n",
            )
            .file(
                "client/two.go",
                "package client\nimport pkg \"example.test/rename/provider\"\nfunc Two() { pkg.Helper() }\n",
            )
            .file(
                "client/build_constrained.go",
                "//go:build bifrost_unselected\n\npackage client\n\nimport pkg \"example.test/rename/provider\"\n\nfunc Unselected() { pkg.Helper() }\n",
            )
            .build();
        let analyzer = GoAnalyzer::new(fixture.project_dyn());
        persist_selected_go_sources(&analyzer);
        crate::analyzer::store::resolution_operation::go_reverse_rows::
            reset_go_reverse_qualified_imports_for_test();
        let target = target_at(&analyzer, &fixture, "provider/api.go", "Helper");
        let renamed = super::super::native_rename::go_native_rename(
            &analyzer,
            fixture.project(),
            &target,
            "Assist",
            &CancellationToken::new(),
        )
        .expect("complete qualified summary rows confirm every candidate site");
        let qualified_imports = crate::analyzer::store::resolution_operation::go_reverse_rows::
            last_go_reverse_qualified_imports_for_test();
        assert_eq!(
            qualified_imports.len(),
            3,
            "each qualified fixture site reaches its source import binder: {qualified_imports:?}"
        );
        assert!(
            qualified_imports
                .iter()
                .all(|(_, _, import_id)| import_id.is_some()),
            "the stored qualifier path selects exact source import IDs: {qualified_imports:?}"
        );
        assert_eq!(renamed.files.len(), 5, "{renamed:#?}");
        assert!(
            renamed.files.iter().all(|file| !file.edits.is_empty()),
            "every selected declaration and confirmed use has an edit: {renamed:#?}"
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "9df40beaa3e1: counterfactual Go rename publication missed a local capture"
    )]
    fn selected_go_native_rename_checks_capture_after_build_selection_gaps() {
        let fixture = InlineTestProject::with_language(Language::Go)
            .file("go.mod", "module example.test/capture\n\ngo 1.22\n")
            .file(
                "main.go",
                "package capture\nfunc Original() {}\nfunc caller() { taken := 1; Original(); _ = taken }\n",
            )
            .file(
                "build_constrained.go",
                "//go:build bifrost_unselected\n\npackage capture\n\nfunc unselectedCaller() { Original() }\n",
            )
            .build();
        let analyzer = GoAnalyzer::new(fixture.project_dyn());
        persist_selected_go_sources(&analyzer);
        let target = target_at(&analyzer, &fixture, "main.go", "Original");
        let selected = inverse(&analyzer, &target);
        assert!(matches!(selected.completeness, EdgeCompleteness::Complete));
        let error = super::super::native_rename::go_native_rename(
            &analyzer,
            fixture.project(),
            &target,
            "taken",
            &CancellationToken::new(),
        )
        .expect_err("the local variable would capture the renamed call");
        assert_eq!(error.kind, "capture_or_rebinding", "{error:?}");
        assert!(
            error.message.contains("captured") && error.message.contains("taken"),
            "the saved scope rows identify the capturing local declaration: {error:?}"
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "9df40beaa3e1: counterfactual Go rename publication missed a root-name rebinding"
    )]
    fn selected_go_native_rename_detects_rebinding_of_an_existing_builtin_reference() {
        let fixture = InlineTestProject::with_language(Language::Go)
            .file("go.mod", "module example.test/rename\n\ngo 1.22\n")
            .file(
                "main.go",
                "package rename\nfunc Original() {}\nfunc useOriginal() { Original() }\nfunc useBuiltin() { _ = len([]int{1}) }\n",
            )
            .build();
        let analyzer = GoAnalyzer::new(fixture.project_dyn());
        persist_selected_go_sources(&analyzer);
        let target = target_at(&analyzer, &fixture, "main.go", "Original");

        let error = super::super::native_rename::go_native_rename(
            &analyzer,
            fixture.project(),
            &target,
            "len",
            &CancellationToken::new(),
        )
        .expect_err("renaming to len would rebind the existing builtin call");
        assert_eq!(error.kind, "capture_or_rebinding", "{error:?}");
        assert!(
            error.message.contains("rebinds") && error.message.contains("len"),
            "the saved root-terminal path names the rebound builtin use: {error:?}"
        );
    }
}
