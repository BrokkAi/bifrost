//! Public declaration identities for selected native definition semantics.
//! Package anchors come from the selected revision, never live path discovery.

use super::*;
use crate::analyzer::PackageAnchor;
use crate::analyzer::resolution::NamedArgumentLabelRead;

pub(in crate::analyzer::store) const GO_DEFINITION_PACKAGE_ANCHOR: &str =
    "SELECT package_name FROM main.workspace_file_anchor_rows AS anchors
     WHERE file_version_id=?1 AND anchor_kind='own_module' AND anchor_pop=0";

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SelectedNativeDefinition {
    Unit(CodeUnit),
    Lexical(LexicalDefinition),
    Intrinsic {
        canonical_name: String,
        tier: Option<crate::analyzer::structural::PrecedenceTier>,
    },
}

pub(crate) enum SelectedNativeDefinitions {
    Ready(Vec<(SemanticId, SelectedNativeDefinition)>),
    Unavailable,
    Cancelled,
}

pub(crate) struct ProjectedNativeExternalMember {
    pub(crate) identity: crate::analyzer::resolution::ExternalMemberIdentity,
    pub(crate) member_name: String,
    pub(crate) is_static: bool,
}

pub(crate) struct SelectedNativeReferenceUnits {
    pub(crate) answer: FactResolutionAnswer,
    pub(crate) definitions: SelectedNativeDefinitions,
    pub(crate) external_members: Vec<ProjectedNativeExternalMember>,
    pub(crate) direct_target: Option<NativeExternalMemberTarget>,
    pub(crate) named_argument: Option<SelectedNativeNamedArgument>,
    pub(crate) predeclared_go_symbol: bool,
    pub(crate) callable_applicability_candidates: Vec<(SemanticId, CodeUnit)>,
    pub(crate) member_contexts: Vec<ProjectedNativeMemberContext>,
    pub(crate) trace_provenance: ProjectedNativeTraceProvenance,
    pub(crate) declared_visibilities:
        Vec<(CodeUnit, crate::analyzer::structural::DeclaredVisibility)>,
    /// The owner types of the answer's absent-member fact, projected to their
    /// declarations. Empty when the answer has no such fact or an owner has no
    /// source-unit projection, so a consumer never names part of the owner set.
    pub(crate) absent_member_owners: Vec<CodeUnit>,
    pub(crate) named_reasons: Vec<(&'static str, String)>,
}

pub(crate) enum SelectedNativeNamedArgument {
    Resolved(SelectedNativeDefinition),
    Incomplete(String),
}

#[derive(Debug)]
pub(crate) struct ProjectedNativeMemberContext {
    pub(crate) target_identity: SemanticId,
    pub(crate) target: CodeUnit,
    pub(crate) owner_path: Vec<CodeUnit>,
    pub(crate) route_kind: crate::analyzer::resolution::FactMemberRouteKind,
    pub(crate) go_interface_owner: Option<bool>,
    pub(crate) selected: bool,
    pub(crate) rejection: Option<crate::analyzer::structural::RejectionReason>,
    /// The native callable verdict for this member's target, or `Unknown` when
    /// the answer recorded none. Member attribution reports it as the
    /// candidate's applicability.
    pub(crate) applicability:
        brokk_bifrost_core::analyzer::structural::callable::ApplicabilityVerdict,
}

pub(crate) enum SelectedNativeTypes {
    Ready {
        nominal: Vec<(SemanticId, SelectedNativeDefinition)>,
        intrinsic: Box<[crate::analyzer::resolution::FactIntrinsicTypeDescriptor]>,
        external_owners: Vec<(
            SemanticId,
            crate::analyzer::resolution::ExternalOwnerIdentity,
        )>,
    },
    Unavailable,
    Cancelled,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum NativeExternalMemberTarget {
    Indexed(crate::analyzer::resolution::ExternalMemberIdentity),
    Unindexed {
        provider_path: std::sync::Arc<str>,
        provider_package_id: Option<i64>,
        member_name: String,
    },
}

pub(crate) struct SelectedNativeReferenceTypes {
    pub(crate) named_reasons: Vec<(&'static str, String)>,
    pub(crate) answer: FactResolutionAnswer,
    pub(crate) value_types: SelectedNativeTypes,
    /// A whole expression selects its exact value slot independently of the
    /// binding projections that its callee reference happens to publish.
    pub(crate) query_result_slot: Option<SemanticId>,
    /// Direct external-member evidence from the same selected answer, with
    /// indexed identities distinguished from unknown provider frontiers.
    /// Keeping this beside the projected expression type prevents consumers
    /// from trying to join mount-local semantic IDs from separate operations.
    pub(crate) direct_target: Option<NativeExternalMemberTarget>,
}

type NativeReferenceUnitsOutcome =
    SelectedResolutionOperationOutcome<SelectedResolutionLocated<SelectedNativeReferenceUnits>>;
type NativeReferenceTypesOutcome =
    SelectedResolutionOperationOutcome<SelectedResolutionLocated<SelectedNativeReferenceTypes>>;

#[cfg(any(test, feature = "test-support"))]
pub(crate) struct SelectedNativeAssignmentValue {
    pub(crate) types: SelectedNativeReferenceTypes,
    pub(crate) observed_frontier_complete: bool,
}

#[cfg(any(test, feature = "test-support"))]
type NativeAssignmentValueOutcome =
    SelectedResolutionOperationOutcome<SelectedResolutionLocated<SelectedNativeAssignmentValue>>;

/// Apply the session's cancellation and budget boundary even when setup or a
/// projection returns an explicit missing-evidence error.
#[cfg(any(test, feature = "test-support"))]
fn finish_assignment_value_query<T>(
    session: &ResolutionSession,
    outcome: Result<T>,
) -> Result<BoundedResolution<T>> {
    Ok(match session.finish(outcome) {
        BoundedResolution::Complete { value, work } => BoundedResolution::Complete {
            value: value?,
            work,
        },
        BoundedResolution::Cancelled { work } => BoundedResolution::Cancelled { work },
        BoundedResolution::Exceeded { limit, work } => BoundedResolution::Exceeded { limit, work },
    })
}

#[cfg(any(test, feature = "test-support"))]
fn assignment_value_answer(
    ready: &ReadySelectedResolution<'_, '_>,
    answer: FactResolutionAnswer,
    slot: SemanticId,
    value_types: SelectedNativeTypes,
) -> Result<SelectedNativeAssignmentValue> {
    let frontier = answer
        .projected_frontiers()
        .iter()
        .find(|frontier| frontier.slot() == slot)
        .ok_or_else(|| StoreError::new("assignment-value probe has no observed frontier"))?;
    let observed_frontier_complete = frontier.completion() == &ResolutionCompletion::Complete;
    let named_reasons = named_reason_details(ready, answer.completion())?;
    Ok(SelectedNativeAssignmentValue {
        types: SelectedNativeReferenceTypes {
            named_reasons,
            answer,
            value_types,
            query_result_slot: Some(slot),
            direct_target: None,
        },
        observed_frontier_complete,
    })
}

impl SelectedResolutionOperation<'_, '_> {
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn resolve_native_assignment_value_bounded(
        &mut self,
        context: SelectedResolutionContextSet,
        locator: &SelectedSemanticLocator,
        budget: ReceiverAnalysisBudget,
        cancellation: &CancellationToken,
    ) -> Result<BoundedResolution<NativeAssignmentValueOutcome>> {
        let session = ResolutionSession::bounded(budget, Some(cancellation));
        self.resolve_native_assignment_value_in_session(super::NativeReferenceQuery {
            context,
            locator,
            cancellation,
            context_metrics: &mut SelectedResolutionContextMetrics,
            session: &session,
            artifacts: None,
            go_demand: None,
            selected_import_gap: None,
            go_receiver_overlay: None,
            query_result_slot: None,
            point_metrics: None,
        })
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn resolve_go_assignment_value_bounded(
        &mut self,
        prepared: super::GoPreparedImportContext,
        locator: &SelectedSemanticLocator,
        budget: ReceiverAnalysisBudget,
        cancellation: &CancellationToken,
    ) -> Result<BoundedResolution<NativeAssignmentValueOutcome>> {
        let session = ResolutionSession::bounded(budget, Some(cancellation));
        self.resolve_native_assignment_value_in_session(super::NativeReferenceQuery {
            context: prepared.context,
            locator,
            cancellation,
            context_metrics: &mut SelectedResolutionContextMetrics,
            session: &session,
            artifacts: None,
            go_demand: Some(prepared.demand),
            selected_import_gap: None,
            go_receiver_overlay: None,
            query_result_slot: None,
            point_metrics: None,
        })
    }

    #[cfg(any(test, feature = "test-support"))]
    fn resolve_native_assignment_value_in_session(
        &mut self,
        query: super::NativeReferenceQuery<'_>,
    ) -> Result<BoundedResolution<NativeAssignmentValueOutcome>> {
        let slot = std::cell::Cell::new(None);
        assert!(query.query_result_slot.is_none());
        let session = query.session;
        let cancellation = query.cancellation;
        let outcome = self.resolve_reference_with_projection_and_setup(
            query,
            |operation, reference| {
                slot.set(Some(
                    operation.select_native_assignment_value_slot(reference)?,
                ));
                Ok(())
            },
            |ready, operation, _, answer| {
                let types = project_native_reference_types(
                    ready,
                    operation,
                    &answer,
                    cancellation,
                    session,
                )?;
                assignment_value_answer(
                    ready,
                    answer,
                    slot.get()
                        .expect("assignment query setup selected its slot"),
                    types,
                )
            },
        );
        finish_assignment_value_query(session, outcome)
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn resolve_rust_assignment_value_bounded(
        &mut self,
        caller: &Path,
        locator: &SelectedSemanticLocator,
        budget: ReceiverAnalysisBudget,
        cancellation: &CancellationToken,
    ) -> Result<BoundedResolution<NativeAssignmentValueOutcome>> {
        let session = ResolutionSession::bounded(budget, Some(cancellation));
        let slot = std::cell::Cell::new(None);
        let outcome = self.resolve_rust_references_for_caller_with_setup(
            caller,
            &[locator],
            cancellation,
            &mut SelectedResolutionContextMetrics,
            &mut ResolutionBatchMetrics::default(),
            &session,
            RustDeclarationAccessKind::Caller,
            |operation, reference| {
                if slot.get().is_some() {
                    return Err(StoreError::new("assignment-value probe has ambiguous reference sites"));
                }
                slot.set(Some(operation.select_native_assignment_value_slot(reference)?));
                Ok(())
            },
            |operation, answer, ready, mounts, session, cancellation| {
                let types = match project_rust_reference_types(
                    operation, answer, ready, mounts, session, cancellation, locator,
                )? {
                    SelectedResolutionOperationOutcome::Native(types) => types,
                    SelectedResolutionOperationOutcome::Unavailable(reason) => {
                        return Ok(SelectedResolutionOperationOutcome::Unavailable(reason));
                    }
                    SelectedResolutionOperationOutcome::Stale(reason) => {
                        return Ok(SelectedResolutionOperationOutcome::Stale(reason));
                    }
                    SelectedResolutionOperationOutcome::Cancelled(completion) => {
                        return Ok(SelectedResolutionOperationOutcome::Cancelled(completion));
                    }
                };
                let nominal = types.nominal_types.into_iter().map(|(identity, definition)| {
                    let definition = match definition {
                        SelectedRustSourceDefinition::Unit(unit) => SelectedNativeDefinition::Unit(unit),
                        SelectedRustSourceDefinition::Lexical(definition) => SelectedNativeDefinition::Lexical(definition),
                        SelectedRustSourceDefinition::UniverseEntry
                        | SelectedRustSourceDefinition::WithoutUnit { .. } => return Err(StoreError::new("assignment-value nominal type has no source projection")),
                    };
                    Ok((identity, definition))
                }).collect::<Result<Vec<_>>>()?;
                Ok(SelectedResolutionOperationOutcome::Native(assignment_value_answer(
                    ready,
                    answer.clone(),
                    slot.get().expect("assignment query setup selected its slot"),
                    SelectedNativeTypes::Ready {
                        nominal,
                        intrinsic: types.intrinsic_types,
                        external_owners: Vec::new(),
                    },
                )?))
            },
        ).and_then(|outcome| {
            Ok(match outcome.into_single() {
                SelectedRustCallerReferenceOutcome::UnsupportedCallerProfile => {
                    return Err(StoreError::new("assignment-value probe has no supported Rust caller profile"));
                }
                SelectedRustCallerReferenceOutcome::Operation(outcome) => match outcome {
                    SelectedResolutionOperationOutcome::Native(located) => {
                        SelectedResolutionOperationOutcome::Native(match located {
                            SelectedResolutionLocated::Missing => SelectedResolutionLocated::Missing,
                            SelectedResolutionLocated::Found(mut answers) => {
                                if answers.len() != 1 {
                                    return Err(StoreError::new("assignment-value probe requires one exact Rust reference"));
                                }
                                SelectedResolutionLocated::Found(answers.remove(0).projection)
                            }
                        })
                    }
                    SelectedResolutionOperationOutcome::Unavailable(reason) => SelectedResolutionOperationOutcome::Unavailable(reason),
                    SelectedResolutionOperationOutcome::Stale(reason) => SelectedResolutionOperationOutcome::Stale(reason),
                    SelectedResolutionOperationOutcome::Cancelled(completion) => SelectedResolutionOperationOutcome::Cancelled(completion),
                },
            })
        });
        finish_assignment_value_query(&session, outcome)
    }

    pub(crate) fn resolve_native_reference_types_bounded(
        mut self,
        context: SelectedResolutionContextSet,
        locator: &SelectedSemanticLocator,
        budget: ReceiverAnalysisBudget,
        cancellation: &CancellationToken,
        context_metrics: &mut SelectedResolutionContextMetrics,
    ) -> Result<BoundedResolution<NativeReferenceTypesOutcome>> {
        let query_result_slot = match (locator.reference_range(), locator.call_argument_ordinal()) {
            (Some((start, end)), Some(ordinal)) => self.point_call_argument_slot_at(
                locator.storage_language(),
                locator.relative_path(),
                start,
                end,
                ordinal,
                cancellation,
            )?,
            (Some((start, end)), None) if locator.storage_language() == "java" => self
                .point_expression_value_slot_at(
                    locator.storage_language(),
                    locator.relative_path(),
                    start,
                    end,
                    cancellation,
                )?,
            _ => None,
        };
        if locator.call_argument_ordinal().is_some() && query_result_slot.is_none() {
            return Ok(if cancellation.is_cancelled() {
                BoundedResolution::Cancelled {
                    work: Default::default(),
                }
            } else {
                BoundedResolution::Complete {
                    value: SelectedResolutionOperationOutcome::Native(
                        SelectedResolutionLocated::Missing,
                    ),
                    work: Default::default(),
                }
            });
        }
        let session = ResolutionSession::bounded(budget, Some(cancellation));
        let outcome = self.resolve_reference_with_projection(
            super::NativeReferenceQuery {
                context,
                locator,
                cancellation,
                context_metrics,
                session: &session,
                artifacts: None,
                go_demand: None,
                selected_import_gap: None,
                go_receiver_overlay: None,
                query_result_slot,
                point_metrics: None,
            },
            |ready, operation, _, answer| {
                let types = project_native_reference_types(
                    ready,
                    operation,
                    &answer,
                    cancellation,
                    &session,
                )?;
                let named_reasons = named_reason_details(ready, answer.completion())?;
                let direct_target = selected_external_member_target(ready, &answer, cancellation)?;
                Ok(SelectedNativeReferenceTypes {
                    answer,
                    value_types: types,
                    query_result_slot,
                    direct_target,
                    named_reasons,
                })
            },
        )?;
        Ok(session.finish(outcome))
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn resolve_native_reference_types_bounded_for_go_request(
        &mut self,
        prepared: super::GoPreparedImportContext,
        query_result_slot: Option<SemanticId>,
        go_receiver_overlay: Option<crate::analyzer::resolution::GoReceiverSlotTypeOverlay>,
        locator: &SelectedSemanticLocator,
        budget: ReceiverAnalysisBudget,
        cancellation: &CancellationToken,
        context_metrics: &mut SelectedResolutionContextMetrics,
        artifacts: &mut crate::analyzer::resolution::ForwardCandidateArtifactCache,
        point_metrics: &mut crate::analyzer::resolution::ResolutionBatchMetrics,
    ) -> Result<BoundedResolution<NativeReferenceTypesOutcome>> {
        let session = ResolutionSession::bounded(budget, Some(cancellation));
        let outcome = self.resolve_reference_with_projection(
            super::NativeReferenceQuery {
                context: prepared.context,
                locator,
                cancellation,
                context_metrics,
                session: &session,
                artifacts: Some(artifacts),
                go_demand: Some(prepared.demand),
                selected_import_gap: None,
                go_receiver_overlay,
                query_result_slot,
                point_metrics: Some(point_metrics),
            },
            |ready, operation, _, answer| {
                let types = project_native_reference_types(
                    ready,
                    operation,
                    &answer,
                    cancellation,
                    &session,
                )?;
                let named_reasons = named_reason_details(ready, answer.completion())?;
                let direct_target = selected_external_member_target(ready, &answer, cancellation)?;
                Ok(SelectedNativeReferenceTypes {
                    answer,
                    value_types: types,
                    query_result_slot,
                    direct_target,
                    named_reasons,
                })
            },
        )?;
        Ok(session.finish(outcome))
    }

    pub(crate) fn resolve_native_reference_units(
        mut self,
        context: SelectedResolutionContextSet,
        locator: &SelectedSemanticLocator,
        cancellation: &CancellationToken,
        context_metrics: &mut SelectedResolutionContextMetrics,
    ) -> Result<NativeReferenceUnitsOutcome> {
        self.resolve_native_reference_units_in_session(super::NativeReferenceQuery {
            context,
            locator,
            cancellation,
            context_metrics,
            session: &ResolutionSession::unbounded(),
            artifacts: None,
            go_demand: None,
            selected_import_gap: None,
            go_receiver_overlay: None,
            query_result_slot: None,
            point_metrics: None,
        })
    }

    pub(crate) fn resolve_native_reference_units_bounded(
        self,
        context: SelectedResolutionContextSet,
        locator: &SelectedSemanticLocator,
        budget: ReceiverAnalysisBudget,
        cancellation: &CancellationToken,
        context_metrics: &mut SelectedResolutionContextMetrics,
    ) -> Result<BoundedResolution<NativeReferenceUnitsOutcome>> {
        self.resolve_native_reference_units_bounded_with_import_gap(
            context,
            locator,
            budget,
            cancellation,
            context_metrics,
            None,
        )
    }

    pub(crate) fn resolve_native_reference_units_bounded_with_import_gap(
        mut self,
        context: SelectedResolutionContextSet,
        locator: &SelectedSemanticLocator,
        budget: ReceiverAnalysisBudget,
        cancellation: &CancellationToken,
        context_metrics: &mut SelectedResolutionContextMetrics,
        selected_import_gap: Option<(SemanticId, SemanticId)>,
    ) -> Result<BoundedResolution<NativeReferenceUnitsOutcome>> {
        let session = ResolutionSession::bounded(budget, Some(cancellation));
        let outcome =
            self.resolve_native_reference_units_in_session(super::NativeReferenceQuery {
                context,
                locator,
                cancellation,
                context_metrics,
                session: &session,
                artifacts: None,
                go_demand: None,
                selected_import_gap,
                go_receiver_overlay: None,
                query_result_slot: None,
                point_metrics: None,
            })?;
        Ok(session.finish(outcome))
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn resolve_native_reference_units_bounded_for_go_request(
        &mut self,
        prepared: super::GoPreparedImportContext,
        go_receiver_overlay: Option<crate::analyzer::resolution::GoReceiverSlotTypeOverlay>,
        locator: &SelectedSemanticLocator,
        budget: ReceiverAnalysisBudget,
        cancellation: &CancellationToken,
        context_metrics: &mut SelectedResolutionContextMetrics,
        artifacts: &mut crate::analyzer::resolution::ForwardCandidateArtifactCache,
        point_metrics: &mut crate::analyzer::resolution::ResolutionBatchMetrics,
    ) -> Result<BoundedResolution<NativeReferenceUnitsOutcome>> {
        let session = ResolutionSession::bounded(budget, Some(cancellation));
        let outcome =
            self.resolve_native_reference_units_in_session(super::NativeReferenceQuery {
                context: prepared.context,
                locator,
                cancellation,
                context_metrics,
                session: &session,
                artifacts: Some(artifacts),
                go_demand: Some(prepared.demand),
                selected_import_gap: None,
                go_receiver_overlay,
                query_result_slot: None,
                point_metrics: Some(point_metrics),
            })?;
        Ok(session.finish(outcome))
    }

    fn resolve_native_reference_units_in_session(
        &mut self,
        query: super::NativeReferenceQuery<'_>,
    ) -> Result<NativeReferenceUnitsOutcome> {
        let super::NativeReferenceQuery {
            context,
            locator,
            cancellation,
            context_metrics,
            session,
            artifacts,
            go_demand,
            selected_import_gap,
            go_receiver_overlay,
            query_result_slot,
            point_metrics,
        } = query;
        self.resolve_reference_with_projection(
            super::NativeReferenceQuery {
                context,
                locator,
                cancellation,
                context_metrics,
                session,
                artifacts,
                go_demand,
                selected_import_gap,
                go_receiver_overlay,
                query_result_slot,
                point_metrics,
            },
            |ready, operation, reference, answer| {
                let named_reasons = named_reason_details(ready, answer.binding().completion())?;
                let named_argument = resolve_named_argument_parameter(
                    ready,
                    operation,
                    reference,
                    cancellation,
                    session,
                )?;
                let applicability_targets = answer
                    .callable_candidate_applicability()
                    .iter()
                    .map(|candidate| candidate.target())
                    .collect::<Vec<_>>();
                let mut external_members = Vec::new();
                for &target in answer.binding().targets() {
                    if let Some((owner, ordinal)) = ready.context_identities.external_member_identity(target) {
                        let (member_name, is_static) = ready.inventory.connection().query_row(
                            "SELECT member_name,is_static FROM jvm_external_owner_members WHERE provider_id=?1 AND owner_fqn=?2 AND ordinal=?3",
                            rusqlite::params![owner.provider_id.as_ref(),owner.owner_fqn.as_ref(),ordinal],
                            |row| Ok((row.get(0)?,row.get(1)?)))?;
                        external_members.push(ProjectedNativeExternalMember {
                            identity: crate::analyzer::resolution::ExternalMemberIdentity { owner, ordinal },
                            member_name, is_static,
                        });
                    }
                }
                let mut definitions = project_native_definition_units(
                    ready,
                    answer.binding().targets(),
                    cancellation,
                    session,
                )?;
                let mut predeclared_go_symbol = false;
                if matches!(&definitions, SelectedNativeDefinitions::Unavailable)
                    && answer.binding().targets().len() == 1
                    && answer.binding().completion() == &ResolutionCompletion::Complete
                {
                    let source = ready.lexical_source();
                    match crate::analyzer::resolution::is_go_universe_identity(
                        &source,
                        answer.binding().targets()[0],
                        cancellation,
                    )? {
                        Some(true) => predeclared_go_symbol = true,
                        Some(false) => {}
                        None => {
                            assert!(cancellation.is_cancelled());
                            definitions = SelectedNativeDefinitions::Cancelled;
                        }
                    }
                }
                let selected_targets = answer
                    .binding()
                    .targets()
                    .iter()
                    .copied()
                    .collect::<BTreeSet<_>>();
                let additional_applicability_targets = applicability_targets
                    .iter()
                    .copied()
                    .filter(|target| !selected_targets.contains(target))
                    .collect::<Vec<_>>();
                let callable_applicability_candidates = match project_native_definition_units(
                    ready,
                    &additional_applicability_targets,
                    cancellation,
                    session,
                )? {
                    SelectedNativeDefinitions::Ready(rows) => rows
                        .into_iter()
                        .filter_map(|(identity, definition)| match definition {
                            SelectedNativeDefinition::Unit(unit) => Some((identity, unit)),
                            SelectedNativeDefinition::Lexical(_) | SelectedNativeDefinition::Intrinsic { .. } => None,
                        })
                        .collect(),
                    SelectedNativeDefinitions::Unavailable
                    | SelectedNativeDefinitions::Cancelled => Vec::new(),
                };
                let member_contexts = project_native_member_contexts(ready, &answer, cancellation)?;
                let trace_provenance = project_native_trace_provenance(ready, &answer, &definitions, &callable_applicability_candidates, &member_contexts, cancellation)?;
                let declared_visibilities = project_native_declared_visibilities(
                    ready, &definitions, &callable_applicability_candidates, &member_contexts, &trace_provenance.visibility_units, cancellation,
                )?;
                let absent_member_owners = project_absent_member_owners(
                    ready,
                    answer.absent_member_owners(),
                    cancellation,
                    session,
                )?;
                let direct_target = selected_external_member_target(ready, &answer, cancellation)?;
                Ok(SelectedNativeReferenceUnits {
                    answer,
                    definitions,
                    external_members,
                    direct_target,
                    named_argument,
                    predeclared_go_symbol,
                    callable_applicability_candidates,
                    member_contexts,
                    trace_provenance,
                    declared_visibilities,
                    absent_member_owners,
                    named_reasons,
                })
            },
        )
    }
}

fn selected_external_member_target(
    ready: &ReadySelectedResolution<'_, '_>,
    answer: &FactResolutionAnswer,
    cancellation: &CancellationToken,
) -> Result<Option<NativeExternalMemberTarget>> {
    if let [target] = answer.binding().targets()
        && let Some((owner, ordinal)) = ready.context_identities.external_member_identity(*target)
    {
        return Ok(Some(NativeExternalMemberTarget::Indexed(
            crate::analyzer::resolution::ExternalMemberIdentity { owner, ordinal },
        )));
    }
    let frontiers = answer
        .projected_frontiers()
        .iter()
        .flat_map(|state| state.unindexed_external())
        .collect::<BTreeSet<_>>();
    let mut frontiers = frontiers.into_iter();
    let Some(frontier) = frontiers.next() else {
        return Ok(None);
    };
    if frontiers.next().is_some() {
        return Ok(None);
    }
    let Some((fragment, lookup)) = frontier.member else {
        return Ok(None);
    };
    let SelectedLookupRecipeReadOutcome::Ready(recipes) =
        ready.lexical_source().lookup_semantic_recipes(
            &[SelectedLookupRecipeRequest {
                fragment,
                semantic: lookup,
            }],
            cancellation,
            None,
        )?
    else {
        return Ok(None);
    };
    let recipe = recipes.into_iter().next().flatten().ok_or_else(|| {
        StoreError::corrupt("unindexed external member has no structured lookup recipe")
    })?;
    Ok(Some(NativeExternalMemberTarget::Unindexed {
        provider_path: frontier.provider_path.clone(),
        provider_package_id: frontier.provider_package_id,
        member_name: recipe.spelling().to_owned(),
    }))
}

fn resolve_named_argument_parameter(
    ready: &ReadySelectedResolution<'_, '_>,
    operation: &mut crate::analyzer::resolution::FactResolutionOperation<'_>,
    reference: SemanticId,
    cancellation: &CancellationToken,
    session: &ResolutionSession,
) -> Result<Option<SelectedNativeNamedArgument>> {
    let label = match operation.named_argument_label_for_reference(reference)? {
        NamedArgumentLabelRead::Found(label) => label,
        NamedArgumentLabelRead::Missing => return Ok(None),
        NamedArgumentLabelRead::Cancelled => return Ok(None),
    };
    let Some(callee_reference) = label.callee_reference else {
        return Ok(Some(SelectedNativeNamedArgument::Incomplete(format!(
            "named-argument call {:?} has no selected call obligation",
            label.call
        ))));
    };
    if cancellation.is_cancelled() || !session.scope_step() {
        return Ok(None);
    }
    let call_answer = operation.resolve_reference(callee_reference)?;
    if cancellation.is_cancelled() {
        return Ok(None);
    }
    let binding = call_answer.binding();
    let [target] = binding.targets() else {
        return Ok(Some(SelectedNativeNamedArgument::Incomplete(format!(
            "named-argument call {:?} has no unique selected callable: targets={:?}, completion={:?}",
            label.call,
            binding.targets(),
            call_answer.completion()
        ))));
    };
    if binding.completion() != &ResolutionCompletion::Complete
        || call_answer.completion() != &ResolutionCompletion::Complete
    {
        return Ok(Some(SelectedNativeNamedArgument::Incomplete(format!(
            "named-argument call {:?} has a selected callable {target:?} but its resolution is incomplete: binding={:?}, resolution={:?}",
            label.call,
            binding.completion(),
            call_answer.completion()
        ))));
    }
    let receiver_dispositions = call_answer.callable_receiver_dispositions();
    let dispatch_is_proven = receiver_dispositions.iter().all(|disposition| {
        disposition.target() == *target && disposition.disposition().gap().is_none()
    });
    let dispatch_evidence_present =
        call_answer.callable_receiver_origin().is_none() || !receiver_dispositions.is_empty();
    if !dispatch_is_proven || !dispatch_evidence_present {
        return Ok(Some(SelectedNativeNamedArgument::Incomplete(format!(
            "named-argument call {:?} lacks complete dispatch evidence for callable {target:?}: receiver_dispositions={receiver_dispositions:?}",
            label.call,
        ))));
    }
    let Some(parameter) = operation.callable_parameter_for_label(*target, &label.spelling)? else {
        return Ok(Some(SelectedNativeNamedArgument::Incomplete(format!(
            "selected callable {target:?} has no unique parameter named {:?}",
            label.spelling
        ))));
    };
    if cancellation.is_cancelled() || !session.scope_step() {
        return Ok(None);
    }
    let SelectedNativeDefinitions::Ready(mut parameters) =
        project_native_definition_units(ready, &[parameter], cancellation, session)?
    else {
        return Ok(Some(SelectedNativeNamedArgument::Incomplete(format!(
            "selected parameter {parameter:?} has no native source-unit projection"
        ))));
    };
    let Some((projected_parameter, definition)) = parameters.pop() else {
        return Ok(Some(SelectedNativeNamedArgument::Incomplete(format!(
            "selected parameter {parameter:?} has no native source-unit projection"
        ))));
    };
    assert_eq!(projected_parameter, parameter);
    assert!(parameters.is_empty());
    Ok(Some(SelectedNativeNamedArgument::Resolved(definition)))
}

fn project_native_reference_types(
    ready: &ReadySelectedResolution<'_, '_>,
    operation: &mut crate::analyzer::resolution::FactResolutionOperation<'_>,
    answer: &FactResolutionAnswer,
    cancellation: &CancellationToken,
    session: &ResolutionSession,
) -> Result<SelectedNativeTypes> {
    let mut identities = BTreeSet::new();
    for frontier in answer.projected_frontiers() {
        for value in frontier.possible_values() {
            if !session.scope_step() {
                return Ok(SelectedNativeTypes::Cancelled);
            }
            identities.insert(value.ty().identity());
        }
    }
    for shape in answer.projected_type_shapes() {
        for node in shape.nodes() {
            if !session.scope_step() {
                return Ok(SelectedNativeTypes::Cancelled);
            }
            if !matches!(node.form(), FactProjectedTypeNodeForm::Alias(_)) {
                identities.insert(node.identity());
            }
        }
    }
    if let Some(identity) = answer.observed_type_identity() {
        if !session.scope_step() {
            return Ok(SelectedNativeTypes::Cancelled);
        }
        identities.insert(identity);
    }
    let identities = identities.into_iter().collect::<Vec<_>>();
    let Some(intrinsic) = operation.read_intrinsic_type_descriptors(&identities)? else {
        return Ok(SelectedNativeTypes::Cancelled);
    };
    let intrinsic_identities = intrinsic
        .iter()
        .map(|descriptor| descriptor.identity())
        .collect::<BTreeSet<_>>();
    let external_owners = identities
        .iter()
        .filter_map(|&identity| {
            ready
                .context_identities
                .external_owner_identity(identity)
                .map(|owner| (identity, owner))
        })
        .collect::<Vec<_>>();
    let external_identities = external_owners
        .iter()
        .map(|(identity, _)| *identity)
        .collect::<BTreeSet<_>>();
    let nominal = identities
        .into_iter()
        .filter(|identity| {
            !intrinsic_identities.contains(identity) && !external_identities.contains(identity)
        })
        .collect::<Vec<_>>();
    Ok(
        match project_native_definition_units(ready, &nominal, cancellation, session)? {
            SelectedNativeDefinitions::Ready(nominal) => SelectedNativeTypes::Ready {
                nominal,
                intrinsic,
                external_owners,
            },
            SelectedNativeDefinitions::Unavailable => SelectedNativeTypes::Unavailable,
            SelectedNativeDefinitions::Cancelled => SelectedNativeTypes::Cancelled,
        },
    )
}

/// The rows one batch read for its fragment-local definitions. A definition's
/// entries are removed when it is projected.
struct FragmentDefinitionRows {
    units: BTreeMap<
        (SelectedResolutionMountOrdinal, ResolutionLocalKey),
        Vec<super::super::HydratedCandidateRow>,
    >,
    lexical: BTreeMap<
        (SelectedResolutionMountOrdinal, ResolutionLocalKey),
        super::super::selected_definition::SelectedDeclarationDefinition,
    >,
}

/// Read the parser units and lexical declarations of every coordinate in one
/// batch. `None` when cancelled. The reads page by coordinate, so a batch
/// costs one temp write per page, not one per definition.
fn read_fragment_definition_rows(
    ready: &ReadySelectedResolution<'_, '_>,
    coordinates: &[(SelectedResolutionMountOrdinal, ResolutionLocalKey)],
    cancellation: &CancellationToken,
) -> Result<Option<FragmentDefinitionRows>> {
    let SelectedDefinitionUnitReadOutcome::Ready(definition_rows) = ready
        .inventory
        .selected_definition_units(coordinates, cancellation)?
    else {
        return Ok(None);
    };
    let mut units = BTreeMap::new();
    for (mount, key, row) in definition_rows {
        assert!(
            units.insert((mount, key), vec![row]).is_none(),
            "one definition crosswalk has one parser unit"
        );
    }
    let declaration_candidates = coordinates
        .iter()
        .filter(|coordinate| !units.contains_key(coordinate))
        .copied()
        .collect::<Vec<_>>();
    let SelectedDefinitionUnitReadOutcome::Ready(declaration_rows) = ready
        .inventory
        .selected_declaration_unit_candidates(&declaration_candidates, cancellation)?
    else {
        return Ok(None);
    };
    for (mount, key, row) in declaration_rows {
        units.entry((mount, key)).or_default().push(row);
    }
    let missing = coordinates
        .iter()
        .filter(|coordinate| !units.contains_key(coordinate))
        .copied()
        .collect::<Vec<_>>();
    let SelectedLexicalDefinitionReadOutcome::Ready(rows) = ready
        .inventory
        .selected_lexical_definitions(&missing, cancellation)?
    else {
        return Ok(None);
    };
    let mut lexical = BTreeMap::new();
    for (mount, key, row) in rows {
        assert!(
            lexical.insert((mount, key), row).is_none(),
            "one source definition has one lexical declaration"
        );
    }
    Ok(Some(FragmentDefinitionRows { units, lexical }))
}

/// Project one fragment-local definition from its batch's rows. `None` when
/// the definition has no unique parser unit or lexical declaration, which the
/// caller reports as an unavailable definition.
fn project_fragment_definition(
    ready: &ReadySelectedResolution<'_, '_>,
    coordinate: (SelectedResolutionMountOrdinal, ResolutionLocalKey),
    rows: &mut FragmentDefinitionRows,
) -> Result<Option<SelectedNativeDefinition>> {
    let mount = SelectedMountTable::new(&ready.inventory).mount_by_ordinal(coordinate.0)?;
    assert!(
        matches!(
            mount.semantic_language(),
            Language::Java | Language::Go | Language::Scala | Language::Kotlin
        ),
        "native Java/Go/Scala/Kotlin projection requires an admitted frontend"
    );
    let file = ProjectFile::new(ready.project.root(), mount.persisted_relative_path());
    let Some(unit_rows) = rows.units.remove(&coordinate) else {
        let Some(super::super::selected_definition::SelectedDeclarationDefinition::Lexical(
            mut row,
        )) = rows.lexical.remove(&coordinate)
        else {
            return Ok(None);
        };
        row.source_file = Some(file);
        return Ok(Some(SelectedNativeDefinition::Lexical(row)));
    };
    let mut selected_unit = None;
    for row in unit_rows {
        let persisted = row
            .fq
            .as_ref()
            .ok_or_else(|| StoreError::corrupt("source declaration lacks structured identity"))?;
        let prefix = match (mount.semantic_language(), persisted.anchor) {
            (Language::Java, None)
            | (Language::Go, None)
            | (Language::Scala, None)
            | (Language::Kotlin, None) => None,
            (Language::Go, Some(PackageAnchor::OwnModule { pop: 0 })) => {
                let record = ready.inventory.mount_record_by_ordinal(coordinate.0)?;
                let Some(version) = super::go_context::go_placement_file_version(
                    ready.inventory.connection(),
                    &record,
                )?
                else {
                    // An unsaved replacement whose membership inputs changed
                    // has no selected placement; its predecessor is not proof.
                    return Ok(None);
                };
                let package: Option<String> = ready
                    .inventory
                    .connection()
                    .query_row(GO_DEFINITION_PACKAGE_ANCHOR, [version], |row| row.get(0))
                    .optional()?;
                let Some(package) = package else {
                    return Ok(None);
                };
                Some(brokk_bifrost_go::declarations::go_package_fq(&package))
            }
            _ => {
                return Err(StoreError::corrupt(
                    "Java/Go source declaration has an unsupported package anchor",
                ));
            }
        };
        let (fq, package_segments) = super::super::hydrate_unit_fq_with_anchor(
            row.fq.as_ref(),
            &row.content_qualifier,
            &file,
            |_, _, _| prefix,
        )?;
        let expected = CodeUnit::from_fq(
            file.clone(),
            row.kind,
            fq,
            package_segments,
            row.signature.clone(),
            row.flags.synthetic,
        );
        let unit = if let Some(analyzer) = ready.analyzer {
            analyzer
                .declarations_named(&file, expected.identifier())
                .into_iter()
                .find(|unit| unit == &expected)
        } else {
            Some(expected)
        };
        let Some(unit) = unit else {
            continue;
        };
        if selected_unit
            .as_ref()
            .is_some_and(|selected| selected != &unit)
        {
            return Ok(None);
        }
        selected_unit = Some(unit);
    }
    Ok(selected_unit.map(SelectedNativeDefinition::Unit))
}

/// Project an intrinsic semantic identity without inventing a source declaration.
fn project_intrinsic_definition(
    ready: &ReadySelectedResolution<'_, '_>,
    definition: SemanticId,
    cancellation: &CancellationToken,
) -> Result<Option<SelectedNativeDefinition>> {
    if let Some(entry) = crate::analyzer::resolution::universe_entry_for_identity(
        &ready.lexical_source(),
        definition,
        cancellation,
    )? {
        // These are language rules in the fixed table: Go keeps predeclared
        // detection and Scala keeps its existing external-boundary projection.
        return Ok(entry
            .definition_tier
            .map(|tier| SelectedNativeDefinition::Intrinsic {
                canonical_name: entry.identity_spelling.to_owned(),
                tier: Some(tier),
            }));
    }
    use crate::analyzer::resolution::{
        SelectedTypedFactSource, TypedFactPageVisitor, TypedFactRequest,
    };
    let mut result = None;
    let outcome = ready
        .typed_source()
        .visit_intrinsic_type_descriptor_pages_for_type_identities(
            TypedFactRequest::new(std::slice::from_ref(&definition)),
            cancellation,
            &mut TypedFactPageVisitor::new(&mut |page| {
                for selected in page {
                    let row = selected.row();
                    assert_eq!(row.identity(), definition);
                    assert!(!row.spelling().is_empty());
                    let projected = SelectedNativeDefinition::Intrinsic {
                        canonical_name: row.spelling().to_owned(),
                        tier: None,
                    };
                    assert!(
                        result
                            .as_ref()
                            .is_none_or(|existing| existing == &projected)
                    );
                    result = Some(projected);
                }
                Ok(true)
            }),
        )?;
    if !outcome.is_exhausted() {
        return Ok(None);
    }
    Ok(result)
}

pub(super) fn project_native_definition_units(
    ready: &ReadySelectedResolution<'_, '_>,
    definitions: &[SemanticId],
    cancellation: &CancellationToken,
    session: &ResolutionSession,
) -> Result<SelectedNativeDefinitions> {
    let lexical = ready.lexical_source();
    let mut coordinates = Vec::with_capacity(definitions.len());
    let mut source_definitions = Vec::with_capacity(definitions.len());
    let mut projected = Vec::with_capacity(definitions.len());
    for &definition in definitions {
        if ready
            .context_identities
            .external_member_identity(definition)
            .is_some()
        {
            continue;
        }
        if cancellation.is_cancelled() || !session.scope_step() {
            return Ok(SelectedNativeDefinitions::Cancelled);
        }
        let Some(provenance) = lexical.semantic_provenance(definition, cancellation)? else {
            return Ok(SelectedNativeDefinitions::Cancelled);
        };
        match provenance {
            SelectedSemanticProvenance::FragmentLocal(provenance) => {
                source_definitions.push(definition);
                coordinates.push((provenance.mount().ordinal(), provenance.local_key()));
            }
            _ => {
                let Some(intrinsic) =
                    project_intrinsic_definition(ready, definition, cancellation)?
                else {
                    return Ok(if cancellation.is_cancelled() {
                        SelectedNativeDefinitions::Cancelled
                    } else {
                        SelectedNativeDefinitions::Unavailable
                    });
                };
                projected.push((definition, intrinsic));
            }
        }
    }
    let Some(mut rows) = read_fragment_definition_rows(ready, &coordinates, cancellation)? else {
        return Ok(SelectedNativeDefinitions::Cancelled);
    };
    for (&definition, coordinate) in source_definitions.iter().zip(coordinates) {
        if cancellation.is_cancelled() || !session.scope_step() {
            return Ok(SelectedNativeDefinitions::Cancelled);
        }
        // Non-structural intrinsic identities are shared. A fragment-local
        // declaration with no source projection is not a source-free intrinsic.
        let Some(unit) = project_fragment_definition(ready, coordinate, &mut rows)? else {
            return Ok(if cancellation.is_cancelled() {
                SelectedNativeDefinitions::Cancelled
            } else {
                SelectedNativeDefinitions::Unavailable
            });
        };
        projected.push((definition, unit));
    }
    if cancellation.is_cancelled() {
        Ok(SelectedNativeDefinitions::Cancelled)
    } else {
        Ok(SelectedNativeDefinitions::Ready(projected))
    }
}

/// The declarations of the owner types an absent-member fact names, or none
/// when any owner has no parser-unit projection.
fn project_absent_member_owners(
    ready: &ReadySelectedResolution<'_, '_>,
    owners: &[SemanticId],
    cancellation: &CancellationToken,
    session: &ResolutionSession,
) -> Result<Vec<CodeUnit>> {
    if owners.is_empty() {
        return Ok(Vec::new());
    }
    let SelectedNativeDefinitions::Ready(rows) =
        project_native_definition_units(ready, owners, cancellation, session)?
    else {
        return Ok(Vec::new());
    };
    let mut units =
        rows.into_iter()
            .filter_map(|(_, definition)| match definition {
                SelectedNativeDefinition::Unit(unit) => Some(unit),
                SelectedNativeDefinition::Lexical(_)
                | SelectedNativeDefinition::Intrinsic { .. } => None,
            })
            .collect::<Vec<_>>();
    if units.len() != owners.len() {
        return Ok(Vec::new());
    }
    units.sort_unstable();
    Ok(units)
}

/// Project every definition in one batch, with no all-or-nothing outcome: a
/// definition with no source or intrinsic projection has `None`, while the
/// others retain their available projections. `None` overall when cancelled.
///
/// Each entry is what [`project_native_definition_units`] returns for that
/// definition alone, so a caller that needs per-definition outcomes does not
/// have to call it once per definition.
/// Each definition with its projection, or `None` when it has none.
pub(super) type EachDefinitionProjection = Vec<(SemanticId, Option<SelectedNativeDefinition>)>;

pub(super) fn project_native_definition_units_each(
    ready: &ReadySelectedResolution<'_, '_>,
    definitions: &[SemanticId],
    cancellation: &CancellationToken,
) -> Result<Option<EachDefinitionProjection>> {
    let lexical = ready.lexical_source();
    let mut entries = Vec::with_capacity(definitions.len());
    for &definition in definitions {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let Some(provenance) = lexical.semantic_provenance(definition, cancellation)? else {
            return Ok(None);
        };
        let coordinate = match provenance {
            SelectedSemanticProvenance::FragmentLocal(provenance) => {
                Some((provenance.mount().ordinal(), provenance.local_key()))
            }
            // A shared name or generated declaration is not a parser unit.
            _ => None,
        };
        entries.push((definition, coordinate));
    }
    let coordinates = entries
        .iter()
        .filter_map(|(_, coordinate)| *coordinate)
        .collect::<Vec<_>>();
    let Some(mut rows) = read_fragment_definition_rows(ready, &coordinates, cancellation)? else {
        return Ok(None);
    };
    let mut projected = Vec::with_capacity(entries.len());
    for (definition, coordinate) in entries {
        let unit = match coordinate {
            Some(coordinate) => project_fragment_definition(ready, coordinate, &mut rows)?,
            None => project_intrinsic_definition(ready, definition, cancellation)?,
        };
        projected.push((definition, unit));
    }
    if cancellation.is_cancelled() {
        Ok(None)
    } else {
        Ok(Some(projected))
    }
}

fn project_native_member_contexts(
    ready: &ReadySelectedResolution<'_, '_>,
    answer: &FactResolutionAnswer,
    cancellation: &CancellationToken,
) -> Result<Vec<ProjectedNativeMemberContext>> {
    if !crate::analyzer::usages::get_definition::trace::recording() {
        return Ok(Vec::new());
    }
    let member_owners = answer.member_owners();
    let member_rejections = answer.member_rejections();
    let verdict_of = |target: SemanticId| {
        answer
            .callable_candidate_applicability()
            .iter()
            .find(|candidate| candidate.target() == target)
            .map_or(
                brokk_bifrost_core::analyzer::structural::callable::ApplicabilityVerdict::Unknown,
                |candidate| candidate.verdict(),
            )
    };
    if member_owners.is_empty() && member_rejections.is_empty() {
        return Ok(Vec::new());
    }
    let identities = member_owners
        .iter()
        .flat_map(|member| {
            std::iter::once(member.target()).chain(member.owner_path().iter().copied())
        })
        .chain(member_rejections.iter().flat_map(|rejection| {
            std::iter::once(rejection.owner().target())
                .chain(rejection.owner().owner_path().iter().copied())
        }))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let metadata_session = ResolutionSession::unbounded();
    let SelectedNativeDefinitions::Ready(rows) =
        project_native_definition_units(ready, &identities, cancellation, &metadata_session)?
    else {
        return Ok(Vec::new());
    };
    let units =
        rows.into_iter()
            .filter_map(|(identity, definition)| match definition {
                SelectedNativeDefinition::Unit(unit) => Some((identity, unit)),
                SelectedNativeDefinition::Lexical(_)
                | SelectedNativeDefinition::Intrinsic { .. } => None,
            })
            .collect::<BTreeMap<_, _>>();
    let mut contexts = Vec::with_capacity(member_owners.len() + member_rejections.len());
    for member in member_owners {
        let Some(target) = units.get(&member.target()).cloned() else {
            continue;
        };
        let Some(owner_path) = member
            .owner_path()
            .iter()
            .map(|identity| units.get(identity).cloned())
            .collect::<Option<Vec<_>>>()
        else {
            continue;
        };
        contexts.push(ProjectedNativeMemberContext {
            target_identity: member.target(),
            target,
            owner_path,
            route_kind: member.route_kind(),
            go_interface_owner: member.go_interface_owner(),
            selected: answer
                .binding()
                .targets()
                .binary_search(&member.target())
                .is_ok(),
            rejection: None,
            applicability: verdict_of(member.target()),
        });
    }
    for rejection in member_rejections {
        let owner = rejection.owner();
        let Some(target) = units.get(&owner.target()).cloned() else {
            continue;
        };
        let Some(owner_path) = owner
            .owner_path()
            .iter()
            .map(|identity| units.get(identity).cloned())
            .collect::<Option<Vec<_>>>()
        else {
            continue;
        };
        contexts.push(ProjectedNativeMemberContext {
            target_identity: owner.target(),
            target,
            owner_path,
            route_kind: owner.route_kind(),
            go_interface_owner: owner.go_interface_owner(),
            selected: false,
            rejection: Some(rejection.reason()),
            applicability: verdict_of(owner.target()),
        });
    }
    Ok(contexts)
}

/// Selected declaration properties for this query's projected candidates only.
fn project_native_declared_visibilities(
    ready: &ReadySelectedResolution<'_, '_>,
    definitions: &SelectedNativeDefinitions,
    callable_candidates: &[(SemanticId, CodeUnit)],
    member_contexts: &[ProjectedNativeMemberContext],
    visibility_units: &[(SemanticId, CodeUnit)],
    cancellation: &CancellationToken,
) -> Result<Vec<(CodeUnit, crate::analyzer::structural::DeclaredVisibility)>> {
    use crate::analyzer::resolution::{
        SelectedTypedFactSource, TypedFactPageVisitor, TypedFactRequest,
    };
    if !crate::analyzer::usages::get_definition::trace::recording() {
        return Ok(Vec::new());
    }
    let mut units = BTreeMap::new();
    if let SelectedNativeDefinitions::Ready(rows) = definitions {
        for (identity, definition) in rows {
            if let SelectedNativeDefinition::Unit(unit) = definition {
                units.insert(*identity, unit);
            }
        }
    }
    units.extend(
        callable_candidates
            .iter()
            .map(|(identity, unit)| (*identity, unit)),
    );
    units.extend(
        member_contexts
            .iter()
            .map(|context| (context.target_identity, &context.target)),
    );
    units.extend(
        visibility_units
            .iter()
            .map(|(identity, unit)| (*identity, unit)),
    );
    let identities = units.keys().copied().collect::<Vec<_>>();
    let mut result = Vec::new();
    let typed = ready.typed_source();
    for chunk in identities.chunks(crate::analyzer::resolution::MAX_TYPED_FACT_REQUESTS_PER_BATCH) {
        let outcome = typed.visit_declaration_visibility_pages_for_definitions(
            TypedFactRequest::new(chunk),
            cancellation,
            &mut TypedFactPageVisitor::new(&mut |page| {
                for row in page {
                    let property = row.row();
                    if let Some(unit) = units.get(&property.definition()) {
                        result.push(((*unit).clone(), property.visibility()));
                    }
                }
                Ok(true)
            }),
        )?;
        if outcome.is_cancelled() {
            return Ok(Vec::new());
        }
    }
    Ok(result)
}

/// Query-owned projection of the selection's actual routes and outcomes.
#[derive(Default)]
pub(crate) struct ProjectedNativeTraceProvenance {
    pub(crate) rows: Vec<crate::analyzer::usages::get_definition::trace::TraceCandidate>,
    pub(crate) rejection_coverage: bool,
    pub(crate) visibility_units: Vec<(SemanticId, CodeUnit)>,
}

fn project_native_trace_provenance(
    ready: &ReadySelectedResolution<'_, '_>,
    answer: &FactResolutionAnswer,
    definitions: &SelectedNativeDefinitions,
    callable_candidates: &[(SemanticId, CodeUnit)],
    member_contexts: &[ProjectedNativeMemberContext],
    cancellation: &CancellationToken,
) -> Result<ProjectedNativeTraceProvenance> {
    use crate::analyzer::structural::{CandidateOutcome, PrecedenceTier};
    use crate::analyzer::usages::get_definition::trace::{self, TraceCandidate, TraceCandidateRef};
    if !trace::native_rejection_projection_active() {
        return Ok(ProjectedNativeTraceProvenance::default());
    }
    let binding = answer.binding();
    let outcome_of = |witness: &crate::analyzer::resolution::ResolutionWitness| {
        let recorded = witness.candidate_outcome();
        match recorded {
            Some(CandidateOutcome::Rejected(_)) => recorded,
            _ if binding.targets().contains(&witness.target()) => Some(CandidateOutcome::Selected),
            _ if answer.callable_candidate_applicability().iter().any(|candidate| {
                candidate.target() == witness.target() && candidate.verdict()
                    == brokk_bifrost_core::analyzer::structural::callable::ApplicabilityVerdict::Inapplicable
            }) => Some(CandidateOutcome::Rejected(crate::analyzer::structural::RejectionReason::CallableApplicabilityDeferred)),
            _ => None,
        }
    };

    let mut covered =
        !binding.witnesses().is_empty() && binding.completion() == &ResolutionCompletion::Complete;
    let mut identities = binding
        .witnesses()
        .iter()
        .filter_map(|witness| {
            let provenance = witness.native_provenance()?;
            let outcome = outcome_of(witness)?;
            let import_loser = matches!(
                outcome,
                CandidateOutcome::Rejected(
                    crate::analyzer::structural::RejectionReason::ShadowedByNearer
                )
            ) && matches!(
                provenance.tier,
                Some(PrecedenceTier::ExplicitImport | PrecedenceTier::WildcardImport)
            );
            (!import_loser).then_some(witness.target())
        })
        .collect::<Vec<_>>();
    identities.sort_unstable();
    identities.dedup();
    let mut units = BTreeMap::new();
    if let SelectedNativeDefinitions::Ready(selected) = definitions {
        units.extend(
            selected
                .iter()
                .map(|(identity, definition)| (*identity, definition)),
        );
    }
    identities.retain(|identity| !units.contains_key(identity));
    let additional = match project_native_definition_units(
        ready,
        &identities,
        cancellation,
        &ResolutionSession::unbounded(),
    )? {
        SelectedNativeDefinitions::Ready(projected) => projected,
        SelectedNativeDefinitions::Unavailable | SelectedNativeDefinitions::Cancelled => {
            covered = false;
            Vec::new()
        }
    };
    units.extend(
        additional
            .iter()
            .map(|(identity, definition)| (*identity, definition)),
    );
    let mut rows = Vec::new();
    // The public definition outcome carries at most one lexical definition.
    // Its existing ambiguity diagnostic reports an unrepresentable selection;
    // the trace must retain partial coverage rather than inventing a winner.
    let selected_lexical_count = match definitions {
        SelectedNativeDefinitions::Ready(rows) => rows
            .iter()
            .filter(|(_, definition)| matches!(definition, SelectedNativeDefinition::Lexical(_)))
            .count(),
        _ => 0,
    };
    let mut seen_imports = std::collections::HashSet::new();
    let mut projected_import_groups = std::collections::HashSet::new();
    for witness in binding.witnesses() {
        if cancellation.is_cancelled() {
            return Ok(ProjectedNativeTraceProvenance::default());
        }
        let Some(provenance) = witness.native_provenance() else {
            covered = false;
            continue;
        };
        covered &= provenance.rejection_coverage;
        let outcome = outcome_of(witness);
        match outcome {
            Some(CandidateOutcome::Selected) if binding.targets().contains(&witness.target()) => {
                let candidate = match units.get(&witness.target()) {
                    Some(SelectedNativeDefinition::Unit(unit)) => {
                        TraceCandidateRef::Unit(unit.clone())
                    }
                    Some(SelectedNativeDefinition::Lexical(lexical))
                        if selected_lexical_count == 1 =>
                    {
                        TraceCandidateRef::Lexical(lexical.clone())
                    }
                    Some(SelectedNativeDefinition::Intrinsic { canonical_name, .. }) => {
                        TraceCandidateRef::Intrinsic {
                            name: canonical_name.clone(),
                        }
                    }
                    Some(SelectedNativeDefinition::Lexical(_)) => {
                        covered = false;
                        continue;
                    }
                    None => {
                        covered = false;
                        continue;
                    }
                };
                let tier = provenance
                    .tier
                    .or_else(|| match units.get(&witness.target()) {
                        Some(SelectedNativeDefinition::Intrinsic { tier, .. }) => *tier,
                        _ => None,
                    });
                rows.push(TraceCandidate::selected(candidate, tier));
            }
            Some(CandidateOutcome::Rejected(reason)) => {
                if reason == crate::analyzer::structural::RejectionReason::ShadowedByNearer
                    && matches!(
                        provenance.tier,
                        Some(PrecedenceTier::ExplicitImport | PrecedenceTier::WildcardImport)
                    )
                {
                    if let Some((token, route)) = provenance.import_route.as_deref() {
                        if seen_imports.insert((*token, provenance.tier)) {
                            if let Some(candidate) =
                                project_native_import_binder(ready, *token, route, cancellation)?
                            {
                                rows.push(TraceCandidate::rejected(
                                    candidate,
                                    provenance.tier,
                                    reason,
                                ));
                            } else {
                                covered = false;
                            }
                        }
                    } else {
                        covered = false;
                    }
                } else {
                    let candidate = match units.get(&witness.target()) {
                        Some(SelectedNativeDefinition::Unit(unit)) => {
                            TraceCandidateRef::Unit(unit.clone())
                        }
                        Some(SelectedNativeDefinition::Lexical(lexical)) => {
                            TraceCandidateRef::Lexical(lexical.clone())
                        }
                        Some(SelectedNativeDefinition::Intrinsic { canonical_name, .. }) => {
                            TraceCandidateRef::Intrinsic {
                                name: canonical_name.clone(),
                            }
                        }
                        None => {
                            covered = false;
                            continue;
                        }
                    };
                    rows.push(TraceCandidate::rejected(candidate, provenance.tier, reason));
                }
            }
            _ => {
                covered = false;
            }
        }
        if projected_import_groups.insert(std::sync::Arc::as_ptr(&provenance.defeated_imports)) {
            for (token, tier, route) in provenance.defeated_imports.iter() {
                if seen_imports.insert((*token, Some(*tier))) {
                    if let Some(candidate) =
                        project_native_import_binder(ready, *token, route, cancellation)?
                    {
                        rows.push(TraceCandidate::rejected(
                            candidate,
                            Some(*tier),
                            crate::analyzer::structural::RejectionReason::ShadowedByNearer,
                        ));
                    } else {
                        covered = false;
                    }
                }
            }
        }
    }
    // Universe fallback has no parser route or source witness. Preserve the
    // actual binding and its table-owned tier without claiming rejected-route
    // coverage that the fallback did not retain.
    if let SelectedNativeDefinitions::Ready(selected) = definitions {
        for (identity, definition) in selected {
            if binding.targets().contains(identity)
                && let SelectedNativeDefinition::Intrinsic {
                    canonical_name,
                    tier,
                } = definition
                && !rows.iter().any(|row| {
                    row.is_selected()
                        && matches!(&row.candidate,
                    TraceCandidateRef::Intrinsic { name } if name == canonical_name)
                })
            {
                covered = false;
                rows.push(TraceCandidate::selected(
                    TraceCandidateRef::Intrinsic {
                        name: canonical_name.clone(),
                    },
                    *tier,
                ));
            }
        }
    }
    // Applicability is a later native selection stage. Every computed loser
    // needs either its actual witness outcome or the shared applicability row.
    covered &= answer.callable_candidate_applicability().iter().all(|candidate| {
        if binding.targets().contains(&candidate.target()) { return true; }
        // A later phase may have erased the whole lookup group that supplied
        // this candidate. Its callable verdict alone cannot prove route coverage.
        if !binding.witnesses().iter().any(|witness| witness.target() == candidate.target() && witness.native_provenance().is_some()) {
            return false;
        }
        let Some((_, unit)) = callable_candidates.iter().find(|(target, _)| *target == candidate.target()) else {
            return false;
        };
        candidate.verdict() == brokk_bifrost_core::analyzer::structural::callable::ApplicabilityVerdict::Inapplicable
            || rows.iter().any(|row| !row.is_selected() && matches!(&row.candidate, TraceCandidateRef::Unit(found) if found == unit))
    });
    covered &= answer.member_rejections().len()
        == member_contexts
            .iter()
            .filter(|context| context.rejection.is_some())
            .count();
    // A projected trace may never claim coverage for an unprojected selection.
    if let SelectedNativeDefinitions::Ready(selected) = definitions {
        covered &= selected.iter().all(|(_, definition)| {
            rows.iter().any(|row| {
                row.is_selected()
                    && match (definition, &row.candidate) {
                        (SelectedNativeDefinition::Unit(left), TraceCandidateRef::Unit(right)) => {
                            left == right
                        }
                        (
                            SelectedNativeDefinition::Lexical(left),
                            TraceCandidateRef::Lexical(right),
                        ) => left == right,
                        (
                            SelectedNativeDefinition::Intrinsic { canonical_name, .. },
                            TraceCandidateRef::Intrinsic { name },
                        ) => canonical_name == name,
                        _ => false,
                    }
            })
        });
    } else {
        covered = false;
    }
    if !covered {
        crate::profiling::note_with(|| {
            format!(
                "resolution::native_trace_partial binding={binding:?} callable={:?} member_contexts={member_contexts:?}",
                answer.callable_candidate_applicability(),
            )
        });
    }
    let visibility_units = units
        .into_iter()
        .filter_map(|(identity, definition)| match definition {
            SelectedNativeDefinition::Unit(unit) => Some((identity, unit.clone())),
            SelectedNativeDefinition::Lexical(_) | SelectedNativeDefinition::Intrinsic { .. } => {
                None
            }
        })
        .collect();
    Ok(ProjectedNativeTraceProvenance {
        rows,
        rejection_coverage: covered,
        visibility_units,
    })
}

/// The exact source token establishes a binder. Recipes provide its structured
/// target segments; neither its target declaration nor a facts-arena node is guessed.
fn project_native_import_binder(
    ready: &ReadySelectedResolution<'_, '_>,
    token: SemanticId,
    route: &[SemanticId],
    cancellation: &CancellationToken,
) -> Result<Option<crate::analyzer::usages::get_definition::trace::TraceCandidateRef>> {
    use crate::analyzer::usages::get_definition::trace::{TraceCandidateRef, WILDCARD_ROUTE_NAME};
    let lexical = ready.lexical_source();
    let Some(SelectedSemanticProvenance::FragmentLocal(provenance)) =
        lexical.semantic_provenance(token, cancellation)?
    else {
        return Ok(None);
    };
    let ordinal = provenance.mount().ordinal();
    let record = ready.inventory.mount_record_by_ordinal(ordinal)?;
    let Some(import) = super::jvm_context::selected_import_route(
        ready.inventory.connection(),
        record.blob_id(),
        ordinal,
        token,
    )?
    else {
        return Ok(None);
    };
    let mut segments = Vec::with_capacity(route.len());
    for page in route.chunks(crate::analyzer::resolution::MAX_SOURCE_ROWS_PER_BATCH) {
        let requests = page
            .iter()
            .map(|&semantic| SelectedLookupRecipeRequest {
                fragment: provenance.mount().fragment(),
                semantic,
            })
            .collect::<Vec<_>>();
        let SelectedLookupRecipeReadOutcome::Ready(recipes) =
            lexical.lookup_semantic_recipes(&requests, cancellation, None)?
        else {
            return Ok(None);
        };
        for recipe in recipes {
            let Some(recipe) = recipe else {
                return Ok(None);
            };
            segments.push(recipe.spelling().to_owned());
        }
    }
    let Some(demand) = segments.pop() else {
        return Ok(None);
    };
    let wildcard = matches!(
        import.kind.as_str(),
        "type_on_demand" | "static_on_demand" | "star"
    );
    let name = if wildcard {
        WILDCARD_ROUTE_NAME.to_owned()
    } else {
        let selector = super::jvm_context::selected_jvm_import_selector(
            ready.inventory.connection(),
            record.blob_id(),
            token,
        )?;
        // JVM named selectors may rename the source member. Without their
        // structured selector row the bound demand is not its target name.
        if import.kind == "named" && selector.is_none() {
            return Ok(None);
        }
        let source_name = selector
            .as_ref()
            .and_then(|selector| selector.source_name.clone())
            .unwrap_or_else(|| demand.clone());
        segments.push(source_name);
        selector
            .and_then(|selector| selector.local_name)
            .unwrap_or(demand)
    };
    let mount = SelectedMountTable::new(&ready.inventory).mount_by_ordinal(ordinal)?;
    Ok(Some(TraceCandidateRef::ImportBinder {
        file: ProjectFile::new(ready.project.root(), mount.persisted_relative_path()),
        node: None,
        name,
        target_segments: segments,
    }))
}
