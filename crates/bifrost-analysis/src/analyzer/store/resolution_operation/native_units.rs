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
    pub(crate) named_argument: Option<SelectedNativeNamedArgument>,
    pub(crate) predeclared_go_symbol: bool,
    pub(crate) callable_applicability_candidates: Vec<(SemanticId, CodeUnit)>,
    pub(crate) member_contexts: Vec<ProjectedNativeMemberContext>,
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
    },
    Unavailable,
    Cancelled,
}

pub(crate) struct SelectedNativeReferenceTypes {
    pub(crate) named_reasons: Vec<(&'static str, String)>,
    pub(crate) answer: FactResolutionAnswer,
    pub(crate) types: SelectedNativeTypes,
}

type NativeReferenceUnitsOutcome =
    SelectedResolutionOperationOutcome<SelectedResolutionLocated<SelectedNativeReferenceUnits>>;
type NativeReferenceTypesOutcome =
    SelectedResolutionOperationOutcome<SelectedResolutionLocated<SelectedNativeReferenceTypes>>;

impl SelectedResolutionOperation<'_, '_> {
    pub(crate) fn resolve_native_reference_types_bounded(
        mut self,
        context: SelectedResolutionContextSet,
        locator: &SelectedSemanticLocator,
        budget: ReceiverAnalysisBudget,
        cancellation: &CancellationToken,
        context_metrics: &mut SelectedResolutionContextMetrics,
    ) -> Result<BoundedResolution<NativeReferenceTypesOutcome>> {
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
                Ok(SelectedNativeReferenceTypes {
                    answer,
                    types,
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
                Ok(SelectedNativeReferenceTypes {
                    answer,
                    types,
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
                            SelectedNativeDefinition::Lexical(_) => None,
                        })
                        .collect(),
                    SelectedNativeDefinitions::Unavailable
                    | SelectedNativeDefinitions::Cancelled => Vec::new(),
                };
                let member_contexts = project_native_member_contexts(ready, &answer, cancellation)?;
                let absent_member_owners = project_absent_member_owners(
                    ready,
                    answer.absent_member_owners(),
                    cancellation,
                    session,
                )?;
                Ok(SelectedNativeReferenceUnits {
                    answer,
                    definitions,
                    external_members,
                    named_argument,
                    predeclared_go_symbol,
                    callable_applicability_candidates,
                    member_contexts,
                    absent_member_owners,
                    named_reasons,
                })
            },
        )
    }
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
    let identities = identities.into_iter().collect::<Vec<_>>();
    let Some(intrinsic) = operation.read_intrinsic_type_descriptors(&identities)? else {
        return Ok(SelectedNativeTypes::Cancelled);
    };
    let intrinsic_identities = intrinsic
        .iter()
        .map(|descriptor| descriptor.identity())
        .collect::<BTreeSet<_>>();
    let nominal = identities
        .into_iter()
        .filter(|identity| !intrinsic_identities.contains(identity))
        .collect::<Vec<_>>();
    Ok(
        match project_native_definition_units(ready, &nominal, cancellation, session)? {
            SelectedNativeDefinitions::Ready(nominal) => {
                SelectedNativeTypes::Ready { nominal, intrinsic }
            }
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

pub(super) fn project_native_definition_units(
    ready: &ReadySelectedResolution<'_, '_>,
    definitions: &[SemanticId],
    cancellation: &CancellationToken,
    session: &ResolutionSession,
) -> Result<SelectedNativeDefinitions> {
    let lexical = ready.lexical_source();
    let mut coordinates = Vec::with_capacity(definitions.len());
    let mut source_definitions = Vec::with_capacity(definitions.len());
    for &definition in definitions {
        if ready
            .context_identities
            .external_member_identity(definition)
            .is_some()
        {
            continue;
        }
        source_definitions.push(definition);
        if cancellation.is_cancelled() || !session.scope_step() {
            return Ok(SelectedNativeDefinitions::Cancelled);
        }
        let Some(provenance) = lexical.semantic_provenance(definition, cancellation)? else {
            return Ok(SelectedNativeDefinitions::Cancelled);
        };
        let SelectedSemanticProvenance::FragmentLocal(provenance) = provenance else {
            // A shared name or generated declaration is not a parser unit.
            return Ok(SelectedNativeDefinitions::Unavailable);
        };
        coordinates.push((provenance.mount().ordinal(), provenance.local_key()));
    }
    let Some(mut rows) = read_fragment_definition_rows(ready, &coordinates, cancellation)? else {
        return Ok(SelectedNativeDefinitions::Cancelled);
    };
    let mut projected = Vec::with_capacity(definitions.len());
    for (&definition, coordinate) in source_definitions.iter().zip(coordinates) {
        if cancellation.is_cancelled() || !session.scope_step() {
            return Ok(SelectedNativeDefinitions::Cancelled);
        }
        let Some(unit) = project_fragment_definition(ready, coordinate, &mut rows)? else {
            return Ok(SelectedNativeDefinitions::Unavailable);
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
    let mut units = rows
        .into_iter()
        .filter_map(|(_, definition)| match definition {
            SelectedNativeDefinition::Unit(unit) => Some(unit),
            SelectedNativeDefinition::Lexical(_) => None,
        })
        .collect::<Vec<_>>();
    if units.len() != owners.len() {
        return Ok(Vec::new());
    }
    units.sort_unstable();
    Ok(units)
}

/// Project every definition in one batch, with no all-or-nothing outcome: a
/// definition that is a shared name, or whose projection is unavailable, has
/// `None` and the others keep their units. `None` overall when cancelled.
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
            None => None,
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
    let units = rows
        .into_iter()
        .filter_map(|(identity, definition)| match definition {
            SelectedNativeDefinition::Unit(unit) => Some((identity, unit)),
            SelectedNativeDefinition::Lexical(_) => None,
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
