//! Public declaration identities for selected Java/Go definition semantics.
//! Package anchors come from the selected revision, never live path discovery.

use super::*;
use crate::analyzer::PackageAnchor;

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

pub(crate) struct SelectedNativeReferenceUnits {
    pub(crate) answer: FactResolutionAnswer,
    pub(crate) definitions: SelectedNativeDefinitions,
    pub(crate) named_reasons: Vec<(&'static str, String)>,
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
        self,
        context: SelectedResolutionContextSet,
        locator: &SelectedSemanticLocator,
        budget: ReceiverAnalysisBudget,
        cancellation: &CancellationToken,
        context_metrics: &mut SelectedResolutionContextMetrics,
    ) -> Result<BoundedResolution<NativeReferenceTypesOutcome>> {
        let session = ResolutionSession::bounded(budget, Some(cancellation));
        let outcome = self.resolve_reference_with_projection(
            context,
            locator,
            cancellation,
            context_metrics,
            &session,
            |ready, operation, answer| {
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
        self,
        context: SelectedResolutionContextSet,
        locator: &SelectedSemanticLocator,
        cancellation: &CancellationToken,
        context_metrics: &mut SelectedResolutionContextMetrics,
    ) -> Result<NativeReferenceUnitsOutcome> {
        self.resolve_native_reference_units_in_session(
            context,
            locator,
            cancellation,
            context_metrics,
            &ResolutionSession::unbounded(),
        )
    }

    pub(crate) fn resolve_native_reference_units_bounded(
        self,
        context: SelectedResolutionContextSet,
        locator: &SelectedSemanticLocator,
        budget: ReceiverAnalysisBudget,
        cancellation: &CancellationToken,
        context_metrics: &mut SelectedResolutionContextMetrics,
    ) -> Result<BoundedResolution<NativeReferenceUnitsOutcome>> {
        let session = ResolutionSession::bounded(budget, Some(cancellation));
        let outcome = self.resolve_native_reference_units_in_session(
            context,
            locator,
            cancellation,
            context_metrics,
            &session,
        )?;
        Ok(session.finish(outcome))
    }

    fn resolve_native_reference_units_in_session(
        self,
        context: SelectedResolutionContextSet,
        locator: &SelectedSemanticLocator,
        cancellation: &CancellationToken,
        context_metrics: &mut SelectedResolutionContextMetrics,
        session: &ResolutionSession,
    ) -> Result<NativeReferenceUnitsOutcome> {
        self.resolve_reference_with_projection(
            context,
            locator,
            cancellation,
            context_metrics,
            session,
            |ready, _, answer| {
                let named_reasons = named_reason_details(ready, answer.binding().completion())?;
                let definitions = project_native_definition_units(
                    ready,
                    answer.binding().targets(),
                    cancellation,
                    session,
                )?;
                Ok(SelectedNativeReferenceUnits {
                    answer,
                    definitions,
                    named_reasons,
                })
            },
        )
    }
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

pub(super) fn project_native_definition_units(
    ready: &ReadySelectedResolution<'_, '_>,
    definitions: &[SemanticId],
    cancellation: &CancellationToken,
    session: &ResolutionSession,
) -> Result<SelectedNativeDefinitions> {
    let lexical = ready.lexical_source();
    let mut coordinates = Vec::with_capacity(definitions.len());
    for &definition in definitions {
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
    let SelectedDefinitionUnitReadOutcome::Ready(rows) = ready
        .inventory
        .selected_declaration_units(&coordinates, cancellation)?
    else {
        return Ok(SelectedNativeDefinitions::Cancelled);
    };
    let mut units = BTreeMap::new();
    for (mount, key, row) in rows {
        assert!(
            units.insert((mount, key), row).is_none(),
            "one source definition has one parser unit"
        );
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
        return Ok(SelectedNativeDefinitions::Cancelled);
    };
    let mut lexical_rows = BTreeMap::new();
    for (mount, key, row) in rows {
        assert!(
            lexical_rows.insert((mount, key), row).is_none(),
            "one source definition has one lexical declaration"
        );
    }
    let mut projected = Vec::with_capacity(definitions.len());
    for (&definition, coordinate) in definitions.iter().zip(coordinates) {
        if cancellation.is_cancelled() || !session.scope_step() {
            return Ok(SelectedNativeDefinitions::Cancelled);
        }
        let mount = SelectedMountTable::new(&ready.inventory).mount_by_ordinal(coordinate.0)?;
        assert!(
            matches!(mount.semantic_language(), Language::Java | Language::Go),
            "native Java/Go projection requires an admitted frontend"
        );
        let file = ProjectFile::new(ready.project.root(), mount.persisted_relative_path());
        let Some(row) = units.get(&coordinate) else {
            let Some(super::super::selected_definition::SelectedDeclarationDefinition::Lexical(
                mut row,
            )) = lexical_rows.remove(&coordinate)
            else {
                return Ok(SelectedNativeDefinitions::Unavailable);
            };
            row.source_file = Some(file);
            projected.push((definition, SelectedNativeDefinition::Lexical(row)));
            continue;
        };
        let persisted = row
            .fq
            .as_ref()
            .ok_or_else(|| StoreError::corrupt("source declaration lacks structured identity"))?;
        let prefix = match (mount.semantic_language(), persisted.anchor) {
            (Language::Java, None) | (Language::Go, None) => None,
            (Language::Go, Some(PackageAnchor::OwnModule { pop: 0 })) => {
                let record = ready.inventory.mount_record_by_ordinal(coordinate.0)?;
                let Some(version) = super::go_context::go_placement_file_version(
                    ready.inventory.connection(),
                    &record,
                )?
                else {
                    // An unsaved replacement whose membership inputs changed
                    // has no selected placement; its predecessor is not proof.
                    return Ok(SelectedNativeDefinitions::Unavailable);
                };
                let package: Option<String> = ready
                    .inventory
                    .connection()
                    .query_row(GO_DEFINITION_PACKAGE_ANCHOR, [version], |row| row.get(0))
                    .optional()?;
                let Some(package) = package else {
                    return Ok(SelectedNativeDefinitions::Unavailable);
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
        projected.push((
            definition,
            SelectedNativeDefinition::Unit(CodeUnit::from_fq(
                file,
                row.kind,
                fq,
                package_segments,
                row.signature.clone(),
                row.flags.synthetic,
            )),
        ));
    }
    if cancellation.is_cancelled() {
        Ok(SelectedNativeDefinitions::Cancelled)
    } else {
        Ok(SelectedNativeDefinitions::Ready(projected))
    }
}
