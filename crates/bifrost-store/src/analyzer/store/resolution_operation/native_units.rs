//! Public declaration identities for selected native definition semantics.
//! Package anchors come from the selected revision, never live path discovery.

use super::imports::SelectedImportRouteKind;
use super::*;
use crate::analyzer::PackageAnchor;
use crate::analyzer::resolution::{LoweredDeclarationTypeProperty, NamedArgumentLabelRead};
use brokk_bifrost_core::analyzer::model::DeclarationKind;
use brokk_bifrost_core::analyzer::resolution_facts::DeclarationTypeRole;

pub(in crate::analyzer::store) const NATIVE_ARGUMENT_REASON_IDENTITY_DIGEST_SQL: &str =
    "SELECT CAST(input.key AS INTEGER), catalog.identity_digest
     FROM json_each(?1) AS input
     LEFT JOIN main.resolution_semantic_catalog AS catalog
       ON catalog.blob_id=CAST(input.value->>0 AS INTEGER)
      AND catalog.local_key=CAST(input.value->>1 AS INTEGER)
      AND catalog.identity_digest IS NOT NULL
     ORDER BY CAST(input.key AS INTEGER)";

pub(in crate::analyzer::store) const NATIVE_ARGUMENT_REASON_GAP_REASONS_SQL: &str =
    "SELECT CAST(input.key AS INTEGER), gap.site, gap.origin
     FROM json_each(?1) AS input
     LEFT JOIN main.resolution_gap_reasons AS gap
       ON gap.blob_id=CAST(input.value->>0 AS INTEGER)
      AND gap.reason=CAST(input.value->>1 AS INTEGER)
     ORDER BY CAST(input.key AS INTEGER)";

pub(in crate::analyzer::store) const GO_DEFINITION_PACKAGE_ANCHOR: &str =
    "SELECT package_name FROM main.workspace_file_anchor_rows AS anchors
     WHERE file_version_id=?1 AND anchor_kind='own_module' AND anchor_pop=0";

#[derive(Debug, PartialEq, Eq)]
#[doc(hidden)]
pub enum SelectedNativeDefinition {
    Unit(CodeUnit),
    Lexical(LexicalDefinition),
    Intrinsic {
        canonical_name: String,
        tier: Option<crate::analyzer::structural::PrecedenceTier>,
    },
}

#[doc(hidden)]
#[cfg_attr(any(test, feature = "test-support"), derive(Debug))]
pub enum SelectedNativeDefinitions {
    Ready(Vec<(SemanticId, SelectedNativeDefinition)>),
    Unavailable,
    Cancelled,
}

/// Ownership of one reason in the final native binding completion.
#[cfg(any(test, feature = "test-support"))]
#[derive(Debug, Clone)]
#[doc(hidden)]
pub struct NativeCompletionReasonOwnership {
    pub kind: &'static str,
    pub name: Option<&'static str>,
    pub context_owned: bool,
    pub operation_local: bool,
}

#[cfg(any(test, feature = "test-support"))]
thread_local! {
    static NATIVE_COMPLETION_REASON_PROBE: std::cell::RefCell<Option<Vec<NativeCompletionReasonOwnership>>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn start_native_completion_reason_probe_for_test() {
    NATIVE_COMPLETION_REASON_PROBE.with(|probe| *probe.borrow_mut() = Some(Vec::new()));
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn take_native_completion_reason_probe_for_test() -> Vec<NativeCompletionReasonOwnership> {
    NATIVE_COMPLETION_REASON_PROBE.with(|probe| {
        probe
            .borrow_mut()
            .take()
            .expect("native completion reason probe started")
    })
}

#[cfg(any(test, feature = "test-support"))]
fn record_native_completion_reason_ownership(
    ready: &ReadySelectedResolution<'_, '_>,
    completion: &ResolutionCompletion,
) {
    NATIVE_COMPLETION_REASON_PROBE.with(|probe| {
        let mut probe = probe.borrow_mut();
        let Some(records) = probe.as_mut() else {
            return;
        };
        let ResolutionCompletion::Incomplete(reasons) = completion else {
            return;
        };
        for reason in reasons.iter() {
            let (kind, Some(semantic)) = public_reason_details(reason) else {
                continue;
            };
            let key = crate::analyzer::resolution::ResolutionIdentityDigestKey::from(semantic);
            records.push(NativeCompletionReasonOwnership {
                kind,
                name: ready
                    .context_identities
                    .named_reason(semantic)
                    .map(|(name, _)| name),
                context_owned: key
                    .context_number()
                    .and_then(|number| ready.context_identities.content_digest(number))
                    .is_some(),
                operation_local: semantic.is_operation_local(),
            });
        }
    });
}

#[doc(hidden)]
#[cfg_attr(any(test, feature = "test-support"), derive(Debug))]
pub struct ProjectedNativeExternalMember {
    #[doc(hidden)]
    pub coordinate: crate::analyzer::resolution::ExternalMemberCoordinate,
    #[doc(hidden)]
    pub identity: crate::analyzer::resolution::ExternalMemberIdentity,
    #[doc(hidden)]
    pub member_name: String,
    #[doc(hidden)]
    pub is_static: bool,
    #[doc(hidden)]
    pub pack: Option<(String, String)>,
}

/// Stable coordinates and shape facts projected from one reached native
/// candidate. Request-minted SemanticIds never leave the selected operation
/// through call-target caches, even though its fact answer uses them locally.
#[derive(Debug, Clone, PartialEq, Eq)]
#[doc(hidden)]
pub struct ProjectedNativeModelMember {
    pub member: crate::analyzer::semantic_model::overlay::ModelSymbolRef,
    pub declaration: crate::analyzer::semantic_model::overlay::SemanticModelSymbol,
    pub owner: crate::analyzer::resolution::ExternalOwnerIdentity,
    pub owner_path: Box<[Option<crate::analyzer::resolution::ExternalOwnerIdentity>]>,
    pub receiver_owner: Option<crate::analyzer::resolution::ExternalOwnerIdentity>,
    pub receiver_pointer_depth: u32,
    pub receiver_addressable: Option<bool>,
    pub receiver_runtime: bool,
    pub receiver_proven: bool,
    pub selected: bool,
    pub selection_complete: bool,
    pub interface: bool,
    pub route_exact: bool,
    pub receiver_route_proven: bool,
    pub complete: bool,
    pub incomplete_reasons: Vec<String>,
    pub rejected: bool,
}

/// Native's invocation verdict, independently of family completeness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeInvocationOutcome {
    NoApplicable,
    Ambiguous,
    Unproven(NativeInvocationContentCause),
}

/// Open argument/formal types, incomplete shapes, or the deterministic syntax
/// depth cap. Dynamic budget/cancellation stops never become this cause: Java's
/// argument collector propagates JavaNativePointStop from the nested
/// BoundedResolution::Exceeded/Cancelled arms before invocation selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeInvocationContentCause {
    OpenEvidence,
}

/// An inventory overload without a model identity still competes for a layout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeInvocationShape {
    pub parameter_count: usize,
    pub variadic: bool,
}

impl ProjectedNativeModelMember {
    /// Stable reached-record projection. Language adapters add only independently
    /// proven receiver and route facts to this initially unselected record.
    pub fn reached(
        declaration: crate::analyzer::semantic_model::overlay::SemanticModelSymbol,
        member: crate::analyzer::semantic_model::overlay::ModelSymbolRef,
        owner: crate::analyzer::resolution::ExternalOwnerIdentity,
    ) -> Self {
        Self {
            declaration,
            member,
            owner,
            owner_path: Box::new([]),
            receiver_owner: None,
            receiver_pointer_depth: 0,
            receiver_addressable: None,
            receiver_runtime: false,
            receiver_proven: false,
            selected: false,
            selection_complete: false,
            interface: false,
            route_exact: false,
            receiver_route_proven: false,
            complete: false,
            incomplete_reasons: Vec::new(),
            rejected: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[doc(hidden)]
pub struct ProjectedNativeModelMemberSelection {
    pub outcome: Option<NativeInvocationOutcome>,
    pub identityless_shapes: Vec<NativeInvocationShape>,
    pub native_target_count: usize,
    pub candidates: Vec<ProjectedNativeModelMember>,
    pub complete: bool,
}

impl ProjectedNativeModelMemberSelection {
    /// A diagnostic family never supplies an executable candidate.
    pub fn selected_candidate(&self) -> Option<&ProjectedNativeModelMember> {
        if self.outcome.is_some() {
            return None;
        }
        let mut selected = self.candidates.iter().filter(|c| c.selected && !c.rejected);
        let candidate = selected.next()?;
        selected.next().is_none().then_some(candidate)
    }
}

#[doc(hidden)]
pub fn project_native_model_member_selection(
    selection: &crate::analyzer::resolution::FactModelMemberSelection,
    cancellation: &CancellationToken,
) -> Option<Box<ProjectedNativeModelMemberSelection>> {
    let mut candidates = Vec::with_capacity(selection.candidates.len());
    for candidate in &selection.candidates {
        if cancellation.is_cancelled() {
            return None;
        }
        candidates.push(ProjectedNativeModelMember {
            owner_path: candidate.owner_coordinates.clone(),
            receiver_owner: candidate.receiver_owner.clone(),
            receiver_pointer_depth: candidate.receiver.ty().indirection(),
            receiver_addressable: candidate.receiver.addressable(),
            receiver_runtime: matches!(
                candidate.receiver,
                crate::analyzer::resolution::ResolutionSlotValue::Runtime { .. }
            ),
            receiver_proven: candidate.receiver_proven,
            selected: candidate.selected,
            selection_complete: candidate.selection_complete,
            interface: candidate.interface,
            route_exact: candidate.route_exact,
            receiver_route_proven: candidate.receiver_route_proven,
            complete: candidate.completion == ResolutionCompletion::Complete,
            incomplete_reasons: candidate.incomplete_reasons.clone(),
            rejected: candidate.rejected,
            ..ProjectedNativeModelMember::reached(
                candidate.declaration.clone(),
                candidate.member.clone(),
                candidate.owner.clone(),
            )
        });
    }
    Some(Box::new(ProjectedNativeModelMemberSelection {
        outcome: None,
        identityless_shapes: Vec::new(),
        native_target_count: selection.native_target_count,
        candidates,
        complete: selection.completion == ResolutionCompletion::Complete,
    }))
}

#[doc(hidden)]
#[cfg_attr(any(test, feature = "test-support"), derive(Debug))]
pub struct SelectedNativeReferenceUnits {
    pub query_obligations: crate::analyzer::resolution::QueryObligations,
    #[doc(hidden)]
    pub answer: FactResolutionAnswer,
    /// Binding after a separately proven exact argument conversion. The
    /// original answer and every result-type frontier keep their obligations.
    #[doc(hidden)]
    pub argument_binding: Option<crate::analyzer::resolution::ResolutionAnswer>,
    /// Canonical identities let a proved nested call discharge only its own
    /// call-local obligations in another selected point operation.
    #[doc(hidden)]
    pub argument_reason_digests: Vec<(crate::analyzer::resolution::SemanticId, [u8; 32])>,
    #[doc(hidden)]
    pub call_binding_reason_digests: Vec<[u8; 32]>,
    #[doc(hidden)]
    pub constructor_hierarchy_reason_digests: Vec<(std::sync::Arc<str>, [u8; 32])>,
    #[doc(hidden)]
    pub static_type_qualifier_reason_digests:
        Vec<(crate::analyzer::resolution::ExternalOwnerIdentity, [u8; 32])>,
    #[doc(hidden)]
    pub definitions: SelectedNativeDefinitions,
    #[doc(hidden)]
    pub external_members: Vec<ProjectedNativeExternalMember>,
    pub model_member_selection: Option<Box<ProjectedNativeModelMemberSelection>>,
    #[doc(hidden)]
    pub direct_target: Option<NativeExternalMemberTarget>,
    #[doc(hidden)]
    pub named_argument: Option<SelectedNativeNamedArgument>,
    #[doc(hidden)]
    pub predeclared_go_symbol: bool,
    #[doc(hidden)]
    pub callable_applicability_candidates: Vec<(SemanticId, CodeUnit)>,
    #[doc(hidden)]
    pub member_contexts: Vec<ProjectedNativeMemberContext>,
    #[doc(hidden)]
    pub trace_provenance: ProjectedNativeTraceProvenance,
    #[doc(hidden)]
    pub declared_visibilities: Vec<(CodeUnit, crate::analyzer::structural::DeclaredVisibility)>,
    /// The owner types of the answer's absent-member fact, projected to their
    /// declarations. Empty when the answer has no such fact or an owner has no
    /// source-unit projection, so a consumer never names part of the owner set.
    #[doc(hidden)]
    pub absent_member_owners: Vec<CodeUnit>,
    #[doc(hidden)]
    pub named_reasons: Vec<(&'static str, String)>,
    #[doc(hidden)]
    pub diagnostic_identities: Vec<(SemanticId, String)>,
}

/// Query-local projection reader that runs before the selected fact operation ends.
pub type SelectedNativeReferenceReader<'a> = dyn FnMut(
        &mut crate::analyzer::resolution::FactResolutionOperation<'_>,
        &SelectedNativeReferenceUnits,
    ) -> Result<()>
    + 'a;

#[doc(hidden)]
#[cfg_attr(any(test, feature = "test-support"), derive(Debug))]
pub enum SelectedNativeNamedArgument {
    Resolved(SelectedNativeDefinition),
    Incomplete(String),
}

#[derive(Debug)]
#[doc(hidden)]
pub struct ProjectedNativeMemberContext {
    #[doc(hidden)]
    pub target_identity: SemanticId,
    #[doc(hidden)]
    pub target: CodeUnit,
    #[doc(hidden)]
    pub owner_path: Vec<CodeUnit>,
    #[doc(hidden)]
    pub route_kind: crate::analyzer::resolution::FactMemberRouteKind,
    #[doc(hidden)]
    pub go_interface_owner: Option<bool>,
    #[doc(hidden)]
    pub selected: bool,
    #[doc(hidden)]
    pub rejection: Option<crate::analyzer::structural::RejectionReason>,
    /// The native callable verdict for this member's target, or `Unknown` when
    /// the answer recorded none. Member attribution reports it as the
    /// candidate's applicability.
    #[doc(hidden)]
    pub applicability: brokk_bifrost_core::analyzer::structural::callable::ApplicabilityVerdict,
}

#[doc(hidden)]
pub enum SelectedNativeTypes {
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
#[doc(hidden)]
pub enum NativeExternalMemberTarget {
    Indexed(crate::analyzer::resolution::ExternalMemberIdentity),
    Unindexed {
        provider_path: std::sync::Arc<str>,
        provider_package_id: Option<i64>,
        member_name: String,
    },
}

#[doc(hidden)]
pub struct SelectedNativeReferenceTypes {
    #[doc(hidden)]
    pub diagnostic_identities: Vec<(SemanticId, String)>,
    #[doc(hidden)]
    pub named_reasons: Vec<(&'static str, String)>,
    #[doc(hidden)]
    pub answer: FactResolutionAnswer,
    #[doc(hidden)]
    pub value_types: SelectedNativeTypes,
    /// A whole expression selects its exact value slot independently of the
    /// binding projections that its callee reference happens to publish.
    #[doc(hidden)]
    pub query_result_slot: Option<SemanticId>,
    /// Direct external-member evidence from the same selected answer, with
    /// indexed identities distinguished from unknown provider frontiers.
    /// Keeping this beside the projected expression type prevents consumers
    /// from trying to join mount-local semantic IDs from separate operations.
    #[doc(hidden)]
    pub direct_target: Option<NativeExternalMemberTarget>,
}

type NativeReferenceUnitsOutcome =
    SelectedResolutionOperationOutcome<SelectedResolutionLocated<SelectedNativeReferenceUnits>>;
type NativeReferenceTypesOutcome =
    SelectedResolutionOperationOutcome<SelectedResolutionLocated<SelectedNativeReferenceTypes>>;

enum SelectedTypeSite {
    Reference,
    Missing,
    Declaration((SelectedSemanticLocator, SemanticId)),
    Incomplete(Box<SelectedNativeReferenceTypes>),
    Cancelled,
}

// A declaration's value is already a published typed slot. Its canonical
// source bridge supplies the name range; no synthetic reference or source-text
// inference is needed. Value and parameter roles share the same value query.
const SELECTED_DECLARATION_VALUE_SITE: &str = r#"
SELECT native.source_site, declared.slot
FROM temp.selected_resolution_mounts mounted
JOIN main.source_declarations source
  ON source.blob_id=mounted.blob_id
 AND source.name_start_byte=?2 AND source.name_end_byte=?3
JOIN main.source_native_declaration_bridges native
  ON native.blob_id=source.blob_id AND native.declaration_id=source.declaration_id
JOIN main.resolution_semantic_sites semantic
  ON semantic.blob_id=native.blob_id AND semantic.source_site=native.source_site
 AND semantic.semantic_role='definition'
JOIN main.resolution_declaration_types declared
  ON declared.blob_id=semantic.blob_id AND declared.definition=semantic.semantic_key
 AND declared.role IN (0,1) -- DeclarationTypeRole::Value, Parameter
WHERE mounted.mount_ordinal=?1
ORDER BY native.source_site,declared.slot
"#;

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub struct SelectedNativeAssignmentValue {
    #[doc(hidden)]
    pub types: SelectedNativeReferenceTypes,
    #[doc(hidden)]
    pub observed_frontier_complete: bool,
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
    let diagnostic_identities = native_type_diagnostic_identities(
        ready,
        &answer,
        &value_types,
        "",
        &CancellationToken::new(),
    )?;
    Ok(SelectedNativeAssignmentValue {
        types: SelectedNativeReferenceTypes {
            named_reasons,
            diagnostic_identities,
            answer,
            value_types,
            query_result_slot: Some(slot),
            direct_target: None,
        },
        observed_frontier_complete,
    })
}

/// A selected local binder, with selected-inventory admission preserved.
#[doc(hidden)]
pub type SelectedLocalDeclarationOutcome =
    SelectedResolutionOperationOutcome<Option<(SemanticId, LexicalDefinition)>>;

/// The canonical path of one selected unindexed Go import, if unique.
#[doc(hidden)]
pub type SelectedGoUnindexedImportOutcome = SelectedResolutionOperationOutcome<
    super::SelectedResolutionLocated<Option<std::sync::Arc<str>>>,
>;

impl SelectedResolutionOperation<'_, '_> {
    /// Project a unique unindexed Go import selected at this package reference.
    /// The binder, rather than source spelling, owns aliases and shadowing.
    #[doc(hidden)]
    pub fn resolve_go_unindexed_import_bounded(
        &mut self,
        prepared: super::GoPreparedImportContext,
        locator: &SelectedSemanticLocator,
        budget: ReceiverAnalysisBudget,
        cancellation: &CancellationToken,
    ) -> Result<BoundedResolution<SelectedGoUnindexedImportOutcome>> {
        let session = ResolutionSession::bounded(budget, Some(cancellation));
        let projected = self.resolve_reference_with_projection(
            super::NativeReferenceQuery {
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
            },
            |ready, _, _, answer| {
                Ok(match answer.binding().targets() {
                    [binder] => ready
                        .context_identities
                        .unindexed_go_import(*binder)
                        .filter(|frontier| frontier.member.is_none())
                        .map(|frontier| frontier.provider_path),
                    _ => None,
                })
            },
        )?;
        Ok(session.finish(projected))
    }

    /// Select only a certified, unique local declaration through lexical facts.
    /// This does not dispatch members, imports, or callable definitions.
    #[doc(hidden)]
    pub fn resolve_local_declaration_bounded(
        &mut self,
        locator: &SelectedSemanticLocator,
        budget: ReceiverAnalysisBudget,
        cancellation: &CancellationToken,
    ) -> Result<BoundedResolution<SelectedLocalDeclarationOutcome>> {
        use crate::analyzer::resolution::BatchResolutionFragmentSource;
        let session = ResolutionSession::bounded(budget, Some(cancellation));
        let lexical = self.ready.lexical_source();
        let mut selected = None;
        if let super::super::resolution_lexical::SelectedSemanticLookupOutcome::Found(sites) =
            lexical.lookup_semantic_sites(locator, cancellation, &session)?
            && let [site] = sites.as_slice()
            && let Some(evidence) =
                lexical.reference_local_path_evidence(site.semantic(), cancellation)?
            && evidence.local_bindings_certified()
            && let [identity] = evidence.local_definitions()
            && let SelectedNativeDefinitions::Ready(mut definitions) =
                project_native_definition_units(&self.ready, &[*identity], cancellation, &session)?
            && definitions.len() == 1
            && let Some((identity, SelectedNativeDefinition::Lexical(definition))) =
                definitions.pop()
            && matches!(
                definition.kind,
                DeclarationKind::LocalVariable
                    | DeclarationKind::Parameter
                    | DeclarationKind::ReceiverParameter
            )
        {
            selected = Some((identity, definition));
        }
        let outcome =
            self.finish_native(selected, &ResolutionCompletion::Complete, cancellation)?;
        Ok(session.finish(outcome))
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn resolve_native_assignment_value_bounded(
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
    #[doc(hidden)]
    pub fn resolve_go_assignment_value_bounded(
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
    #[doc(hidden)]
    pub fn resolve_rust_assignment_value_bounded(
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
                    operation, answer, ready, mounts, session, cancellation,
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

    #[doc(hidden)]
    pub fn resolve_native_type_site_bounded(
        mut self,
        context: SelectedResolutionContextSet,
        locator: &SelectedSemanticLocator,
        budget: ReceiverAnalysisBudget,
        cancellation: &CancellationToken,
        context_metrics: &mut SelectedResolutionContextMetrics,
    ) -> Result<BoundedResolution<NativeReferenceTypesOutcome>> {
        let session = ResolutionSession::bounded(budget, Some(cancellation));
        // Positioned references include their ordinary expression projections.
        // A declaration name instead selects its exact published value slot.
        let declaration = match self.declaration_value_site_for_missing_reference(
            locator,
            cancellation,
            &session,
        )? {
            SelectedTypeSite::Reference => None,
            SelectedTypeSite::Missing => {
                return Ok(session.finish(SelectedResolutionOperationOutcome::Native(
                    SelectedResolutionLocated::Missing,
                )));
            }
            SelectedTypeSite::Declaration(site) => Some(site),
            SelectedTypeSite::Incomplete(answer) => {
                let completion = answer.answer.completion().clone();
                let outcome = self.finish_native(
                    SelectedResolutionLocated::Found(*answer),
                    &completion,
                    cancellation,
                )?;
                return Ok(session.finish(outcome));
            }
            SelectedTypeSite::Cancelled => {
                return Ok(
                    session.finish(SelectedResolutionOperationOutcome::Cancelled(
                        cancelled_completion(),
                    )),
                );
            }
        };
        let (selected, query_result_slot) = match &declaration {
            Some((selected, slot)) => (selected, Some(*slot)),
            None => {
                return self.resolve_native_reference_types_bounded(
                    context,
                    locator,
                    budget,
                    cancellation,
                    context_metrics,
                );
            }
        };
        self.resolve_native_type_query_bounded(super::NativeReferenceQuery {
            context,
            locator: selected,
            cancellation,
            context_metrics,
            session: &session,
            artifacts: None,
            go_demand: None,
            selected_import_gap: None,
            go_receiver_overlay: None,
            query_result_slot,
            point_metrics: None,
        })
    }

    /// A reference owns its expression projections; only a missing reference
    /// may select a declaration by its name range.
    fn declaration_value_site_for_missing_reference(
        &self,
        locator: &SelectedSemanticLocator,
        cancellation: &CancellationToken,
        session: &ResolutionSession,
    ) -> Result<SelectedTypeSite> {
        let lexical = self.ready.lexical_source();
        match lexical.lookup_semantic_sites(locator, cancellation, session)? {
            super::super::resolution_lexical::SelectedSemanticLookupOutcome::Found(_) => {
                Ok(SelectedTypeSite::Reference)
            }
            super::super::resolution_lexical::SelectedSemanticLookupOutcome::Missing => {
                self.selected_declaration_value_site(locator, cancellation)
            }
            super::super::resolution_lexical::SelectedSemanticLookupOutcome::Cancelled => {
                Ok(SelectedTypeSite::Cancelled)
            }
        }
    }

    fn selected_declaration_value_site(
        &self,
        locator: &SelectedSemanticLocator,
        cancellation: &CancellationToken,
    ) -> Result<SelectedTypeSite> {
        let Some((start, end)) = locator.reference_range() else {
            return Ok(SelectedTypeSite::Reference);
        };
        let Some(mount) = self
            .mount_table()
            .mount_for_path(locator.storage_language(), locator.relative_path())?
        else {
            return Ok(SelectedTypeSite::Reference);
        };
        if cancellation.is_cancelled() {
            return Ok(SelectedTypeSite::Cancelled);
        }
        let rows = self
            .ready
            .inventory
            .connection()
            .prepare_cached(SELECTED_DECLARATION_VALUE_SITE)?
            .query_map(
                rusqlite::params![
                    mount.ordinal().get(),
                    i64::try_from(start).expect("source offsets fit SQLite integers"),
                    i64::try_from(end).expect("source offsets fit SQLite integers"),
                ],
                |row| Ok((row.get::<_, u32>(0)?, row.get::<_, u32>(1)?)),
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(
            match self.declaration_value_site_from_rows(
                locator,
                mount.ordinal(),
                &rows,
                cancellation,
            )? {
                SelectedTypeSite::Missing => SelectedTypeSite::Reference,
                selected => selected,
            },
        )
    }

    fn selected_declaration_value_site_for_definition(
        &self,
        locator: &SelectedSemanticLocator,
        definition: SemanticId,
        cancellation: &CancellationToken,
        session: &ResolutionSession,
    ) -> Result<SelectedTypeSite> {
        let Some(mount) = self
            .mount_table()
            .mount_for_path(locator.storage_language(), locator.relative_path())?
        else {
            return Ok(SelectedTypeSite::Missing);
        };
        if cancellation.is_cancelled() {
            return Ok(SelectedTypeSite::Cancelled);
        }
        if definition.ordinal() != Some(mount.ordinal().get()) {
            return Err(StoreError::corrupt(format!(
                "declaration definition {definition:?} does not belong to selected mount {:?}",
                mount.ordinal()
            )));
        }
        let site = definition.local_key().ok_or_else(|| {
            StoreError::corrupt("declaration definition has no local source site")
        })?;
        let mut rows = Vec::new();
        let read = self.ready.typed_source().visit_declaration_type_pages_for_definitions(
            TypedFactRequest::new(&[definition]), cancellation,
            &mut FactPageVisitor::new(&mut |page: &[SelectedTypedRow<LoweredDeclarationTypeProperty>]| {
                for property in page {
                    if !session.scope_step() { return Ok(false); }
                    let property = property.row();
                    if property.definition() != definition {
                        return Err(StoreError::corrupt(format!(
                            "declaration type row {:?} answers a different definition than {definition:?}", property.definition()
                        )));
                    }
                    if property.slot().ordinal() != definition.ordinal() {
                        return Err(StoreError::corrupt(format!(
                            "declaration type slot {:?} has a different mount from definition {definition:?}", property.slot()
                        )));
                    }
                    if matches!(property.role(), DeclarationTypeRole::Value | DeclarationTypeRole::Parameter) {
                        let slot = property.slot().local_key().ok_or_else(|| StoreError::corrupt(
                            "declaration type slot has no local key",
                        ))?;
                        rows.push((site, slot));
                    }
                }
                Ok(true)
            }),
        )?;
        if read.is_cancelled() || cancellation.is_cancelled() {
            return Ok(SelectedTypeSite::Cancelled);
        }
        self.declaration_value_site_from_rows(locator, mount.ordinal(), &rows, cancellation)
    }

    fn declaration_value_site_from_rows(
        &self,
        locator: &SelectedSemanticLocator,
        ordinal: SelectedResolutionMountOrdinal,
        rows: &[(u32, u32)],
        cancellation: &CancellationToken,
    ) -> Result<SelectedTypeSite> {
        match rows {
            [] => Ok(SelectedTypeSite::Missing),
            [(site, slot)] => Ok(SelectedTypeSite::Declaration((
                SelectedSemanticLocator::new(
                    locator.storage_language(),
                    locator.relative_path(),
                    brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteId::new(*site),
                    crate::analyzer::resolution::LoweredSemanticRole::Definition,
                ),
                SemanticId::local(ordinal.get(), *slot),
            ))),
            _ => {
                // Several case-local binders can share one source name range.
                // A range does not select one of their distinct static slots,
                // so the answer carries one named reason instead of choosing.
                // Only dense site/slot coordinates are in hand here. Their
                // numbering changes with unrelated producer edits; a count is
                // the exception to full-collection diagnostics until stable
                // per-candidate source evidence is available without new reads.
                let evidence = format!(
                    "declaration range names several case-local bindings; no single value anchor is selected: {locator:?}, {} candidate bindings",
                    rows.len()
                );
                let mut hash = brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher::new(
                    b"bifrost-ambiguous-declaration-bindings:v1",
                );
                hash.field("evidence", evidence.as_bytes());
                let reason = self.ready.context_identities.named_semantic(
                    hash.finish(),
                    "ambiguous_declaration_bindings",
                    &evidence,
                );
                let completion = ResolutionCompletion::incomplete([
                    crate::analyzer::resolution::ResolutionIncompleteReason::UnsupportedSemantic(
                        reason,
                    ),
                ]);
                let answer =
                    crate::analyzer::resolution::fact_resolution::incomplete_fact_resolution_answer(
                        None,
                        completion,
                        cancellation,
                    );
                Ok(SelectedTypeSite::Incomplete(Box::new(
                    SelectedNativeReferenceTypes {
                        answer,
                        value_types: SelectedNativeTypes::Ready {
                            nominal: Vec::new(),
                            intrinsic: Box::new([]),
                            external_owners: Vec::new(),
                        },
                        query_result_slot: None,
                        direct_target: None,
                        named_reasons: vec![("ambiguous_declaration_bindings", evidence)],
                        diagnostic_identities: Vec::new(),
                    },
                )))
            }
        }
    }

    fn point_query_result_slot_at(
        &self,
        locator: &SelectedSemanticLocator,
        cancellation: &CancellationToken,
    ) -> Result<Option<SemanticId>> {
        Ok(
            match (locator.reference_range(), locator.call_argument_ordinal()) {
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
            },
        )
    }

    pub(crate) fn resolve_native_reference_types_bounded(
        mut self,
        context: SelectedResolutionContextSet,
        locator: &SelectedSemanticLocator,
        budget: ReceiverAnalysisBudget,
        cancellation: &CancellationToken,
        context_metrics: &mut SelectedResolutionContextMetrics,
    ) -> Result<BoundedResolution<NativeReferenceTypesOutcome>> {
        let query_result_slot = self.point_query_result_slot_at(locator, cancellation)?;
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
                let diagnostic_identities = native_type_diagnostic_identities(
                    ready,
                    &answer,
                    &types,
                    locator.storage_language(),
                    cancellation,
                )?;
                Ok(SelectedNativeReferenceTypes {
                    answer,
                    value_types: types,
                    query_result_slot,
                    direct_target,
                    named_reasons,
                    diagnostic_identities,
                })
            },
        )?;
        Ok(session.finish(outcome))
    }

    #[allow(clippy::too_many_arguments)]
    #[doc(hidden)]
    pub fn resolve_native_reference_types_bounded_for_go_request(
        &mut self,
        prepared: super::GoPreparedImportContext,
        query_result_slot: Option<SemanticId>,
        go_receiver_overlay: Option<crate::analyzer::resolution::GoReceiverSlotTypeOverlay>,
        locator: &SelectedSemanticLocator,
        definition: Option<SemanticId>,
        budget: ReceiverAnalysisBudget,
        cancellation: &CancellationToken,
        context_metrics: &mut SelectedResolutionContextMetrics,
        artifacts: &mut crate::analyzer::resolution::ForwardCandidateArtifactCache,
        point_metrics: &mut crate::analyzer::resolution::ResolutionBatchMetrics,
    ) -> Result<BoundedResolution<NativeReferenceTypesOutcome>> {
        let session = ResolutionSession::bounded(budget, Some(cancellation));
        let selected = match definition {
            Some(definition) => self.selected_declaration_value_site_for_definition(
                locator,
                definition,
                cancellation,
                &session,
            )?,
            None => {
                self.declaration_value_site_for_missing_reference(locator, cancellation, &session)?
            }
        };
        let declaration = match selected {
            SelectedTypeSite::Reference => None,
            SelectedTypeSite::Missing => {
                return Ok(session.finish(SelectedResolutionOperationOutcome::Native(
                    SelectedResolutionLocated::Missing,
                )));
            }
            SelectedTypeSite::Declaration(site) => Some(site),
            SelectedTypeSite::Incomplete(answer) => {
                let completion = answer.answer.completion().clone();
                let outcome = self.finish_native(
                    SelectedResolutionLocated::Found(*answer),
                    &completion,
                    cancellation,
                )?;
                return Ok(session.finish(outcome));
            }
            SelectedTypeSite::Cancelled => {
                return Ok(
                    session.finish(SelectedResolutionOperationOutcome::Cancelled(
                        cancelled_completion(),
                    )),
                );
            }
        };
        let (locator, query_result_slot) = match &declaration {
            Some((selected, slot)) => (selected, Some(*slot)),
            None => (locator, query_result_slot),
        };
        let query_result_slot = match query_result_slot {
            Some(slot) => Some(slot),
            None => self.point_query_result_slot_at(locator, cancellation)?,
        };
        if locator.call_argument_ordinal().is_some() && query_result_slot.is_none() {
            return Ok(session.finish(SelectedResolutionOperationOutcome::Native(
                SelectedResolutionLocated::Missing,
            )));
        }
        self.resolve_native_type_query_bounded(super::NativeReferenceQuery {
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
        })
    }

    fn resolve_native_type_query_bounded(
        &mut self,
        query: super::NativeReferenceQuery<'_>,
    ) -> Result<BoundedResolution<NativeReferenceTypesOutcome>> {
        let session = query.session;
        let cancellation = query.cancellation;
        let query_result_slot = query.query_result_slot;
        let storage_language = query.locator.storage_language();
        let outcome =
            self.resolve_reference_with_projection(query, |ready, operation, _, answer| {
                let types = project_native_reference_types(
                    ready,
                    operation,
                    &answer,
                    cancellation,
                    session,
                )?;
                let named_reasons = named_reason_details(ready, answer.completion())?;
                let direct_target = selected_external_member_target(ready, &answer, cancellation)?;
                let diagnostic_identities = native_type_diagnostic_identities(
                    ready,
                    &answer,
                    &types,
                    storage_language,
                    cancellation,
                )?;
                Ok(SelectedNativeReferenceTypes {
                    answer,
                    value_types: types,
                    query_result_slot,
                    direct_target,
                    named_reasons,
                    diagnostic_identities,
                })
            })?;
        Ok(session.finish(outcome))
    }

    pub(crate) fn resolve_native_reference_units(
        mut self,
        context: SelectedResolutionContextSet,
        locator: &SelectedSemanticLocator,
        cancellation: &CancellationToken,
        context_metrics: &mut SelectedResolutionContextMetrics,
    ) -> Result<NativeReferenceUnitsOutcome> {
        self.resolve_native_reference_units_in_session(
            super::NativeReferenceQuery {
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
            },
            None,
        )
    }

    #[doc(hidden)]
    pub fn resolve_native_reference_units_bounded(
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

    #[doc(hidden)]
    pub fn resolve_native_reference_units_bounded_with_import_gap(
        mut self,
        context: SelectedResolutionContextSet,
        locator: &SelectedSemanticLocator,
        budget: ReceiverAnalysisBudget,
        cancellation: &CancellationToken,
        context_metrics: &mut SelectedResolutionContextMetrics,
        selected_import_gap: Option<(SemanticId, SemanticId)>,
    ) -> Result<BoundedResolution<NativeReferenceUnitsOutcome>> {
        let session = ResolutionSession::bounded(budget, Some(cancellation));
        let outcome = self.resolve_native_reference_units_in_session(
            super::NativeReferenceQuery {
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
            },
            None,
        )?;
        Ok(session.finish(outcome))
    }

    #[allow(clippy::too_many_arguments)]
    #[doc(hidden)]
    pub fn resolve_native_reference_units_bounded_for_go_request(
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
        self.resolve_native_reference_units_bounded_for_go_request_with_reader(
            prepared,
            go_receiver_overlay,
            locator,
            budget,
            cancellation,
            context_metrics,
            artifacts,
            point_metrics,
            &mut |_, _| Ok(()),
        )
    }

    #[allow(clippy::too_many_arguments)]
    #[doc(hidden)]
    pub fn resolve_native_reference_units_bounded_for_go_request_with_reader(
        &mut self,
        prepared: super::GoPreparedImportContext,
        go_receiver_overlay: Option<crate::analyzer::resolution::GoReceiverSlotTypeOverlay>,
        locator: &SelectedSemanticLocator,
        budget: ReceiverAnalysisBudget,
        cancellation: &CancellationToken,
        context_metrics: &mut SelectedResolutionContextMetrics,
        artifacts: &mut crate::analyzer::resolution::ForwardCandidateArtifactCache,
        point_metrics: &mut crate::analyzer::resolution::ResolutionBatchMetrics,
        selected_reader: &mut SelectedNativeReferenceReader<'_>,
    ) -> Result<BoundedResolution<NativeReferenceUnitsOutcome>> {
        let session = ResolutionSession::bounded(budget, Some(cancellation));
        let outcome = self.resolve_native_reference_units_in_session(
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
                query_result_slot: None,
                point_metrics: Some(point_metrics),
            },
            Some(selected_reader),
        )?;
        Ok(session.finish(outcome))
    }

    /// #7314 6b: full native query and post-query oracle evidence, deleted with the oracle.
    #[cfg(any(test, feature = "test-support"))]
    pub fn jvm_model_observation_for_test(
        mut self,
        language: Language,
        path: &str,
        start: usize,
        end: usize,
        subject: super::jvm_context::JvmOracleSourceSubject<'_>,
        cancellation: &CancellationToken,
    ) -> Result<std::collections::BTreeMap<String, serde_json::Value>> {
        let super::JvmImportContext::Ready { context, .. } =
            self.jvm_import_context(language, path, cancellation)?
        else {
            panic!("model oracle context unavailable")
        };
        let locator =
            SelectedSemanticLocator::for_reference_range(language.config_label(), path, start, end);
        let session = ResolutionSession::unbounded();
        let outcome = self.resolve_native_reference_units_in_session(
            super::NativeReferenceQuery {
                context: (*context).clone(),
                locator: &locator,
                cancellation,
                context_metrics: &mut SelectedResolutionContextMetrics,
                session: &session,
                artifacts: None,
                go_demand: None,
                selected_import_gap: None,
                go_receiver_overlay: None,
                query_result_slot: None,
                point_metrics: None,
            },
            None,
        )?;
        let mut fields = std::collections::BTreeMap::new();
        let lexical = self.ready.lexical_source();
        let sites = match lexical.lookup_semantic_sites(&locator, cancellation, &session)? {
            crate::analyzer::store::resolution_lexical::SelectedSemanticLookupOutcome::Found(
                sites,
            ) => sites,
            _ => Vec::new(),
        };
        let mut associations = Vec::new();
        for site in sites {
            let reference = site.semantic();
            associations.push(self.java_oracle_reference_observation_for_test(
                language,
                path,
                reference,
                subject,
                cancellation,
            )?);
        }
        fields.insert(
            "reference_association".into(),
            serde_json::json!(associations),
        );
        // #7314 6b: compact Debug keeps typed aliases recognizable by the shared
        // canonical renderer. Validate native portable reason receipts against
        // the operation's retained canonical demand identities.
        let mut rendered = format!("{outcome:?}");
        if let SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Found(
            answer,
        )) = &outcome
        {
            for (alias, digest) in &answer.argument_reason_digests {
                if alias.shared_name_id().is_none() && alias.ordinal().is_none() {
                    assert_eq!(
                        self.ready
                            .identity_content_digest((*alias).into(), cancellation)?,
                        *digest,
                        "native reason receipt must denote the same canonical content"
                    );
                }
            }
            // These are typed canonical digest fields, not arbitrary numeric arrays.
            let digests = answer
                .argument_reason_digests
                .iter()
                .map(|(_, digest)| digest)
                .chain(answer.call_binding_reason_digests.iter())
                .chain(
                    answer
                        .constructor_hierarchy_reason_digests
                        .iter()
                        .map(|(_, digest)| digest),
                )
                .chain(
                    answer
                        .static_type_qualifier_reason_digests
                        .iter()
                        .map(|(_, digest)| digest),
                );
            for digest in digests {
                rendered = rendered.replace(
                    &format!("{digest:?}"),
                    &format!(
                        "digest:{}",
                        brokk_bifrost_core::analyzer::canonical_hash::lower_hex_string(digest)
                    ),
                );
            }
        }
        fields.insert(
            "answer".into(),
            serde_json::json!(self.canonical_java_snapshot(rendered)),
        );
        // Canonicalize the complete event collection once, preserving every event.
        let provenance = serde_json::to_string(
            &self
                .ready
                .context_identities
                .java_oracle_registration_trace(),
        )
        .unwrap();
        fields.insert(
            "registration_provenance".into(),
            serde_json::from_str(&self.canonical_java_snapshot(provenance)).unwrap(),
        );
        fields.insert(
            "route_visits".into(),
            serde_json::json!(self.java_oracle_visits_for_test()),
        );
        Ok(fields)
    }

    fn resolve_native_reference_units_in_session(
        &mut self,
        query: super::NativeReferenceQuery<'_>,
        mut selected_reader: Option<&mut SelectedNativeReferenceReader<'_>>,
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
                let argument_binding = operation.binding_after_argument_proof(&answer);
                let call_binding_reason_digests = operation.external_call_binding_reason_digests(&answer)?;
                let constructor_hierarchy_reason_digests = operation.constructor_hierarchy_reason_digests(&answer)?;
                let static_type_qualifier_reason_digests = operation.static_type_qualifier_reason_digests(&answer)?;
                let mut argument_reason_ids = Vec::new();
                if let Some(binding) = &argument_binding
                    && let crate::analyzer::resolution::ResolutionCompletion::Incomplete(reasons) = binding.completion()
                {
                    for reason in reasons.iter() {
                        if let crate::analyzer::resolution::ResolutionIncompleteReason::UnsupportedSemantic(reason)
                            | crate::analyzer::resolution::ResolutionIncompleteReason::OpenBoundary { semantic: reason, status: crate::analyzer::structural::BoundaryStatus::ExternalDeclaredUnindexed } = reason {
                            argument_reason_ids.push(*reason);
                        }
                    }
                }
                let argument_reason_digests = ready.argument_reason_digests_batch(operation, &argument_reason_ids)?;
                let named_reasons = native_reference_reason_details(ready, operation, reference, answer.binding().completion())?;
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
                        let (member_name, is_static) = if let Some(members) = super::super::resolution_typed::external_owners::intrinsic_member_inventory_for_owner(ready.inventory.connection(), &owner)? {
                            (members[ordinal as usize].name.to_owned(), false)
                        } else { ready.inventory.connection().query_row(
                            "SELECT member_name,is_static FROM jvm_external_owner_members WHERE provider_id=?1 AND owner_fqn=?2 AND ordinal=?3",
                            rusqlite::params![owner.provider_id.as_ref(),owner.owner_fqn.as_ref(),ordinal],
                            |row| Ok((row.get(0)?,row.get(1)?)))? };
                        external_members.push(ProjectedNativeExternalMember {
                            coordinate: crate::analyzer::resolution::ExternalMemberCoordinate::InventoryOrdinal(ordinal),
                            identity: crate::analyzer::resolution::ExternalMemberIdentity { owner: owner.clone(), ordinal },
                            member_name, is_static,
                            pack: ready.context_identities.is_jvm_package_member_target(target).then(|| {
                                let shards = ready.model_authority().and_then(|authority| authority.active_models()).expect("selected package member has an active pack").shards();
                                let shard = shards.iter().find(|shard| shard.manifest.semantic_sha256 == owner.provider_id.as_ref()).expect("member provider is active");
                                (shard.manifest.pack_id.clone(), shard.manifest.version.clone())
                            }),
                        });
                    }
                }
                let model_targets = answer.model_member_selection().into_iter().flat_map(|selection| selection.candidates.iter().map(|member| member.target)).collect::<BTreeSet<_>>();
                let model_member_selection = answer.model_member_selection().and_then(|selection| project_native_model_member_selection(selection, cancellation));
                let source_targets = answer.binding().targets().iter().copied().filter(|target| !model_targets.contains(target)).collect::<Vec<_>>();
                let mut definitions = project_native_definition_units(
                    ready,
                    &source_targets,
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
                    .filter(|target| !model_targets.contains(target))
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
                // A cancelled read keeps the binding's whole completion, which
                // can only withhold coverage.
                let call_applicability_reason = if crate::analyzer::resolution::resolution_diagnostics().native_rejection_projection_active() {
                    operation.call_applicability_reason_for_callee(reference)?.flatten()
                } else {
                    None
                };
                let trace_provenance = project_native_trace_provenance(ready, &answer, call_applicability_reason, &definitions, &callable_applicability_candidates, &member_contexts, cancellation)?;
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
                // Unit targets are already projected above. Only unresolved
                // identities need to consult source/content evidence again.
                #[cfg(any(test, feature = "test-support"))]
                record_native_completion_reason_ownership(ready, answer.binding().completion());
                let mut diagnostic_semantics = Vec::new();
                if answer.binding().targets().len() > 1 || matches!(answer.binding().completion(), ResolutionCompletion::Incomplete(reasons) if reasons.iter().any(|reason| matches!(reason, ResolutionIncompleteReason::InconsistentPrecedence(_)))) {
                    diagnostic_semantics.extend(answer.binding().targets().iter().copied());
                }
                diagnostic_semantics.extend(answer.callable_candidate_applicability().iter()
                    .filter(|candidate| candidate.verdict() == brokk_bifrost_core::analyzer::structural::callable::ApplicabilityVerdict::Inapplicable)
                    .map(|candidate| candidate.target()));
                if let ResolutionCompletion::Incomplete(reasons) = answer.binding().completion() {
                    diagnostic_semantics.extend(reasons.iter().filter_map(|reason| public_reason_details(reason).1));
                }
                diagnostic_semantics.sort_unstable();
                diagnostic_semantics.dedup();
                let diagnostic_identities = diagnostic_semantics.into_iter().map(|semantic| {
                    let unit = match &definitions {
                        SelectedNativeDefinitions::Ready(rows) => rows.iter().find_map(|(id, definition)| {
                            if *id != semantic { return None; }
                            match definition { SelectedNativeDefinition::Unit(unit) => Some(unit), _ => None }
                        }),
                        _ => None,
                    }.or_else(|| callable_applicability_candidates.iter().find_map(|(id, unit)| (*id == semantic).then_some(unit)));
                    let identity = if let Some(unit) = unit {
                        public_diagnostic_identity("semantic", Some(unit), None, None)
                    } else {
                        selected_public_diagnostic_identity(ready, semantic, cancellation, session)?
                    };
                    Ok((semantic, identity))
                }).collect::<Result<Vec<_>>>()?;
                let selected = SelectedNativeReferenceUnits {
                    query_obligations: answer.query_obligations.clone(),
                    answer,
                    argument_binding,
                    argument_reason_digests,
                    call_binding_reason_digests,
                    constructor_hierarchy_reason_digests,
                    static_type_qualifier_reason_digests,
                    definitions,
                    external_members,
                    model_member_selection,
                    direct_target,
                    named_argument,
                    predeclared_go_symbol,
                    callable_applicability_candidates,
                    member_contexts,
                    trace_provenance,
                    declared_visibilities,
                    absent_member_owners,
                    named_reasons,
                    diagnostic_identities,
                };
                if let Some(reader) = selected_reader.as_mut() {
                    reader(operation, &selected)?;
                }
                Ok(selected)
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
            "named-argument call {} has no selected call obligation",
            selected_public_diagnostic_identity(ready, label.call, cancellation, session)?
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
            "named-argument call {} has no unique selected callable: targets={:?}, completion={}",
            selected_public_diagnostic_identity(ready, label.call, cancellation, session)?,
            binding
                .targets()
                .iter()
                .map(|target| selected_public_diagnostic_identity(
                    ready,
                    *target,
                    cancellation,
                    session
                ))
                .collect::<Result<Vec<_>>>()?,
            selected_public_completion_details(
                ready,
                call_answer.completion(),
                cancellation,
                session
            )?
        ))));
    };
    if binding.completion() != &ResolutionCompletion::Complete
        || call_answer.completion() != &ResolutionCompletion::Complete
    {
        return Ok(Some(SelectedNativeNamedArgument::Incomplete(format!(
            "named-argument call {} has a selected callable {} but its resolution is incomplete: binding={}, resolution={}",
            selected_public_diagnostic_identity(ready, label.call, cancellation, session)?,
            selected_public_diagnostic_identity(ready, *target, cancellation, session)?,
            selected_public_completion_details(ready, binding.completion(), cancellation, session)?,
            selected_public_completion_details(
                ready,
                call_answer.completion(),
                cancellation,
                session
            )?
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
            "named-argument call {} lacks complete dispatch evidence for callable {}: receiver_dispositions={:?}",
            selected_public_diagnostic_identity(ready, label.call, cancellation, session)?,
            selected_public_diagnostic_identity(ready, *target, cancellation, session)?,
            receiver_dispositions
                .iter()
                .map(|value| (value.disposition().channels(), value.disposition().gap()))
                .collect::<Vec<_>>(),
        ))));
    }
    let Some(parameter) = operation.callable_parameter_for_label(*target, &label.spelling)? else {
        return Ok(Some(SelectedNativeNamedArgument::Incomplete(format!(
            "selected callable {} has no unique parameter named {:?}",
            selected_public_diagnostic_identity(ready, *target, cancellation, session)?,
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
            "selected parameter {} has no native source-unit projection",
            selected_public_diagnostic_identity(ready, parameter, cancellation, session)?
        ))));
    };
    let Some((projected_parameter, definition)) = parameters.pop() else {
        return Ok(Some(SelectedNativeNamedArgument::Incomplete(format!(
            "selected parameter {} has no native source-unit projection",
            selected_public_diagnostic_identity(ready, parameter, cancellation, session)?
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
/// batch. `None` when cancelled. Each read binds a page of coordinates as one
/// JSON array, so a batch costs one statement execution per page, not one
/// per definition.
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
    let file = ProjectFile::new(ready.project.root(), mount.persisted_relative_path());
    let Some(unit_rows) = rows.units.remove(&coordinate) else {
        use super::super::selected_definition::SelectedDeclarationDefinition;
        return match rows.lexical.remove(&coordinate) {
            Some(SelectedDeclarationDefinition::Lexical(mut row)) => {
                row.source_file = Some(file);
                Ok(Some(SelectedNativeDefinition::Lexical(row)))
            }
            Some(SelectedDeclarationDefinition::Module(_)) => {
                let anchor = ready.definition_module_anchor(coordinate.0, &file)?;
                Ok(
                    super::super::linked_store_language_support(mount.semantic_language())
                        .expect("selected language has store support")
                        .selected_module_definition(ready.project, &file, anchor.as_ref())?
                        .map(SelectedNativeDefinition::Unit),
                )
            }
            Some(SelectedDeclarationDefinition::WithoutUnit(_)) | None => Ok(None),
        };
    };
    let mut selected_unit = None;
    for row in unit_rows {
        let persisted = row
            .fq
            .as_ref()
            .ok_or_else(|| StoreError::corrupt("source declaration lacks structured identity"))?;
        let prefix = match persisted.anchor {
            None => None,
            Some(PackageAnchor::OwnModule { pop: 0 }) => {
                let Some(prefix) = ready.definition_module_anchor(coordinate.0, &file)? else {
                    return Ok(None);
                };
                Some(prefix)
            }
            _ => {
                return Err(StoreError::corrupt(
                    "source declaration has an unsupported package anchor",
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

impl ReadySelectedResolution<'_, '_> {
    fn argument_reason_digests_batch(
        &self,
        operation: &crate::analyzer::resolution::FactResolutionOperation<'_>,
        reasons: &[SemanticId],
    ) -> Result<Vec<(SemanticId, [u8; 32])>> {
        selected_argument_reason_digests_batch(&self.inventory, reasons, |reason| {
            operation.identity_content_digest(reason.into())
        })
    }

    pub(crate) fn definition_module_anchor(
        &self,
        ordinal: SelectedResolutionMountOrdinal,
        file: &ProjectFile,
    ) -> Result<Option<crate::analyzer::fq_name::FqName>> {
        if let Some(anchor) = self.definition_module_anchors.borrow().get(&ordinal) {
            return Ok(anchor.clone());
        }
        let mount = SelectedMountTable::new(&self.inventory).mount_by_ordinal(ordinal)?;
        let anchor = super::super::linked_store_language_support(mount.semantic_language())
            .expect("selected language has store support")
            .selected_definition_module_anchor(&self.inventory, ordinal, self.project, file)?;
        self.definition_module_anchors
            .borrow_mut()
            .insert(ordinal, anchor.clone());
        Ok(anchor)
    }
}

fn selected_argument_reason_digests_batch(
    inventory: &SelectedResolutionMountInventory<'_>,
    reasons: &[SemanticId],
    mut identity_content_digest: impl FnMut(SemanticId) -> Result<[u8; 32]>,
) -> Result<Vec<(SemanticId, [u8; 32])>> {
    use crate::analyzer::resolution::{gap_reason_semantic_identity, mounted_identity_digest};
    use rusqlite::params;

    let authority =
        super::super::resolution_authority::SelectedResolutionAuthority::from_selection(inventory);
    let mut checked_mounts = crate::hash::HashSet::default();
    let mut interrupted_mounts = crate::hash::HashSet::default();
    let mut inputs = Vec::new();
    let mut mounts = Vec::new();
    for &reason in reasons {
        let (Some(ordinal), Some(local_key)) = (reason.ordinal(), reason.local_key()) else {
            mounts.push(None);
            continue;
        };
        if !super::super::resolution_stage::allocation::is_ordinary_key(local_key) {
            mounts.push(None);
            continue;
        }
        let ordinal = SelectedResolutionMountOrdinal::new(ordinal);
        let mount = inventory.mount_record_by_ordinal(ordinal)?;
        if checked_mounts.insert(ordinal) {
            // A content lookup has its own finite cancellation token. The
            // selected authority memo avoids a second publication query
            // when this operation already checked the mount.
            let content_lookup = CancellationToken::new();
            if authority
                .ensure_authority(&mount, &content_lookup)?
                .is_none()
            {
                interrupted_mounts.insert(ordinal);
            }
        }
        if interrupted_mounts.contains(&ordinal) {
            mounts.push(None);
            continue;
        }
        inputs.push((mount.blob_id(), local_key));
        mounts.push(Some(mount.fragment_digest().as_bytes()));
    }
    let (catalog, gaps) = if inputs.is_empty() {
        (Vec::new(), Vec::new())
    } else {
        let keys =
            serde_json::to_string(&inputs).map_err(|error| StoreError::new(error.to_string()))?;
        let content_lookup = CancellationToken::new();
        let batch = super::super::resolution::read_resolution_statement(
            inventory.connection(),
            &content_lookup,
            |conn| {
                let mut catalog = vec![None; inputs.len()];
                let mut gaps = vec![None; inputs.len()];
                let mut statement =
                    conn.prepare_cached(NATIVE_ARGUMENT_REASON_IDENTITY_DIGEST_SQL)?;
                let rows = statement.query_map(params![keys], |row| {
                    Ok((row.get::<_, usize>(0)?, row.get::<_, Option<[u8; 32]>>(1)?))
                })?;
                for row in rows {
                    let (index, digest) = row?;
                    catalog[index] = digest;
                }
                let mut statement = conn.prepare_cached(NATIVE_ARGUMENT_REASON_GAP_REASONS_SQL)?;
                let rows = statement.query_map(params![keys], |row| {
                    Ok((
                        row.get::<_, usize>(0)?,
                        row.get::<_, Option<u32>>(1)?,
                        row.get::<_, Option<i64>>(2)?,
                    ))
                })?;
                for row in rows {
                    let (index, site, origin) = row?;
                    gaps[index] = site.zip(origin);
                }
                Ok(Some((catalog, gaps)))
            },
        )?;
        let Some(batch) = batch else {
            return reasons
                .iter()
                .copied()
                .map(|reason| Ok((reason, identity_content_digest(reason)?)))
                .collect();
        };
        batch
    };
    let mut next_input = 0;
    let mut result = Vec::with_capacity(reasons.len());
    for (&reason, mount) in reasons.iter().zip(mounts) {
        let digest = if let Some(mount) = mount {
            let index = next_input;
            next_input += 1;
            if let Some(identity) = catalog[index] {
                mounted_identity_digest(b"semantic", mount, identity)
            } else if let Some((site, origin)) = gaps[index] {
                let identity = gap_reason_semantic_identity(
                    ResolutionSiteId::new(site),
                    super::super::resolution_prepare::resolution_rows::gap_origin_from_code(origin),
                );
                mounted_identity_digest(b"semantic", mount, identity.fragment_local_digest())
            } else {
                identity_content_digest(reason)?
            }
        } else {
            identity_content_digest(reason)?
        };
        result.push((reason, digest));
    }
    Ok(result)
}

#[cfg(test)]
mod argument_reason_digest_tests {
    use super::*;

    #[test]
    fn batched_reason_digests_check_mount_before_catalog_or_gap_rows() {
        let (store, workspace, snapshots) =
            super::super::super::resolution_selection::tests::qualifier_completion_gap_fixture();
        let languages = [SelectedResolutionLanguage::new("go", Language::Go)];
        let cancellation = CancellationToken::new();
        let open = || {
            let SelectedResolutionMountInventoryOutcome::Ready(selection) = store
                .open_selected_resolution_mount_inventory(
                    &workspace,
                    &snapshots,
                    &languages,
                    &[],
                    &cancellation,
                )
                .unwrap()
            else {
                panic!("published fixture must open a selected inventory");
            };
            selection
        };

        let catalog = SemanticId::local(0, 0);
        let gap = SemanticId::local(0, 2);
        let missing = SemanticId::local(0, 1);
        let staged = SemanticId::local(0, 1 << 31);
        let selection = open();
        let mount = selection
            .mount_record_by_ordinal(SelectedResolutionMountOrdinal::new(0))
            .unwrap();
        let mut fallbacks = Vec::new();
        let ordered = [catalog, gap, catalog, missing, staged, gap];
        let actual = selected_argument_reason_digests_batch(&selection, &ordered, |reason| {
            fallbacks.push(reason);
            Ok([9; 32])
        })
        .unwrap();
        let mounted = mount.fragment_digest().as_bytes();
        let expected_catalog =
            crate::analyzer::resolution::mounted_identity_digest(b"semantic", mounted, [1; 32]);
        let gap_identity = crate::analyzer::resolution::gap_reason_semantic_identity(
            ResolutionSiteId::new(0),
            super::super::super::resolution_prepare::resolution_rows::gap_origin_from_code(0),
        );
        let expected_gap = crate::analyzer::resolution::mounted_identity_digest(
            b"semantic",
            mounted,
            gap_identity.fragment_local_digest(),
        );
        assert_eq!(
            actual,
            [
                (catalog, expected_catalog),
                (gap, expected_gap),
                (catalog, expected_catalog),
                (missing, [9; 32]),
                (staged, [9; 32]),
                (gap, expected_gap),
            ]
        );
        assert_eq!(fallbacks, [missing, staged]);
        drop(selection);

        let stale_selection = open();
        let blob_id = stale_selection
            .mount_record_by_ordinal(SelectedResolutionMountOrdinal::new(0))
            .unwrap()
            .blob_id();
        store.conn.execute(move |conn| {
            assert_eq!(
                conn.execute(
                    "UPDATE resolution_fragment_interiors SET producer_epoch='stale' WHERE blob_id=?1",
                    [blob_id],
                )
                .unwrap(),
                1
            );
        });
        let failure =
            selected_argument_reason_digests_batch(&stale_selection, &[catalog, gap], |_| {
                panic!("published rows must not fall back when their mount is stale")
            })
            .unwrap_err();
        assert!(failure.is_stale_resolution(), "{failure:?}");
    }
}

/// Canonical Python declaration placement from the selected file publication.
pub fn python_definition_module_anchor(
    selection: &super::super::resolution_selection::SelectedResolutionMountInventory<'_>,
    ordinal: SelectedResolutionMountOrdinal,
    file: &ProjectFile,
) -> Result<Option<crate::analyzer::fq_name::FqName>> {
    let name: Option<String> = selection
        .connection()
        .query_row(
            "SELECT anchors.package_name FROM temp.selected_resolution_mounts mounts
         JOIN main.workspace_file_anchor_rows anchors USING(file_version_id)
         WHERE mounts.mount_ordinal=?1 AND anchors.anchor_kind='own_module'
           AND anchors.anchor_pop=0",
            [ordinal.get()],
            |row| row.get(0),
        )
        .optional()?;
    name.map(|name| {
        let components =
            brokk_bifrost_python::declarations::python_module_components_from_name(file, &name)
                .ok_or_else(|| {
                    StoreError::corrupt(
                        "published Python module is not a suffix of its mounted path",
                    )
                })?;
        Ok(crate::analyzer::fq_name::FqName::from_package_components(
            &components,
        ))
    })
    .transpose()
}

/// Go package placement authority for a selected definition's OwnModule anchor.
#[doc(hidden)]
pub fn go_definition_module_anchor(
    selection: &super::super::resolution_selection::SelectedResolutionMountInventory<'_>,
    ordinal: SelectedResolutionMountOrdinal,
) -> Result<Option<crate::analyzer::fq_name::FqName>> {
    let record = selection.mount_record_by_ordinal(ordinal)?;
    let Some(version) =
        super::go_context::go_placement_file_version(selection.connection(), &record)?
    else {
        // An unsaved replacement whose membership inputs changed has no selected
        // placement; its predecessor is not proof.
        return Ok(None);
    };
    let package: Option<String> = selection
        .connection()
        .query_row(GO_DEFINITION_PACKAGE_ANCHOR, [version], |row| row.get(0))
        .optional()?;
    Ok(package.map(|package| brokk_bifrost_go::declarations::go_package_fq(&package)))
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

fn native_type_diagnostic_identities(
    ready: &ReadySelectedResolution<'_, '_>,
    answer: &FactResolutionAnswer,
    types: &SelectedNativeTypes,
    storage_language: &str,
    cancellation: &CancellationToken,
) -> Result<Vec<(SemanticId, String)>> {
    let SelectedNativeTypes::Ready {
        nominal,
        intrinsic,
        external_owners,
    } = types
    else {
        return Ok(Vec::new());
    };
    let mut semantics = Vec::new();
    let mut collect_reasons = |completion: &ResolutionCompletion| {
        if let ResolutionCompletion::Incomplete(reasons) = completion {
            semantics.extend(
                reasons
                    .iter()
                    .filter_map(|reason| public_reason_details(reason).1),
            );
        }
    };
    collect_reasons(answer.completion());
    for frontier in answer.projected_frontiers() {
        collect_reasons(frontier.completion());
    }
    let alternatives = answer
        .projected_frontiers()
        .iter()
        .flat_map(|frontier| {
            frontier
                .possible_values()
                .iter()
                .map(|value| (value.ty().identity(), value.ty().indirection()))
        })
        .collect::<BTreeSet<_>>();
    let may_be_ambiguous = alternatives.len() > 1 || answer.projected_frontiers().len() > 1;
    for frontier in answer.projected_frontiers() {
        if may_be_ambiguous {
            semantics.push(frontier.slot());
        }
        for value in frontier.possible_values() {
            let identity = value.ty().identity();
            let known = nominal.iter().any(|(id, definition)| {
                *id == identity && !matches!(definition, SelectedNativeDefinition::Lexical(_))
            }) || intrinsic
                .iter()
                .any(|descriptor| descriptor.identity() == identity)
                || external_owners.iter().any(|(id, _)| *id == identity);
            if may_be_ambiguous
                || !known
                || (storage_language != "go" && value.ty().indirection() != 0)
            {
                semantics.push(identity);
            }
        }
    }
    for projection in answer.projections() {
        if !answer
            .projected_frontiers()
            .iter()
            .any(|frontier| frontier.slot() == projection.output_slot())
        {
            semantics.push(projection.output_slot());
        }
    }
    for shape in answer.projected_type_shapes() {
        if !shape.supported() {
            semantics.push(shape.output_slot());
        }
    }
    semantics.sort_unstable();
    semantics.dedup();
    let session = ResolutionSession::unbounded();
    semantics
        .into_iter()
        .map(|semantic| {
            let unit = nominal
                .iter()
                .find_map(|(id, definition)| match definition {
                    SelectedNativeDefinition::Unit(unit) if *id == semantic => Some(unit),
                    _ => None,
                });
            let identity = if let Some(unit) = unit {
                public_diagnostic_identity("semantic", Some(unit), None, None)
            } else {
                selected_public_diagnostic_identity(ready, semantic, cancellation, &session)?
            };
            Ok((semantic, identity))
        })
        .collect()
}

/// Project a semantic's available evidence into a portable public identity.
/// Numeric semantic aliases are deliberately never an input to this policy.
#[doc(hidden)]
pub fn public_diagnostic_identity(
    kind: &str,
    declaration: Option<&CodeUnit>,
    shared_digest: Option<&[u8; 32]>,
    site: Option<&serde_json::Value>,
) -> String {
    if let Some(unit) = declaration {
        return unit.declaration_id().to_string();
    }
    if let Some(digest) = shared_digest {
        return format!(
            "shared:{}",
            digest
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        );
    }
    if let Some(site) = site
        && let (Some(path), Some(line), Some(column)) = (
            site.get("path").and_then(|v| v.as_str()),
            site.get("line"),
            site.get("column"),
        )
    {
        return format!("{path}:{line}:{column}");
    }
    kind.to_owned()
}

/// Keep alternative multiplicity while ordering by public evidence.
#[doc(hidden)]
pub fn public_diagnostic_targets(
    targets: &[SemanticId],
    project: impl Fn(SemanticId) -> String,
) -> Vec<String> {
    let mut projected = targets
        .iter()
        .map(|target| project(*target))
        .collect::<Vec<_>>();
    projected.sort_unstable();
    projected
}

/// The public structure of one incomplete reason, without Debug aliases.
#[doc(hidden)]
pub fn public_reason_details(
    reason: &ResolutionIncompleteReason,
) -> (&'static str, Option<SemanticId>) {
    match *reason {
        ResolutionIncompleteReason::UnsupportedSemantic(id) => ("UnsupportedSemantic", Some(id)),
        ResolutionIncompleteReason::OpenBoundary { semantic, .. } => {
            ("OpenBoundary", Some(semantic))
        }
        ResolutionIncompleteReason::CyclicPrefixDependency(id) => {
            ("CyclicPrefixDependency", Some(id))
        }
        ResolutionIncompleteReason::InconsistentPrecedence(id) => {
            ("InconsistentPrecedence", Some(id))
        }
        ResolutionIncompleteReason::ReceiverBudgetExhausted(id) => {
            ("ReceiverBudgetExhausted", Some(id))
        }
        ResolutionIncompleteReason::TimeBudgetExceeded(id) => ("TimeBudgetExceeded", Some(id)),
        ResolutionIncompleteReason::Cancelled => ("Cancelled", None),
        ResolutionIncompleteReason::CyclicExpansion(_) => ("CyclicExpansion", None),
        ResolutionIncompleteReason::UnmountedFile { .. } => ("UnmountedFile", None),
    }
}

#[doc(hidden)]
pub fn public_completion_details(
    completion: &ResolutionCompletion,
    project: impl Fn(SemanticId) -> String,
) -> String {
    let ResolutionCompletion::Incomplete(reasons) = completion else {
        return "Complete".to_owned();
    };
    let mut details = reasons
        .iter()
        .map(|reason| {
            let (kind, semantic) = public_reason_details(reason);
            let mut fields = vec![kind.to_owned()];
            if let Some(semantic) = semantic {
                fields.push(project(semantic));
            }
            if let ResolutionIncompleteReason::OpenBoundary { status, .. } = reason {
                fields.push(status.label().to_owned());
            }
            fields.join(": ")
        })
        .collect::<Vec<_>>();
    details.sort_unstable();
    format!("Incomplete [{}]", details.join(", "))
}

fn selected_public_completion_details(
    ready: &ReadySelectedResolution<'_, '_>,
    completion: &ResolutionCompletion,
    cancellation: &CancellationToken,
    session: &ResolutionSession,
) -> Result<String> {
    let ResolutionCompletion::Incomplete(reasons) = completion else {
        return Ok("Complete".to_owned());
    };
    let projected = reasons
        .iter()
        .filter_map(|reason| public_reason_details(reason).1)
        .map(|semantic| {
            Ok((
                semantic,
                selected_public_diagnostic_identity(ready, semantic, cancellation, session)?,
            ))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    Ok(public_completion_details(completion, |semantic| {
        projected[&semantic].clone()
    }))
}

/// Locate the source evidence of a semantic through the native row relations.
pub(super) fn selected_public_diagnostic_site(
    ready: &ReadySelectedResolution<'_, '_>,
    semantic: SemanticId,
) -> Result<Option<serde_json::Value>> {
    let (Some(ordinal), Some(key)) = (semantic.ordinal(), semantic.local_key()) else {
        return Ok(None);
    };
    let mount = ready
        .inventory
        .mount_record_by_ordinal(SelectedResolutionMountOrdinal::new(ordinal))?;
    let site = ready.inventory.connection().prepare_cached(
        "SELECT source_site AS site, 0 AS priority FROM resolution_semantic_sites WHERE blob_id=?1 AND semantic_key=?2
         UNION ALL SELECT site, 1 FROM resolution_gap_reasons WHERE blob_id=?1 AND reason=?2
         UNION ALL SELECT site, 2 FROM resolution_definition_property_gaps WHERE blob_id=?1 AND reason=?2
         ORDER BY priority, site LIMIT 1"
    )?.query_row(rusqlite::params![mount.blob_id(), key], |row| row.get::<_, i64>(0)).optional()?;
    match site {
        Some(site) => obligation_site_details(ready, ordinal, site),
        None => Ok(None),
    }
}

/// Resolve evidence for one query only. No identity lookup survives its answer.
pub(super) fn selected_public_diagnostic_identity(
    ready: &ReadySelectedResolution<'_, '_>,
    semantic: SemanticId,
    cancellation: &CancellationToken,
    _session: &ResolutionSession,
) -> Result<String> {
    use crate::analyzer::resolution::SharedNameInterner;
    // Only mounted declarations can project to source CodeUnits. Runtime
    // reason aliases have no source authority; do not ask the resolver to
    // invent one while rendering a diagnostic.
    let declaration = if let (Some(ordinal), Some(key)) = (semantic.ordinal(), semantic.local_key())
    {
        let ordinal = SelectedResolutionMountOrdinal::new(ordinal);
        let coordinate = (ordinal, ResolutionLocalKey::new(i64::from(key)));
        let mounts = SelectedMountTable::new(&ready.inventory);
        let mount = mounts.mount_by_ordinal(ordinal)?;
        // A reason operand can be an unregistered local obligation, rather
        // than a declaration. Read the source crosswalk without requiring
        // declaration authority from the resolver just to explain it.
        if let Some(mut rows) = read_fragment_definition_rows(ready, &[coordinate], cancellation)? {
            if mount.semantic_language() == Language::Rust {
                match rows.units.remove(&coordinate) {
                    Some(rows) => {
                        let mut units = rows
                            .iter()
                            .map(|row| RustMountUnits::new(ready, &mount)?.unit(row))
                            .collect::<Result<Vec<_>>>()?;
                        units.sort_unstable();
                        units.dedup();
                        (units.len() == 1).then(|| units.remove(0))
                    }
                    None => None,
                }
            } else {
                match project_fragment_definition(ready, coordinate, &mut rows)? {
                    Some(SelectedNativeDefinition::Unit(unit)) => Some(unit),
                    _ => None,
                }
            }
        } else {
            None
        }
    } else {
        None
    };
    if let Some(unit) = declaration.as_ref() {
        return Ok(public_diagnostic_identity(
            "semantic",
            Some(unit),
            None,
            None,
        ));
    }
    let digest = if let Some(name) = semantic.shared_name_id() {
        match ready.shared_names().digest_for_id(name) {
            Some(digest) => Some(digest),
            None if name.is_interned() => ready
                .inventory
                .connection()
                .query_row(
                    "SELECT identity_digest FROM main.resolution_identities WHERE id=?1",
                    [i64::from(name.get())],
                    |row| row.get::<_, [u8; 32]>(0),
                )
                .optional()?,
            None => None,
        }
    } else {
        None
    };
    let site = selected_public_diagnostic_site(ready, semantic)?;
    Ok(public_diagnostic_identity(
        "semantic",
        None,
        digest.as_ref(),
        site.as_ref(),
    ))
}

fn native_reference_reason_details(
    ready: &ReadySelectedResolution<'_, '_>,
    operation: &mut crate::analyzer::resolution::FactResolutionOperation<'_>,
    reference: SemanticId,
    completion: &ResolutionCompletion,
) -> Result<Vec<(&'static str, String)>> {
    let Some(ordinal) = reference.ordinal() else {
        return named_reason_details(ready, completion);
    };
    let mount = SelectedMountTable::new(&ready.inventory)
        .mount_by_ordinal(SelectedResolutionMountOrdinal::new(ordinal))?;
    if !matches!(
        mount.semantic_language(),
        Language::Java | Language::Kotlin | Language::Scala
    ) {
        return named_reason_details(ready, completion);
    }
    let ResolutionCompletion::Incomplete(reasons) = completion else {
        return Ok(Vec::new());
    };
    let site = obligation_site_details(
        ready,
        ordinal,
        i64::from(
            reference
                .local_key()
                .expect("a mounted reference has a local key"),
        ),
    )?;
    let mut details = Vec::new();
    for reason in reasons.iter() {
        let mut named = named_reason_details(ready, &ResolutionCompletion::incomplete([*reason]))?;
        if named.is_empty() {
            let (kind, semantic) = public_reason_details(reason);
            let cancellation = CancellationToken::new();
            let session = ResolutionSession::unbounded();
            let mut evidence = kind.to_owned();
            if let Some(semantic) = semantic {
                let identity =
                    selected_public_diagnostic_identity(ready, semantic, &cancellation, &session)?;
                if identity != "semantic" {
                    evidence = format!("{kind}: {identity}");
                }
                if let Some((operation_name, semantics)) =
                    operation.service_reason_details(semantic)
                {
                    let mut operands = Vec::with_capacity(semantics.len());
                    for anchor in semantics {
                        let source_site = match (anchor.ordinal(), anchor.local_key()) {
                            (Some(ordinal), Some(key)) => {
                                obligation_site_details(ready, ordinal, i64::from(key))?
                            }
                            _ => None,
                        };
                        let descriptor = operation.read_intrinsic_type_descriptors(&[anchor])?;
                        operands.push(serde_json::json!({
                            "identity": selected_public_diagnostic_identity(ready, anchor, &cancellation, &session)?,
                            "site": source_site,
                            "intrinsic_types": descriptor.map(|values| values.iter().map(|value| value.spelling().to_owned()).collect::<Vec<_>>()),
                        }));
                    }
                    evidence =
                        serde_json::json!({"operation": operation_name, "operands": operands})
                            .to_string();
                } else if let Some(descriptors) =
                    operation.read_intrinsic_type_descriptors(&[semantic])?
                    && !descriptors.is_empty()
                {
                    evidence = serde_json::json!({"identity": identity, "intrinsic_types": descriptors.iter().map(|value| value.spelling()).collect::<Vec<_>>()}).to_string();
                }
            }
            // The message below embeds this evidence as a string, so sorting
            // the outer message cannot reach its keys (#6112).
            named.push((kind, feature_invariant_reason_json(evidence)));
        }
        for (kind, evidence) in named {
            // Named provider reasons retain their complete evidence. The query
            // site also anchors context-owned obligations with no persisted site.
            let message = match serde_json::from_str::<serde_json::Value>(&evidence) {
                Ok(value) if value.get("site").is_some() => evidence,
                // The outer sort cannot reach JSON nested as a string, so sort
                // it before nesting (#6112).
                _ => serde_json::json!({
                    "kind": kind,
                    "site": site,
                    "semantic": feature_invariant_reason_json(evidence),
                })
                .to_string(),
            };
            details.push((kind, feature_invariant_reason_json(message)));
        }
    }
    details.sort_unstable();
    // Do not deduplicate: each retained obligation must remain represented.
    Ok(details)
}

#[doc(hidden)]
pub fn project_native_definition_units(
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
    match project_source_definition_coordinates(
        ready,
        &source_definitions,
        &coordinates,
        cancellation,
        session,
    )? {
        SelectedNativeDefinitions::Ready(source) => {
            projected.extend(source);
            Ok(SelectedNativeDefinitions::Ready(projected))
        }
        stopped => Ok(stopped),
    }
}

/// The reverse candidate reader constructed these IDs from complete selected
/// rows, so their mount/local-key coordinates already have source authority.
/// Do not rediscover that provenance once per candidate.
pub(super) fn project_hydrated_source_definition_units(
    ready: &ReadySelectedResolution<'_, '_>,
    definitions: &[SemanticId],
    cancellation: &CancellationToken,
    session: &ResolutionSession,
) -> Result<SelectedNativeDefinitions> {
    let coordinates = definitions
        .iter()
        .map(|definition| {
            (
                SelectedResolutionMountOrdinal::new(
                    definition
                        .ordinal()
                        .expect("hydrated source definition has a mount"),
                ),
                ResolutionLocalKey::new(i64::from(
                    definition
                        .local_key()
                        .expect("hydrated source definition has a local key"),
                )),
            )
        })
        .collect::<Vec<_>>();
    let mounts = coordinates
        .iter()
        .map(|(mount, _)| *mount)
        .collect::<Vec<_>>();
    ready
        .inventory
        .requested_mount_rows()
        .prefetch_ordinals(ready.inventory.connection(), &mounts)?;
    project_source_definition_coordinates(ready, definitions, &coordinates, cancellation, session)
}

fn project_source_definition_coordinates(
    ready: &ReadySelectedResolution<'_, '_>,
    source_definitions: &[SemanticId],
    coordinates: &[(SelectedResolutionMountOrdinal, ResolutionLocalKey)],
    cancellation: &CancellationToken,
    session: &ResolutionSession,
) -> Result<SelectedNativeDefinitions> {
    let mut projected = Vec::with_capacity(source_definitions.len());
    let Some(mut rows) = read_fragment_definition_rows(ready, coordinates, cancellation)? else {
        return Ok(SelectedNativeDefinitions::Cancelled);
    };
    for (&definition, coordinate) in source_definitions.iter().zip(coordinates.iter().copied()) {
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
    if !crate::analyzer::resolution::resolution_diagnostics().recording() {
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
        .filter(|identity| {
            ready.context_identities.external_owner_language(*identity)
                != Some(crate::analyzer::resolution::ExternalOwnerLanguage::Go)
                && !answer.model_member_selection().is_some_and(|selection| {
                    selection
                        .candidates
                        .iter()
                        .any(|member| member.target == *identity)
                })
        })
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
    if !crate::analyzer::resolution::resolution_diagnostics().recording() {
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
#[doc(hidden)]
#[cfg_attr(any(test, feature = "test-support"), derive(Debug))]
pub struct ProjectedNativeTraceProvenance {
    #[doc(hidden)]
    pub rows: Vec<crate::analyzer::resolution::trace_vocabulary::TraceCandidate>,
    #[doc(hidden)]
    pub rejection_coverage: bool,
    pub(crate) visibility_units: Vec<(SemanticId, CodeUnit)>,
}

fn project_native_trace_provenance(
    ready: &ReadySelectedResolution<'_, '_>,
    answer: &FactResolutionAnswer,
    call_applicability_reason: Option<SemanticId>,
    definitions: &SelectedNativeDefinitions,
    callable_candidates: &[(SemanticId, CodeUnit)],
    member_contexts: &[ProjectedNativeMemberContext],
    cancellation: &CancellationToken,
) -> Result<ProjectedNativeTraceProvenance> {
    use crate::analyzer::resolution::trace_vocabulary::TraceCandidate;
    use crate::analyzer::resolution::trace_vocabulary::TraceCandidateRef;
    use crate::analyzer::structural::{CandidateOutcome, PrecedenceTier};
    if !crate::analyzer::resolution::resolution_diagnostics().native_rejection_projection_active() {
        return Ok(ProjectedNativeTraceProvenance::default());
    }
    use brokk_bifrost_core::analyzer::structural::callable::ApplicabilityVerdict;
    let binding = answer.binding();
    // An inapplicable or less specific candidate is refused by the call, not
    // by its lookup; both keep their row as a callable rejection.
    let refused_by_call = |verdict: ApplicabilityVerdict| {
        matches!(
            verdict,
            ApplicabilityVerdict::Inapplicable | ApplicabilityVerdict::LessSpecific
        )
    };
    let outcome_of = |witness: &crate::analyzer::resolution::ResolutionWitness| {
        let recorded = witness.candidate_outcome();
        match recorded {
            Some(CandidateOutcome::Rejected(_)) => recorded,
            _ if binding.targets().contains(&witness.target()) => Some(CandidateOutcome::Selected),
            _ if answer
                .callable_candidate_applicability()
                .iter()
                .any(|candidate| {
                    candidate.target() == witness.target() && refused_by_call(candidate.verdict())
                }) =>
            {
                Some(CandidateOutcome::Rejected(
                    crate::analyzer::structural::RejectionReason::CallableApplicabilityDeferred,
                ))
            }
            _ => None,
        }
    };

    // The call's own applicability obligation stays open while the verdicts
    // do not prove one unique winner (an ambiguity, an undecided candidate).
    // That is a fact about the selection, which the rows report; it is not a
    // candidate the lookup failed to enumerate.
    let enumerated_completion = call_applicability_reason.map_or_else(
        || binding.completion().clone(),
        |reason| {
            crate::analyzer::resolution::completion_without_unsupported_semantic(
                binding.completion(),
                reason,
            )
        },
    );
    let mut covered =
        !binding.witnesses().is_empty() && enumerated_completion == ResolutionCompletion::Complete;
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
    //
    // A later phase may have erased the whole lookup group that supplied a
    // loser, so its callable verdict alone cannot prove route coverage. The
    // applicability filters drop a refused candidate's witness, so its route
    // was read when the check received it; the group survived when every
    // selected target was classified by that same check.
    let selection_classified = binding.targets().iter().all(|target| {
        answer
            .callable_candidate_applicability()
            .iter()
            .any(|candidate| candidate.target() == *target)
    });
    covered &= answer
        .callable_candidate_applicability()
        .iter()
        .all(|candidate| {
            if binding.targets().contains(&candidate.target()) {
                return true;
            }
            let witnessed = binding.witnesses().iter().any(|witness| {
                witness.target() == candidate.target() && witness.native_provenance().is_some()
            });
            if !witnessed && !(candidate.traced_route() && selection_classified) {
                return false;
            }
            let Some((_, unit)) = callable_candidates
                .iter()
                .find(|(target, _)| *target == candidate.target())
            else {
                return false;
            };
            refused_by_call(candidate.verdict())
                || rows.iter().any(|row| {
                    !row.is_selected()
                        && matches!(&row.candidate, TraceCandidateRef::Unit(found) if found == unit)
                })
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
) -> Result<Option<crate::analyzer::resolution::trace_vocabulary::TraceCandidateRef>> {
    use crate::analyzer::resolution::trace_vocabulary::{TraceCandidateRef, WILDCARD_ROUTE_NAME};
    let lexical = ready.lexical_source();
    let Some(SelectedSemanticProvenance::FragmentLocal(provenance)) =
        lexical.semantic_provenance(token, cancellation)?
    else {
        return Ok(None);
    };
    let ordinal = provenance.mount().ordinal();
    let record = ready.inventory.mount_record_by_ordinal(ordinal)?;
    let Some(import) =
        super::imports::selected_import_route(&ready.inventory, record.blob_id(), ordinal, token)?
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
        import.kind,
        SelectedImportRouteKind::TypeOnDemand
            | SelectedImportRouteKind::StaticOnDemand
            | SelectedImportRouteKind::Star
    );
    let name = if wildcard {
        WILDCARD_ROUTE_NAME.to_owned()
    } else {
        let selector = super::imports::selected_import_selector(
            ready.inventory.connection(),
            record.blob_id(),
            token,
        )?;
        // JVM named selectors may rename the source member. Without their
        // structured selector row the bound demand is not its target name.
        if import.kind == SelectedImportRouteKind::Named && selector.is_none() {
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

impl SelectedResolutionOperation<'_, '_> {
    /// Map only the identities returned by the current hierarchy request.
    pub fn selected_hierarchy_definition_units(
        &self,
        definitions: &[SemanticId],
        cancellation: &CancellationToken,
        session: &ResolutionSession,
    ) -> Result<SelectedNativeDefinitions> {
        native_units::project_native_definition_units(
            &self.ready,
            definitions,
            cancellation,
            session,
        )
    }
}

impl SelectedResolutionOperation<'_, '_> {
    /// Locate a source unit through the selected definition crosswalk. A unit's
    /// declaration extent is not its identifier span, so it is not a locator.
    pub fn selected_hierarchy_definition(
        &self,
        target: &CodeUnit,
        cancellation: &CancellationToken,
        session: &ResolutionSession,
    ) -> Result<LocatedSemantic> {
        let language = brokk_bifrost_core::analyzer::common::language_for_file(target.source());
        let path = crate::path_utils::rel_path_string(target.source());
        let Some(mount) = self
            .mount_table()
            .mount_for_path(language.config_label(), &path)?
        else {
            return Ok(LocatedSemantic::Missing);
        };
        let super::super::selected_definition::SelectedDefinitionSemanticReadOutcome::Ready(rows) =
            self.ready
                .inventory
                .hierarchy_definition_semantics_for_mount(mount.ordinal(), cancellation)?
        else {
            return Ok(LocatedSemantic::Cancelled);
        };
        let mut definitions = rows
            .iter()
            .map(|(key, _)| {
                let key = u32::try_from(key.get()).map_err(|_| {
                    StoreError::new(format!("selected definition key does not fit u32: {key:?}"))
                })?;
                Ok(SemanticId::local(mount.ordinal().get(), key))
            })
            .collect::<Result<Vec<_>>>()?;
        definitions.sort_unstable();
        definitions.dedup();
        match self.selected_hierarchy_definition_units(&definitions, cancellation, session)? {
            SelectedNativeDefinitions::Ready(units) => {
                let found = units
                    .iter()
                    .filter_map(|(id, definition)| match definition {
                        SelectedNativeDefinition::Unit(unit) if unit == target => Some(*id),
                        _ => None,
                    })
                    .collect::<Vec<_>>();
                match found.as_slice() {
                    [] => Err(StoreError::new(format!(
                        "selected JVM definition crosswalk does not contain {target:?}: {units:?}"
                    ))),
                    [definition] => Ok(LocatedSemantic::Found(*definition)),
                    _ => Err(StoreError::new(format!(
                        "selected JVM unit has several definition identities: {target:?}, {found:?}"
                    ))),
                }
            }
            SelectedNativeDefinitions::Cancelled => Ok(LocatedSemantic::Cancelled),
            SelectedNativeDefinitions::Unavailable => Ok(LocatedSemantic::Missing),
        }
    }
}
