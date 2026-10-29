//! The execution adapter between the query engine and the flow-sensitive
//! state derivation layer (#1480, Milestone 3).
//!
//! Rows follow the reference-edge precedent ([`super::edges`]): plain pipeline
//! values derived on demand and memoised per request, never carried in the
//! semantic artifact. One requested file or procedure scope is derived once
//! per query, and its per-axis completeness becomes typed diagnostics before
//! any filter runs -- so a `:class read` filter that drops every row still
//! leaves the reason the row set is partial on the response.
//!
//! There is no capability table here on purpose: a static gate cannot describe
//! per-procedure lowering completeness. The per-procedure lowering result is
//! the honest source, and it is what [`FlowStateCompleteness`] reports (#1480).

use super::super::flow_state::{
    FLOW_STATE_AXES, FileFlowState, FlowRelationRow, FlowStateAxis, FlowStateCompleteness,
    FlowStateDerivation, FlowStateIncompleteReason, FlowStateRequest, StateEventRow,
    flow_state_for_file_with_snapshot, flow_state_for_materialized_artifact,
    flow_state_for_materialized_procedure, flow_state_for_selected_property,
};
use super::results::{
    CodeQueryBindingInitializerCall, CodeQueryDiagnostic, CodeQueryDiagnosticCode,
    CodeQueryDiagnosticImpact, CodeQueryFlowRelation, CodeQueryRange, CodeQueryStateEvent,
    CodeQueryStateEventRef,
};
use super::{DerivationExecutionCause, rel_path_string};
#[cfg(test)]
use crate::analyzer::semantic::SemanticGapKind;
use crate::analyzer::semantic::{
    LengthDelimitedDigest, ProcedureHandle, ProcedureId, ProgramPointId, SemanticArtifact,
    SemanticCapability, SemanticOutcome,
};
use crate::analyzer::semantic_model::ActiveSemanticModelSnapshot;
use crate::analyzer::{IAnalyzer, Language, ProjectFile, WorkspaceAnalyzer};
use crate::cancellation::CancellationToken;
use crate::hash::HashMap;
use brokk_bifrost_rql::{FlowRelationFilter, StateEventFilter};
use std::sync::Arc;

/// Domain separators for the two row families' stable ids.
const STATE_EVENT_ID_DOMAIN: &[u8] = b"bifrost.code_query.state_event.v1";
const FLOW_RELATION_ID_DOMAIN: &[u8] = b"bifrost.code_query.flow_relation.v1";

/// Per-request value memo of derived flow state. Every invocation reports its
/// own completeness evidence; policy normalization deduplicates diagnostics.
pub(super) struct FlowStateTraversalCache {
    /// One immutable activation snapshot for every file this request derives.
    active_semantic_model_snapshot: Option<Arc<ActiveSemanticModelSnapshot>>,
    /// The same snapshot identity carried into every memo key. `None` remains
    /// distinct from the hash of an activated but empty model set.
    active_model_set_hash: Option<Arc<str>>,
    files: HashMap<FlowStateCacheKey, CachedFileFlowState>,
}

struct CachedFileFlowState {
    /// Retain the exact artifact allocation whose handles the derivation
    /// accepts. `None` marks the standalone acquisition path, which cannot
    /// prove identity with a separately materialized query artifact.
    artifact: Option<Arc<SemanticArtifact>>,
    state: Arc<FileFlowState>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct FlowStateCacheKey {
    file: ProjectFile,
    active_model_set_hash: Option<Arc<str>>,
    scope: FlowStateCacheScope,
    outcome: FlowStateOutcomeIdentity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum FlowStateCacheScope {
    File,
    Procedure(ProcedureId),
}

/// The parts of a semantic outcome that shape flow-state completeness.
///
/// Work counters do not change derived rows. Unsupported capability does
/// appear in the typed reason, so it remains part of the identity alongside
/// the outcome discriminant and exact artifact allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum FlowStateOutcomeIdentity {
    Standalone,
    Complete,
    Ambiguous,
    Unknown,
    Unsupported(SemanticCapability),
    Unproven,
    ExceededBudget,
    Cancelled,
}

impl FlowStateOutcomeIdentity {
    fn for_outcome<T>(outcome: &SemanticOutcome<T>) -> Self {
        match outcome {
            SemanticOutcome::Complete { .. } => Self::Complete,
            SemanticOutcome::Ambiguous { .. } => Self::Ambiguous,
            SemanticOutcome::Unknown { .. } => Self::Unknown,
            SemanticOutcome::Unsupported { capability, .. } => Self::Unsupported(*capability),
            SemanticOutcome::Unproven { .. } => Self::Unproven,
            SemanticOutcome::ExceededBudget { .. } => Self::ExceededBudget,
            SemanticOutcome::Cancelled { .. } => Self::Cancelled,
        }
    }
}

impl Default for FlowStateTraversalCache {
    fn default() -> Self {
        Self::new(None)
    }
}

/// Record the semantic artifact one flow-state derivation was taken from.
///
/// The cache's own key carries a `ProjectFile`, which knows its workspace root,
/// so it can never be the recorded identity. The artifact's public fingerprint
/// can: it names the exact path, content, adapter, IR version, configuration
/// and dependency identity the state was derived under, and nothing about
/// where the checkout lives.
fn record_flow_artifact_read(
    workspace: &WorkspaceAnalyzer,
    artifact: Option<&brokk_bifrost_analysis::analyzer::semantic::SemanticArtifact>,
) {
    let analyzer = workspace.analyzer();
    if !brokk_bifrost_analysis::analyzer::read_attribution_records_reads(|| {
        analyzer.read_ledger_attached()
    }) {
        return;
    }
    let Some(artifact) = artifact else {
        return;
    };
    analyzer.record_read(crate::analyzer::ReadKey::semantic_artifact(artifact.key()));
}

impl FlowStateTraversalCache {
    /// Start one request cache from the activation snapshot its other semantic
    /// row families use.
    pub(super) fn new(
        active_semantic_model_snapshot: Option<Arc<ActiveSemanticModelSnapshot>>,
    ) -> Self {
        let active_model_set_hash = active_semantic_model_snapshot
            .as_ref()
            .map(|snapshot| Arc::<str>::from(snapshot.active_models().active_model_set_hash()));
        Self {
            active_semantic_model_snapshot,
            active_model_set_hash,
            files: HashMap::default(),
        }
    }

    /// Release derived rows for a completed artifact-independent file window.
    pub(super) fn release_file_window(&mut self) {
        self.files.clear();
    }

    /// Derive (or replay) the flow state of one file.
    ///
    /// No read key is formed here: the semantic artifact this state is derived
    /// from records its own `Artifact` key at the materialization funnel, which
    /// runs below this call. The two materialized entry points below *do* form
    /// one, because the caller already owns the artifact and this cache can
    /// answer from a retained state without crossing that funnel again.
    pub(super) fn for_file(
        &mut self,
        workspace: &WorkspaceAnalyzer,
        file: &ProjectFile,
        cancellation: Option<&CancellationToken>,
    ) -> Arc<FileFlowState> {
        let key = FlowStateCacheKey {
            file: file.clone(),
            active_model_set_hash: self.active_model_set_hash.clone(),
            scope: FlowStateCacheScope::File,
            outcome: FlowStateOutcomeIdentity::Standalone,
        };
        if let Some(cached) = self.files.get(&key) {
            return Arc::clone(&cached.state);
        }
        let derived = Arc::new(flow_state_for_file_with_snapshot(
            workspace,
            file,
            cancellation,
            self.active_semantic_model_snapshot.clone(),
        ));
        self.files.insert(
            key,
            CachedFileFlowState {
                artifact: None,
                state: Arc::clone(&derived),
            },
        );
        derived
    }

    /// Derive (or replay) flow state from the exact semantic artifact outcome
    /// whose handles the caller will join against.
    pub(super) fn for_materialized_file(
        &mut self,
        workspace: &WorkspaceAnalyzer,
        file: &ProjectFile,
        outcome: SemanticOutcome<Arc<SemanticArtifact>>,
        cancellation: Option<&CancellationToken>,
    ) -> Arc<FileFlowState> {
        let artifact = outcome.available_value().cloned();
        record_flow_artifact_read(workspace, artifact.as_deref());
        self.cached_materialized_scope(
            workspace.analyzer(),
            file,
            outcome,
            artifact,
            FlowStateCacheScope::File,
            cancellation,
            |outcome, request| {
                flow_state_for_materialized_artifact(workspace, file, outcome, request)
            },
        )
    }

    /// Derive (or replay) flow state for one exact procedure from the semantic
    /// artifact allocation that minted its handle.
    pub(super) fn for_materialized_procedure(
        &mut self,
        workspace: &WorkspaceAnalyzer,
        file: &ProjectFile,
        outcome: SemanticOutcome<Arc<SemanticArtifact>>,
        procedure: &ProcedureHandle,
        cancellation: Option<&CancellationToken>,
    ) -> Arc<FileFlowState> {
        let artifact = outcome.available_value().cloned();
        record_flow_artifact_read(workspace, artifact.as_deref());
        if let Some(artifact) = artifact.as_ref() {
            assert!(
                Arc::ptr_eq(artifact, procedure.artifact()),
                "procedure-scoped flow cache requires a handle from the supplied artifact allocation"
            );
        }
        self.cached_materialized_scope(
            workspace.analyzer(),
            file,
            outcome,
            artifact,
            FlowStateCacheScope::Procedure(procedure.id()),
            cancellation,
            |outcome, request| {
                flow_state_for_materialized_procedure(workspace, file, outcome, procedure, request)
            },
        )
    }

    /// Derive property-reaching rows for one exact point from its retained
    /// procedure artifact and this request's frozen semantic-model snapshot.
    pub(super) fn for_selected_property(
        &mut self,
        workspace: &WorkspaceAnalyzer,
        file: &ProjectFile,
        outcome: SemanticOutcome<Arc<SemanticArtifact>>,
        procedure: &ProcedureHandle,
        point: ProgramPointId,
        cancellation: Option<&CancellationToken>,
    ) -> Arc<FileFlowState> {
        let state =
            self.for_materialized_procedure(workspace, file, outcome, procedure, cancellation);
        let token = cancellation.cloned().unwrap_or_default();
        let mut request = FlowStateRequest::new(&token)
            .with_active_semantic_model_snapshot(self.active_semantic_model_snapshot.clone());
        Arc::new(flow_state_for_selected_property(
            workspace,
            file,
            &state,
            procedure,
            point,
            &mut request,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    fn cached_materialized_scope<F>(
        &mut self,
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
        outcome: SemanticOutcome<Arc<SemanticArtifact>>,
        artifact: Option<Arc<SemanticArtifact>>,
        scope: FlowStateCacheScope,
        cancellation: Option<&CancellationToken>,
        derive: F,
    ) -> Arc<FileFlowState>
    where
        F: FnOnce(
            SemanticOutcome<Arc<SemanticArtifact>>,
            &mut FlowStateRequest<'_>,
        ) -> FileFlowState,
    {
        let key = FlowStateCacheKey {
            file: file.clone(),
            active_model_set_hash: self.active_model_set_hash.clone(),
            scope,
            outcome: FlowStateOutcomeIdentity::for_outcome(&outcome),
        };
        if let (Some(wanted), Some(cached)) = (artifact.as_ref(), self.files.get(&key))
            && cached
                .artifact
                .as_ref()
                .is_some_and(|retained| Arc::ptr_eq(retained, wanted))
        {
            return Arc::clone(&cached.state);
        }
        let token = cancellation.cloned().unwrap_or_default();
        let mut request = FlowStateRequest::new(&token)
            .with_active_semantic_model_snapshot(self.active_semantic_model_snapshot.clone());
        let derived = Arc::new(derive(outcome, &mut request));
        if request.refusal_count() > 0 {
            brokk_bifrost_core::profiling::note_with(|| {
                format!(
                    "policy.units unbounded origin={}:{} cause=budget:cfg",
                    file!(),
                    line!()
                )
            });
            analyzer.mark_execution_dependent();
        }
        self.files.insert(
            key,
            CachedFileFlowState {
                artifact,
                state: Arc::clone(&derived),
            },
        );
        derived
    }

    /// Turn one derivation's completeness into typed diagnostics.
    ///
    /// Every [`FlowStateIncompleteReason`] that blocks an axis of `axes`
    /// surfaces: budget exhaustion and a file that does not lower are
    /// `Incomplete`, never an empty complete answer. `subject` is the thing the
    /// derivation was about (a workspace-relative path, or a procedure's wire
    /// id).
    ///
    /// `axes` is the set of axes the *caller's* row family publishes, and a
    /// reason blocking none of them is not reported. Without it, a
    /// `state-events-of` query over any procedure that contains a call would be
    /// reported incomplete because the lowering cannot model the call's
    /// same-evaluation dependence -- an axis that query does not publish, and
    /// whose hole the event rows already declare covered in their own
    /// `completeness` field. Reporting it made every relational policy over
    /// state events inconclusive on every language with calls (#2443).
    #[allow(clippy::too_many_arguments)]
    pub(super) fn report_completeness(
        &mut self,
        analyzer: &dyn IAnalyzer,
        subject: &str,
        procedure: Option<&super::semantic::SemanticProcedureValue>,
        language: Language,
        completeness: &FlowStateCompleteness,
        axes: &[FlowStateAxis],
        generation: u64,
        diagnostics: &mut Vec<CodeQueryDiagnostic>,
    ) {
        for reason in completeness.reasons() {
            if !axes.iter().any(|axis| reason.blocks(*axis)) {
                continue;
            }
            let (code, detail, cause) = classify_reason(reason);
            let source = procedure.and_then(|procedure| procedure.diagnostic_source());
            let related = procedure
                .map(|procedure| {
                    procedure.related_flow_reasons(
                        &completeness
                            .reasons()
                            .iter()
                            .filter(|other| {
                                axes.iter().any(|axis| other.blocks(*axis))
                                    && classify_reason(other).1 == detail
                            })
                            .cloned()
                            .collect::<Vec<_>>(),
                    )
                })
                .unwrap_or_default();
            let uncovered = FLOW_STATE_AXES
                .iter()
                .filter(|axis| !completeness.covers(**axis))
                .map(|axis| axis.label())
                .collect::<Vec<_>>();
            diagnostics.push(super::QueryExecutionState::diagnostic(analyzer, CodeQueryDiagnostic {
                related,
                source,
                code,
                impact: CodeQueryDiagnosticImpact::Incomplete,
                branch: Vec::new(),
                language: language.config_label(),
                message: format!(
                    "{subject} has an incomplete flow-state derivation in generation {generation} ({detail}); uncovered axes: [{}]",
                    uncovered.join(", ")
                ),
            exhausted_roots: Vec::new(),
                withheld_rows_path: None,
            }, cause));
        }
    }
}

/// The axes a `state_event` row family publishes. A hole in a relation axis
/// leaves the event rows themselves exactly as complete as they were.
pub(super) const STATE_EVENT_AXES: &[FlowStateAxis] =
    &[FlowStateAxis::BindingEvents, FlowStateAxis::PropertyEvents];

/// The axes a `flow_relation` row family publishes.
pub(super) const FLOW_RELATION_AXES: &[FlowStateAxis] = &[
    FlowStateAxis::ReachingRelation,
    FlowStateAxis::DominanceRelation,
    FlowStateAxis::PropertyReachingRelation,
    FlowStateAxis::PropertyDominanceRelation,
    FlowStateAxis::SameEvaluationRelation,
];

/// The diagnostic code and human reason of one incompleteness.
///
/// Total on purpose: a reason added to the derivation layer must be classified
/// here deliberately rather than defaulting into a generic message.
fn classify_reason(
    reason: &FlowStateIncompleteReason,
) -> (
    CodeQueryDiagnosticCode,
    &'static str,
    Option<DerivationExecutionCause>,
) {
    use FlowStateIncompleteReason::*;
    match reason {
        AxisUnsupported(_) => (
            CodeQueryDiagnosticCode::FlowStateAxisUnsupported,
            "the lowering declares an axis this derivation stands on unsupported",
            None,
        ),
        NoSemanticProvider => (
            CodeQueryDiagnosticCode::FlowStateAxisUnsupported,
            "no semantic provider is registered for the file's language",
            None,
        ),
        SemanticProviderFailed { .. } => (
            CodeQueryDiagnosticCode::FlowStateDerivationIncomplete,
            "the semantic provider returned a typed error",
            Some(DerivationExecutionCause::Provider),
        ),
        SemanticAnalysisPartial { .. } => (
            CodeQueryDiagnosticCode::FlowStateDerivationIncomplete,
            "the semantic lowering itself is partial",
            None,
        ),
        Cancelled => (
            CodeQueryDiagnosticCode::FlowStateDerivationIncomplete,
            "the derivation was cancelled",
            Some(DerivationExecutionCause::Cancelled),
        ),
        SourceGenerationChanged => (
            CodeQueryDiagnosticCode::FlowStateDerivationIncomplete,
            "the analyzed content changed under the derivation",
            Some(DerivationExecutionCause::Snapshot),
        ),
        NoStructuralFacts => (
            CodeQueryDiagnosticCode::FlowStateDerivationIncomplete,
            "the language has no structural facts arena to join events onto",
            None,
        ),
        LoweringGap {
            kind: crate::analyzer::semantic::SemanticGapKind::ExceededBudget,
            ..
        } => (
            CodeQueryDiagnosticCode::FlowStateAxisUnsupported,
            "the lowering published an explicit capability gap",
            Some(DerivationExecutionCause::Budget),
        ),
        LoweringGap { .. } => (
            CodeQueryDiagnosticCode::FlowStateAxisUnsupported,
            "the lowering published an explicit capability gap",
            None,
        ),
        BudgetExhausted { .. } => (
            CodeQueryDiagnosticCode::FlowStateDerivationIncomplete,
            "a control-flow algorithm exhausted its budget, so its relation emitted no rows",
            Some(DerivationExecutionCause::Budget),
        ),
        SelectedPropertyEndpointUnavailable { .. } => (
            CodeQueryDiagnosticCode::FlowStateDerivationIncomplete,
            "a selected semantic property endpoint has no public event projection",
            None,
        ),
        PropertyBaseNotCanonical { .. } => (
            CodeQueryDiagnosticCode::FlowStateDerivationIncomplete,
            "a field access has no binding-rooted base, so it contributes no property subject",
            None,
        ),
        BindingWithoutEstablishment { .. } => (
            CodeQueryDiagnosticCode::FlowStateDerivationIncomplete,
            "the lowering declares a local binding it never establishes",
            None,
        ),
        BindingScopeLivenessUnavailable { .. } => (
            CodeQueryDiagnosticCode::FlowStateDerivationIncomplete,
            "Rust lexical-scope future-frame liveness could not be derived completely",
            None,
        ),
        BindingStateNotClosed { .. } => (
            CodeQueryDiagnosticCode::FlowStateDerivationIncomplete,
            "aliasing, capture, or ownership transfer leaves the binding's read/write state open",
            None,
        ),
        PropertyProviderUnavailable => (
            CodeQueryDiagnosticCode::FlowStateDerivationIncomplete,
            "the structured property-reaching provider was unavailable",
            Some(DerivationExecutionCause::Provider),
        ),
        PropertyProviderFailed { .. } => (
            CodeQueryDiagnosticCode::FlowStateDerivationIncomplete,
            "the structured property-reaching provider returned a typed error",
            Some(DerivationExecutionCause::Provider),
        ),
        PropertyAnalysisPartial { .. } => (
            CodeQueryDiagnosticCode::FlowStateDerivationIncomplete,
            "the structured property-reaching snapshot was unavailable from a partial outcome",
            None,
        ),
        PropertyReaching { reason } => (
            CodeQueryDiagnosticCode::FlowStateDerivationIncomplete,
            "structured property-reaching evidence was incomplete",
            property_execution_cause(reason),
        ),
        ControlProjectionRejected { .. } => (
            CodeQueryDiagnosticCode::FlowStateDerivationIncomplete,
            "the request-local control projection did not match the semantic artifact",
            None,
        ),
        ModeledControlProjectionIncomplete { .. } => (
            CodeQueryDiagnosticCode::FlowStateDerivationIncomplete,
            "an applicable modeled control projection could not be proved exactly",
            None,
        ),
    }
}

fn property_execution_cause(
    reason: &crate::analyzer::semantic::PropertyReachingIncompleteReason,
) -> Option<DerivationExecutionCause> {
    use crate::analyzer::semantic::PropertyReachingIncompleteReason::*;
    use crate::analyzer::semantic::cfg_algorithms::CfgAlgorithmError;
    match reason {
        Cancelled => Some(DerivationExecutionCause::Cancelled),
        InputRelationBudgetExceeded { .. } | ReachingPairBudgetExceeded { .. } => {
            Some(DerivationExecutionCause::Budget)
        }
        CandidateCoverage(crate::analyzer::semantic::CandidateCoverage::Truncated) => {
            Some(DerivationExecutionCause::Budget)
        }
        SelectedSemanticGap { gap }
            if gap.kind == crate::analyzer::semantic::SemanticGapKind::ExceededBudget =>
        {
            Some(DerivationExecutionCause::Budget)
        }
        Reachability(error)
        | ReachingDefinitions(error)
        | Dominators(error)
        | ReachingPairs(error) => match error {
            CfgAlgorithmError::Cancelled { .. } => Some(DerivationExecutionCause::Cancelled),
            CfgAlgorithmError::ExceededBudget(_) => Some(DerivationExecutionCause::Budget),
            CfgAlgorithmError::InvalidNode(_) => None,
        },
        SelectedReadMissing { .. }
        | SelectedReadAmbiguous { .. }
        | SelectedRelationEndpointUnavailable { .. }
        | SelectedRuntimeAccess { .. }
        | SelectedAncestorStore { .. }
        | SelectedAliasClosureUnavailable { .. }
        | SelectedSemanticGap { .. }
        | CandidateCoverage(_)
        | UnsupportedLocation { .. }
        | DurableIdentityUnavailable { .. }
        | SourceMappingUnavailable { .. }
        | StoreEvidenceIncomplete { .. }
        | ReadEvidenceIncomplete { .. }
        | FieldMemoryEndpointUnavailable { .. }
        | EvaluationEndpointUnavailable { .. }
        | EvaluationEvidenceIncomplete { .. }
        | EvaluationSourceUnknown => None,
    }
}

/// One state-event row travelling through the pipeline.
///
/// The whole file derivation is held by `Arc` rather than the single row,
/// because `flow-relations-of` seeded from an event needs its siblings and its
/// procedure's relations without deriving anything twice.
#[derive(Debug, Clone)]
pub(super) struct StateEventValue {
    pub(super) file_state: Arc<FileFlowState>,
    pub(super) procedure_index: usize,
    pub(super) event: usize,
    pub(super) file: ProjectFile,
    /// The wire identity of the seed procedure, carried from the semantic
    /// handle that produced it so two row families agree on one spelling.
    pub(super) procedure_id: Arc<str>,
    /// Exact request-retained semantic procedure used to relate the event's
    /// establishment value to call results in its initializer.
    pub(super) procedure: ProcedureHandle,
    pub(super) diagnostic_procedure: super::semantic::SemanticProcedureValue,
    /// A scoped relation endpoint still belongs to the original aggregate
    /// derivation. Its origin tells a subsequent aggregate expansion to emit
    /// that scope's coverage before filtering.
    pub(super) selected_property_origin: Option<ProgramPointId>,
}

impl StateEventValue {
    pub(super) fn derivation(&self) -> &FlowStateDerivation {
        &self.file_state.procedures[self.procedure_index]
    }

    pub(super) fn row(&self) -> &StateEventRow {
        self.derivation().event(self.event)
    }

    pub(super) fn file(&self) -> &ProjectFile {
        &self.file
    }

    pub(super) fn key(&self) -> StateEventKey {
        StateEventKey {
            file: self.file.clone(),
            procedure: self.procedure_id.to_string(),
            event: self.event,
            selected_property_origin: self.selected_property_origin,
        }
    }

    pub(super) fn id(&self) -> String {
        state_event_id(&self.procedure_id, self.row())
    }
}

/// Evidence for one selected read. It retains only its relation rows and
/// coverage; endpoints remain in the shared aggregate derivation.
#[derive(Debug)]
pub(super) struct SelectedPropertyRelations {
    pub(super) point: ProgramPointId,
    pub(super) relations: Box<[FlowRelationRow]>,
    pub(super) completeness: FlowStateCompleteness,
}

/// One flow-relation row travelling through the pipeline.
#[derive(Debug, Clone)]
pub(super) struct FlowRelationValue {
    pub(super) file_state: Arc<FileFlowState>,
    pub(super) procedure_index: usize,
    pub(super) relation: usize,
    pub(super) file: ProjectFile,
    pub(super) procedure_id: Arc<str>,
    pub(super) procedure: ProcedureHandle,
    pub(super) diagnostic_procedure: super::semantic::SemanticProcedureValue,
    pub(super) selected_property: Option<Arc<SelectedPropertyRelations>>,
}

impl FlowRelationValue {
    pub(super) fn derivation(&self) -> &FlowStateDerivation {
        &self.file_state.procedures[self.procedure_index]
    }

    pub(super) fn row(&self) -> &FlowRelationRow {
        match &self.selected_property {
            Some(proof) => &proof.relations[self.relation],
            None => &self.derivation().relations[self.relation],
        }
    }

    fn completeness(&self) -> &FlowStateCompleteness {
        match &self.selected_property {
            Some(proof) => &proof.completeness,
            None => &self.derivation().completeness,
        }
    }

    pub(super) fn source(&self) -> &StateEventRow {
        self.derivation().event(self.row().source_event)
    }

    pub(super) fn target(&self) -> &StateEventRow {
        self.derivation().event(self.row().target_event)
    }

    /// The relation's own source anchor is its target read: that is the
    /// position an author is asking about when they ask what serves a read.
    pub(super) fn file(&self) -> &ProjectFile {
        &self.file
    }

    pub(super) fn key(&self) -> FlowRelationKey {
        FlowRelationKey {
            file: self.file.clone(),
            procedure: self.procedure_id.to_string(),
            relation: self.relation,
            selected_property_origin: self.selected_property.as_ref().map(|proof| proof.point),
            selected_relation: self.selected_property.as_ref().map(|_| self.id()),
        }
    }

    pub(super) fn id(&self) -> String {
        let mut digest = LengthDelimitedDigest::new(FLOW_RELATION_ID_DOMAIN);
        digest.push(self.procedure_id.as_bytes());
        digest.push(self.row().relation.label().as_bytes());
        digest.push(self.row().certainty.label().as_bytes());
        digest.push(state_event_id(&self.procedure_id, self.source()).as_bytes());
        digest.push(state_event_id(&self.procedure_id, self.target()).as_bytes());
        digest.finish().to_string()
    }

    /// The state event one projection step returns.
    pub(super) fn endpoint(&self, target_end: bool) -> StateEventValue {
        StateEventValue {
            file_state: Arc::clone(&self.file_state),
            procedure_index: self.procedure_index,
            event: if target_end {
                self.row().target_event
            } else {
                self.row().source_event
            },
            file: self.file.clone(),
            procedure_id: Arc::clone(&self.procedure_id),
            procedure: self.procedure.clone(),
            diagnostic_procedure: self.diagnostic_procedure.clone(),
            selected_property_origin: self.selected_property.as_ref().map(|proof| proof.point),
        }
    }
}

/// One request-derived link from a binding establishment to a call result in
/// its initializer receiver chain.
#[derive(Debug, Clone)]
pub(super) struct BindingInitializerCallValue {
    pub(super) row: CodeQueryBindingInitializerCall,
    pub(super) file: ProjectFile,
}

pub(super) fn state_event_id(procedure_id: &str, row: &StateEventRow) -> String {
    let mut digest = LengthDelimitedDigest::new(STATE_EVENT_ID_DOMAIN);
    digest.push(procedure_id.as_bytes());
    digest.push(rel_path_string(&row.site.file).as_bytes());
    digest.push(&row.site.range.start_byte.to_le_bytes());
    digest.push(&row.site.range.end_byte.to_le_bytes());
    digest.push(row.event_class.label().as_bytes());
    digest.push(row.subject.kind().label().as_bytes());
    digest.push(row.subject.member().unwrap_or("").as_bytes());
    digest.push(&(row.subject.value().index() as u64).to_le_bytes());
    digest.finish().to_string()
}

/// Dedup identity of a state-event row: the seed procedure plus the dense
/// event index the derivation minted. Two events at one source position with
/// different classes are two rows, which is the point of the domain.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct StateEventKey {
    pub(super) file: ProjectFile,
    pub(super) procedure: String,
    pub(super) event: usize,
    pub(super) selected_property_origin: Option<ProgramPointId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct FlowRelationKey {
    pub(super) file: ProjectFile,
    pub(super) procedure: String,
    pub(super) relation: usize,
    pub(super) selected_property_origin: Option<ProgramPointId>,
    pub(super) selected_relation: Option<String>,
}

pub(super) fn state_event_filter_matches(filter: &StateEventFilter, row: &StateEventRow) -> bool {
    if !filter.classes.is_empty() && !filter.classes.contains(&row.event_class) {
        return false;
    }
    if !filter.subjects.is_empty() && !filter.subjects.contains(&row.subject.kind()) {
        return false;
    }
    if !filter.read_causes.is_empty()
        && !row
            .read_cause
            .is_some_and(|cause| filter.read_causes.contains(&cause))
    {
        return false;
    }
    true
}

pub(super) fn flow_relation_filter_matches(
    filter: &FlowRelationFilter,
    row: &FlowRelationRow,
) -> bool {
    if !filter.relations.is_empty() && !filter.relations.contains(&row.relation) {
        return false;
    }
    if !filter.certainties.is_empty() && !filter.certainties.contains(&row.certainty) {
        return false;
    }
    true
}

/// The public projection of one state-event row.
pub(super) fn public_state_event(
    value: &StateEventValue,
    range: CodeQueryRange,
) -> CodeQueryStateEvent {
    let row = value.row();
    let common = state_event_projection(value.id(), row, range);
    CodeQueryStateEvent {
        id: common.id,
        ast_id: common.ast_id,
        procedure_id: value.procedure_id.to_string(),
        path: common.path,
        language: crate::analyzer::common::language_for_file(&row.site.file).config_label(),
        range: common.range,
        start_byte: row.site.range.start_byte,
        end_byte: row.site.range.end_byte,
        event_class: common.event_class,
        read_cause: row.read_cause.map(|cause| cause.label()),
        subject: common.subject,
        member: common.member,
        subject_value: row.subject.value().index(),
        program_point: common.program_point,
        program_point_id: common.program_point_id,
        value: row.value.index(),
        completeness: axis_completeness_label(&value.derivation().completeness, row.subject.axis()),
        uncovered_axes: uncovered_axes(&value.derivation().completeness),
        generation: row.generation,
    }
}

/// The public projection of one flow-relation row, with both endpoints
/// rendered inline: a relation is unreadable without knowing which write and
/// which read it names.
pub(super) fn public_flow_relation(
    value: &FlowRelationValue,
    source_range: CodeQueryRange,
    target_range: CodeQueryRange,
) -> CodeQueryFlowRelation {
    let row = value.row();
    CodeQueryFlowRelation {
        id: value.id(),
        procedure_id: value.procedure_id.to_string(),
        path: rel_path_string(value.file()),
        language: crate::analyzer::common::language_for_file(value.file()).config_label(),
        range: target_range,
        relation: row.relation.label(),
        certainty: row.certainty.label(),
        source: state_event_ref(&value.procedure_id, value.source(), source_range),
        target: state_event_ref(&value.procedure_id, value.target(), target_range),
        completeness: axis_completeness_label(
            value.completeness(),
            row.relation.axis_for_subject(value.target().subject.kind()),
        ),
        uncovered_axes: uncovered_axes(value.completeness()),
        generation: row.generation,
    }
}

pub(super) fn state_event_ref(
    procedure_id: &str,
    row: &StateEventRow,
    range: CodeQueryRange,
) -> CodeQueryStateEventRef {
    state_event_projection(state_event_id(procedure_id, row), row, range)
}

fn state_event_projection(
    id: String,
    row: &StateEventRow,
    range: CodeQueryRange,
) -> CodeQueryStateEventRef {
    CodeQueryStateEventRef {
        id,
        ast_id: row.site.ast_id.clone(),
        path: rel_path_string(&row.site.file),
        range,
        event_class: row.event_class.label(),
        subject: row.subject.kind().label(),
        member: row.subject.member().map(str::to_string),
        program_point: row.point.index(),
        program_point_id: row.point_id.to_string(),
    }
}

/// The value domain the `state_event.completeness` and
/// `flow_relation.completeness` row fields publish, minted by
/// [`axis_completeness_label`] (issue #2515).
pub(super) const FLOW_STATE_COMPLETENESS_LABELS: &[&str] = &["complete", "partial"];

/// `complete` exactly when the derivation answers *this row's own axis*;
/// otherwise `partial`. A row whose family was fully enumerated is not made
/// partial by a hole in an unrelated axis, and `uncovered_axes` still names
/// every hole the derivation left.
fn axis_completeness_label(
    completeness: &FlowStateCompleteness,
    axis: FlowStateAxis,
) -> &'static str {
    super::completeness_label_for_coverage(completeness.covers(axis))
}

fn uncovered_axes(completeness: &FlowStateCompleteness) -> Vec<&'static str> {
    FLOW_STATE_AXES
        .iter()
        .filter(|axis| !completeness.covers(**axis))
        .map(|axis| axis.label())
        .collect()
}

/// Assertions that keep this module honest about the vocabulary it renders.
#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_test_macros::hardwon;

    #[test]
    #[hardwon("#7107: flow-state value memo suppressed diagnostics across invocation boundaries")]
    fn an_incomplete_derivation_replays_every_invocation() {
        let directory = tempfile::tempdir().unwrap();
        let analyzer =
            crate::analyzer::JavascriptAnalyzer::from_project(crate::analyzer::TestProject::new(
                directory.path().to_path_buf(),
                crate::analyzer::Language::JavaScript,
            ));

        let mut cache = FlowStateTraversalCache::default();
        let completeness = FlowStateCompleteness::Incomplete {
            reasons: vec![
                FlowStateIncompleteReason::AxisUnsupported(FlowStateAxis::PropertyEvents),
                FlowStateIncompleteReason::BudgetExhausted {
                    axis: FlowStateAxis::ReachingRelation,
                    detail: "NodeVisits limit 1 exceeded at 2".to_string(),
                },
            ],
        };
        let mut diagnostics = Vec::new();
        cache.report_completeness(
            &analyzer,
            "src/main.js",
            None,
            Language::JavaScript,
            &completeness,
            FLOW_STATE_AXES,
            7,
            &mut diagnostics,
        );
        crate::structural::search::test_support::assert_incomplete_diagnostics(&diagnostics, 2);
        // A fresh invocation reports the same evidence independently.
        cache.report_completeness(
            &analyzer,
            "src/main.js",
            None,
            Language::JavaScript,
            &completeness,
            FLOW_STATE_AXES,
            7,
            &mut diagnostics,
        );
        crate::structural::search::test_support::assert_incomplete_diagnostics(&diagnostics, 4);
        assert!(!completeness.covers(FlowStateAxis::PropertyEvents));
        assert!(!completeness.covers(FlowStateAxis::ReachingRelation));
    }

    /// A reason that blocks no axis the caller publishes is not the caller's
    /// incompleteness. This is what keeps a state-event query over a procedure
    /// with a call conclusive: the lowering cannot model the call's
    /// same-evaluation dependence, and a set of binding events is not made
    /// partial by that.
    #[test]
    fn a_reason_outside_the_requested_axes_is_not_reported() {
        let directory = tempfile::tempdir().unwrap();
        let analyzer =
            crate::analyzer::JavascriptAnalyzer::from_project(crate::analyzer::TestProject::new(
                directory.path().to_path_buf(),
                crate::analyzer::Language::JavaScript,
            ));

        let mut cache = FlowStateTraversalCache::default();
        let completeness = FlowStateCompleteness::Incomplete {
            reasons: vec![FlowStateIncompleteReason::LoweringGap {
                gaps: Vec::new(),
                capability: SemanticCapability::Calls,
                kind: SemanticGapKind::Unsupported,
                detail: "the adapter does not model this call".to_string(),
            }],
        };
        let mut diagnostics = Vec::new();
        cache.report_completeness(
            &analyzer,
            "src/main.js",
            None,
            Language::JavaScript,
            &completeness,
            STATE_EVENT_AXES,
            7,
            &mut diagnostics,
        );
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        assert!(completeness.covers(FlowStateAxis::BindingEvents));

        cache.report_completeness(
            &analyzer,
            "src/main.js",
            None,
            Language::JavaScript,
            &completeness,
            FLOW_RELATION_AXES,
            7,
            &mut diagnostics,
        );
        assert_eq!(
            diagnostics.len(),
            1,
            "the same reason does block the relation family: {diagnostics:?}"
        );
        assert!(!completeness.covers(FlowStateAxis::SameEvaluationRelation));
    }
}
