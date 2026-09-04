use std::{cmp::Ordering, error::Error, fmt, hash::Hash, mem::size_of_val, sync::Arc};

use crate::analyzer::semantic::{
    AbstractLocation, AbstractObject, AccessPathRoot, CallArgumentEndpoint, CallBinding,
    CallBindings, CallSiteHandle, CallSiteId, CallableTarget, CallableTargetResolution,
    CandidateCoverage, ControlEdgeId, ControlEdgeKind, DeclarationLocator, DeclarationSegmentKind,
    DispatchBoundaryKind, EvidenceCompleteness, GuardFact, IcfgEdgeKind, MemoryLocationKind,
    ObjectCardinality, ProcedureHandle, ProcedureSemantics, ProgramPointHandle, ProgramPointId,
    ProofStatus, SemanticArtifact, SemanticArtifactKey, SemanticCapability, SemanticEffect,
    SemanticGapHandle, SemanticGapImpact, SemanticGapKind, SemanticGapSubject, SemanticLocator,
    SemanticValueKind, ValueFlowRelationKind, ValueFlowSnapshot, ValueTransfer,
};
use crate::dataflow::{
    CuratedCallModel, CuratedCallModelFingerprint, ExternalSemanticSummarySet,
    ExternalSummaryOrigin, ExternalSummarySetFingerprint, MAX_SUMMARY_BOUNDARY_BINDINGS,
    SemanticInputStatus, SemanticProcedureSummary, SummaryBoundary, SummaryBoundaryKind,
    SummaryDataflowResult, SummaryEffect, SummaryEffectKey, SummaryEvidence, SummaryExitKind,
    SummaryOrigin, SummaryPort, SummaryTransfer, UnmodeledCallBehavior,
};
use crate::hash::{HashMap, HashSet};

use super::{
    ValueFlowCarrier, ValueFlowCarrierId, ValueFlowCarrierKey, ValueFlowEventKey,
    ValueFlowModelError, ValueFlowObservationPhase, ValueFlowSinkId, ValueFlowSinkSpec,
    ValueFlowSourceId, ValueFlowSourceSpec,
};

pub const MAX_VALUE_FLOW_CARRIERS: usize = 262_144;
pub const MAX_VALUE_FLOW_RELATIONS: usize = 1_000_000;
pub const MAX_VALUE_FLOW_SOURCES: usize = 65_536;
pub const MAX_VALUE_FLOW_SINKS: usize = 65_536;

/// Remove selected source facts from one carrier while traversing one exact
/// intraprocedural edge.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ValueFlowEdgeKillSpec {
    pub point: ProgramPointHandle,
    pub target: ProgramPointId,
    pub kind: ControlEdgeKind,
    pub carrier: ValueFlowCarrier,
    pub sources: Vec<ValueFlowEventKey>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BoundValueFlowEdgeKill {
    pub carrier: ValueFlowCarrierId,
    pub sources: Box<[ValueFlowSourceId]>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct EdgeKillKey {
    point: ProgramPointHandle,
    target: ProgramPointId,
    kind: ControlEdgeKind,
}

#[derive(Debug, Clone, Default)]
struct EdgeKillIndex {
    by_edge: HashMap<EdgeKillKey, Box<[BoundValueFlowEdgeKill]>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValueFlowPlanLimits {
    max_carriers: usize,
    max_relations: usize,
    max_sources: usize,
    max_sinks: usize,
}

impl ValueFlowPlanLimits {
    pub fn new(
        max_carriers: usize,
        max_relations: usize,
        max_sources: usize,
        max_sinks: usize,
    ) -> Result<Self, ValueFlowPlanError> {
        if max_carriers == 0
            || max_carriers > MAX_VALUE_FLOW_CARRIERS
            || max_relations == 0
            || max_relations > MAX_VALUE_FLOW_RELATIONS
            || max_sources == 0
            || max_sources > MAX_VALUE_FLOW_SOURCES
            || max_sinks == 0
            || max_sinks > MAX_VALUE_FLOW_SINKS
        {
            return Err(ValueFlowPlanError::InvalidLimits);
        }
        Ok(Self {
            max_carriers,
            max_relations,
            max_sources,
            max_sinks,
        })
    }
}

impl Default for ValueFlowPlanLimits {
    fn default() -> Self {
        Self {
            max_carriers: MAX_VALUE_FLOW_CARRIERS,
            max_relations: MAX_VALUE_FLOW_RELATIONS,
            max_sources: MAX_VALUE_FLOW_SOURCES,
            max_sinks: MAX_VALUE_FLOW_SINKS,
        }
    }
}

/// One discovered oracle payload and the semantic outcome that produced it.
#[derive(Debug, Clone)]
pub struct ValueFlowInput<T> {
    value: T,
    status: SemanticInputStatus,
}

impl<T> ValueFlowInput<T> {
    pub const fn new(value: T, status: SemanticInputStatus) -> Self {
        Self { value, status }
    }

    pub const fn value(&self) -> &T {
        &self.value
    }

    pub const fn status(&self) -> SemanticInputStatus {
        self.status
    }

    pub fn into_parts(self) -> (T, SemanticInputStatus) {
        (self.value, self.status)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct LocalFlowRule {
    pub point: ProgramPointHandle,
    pub event_index: u32,
    pub kind: ValueFlowRelationKind,
    pub transfer: Option<ValueTransfer>,
    pub source: ValueFlowCarrierId,
    pub target: ValueFlowCarrierId,
    pub proof: ProofStatus,
    pub completeness: EvidenceCompleteness,
    /// The heap oracle certified this store as a strong update (#2444), so a
    /// client may replace rather than join the facts at `target`.
    pub strong_update: bool,
}

/// One point-local rule as the flow clients read it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LocalRuleView {
    pub source: ValueFlowCarrierId,
    pub target: ValueFlowCarrierId,
    pub kind: ValueFlowRelationKind,
    pub transfer: Option<ValueTransfer>,
    /// The rule's own evidence is proven and complete.
    pub complete: bool,
    /// The store this rule publishes overwrites `target` outright (#2444).
    pub strong_update: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum CallFlowRuleKind {
    Call,
    NormalReturn,
    ExceptionalReturn,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct ValueFlowLocalSummaryRule {
    point: ProgramPointId,
    event_index: u32,
    kind: ValueFlowRelationKind,
    transfer: Option<ValueTransfer>,
    source: ValueFlowCarrierKey,
    target: ValueFlowCarrierKey,
    proof: ProofStatus,
    completeness: EvidenceCompleteness,
    /// Part of the identity: two plans that disagree about whether a store
    /// kills its target do not compute the same summary.
    strong_update: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct ValueFlowCallSummaryRule {
    call: CallSiteId,
    callee_artifact: SemanticArtifactKey,
    callee_declaration: DeclarationLocator,
    kind: CallFlowRuleKind,
    source: ValueFlowCarrierKey,
    target: ValueFlowCarrierKey,
    proof: ProofStatus,
    completeness: EvidenceCompleteness,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct ValueFlowCuratedModelSummaryRule {
    call: CallSiteId,
    model: CuratedCallModelFingerprint,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct ValueFlowFallbackSummaryRule {
    call: CallSiteId,
    inputs: Box<[ValueFlowCarrierKey]>,
    reachable_components: Box<[usize]>,
    normal_output: Option<ValueFlowCarrierKey>,
    exceptional_output: Option<ValueFlowCarrierKey>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct ValueFlowLocationBindingSummaryRule {
    call: CallSiteId,
    port: SummaryPort,
    carrier: ValueFlowCarrierKey,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct ValueFlowEdgeKillSummaryRule {
    point: ProgramPointId,
    target: ProgramPointId,
    kind: ControlEdgeKind,
    carrier: ValueFlowCarrierKey,
    sources: Box<[ValueFlowEventKey]>,
}

/// Stable, procedure-local value-flow identity used by reusable client summaries.
///
/// Source, sink, sanitizer, and transform matching are intentionally absent;
/// clients add those independently according to their invalidation contract.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct ValueFlowCarrierSummaryIdentity {
    unmodeled_call_behavior: UnmodeledCallBehavior,
    external_summaries: Box<[ExternalSummarySetFingerprint]>,
    fallback_globals: Box<[ValueFlowCarrierKey]>,
    has_snapshot: bool,
    local_rules: Box<[ValueFlowLocalSummaryRule]>,
    call_rules: Box<[ValueFlowCallSummaryRule]>,
    curated_models: Box<[ValueFlowCuratedModelSummaryRule]>,
    fallback_rules: Box<[ValueFlowFallbackSummaryRule]>,
    location_bindings: Box<[ValueFlowLocationBindingSummaryRule]>,
    edge_kills: Box<[ValueFlowEdgeKillSummaryRule]>,
}

impl ValueFlowCarrierSummaryIdentity {
    pub(crate) fn retained_bytes(&self) -> usize {
        let local = size_of_val(self.local_rules.as_ref()).saturating_add(
            self.local_rules.iter().fold(0usize, |total, rule| {
                total
                    .saturating_add(rule.source.retained_bytes())
                    .saturating_add(rule.target.retained_bytes())
                    .saturating_add(proof_heap_bytes(&rule.proof))
                    .saturating_add(completeness_heap_bytes(&rule.completeness))
            }),
        );
        let calls = size_of_val(self.call_rules.as_ref()).saturating_add(
            self.call_rules.iter().fold(0usize, |total, rule| {
                total
                    .saturating_add(rule.callee_artifact.path().as_str().len())
                    .saturating_add(declaration_heap_bytes(&rule.callee_declaration))
                    .saturating_add(rule.source.retained_bytes())
                    .saturating_add(rule.target.retained_bytes())
                    .saturating_add(proof_heap_bytes(&rule.proof))
                    .saturating_add(completeness_heap_bytes(&rule.completeness))
            }),
        );
        let fallbacks = size_of_val(self.fallback_rules.as_ref()).saturating_add(
            self.fallback_rules.iter().fold(0usize, |total, rule| {
                total
                    .saturating_add(size_of_val(rule.inputs.as_ref()))
                    .saturating_add(
                        rule.inputs
                            .iter()
                            .map(ValueFlowCarrierKey::retained_bytes)
                            .fold(0usize, usize::saturating_add),
                    )
                    .saturating_add(size_of_val(rule.reachable_components.as_ref()))
                    .saturating_add(
                        rule.normal_output
                            .as_ref()
                            .map_or(0, ValueFlowCarrierKey::retained_bytes),
                    )
                    .saturating_add(
                        rule.exceptional_output
                            .as_ref()
                            .map_or(0, ValueFlowCarrierKey::retained_bytes),
                    )
            }),
        );
        let location_bindings = size_of_val(self.location_bindings.as_ref()).saturating_add(
            self.location_bindings
                .iter()
                .map(|binding| binding.carrier.retained_bytes())
                .fold(0usize, usize::saturating_add),
        );
        let edge_kills = size_of_val(self.edge_kills.as_ref()).saturating_add(
            self.edge_kills
                .iter()
                .map(|kill| {
                    kill.carrier
                        .retained_bytes()
                        .saturating_add(size_of_val(kill.sources.as_ref()))
                        .saturating_add(
                            kill.sources
                                .iter()
                                .map(ValueFlowEventKey::retained_bytes)
                                .fold(0usize, usize::saturating_add),
                        )
                })
                .fold(0usize, usize::saturating_add),
        );
        std::mem::size_of::<Self>()
            .saturating_add(local)
            .saturating_add(calls)
            .saturating_add(size_of_val(self.curated_models.as_ref()))
            .saturating_add(size_of_val(self.external_summaries.as_ref()))
            .saturating_add(size_of_val(self.fallback_globals.as_ref()))
            .saturating_add(
                self.fallback_globals
                    .iter()
                    .map(ValueFlowCarrierKey::retained_bytes)
                    .fold(0usize, usize::saturating_add),
            )
            .saturating_add(fallbacks)
            .saturating_add(location_bindings)
            .saturating_add(edge_kills)
    }
}

fn declaration_heap_bytes(declaration: &DeclarationLocator) -> usize {
    size_of_val(declaration.segments()).saturating_add(
        declaration
            .segments()
            .iter()
            .filter_map(|segment| segment.name())
            .map(str::len)
            .fold(0usize, usize::saturating_add),
    )
}

fn proof_heap_bytes(proof: &ProofStatus) -> usize {
    match proof {
        ProofStatus::Proven => 0,
        ProofStatus::Unproven(reason) => reason.len(),
    }
}

fn completeness_heap_bytes(completeness: &EvidenceCompleteness) -> usize {
    match completeness {
        EvidenceCompleteness::Complete => 0,
        EvidenceCompleteness::Partial(reason) => reason.len(),
    }
}

/// Classify a snapshot's residual openness (#1952). `Blocked(Some(...))`
/// retains the first relevant producer gap; `Blocked(None)` means a required
/// capability is unavailable without one scoped gap. `Refinable(residual)`
/// means every relevant gap is either discharged or a call-target refinement
/// gap, and lists the calls without complete bindings (empty when the plan's
/// own bindings answer them all).
enum SnapshotOpenness {
    Refinable(Vec<CallSiteHandle>),
    Blocked(Option<(SemanticGapHandle, SemanticCapability)>),
}

fn classify_snapshot_openness(
    snapshot: &ValueFlowSnapshot,
    binding_complete: &HashMap<CallSiteHandle, bool>,
    sources: &[ValueFlowSourceSpec],
    sinks: &[ValueFlowSinkSpec],
) -> SnapshotOpenness {
    let procedure = snapshot.procedure();
    // A typed gap may outrank an unproven retained relation in the oracle's
    // top-level outcome, but refining that gap does not prove the relation.
    // Preserve the relation's independent quality floor before considering
    // whether the typed gaps can be discharged by this plan (#2835).
    if snapshot
        .relations()
        .iter()
        .any(|relation| !relation.is_proven_complete())
    {
        return SnapshotOpenness::Blocked(None);
    }
    if crate::analyzer::semantic::workspace_oracle::value_flow_capabilities_are_open(procedure) {
        return SnapshotOpenness::Blocked(None);
    }
    let abort_user_code = crate::analyzer::semantic::workspace_oracle::abort_paths_run_user_code(
        procedure.semantics(),
    );
    let relevant_value_gaps = relevant_value_gap_carriers(snapshot, sources, sinks);
    let mut residual = Vec::new();
    for gap in procedure.semantics().gaps() {
        if !crate::analyzer::semantic::workspace_oracle::gap_impacts_value_flow(gap) {
            continue;
        }
        if crate::analyzer::semantic::workspace_oracle::implicit_abort_gap_is_discharged(
            gap,
            abort_user_code,
        ) {
            continue;
        }
        if crate::analyzer::semantic::workspace_oracle::constructor_call_gap_is_discharged(
            procedure.semantics(),
            gap,
        ) {
            continue;
        }
        let refinement_call =
            crate::analyzer::semantic::workspace_oracle::call_target_refinement_call(
                procedure.semantics(),
                gap,
            )
            .and_then(|call| procedure.call_site_handle(call));
        match refinement_call {
            Some(call) => {
                if !binding_complete.get(&call).copied().unwrap_or(false)
                    && !residual.contains(&call)
                {
                    residual.push(call);
                }
            }
            // Not a call-target refinement gap. It still does not have to
            // block this snapshot: a gap of any other capability (for
            // example `FieldMemory`, #2538/#2545) can be proven discharged
            // by a predicate that needs query-time analyzer access this
            // pure re-derivation does not have. `snapshot` itself already
            // ran that predicate while it was materialized
            // (`WorkspaceSemanticOracle::procedure_relations`'s own-gap
            // sweep) and recorded the answer; trust it here rather than
            // either duplicating every such predicate or treating every
            // non-refinement gap as permanently blocking. A gap this
            // snapshot did *not* prove discharged still ends this function
            // with `None`, exactly as before -- the fails-closed path is
            // unchanged.
            None if snapshot.gap_is_discharged(gap.id) => {}
            None if value_call_gap_is_local_dead_end(snapshot, gap, &relevant_value_gaps) => {}
            None => {
                let handle = procedure
                    .gap_handle(gap.id)
                    .expect("a snapshot gap remains live in its procedure");
                return SnapshotOpenness::Blocked(Some((handle, gap.capability)));
            }
        }
    }
    SnapshotOpenness::Refinable(residual)
}

/// The value carriers whose incomplete semantics can affect a selected source
/// or sink, or escape this procedure through a port, memory location, or call
/// operand.
///
/// Build the reverse closure once per snapshot rather than walking every
/// relation once per gap. The seed set is conservative at every boundary: a
/// value passed to a call or projected onto heap/port state stays relevant even
/// when this plan has no local sink for it (#2600).
fn relevant_value_gap_carriers(
    snapshot: &ValueFlowSnapshot,
    sources: &[ValueFlowSourceSpec],
    sinks: &[ValueFlowSinkSpec],
) -> HashSet<ValueFlowCarrier> {
    let mut predecessors: HashMap<ValueFlowCarrier, Vec<ValueFlowCarrier>> = HashMap::default();
    let mut pending = sources
        .iter()
        .map(|source| source.carrier().clone())
        .chain(sinks.iter().map(|sink| sink.carrier().clone()))
        .collect::<Vec<_>>();
    for relation in snapshot.relations() {
        let source = ValueFlowCarrier::from(&relation.source);
        let target = ValueFlowCarrier::from(&relation.target);
        if matches!(
            source,
            ValueFlowCarrier::Port(_) | ValueFlowCarrier::Location(_)
        ) {
            pending.push(source.clone());
        }
        if matches!(
            target,
            ValueFlowCarrier::Port(_) | ValueFlowCarrier::Location(_)
        ) {
            pending.push(target.clone());
        }
        predecessors.entry(target).or_default().push(source);
    }
    for call in snapshot.procedure().semantics().call_sites() {
        pending.extend(
            std::iter::once(call.callee)
                .chain(call.receiver)
                .chain(call.arguments.iter().map(|argument| argument.value))
                .filter_map(|value| snapshot.procedure().value_handle(value))
                .map(ValueFlowCarrier::Value),
        );
    }

    let mut reached = HashSet::default();
    while let Some(carrier) = pending.pop() {
        if !reached.insert(carrier.clone()) {
            continue;
        }
        if let Some(sources) = predecessors.get(&carrier) {
            pending.extend(sources.iter().cloned());
        }
    }
    reached
}

/// Whether a value-scoped call-semantics gap is trapped in unobserved local
/// values. Other capabilities, including callable-reference construction, keep
/// their existing fail-closed behavior even when their subject looks dead.
fn value_call_gap_is_local_dead_end(
    snapshot: &ValueFlowSnapshot,
    gap: &crate::analyzer::semantic::SemanticGap,
    relevant: &HashSet<ValueFlowCarrier>,
) -> bool {
    if gap.capability != crate::analyzer::semantic::SemanticCapability::Calls {
        return false;
    }
    let SemanticGapSubject::Value(value) = gap.subject else {
        return false;
    };
    let Some(value) = snapshot.procedure().value_handle(value) else {
        debug_assert!(false, "validated gap subject must name a live value");
        return false;
    };
    !relevant.contains(&ValueFlowCarrier::Value(value))
}

fn summary_evidence_is_proven_complete(evidence: &SummaryEvidence) -> bool {
    evidence
        .alternatives()
        .iter()
        .any(|alternative| alternative.quality().is_proven() && alternative.quality().is_complete())
}

/// The labels a sanitize effect removes on the `input`-to-`output` transfer, or
/// an empty slice when no sanitize effect names that exact port pair (#1923).
/// A summary declares at most one sanitize per port pair, so the first match
/// is the answer.
fn sanitize_removed_labels<'a>(
    effects: &'a [SummaryEffect],
    input: &SummaryPort,
    output: &SummaryPort,
) -> &'a [Box<str>] {
    effects
        .iter()
        .find_map(|effect| match effect.key() {
            SummaryEffectKey::Sanitize {
                input: sanitize_input,
                output: sanitize_output,
                removed,
            } if sanitize_input == input && sanitize_output == output => Some(removed.as_ref()),
            _ => None,
        })
        .unwrap_or(&[])
}

/// How strong a dispatch boundary's proof must be for it to count as fully
/// modeled.
///
/// `execution_result_complete` asks with `Derived`: a boundary is modeled only
/// when the solver derived a proof for it. The `ProvenBySummary` completion
/// tier (#1916) asks the weaker question with `AcceptAuthoredComplete` -- would
/// the run be complete if an authored-complete external procedure summary were
/// accepted as closing its boundary, even though `bind_compiled_procedure_summaries`
/// deliberately stamps that boundary's proof authored rather than derived. The
/// relaxation touches only the external-summary branch; a curated model, a
/// limit, a continuation, or a partial summary is unaffected.
#[derive(Clone, Copy, PartialEq, Eq)]
enum SummaryProofRequirement {
    Derived,
    AcceptAuthoredComplete,
}

/// How one summary transfer input binds at a concrete call.
///
/// Constants deliberately have no value-flow carrier: no caller fact can flow
/// into a literal. A transfer sourced by such a parameter is therefore an
/// empty, vacuously modeled transfer rather than a missing-model gap (#2455).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SummaryInputBinding {
    Carrier(ValueFlowCarrierId),
    VacuousConstant,
    Unbound,
}

/// One dispatch boundary closed by an authored-complete external summary
/// (#2342).
///
/// A run that concludes `ProvenBySummary` because of such a closure is trusting
/// an authored claim to model an external target. When the dispatch result also
/// retained a residual arm, the claim describes that target's whole target set,
/// not only its behavior. The run records which claim it was in both cases: the
/// call whose boundary was closed, the exact target the summary was selected by,
/// and the summary's authored origin -- model id, content hash, and contract
/// version. A consumer rendering the run can state what proved the closure
/// instead of reporting an unexplained conclusion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthoredArmClosure {
    call: CallSiteHandle,
    target: SemanticLocator,
    origin: ExternalSummaryOrigin,
}

impl AuthoredArmClosure {
    /// The call whose dispatch boundary this closure discharged.
    pub const fn call(&self) -> &CallSiteHandle {
        &self.call
    }

    /// The exact target the discharging summary was selected by.
    pub const fn target(&self) -> &SemanticLocator {
        &self.target
    }

    /// The authored identity of the discharging summary.
    pub const fn origin(&self) -> &ExternalSummaryOrigin {
        &self.origin
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct CallFlowRule {
    pub call: CallSiteHandle,
    pub callee: ProcedureHandle,
    pub kind: CallFlowRuleKind,
    pub source: ValueFlowCarrierId,
    pub target: ValueFlowCarrierId,
    pub proof: ProofStatus,
    pub completeness: EvidenceCompleteness,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct CallFallbackProfile {
    call: CallSiteHandle,
    inputs: Box<[ValueFlowCarrierId]>,
    reachable_components: Box<[usize]>,
    normal_output: Option<ValueFlowCarrierId>,
    exceptional_output: Option<ValueFlowCarrierId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BoundaryTransferApplication {
    pub modeled: bool,
    pub complete: bool,
    pub abstained: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BoundBoundaryTransfer {
    pub target: ValueFlowCarrierId,
    pub proven_complete: bool,
    /// Stable labels a matching sanitize effect removes on this modeled
    /// transfer (#1923). It is empty for a plain flow-through. When this
    /// transfer's own input was composed from a sibling transfer's output on
    /// the same call (#2567), this is the *union* of every sanitize
    /// encountered along the composed path, not only this transfer's own
    /// effect -- see `visit_modeled_transfers` for why that union is exactly
    /// equivalent to chaining `TaintEdgeFunction::kill` once per hop. Owned
    /// (not borrowed) because a composed path's label set does not live
    /// inside any single transfer's own effect record. The taint client
    /// resolves these labels against its run universe and composes a kill.
    pub removed_labels: Vec<Box<str>>,
}

/// One curated transfer model after its selector has been bound to a live
/// semantic call site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValueFlowCuratedCallModel {
    call: CallSiteHandle,
    model: CuratedCallModel,
}

/// Structured binding from a summary heap/capture port to one live bounded
/// value-flow carrier at a call site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValueFlowSummaryLocationBinding {
    call: CallSiteHandle,
    port: SummaryPort,
    carrier: ValueFlowCarrier,
}

impl ValueFlowSummaryLocationBinding {
    pub fn new(call: CallSiteHandle, port: SummaryPort, carrier: ValueFlowCarrier) -> Self {
        Self {
            call,
            port,
            carrier,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct BoundSummaryLocationBinding {
    call: CallSiteHandle,
    port: SummaryPort,
    carrier: ValueFlowCarrierId,
}

impl ValueFlowCuratedCallModel {
    pub fn new(call: CallSiteHandle, model: CuratedCallModel) -> Self {
        Self { call, model }
    }

    pub fn call(&self) -> &CallSiteHandle {
        &self.call
    }

    pub const fn model(&self) -> &CuratedCallModel {
        &self.model
    }
}

/// How one snapshot input participates in discovery completeness (#1952).
///
/// `Refinable` records a snapshot left `Unknown` only by call-target
/// refinement gaps whose calls have no complete binding in this plan. Such a
/// snapshot does not make discovery complete by itself, but an execution
/// result that fully models exactly those calls (a complete external summary
/// or curated model closing their boundaries) answers the same gaps, so
/// `execution_result_complete` treats it as closed.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum SnapshotDiscovery {
    Complete,
    Refinable {
        calls: Box<[CallSiteHandle]>,
    },
    Incomplete {
        gap: Option<(SemanticGapHandle, SemanticCapability)>,
    },
}

/// The first discovery input, in the plan's deterministic input order
/// (sorted snapshots, then sorted bindings, then sources, then sinks), that
/// prevented `discovery_complete` (#1952).
///
/// The cause keeps the typed `SemanticInputStatus`, so a downstream client can
/// distinguish a missing capability from an unproven or budget-limited input
/// instead of collapsing every incomplete run into one generic reason.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ValueFlowIncompleteCause {
    Snapshot {
        procedure: ProcedureHandle,
        status: SemanticInputStatus,
    },
    SnapshotCoverage {
        procedure: ProcedureHandle,
    },
    /// The snapshot retained usable local relations, but one exact producer
    /// gap still blocks a complete verdict. Keeping the gap handle and its
    /// capability prevents access-path, control-flow, and other semantic
    /// blockers from being flattened into an "unknown snapshot" diagnosis.
    SemanticGap {
        gap: SemanticGapHandle,
        capability: SemanticCapability,
        status: SemanticInputStatus,
    },
    /// The snapshot's local relations are usable, but one call-target
    /// refinement gap has no complete binding in this plan. The execution
    /// layer may still close this boundary with a complete model; until then
    /// the run remains typed incomplete.
    CallResolution {
        call: CallSiteHandle,
        status: SemanticInputStatus,
    },
    CallBinding {
        call: CallSiteHandle,
        callee: ProcedureHandle,
        status: SemanticInputStatus,
    },
    CallBindingCoverage {
        call: CallSiteHandle,
        callee: ProcedureHandle,
    },
    /// A source or sink was observed in a procedure this plan mounts but the
    /// solve cannot enter (#2640).
    UnenteredProcedure {
        procedure: ProcedureHandle,
    },
    SourceEvidence {
        point: ProgramPointHandle,
    },
    SinkEvidence {
        point: ProgramPointHandle,
    },
}

impl ValueFlowIncompleteCause {
    pub const fn status(&self) -> Option<SemanticInputStatus> {
        match self {
            Self::Snapshot { status, .. }
            | Self::SemanticGap { status, .. }
            | Self::CallResolution { status, .. }
            | Self::CallBinding { status, .. } => Some(*status),
            Self::SnapshotCoverage { .. }
            | Self::CallBindingCoverage { .. }
            | Self::UnenteredProcedure { .. }
            | Self::SourceEvidence { .. }
            | Self::SinkEvidence { .. } => None,
        }
    }

    pub fn procedure(&self) -> &ProcedureHandle {
        match self {
            Self::Snapshot { procedure, .. }
            | Self::SnapshotCoverage { procedure }
            | Self::UnenteredProcedure { procedure } => procedure,
            Self::SemanticGap { gap, .. } => gap.procedure(),
            Self::CallResolution { call, .. } => call.procedure(),
            Self::CallBinding { callee, .. } | Self::CallBindingCoverage { callee, .. } => callee,
            Self::SourceEvidence { point } | Self::SinkEvidence { point } => point.procedure(),
        }
    }

    pub const fn label(&self) -> &'static str {
        match self {
            Self::Snapshot { .. } => "procedure value-flow snapshot",
            Self::SnapshotCoverage { .. } => "procedure value-flow coverage",
            Self::SemanticGap { capability, .. } => match capability {
                SemanticCapability::FieldMemory | SemanticCapability::IndexMemory => {
                    "access-path resolution"
                }
                _ => "procedure semantics",
            },
            Self::CallResolution { .. } => "call resolution",
            Self::CallBinding { .. } => "call binding",
            Self::CallBindingCoverage { .. } => "call binding coverage",
            Self::UnenteredProcedure { .. } => "procedure entry",
            Self::SourceEvidence { .. } => "source evidence",
            Self::SinkEvidence { .. } => "sink evidence",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct BoundValueFlowSource {
    pub id: ValueFlowSourceId,
    pub spec: ValueFlowSourceSpec,
    pub carrier: ValueFlowCarrierId,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct BoundValueFlowSink {
    pub id: ValueFlowSinkId,
    pub spec: ValueFlowSinkSpec,
    pub carrier: ValueFlowCarrierId,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CallRuleTargetKey {
    call: CallSiteHandle,
    callee: ProcedureHandle,
    kind: CallFlowRuleKind,
    target: ValueFlowCarrierId,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ObservationKey {
    point: ProgramPointHandle,
    phase: ValueFlowObservationPhase,
}

/// Immutable reverse lookup tables derived from the canonical local rule
/// array. The values are rule-array positions rather than cloned rules, so
/// every lookup retains the plan's one authoritative rule representation.
#[derive(Debug, Clone, Default)]
struct LocalRuleReverseIndex {
    /// Every local rule at a point in reverse event order. A backward
    /// preimage may change carriers, so a target-only bucket is insufficient
    /// for chained same-point rules.
    by_point: HashMap<ProgramPointHandle, Box<[usize]>>,
}

/// Immutable reverse lookup tables derived from the canonical call rule array.
/// Entries for one target retain the canonical source ordering used by the
/// forward client.
#[derive(Debug, Clone, Default)]
struct CallRuleReverseIndex {
    by_target: HashMap<CallRuleTargetKey, Box<[usize]>>,
}

/// Immutable point/phase lookup table for one observation kind.
#[derive(Debug, Clone, Default)]
struct ObservationIndex {
    by_point_phase: HashMap<ObservationKey, Box<[usize]>>,
}

impl LocalRuleReverseIndex {
    fn retained_heap_bytes(&self) -> usize {
        reverse_index_heap_bytes(&self.by_point)
    }
}

impl CallRuleReverseIndex {
    fn retained_heap_bytes(&self) -> usize {
        reverse_index_heap_bytes(&self.by_target)
    }
}

impl ObservationIndex {
    fn retained_heap_bytes(&self) -> usize {
        reverse_index_heap_bytes(&self.by_point_phase)
    }
}

impl EdgeKillIndex {
    fn retained_heap_bytes(&self) -> usize {
        self.by_edge
            .capacity()
            .saturating_mul(
                std::mem::size_of::<(EdgeKillKey, Box<[BoundValueFlowEdgeKill]>)>()
                    .saturating_add(1),
            )
            .saturating_add(
                self.by_edge
                    .values()
                    .map(|kills| {
                        size_of_val(kills.as_ref()).saturating_add(
                            kills
                                .iter()
                                .map(|kill| size_of_val(kill.sources.as_ref()))
                                .fold(0usize, usize::saturating_add),
                        )
                    })
                    .fold(0usize, usize::saturating_add),
            )
    }
}

fn reverse_index_heap_bytes<K>(index: &HashMap<K, Box<[usize]>>) -> usize {
    index
        .capacity()
        .saturating_mul(std::mem::size_of::<(K, Box<[usize]>)>().saturating_add(1))
        .saturating_add(
            index
                .values()
                .map(|positions| size_of_val(positions.as_ref()))
                .fold(0usize, usize::saturating_add),
        )
}

/// Immutable, canonical, already-resolved transfer plan for one solver run.
#[derive(Debug, Clone)]
pub struct ValueFlowPlan {
    root: ProcedureHandle,
    unmodeled_call_behavior: UnmodeledCallBehavior,
    external_summaries: ExternalSemanticSummarySet,
    curated_call_models: Box<[ValueFlowCuratedCallModel]>,
    carriers: Box<[ValueFlowCarrier]>,
    carrier_keys: Box<[ValueFlowCarrierKey]>,
    carrier_ids: HashMap<ValueFlowCarrier, ValueFlowCarrierId>,
    local_rules: Box<[LocalFlowRule]>,
    /// Derived lookup only; canonical rule identity remains `local_rules`.
    /// This field is intentionally absent from `PartialEq`, `Hash`, and
    /// propagation compatibility; `retained_bytes` still charges its storage.
    local_rule_reverse_index: LocalRuleReverseIndex,
    call_rules: Box<[CallFlowRule]>,
    /// Derived lookup only; canonical rule identity remains `call_rules`.
    /// This field is intentionally absent from `PartialEq`, `Hash`, and
    /// propagation compatibility; `retained_bytes` still charges its storage.
    call_rule_reverse_index: CallRuleReverseIndex,
    fallback_profiles: Box<[CallFallbackProfile]>,
    fallback_locations: FallbackLocationIndex,
    summary_location_bindings: Box<[BoundSummaryLocationBinding]>,
    sources: Box<[BoundValueFlowSource]>,
    /// Derived point/phase lookup; observation identity remains `sources`.
    source_index: ObservationIndex,
    sinks: Box<[BoundValueFlowSink]>,
    /// Derived point/phase lookup; observation identity remains `sinks`.
    sink_index: ObservationIndex,
    edge_kills: Box<[ValueFlowEdgeKillSpec]>,
    /// Derived dense-ID lookup; canonical identity remains `edge_kills`.
    edge_kill_index: EdgeKillIndex,
    snapshot_procedures: Box<[ProcedureHandle]>,
    /// Derived from the same procedures the plan was built over, so it is
    /// deliberately absent from `PartialEq` and `Hash`: two plans that agree on
    /// their inputs cannot disagree here (#2443 slice 2).
    infeasible_points: ConstantInfeasiblePoints,
    binding_pairs: Box<[(CallSiteHandle, ProcedureHandle)]>,
    discovery_status: SemanticInputStatus,
    first_incomplete_cause: Option<ValueFlowIncompleteCause>,
    snapshot_discoveries: Box<[SnapshotDiscovery]>,
    non_snapshot_discovery_complete: bool,
    /// Endpoint-only slice of `non_snapshot_discovery_complete`: whether every
    /// source and sink spec is proven, complete, and entered. Binding-input
    /// incompleteness is tracked per call in `incomplete_binding_calls` so a
    /// curated model that claims a call's whole behavior can answer it at
    /// result time.
    endpoint_discovery_complete: bool,
    /// Calls whose `CallBindings` input stayed incomplete. Discovery closes
    /// only when each is answered by a curated model over a fully modeled
    /// result boundary; without a curated model the plan stays exactly as
    /// strict as the combined flag was.
    incomplete_binding_calls: Box<[CallSiteHandle]>,
    ambiguous_dispatch: bool,
    discovery_complete: bool,
    structural_discovery_complete: bool,
    owner: Arc<()>,
}

impl PartialEq for ValueFlowPlan {
    fn eq(&self, other: &Self) -> bool {
        self.root == other.root
            && self.unmodeled_call_behavior == other.unmodeled_call_behavior
            && self.external_summaries == other.external_summaries
            && self.curated_call_models == other.curated_call_models
            && self.carriers == other.carriers
            && self.carrier_keys == other.carrier_keys
            && self.carrier_ids == other.carrier_ids
            && self.local_rules == other.local_rules
            && self.call_rules == other.call_rules
            && self.fallback_profiles == other.fallback_profiles
            && self.fallback_locations == other.fallback_locations
            && self.summary_location_bindings == other.summary_location_bindings
            && self.sources == other.sources
            && self.sinks == other.sinks
            && self.edge_kills == other.edge_kills
            && self.snapshot_procedures == other.snapshot_procedures
            && self.binding_pairs == other.binding_pairs
            && self.discovery_status == other.discovery_status
            && self.first_incomplete_cause == other.first_incomplete_cause
            && self.snapshot_discoveries == other.snapshot_discoveries
            && self.non_snapshot_discovery_complete == other.non_snapshot_discovery_complete
            && self.ambiguous_dispatch == other.ambiguous_dispatch
            && self.discovery_complete == other.discovery_complete
            && self.structural_discovery_complete == other.structural_discovery_complete
    }
}

impl Eq for ValueFlowPlan {}

impl Hash for ValueFlowPlan {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.root.hash(state);
        self.unmodeled_call_behavior.hash(state);
        self.external_summaries.fingerprint().hash(state);
        self.curated_call_models.len().hash(state);
        for model in &self.curated_call_models {
            model.call.hash(state);
            model.model.fingerprint().hash(state);
        }
        self.carrier_keys.hash(state);
        self.local_rules.hash(state);
        self.call_rules.hash(state);
        self.fallback_profiles.hash(state);
        self.summary_location_bindings.hash(state);
        self.sources.hash(state);
        self.sinks.hash(state);
        self.edge_kills.hash(state);
        self.snapshot_procedures.hash(state);
        self.binding_pairs.hash(state);
        self.discovery_status.hash(state);
        self.first_incomplete_cause.hash(state);
        self.snapshot_discoveries.hash(state);
        self.non_snapshot_discovery_complete.hash(state);
        self.ambiguous_dispatch.hash(state);
        self.discovery_complete.hash(state);
        self.structural_discovery_complete.hash(state);
    }
}

/// The program points a constant branch condition proves cannot execute, for
/// every procedure in one plan that has any (#2443 slice 2).
///
/// Almost always empty, and the empty case costs one length check: a lowerer
/// that folds `if (false)` emits no excluded edge at all -- the guard row
/// records the fold, and the dead region is unreachable without help from
/// here. What this covers is a condition a lowerer normalizes but does not
/// fold, such as Java's `!true`, where both arms are real edges and the solver
/// would otherwise walk the one that cannot execute.
///
/// A procedure with any infeasible point keeps its points sorted, so a lookup
/// is a scan of a list that is normally length zero followed by a binary
/// search.
type ConstantInfeasiblePoints = Box<[(ProcedureHandle, Box<[ProgramPointId]>)]>;

fn constant_infeasible_points<'a>(
    procedures: impl IntoIterator<Item = &'a ProcedureHandle>,
) -> ConstantInfeasiblePoints {
    let mut index: Vec<(ProcedureHandle, Box<[ProgramPointId]>)> = Vec::new();
    for procedure in procedures {
        if index.iter().any(|(known, _)| known == procedure) {
            continue;
        }
        let points = procedure_infeasible_points(procedure.semantics());
        if !points.is_empty() {
            index.push((procedure.clone(), points));
        }
    }
    index.into_boxed_slice()
}

/// The points of one procedure that only a constant condition's excluded arm
/// reaches.
///
/// A `ConstantBoolean` guard names the successor its own value excludes. A
/// point the entry can reach *only* through such an edge cannot execute, so
/// nothing observed there is a fact about any run of the program.
///
/// The answer is the difference between forward reachability over the whole
/// control-flow graph and forward reachability over the graph minus every
/// excluded edge. Taking the difference rather than the second set alone is
/// deliberate: a point already unreachable for some unrelated reason is not
/// something a constant condition proved, and claiming it would put this
/// rule's name on someone else's answer.
fn procedure_infeasible_points(procedure: &ProcedureSemantics) -> Box<[ProgramPointId]> {
    let excluded = procedure
        .guard_facts()
        .iter()
        .filter_map(GuardFact::infeasible_edge)
        .collect::<HashSet<ControlEdgeId>>();
    if excluded.is_empty() {
        return Box::default();
    }
    let reachable = |skip: &HashSet<ControlEdgeId>| {
        let mut seen = vec![false; procedure.points().len()];
        let mut stack = vec![procedure.entry_point()];
        while let Some(point) = stack.pop() {
            if std::mem::replace(&mut seen[point.index()], true) {
                continue;
            }
            for (id, edge) in procedure.successor_edges(point) {
                if !skip.contains(&id) {
                    stack.push(edge.target_point);
                }
            }
        }
        seen
    };
    let with_every_edge = reachable(&HashSet::default());
    let without_excluded_edges = reachable(&excluded);
    with_every_edge
        .into_iter()
        .zip(without_excluded_edges)
        .enumerate()
        .filter(|(_, (before, after))| *before && !*after)
        .map(|(index, _)| {
            ProgramPointId::try_from_index(index).expect("a validated point index fits u32")
        })
        .collect()
}

impl ValueFlowPlan {
    pub fn try_new(
        root: ProcedureHandle,
        snapshots: Vec<ValueFlowInput<ValueFlowSnapshot>>,
        bindings: Vec<ValueFlowInput<CallBindings>>,
        sources: Vec<ValueFlowSourceSpec>,
        sinks: Vec<ValueFlowSinkSpec>,
    ) -> Result<Self, ValueFlowPlanError> {
        Self::try_new_with_edge_kills(root, snapshots, bindings, sources, sinks, Vec::new())
    }

    pub fn try_new_with_edge_kills(
        root: ProcedureHandle,
        snapshots: Vec<ValueFlowInput<ValueFlowSnapshot>>,
        bindings: Vec<ValueFlowInput<CallBindings>>,
        sources: Vec<ValueFlowSourceSpec>,
        sinks: Vec<ValueFlowSinkSpec>,
        edge_kills: Vec<ValueFlowEdgeKillSpec>,
    ) -> Result<Self, ValueFlowPlanError> {
        Self::with_call_behavior_and_edge_kills(
            root,
            snapshots,
            bindings,
            sources,
            sinks,
            edge_kills,
            UnmodeledCallBehavior::default(),
        )
    }

    pub fn with_call_behavior(
        root: ProcedureHandle,
        snapshots: Vec<ValueFlowInput<ValueFlowSnapshot>>,
        bindings: Vec<ValueFlowInput<CallBindings>>,
        sources: Vec<ValueFlowSourceSpec>,
        sinks: Vec<ValueFlowSinkSpec>,
        unmodeled_call_behavior: UnmodeledCallBehavior,
    ) -> Result<Self, ValueFlowPlanError> {
        Self::with_call_behavior_and_edge_kills(
            root,
            snapshots,
            bindings,
            sources,
            sinks,
            Vec::new(),
            unmodeled_call_behavior,
        )
    }

    pub fn with_call_behavior_and_edge_kills(
        root: ProcedureHandle,
        snapshots: Vec<ValueFlowInput<ValueFlowSnapshot>>,
        bindings: Vec<ValueFlowInput<CallBindings>>,
        sources: Vec<ValueFlowSourceSpec>,
        sinks: Vec<ValueFlowSinkSpec>,
        edge_kills: Vec<ValueFlowEdgeKillSpec>,
        unmodeled_call_behavior: UnmodeledCallBehavior,
    ) -> Result<Self, ValueFlowPlanError> {
        Self::with_limits_and_call_behavior_and_edge_kills(
            root,
            snapshots,
            bindings,
            sources,
            sinks,
            edge_kills,
            ValueFlowPlanLimits::default(),
            unmodeled_call_behavior,
        )
    }

    pub fn with_limits(
        root: ProcedureHandle,
        snapshots: Vec<ValueFlowInput<ValueFlowSnapshot>>,
        bindings: Vec<ValueFlowInput<CallBindings>>,
        sources: Vec<ValueFlowSourceSpec>,
        sinks: Vec<ValueFlowSinkSpec>,
        limits: ValueFlowPlanLimits,
    ) -> Result<Self, ValueFlowPlanError> {
        Self::with_limits_and_call_behavior_and_edge_kills(
            root,
            snapshots,
            bindings,
            sources,
            sinks,
            Vec::new(),
            limits,
            UnmodeledCallBehavior::default(),
        )
    }

    pub fn with_limits_and_call_behavior(
        root: ProcedureHandle,
        snapshots: Vec<ValueFlowInput<ValueFlowSnapshot>>,
        bindings: Vec<ValueFlowInput<CallBindings>>,
        sources: Vec<ValueFlowSourceSpec>,
        sinks: Vec<ValueFlowSinkSpec>,
        limits: ValueFlowPlanLimits,
        unmodeled_call_behavior: UnmodeledCallBehavior,
    ) -> Result<Self, ValueFlowPlanError> {
        Self::with_limits_and_call_behavior_and_edge_kills(
            root,
            snapshots,
            bindings,
            sources,
            sinks,
            Vec::new(),
            limits,
            unmodeled_call_behavior,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_limits_and_call_behavior_and_edge_kills(
        root: ProcedureHandle,
        mut snapshots: Vec<ValueFlowInput<ValueFlowSnapshot>>,
        mut bindings: Vec<ValueFlowInput<CallBindings>>,
        mut sources: Vec<ValueFlowSourceSpec>,
        mut sinks: Vec<ValueFlowSinkSpec>,
        mut edge_kills: Vec<ValueFlowEdgeKillSpec>,
        limits: ValueFlowPlanLimits,
        unmodeled_call_behavior: UnmodeledCallBehavior,
    ) -> Result<Self, ValueFlowPlanError> {
        if sources.len() > limits.max_sources || sinks.len() > limits.max_sinks {
            return Err(ValueFlowPlanError::LimitExceeded);
        }
        if snapshots.iter().any(|input| {
            !input.value().context().calls().is_empty() || input.value().context().was_truncated()
        }) || bindings.iter().any(|input| {
            !input.value().context().calls().is_empty() || input.value().context().was_truncated()
        }) {
            return Err(ValueFlowPlanError::ContextSensitiveInputUnsupported);
        }
        snapshots.sort_by(|left, right| compare_snapshots(left.value(), right.value()));
        bindings.sort_by(|left, right| compare_bindings(left.value(), right.value()));
        sources.sort_by(|left, right| left.key().cmp(right.key()));
        sinks.sort_by(|left, right| left.key().cmp(right.key()));
        for kill in &mut edge_kills {
            kill.sources.sort();
            kill.sources.dedup();
        }
        edge_kills.sort_by(compare_edge_kills);
        edge_kills.dedup();
        if adjacent_duplicate(sources.iter().map(ValueFlowSourceSpec::key))
            || adjacent_duplicate(sinks.iter().map(ValueFlowSinkSpec::key))
        {
            return Err(ValueFlowPlanError::DuplicateEventKey);
        }

        let mount = root.artifact().key().mount();
        let mut discovery_status = SemanticInputStatus::Complete;
        let ambiguous_dispatch = snapshots.iter().any(|input| {
            input
                .value()
                .procedure()
                .semantics()
                .gaps()
                .iter()
                .any(|gap| {
                    gap.kind == SemanticGapKind::Ambiguous
                        && gap.impacts.contains(SemanticGapImpact::DispatchCoverage)
                })
        });
        let mut discovery_complete = true;
        let mut structural_discovery_complete = true;
        let mut first_incomplete_cause: Option<ValueFlowIncompleteCause> = None;
        let mut carrier_candidates = Vec::new();
        let mut relation_count = 0usize;
        let snapshot_procedures = snapshots
            .iter()
            .map(|input| input.value().procedure().clone())
            .collect::<Vec<_>>();
        let binding_pairs = bindings
            .iter()
            .map(|input| (input.value().call().clone(), input.value().callee().clone()))
            .collect::<Vec<_>>();
        // An exhaustive candidate-specific receiver proof may also prove that
        // resolver alternatives cannot be entered by that call. Preserve that
        // negative identity evidence so an endpoint in an excluded anonymous
        // sibling does not make an otherwise closed plan inconclusive. Merely
        // mounting a lexical child still proves nothing: #2640 shapes without
        // this explicit exclusion continue to report an unentered procedure.
        let excluded = bindings
            .iter()
            .filter(|input| {
                input.status().is_complete()
                    && input.value().coverage() == CandidateCoverage::Exhaustive
                    && !input.value().context().was_truncated()
            })
            .flat_map(|input| input.value().candidate().excluded_targets())
            .map(ProcedureHandle::durable_key)
            .collect::<HashSet<_>>();
        let mut non_snapshot_discovery_complete = true;
        let mut endpoint_discovery_complete = true;
        let mut incomplete_binding_calls: Vec<CallSiteHandle> = Vec::new();
        let mut binding_complete = HashMap::<CallSiteHandle, bool>::default();
        for input in &bindings {
            let complete = input.status().is_complete()
                && input.value().coverage() == CandidateCoverage::Exhaustive
                && !input.value().context().was_truncated();
            binding_complete
                .entry(input.value().call().clone())
                .and_modify(|value| *value &= complete)
                .or_insert(complete);
        }
        // The procedures the solve can actually visit (#2640). An IDE solve
        // seeds at the root's entry point and reaches every other procedure
        // through a mounted call binding's flow rules, so a mounted procedure
        // that is neither the root nor any binding's callee holds no reachable
        // program point. A region mounts such a procedure when it is lexically
        // part of the region but nothing in the region dispatches to it: a
        // lambda, closure, or block body whose invocation resolves to an
        // interface method or a runtime block rather than to the body itself.
        // Before nested bodies were mounted, every snapshot was the root or
        // some binding's callee, so this set changes nothing for the plans that
        // already existed.
        //
        // Membership is durable identity -- artifact key plus procedure ID --
        // not handle identity, because a binding's callee handle comes from the
        // oracle and a snapshot's procedure handle from discovery, and the two
        // can name one procedure through two materializations of its file
        // (#2289). Comparing handles would then read a genuinely entered
        // procedure as unreachable and abstain a decidable region.
        let entered = std::iter::once(&root)
            .chain(binding_pairs.iter().map(|(_, callee)| callee))
            .map(ProcedureHandle::durable_key)
            .collect::<HashSet<_>>();
        let mut snapshot_discoveries = Vec::with_capacity(snapshots.len());
        for input in &snapshots {
            validate_mount(input.value().procedure(), mount)?;
            // An unentered procedure's own input quality cannot change a
            // verdict, because no point in it is reachable. Its relations still
            // mount, but it opens no discovery here; otherwise a lambda with an
            // unlowered construct would abstain a region that never runs it.
            // What the region must not do is decide an endpoint bound inside
            // one, and the source and sink loops below catch exactly that.
            let entered_procedure = entered.contains(&input.value().procedure().durable_key());
            // A snapshot left Unknown only by call-target refinement gaps is
            // answered by this plan's own complete resolutions and bindings of
            // exactly those calls (#1952): the refinement the gaps demand has
            // been performed, so the input does not open discovery. Residual
            // refinement calls without a complete binding stay open here and
            // may still be closed by a fully modeled execution boundary.
            let discovery = if !entered_procedure
                || (input.status().is_complete()
                    && input.value().coverage() == CandidateCoverage::Exhaustive)
            {
                SnapshotDiscovery::Complete
            } else if matches!(input.status(), SemanticInputStatus::Unknown)
                && input.value().coverage() == CandidateCoverage::Open
            {
                match classify_snapshot_openness(input.value(), &binding_complete, &sources, &sinks)
                {
                    SnapshotOpenness::Refinable(residual) if residual.is_empty() => {
                        SnapshotDiscovery::Complete
                    }
                    SnapshotOpenness::Refinable(residual) => SnapshotDiscovery::Refinable {
                        calls: residual.into_boxed_slice(),
                    },
                    SnapshotOpenness::Blocked(gap) => SnapshotDiscovery::Incomplete { gap },
                }
            } else {
                SnapshotDiscovery::Incomplete { gap: None }
            };
            let refined = discovery == SnapshotDiscovery::Complete && !input.status().is_complete();
            let complete = discovery == SnapshotDiscovery::Complete;
            if entered_procedure && !refined {
                discovery_status = discovery_status.merge(input.status());
            }
            if first_incomplete_cause.is_none() && !complete {
                first_incomplete_cause = Some(match &discovery {
                    SnapshotDiscovery::Refinable { calls } => {
                        let call = calls
                            .first()
                            .expect("a non-complete refinable snapshot retains a residual call")
                            .clone();
                        ValueFlowIncompleteCause::CallResolution {
                            call,
                            status: input.status(),
                        }
                    }
                    SnapshotDiscovery::Incomplete {
                        gap: Some((gap, capability)),
                    } => ValueFlowIncompleteCause::SemanticGap {
                        gap: gap.clone(),
                        capability: *capability,
                        status: input.status(),
                    },
                    SnapshotDiscovery::Incomplete { gap: None }
                        if !input.status().is_complete() =>
                    {
                        ValueFlowIncompleteCause::Snapshot {
                            procedure: input.value().procedure().clone(),
                            status: input.status(),
                        }
                    }
                    SnapshotDiscovery::Incomplete { gap: None } => {
                        ValueFlowIncompleteCause::SnapshotCoverage {
                            procedure: input.value().procedure().clone(),
                        }
                    }
                    SnapshotDiscovery::Complete => {
                        unreachable!("a complete snapshot discovery cannot be incomplete")
                    }
                });
            }
            snapshot_discoveries.push(discovery);
            discovery_complete &= complete;
            relation_count = relation_count.saturating_add(input.value().relations().len());
            for relation in input.value().relations() {
                carrier_candidates.push(ValueFlowCarrier::from(&relation.source));
                carrier_candidates.push(ValueFlowCarrier::from(&relation.target));
            }
        }
        for input in &bindings {
            validate_mount(input.value().call().procedure(), mount)?;
            validate_mount(input.value().callee(), mount)?;
            discovery_status = discovery_status.merge(input.status());
            if first_incomplete_cause.is_none() {
                if !input.status().is_complete() {
                    first_incomplete_cause = Some(ValueFlowIncompleteCause::CallBinding {
                        call: input.value().call().clone(),
                        callee: input.value().callee().clone(),
                        status: input.status(),
                    });
                } else if input.value().coverage() != CandidateCoverage::Exhaustive
                    || input.value().context().was_truncated()
                {
                    first_incomplete_cause = Some(ValueFlowIncompleteCause::CallBindingCoverage {
                        call: input.value().call().clone(),
                        callee: input.value().callee().clone(),
                    });
                }
            }
            let complete = input.status().is_complete()
                && input.value().coverage() == CandidateCoverage::Exhaustive
                && !input.value().context().was_truncated();
            non_snapshot_discovery_complete &= complete;
            if !complete
                && !incomplete_binding_calls
                    .iter()
                    .any(|call| compare_calls(call, input.value().call()) == Ordering::Equal)
            {
                incomplete_binding_calls.push(input.value().call().clone());
            }
            discovery_complete &= complete;
            structural_discovery_complete &= !input.value().context().was_truncated();
            for binding in input.value().bindings() {
                relation_count = relation_count.saturating_add(call_binding_rule_count(binding));
                append_binding_carriers(binding, &mut carrier_candidates)?;
            }
        }
        // An endpoint observed in a procedure the solve cannot enter was not
        // analyzed: a sink there can never report, and calling the region clean
        // would claim a verdict for a site the solve never visited (#2640).
        for source in &sources {
            validate_event(source.point(), source.carrier(), mount)?;
            let evidence_complete = matches!(source.proof(), ProofStatus::Proven)
                && matches!(source.completeness(), EvidenceCompleteness::Complete);
            let entered_procedure = entered.contains(&source.point().procedure().durable_key());
            let excluded_procedure = excluded.contains(&source.point().procedure().durable_key());
            if first_incomplete_cause.is_none() {
                if !evidence_complete {
                    first_incomplete_cause = Some(ValueFlowIncompleteCause::SourceEvidence {
                        point: source.point().clone(),
                    });
                } else if !entered_procedure && !excluded_procedure {
                    first_incomplete_cause = Some(ValueFlowIncompleteCause::UnenteredProcedure {
                        procedure: source.point().procedure().clone(),
                    });
                }
            }
            let complete = evidence_complete && (entered_procedure || excluded_procedure);
            non_snapshot_discovery_complete &= complete;
            endpoint_discovery_complete &= complete;
            discovery_complete &= complete;
            structural_discovery_complete &= evidence_complete;
            carrier_candidates.push(source.carrier().clone());
        }
        for sink in &sinks {
            validate_event(sink.point(), sink.carrier(), mount)?;
            let evidence_complete = matches!(sink.proof(), ProofStatus::Proven)
                && matches!(sink.completeness(), EvidenceCompleteness::Complete);
            let entered_procedure = entered.contains(&sink.point().procedure().durable_key());
            let excluded_procedure = excluded.contains(&sink.point().procedure().durable_key());
            if first_incomplete_cause.is_none() {
                if !evidence_complete {
                    first_incomplete_cause = Some(ValueFlowIncompleteCause::SinkEvidence {
                        point: sink.point().clone(),
                    });
                } else if !entered_procedure && !excluded_procedure {
                    first_incomplete_cause = Some(ValueFlowIncompleteCause::UnenteredProcedure {
                        procedure: sink.point().procedure().clone(),
                    });
                }
            }
            let complete = evidence_complete && (entered_procedure || excluded_procedure);
            non_snapshot_discovery_complete &= complete;
            endpoint_discovery_complete &= complete;
            discovery_complete &= complete;
            structural_discovery_complete &= evidence_complete;
            carrier_candidates.push(sink.carrier().clone());
        }
        for kill in &edge_kills {
            validate_event(&kill.point, &kill.carrier, mount)?;
            let edge_exists = kill
                .point
                .procedure()
                .semantics()
                .successor_edges(kill.point.id())
                .any(|(_, edge)| edge.target_point == kill.target && edge.kind == kill.kind);
            if !edge_exists
                || kill.sources.is_empty()
                || kill.sources.iter().any(|key| {
                    sources
                        .binary_search_by(|source| source.key().cmp(key))
                        .is_err()
                })
            {
                return Err(ValueFlowPlanError::InvalidEdgeKill);
            }
            carrier_candidates.push(kill.carrier.clone());
        }
        if relation_count > limits.max_relations {
            return Err(ValueFlowPlanError::LimitExceeded);
        }
        debug_assert_eq!(
            first_incomplete_cause.is_some(),
            !discovery_complete,
            "the retained cause and discovery completeness must agree"
        );

        let CarrierIndex {
            carriers,
            carrier_keys,
            carrier_ids,
        } = assign_carrier_ids(carrier_candidates, limits.max_carriers)?;

        let mut local_rules = Vec::new();
        for input in snapshots {
            let (snapshot, _) = input.into_parts();
            for relation in snapshot.relations() {
                local_rules.push(LocalFlowRule {
                    point: relation.point().clone(),
                    event_index: relation.event_index(),
                    kind: relation.kind,
                    transfer: relation.transfer,
                    source: lookup_carrier(&carrier_ids, &relation.source)?,
                    target: lookup_carrier(&carrier_ids, &relation.target)?,
                    proof: relation.proof.clone(),
                    completeness: relation.completeness.clone(),
                    strong_update: relation.strong_update,
                });
            }
        }
        local_rules.sort_by(compare_local_rules);

        let mut call_rules = Vec::new();
        for input in bindings {
            let (bindings, _) = input.into_parts();
            append_call_rules(&bindings, &carrier_ids, &mut call_rules)?;
        }
        call_rules.sort_by(compare_call_rules);
        call_rules.dedup_by(|left, right| {
            left.call == right.call
                && left.callee == right.callee
                && left.kind == right.kind
                && left.source == right.source
                && left.target == right.target
                && left.proof == right.proof
                && left.completeness == right.completeness
        });

        let carrier_components = build_carrier_components(carriers.len(), &local_rules);
        let fallback_locations =
            build_fallback_location_index(&carriers, &carrier_ids, &carrier_components);
        let fallback_profiles = build_call_fallback_profiles(
            std::iter::once(&root)
                .chain(snapshot_procedures.iter())
                .collect::<Vec<_>>(),
            &carrier_ids,
            &carrier_components,
        );

        let bound_sources = sources
            .into_iter()
            .enumerate()
            .map(|(index, spec)| {
                Ok(BoundValueFlowSource {
                    id: ValueFlowSourceId::try_from_index(index)
                        .map_err(|_| ValueFlowPlanError::SourceIdOverflow)?,
                    carrier: *carrier_ids
                        .get(spec.carrier())
                        .ok_or(ValueFlowPlanError::MissingCarrier)?,
                    spec,
                })
            })
            .collect::<Result<Vec<_>, ValueFlowPlanError>>()?;
        let bound_sinks = sinks
            .into_iter()
            .enumerate()
            .map(|(index, spec)| {
                Ok(BoundValueFlowSink {
                    id: ValueFlowSinkId::try_from_index(index)
                        .map_err(|_| ValueFlowPlanError::SinkIdOverflow)?,
                    carrier: *carrier_ids
                        .get(spec.carrier())
                        .ok_or(ValueFlowPlanError::MissingCarrier)?,
                    spec,
                })
            })
            .collect::<Result<Vec<_>, ValueFlowPlanError>>()?;
        let edge_kill_index = build_edge_kill_index(&edge_kills, &carrier_ids, &bound_sources)?;

        let local_rule_reverse_index = build_local_rule_reverse_index(&local_rules);
        let call_rule_reverse_index = build_call_rule_reverse_index(&call_rules);
        let source_index = build_observation_index(&bound_sources, |source| ObservationKey {
            point: source.spec.point().clone(),
            phase: source.spec.phase(),
        });
        let sink_index = build_observation_index(&bound_sinks, |sink| ObservationKey {
            point: sink.spec.point().clone(),
            phase: sink.spec.phase(),
        });
        let infeasible_points =
            constant_infeasible_points(std::iter::once(&root).chain(snapshot_procedures.iter()));
        Ok(Self {
            root,
            unmodeled_call_behavior,
            external_summaries: ExternalSemanticSummarySet::default(),
            curated_call_models: Box::default(),
            carriers: carriers.into_boxed_slice(),
            carrier_keys: carrier_keys.into_boxed_slice(),
            carrier_ids,
            local_rules: local_rules.into_boxed_slice(),
            local_rule_reverse_index,
            call_rules: call_rules.into_boxed_slice(),
            call_rule_reverse_index,
            fallback_profiles: fallback_profiles.into_boxed_slice(),
            fallback_locations,
            summary_location_bindings: Box::default(),
            sources: bound_sources.into_boxed_slice(),
            source_index,
            sinks: bound_sinks.into_boxed_slice(),
            sink_index,
            edge_kills: edge_kills.into_boxed_slice(),
            edge_kill_index,
            infeasible_points,
            snapshot_procedures: snapshot_procedures.into_boxed_slice(),
            binding_pairs: binding_pairs.into_boxed_slice(),
            discovery_status,
            first_incomplete_cause,
            snapshot_discoveries: snapshot_discoveries.into_boxed_slice(),
            non_snapshot_discovery_complete,
            endpoint_discovery_complete,
            incomplete_binding_calls: incomplete_binding_calls.into_boxed_slice(),
            ambiguous_dispatch,
            discovery_complete,
            structural_discovery_complete,
            owner: Arc::new(()),
        })
    }

    pub fn root(&self) -> &ProcedureHandle {
        &self.root
    }

    /// Visit every concrete semantic artifact allocation retained by handles
    /// in this immutable plan. Duplicate allocations are intentional: bounded
    /// host registries deduplicate them while accounting and validating.
    pub fn for_each_retained_artifact(&self, mut visit: impl FnMut(&Arc<SemanticArtifact>)) {
        visit(self.root.artifact());
        for procedure in &self.snapshot_procedures {
            visit(procedure.artifact());
        }
        for (call, callee) in &self.binding_pairs {
            visit(call.procedure().artifact());
            visit(callee.artifact());
        }
        for carrier in &self.carriers {
            carrier.for_each_retained_artifact(&mut visit);
        }
        for rule in &self.local_rules {
            visit(rule.point.procedure().artifact());
        }
        for rule in &self.call_rules {
            visit(rule.call.procedure().artifact());
            visit(rule.callee.artifact());
        }
        for profile in &self.fallback_profiles {
            visit(profile.call.procedure().artifact());
        }
        for model in &self.curated_call_models {
            visit(model.call.procedure().artifact());
        }
        for binding in &self.summary_location_bindings {
            visit(binding.call.procedure().artifact());
        }
        for source in &self.sources {
            visit(source.spec.point().procedure().artifact());
        }
        for sink in &self.sinks {
            visit(sink.spec.point().procedure().artifact());
        }
        for kill in &self.edge_kills {
            visit(kill.point.procedure().artifact());
            kill.carrier.for_each_retained_artifact(&mut visit);
        }
        if let Some(cause) = &self.first_incomplete_cause {
            visit(cause.procedure().artifact());
            if let ValueFlowIncompleteCause::CallResolution { call, .. }
            | ValueFlowIncompleteCause::CallBinding { call, .. }
            | ValueFlowIncompleteCause::CallBindingCoverage { call, .. } = cause
            {
                visit(call.procedure().artifact());
            }
        }
    }

    /// Visit every semantic artifact identity retained by this plan.
    pub fn for_each_retained_artifact_key(&self, mut visit: impl FnMut(&SemanticArtifactKey)) {
        self.for_each_retained_artifact(|artifact| visit(artifact.key()));
    }

    /// Conservative retained size of plan-owned metadata, excluding semantic
    /// artifact allocations which host registries account separately.
    pub fn retained_bytes(&self) -> usize {
        let carrier_key_bytes = self
            .carrier_keys
            .iter()
            .map(ValueFlowCarrierKey::retained_bytes)
            .fold(0usize, usize::saturating_add);
        let local_rule_heap = self.local_rules.iter().fold(0usize, |total, rule| {
            total
                .saturating_add(proof_heap_bytes(&rule.proof))
                .saturating_add(completeness_heap_bytes(&rule.completeness))
        });
        let call_rule_heap = self.call_rules.iter().fold(0usize, |total, rule| {
            total
                .saturating_add(proof_heap_bytes(&rule.proof))
                .saturating_add(completeness_heap_bytes(&rule.completeness))
        });
        let source_heap = self.sources.iter().fold(0usize, |total, source| {
            total
                .saturating_add(source.spec.key().retained_bytes())
                .saturating_add(self.carrier_keys[source.carrier.index()].retained_bytes())
                .saturating_add(proof_heap_bytes(source.spec.proof()))
                .saturating_add(completeness_heap_bytes(source.spec.completeness()))
        });
        let sink_heap = self.sinks.iter().fold(0usize, |total, sink| {
            total
                .saturating_add(sink.spec.key().retained_bytes())
                .saturating_add(self.carrier_keys[sink.carrier.index()].retained_bytes())
                .saturating_add(proof_heap_bytes(sink.spec.proof()))
                .saturating_add(completeness_heap_bytes(sink.spec.completeness()))
        });
        let edge_kill_heap = self.edge_kills.iter().fold(0usize, |total, kill| {
            total
                .saturating_add(
                    kill.sources
                        .iter()
                        .map(ValueFlowEventKey::retained_bytes)
                        .fold(0usize, usize::saturating_add),
                )
                .saturating_add(
                    kill.carrier
                        .stable_key()
                        .map_or(0, |key| key.retained_bytes()),
                )
        });

        std::mem::size_of::<Self>()
            .saturating_add(self.external_summaries.retained_heap_bytes())
            .saturating_add(size_of_val(self.curated_call_models.as_ref()))
            .saturating_add(
                self.curated_call_models
                    .iter()
                    .map(|model| model.model.retained_heap_bytes())
                    .fold(0usize, usize::saturating_add),
            )
            .saturating_add(size_of_val(self.carriers.as_ref()))
            // Locations own an access path in addition to the carrier enum.
            // Its stable key is a conservative structural estimate of that path.
            .saturating_add(carrier_key_bytes)
            .saturating_add(size_of_val(self.carrier_keys.as_ref()))
            .saturating_add(carrier_key_bytes)
            .saturating_add(
                self.carrier_ids
                    .capacity()
                    .saturating_mul(
                        std::mem::size_of::<(ValueFlowCarrier, ValueFlowCarrierId)>()
                            .saturating_add(1),
                    )
                    // The map clones every carrier; charge the structural keys
                    // again to conservatively cover cloned locations.
                    .saturating_add(carrier_key_bytes),
            )
            .saturating_add(size_of_val(self.local_rules.as_ref()))
            .saturating_add(local_rule_heap)
            .saturating_add(self.local_rule_reverse_index.retained_heap_bytes())
            .saturating_add(size_of_val(self.call_rules.as_ref()))
            .saturating_add(call_rule_heap)
            .saturating_add(self.call_rule_reverse_index.retained_heap_bytes())
            .saturating_add(size_of_val(self.fallback_profiles.as_ref()))
            .saturating_add(
                self.fallback_profiles
                    .iter()
                    .map(|profile| {
                        size_of_val(profile.inputs.as_ref())
                            .saturating_add(size_of_val(profile.reachable_components.as_ref()))
                    })
                    .fold(0usize, usize::saturating_add),
            )
            .saturating_add(self.fallback_locations.retained_heap_bytes())
            .saturating_add(size_of_val(self.summary_location_bindings.as_ref()))
            .saturating_add(size_of_val(self.sources.as_ref()))
            .saturating_add(self.source_index.retained_heap_bytes())
            .saturating_add(source_heap)
            .saturating_add(size_of_val(self.sinks.as_ref()))
            .saturating_add(self.sink_index.retained_heap_bytes())
            .saturating_add(sink_heap)
            .saturating_add(size_of_val(self.edge_kills.as_ref()))
            .saturating_add(edge_kill_heap)
            .saturating_add(self.edge_kill_index.retained_heap_bytes())
            .saturating_add(size_of_val(self.snapshot_procedures.as_ref()))
            .saturating_add(size_of_val(self.binding_pairs.as_ref()))
            // Account for the plan-ownership Arc allocation and reference counts.
            .saturating_add(
                std::mem::size_of::<usize>()
                    .saturating_mul(2)
                    .saturating_add(1),
            )
    }

    pub const fn unmodeled_call_behavior(&self) -> UnmodeledCallBehavior {
        self.unmodeled_call_behavior
    }

    /// Install complete external semantic summaries used before the configured
    /// fallback profile. The set owns its content-addressed validity identity,
    /// so changing a model partitions value-flow and downstream taint caches.
    pub fn with_external_summaries(
        mut self,
        summaries: ExternalSemanticSummarySet,
    ) -> Result<Self, ValueFlowPlanError> {
        if summaries.compatibility().is_some_and(|compatibility| {
            compatibility.unmodeled_call_behavior() != self.unmodeled_call_behavior
                || compatibility.dependencies() != self.root.artifact().key().dependencies()
        }) {
            return Err(ValueFlowPlanError::IncompatibleExternalSummary);
        }
        self.external_summaries = summaries;
        Ok(self)
    }

    pub const fn external_summaries(&self) -> &ExternalSemanticSummarySet {
        &self.external_summaries
    }

    /// Install selector-bound curated models, merging with any models already
    /// installed (external-model and persistence-store declarations each
    /// contribute their own). Exactly one model may own a call site -- two
    /// declarations claiming one call, within or across categories, are a
    /// duplicate -- and exact target summaries are still selected first
    /// during transfer.
    pub fn with_curated_call_models(
        mut self,
        mut models: Vec<ValueFlowCuratedCallModel>,
    ) -> Result<Self, ValueFlowPlanError> {
        let mount = self.root.artifact().key().mount();
        for model in &models {
            validate_mount(model.call.procedure(), mount)?;
            if model
                .call
                .procedure()
                .semantics()
                .call_site(model.call.id())
                .is_none()
            {
                return Err(ValueFlowPlanError::StaleCallModel);
            }
        }
        models.extend(self.curated_call_models.iter().cloned());
        models.sort_by(|left, right| compare_calls(&left.call, &right.call));
        if models.windows(2).any(|pair| pair[0].call == pair[1].call) {
            return Err(ValueFlowPlanError::DuplicateCallModel);
        }
        self.curated_call_models = models.into_boxed_slice();
        Ok(self)
    }

    /// Bind the stable heap/capture ports referenced by exact or curated
    /// models. The carriers must already belong to the demand-driven plan.
    pub fn with_summary_location_bindings(
        mut self,
        mut bindings: Vec<ValueFlowSummaryLocationBinding>,
    ) -> Result<Self, ValueFlowPlanError> {
        if bindings.len() > MAX_SUMMARY_BOUNDARY_BINDINGS {
            return Err(ValueFlowPlanError::LimitExceeded);
        }
        let mount = self.root.artifact().key().mount();
        for binding in &bindings {
            validate_mount(binding.call.procedure(), mount)?;
            if !matches!(binding.port, SummaryPort::Capture(_) | SummaryPort::Heap(_)) {
                return Err(ValueFlowPlanError::InvalidSummaryLocationPort);
            }
        }
        bindings.sort_by(|left, right| {
            compare_calls(&left.call, &right.call).then_with(|| left.port.cmp(&right.port))
        });
        if bindings
            .windows(2)
            .any(|pair| pair[0].call == pair[1].call && pair[0].port == pair[1].port)
        {
            return Err(ValueFlowPlanError::DuplicateSummaryLocationBinding);
        }
        self.summary_location_bindings = bindings
            .into_iter()
            .map(|binding| {
                Ok(BoundSummaryLocationBinding {
                    call: binding.call,
                    port: binding.port,
                    carrier: self
                        .carrier_id(&binding.carrier)
                        .ok_or(ValueFlowPlanError::MissingCarrier)?,
                })
            })
            .collect::<Result<Vec<_>, ValueFlowPlanError>>()?
            .into_boxed_slice();
        Ok(self)
    }

    pub fn carriers(&self) -> &[ValueFlowCarrier] {
        &self.carriers
    }

    pub fn carrier(&self, id: ValueFlowCarrierId) -> Option<&ValueFlowCarrier> {
        self.carriers.get(id.index())
    }

    pub fn carrier_key(&self, id: ValueFlowCarrierId) -> Option<&ValueFlowCarrierKey> {
        self.carrier_keys.get(id.index())
    }

    pub(crate) fn carrier_id_for_key(
        &self,
        key: &ValueFlowCarrierKey,
    ) -> Option<ValueFlowCarrierId> {
        self.carrier_keys
            .binary_search(key)
            .ok()
            .and_then(|index| ValueFlowCarrierId::try_from_index(index).ok())
    }

    pub(crate) fn sink_id_for_key(
        &self,
        key: &super::ValueFlowEventKey,
    ) -> Option<ValueFlowSinkId> {
        self.sinks
            .binary_search_by(|sink| sink.spec.key().cmp(key))
            .ok()
            .map(|index| self.sinks[index].id)
    }

    pub(crate) fn source_id_for_key(
        &self,
        key: &super::ValueFlowEventKey,
    ) -> Option<ValueFlowSourceId> {
        self.sources
            .binary_search_by(|source| source.spec.key().cmp(key))
            .ok()
            .map(|index| self.sources[index].id)
    }

    /// Hash only the transfer semantics that determine propagation. Source and
    /// sink observations are deliberately excluded so compatible clients can
    /// union their demand sets and share one fixed-point solve.
    pub fn propagation_semantics_hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.root.hash(state);
        self.unmodeled_call_behavior.hash(state);
        self.external_summaries.fingerprint().hash(state);
        self.curated_call_models.len().hash(state);
        for model in &self.curated_call_models {
            model.call.hash(state);
            model.model.fingerprint().hash(state);
        }
        for rule in &self.local_rules {
            rule.point.hash(state);
            rule.event_index.hash(state);
            rule.kind.hash(state);
            rule.transfer.hash(state);
            self.carrier_keys[rule.source.index()].hash(state);
            self.carrier_keys[rule.target.index()].hash(state);
            rule.proof.hash(state);
            rule.completeness.hash(state);
            rule.strong_update.hash(state);
        }
        for rule in &self.call_rules {
            rule.call.hash(state);
            rule.callee.hash(state);
            rule.kind.hash(state);
            self.carrier_keys[rule.source.index()].hash(state);
            self.carrier_keys[rule.target.index()].hash(state);
            rule.proof.hash(state);
            rule.completeness.hash(state);
        }
        for binding in &self.summary_location_bindings {
            binding.call.hash(state);
            binding.port.hash(state);
            self.carrier_keys[binding.carrier.index()].hash(state);
        }
        for kill in &self.edge_kills {
            kill.point.hash(state);
            kill.target.hash(state);
            kill.kind.hash(state);
            self.carrier_ids
                .get(&kill.carrier)
                .map(|id| &self.carrier_keys[id.index()])
                .expect("a validated edge-kill carrier is bound")
                .hash(state);
            kill.sources.hash(state);
        }
        self.snapshot_procedures.hash(state);
        self.binding_pairs.hash(state);
        self.discovery_status.hash(state);
        self.discovery_complete.hash(state);
        self.structural_discovery_complete.hash(state);
    }

    pub(crate) fn has_same_propagation_semantics(&self, other: &Self) -> bool {
        self.root == other.root
            && self.unmodeled_call_behavior == other.unmodeled_call_behavior
            && self.external_summaries == other.external_summaries
            && self.curated_call_models == other.curated_call_models
            && same_local_rules(self, other)
            && same_call_rules(self, other)
            && same_summary_location_bindings(self, other)
            && self.edge_kills == other.edge_kills
            && self.snapshot_procedures == other.snapshot_procedures
            && self.binding_pairs == other.binding_pairs
            && self.discovery_status == other.discovery_status
            && self.discovery_complete == other.discovery_complete
            && self.structural_discovery_complete == other.structural_discovery_complete
    }

    /// Union endpoint observations from transfer-compatible plans and rebind
    /// their dense carrier/source/sink IDs once. This is the only supported
    /// path for sharing propagation across different policy demand sets.
    pub(crate) fn union_observations(plans: &[&Self]) -> Result<Self, ValueFlowPlanError> {
        let first = plans.first().ok_or(ValueFlowPlanError::MissingCarrier)?;
        if plans
            .iter()
            .skip(1)
            .any(|plan| !first.has_same_propagation_semantics(plan))
        {
            return Err(ValueFlowPlanError::IncompatibleObservationUnion);
        }

        let CarrierIndex {
            carriers,
            carrier_keys,
            carrier_ids,
        } = assign_carrier_ids(
            plans
                .iter()
                .flat_map(|plan| plan.carriers.iter().cloned())
                .collect(),
            MAX_VALUE_FLOW_CARRIERS,
        )?;
        let remap = |id: ValueFlowCarrierId| {
            carrier_ids
                .get(&first.carriers[id.index()])
                .copied()
                .ok_or(ValueFlowPlanError::MissingCarrier)
        };
        let mut local_rules = first.local_rules.to_vec();
        for rule in &mut local_rules {
            rule.source = remap(rule.source)?;
            rule.target = remap(rule.target)?;
        }
        let mut call_rules = first.call_rules.to_vec();
        for rule in &mut call_rules {
            rule.source = remap(rule.source)?;
            rule.target = remap(rule.target)?;
        }
        let mut summary_location_bindings = first.summary_location_bindings.to_vec();
        for binding in &mut summary_location_bindings {
            binding.carrier = remap(binding.carrier)?;
        }

        let mut source_specs = plans
            .iter()
            .flat_map(|plan| plan.sources.iter().map(|source| source.spec.clone()))
            .collect::<Vec<_>>();
        source_specs.sort_by(|left, right| left.key().cmp(right.key()));
        source_specs.dedup();
        if source_specs.len() > MAX_VALUE_FLOW_SOURCES
            || source_specs
                .windows(2)
                .any(|pair| pair[0].key() == pair[1].key())
        {
            return Err(ValueFlowPlanError::DuplicateEventKey);
        }
        let sources = source_specs
            .into_iter()
            .enumerate()
            .map(|(index, spec)| {
                Ok(BoundValueFlowSource {
                    id: ValueFlowSourceId::try_from_index(index)
                        .map_err(|_| ValueFlowPlanError::SourceIdOverflow)?,
                    carrier: *carrier_ids
                        .get(spec.carrier())
                        .ok_or(ValueFlowPlanError::MissingCarrier)?,
                    spec,
                })
            })
            .collect::<Result<Vec<_>, ValueFlowPlanError>>()?;
        let mut sink_specs = plans
            .iter()
            .flat_map(|plan| plan.sinks.iter().map(|sink| sink.spec.clone()))
            .collect::<Vec<_>>();
        sink_specs.sort_by(|left, right| left.key().cmp(right.key()));
        sink_specs.dedup();
        if sink_specs.len() > MAX_VALUE_FLOW_SINKS
            || sink_specs
                .windows(2)
                .any(|pair| pair[0].key() == pair[1].key())
        {
            return Err(ValueFlowPlanError::DuplicateEventKey);
        }
        let sinks = sink_specs
            .into_iter()
            .enumerate()
            .map(|(index, spec)| {
                Ok(BoundValueFlowSink {
                    id: ValueFlowSinkId::try_from_index(index)
                        .map_err(|_| ValueFlowPlanError::SinkIdOverflow)?,
                    carrier: *carrier_ids
                        .get(spec.carrier())
                        .ok_or(ValueFlowPlanError::MissingCarrier)?,
                    spec,
                })
            })
            .collect::<Result<Vec<_>, ValueFlowPlanError>>()?;

        let carrier_components = build_carrier_components(carriers.len(), &local_rules);
        let fallback_locations =
            build_fallback_location_index(&carriers, &carrier_ids, &carrier_components);
        let fallback_profiles = build_call_fallback_profiles(
            std::iter::once(&first.root)
                .chain(first.snapshot_procedures.iter())
                .collect::<Vec<_>>(),
            &carrier_ids,
            &carrier_components,
        );
        let local_rule_reverse_index = build_local_rule_reverse_index(&local_rules);
        let call_rule_reverse_index = build_call_rule_reverse_index(&call_rules);
        let source_index = build_observation_index(&sources, |source| ObservationKey {
            point: source.spec.point().clone(),
            phase: source.spec.phase(),
        });
        let sink_index = build_observation_index(&sinks, |sink| ObservationKey {
            point: sink.spec.point().clone(),
            phase: sink.spec.phase(),
        });
        let edge_kill_index = build_edge_kill_index(&first.edge_kills, &carrier_ids, &sources)?;

        Ok(Self {
            root: first.root.clone(),
            unmodeled_call_behavior: first.unmodeled_call_behavior,
            external_summaries: first.external_summaries.clone(),
            curated_call_models: first.curated_call_models.clone(),
            carriers: carriers.into_boxed_slice(),
            carrier_keys: carrier_keys.into_boxed_slice(),
            carrier_ids,
            local_rules: local_rules.into_boxed_slice(),
            local_rule_reverse_index,
            call_rules: call_rules.into_boxed_slice(),
            call_rule_reverse_index,
            fallback_profiles: fallback_profiles.into_boxed_slice(),
            fallback_locations,
            summary_location_bindings: summary_location_bindings.into_boxed_slice(),
            sources: sources.into_boxed_slice(),
            source_index,
            sinks: sinks.into_boxed_slice(),
            sink_index,
            edge_kills: first.edge_kills.clone(),
            edge_kill_index,
            infeasible_points: first.infeasible_points.clone(),
            snapshot_procedures: first.snapshot_procedures.clone(),
            binding_pairs: first.binding_pairs.clone(),
            discovery_status: first.discovery_status,
            first_incomplete_cause: plans
                .iter()
                .find_map(|plan| plan.first_incomplete_cause.clone()),
            snapshot_discoveries: first.snapshot_discoveries.clone(),
            non_snapshot_discovery_complete: plans
                .iter()
                .all(|plan| plan.non_snapshot_discovery_complete),
            endpoint_discovery_complete: plans.iter().all(|plan| plan.endpoint_discovery_complete),
            incomplete_binding_calls: {
                let mut calls: Vec<CallSiteHandle> = Vec::new();
                for plan in plans {
                    for call in plan.incomplete_binding_calls.iter() {
                        if !calls
                            .iter()
                            .any(|known| compare_calls(known, call) == Ordering::Equal)
                        {
                            calls.push(call.clone());
                        }
                    }
                }
                calls.sort_by(compare_calls);
                calls.into_boxed_slice()
            },
            ambiguous_dispatch: plans.iter().any(|plan| plan.ambiguous_dispatch),
            discovery_complete: plans.iter().all(|plan| plan.discovery_complete),
            structural_discovery_complete: plans
                .iter()
                .all(|plan| plan.structural_discovery_complete),
            owner: Arc::new(()),
        })
    }

    pub fn carrier_id(&self, carrier: &ValueFlowCarrier) -> Option<ValueFlowCarrierId> {
        self.carrier_ids.get(carrier).copied()
    }

    pub const fn discovery_status(&self) -> SemanticInputStatus {
        self.discovery_status
    }

    /// The first discovery input, in the plan's deterministic input order, that
    /// prevented `discovery_complete` (#1952). `None` exactly when discovery is
    /// complete.
    pub const fn first_incomplete_cause(&self) -> Option<&ValueFlowIncompleteCause> {
        self.first_incomplete_cause.as_ref()
    }

    pub const fn has_ambiguous_dispatch(&self) -> bool {
        self.ambiguous_dispatch
    }

    pub const fn discovery_complete(&self) -> bool {
        self.discovery_complete
    }

    pub(crate) fn owner(&self) -> &Arc<()> {
        &self.owner
    }

    /// Whether every row this run reached sits in a procedure this plan has a
    /// snapshot for, with every call at that point either bound by this plan or
    /// fully modeled by this result's boundaries.
    ///
    /// This quantifier ranges over `result.reached()`, so a result with fewer
    /// rows satisfies it more easily. That matters because a reuse-backed solve
    /// really does have fewer: binding a reusable summary for a callee replaces
    /// the callee's whole body, so nothing that callee calls is entered and the
    /// subtree contributes no reached row and no coverage row (#2291).
    ///
    /// A replay therefore cannot report a completeness the fresh solve refuses,
    /// but not because of anything in this predicate. Two properties of the
    /// summary itself carry it, and #2296 constructed the three subtree shapes
    /// -- an unmodeled dispatch boundary, an unproven relation, a capability
    /// gap -- that would otherwise break it.
    ///
    /// First, a summary exists only because some solve reported itself complete.
    /// `solve_taint_with_reusable_summaries` in
    /// `crate::taint::summary` returns
    /// `TaintTransferSummaryCacheStatus::Incomplete` and publishes nothing when
    /// its own result's `is_complete()` is false, and
    /// `project_complete_taint_summaries` refuses the projection for the same
    /// reason. That verdict is this predicate, applied by a solve that did walk
    /// the subtree. So the subtree's state is recorded in the summary's
    /// existence, not in the rows the replay drops.
    ///
    /// Second, the summary is looked up under a key that pins the analysis
    /// inputs of that subtree. The taint summary key carries a dependency
    /// contract: the transitive closure of the summarized procedure's declared
    /// dependencies, each with the value-flow carrier identity this plan would
    /// give it (`Self::carrier_summary_identities`), which includes the curated
    /// call models, external summary fingerprints, snapshot presence, local and
    /// call rules, and unmodeled call behavior that decide whether a construct
    /// in that subtree is discharged. A summary published under a plan that
    /// models the subtree cannot be bound by a plan that does not.
    ///
    /// Both rest on the dependency closure naming what the body calls. When it
    /// does not, the solver refuses the summary rather than trusting it: see
    /// `SummaryCalledProcedures` in `crate::dataflow`. The tests that
    /// pin all of this are in `tests/suite_semantic/taint_client.rs`, named for
    /// the three subtree shapes.
    ///
    /// One coverage-derived projection does diverge, deliberately and
    /// documented: `Self::public_semantic_status` merges retained semantic
    /// boundary statuses without applying the models that discharge them, so a
    /// replay that retained no boundary reports `Complete` where the fresh
    /// solve reports the subtree's raw status. No reuse-backed consumer reads
    /// it today -- the CodeQuery value-flow search paths that do solve through
    /// the non-reusable entry point -- and
    /// `a_modeled_subtree_construct_reuses_a_non_leaf_callee_without_claiming_more_completeness`
    /// fails if that changes.
    fn execution_discovery_modeled<Fact>(
        &self,
        result: &SummaryDataflowResult<Fact>,
        requirement: SummaryProofRequirement,
    ) -> bool {
        self.structural_discovery_complete
            && result.reached().iter().all(|reached| {
                let procedure = reached.point().procedure();
                self.has_snapshot(procedure)
                    && procedure
                        .semantics()
                        .point(reached.point().id())
                        .is_some_and(|point| {
                            point.events.iter().all(|event| match event.effect {
                                SemanticEffect::Invoke { call_site } => {
                                    procedure.call_site_handle(call_site).is_some_and(|call| {
                                        self.has_binding_for_call(&call)
                                            || self.call_boundaries_are_fully_modeled(
                                                result,
                                                &call,
                                                requirement,
                                            )
                                    })
                                }
                                _ => true,
                            })
                        })
            })
    }

    pub(crate) fn execution_result_complete<Fact>(
        &self,
        result: &SummaryDataflowResult<Fact>,
    ) -> bool {
        self.execution_result_modeled(result, SummaryProofRequirement::Derived)
    }

    /// Whether the run is complete once authored-complete external procedure
    /// summaries are accepted as closing their boundaries. A run that is already
    /// complete on derived proof also satisfies this, so callers that want the
    /// distinct `ProvenBySummary` case must additionally require
    /// `!execution_result_complete`.
    pub(crate) fn execution_result_complete_accepting_authored_summaries<Fact>(
        &self,
        result: &SummaryDataflowResult<Fact>,
    ) -> bool {
        self.execution_result_modeled(result, SummaryProofRequirement::AcceptAuthoredComplete)
    }

    /// Whether this run terminated precisely and every open edge and boundary
    /// it retained is discharged.
    ///
    /// Like `Self::execution_discovery_modeled`, every quantifier here ranges
    /// over rows a reuse-backed solve can be missing: `result.coverage()` is
    /// accumulated as the solver walks edges and materializes call transfers,
    /// so a skipped subtree contributes no unproven edge, no partial edge, and
    /// no boundary. See that function's comment for why a replay still cannot
    /// claim a completeness the fresh solve refuses (#2296), and for the one
    /// coverage-derived projection that does diverge.
    fn execution_result_modeled<Fact>(
        &self,
        result: &SummaryDataflowResult<Fact>,
        requirement: SummaryProofRequirement,
    ) -> bool {
        if !result.termination().is_fixed_point()
            || !self.execution_discovery_modeled(result, requirement)
            || !self.discovery_closed_by(result, requirement)
        {
            return false;
        }
        let fully_modeled_calls = result
            .coverage()
            .boundaries()
            .iter()
            .filter_map(SummaryBoundary::origin)
            .filter(|call| self.call_boundaries_are_fully_modeled(result, call, requirement))
            .collect::<Vec<_>>();
        let abort_paths_only_unwind = std::cell::OnceCell::new();
        let edge_is_discharged = |edge: &crate::dataflow::SummaryEdge| {
            (matches!(
                edge.kind(),
                IcfgEdgeKind::CallToNormalContinuation
                    | IcfgEdgeKind::CallToExceptionalContinuation
            ) && edge
                .origin()
                .is_some_and(|origin| fully_modeled_calls.contains(&origin)))
                || self.exceptional_return_edge_is_abort_only(edge, &abort_paths_only_unwind)
        };
        result
            .coverage()
            .unproven_edges()
            .iter()
            .all(edge_is_discharged)
            && result
                .coverage()
                .partial_edges()
                .iter()
                .all(edge_is_discharged)
            && result.coverage().boundaries().iter().all(|boundary| {
                self.boundary_is_fully_modeled(
                    result,
                    boundary,
                    requirement,
                    &abort_paths_only_unwind,
                )
            })
    }

    /// Whether typed discovery is closed for this execution result (#1952):
    /// every non-snapshot input is complete, and every snapshot is either
    /// complete (possibly refined by this plan's own bindings) or refinable
    /// with each residual call fully modeled by this result's boundaries (a
    /// complete external summary or curated model).
    fn discovery_closed_by<Fact>(
        &self,
        result: &SummaryDataflowResult<Fact>,
        requirement: SummaryProofRequirement,
    ) -> bool {
        self.endpoint_discovery_complete
            && self.incomplete_binding_calls.iter().all(|call| {
                // Only a curated model may answer an incomplete binding input:
                // it is an authored claim about the call's whole behavior. An
                // external pack summary keeps the pre-existing strictness.
                self.curated_model_for_call(call).is_some()
                    && self.call_boundaries_are_fully_modeled(result, call, requirement)
            })
            && self
                .snapshot_discoveries
                .iter()
                .all(|discovery| match discovery {
                    SnapshotDiscovery::Complete => true,
                    SnapshotDiscovery::Incomplete { .. } => false,
                    SnapshotDiscovery::Refinable { calls } => calls.iter().all(|call| {
                        self.call_boundaries_are_fully_modeled(result, call, requirement)
                    }),
                })
    }

    fn call_boundaries_are_fully_modeled<Fact>(
        &self,
        result: &SummaryDataflowResult<Fact>,
        call: &CallSiteHandle,
        requirement: SummaryProofRequirement,
    ) -> bool {
        let mut saw_dispatch = false;
        let allocation_call =
            crate::analyzer::semantic::workspace_oracle::allocation_call_is_dischargeable(
                call.procedure().semantics(),
                call.procedure()
                    .semantics()
                    .call_site(call.id())
                    .expect("call boundary origin must remain live"),
            );
        for boundary in result
            .coverage()
            .boundaries()
            .iter()
            .filter(|boundary| boundary.origin() == Some(call))
        {
            match boundary.kind() {
                SummaryBoundaryKind::Dispatch(_) => {
                    saw_dispatch = true;
                    if !allocation_call
                        && !self.dispatch_boundary_is_fully_modeled(result, boundary, requirement)
                    {
                        return false;
                    }
                }
                SummaryBoundaryKind::Semantic(_) => {}
                SummaryBoundaryKind::Limit(_) | SummaryBoundaryKind::Continuation { .. } => {
                    return false;
                }
            }
        }
        // A fully bindable curated model answers a residual refinement call
        // even when the run recorded no dispatch boundary for it: a plan that
        // deliberately binds no callee for a modeled call (a policy-declared
        // external model, #2691) leaves the call with neither a binding nor a
        // boundary, and the model's transfers are the call's complete
        // semantics, exactly as in `dispatch_boundary_is_fully_modeled`.
        saw_dispatch
            || allocation_call
            || self.curated_model_for_call(call).is_some_and(|model| {
                self.model_is_fully_bindable(
                    call,
                    model.transfers(),
                    SummaryProofRequirement::Derived,
                )
            })
    }

    fn boundary_is_fully_modeled<Fact>(
        &self,
        result: &SummaryDataflowResult<Fact>,
        boundary: &SummaryBoundary,
        requirement: SummaryProofRequirement,
        abort_paths_only_unwind: &std::cell::OnceCell<bool>,
    ) -> bool {
        if matches!(boundary.kind(), SummaryBoundaryKind::Semantic(_)) {
            if self.exceptional_exit_boundary_is_abort_only(boundary, abort_paths_only_unwind) {
                return true;
            }
            return boundary.origin().is_some_and(|call| {
                self.call_boundaries_are_fully_modeled(result, call, requirement)
            });
        }
        if boundary.origin().is_some_and(|call| {
            crate::analyzer::semantic::workspace_oracle::allocation_call_is_dischargeable(
                call.procedure().semantics(),
                call.procedure()
                    .semantics()
                    .call_site(call.id())
                    .expect("call boundary origin must remain live"),
            )
        }) {
            return true;
        }
        self.dispatch_boundary_is_fully_modeled(result, boundary, requirement)
    }

    /// Whether an exceptional-exit profile boundary reports only unlowered
    /// implicit abort edges that cannot carry a value (#1952).
    ///
    /// The exit profile keeps an `Unsupported` exceptional-control-flow status
    /// when a procedure's implicit abort edges are not lowered. When no
    /// procedure in this plan runs user code on an abort path -- no handler
    /// and no cleanup body anywhere in the analyzed region -- those edges can
    /// only unwind, so the boundary cannot hide a flow the demanded endpoints
    /// could observe. One handler anywhere keeps every such boundary open,
    /// because a callee's implicit throw decides that handler's reachability.
    /// The solver coverage's semantic-status merge, minus the abort-only
    /// exceptional-exit boundaries this plan's completion logic discharges
    /// (#1952), so public projections and completion agree on one status.
    pub fn public_semantic_status<Fact>(
        &self,
        result: &SummaryDataflowResult<Fact>,
    ) -> SemanticInputStatus {
        // A solve that replayed a cross-query reusable summary retained none of
        // the skipped subtree's coverage boundaries, so folding the boundaries
        // that are present would answer `Complete` for material this result
        // never looked at (#2296). The envelope for that subtree is not in the
        // result at all, which is exactly what `Unknown` states; a consumer
        // that needs the raw statuses must solve through the non-reusable
        // entry point, as the CodeQuery value-flow search paths do.
        let seed = if result.metrics().reusable_summary_hits > 0 {
            SemanticInputStatus::Unknown
        } else {
            SemanticInputStatus::Complete
        };
        let abort_paths_only_unwind = std::cell::OnceCell::new();
        result
            .coverage()
            .boundaries()
            .iter()
            .filter(|boundary| {
                !self.exceptional_exit_boundary_is_abort_only(boundary, &abort_paths_only_unwind)
            })
            .filter_map(|boundary| match boundary.kind() {
                SummaryBoundaryKind::Semantic(status) => Some(*status),
                SummaryBoundaryKind::Dispatch(_)
                | SummaryBoundaryKind::Limit(_)
                | SummaryBoundaryKind::Continuation { .. } => None,
            })
            .fold(seed, |current, incoming| current.merge(incoming))
    }

    fn exceptional_exit_boundary_is_abort_only(
        &self,
        boundary: &SummaryBoundary,
        abort_paths_only_unwind: &std::cell::OnceCell<bool>,
    ) -> bool {
        let SummaryBoundaryKind::Semantic(SemanticInputStatus::Unsupported {
            capability: crate::analyzer::semantic::SemanticCapability::ExceptionalControlFlow,
        }) = boundary.kind()
        else {
            return false;
        };
        if boundary.origin().is_some()
            || boundary.at().id()
                != boundary
                    .at()
                    .procedure()
                    .semantics()
                    .exceptional_exit_point()
        {
            return false;
        }
        *abort_paths_only_unwind.get_or_init(|| self.abort_paths_only_unwind())
    }

    /// Whether an exceptional-return edge was weakened only by the same
    /// implicit-abort profile that completion discharges at the callee's
    /// exceptional-exit boundary.
    ///
    /// Return projection attaches the profile's proof and completeness to the
    /// edge as well as publishing its semantic boundary. Its structured marker
    /// is present only when the incoming call transfer was independently
    /// proven and complete, so this discharge cannot forgive dispatch or call
    /// evaluation uncertainty. Rendered proof text is deliberately not parsed.
    fn exceptional_return_edge_is_abort_only(
        &self,
        edge: &crate::dataflow::SummaryEdge,
        abort_paths_only_unwind: &std::cell::OnceCell<bool>,
    ) -> bool {
        if edge.kind() != IcfgEdgeKind::ExceptionalReturn || !edge.implicit_abort_only() {
            return false;
        }
        *abort_paths_only_unwind.get_or_init(|| self.abort_paths_only_unwind())
    }

    fn abort_paths_only_unwind(&self) -> bool {
        self.summary_procedures().all(|procedure| {
            !crate::analyzer::semantic::workspace_oracle::abort_paths_run_user_code(
                procedure.semantics(),
            )
        })
    }

    fn dispatch_boundary_is_fully_modeled<Fact>(
        &self,
        result: &SummaryDataflowResult<Fact>,
        boundary: &SummaryBoundary,
        requirement: SummaryProofRequirement,
    ) -> bool {
        let Some(call) = boundary.origin() else {
            return false;
        };
        let SummaryBoundaryKind::Dispatch(kind) = boundary.kind() else {
            return false;
        };
        if let Some(summary) = self.external_summary_for_boundary(kind) {
            let authored_complete = summary.completeness().is_complete()
                && self.model_is_fully_bindable(call, summary.transfers(), requirement);
            return match requirement {
                SummaryProofRequirement::Derived => {
                    matches!(boundary.proof(), Some(ProofStatus::Proven)) && authored_complete
                }
                // A retained canonical callee from an unresolved lookup can
                // select and contribute an authored model, but the model is
                // not proof that the unresolved target set was complete.
                SummaryProofRequirement::AcceptAuthoredComplete => {
                    matches!(boundary.proof(), Some(ProofStatus::Proven)) && authored_complete
                }
            };
        }
        if matches!(kind, DispatchBoundaryKind::Unresolved)
            && matches!(requirement, SummaryProofRequirement::AcceptAuthoredComplete)
            && self.authored_arm_closure(result, call).is_some()
        {
            return true;
        }
        // A curated model is a Bifrost-authored fallback, not an external pack
        // summary, so it always answers to the derived requirement.
        self.curated_model_for_call(call).is_some_and(|model| {
            self.model_is_fully_bindable(call, model.transfers(), SummaryProofRequirement::Derived)
        })
    }

    /// The contract-claiming external summary that closes this call's named
    /// external boundary or residual blanket-refinement arm, if the guards
    /// permit the closure (#2342, #2371).
    ///
    /// The named-target arm is addressed directly by its activated summary. A
    /// call whose language adapter also retained a blanket "the target may
    /// select an override" gap carries a residual `Unresolved` arm beside it.
    /// That residual names no target, so `external_summary_for_boundary` cannot
    /// address it directly.
    ///
    /// A contract-claiming summary for the exact target named on the call is an
    /// assertion about every implementation of that target, so it answers the
    /// residual arm too -- that is the "external residual" half of #2371's
    /// discharge rule. The guards keep that from becoming a blanket amnesty:
    ///
    ///   * The caller admits only `AcceptAuthoredComplete`, so `Complete` keeps
    ///     asking `Derived` and authored trust still cannot launder into it
    ///     (#1916).
    ///   * Only a sibling `External` or `Unmaterialized` arm that names its
    ///     target qualifies. `External(None)`, `Deferred`, `Truncated`, and a
    ///     second `Unresolved` arm name none, and a `Limit` or `Continuation`
    ///     boundary is not a dispatch arm at all -- none of them can carry the
    ///     summary, so a genuinely ambiguous target set still refuses.
    ///   * A receiver-bearing summary must carry an explicit
    ///     `covers_overrides` claim (#2371). A receiverless target has no
    ///     overrides to cover, so authored completeness is already a statement
    ///     about its whole target set. In both cases the summary must be fully
    ///     bindable at this call.
    ///   * The call must have no analyzed callee of its own. A call that both
    ///     enters a workspace body and names an unmaterialized declaration --
    ///     an interface member with one visible implementor, say -- has a
    ///     target set the summary does not describe, and its residual arm is
    ///     about the implementors nobody enumerated. That is exactly the
    ///     genuine ambiguity the residual arm exists to report, so it refuses.
    ///
    /// When a residual exists, this closure is the "external residual" half of
    /// the discharge rule only. The "workspace half" -- CHA proving the
    /// workspace implementors of the resolved declaring member enumerated,
    /// possibly empty -- is proven upstream in `workspace_oracle::dispatch`.
    /// A call whose only named target is an unmaterialized external member
    /// carries no workspace declaration to run CHA against, so that half is
    /// proven instead from the analyzer's complete short-name index. When it
    /// cannot be proven the call gets an additional `Truncated` arm that this
    /// closure cannot address (`Truncated` is excluded above), so
    /// `call_boundaries_are_fully_modeled` still refuses the call as a whole.
    /// This closure never has to ask that question itself.
    ///
    /// A sibling arm that names a target the activated packs do not summarize
    /// fails `call_boundaries_are_fully_modeled` on its own turn through the
    /// loop, so this closure cannot rescue a call that has an unmodeled arm.
    fn authored_arm_closure<Fact>(
        &self,
        result: &SummaryDataflowResult<Fact>,
        call: &CallSiteHandle,
    ) -> Option<AuthoredArmClosure> {
        let target = result
            .coverage()
            .boundaries()
            .iter()
            .filter(|sibling| sibling.origin() == Some(call))
            .find_map(|sibling| {
                let SummaryBoundaryKind::Dispatch(kind) = sibling.kind() else {
                    return None;
                };
                match kind {
                    DispatchBoundaryKind::External(Some(target))
                    | DispatchBoundaryKind::Unmaterialized(target) => Some(target),
                    DispatchBoundaryKind::External(None)
                    | DispatchBoundaryKind::Deferred { .. }
                    | DispatchBoundaryKind::Unresolved
                    | DispatchBoundaryKind::Truncated => None,
                }
            })?;
        self.authored_target_closure(call, target)
    }

    fn authored_target_closure(
        &self,
        call: &CallSiteHandle,
        target: &SemanticLocator,
    ) -> Option<AuthoredArmClosure> {
        if self.has_binding_for_call(call) {
            return None;
        }
        let summary = self.external_summaries.summary_for(target)?;
        let SummaryOrigin::External(origin) = summary.key().identity().origin() else {
            // An inferred summary is derived from a body Bifrost read, so it is
            // not an authored claim and has no authored identity to record.
            return None;
        };
        // #2371: receiver-bearing calls need an explicit claim about every
        // implementation. A receiverless target has no implementations
        // selected by override dispatch, so its complete summary already
        // describes the entire target set.
        let target_has_receiver = target
            .declaration()
            .segments()
            .last()
            .is_some_and(|segment| segment.kind() == DeclarationSegmentKind::Method);
        if (target_has_receiver && !origin.covers_overrides())
            || !summary.completeness().is_complete()
            || !self.model_is_fully_bindable(
                call,
                summary.transfers(),
                SummaryProofRequirement::AcceptAuthoredComplete,
            )
        {
            return None;
        }
        Some(AuthoredArmClosure {
            call: call.clone(),
            target: target.clone(),
            origin: origin.clone(),
        })
    }

    /// Every dispatch boundary this result closed by an authored-complete
    /// external summary, in call order (#2342).
    ///
    /// A run that concludes `ProvenBySummary` because of such a closure must be
    /// able to say which authored claim proved it, so this is retained on the
    /// result rather than recomputed by a consumer that would have to
    /// re-derive the guards.
    pub fn authored_arm_closures<Fact>(
        &self,
        result: &SummaryDataflowResult<Fact>,
    ) -> Vec<AuthoredArmClosure> {
        let mut closures = Vec::new();
        for boundary in result.coverage().boundaries() {
            let (Some(call), SummaryBoundaryKind::Dispatch(kind)) =
                (boundary.origin(), boundary.kind())
            else {
                continue;
            };
            let closure = match kind {
                DispatchBoundaryKind::External(Some(target))
                | DispatchBoundaryKind::Unmaterialized(target) => {
                    self.authored_target_closure(call, target)
                }
                DispatchBoundaryKind::Unresolved => self.authored_arm_closure(result, call),
                DispatchBoundaryKind::External(None)
                | DispatchBoundaryKind::Deferred { .. }
                | DispatchBoundaryKind::Truncated => None,
            };
            if let Some(closure) = closure
                && !closures.iter().any(|existing: &AuthoredArmClosure| {
                    existing.call == closure.call && existing.target == closure.target
                })
            {
                closures.push(closure);
            }
        }
        closures
    }

    fn model_is_fully_bindable(
        &self,
        call: &CallSiteHandle,
        transfers: &[SummaryTransfer],
        requirement: SummaryProofRequirement,
    ) -> bool {
        transfers.iter().all(|transfer| {
            let evidence = transfer.evidence();
            let evidence_ok = match requirement {
                SummaryProofRequirement::Derived => summary_evidence_is_proven_complete(evidence),
                // `bind_compiled_procedure_summaries` stamps an external transfer
                // unproven, because a summary is an authored assertion about a
                // body Bifrost never analyzed (#1916). An authored-complete
                // summary still carries complete evidence, so accept completeness
                // alone when the summary-backed tier is the question.
                SummaryProofRequirement::AcceptAuthoredComplete => evidence.is_complete(),
            };
            evidence_ok
                && match self.summary_input_binding(call, transfer.input()) {
                    SummaryInputBinding::Carrier(_) => self
                        .summary_port_carrier(call, transfer.exit().port())
                        .is_some(),
                    SummaryInputBinding::VacuousConstant => true,
                    SummaryInputBinding::Unbound => false,
                }
        })
    }

    pub(crate) fn has_snapshot(&self, procedure: &ProcedureHandle) -> bool {
        self.snapshot_procedures
            .iter()
            .any(|candidate| candidate == procedure)
    }

    pub(crate) fn summary_procedures(&self) -> impl Iterator<Item = &ProcedureHandle> {
        std::iter::once(&self.root).chain(self.snapshot_procedures.iter())
    }

    pub(crate) fn has_binding_for_call(&self, call: &CallSiteHandle) -> bool {
        self.binding_pairs
            .iter()
            .any(|(candidate, _)| candidate == call)
    }

    /// Every analyzed procedure this plan binds a call of `procedure` to
    /// (#2296).
    ///
    /// A bound call is the only kind that `execution_discovery_modeled` above
    /// accepts without a fully modeled dispatch boundary, so it is also the
    /// only kind whose callee can contribute reached rows to a complete run
    /// without appearing in this plan's own boundary coverage. A reusable
    /// summary provider uses this to check that its summary's validity
    /// contract names those callees, because they are exactly the procedures a
    /// replay skips whose analysis inputs the contract would otherwise not
    /// pin.
    pub(crate) fn bound_callees_of<'plan>(
        &'plan self,
        procedure: &'plan ProcedureHandle,
    ) -> impl Iterator<Item = &'plan ProcedureHandle> {
        self.binding_pairs
            .iter()
            .filter(move |(call, _)| call.procedure() == procedure)
            .map(|(_, callee)| callee)
    }

    pub(crate) fn carrier_summary_identities(
        &self,
    ) -> HashMap<ProcedureHandle, ValueFlowCarrierSummaryIdentity> {
        #[derive(Default)]
        struct Builder {
            has_snapshot: bool,
            local_rules: Vec<ValueFlowLocalSummaryRule>,
            call_rules: Vec<ValueFlowCallSummaryRule>,
            curated_models: Vec<ValueFlowCuratedModelSummaryRule>,
            fallback_rules: Vec<ValueFlowFallbackSummaryRule>,
            location_bindings: Vec<ValueFlowLocationBindingSummaryRule>,
            edge_kills: Vec<ValueFlowEdgeKillSummaryRule>,
        }

        let mut builders = HashMap::<ProcedureHandle, Builder>::default();
        for procedure in self.summary_procedures() {
            builders.entry(procedure.clone()).or_default().has_snapshot |=
                self.has_snapshot(procedure);
        }
        for rule in &self.local_rules {
            builders
                .entry(rule.point.procedure().clone())
                .or_default()
                .local_rules
                .push(ValueFlowLocalSummaryRule {
                    point: rule.point.id(),
                    event_index: rule.event_index,
                    kind: rule.kind,
                    transfer: rule.transfer,
                    source: self.carrier_keys[rule.source.index()].clone(),
                    target: self.carrier_keys[rule.target.index()].clone(),
                    proof: rule.proof.clone(),
                    completeness: rule.completeness.clone(),
                    strong_update: rule.strong_update,
                });
        }
        for rule in &self.call_rules {
            builders
                .entry(rule.call.procedure().clone())
                .or_default()
                .call_rules
                .push(ValueFlowCallSummaryRule {
                    call: rule.call.id(),
                    callee_artifact: rule.callee.artifact().key().clone(),
                    callee_declaration: rule.callee.semantics().locator().declaration().clone(),
                    kind: rule.kind,
                    source: self.carrier_keys[rule.source.index()].clone(),
                    target: self.carrier_keys[rule.target.index()].clone(),
                    proof: rule.proof.clone(),
                    completeness: rule.completeness.clone(),
                });
        }
        for model in &self.curated_call_models {
            builders
                .entry(model.call.procedure().clone())
                .or_default()
                .curated_models
                .push(ValueFlowCuratedModelSummaryRule {
                    call: model.call.id(),
                    model: model.model.fingerprint(),
                });
        }
        for profile in &self.fallback_profiles {
            builders
                .entry(profile.call.procedure().clone())
                .or_default()
                .fallback_rules
                .push(ValueFlowFallbackSummaryRule {
                    call: profile.call.id(),
                    inputs: profile
                        .inputs
                        .iter()
                        .map(|carrier| self.carrier_keys[carrier.index()].clone())
                        .collect(),
                    reachable_components: profile.reachable_components.clone(),
                    normal_output: profile
                        .normal_output
                        .map(|carrier| self.carrier_keys[carrier.index()].clone()),
                    exceptional_output: profile
                        .exceptional_output
                        .map(|carrier| self.carrier_keys[carrier.index()].clone()),
                });
        }
        for binding in &self.summary_location_bindings {
            builders
                .entry(binding.call.procedure().clone())
                .or_default()
                .location_bindings
                .push(ValueFlowLocationBindingSummaryRule {
                    call: binding.call.id(),
                    port: binding.port.clone(),
                    carrier: self.carrier_keys[binding.carrier.index()].clone(),
                });
        }
        for kill in &self.edge_kills {
            let carrier = self
                .carrier_ids
                .get(&kill.carrier)
                .copied()
                .expect("a validated edge-kill carrier is bound");
            builders
                .entry(kill.point.procedure().clone())
                .or_default()
                .edge_kills
                .push(ValueFlowEdgeKillSummaryRule {
                    point: kill.point.id(),
                    target: kill.target,
                    kind: kill.kind,
                    carrier: self.carrier_keys[carrier.index()].clone(),
                    sources: kill.sources.clone().into_boxed_slice(),
                });
        }
        builders
            .into_iter()
            .map(|(procedure, builder)| {
                let external_summaries = self.external_summary_fingerprints_for(&procedure);
                let fallback_globals = if builder.fallback_rules.is_empty() {
                    Box::default()
                } else {
                    self.fallback_locations
                        .bounded_globals
                        .iter()
                        .map(|carrier| self.carrier_keys[carrier.index()].clone())
                        .collect()
                };
                (
                    procedure,
                    ValueFlowCarrierSummaryIdentity {
                        unmodeled_call_behavior: self.unmodeled_call_behavior,
                        external_summaries,
                        fallback_globals,
                        has_snapshot: builder.has_snapshot,
                        local_rules: builder.local_rules.into_boxed_slice(),
                        call_rules: builder.call_rules.into_boxed_slice(),
                        curated_models: builder.curated_models.into_boxed_slice(),
                        fallback_rules: builder.fallback_rules.into_boxed_slice(),
                        location_bindings: builder.location_bindings.into_boxed_slice(),
                        edge_kills: builder.edge_kills.into_boxed_slice(),
                    },
                )
            })
            .collect()
    }

    pub(crate) fn carrier_summary_identity_total_rows(&self) -> usize {
        self.local_rules
            .len()
            .saturating_add(self.call_rules.len())
            .saturating_add(self.curated_call_models.len())
            .saturating_add(self.summary_location_bindings.len())
            .saturating_add(self.edge_kills.len())
            .saturating_add(
                self.fallback_profiles
                    .iter()
                    .fold(0usize, |total, profile| {
                        total
                            .saturating_add(1)
                            .saturating_add(profile.inputs.len())
                            .saturating_add(profile.reachable_components.len())
                            .saturating_add(usize::from(profile.normal_output.is_some()))
                            .saturating_add(usize::from(profile.exceptional_output.is_some()))
                    }),
            )
            .saturating_add(self.fallback_locations.bounded_globals.len())
    }

    fn external_summary_fingerprints_for(
        &self,
        procedure: &ProcedureHandle,
    ) -> Box<[ExternalSummarySetFingerprint]> {
        let mut fingerprints = Vec::new();
        for call in procedure.semantics().call_sites() {
            let targets: &[CallableTarget] = match &call.declared_targets {
                CallableTargetResolution::Proven(target) => std::slice::from_ref(target),
                CallableTargetResolution::Ambiguous(targets)
                | CallableTargetResolution::Unproven(targets)
                | CallableTargetResolution::ExceededBudget(targets) => targets,
                CallableTargetResolution::Unknown | CallableTargetResolution::Unsupported => {
                    return vec![self.external_summaries.fingerprint()].into_boxed_slice();
                }
            };
            fingerprints.extend(targets.iter().filter_map(|target| match target {
                CallableTarget::Local(_) => None,
                CallableTarget::Unmaterialized(locator) | CallableTarget::External(locator) => {
                    self.external_summaries.fingerprint_for(locator)
                }
            }));
        }
        fingerprints.sort_unstable();
        fingerprints.dedup();
        fingerprints.into_boxed_slice()
    }

    pub(crate) fn is_call_input(&self, call: &CallSiteHandle, carrier: ValueFlowCarrierId) -> bool {
        let Some(profile) = self.fallback_profile(call) else {
            return false;
        };
        profile.inputs.binary_search(&carrier).is_ok()
            || self
                .fallback_locations
                .bounded_globals
                .binary_search(&carrier)
                .is_ok()
            || self
                .fallback_locations
                .location_components
                .get(&carrier)
                .is_some_and(|component| {
                    profile
                        .reachable_components
                        .binary_search(component)
                        .is_ok()
                })
    }

    pub(crate) fn external_summary_for_boundary(
        &self,
        boundary: &DispatchBoundaryKind,
    ) -> Option<&SemanticProcedureSummary> {
        if matches!(boundary, DispatchBoundaryKind::Deferred { .. }) {
            return None;
        }
        self.external_summaries
            .summary_for(boundary.target_locator()?)
    }

    pub(crate) fn curated_model_for_call(
        &self,
        call: &CallSiteHandle,
    ) -> Option<&CuratedCallModel> {
        self.curated_call_models
            .binary_search_by(|candidate| compare_calls(&candidate.call, call))
            .ok()
            .map(|index| &self.curated_call_models[index].model)
    }

    fn summary_port_carrier(
        &self,
        call: &CallSiteHandle,
        port: &SummaryPort,
    ) -> Option<ValueFlowCarrierId> {
        if matches!(port, SummaryPort::Capture(_) | SummaryPort::Heap(_)) {
            return self
                .summary_location_bindings
                .binary_search_by(|binding| {
                    compare_calls(&binding.call, call).then_with(|| binding.port.cmp(port))
                })
                .ok()
                .map(|index| self.summary_location_bindings[index].carrier);
        }
        let row = call.procedure().semantics().call_site(call.id())?;
        let value = match port {
            SummaryPort::Receiver => row.receiver?,
            SummaryPort::Parameter(index) => row.arguments.get(*index as usize)?.value,
            SummaryPort::NormalReturn => row.result?,
            SummaryPort::IndexedNormalReturn(index) => row.normal_result(*index as usize)?,
            SummaryPort::ExceptionalReturn => row.thrown?,
            SummaryPort::Capture(_) | SummaryPort::Heap(_) => return None,
        };
        let value = call.procedure().value_handle(value)?;
        self.carrier_id(&ValueFlowCarrier::Value(value))
    }

    fn summary_input_binding(
        &self,
        call: &CallSiteHandle,
        port: &SummaryPort,
    ) -> SummaryInputBinding {
        if let Some(carrier) = self.summary_port_carrier(call, port) {
            return SummaryInputBinding::Carrier(carrier);
        }
        let Some(row) = call.procedure().semantics().call_site(call.id()) else {
            return SummaryInputBinding::Unbound;
        };
        let value_kind = match port {
            SummaryPort::Parameter(index) => row
                .arguments
                .get(*index as usize)
                .and_then(|argument| call.procedure().semantics().value(argument.value))
                .map(|value| &value.kind),
            _ => None,
        };
        if carrierless_summary_input_is_vacuous(port, value_kind) {
            SummaryInputBinding::VacuousConstant
        } else {
            SummaryInputBinding::Unbound
        }
    }

    pub(crate) fn visit_boundary_transfers(
        &self,
        call: &CallSiteHandle,
        boundary: Option<&DispatchBoundaryKind>,
        kind: IcfgEdgeKind,
        input: ValueFlowCarrierId,
        mut visitor: impl FnMut(BoundBoundaryTransfer) -> bool,
    ) -> BoundaryTransferApplication {
        if let Some(summary) =
            boundary.and_then(|boundary| self.external_summary_for_boundary(boundary))
        {
            return self.visit_modeled_transfers(
                call,
                kind,
                input,
                summary.transfers(),
                summary.effects(),
                summary.completeness().is_complete(),
                visitor,
            );
        }
        if let Some(model) = self.curated_model_for_call(call) {
            return self.visit_modeled_transfers(
                call,
                kind,
                input,
                model.transfers(),
                model.effects(),
                true,
                visitor,
            );
        }

        // A call this plan bound is modeled by its call/return rules; the
        // caller-side continuation edge preserves unrelated facts as identity
        // (#1952). Neither the paranoid fallback smear nor the require-model
        // abstention applies to it.
        if boundary.is_none() && self.has_binding_for_call(call) {
            return BoundaryTransferApplication {
                modeled: true,
                complete: true,
                abstained: false,
            };
        }
        let is_input = self.is_call_input(call, input);
        if self.unmodeled_call_behavior == UnmodeledCallBehavior::Paranoid && is_input {
            self.visit_fallback_outputs(call, kind, |target| {
                visitor(BoundBoundaryTransfer {
                    target,
                    proven_complete: false,
                    removed_labels: Vec::new(),
                })
            });
        }
        BoundaryTransferApplication {
            modeled: false,
            complete: false,
            abstained: self.unmodeled_call_behavior == UnmodeledCallBehavior::RequireModel
                && is_input,
        }
    }

    /// Applies one call's modeled transfers to one already-active incoming
    /// fact (`input`), composing sibling transfers on the *same* call so a
    /// value one transfer just wrote to a port (typically `Receiver`) can
    /// feed a second transfer that reads that same port (#2567).
    ///
    /// Before this fix, the loop below tested every transfer's own `input`
    /// port against `input` only -- the one fact this invocation started
    /// with -- so a summary like `HashMap.put`'s, whose authored transfers
    /// deliberately chain through the receiver (`parameter[1] -> receiver`,
    /// then `receiver -> normal_return`, so "the value just written" can be
    /// read back through the method's own return value), never composed:
    /// the second transfer's `input` (`Receiver`) only ever matched a fact
    /// that already carried the receiver's value *before* the call, which a
    /// freshly constructed or freshly received map never does. A run could
    /// then reach `ProvenBySummary` (every transfer's ports structurally
    /// bind, which is all `model_is_fully_bindable`'s completion-time check
    /// asks) while silently dropping the one flow the fixture carries -- a
    /// false green in the sense the project's own no-false-greens property
    /// forbids.
    ///
    /// The fix below runs a small, local fixed point over `transfers`
    /// (bounded by `transfers.len()`, since every transfer fires at most
    /// once): `reached` starts containing only `input`, and a transfer fires
    /// once its own `input` port's live carrier appears in `reached`,
    /// whether that is because `input` itself is that carrier (an ordinary,
    /// direct one-hop transfer, unchanged from before this fix) or because
    /// an earlier-firing sibling transfer *on this same call* just wrote
    /// that carrier as its own output. This is deliberately scoped to one
    /// call's own transfer list -- it never reads or writes any state
    /// outside this one invocation, so it cannot compose a value across two
    /// different calls (that composition, when it happens at all, still
    /// only happens because two calls' `Receiver` ports resolve to the same
    /// underlying carrier, which is the ordinary cross-call value-flow
    /// carrier identity this function never touches).
    ///
    /// A transfer fires **at most once** per invocation (`fired`), which
    /// bounds every pass to firing at least one new transfer or terminating,
    /// so the loop always halts within `transfers.len()` passes even for a
    /// pathological cyclic or self-referencing (`receiver -> receiver`)
    /// summary -- it can never double-apply a transfer to its own output.
    ///
    /// Sanitize composition: `reached` also carries, for every carrier it
    /// contains, the union of every sanitize effect's removed labels along
    /// whichever path first reached that carrier (`sanitize_removed_labels`,
    /// #1923). A transfer that fires by composition (not directly against
    /// `input`) reports that accumulated union as its own `removed_labels`,
    /// not only its own effect. This is exactly equivalent to composing one
    /// `TaintEdgeFunction::kill` per hop: `kill(A)` composed with `kill(B)`
    /// is `kill(A ∪ B)`, because both are monotonic label removals over
    /// independent label dimensions, so the order they are removed in
    /// cannot matter (verified against `TaintEdgeFunction::compose`'s own
    /// definition in `taint/client.rs`). A sanitize declared on a *second*
    /// hop of a chain therefore still cuts labels a *first* hop let through,
    /// exactly as a single-hop sanitize already did.
    ///
    /// Scope note, checked against every sanitize effect shipped in this
    /// repository (`semantic-packs/sanitizers/**/*.json`): every one is a
    /// direct `parameter[n] -> normal_return` pair, never a self-loop
    /// (`port -> itself`) and never downstream of a port two or more
    /// transfers also write to. `reached` therefore records the *first*
    /// path that reaches a given carrier and does not update it if a later
    /// transfer reaches that same carrier by a different path with a
    /// different accumulated label set (which would matter only for a
    /// summary with divergent per-path sanitize outcomes converging on one
    /// port, or a self-loop transfer carrying its own sanitize -- neither
    /// occurs in any shipped content today). Deterministic either way
    /// (`transfers` is a stable slice, walked in the same index order every
    /// pass, with no unordered collection involved), but this is the one
    /// documented limitation of the composition below.
    #[allow(clippy::too_many_arguments)]
    fn visit_modeled_transfers<'a>(
        &'a self,
        call: &CallSiteHandle,
        kind: IcfgEdgeKind,
        input: ValueFlowCarrierId,
        transfers: &'a [SummaryTransfer],
        effects: &'a [SummaryEffect],
        mut complete: bool,
        mut visitor: impl FnMut(BoundBoundaryTransfer) -> bool,
    ) -> BoundaryTransferApplication {
        let exit = match kind {
            IcfgEdgeKind::CallToNormalContinuation => SummaryExitKind::Normal,
            IcfgEdgeKind::CallToExceptionalContinuation => SummaryExitKind::Exceptional,
            _ => {
                return BoundaryTransferApplication {
                    modeled: false,
                    complete: false,
                    abstained: false,
                };
            }
        };

        // Resolve every relevant transfer's static binding once, up front.
        // `summary_input_binding`/`summary_port_carrier` read only this call
        // site's own live value slots -- never which carrier this invocation
        // started from -- so nothing about the composition below changes
        // their answer. This also settles `complete` for every transfer
        // exactly once, unconditionally (matching the pre-fix behavior for
        // `VacuousConstant`/`Unbound`/an unbound output port), rather than
        // interleaving it with firing: `complete` is not read by any current
        // caller (only `.abstained` is), so decoupling it from the
        // composition loop below is a deliberate simplification, not a
        // behavior this function's callers depend on.
        let mut carrier_bound: Vec<(ValueFlowCarrierId, ValueFlowCarrierId, &'a SummaryTransfer)> =
            Vec::new();
        for transfer in transfers
            .iter()
            .filter(|transfer| transfer.exit().kind() == exit)
        {
            match self.summary_input_binding(call, transfer.input()) {
                SummaryInputBinding::Carrier(source) => {
                    match self.summary_port_carrier(call, transfer.exit().port()) {
                        Some(target) => {
                            complete &= summary_evidence_is_proven_complete(transfer.evidence());
                            carrier_bound.push((source, target, transfer));
                        }
                        None => complete = false,
                    }
                }
                SummaryInputBinding::VacuousConstant => {
                    complete &= summary_evidence_is_proven_complete(transfer.evidence());
                }
                SummaryInputBinding::Unbound => complete = false,
            }
        }

        // The composition fixed point (see the doc comment above for the
        // full rationale). `reached` maps a carrier this call's own transfer
        // graph has made active, starting from `input`, to the accumulated
        // union of sanitize labels removed along the path that reached it.
        let mut reached: Vec<(ValueFlowCarrierId, Vec<Box<str>>)> = vec![(input, Vec::new())];
        let mut fired = vec![false; carrier_bound.len()];
        'compose: loop {
            let mut progressed = false;
            for (index, (source, target, transfer)) in carrier_bound.iter().enumerate() {
                if fired[index] {
                    continue;
                }
                let Some(prefix) = reached
                    .iter()
                    .find(|(carrier, _)| carrier == source)
                    .map(|(_, labels)| labels.clone())
                else {
                    continue;
                };
                fired[index] = true;
                progressed = true;
                let mut removed_labels = prefix;
                removed_labels.extend(
                    sanitize_removed_labels(effects, transfer.input(), transfer.exit().port())
                        .iter()
                        .cloned(),
                );
                if !reached.iter().any(|(carrier, _)| carrier == target) {
                    reached.push((*target, removed_labels.clone()));
                }
                let keep_going = visitor(BoundBoundaryTransfer {
                    target: *target,
                    proven_complete: summary_evidence_is_proven_complete(transfer.evidence()),
                    removed_labels,
                });
                if !keep_going {
                    break 'compose;
                }
            }
            if !progressed {
                break;
            }
        }

        BoundaryTransferApplication {
            modeled: true,
            complete,
            abstained: false,
        }
    }

    fn visit_fallback_outputs(
        &self,
        call: &CallSiteHandle,
        kind: IcfgEdgeKind,
        mut visitor: impl FnMut(ValueFlowCarrierId) -> bool,
    ) {
        let Some(profile) = self.fallback_profile(call) else {
            return;
        };
        for target in self.fallback_locations.bounded_globals.iter().copied() {
            if !visitor(target) {
                return;
            }
        }
        for component in &profile.reachable_components {
            if let Some(targets) = self.fallback_locations.by_component.get(component) {
                for target in targets.iter().copied() {
                    if !visitor(target) {
                        return;
                    }
                }
            }
        }
        let result = match kind {
            IcfgEdgeKind::CallToNormalContinuation => profile.normal_output,
            IcfgEdgeKind::CallToExceptionalContinuation => profile.exceptional_output,
            _ => None,
        };
        if let Some(result) = result {
            let already_emitted = self
                .fallback_locations
                .bounded_globals
                .binary_search(&result)
                .is_ok()
                || profile.reachable_components.iter().any(|component| {
                    self.fallback_locations
                        .by_component
                        .get(component)
                        .is_some_and(|targets| targets.binary_search(&result).is_ok())
                });
            if !already_emitted {
                let _ = visitor(result);
            }
        }
    }

    fn fallback_profile(&self, call: &CallSiteHandle) -> Option<&CallFallbackProfile> {
        self.fallback_profiles
            .binary_search_by(|profile| compare_calls(&profile.call, call))
            .ok()
            .map(|index| &self.fallback_profiles[index])
    }

    pub(crate) fn is_callee_port(
        &self,
        carrier: ValueFlowCarrierId,
        callee: &ProcedureHandle,
    ) -> bool {
        matches!(self.carrier(carrier), Some(ValueFlowCarrier::Port(port)) if port.procedure() == callee)
    }

    pub fn source(&self, id: ValueFlowSourceId) -> Option<&ValueFlowSourceSpec> {
        self.sources.get(id.index()).map(|source| &source.spec)
    }

    pub fn sources(
        &self,
    ) -> impl ExactSizeIterator<Item = (ValueFlowSourceId, &ValueFlowSourceSpec)> {
        self.sources.iter().map(|source| (source.id, &source.spec))
    }

    pub fn sink(&self, id: ValueFlowSinkId) -> Option<&ValueFlowSinkSpec> {
        self.sinks.get(id.index()).map(|sink| &sink.spec)
    }

    pub fn sinks(&self) -> impl ExactSizeIterator<Item = (ValueFlowSinkId, &ValueFlowSinkSpec)> {
        self.sinks.iter().map(|sink| (sink.id, &sink.spec))
    }

    /// Conservative fan-out inputs for a bounded forward estimate.
    ///
    /// The estimate counts every retained local and call transfer relation,
    /// fallback profile, and bound source once.  It is intentionally a cheap
    /// upper-bound proxy; the snapshot reachability walk supplies the graph
    /// topology separately.
    pub(crate) fn forward_transfer_fanout_estimate(&self) -> usize {
        self.local_rules
            .len()
            .saturating_add(self.call_rules.len())
            .saturating_add(self.fallback_profiles.len())
            .saturating_add(self.sources.len())
    }

    /// Conservative fan-out inputs for a bounded backward estimate.
    ///
    /// Reverse transfer uses the same retained relations but starts from
    /// bound sinks, so sink bindings are counted independently of sources.
    pub(crate) fn backward_transfer_fanout_estimate(&self) -> usize {
        self.local_rules
            .len()
            .saturating_add(self.call_rules.len())
            .saturating_add(self.fallback_profiles.len())
            .saturating_add(self.sinks.len())
    }

    /// Whether a constant branch condition proves this point cannot execute.
    ///
    /// Gating the three point-keyed accessors below on this is what makes the
    /// exclusion total: no source produces at the point, no sink observes
    /// there, no local rule propagates through it, and both flow clients
    /// therefore lose the fact at the dead point rather than at some later
    /// place each would have to remember to check (#2443 slice 2).
    fn point_is_infeasible(&self, point: &ProgramPointHandle) -> bool {
        self.infeasible_points
            .iter()
            .find(|(procedure, _)| procedure == point.procedure())
            .is_some_and(|(_, points)| points.binary_search(&point.id()).is_ok())
    }

    pub(crate) fn local_rules_at(
        &self,
        point: &ProgramPointHandle,
    ) -> impl Iterator<Item = &LocalFlowRule> {
        let feasible = !self.point_is_infeasible(point);
        self.local_rules
            .iter()
            .filter(move |rule| feasible && &rule.point == point)
    }

    pub(crate) fn edge_kills(
        &self,
        point: &ProgramPointHandle,
        target: ProgramPointId,
        kind: ControlEdgeKind,
    ) -> &[BoundValueFlowEdgeKill] {
        self.edge_kill_index
            .by_edge
            .get(&EdgeKillKey {
                point: point.clone(),
                target,
                kind,
            })
            .map_or(&[], Box::as_ref)
    }

    pub(crate) fn has_edge_kills(&self) -> bool {
        !self.edge_kills.is_empty()
    }

    pub(crate) fn local_rule_views(
        &self,
        point: &ProgramPointHandle,
    ) -> impl Iterator<Item = LocalRuleView> {
        self.local_rules_at(point).map(|rule| LocalRuleView {
            source: rule.source,
            target: rule.target,
            kind: rule.kind,
            transfer: rule.transfer,
            complete: matches!(rule.proof, ProofStatus::Proven)
                && matches!(rule.completeness, EvidenceCompleteness::Complete),
            strong_update: rule.strong_update,
        })
    }

    /// Return every local rule at `point` in reverse event order. A backward
    /// client must use this when a rule's source becomes the demanded carrier,
    /// because the next preimage may be produced by a different target.
    pub(crate) fn local_rule_views_reverse_at(
        &self,
        point: &ProgramPointHandle,
    ) -> impl Iterator<Item = LocalRuleView> {
        let feasible = !self.point_is_infeasible(point);
        self.local_rule_reverse_index
            .by_point
            .get(point)
            .into_iter()
            .flatten()
            .filter(move |_| feasible)
            .map(move |index| {
                let rule = &self.local_rules[*index];
                LocalRuleView {
                    source: rule.source,
                    target: rule.target,
                    kind: rule.kind,
                    transfer: rule.transfer,
                    complete: matches!(rule.proof, ProofStatus::Proven)
                        && matches!(rule.completeness, EvidenceCompleteness::Complete),
                    strong_update: rule.strong_update,
                }
            })
    }

    pub(crate) fn call_rules<'a>(
        &'a self,
        call: &'a CallSiteHandle,
        callee: &'a ProcedureHandle,
        kind: CallFlowRuleKind,
    ) -> impl Iterator<Item = &'a CallFlowRule> + 'a {
        self.call_rules
            .iter()
            .filter(move |rule| &rule.call == call && &rule.callee == callee && rule.kind == kind)
    }

    pub(crate) fn call_targets<'a>(
        &'a self,
        call: &'a CallSiteHandle,
        callee: &'a ProcedureHandle,
        source: ValueFlowCarrierId,
    ) -> impl Iterator<Item = (ValueFlowCarrierId, bool)> + 'a {
        self.call_rules(call, callee, CallFlowRuleKind::Call)
            .filter(move |rule| rule.source == source)
            .map(rule_target)
    }

    pub(crate) fn normal_return_targets<'a>(
        &'a self,
        call: &'a CallSiteHandle,
        callee: &'a ProcedureHandle,
        source: ValueFlowCarrierId,
    ) -> impl Iterator<Item = (ValueFlowCarrierId, bool)> + 'a {
        self.call_rules(call, callee, CallFlowRuleKind::NormalReturn)
            .filter(move |rule| rule.source == source)
            .map(rule_target)
    }

    pub(crate) fn exceptional_return_targets<'a>(
        &'a self,
        call: &'a CallSiteHandle,
        callee: &'a ProcedureHandle,
        source: ValueFlowCarrierId,
    ) -> impl Iterator<Item = (ValueFlowCarrierId, bool)> + 'a {
        self.call_rules(call, callee, CallFlowRuleKind::ExceptionalReturn)
            .filter(move |rule| rule.source == source)
            .map(rule_target)
    }

    /// Return call-boundary rules whose target is `target`. Entries retain the
    /// canonical source order for one call, callee, and rule kind.
    pub(crate) fn call_rules_to_target<'a>(
        &'a self,
        call: &CallSiteHandle,
        callee: &ProcedureHandle,
        kind: CallFlowRuleKind,
        target: ValueFlowCarrierId,
    ) -> impl Iterator<Item = &'a CallFlowRule> + 'a {
        let key = CallRuleTargetKey {
            call: call.clone(),
            callee: callee.clone(),
            kind,
            target,
        };
        self.call_rule_reverse_index
            .by_target
            .get(&key)
            .into_iter()
            .flatten()
            .map(move |index| &self.call_rules[*index])
    }

    pub(crate) fn sources_at<'a>(
        &'a self,
        point: &ProgramPointHandle,
        phase: ValueFlowObservationPhase,
    ) -> impl Iterator<Item = &'a BoundValueFlowSource> + 'a {
        let feasible = !self.point_is_infeasible(point);
        let key = ObservationKey {
            point: point.clone(),
            phase,
        };
        self.source_index
            .by_point_phase
            .get(&key)
            .into_iter()
            .flatten()
            .filter(move |_| feasible)
            .map(move |index| &self.sources[*index])
    }

    pub(crate) fn source_bindings_at(
        &self,
        point: &ProgramPointHandle,
        phase: ValueFlowObservationPhase,
    ) -> impl Iterator<Item = (ValueFlowSourceId, ValueFlowCarrierId)> {
        self.sources_at(point, phase)
            .map(|source| (source.id, source.carrier))
    }

    pub(crate) fn sinks_at<'a>(
        &'a self,
        point: &ProgramPointHandle,
        phase: ValueFlowObservationPhase,
    ) -> impl Iterator<Item = &'a BoundValueFlowSink> + 'a {
        let feasible = !self.point_is_infeasible(point);
        let key = ObservationKey {
            point: point.clone(),
            phase,
        };
        self.sink_index
            .by_point_phase
            .get(&key)
            .into_iter()
            .flatten()
            .filter(move |_| feasible)
            .map(move |index| &self.sinks[*index])
    }

    pub(crate) fn sink_bindings_at(
        &self,
        point: &ProgramPointHandle,
        phase: ValueFlowObservationPhase,
    ) -> impl Iterator<Item = (ValueFlowSinkId, ValueFlowCarrierId)> {
        self.sinks_at(point, phase)
            .map(|sink| (sink.id, sink.carrier))
    }
}

fn carrierless_summary_input_is_vacuous(
    port: &SummaryPort,
    value_kind: Option<&SemanticValueKind>,
) -> bool {
    matches!(port, SummaryPort::Parameter(_))
        && matches!(value_kind, Some(SemanticValueKind::Constant))
}

#[cfg(test)]
mod tests {
    use std::hash::Hasher;

    use crate::analyzer::semantic::{
        CancellationToken, OracleCallContext, SemanticBudget, SemanticRequest, ValueFlowOracle,
    };
    use crate::analyzer::{AnalyzerConfig, Language};

    use super::*;
    use crate::inline_project::InlineTestProject;

    #[derive(Default)]
    struct HashTrace(Vec<u8>);

    impl Hasher for HashTrace {
        fn finish(&self) -> u64 {
            0
        }

        fn write(&mut self, bytes: &[u8]) {
            self.0.extend_from_slice(bytes);
        }
    }

    fn propagation_hash_trace(plan: &ValueFlowPlan) -> Vec<u8> {
        let mut trace = HashTrace::default();
        plan.propagation_semantics_hash(&mut trace);
        trace.0
    }

    #[test]
    fn call_rule_quality_includes_dispatch_candidate_quality() {
        let candidate_proof = ProofStatus::Unproven("multi-class dispatch".into());
        let candidate_completeness =
            EvidenceCompleteness::Partial("receiver set is incomplete".into());

        assert_eq!(
            merge_call_rule_proof(&candidate_proof, ProofStatus::Proven),
            candidate_proof
        );
        assert_eq!(
            merge_call_rule_completeness(&candidate_completeness, EvidenceCompleteness::Complete,),
            candidate_completeness
        );
    }

    #[test]
    fn only_carrierless_constant_parameters_are_vacuous_summary_inputs() {
        assert!(carrierless_summary_input_is_vacuous(
            &SummaryPort::Parameter(0),
            Some(&SemanticValueKind::Constant),
        ));
        assert!(!carrierless_summary_input_is_vacuous(
            &SummaryPort::Parameter(0),
            Some(&SemanticValueKind::Local),
        ));
        assert!(!carrierless_summary_input_is_vacuous(
            &SummaryPort::Receiver,
            Some(&SemanticValueKind::Constant),
        ));
        assert!(!carrierless_summary_input_is_vacuous(
            &SummaryPort::Parameter(0),
            None,
        ));
    }

    #[test]
    fn strong_update_changes_propagation_compatibility_hash() {
        const SOURCE: &str = r#"
package fixture

type box struct {
    value string
}

func run(input string) string {
    holder := &box{}
    holder.value = input
    return holder.value
}
"#;

        let project = InlineTestProject::with_language(Language::Go)
            .file("flow.go", SOURCE)
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let artifact_outcome = workspace
            .materialize_program_semantics(
                &project.file("flow.go"),
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("fixture semantics materialize");
        let artifact = artifact_outcome
            .available_value()
            .cloned()
            .expect("fixture semantics remain available");
        let procedure = artifact
            .procedures()
            .iter()
            .find(|procedure| {
                procedure
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|segment| segment.name())
                    == Some("run")
            })
            .expect("fixture declares run");
        let root = artifact
            .procedure_handle(procedure.id())
            .expect("fixture procedure remains live");

        let mut budget = SemanticBudget::default();
        let snapshot_outcome = workspace
            .semantic_oracle_provider()
            .procedure_relations(
                &root,
                &OracleCallContext::empty(),
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("fixture value-flow snapshot materializes");
        let status = SemanticInputStatus::from_outcome(&snapshot_outcome);
        let snapshot = snapshot_outcome
            .available_value()
            .cloned()
            .expect("fixture value-flow snapshot remains available");
        let plan = ValueFlowPlan::try_new(
            root,
            vec![ValueFlowInput::new(snapshot, status)],
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
        .expect("fixture value-flow plan");
        let store = plan
            .local_rules
            .iter()
            .position(|rule| rule.kind == ValueFlowRelationKind::MemoryStore)
            .expect("fixture publishes a memory-store rule");

        let mut changed = plan.clone();
        changed.local_rules[store].strong_update = !changed.local_rules[store].strong_update;

        assert!(
            !plan.has_same_propagation_semantics(&changed),
            "strong-update eligibility changes exact propagation semantics"
        );
        assert_ne!(
            propagation_hash_trace(&plan),
            propagation_hash_trace(&changed),
            "the compatibility hash must partition every distinction enforced by exact compatibility"
        );
    }

    #[test]
    fn first_incomplete_cause_retains_the_blocking_semantic_gap() {
        const SOURCE: &str = r#"package fixture

type leaf struct { value string }
type branch struct { leaf leaf }

func run(input string) string {
    holder := branch{leaf: leaf{value: "clean"}}
    holder.leaf.value = input
    return holder.leaf.value
}
"#;

        let project = InlineTestProject::with_language(Language::Go)
            .file("flow.go", SOURCE)
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let artifact = workspace
            .materialize_program_semantics(
                &project.file("flow.go"),
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("fixture semantics materialize")
            .available_value()
            .cloned()
            .expect("fixture semantics remain available");
        let procedure = artifact
            .procedures()
            .iter()
            .find(|procedure| {
                procedure
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|segment| segment.name())
                    == Some("run")
            })
            .expect("fixture declares run");
        let root = artifact
            .procedure_handle(procedure.id())
            .expect("fixture procedure remains live");
        let mut budget = SemanticBudget::default();
        let snapshot_outcome = workspace
            .semantic_oracle_provider()
            .procedure_relations(
                &root,
                &OracleCallContext::empty(),
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("fixture value-flow snapshot materializes");
        let status = SemanticInputStatus::from_outcome(&snapshot_outcome);
        let snapshot = snapshot_outcome
            .available_value()
            .cloned()
            .expect("fixture value-flow snapshot remains available");
        let plan = ValueFlowPlan::try_new(
            root,
            vec![ValueFlowInput::new(snapshot, status)],
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
        .expect("fixture value-flow plan");

        assert!(
            matches!(
                plan.first_incomplete_cause(),
                Some(ValueFlowIncompleteCause::SemanticGap {
                    capability: SemanticCapability::FieldMemory,
                    status: SemanticInputStatus::Unknown,
                    ..
                })
            ),
            "the generic plan must retain the exact structured blocker: {:?}",
            plan.first_incomplete_cause()
        );
        assert_eq!(
            plan.first_incomplete_cause()
                .expect("incomplete fixture has a cause")
                .label(),
            "access-path resolution"
        );
    }

    #[test]
    fn transfer_metadata_changes_propagation_compatibility_hash() {
        use crate::analyzer::semantic::{
            TransferKind, TransferOperation, ValuePreservation, ValueTransfer,
        };

        let project = InlineTestProject::with_language(Language::Go)
            .file(
                "flow.go",
                r#"package fixture
func run() [1]int {
    first := [1]int{}
    second := first
    return second
}
"#,
            )
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let artifact = workspace
            .materialize_program_semantics(
                &project.file("flow.go"),
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("fixture semantics materialize")
            .available_value()
            .cloned()
            .expect("fixture semantics remain available");
        let root = artifact
            .procedures()
            .iter()
            .find(|procedure| {
                procedure
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|segment| segment.name())
                    == Some("run")
            })
            .and_then(|procedure| artifact.procedure_handle(procedure.id()))
            .expect("fixture declares run");
        let mut budget = SemanticBudget::default();
        let snapshot_outcome = workspace
            .semantic_oracle_provider()
            .procedure_relations(
                &root,
                &OracleCallContext::empty(),
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("fixture value-flow snapshot materializes");
        let status = SemanticInputStatus::from_outcome(&snapshot_outcome);
        let snapshot = snapshot_outcome
            .available_value()
            .cloned()
            .expect("fixture value-flow snapshot remains available");
        let mut plan = ValueFlowPlan::try_new(
            root,
            vec![ValueFlowInput::new(snapshot, status)],
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
        .expect("fixture value-flow plan");
        let transfer = plan
            .local_rules
            .iter()
            .position(|rule| rule.transfer.is_some())
            .expect("array copy publishes transfer metadata");
        let mut changed = plan.clone();
        changed.local_rules[transfer].transfer = Some(ValueTransfer {
            kind: TransferKind::Conversion {
                preservation: ValuePreservation::Changing,
            },
            operation: TransferOperation::None,
        });

        assert!(!plan.has_same_propagation_semantics(&changed));
        assert_ne!(
            propagation_hash_trace(&plan),
            propagation_hash_trace(&changed)
        );
        plan.local_rules[transfer].transfer = changed.local_rules[transfer].transfer;
        assert!(plan.has_same_propagation_semantics(&changed));
    }
}

fn rule_target(rule: &CallFlowRule) -> (ValueFlowCarrierId, bool) {
    (
        rule.target,
        matches!(rule.proof, ProofStatus::Proven)
            && matches!(rule.completeness, EvidenceCompleteness::Complete),
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValueFlowPlanError {
    InvalidLimits,
    LimitExceeded,
    ForeignWorkspace,
    InvalidEventCarrier,
    ContextSensitiveInputUnsupported,
    InvalidCallArgumentLocation,
    DuplicateEventKey,
    InvalidEdgeKill,
    DuplicateCallModel,
    StaleCallModel,
    InvalidSummaryLocationPort,
    DuplicateSummaryLocationBinding,
    IncompatibleExternalSummary,
    IncompatibleObservationUnion,
    StableCarrierCollision,
    CarrierIdOverflow,
    SourceIdOverflow,
    SinkIdOverflow,
    MissingCarrier,
    Model(ValueFlowModelError),
}

impl fmt::Display for ValueFlowPlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits => formatter.write_str("invalid value-flow plan limits"),
            Self::LimitExceeded => formatter.write_str("value-flow plan limit exceeded"),
            Self::ForeignWorkspace => {
                formatter.write_str("value-flow input belongs to another workspace mount")
            }
            Self::InvalidEventCarrier => {
                formatter.write_str("value-flow event carrier belongs to another procedure")
            }
            Self::ContextSensitiveInputUnsupported => formatter.write_str(
                "context-sensitive oracle input cannot be flattened into a value-flow plan",
            ),
            Self::InvalidCallArgumentLocation => {
                formatter.write_str("call argument contains an invalid abstract location")
            }
            Self::DuplicateEventKey => formatter.write_str("duplicate value-flow event key"),
            Self::InvalidEdgeKill => {
                formatter.write_str("value-flow edge kill names an absent edge, source, or carrier")
            }
            Self::DuplicateCallModel => {
                formatter.write_str("multiple curated call models target the same call site")
            }
            Self::StaleCallModel => formatter.write_str("curated call model targets a stale call"),
            Self::InvalidSummaryLocationPort => {
                formatter.write_str("summary location binding requires a heap or capture port")
            }
            Self::DuplicateSummaryLocationBinding => formatter
                .write_str("multiple summary location bindings target the same call and port"),
            Self::IncompatibleExternalSummary => formatter
                .write_str("external summaries are incompatible with the active analysis contract"),
            Self::IncompatibleObservationUnion => {
                formatter.write_str("value-flow observations have different propagation semantics")
            }
            Self::StableCarrierCollision => {
                formatter.write_str("distinct value-flow carriers share one stable key")
            }
            Self::CarrierIdOverflow => formatter.write_str("value-flow carrier ID overflow"),
            Self::SourceIdOverflow => formatter.write_str("value-flow source ID overflow"),
            Self::SinkIdOverflow => formatter.write_str("value-flow sink ID overflow"),
            Self::MissingCarrier => formatter.write_str("value-flow plan carrier is missing"),
            Self::Model(error) => error.fmt(formatter),
        }
    }
}

impl Error for ValueFlowPlanError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Model(error) => Some(error),
            _ => None,
        }
    }
}

impl From<ValueFlowModelError> for ValueFlowPlanError {
    fn from(error: ValueFlowModelError) -> Self {
        Self::Model(error)
    }
}

fn validate_mount(
    procedure: &ProcedureHandle,
    mount: crate::analyzer::semantic::WorkspaceMountId,
) -> Result<(), ValueFlowPlanError> {
    if procedure.artifact().key().mount() == mount {
        Ok(())
    } else {
        Err(ValueFlowPlanError::ForeignWorkspace)
    }
}

fn validate_event(
    point: &ProgramPointHandle,
    carrier: &ValueFlowCarrier,
    mount: crate::analyzer::semantic::WorkspaceMountId,
) -> Result<(), ValueFlowPlanError> {
    validate_mount(point.procedure(), mount)?;
    if carrier
        .procedure()
        .is_some_and(|procedure| procedure != point.procedure())
    {
        return Err(ValueFlowPlanError::InvalidEventCarrier);
    }
    Ok(())
}

/// One dense carrier per stable key, plus the reverse map from every handle
/// that named it.
struct CarrierIndex {
    carriers: Vec<ValueFlowCarrier>,
    carrier_keys: Vec<ValueFlowCarrierKey>,
    carrier_ids: HashMap<ValueFlowCarrier, ValueFlowCarrierId>,
}

/// Give every named carrier one dense ID, keyed by its stable identity.
///
/// The stable key is the plan's carrier identity: `carrier_keys` is the sorted
/// domain `carrier_id_for_key` searches, and it is what
/// `propagation_semantics_hash` hashes. Handle equality is finer than that,
/// because a `ProcedureHandle` compares its owning `Arc<SemanticArtifact>` by
/// pointer. A caller that walks an interprocedural closure can therefore
/// present one procedure twice: the byte-bounded artifact cache may evict an
/// artifact that a later call resolution re-materializes, and both handles then
/// reach the plan. Those candidates name one entity, so they share one dense
/// ID, and `carrier_ids` retains every handle that named it so a client holding
/// either materialization still resolves it.
///
/// Two candidates that share a key but do not name one entity are a real
/// identity failure: `stable_key` lost a distinction the plan cannot recover,
/// and merging them would silently join two entities' flows. The plan refuses
/// that input instead.
fn assign_carrier_ids(
    candidates: Vec<ValueFlowCarrier>,
    max_carriers: usize,
) -> Result<CarrierIndex, ValueFlowPlanError> {
    let mut keyed = candidates
        .into_iter()
        .map(|carrier| Ok((carrier.stable_key()?, carrier)))
        .collect::<Result<Vec<_>, ValueFlowPlanError>>()?;
    keyed.sort_by(|left, right| left.0.cmp(&right.0));

    let mut groups = Vec::new();
    let mut start = 0usize;
    while start < keyed.len() {
        let end = start + keyed[start..].partition_point(|entry| entry.0 == keyed[start].0);
        groups.push((start, end));
        start = end;
    }
    if groups.len() > max_carriers {
        return Err(ValueFlowPlanError::LimitExceeded);
    }

    let mut index = CarrierIndex {
        carriers: Vec::with_capacity(groups.len()),
        carrier_keys: Vec::with_capacity(groups.len()),
        carrier_ids: HashMap::default(),
    };
    for (ordinal, (start, end)) in groups.into_iter().enumerate() {
        let (key, representative) = &keyed[start];
        if keyed[start + 1..end]
            .iter()
            .any(|(_, carrier)| !carrier.denotes_same_entity(representative))
        {
            return Err(ValueFlowPlanError::StableCarrierCollision);
        }
        let id = ValueFlowCarrierId::try_from_index(ordinal)
            .map_err(|_| ValueFlowPlanError::CarrierIdOverflow)?;
        for (_, carrier) in &keyed[start..end] {
            index.carrier_ids.insert(carrier.clone(), id);
        }
        index.carrier_keys.push(key.clone());
        index.carriers.push(representative.clone());
    }
    Ok(index)
}

fn lookup_carrier(
    ids: &HashMap<ValueFlowCarrier, ValueFlowCarrierId>,
    endpoint: &crate::analyzer::semantic::ValueFlowEndpoint,
) -> Result<ValueFlowCarrierId, ValueFlowPlanError> {
    ids.get(&ValueFlowCarrier::from(endpoint))
        .copied()
        .ok_or(ValueFlowPlanError::MissingCarrier)
}

fn append_binding_carriers(
    binding: &CallBinding,
    output: &mut Vec<ValueFlowCarrier>,
) -> Result<(), ValueFlowPlanError> {
    match binding {
        CallBinding::Receiver { actual, formal, .. } => {
            output.push(ValueFlowCarrier::Value(actual.clone()));
            output.push(ValueFlowCarrier::Port(formal.clone()));
        }
        CallBinding::ArgumentGroup(group) => {
            for mapping in group.mappings() {
                output.push(argument_carrier(mapping.value().actual())?);
                output.push(ValueFlowCarrier::Port(mapping.value().formal().clone()));
            }
        }
        CallBinding::ImplicitArgument { source, formal, .. } => {
            output.push(ValueFlowCarrier::Value(source.clone()));
            output.push(ValueFlowCarrier::Port(formal.clone()));
        }
        CallBinding::NormalReturn { formal, result, .. }
        | CallBinding::ExceptionalReturn { formal, result, .. } => {
            output.push(ValueFlowCarrier::Port(formal.clone()));
            output.push(ValueFlowCarrier::Value(result.clone()));
        }
    }
    Ok(())
}

fn call_binding_rule_count(binding: &CallBinding) -> usize {
    match binding {
        CallBinding::ArgumentGroup(group) => group.mappings().len(),
        _ => 1,
    }
}

fn append_call_rules(
    bindings: &CallBindings,
    ids: &HashMap<ValueFlowCarrier, ValueFlowCarrierId>,
    output: &mut Vec<CallFlowRule>,
) -> Result<(), ValueFlowPlanError> {
    let candidate_proof = bindings.candidate().proof();
    let candidate_completeness = bindings.candidate().completeness();
    let mut append =
        |kind, source: ValueFlowCarrier, target: ValueFlowCarrier, proof, completeness| {
            output.push(CallFlowRule {
                call: bindings.call().clone(),
                callee: bindings.callee().clone(),
                kind,
                source: *ids.get(&source).ok_or(ValueFlowPlanError::MissingCarrier)?,
                target: *ids.get(&target).ok_or(ValueFlowPlanError::MissingCarrier)?,
                proof: merge_call_rule_proof(candidate_proof, proof),
                completeness: merge_call_rule_completeness(candidate_completeness, completeness),
            });
            Ok::<_, ValueFlowPlanError>(())
        };
    for binding in bindings.bindings() {
        match binding {
            CallBinding::Receiver { actual, formal, .. } => append(
                CallFlowRuleKind::Call,
                ValueFlowCarrier::Value(actual.clone()),
                ValueFlowCarrier::Port(formal.clone()),
                ProofStatus::Proven,
                EvidenceCompleteness::Complete,
            )?,
            CallBinding::ArgumentGroup(group) => {
                for mapping in group.mappings() {
                    append(
                        CallFlowRuleKind::Call,
                        argument_carrier(mapping.value().actual())?,
                        ValueFlowCarrier::Port(mapping.value().formal().clone()),
                        mapping.proof().clone(),
                        mapping.completeness().clone(),
                    )?;
                }
            }
            CallBinding::ImplicitArgument { source, formal, .. } => append(
                CallFlowRuleKind::Call,
                ValueFlowCarrier::Value(source.clone()),
                ValueFlowCarrier::Port(formal.clone()),
                ProofStatus::Proven,
                EvidenceCompleteness::Complete,
            )?,
            CallBinding::NormalReturn { formal, result, .. } => append(
                CallFlowRuleKind::NormalReturn,
                ValueFlowCarrier::Port(formal.clone()),
                ValueFlowCarrier::Value(result.clone()),
                ProofStatus::Proven,
                EvidenceCompleteness::Complete,
            )?,
            CallBinding::ExceptionalReturn { formal, result, .. } => append(
                CallFlowRuleKind::ExceptionalReturn,
                ValueFlowCarrier::Port(formal.clone()),
                ValueFlowCarrier::Value(result.clone()),
                ProofStatus::Proven,
                EvidenceCompleteness::Complete,
            )?,
        }
    }
    Ok(())
}

fn merge_call_rule_proof(candidate: &ProofStatus, binding: ProofStatus) -> ProofStatus {
    match (candidate, binding) {
        (ProofStatus::Proven, binding) => binding,
        (candidate @ ProofStatus::Unproven(_), ProofStatus::Proven) => candidate.clone(),
        (ProofStatus::Unproven(candidate), ProofStatus::Unproven(binding)) => {
            ProofStatus::Unproven(format!("{candidate}; {binding}").into())
        }
    }
}

fn merge_call_rule_completeness(
    candidate: &EvidenceCompleteness,
    binding: EvidenceCompleteness,
) -> EvidenceCompleteness {
    match (candidate, binding) {
        (EvidenceCompleteness::Complete, binding) => binding,
        (candidate @ EvidenceCompleteness::Partial(_), EvidenceCompleteness::Complete) => {
            candidate.clone()
        }
        (EvidenceCompleteness::Partial(candidate), EvidenceCompleteness::Partial(binding)) => {
            EvidenceCompleteness::Partial(format!("{candidate}; {binding}").into())
        }
    }
}

fn build_local_rule_reverse_index(rules: &[LocalFlowRule]) -> LocalRuleReverseIndex {
    let mut by_point = HashMap::<ProgramPointHandle, Vec<usize>>::default();
    for (index, rule) in rules.iter().enumerate() {
        by_point.entry(rule.point.clone()).or_default().push(index);
    }
    // `rules` is canonicalized in forward event order. Reverse each point so
    // a backward client sees the exact preimage order at a point, including
    // strong updates followed by weak rules at the same target.
    let by_point = by_point
        .into_iter()
        .map(|(point, mut positions)| {
            positions.reverse();
            (point, positions.into_boxed_slice())
        })
        .collect();
    LocalRuleReverseIndex { by_point }
}

fn build_call_rule_reverse_index(rules: &[CallFlowRule]) -> CallRuleReverseIndex {
    let mut by_target = HashMap::<CallRuleTargetKey, Vec<usize>>::default();
    for (index, rule) in rules.iter().enumerate() {
        by_target
            .entry(CallRuleTargetKey {
                call: rule.call.clone(),
                callee: rule.callee.clone(),
                kind: rule.kind,
                target: rule.target,
            })
            .or_default()
            .push(index);
    }
    CallRuleReverseIndex {
        by_target: by_target
            .into_iter()
            .map(|(key, positions)| (key, positions.into_boxed_slice()))
            .collect(),
    }
}

fn build_observation_index<T>(
    observations: &[T],
    key: impl Fn(&T) -> ObservationKey,
) -> ObservationIndex {
    let mut by_point_phase = HashMap::<ObservationKey, Vec<usize>>::default();
    for (index, observation) in observations.iter().enumerate() {
        by_point_phase
            .entry(key(observation))
            .or_default()
            .push(index);
    }
    ObservationIndex {
        by_point_phase: by_point_phase
            .into_iter()
            .map(|(key, positions)| (key, positions.into_boxed_slice()))
            .collect(),
    }
}

fn argument_carrier(
    endpoint: &CallArgumentEndpoint,
) -> Result<ValueFlowCarrier, ValueFlowPlanError> {
    match endpoint {
        CallArgumentEndpoint::Value(value) => Ok(ValueFlowCarrier::Value(value.clone())),
        CallArgumentEndpoint::Location { location, .. } => {
            let cardinality = if matches!(location.path().root(), AccessPathRoot::TypeSummary(_)) {
                ObjectCardinality::Summary
            } else {
                ObjectCardinality::Unknown
            };
            let object = AbstractObject::new(location.path().root().clone(), cardinality)
                .map_err(|_| ValueFlowPlanError::InvalidCallArgumentLocation)?;
            let location = AbstractLocation::new(object, location.path().clone())
                .map_err(|_| ValueFlowPlanError::InvalidCallArgumentLocation)?;
            Ok(ValueFlowCarrier::Location(Box::new(location)))
        }
    }
}

fn build_call_fallback_profiles(
    mut procedures: Vec<&ProcedureHandle>,
    carrier_ids: &HashMap<ValueFlowCarrier, ValueFlowCarrierId>,
    carrier_components: &[usize],
) -> Vec<CallFallbackProfile> {
    procedures.sort_by(|left, right| compare_procedures(left, right));
    procedures.dedup_by(|left, right| *left == *right);
    let mut profiles = Vec::new();
    for procedure in procedures {
        for row in procedure.semantics().call_sites() {
            let Some(call) = procedure.call_site_handle(row.id) else {
                continue;
            };
            let mut input_values = Vec::with_capacity(row.arguments.len().saturating_add(1));
            if let Some(receiver) = row.receiver.and_then(|value| procedure.value_handle(value)) {
                input_values.push(receiver);
            }
            input_values.extend(
                row.arguments
                    .iter()
                    .filter_map(|argument| procedure.value_handle(argument.value)),
            );

            let mut inputs = input_values
                .iter()
                .filter_map(|value| {
                    carrier_ids
                        .get(&ValueFlowCarrier::Value(value.clone()))
                        .copied()
                })
                .collect::<Vec<_>>();
            let mut input_components = inputs
                .iter()
                .map(|carrier| carrier_components[carrier.index()])
                .collect::<Vec<_>>();
            input_components.sort_unstable();
            input_components.dedup();
            inputs.sort_unstable();
            inputs.dedup();
            let result_carrier = |value| {
                procedure
                    .value_handle(value)
                    .and_then(|value| carrier_ids.get(&ValueFlowCarrier::Value(value)).copied())
            };
            profiles.push(CallFallbackProfile {
                call,
                inputs: inputs.into_boxed_slice(),
                reachable_components: input_components.into_boxed_slice(),
                normal_output: row.result.and_then(result_carrier),
                exceptional_output: row.thrown.and_then(result_carrier),
            });
        }
    }
    profiles.sort_by(|left, right| compare_calls(&left.call, &right.call));
    profiles
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct FallbackLocationIndex {
    by_component: HashMap<usize, Vec<ValueFlowCarrierId>>,
    bounded_globals: Vec<ValueFlowCarrierId>,
    location_components: HashMap<ValueFlowCarrierId, usize>,
}

impl FallbackLocationIndex {
    fn retained_heap_bytes(&self) -> usize {
        let by_component = self
            .by_component
            .capacity()
            .saturating_mul(
                std::mem::size_of::<(usize, Vec<ValueFlowCarrierId>)>().saturating_add(1),
            )
            .saturating_add(
                self.by_component
                    .values()
                    .map(|carriers| {
                        carriers
                            .capacity()
                            .saturating_mul(std::mem::size_of::<ValueFlowCarrierId>())
                    })
                    .fold(0usize, usize::saturating_add),
            );
        let bounded_globals = self
            .bounded_globals
            .capacity()
            .saturating_mul(std::mem::size_of::<ValueFlowCarrierId>());
        let location_components = self
            .location_components
            .capacity()
            .saturating_mul(std::mem::size_of::<(ValueFlowCarrierId, usize)>().saturating_add(1));
        by_component
            .saturating_add(bounded_globals)
            .saturating_add(location_components)
    }
}

fn build_fallback_location_index(
    carriers: &[ValueFlowCarrier],
    carrier_ids: &HashMap<ValueFlowCarrier, ValueFlowCarrierId>,
    carrier_components: &[usize],
) -> FallbackLocationIndex {
    let mut index = FallbackLocationIndex::default();
    for (position, carrier) in carriers.iter().enumerate() {
        let ValueFlowCarrier::Location(location) = carrier else {
            continue;
        };
        let id = ValueFlowCarrierId::try_from_index(position)
            .expect("canonical carrier count is bounded before fallback indexing");
        let root = location.path().root();
        if matches!(
            root,
            AccessPathRoot::Static(_)
                | AccessPathRoot::TypeSummary(_)
                | AccessPathRoot::ModuleObject(_)
                | AccessPathRoot::External(_)
        ) {
            index.bounded_globals.push(id);
        } else if let Some(component) = root_carrier(root)
            .and_then(|carrier| carrier_ids.get(&carrier).copied())
            .map(|carrier| carrier_components[carrier.index()])
        {
            index.location_components.insert(id, component);
            index.by_component.entry(component).or_default().push(id);
        }
    }
    index.bounded_globals.sort_unstable();
    for locations in index.by_component.values_mut() {
        locations.sort_unstable();
    }
    index
}

fn root_carrier(root: &AccessPathRoot) -> Option<ValueFlowCarrier> {
    match root {
        AccessPathRoot::Value(value) => Some(ValueFlowCarrier::Value(value.clone())),
        AccessPathRoot::CallResult(result) => {
            Some(ValueFlowCarrier::Value(result.result().clone()))
        }
        AccessPathRoot::ProcedurePort(port) | AccessPathRoot::CaptureSlot(port) => {
            Some(ValueFlowCarrier::Port(port.clone()))
        }
        AccessPathRoot::Allocation(allocation) => allocation
            .procedure()
            .semantics()
            .allocation(allocation.id())
            .and_then(|row| allocation.procedure().value_handle(row.result))
            .map(ValueFlowCarrier::Value),
        AccessPathRoot::LexicalCell(location) => location
            .procedure()
            .semantics()
            .memory_location(location.id())
            .and_then(|row| match row.kind {
                MemoryLocationKind::LexicalCell { binding } => {
                    location.procedure().value_handle(binding)
                }
                _ => None,
            })
            .map(ValueFlowCarrier::Value),
        AccessPathRoot::Static(_)
        | AccessPathRoot::TypeSummary(_)
        | AccessPathRoot::ModuleObject(_)
        | AccessPathRoot::External(_) => None,
    }
}

fn build_carrier_components(carrier_count: usize, local_rules: &[LocalFlowRule]) -> Vec<usize> {
    fn find_root(parents: &mut [usize], mut index: usize) -> usize {
        while parents[index] != index {
            parents[index] = parents[parents[index]];
            index = parents[index];
        }
        index
    }

    let mut parents = (0..carrier_count).collect::<Vec<_>>();
    let mut ranks = vec![0_u8; carrier_count];
    for rule in local_rules {
        let source = find_root(&mut parents, rule.source.index());
        let target = find_root(&mut parents, rule.target.index());
        if source == target {
            continue;
        }
        match ranks[source].cmp(&ranks[target]) {
            Ordering::Less => parents[source] = target,
            Ordering::Greater => parents[target] = source,
            Ordering::Equal => {
                parents[target] = source;
                ranks[source] = ranks[source].saturating_add(1);
            }
        }
    }
    (0..carrier_count)
        .map(|index| find_root(&mut parents, index))
        .collect()
}

fn compare_snapshots(left: &ValueFlowSnapshot, right: &ValueFlowSnapshot) -> Ordering {
    compare_procedures(left.procedure(), right.procedure()).then_with(|| {
        compare_call_contexts(left.context().calls(), right.context().calls()).then_with(|| {
            left.context()
                .was_truncated()
                .cmp(&right.context().was_truncated())
        })
    })
}

fn compare_bindings(left: &CallBindings, right: &CallBindings) -> Ordering {
    compare_calls(left.call(), right.call())
        .then_with(|| compare_procedures(left.callee(), right.callee()))
        .then_with(|| compare_call_contexts(left.context().calls(), right.context().calls()))
        .then_with(|| {
            left.context()
                .was_truncated()
                .cmp(&right.context().was_truncated())
        })
}

fn compare_call_contexts(left: &[CallSiteHandle], right: &[CallSiteHandle]) -> Ordering {
    left.iter()
        .zip(right)
        .find_map(|(left, right)| {
            let ordering = compare_calls(left, right);
            (ordering != Ordering::Equal).then_some(ordering)
        })
        .unwrap_or_else(|| left.len().cmp(&right.len()))
}

fn compare_local_rules(left: &LocalFlowRule, right: &LocalFlowRule) -> Ordering {
    compare_points(&left.point, &right.point)
        .then_with(|| left.event_index.cmp(&right.event_index))
        .then_with(|| left.source.cmp(&right.source))
        .then_with(|| left.target.cmp(&right.target))
        .then_with(|| relation_kind_rank(left.kind).cmp(&relation_kind_rank(right.kind)))
        .then_with(|| transfer_rank(left.transfer).cmp(&transfer_rank(right.transfer)))
}

fn transfer_rank(transfer: Option<ValueTransfer>) -> (u8, u8, u32) {
    use crate::analyzer::semantic::{
        MoveInvalidation, TransferKind, TransferOperation, ValuePreservation,
    };

    let Some(transfer) = transfer else {
        return (0, 0, 0);
    };
    let (operation, call_site) = match transfer.operation {
        TransferOperation::None => (0, 0),
        TransferOperation::CallSite(call) => (1, call.get()),
        TransferOperation::Unknown => (2, 0),
    };
    let kind = match transfer.kind {
        TransferKind::Copy => 1,
        TransferKind::AggregateCopy => 2,
        TransferKind::Move {
            invalidation: MoveInvalidation::Invalidated,
        } => 3,
        TransferKind::Move {
            invalidation: MoveInvalidation::Unknown,
        } => 4,
        TransferKind::Conversion {
            preservation: ValuePreservation::Identity,
        } => 5,
        TransferKind::Conversion {
            preservation: ValuePreservation::Preserving,
        } => 6,
        TransferKind::Conversion {
            preservation: ValuePreservation::Changing,
        } => 7,
        TransferKind::Boxing => 8,
        TransferKind::Unboxing => 9,
    };
    (kind, operation, call_site)
}

fn same_local_rules(left: &ValueFlowPlan, right: &ValueFlowPlan) -> bool {
    left.local_rules.len() == right.local_rules.len()
        && left
            .local_rules
            .iter()
            .zip(&right.local_rules)
            .all(|(left_rule, right_rule)| {
                left_rule.point == right_rule.point
                    && left_rule.event_index == right_rule.event_index
                    && left_rule.kind == right_rule.kind
                    && left_rule.transfer == right_rule.transfer
                    && left.carrier_keys[left_rule.source.index()]
                        == right.carrier_keys[right_rule.source.index()]
                    && left.carrier_keys[left_rule.target.index()]
                        == right.carrier_keys[right_rule.target.index()]
                    && left_rule.proof == right_rule.proof
                    && left_rule.completeness == right_rule.completeness
                    && left_rule.strong_update == right_rule.strong_update
            })
}

fn same_call_rules(left: &ValueFlowPlan, right: &ValueFlowPlan) -> bool {
    left.call_rules.len() == right.call_rules.len()
        && left
            .call_rules
            .iter()
            .zip(&right.call_rules)
            .all(|(left_rule, right_rule)| {
                left_rule.call == right_rule.call
                    && left_rule.callee == right_rule.callee
                    && left_rule.kind == right_rule.kind
                    && left.carrier_keys[left_rule.source.index()]
                        == right.carrier_keys[right_rule.source.index()]
                    && left.carrier_keys[left_rule.target.index()]
                        == right.carrier_keys[right_rule.target.index()]
                    && left_rule.proof == right_rule.proof
                    && left_rule.completeness == right_rule.completeness
            })
}

fn same_summary_location_bindings(left: &ValueFlowPlan, right: &ValueFlowPlan) -> bool {
    left.summary_location_bindings.len() == right.summary_location_bindings.len()
        && left
            .summary_location_bindings
            .iter()
            .zip(&right.summary_location_bindings)
            .all(|(left_binding, right_binding)| {
                left_binding.call == right_binding.call
                    && left_binding.port == right_binding.port
                    && left.carrier_keys[left_binding.carrier.index()]
                        == right.carrier_keys[right_binding.carrier.index()]
            })
}

fn relation_kind_rank(kind: ValueFlowRelationKind) -> u8 {
    match kind {
        ValueFlowRelationKind::Assignment => 0,
        ValueFlowRelationKind::Parameter => 1,
        ValueFlowRelationKind::Receiver => 2,
        ValueFlowRelationKind::NormalReturn => 3,
        ValueFlowRelationKind::ExceptionalReturn => 4,
        ValueFlowRelationKind::Allocation => 5,
        ValueFlowRelationKind::MemoryLoad => 6,
        ValueFlowRelationKind::MemoryStore => 7,
        ValueFlowRelationKind::Capture => 8,
        ValueFlowRelationKind::LanguageDefined => 9,
        ValueFlowRelationKind::HandlerBinding => 10,
        ValueFlowRelationKind::ContainerCollapse => 11,
    }
}

fn compare_call_rules(left: &CallFlowRule, right: &CallFlowRule) -> Ordering {
    compare_calls(&left.call, &right.call)
        .then_with(|| compare_procedures(&left.callee, &right.callee))
        .then_with(|| call_rule_rank(left.kind).cmp(&call_rule_rank(right.kind)))
        .then_with(|| left.source.cmp(&right.source))
        .then_with(|| left.target.cmp(&right.target))
}

fn call_rule_rank(kind: CallFlowRuleKind) -> u8 {
    match kind {
        CallFlowRuleKind::Call => 0,
        CallFlowRuleKind::NormalReturn => 1,
        CallFlowRuleKind::ExceptionalReturn => 2,
    }
}

fn compare_procedures(left: &ProcedureHandle, right: &ProcedureHandle) -> Ordering {
    left.artifact()
        .key()
        .cmp(right.artifact().key())
        .then_with(|| left.semantics().locator().cmp(right.semantics().locator()))
        .then_with(|| left.id().cmp(&right.id()))
        .then_with(|| {
            Arc::as_ptr(left.artifact())
                .cast::<()>()
                .cmp(&Arc::as_ptr(right.artifact()).cast::<()>())
        })
}

fn compare_points(left: &ProgramPointHandle, right: &ProgramPointHandle) -> Ordering {
    compare_procedures(left.procedure(), right.procedure()).then_with(|| left.id().cmp(&right.id()))
}

fn compare_edge_kills(left: &ValueFlowEdgeKillSpec, right: &ValueFlowEdgeKillSpec) -> Ordering {
    compare_points(&left.point, &right.point)
        .then_with(|| left.target.cmp(&right.target))
        .then_with(|| left.kind.label().cmp(right.kind.label()))
        .then_with(|| {
            left.carrier
                .stable_key()
                .ok()
                .cmp(&right.carrier.stable_key().ok())
        })
        .then_with(|| left.sources.cmp(&right.sources))
}

fn build_edge_kill_index(
    specs: &[ValueFlowEdgeKillSpec],
    carrier_ids: &HashMap<ValueFlowCarrier, ValueFlowCarrierId>,
    sources: &[BoundValueFlowSource],
) -> Result<EdgeKillIndex, ValueFlowPlanError> {
    let mut by_edge = HashMap::<EdgeKillKey, Vec<BoundValueFlowEdgeKill>>::default();
    for spec in specs {
        let carrier = *carrier_ids
            .get(&spec.carrier)
            .ok_or(ValueFlowPlanError::MissingCarrier)?;
        let source_ids = spec
            .sources
            .iter()
            .map(|key| {
                sources
                    .binary_search_by(|source| source.spec.key().cmp(key))
                    .map(|index| sources[index].id)
                    .map_err(|_| ValueFlowPlanError::InvalidEdgeKill)
            })
            .collect::<Result<Box<[_]>, _>>()?;
        by_edge
            .entry(EdgeKillKey {
                point: spec.point.clone(),
                target: spec.target,
                kind: spec.kind,
            })
            .or_default()
            .push(BoundValueFlowEdgeKill {
                carrier,
                sources: source_ids,
            });
    }
    Ok(EdgeKillIndex {
        by_edge: by_edge
            .into_iter()
            .map(|(key, kills)| (key, kills.into_boxed_slice()))
            .collect(),
    })
}

fn compare_calls(left: &CallSiteHandle, right: &CallSiteHandle) -> Ordering {
    compare_procedures(left.procedure(), right.procedure()).then_with(|| left.id().cmp(&right.id()))
}

fn adjacent_duplicate<'a, T: Eq + 'a>(mut values: impl Iterator<Item = &'a T>) -> bool {
    let Some(mut previous) = values.next() else {
        return false;
    };
    for value in values {
        if value == previous {
            return true;
        }
        previous = value;
    }
    false
}
