//! One root's class-set plan.
//!
//! A [`TypeFlowPlan`] is a [`ValueFlowPlan`] whose sources are the
//! class-producing sites of every procedure in the root's discovered closure
//! (constructor calls, literals, container literals, declared parameters, and
//! one explicit Unknown source wherever the engine cannot classify a value)
//! and whose sinks are the member accesses. A side table maps each source id
//! to its class atom and each sink id to its member-access site, so the
//! solver's meetings answer "which classes can reach this receiver".

use std::error::Error;
use std::fmt;
use std::path::Path;

use brokk_bifrost_core::profiling;

use crate::analyzer::read_ledger::ReadKey;
use crate::analyzer::semantic::cfg_algorithms::{
    CfgAlgorithmBudget, CfgAlgorithmError, CfgAlgorithmRequest, postdominators,
};
use crate::analyzer::semantic::{
    CallSiteId, CancellationToken, ClassAtom, ClassIdentity, ClassSeed, DispatchReadAttribution,
    DispatchReadUnattributedReason, EvidenceCompleteness, GuardPredicate, LengthDelimitedDigest,
    MemberAccessKind, MemberAccessQuery, MemberLookup, MemoryLocationKind, NarrowingVerdict,
    ProcedureHandle, ProcedurePortHandle, ProgramPointHandle, ProgramPointId, ProofStatus,
    SemanticBudget, SemanticCallSite, SemanticEffect, SemanticLocator, SemanticProviderError,
    SemanticValueKind, SemanticWork, SourceSite, SourceSiteKind, SourceSpan, StableDigest,
    TypeFlowAdapter, UnknownReason, ValueFlowEndpoint, ValueFlowSnapshot,
};
use crate::analyzer::{ProjectFile, WorkspaceAnalyzer};
use crate::dataflow::SemanticInputStatus;
use crate::dataflow::{
    ExternalSummaryCompatibilityKey, SummaryBehaviorKey, SummaryContextKey, SummarySchemaVersion,
    SummarySemanticsVersion, UnmodeledCallBehavior,
};
use crate::hash::{HashMap, HashSet};
use crate::value_flow::{
    BindingCoverage, CallSiteCoverage, ClosureCutDecider, ClosureLimits, DiscoveredClosure,
    DispatchReadCollector, DispatchStatus, DurableProcedureKey, ProcedureDispatchRead, SkipReason,
    ValueFlowCarrier, ValueFlowEdgeKillSpec, ValueFlowEventKey, ValueFlowEventKind, ValueFlowInput,
    ValueFlowObservationPhase, ValueFlowPlan, ValueFlowPlanError, ValueFlowSinkId,
    ValueFlowSinkSpec, ValueFlowSourceId, ValueFlowSourceSpec, WorkspaceValueFlowProvider,
    discover_closure_with_cuts,
};
use crate::{ProcedureSummaryBindingError, bind_active_unmaterialized_procedure_summaries};

use super::binding_refinement::{self, GuardBindings};
use super::correlations::{CorrelationAnalysis, CorrelationError, analyze_correlations};
use super::field_refinement::{self, FieldLoadRefinement, FieldVersion};
use super::field_slots::{FieldSlotIndex, MemberStoreEvidence, receiver_values};
use super::refinement_sources::DefinitionSources;
use super::summary::class_set_local_structure_digest;

/// Restrict the dependency relation to transfers that preserve runtime class.
/// Computation result seeds are added separately by `seed_procedure`.
pub(super) fn class_set_snapshot(
    input: ValueFlowInput<ValueFlowSnapshot>,
) -> ValueFlowInput<ValueFlowSnapshot> {
    let (snapshot, status) = input.into_parts();
    ValueFlowInput::new(snapshot.into_class_identity_projection(), status)
}

/// One member access whose receiver's class set the solve computes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberAccessSite {
    pub procedure: ProcedureHandle,
    pub point: ProgramPointHandle,
    /// Present exactly for a call-shaped access; load-shaped field access has
    /// no call-site identity.
    pub call: Option<CallSiteId>,
    pub file: ProjectFile,
    pub span: SourceSpan,
    pub member: Box<str>,
    pub kind: MemberAccessKind,
}

/// The exact dispatch inputs read while discovering one procedure.
///
/// `Complete` is authoritative even when its slice is empty: the procedure
/// was in the discovered closure and crossed no dispatch funnel. One or more
/// `Unattributed` reasons instead make the contract unusable for summary
/// publication; attributed reads observed alongside them are deliberately not
/// exposed as if they were complete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcedureDispatchReadContract {
    Complete(Box<[ReadKey]>),
    Unattributed(Box<[DispatchReadUnattributedReason]>),
}

/// A root's value-flow plan plus the class-set tables keyed by its ids.
///
/// The discovered closure is consumed by construction: its snapshots and
/// bindings move into the value-flow plan. Its per-call coverage is retained
/// beside them so `interpret` can attribute an unreached sink to the boundary
/// (`UnresolvedCall`, `Truncated`) the coverage names, the same derivation
/// the seeds already use.
#[derive(Debug)]
pub struct TypeFlowPlan {
    value_flow: ValueFlowPlan,
    atoms: Vec<ClassAtom>,
    source_sites: Vec<SourceSite>,
    member_surface_sources: HashSet<ValueFlowEventKey>,
    sinks: Vec<MemberAccessSite>,
    coverage: HashMap<(DurableProcedureKey, CallSiteId), CallSiteCoverage>,
    dispatch_reads: HashMap<DurableProcedureKey, ProcedureDispatchReadContract>,
    local_structure_digests: HashMap<DurableProcedureKey, StableDigest>,
    summary_cuts: HashSet<DurableProcedureKey>,
    field_slot_semantic_budget_exhausted: bool,
    provider_failure_observed: bool,
    field_refinements: Vec<(ProcedureHandle, FieldLoadRefinement)>,
    refinement_budget_exhausted: bool,
    correlations: Vec<(ProcedureHandle, CorrelationAnalysis)>,
    guard_bindings: HashMap<DurableProcedureKey, GuardBindings>,
}

fn closure_has_provider_failure(closure: &DiscoveredClosure) -> bool {
    provider_failure_observed(
        closure.skipped.iter().map(|(_, reason)| reason),
        closure.coverage.values(),
    )
}

fn provider_failure_observed<'a>(
    skipped: impl IntoIterator<Item = &'a SkipReason>,
    coverage: impl IntoIterator<Item = &'a CallSiteCoverage>,
) -> bool {
    skipped
        .into_iter()
        .any(|reason| matches!(reason, SkipReason::ProviderError { .. }))
        || coverage.into_iter().any(|coverage| {
            matches!(coverage.dispatch, DispatchStatus::ProviderError { .. })
                || coverage
                    .bindings
                    .iter()
                    .any(|binding| matches!(binding, BindingCoverage::ProviderError { .. }))
        })
}

fn canonical_dispatch_read_contract(
    attributions: impl IntoIterator<Item = DispatchReadAttribution>,
) -> ProcedureDispatchReadContract {
    let mut reads = Vec::new();
    let mut unattributed = Vec::new();
    for attribution in attributions {
        match attribution {
            DispatchReadAttribution::Attributed(read) => reads.push(read),
            DispatchReadAttribution::Unattributed(reason) => unattributed.push(reason),
        }
    }
    reads.sort_unstable();
    reads.dedup();
    unattributed.sort_unstable();
    unattributed.dedup();
    if unattributed.is_empty() {
        ProcedureDispatchReadContract::Complete(reads.into_boxed_slice())
    } else {
        ProcedureDispatchReadContract::Unattributed(unattributed.into_boxed_slice())
    }
}

fn canonical_dispatch_read_contracts(
    procedures: &[ProcedureHandle],
    observations: Vec<ProcedureDispatchRead>,
    certified: HashMap<DurableProcedureKey, Box<[ReadKey]>>,
) -> HashMap<DurableProcedureKey, ProcedureDispatchReadContract> {
    let mut pending = HashMap::default();
    for procedure in procedures {
        let previous = pending.insert(
            procedure.durable_key(),
            Vec::<DispatchReadAttribution>::new(),
        );
        assert!(
            previous.is_none(),
            "the discovered closure contains each procedure exactly once"
        );
    }
    for observation in observations {
        let (caller, attribution) = observation.into_parts();
        let contract = pending
            .get_mut(&caller.durable_key())
            .expect("every dispatch observation belongs to a discovered procedure");
        contract.push(attribution);
    }
    let mut contracts = pending
        .into_iter()
        .map(|(procedure, attributions)| {
            (procedure, canonical_dispatch_read_contract(attributions))
        })
        .collect::<HashMap<_, _>>();
    for (procedure, reads) in certified {
        let contract = contracts
            .get_mut(&procedure)
            .expect("a certified dispatch contract belongs to a mounted surface");
        assert!(
            matches!(contract, ProcedureDispatchReadContract::Complete(reads) if reads.is_empty()),
            "identity-only surfaces have no live dispatch observations"
        );
        *contract = ProcedureDispatchReadContract::Complete(reads);
    }
    contracts
}

/// Why one root's class-set plan could not be built.
#[derive(Debug)]
pub enum TypeFlowPlanError {
    /// The closure walk's provider failed on the root's own relations.
    Discovery(SemanticProviderError),
    /// The root's relations were unavailable, so no plan can seed its body.
    RootRelationsUnavailable,
    WorkspaceEnumeration(std::io::Error),
    Cancelled,
    RefinementBudget(crate::analyzer::semantic::SemanticBudgetExceeded),
    Flow(ValueFlowPlanError),
    GuardControl(CfgAlgorithmError<ProgramPointId>),
    ExternalSummary(ProcedureSummaryBindingError),
}

impl fmt::Display for TypeFlowPlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Discovery(error) => write!(formatter, "type-flow discovery failed: {error}"),
            Self::RootRelationsUnavailable => {
                formatter.write_str("the root procedure's value-flow relations are unavailable")
            }
            Self::WorkspaceEnumeration(error) => {
                write!(formatter, "type-flow workspace enumeration failed: {error}")
            }
            Self::Cancelled => formatter.write_str("type-flow refinement was cancelled"),
            Self::RefinementBudget(error) => {
                write!(formatter, "type-flow refinement budget exhausted: {error}")
            }
            Self::Flow(error) => write!(formatter, "type-flow value-flow plan failed: {error}"),
            Self::GuardControl(error) => {
                write!(
                    formatter,
                    "type-flow guard control analysis failed: {error:?}"
                )
            }
            Self::ExternalSummary(error) => {
                write!(
                    formatter,
                    "type-flow external summary binding failed: {error}"
                )
            }
        }
    }
}

impl Error for TypeFlowPlanError {}

impl From<CorrelationError> for TypeFlowPlanError {
    fn from(error: CorrelationError) -> Self {
        match error {
            CorrelationError::Budget(error) => Self::RefinementBudget(error),
            CorrelationError::Cancelled { .. } => Self::Cancelled,
        }
    }
}

impl From<ValueFlowPlanError> for TypeFlowPlanError {
    fn from(error: ValueFlowPlanError) -> Self {
        Self::Flow(error)
    }
}

/// One spec under construction plus the reporting record parallel to it.
struct SeedTables {
    sources: Vec<(ValueFlowSourceSpec, ClassAtom, SourceSite)>,
    sinks: Vec<(ValueFlowSinkSpec, MemberAccessSite)>,
    member_surface_sources: HashSet<ValueFlowEventKey>,
    /// Distinct ordinals at each stable source location. Several program
    /// points can share a source mapping.
    ordinals: HashMap<(SemanticLocator, ValueFlowEventKind), u32>,
}

impl SeedTables {
    fn new() -> Self {
        Self {
            sources: Vec::new(),
            sinks: Vec::new(),
            ordinals: HashMap::default(),
            member_surface_sources: HashSet::default(),
        }
    }

    fn push_source(
        &mut self,
        point: &ProgramPointHandle,
        phase: ValueFlowObservationPhase,
        carrier: ValueFlowCarrier,
        atom: ClassAtom,
        site: SourceSite,
    ) {
        let key = self.event_key(point, ValueFlowEventKind::Source);
        self.sources.push((
            ValueFlowSourceSpec::new(
                key,
                point.clone(),
                phase,
                carrier,
                ProofStatus::Proven,
                EvidenceCompleteness::Complete,
            ),
            atom,
            site,
        ));
    }

    fn push_member_surface_source(
        &mut self,
        point: &ProgramPointHandle,
        carrier: ValueFlowCarrier,
        atom: ClassAtom,
        site: SourceSite,
    ) {
        assert!(matches!(atom, ClassAtom::Unknown(_)));
        self.push_source(
            point,
            ValueFlowObservationPhase::BeforeEffects,
            carrier,
            atom,
            site,
        );
        self.member_surface_sources.insert(
            self.sources
                .last()
                .expect("the source was just inserted")
                .0
                .key()
                .clone(),
        );
    }

    fn push_sink(
        &mut self,
        point: &ProgramPointHandle,
        carrier: ValueFlowCarrier,
        site: MemberAccessSite,
    ) {
        let key = self.event_key(point, ValueFlowEventKind::Sink);
        self.sinks.push((
            ValueFlowSinkSpec::new(
                key,
                point.clone(),
                ValueFlowObservationPhase::BeforeEffects,
                carrier,
                ProofStatus::Proven,
                EvidenceCompleteness::Complete,
            ),
            site,
        ));
    }

    fn event_key(
        &mut self,
        point: &ProgramPointHandle,
        kind: ValueFlowEventKind,
    ) -> ValueFlowEventKey {
        let base = ValueFlowEventKey::at_point(point, 0, kind)
            .expect("a live point retains its source mapping");
        let ordinal = self
            .ordinals
            .entry((base.site().clone(), kind))
            .or_insert(0);
        let key = ValueFlowEventKey::at_point(point, *ordinal, kind)
            .expect("a live point with a retained source mapping yields an event key");
        *ordinal += 1;
        key
    }
}

fn file_for_locator(
    workspace: &WorkspaceAnalyzer,
    locator: &SemanticLocator,
) -> Option<ProjectFile> {
    workspace
        .analyzer()
        .project()
        .file_by_rel_path(Path::new(locator.path().as_str()))
}

fn mapping_span(
    procedure: &ProcedureHandle,
    source: crate::analyzer::semantic::SourceMappingId,
) -> SourceSpan {
    procedure
        .semantics()
        .source_mapping(source)
        .expect("a retained IR row's source mapping is live")
        .locator
        .anchor()
        .span()
}

/// The point and result carrier on which a call's class fact rides: the
/// normal continuation, where the result exists after the call returns.
fn call_result_anchor(
    procedure: &ProcedureHandle,
    call: &SemanticCallSite,
) -> Option<(ProgramPointHandle, ValueFlowCarrier)> {
    let target = call.normal_continuation.target()?;
    let result = call.result?;
    let point = procedure
        .point_handle(target)
        .expect("a call site's normal continuation point is live");
    let carrier = ValueFlowCarrier::Value(
        procedure
            .value_handle(result)
            .expect("a call site's result value is live"),
    );
    Some((point, carrier))
}

fn narrowing_member_lookup(
    workspace: &WorkspaceAnalyzer,
    adapter: &dyn TypeFlowAdapter,
    field_slots: &FieldSlotIndex,
    class: &ClassIdentity,
    member: &str,
) -> MemberLookup {
    match adapter.member_lookup(workspace, MemberAccessKind::Load, class, member) {
        MemberLookup::Absent | MemberLookup::DeclarationAbsent
            if field_slots.dynamic_write_evidence(class).next().is_some() =>
        {
            MemberLookup::Unknown(UnknownReason::DynamicFieldWrite)
        }
        MemberLookup::DeclarationAbsent => {
            match field_slots.member_store_evidence(workspace, adapter, class, member) {
                MemberStoreEvidence::NoStore => MemberLookup::Absent,
                MemberStoreEvidence::Stored | MemberStoreEvidence::Unknown => {
                    MemberLookup::Unknown(UnknownReason::FieldSlotIncomplete)
                }
            }
        }
        result => result,
    }
}

fn field_atom_survives(
    workspace: &WorkspaceAnalyzer,
    adapter: &dyn TypeFlowAdapter,
    field_slots: &FieldSlotIndex,
    procedure: &ProcedureHandle,
    refinement: &FieldLoadRefinement,
    atom: &ClassAtom,
) -> bool {
    let ClassAtom::Class(class) = atom else {
        return true;
    };
    let member_lookup = |class: &ClassIdentity, member: &str| {
        narrowing_member_lookup(workspace, adapter, field_slots, class, member)
    };
    refinement.alternatives.iter().any(|alternative| {
        alternative.guards.iter().all(|&(index, truth)| {
            let verdicts = adapter.narrowing_verdicts(
                workspace,
                procedure,
                &procedure.semantics().guard_facts()[index],
                &[class],
                &member_lookup,
            );
            assert_eq!(verdicts.len(), 1, "one verdict for the field candidate");
            !matches!(
                (&verdicts[0], truth),
                (NarrowingVerdict::Drop, true) | (NarrowingVerdict::Keep, false)
            )
        })
    })
}

#[allow(clippy::too_many_arguments)]
fn guard_transfers(
    workspace: &WorkspaceAnalyzer,
    adapter: &dyn TypeFlowAdapter,
    field_slots: &FieldSlotIndex,
    procedures: &[ProcedureHandle],
    tables: &mut SeedTables,
    guard_bindings: &HashMap<DurableProcedureKey, GuardBindings>,
    cancellation: &CancellationToken,
) -> Result<Vec<ValueFlowEdgeKillSpec>, TypeFlowPlanError> {
    let mut sources_by_class = HashMap::<ClassIdentity, Vec<ValueFlowEventKey>>::default();
    for (source, atom, _) in &tables.sources {
        let ClassAtom::Class(atom) = atom else {
            continue;
        };
        sources_by_class
            .entry(atom.clone())
            .or_default()
            .push(source.key().clone());
    }
    let mut kills = Vec::new();
    let class_sources = sources_by_class.iter().collect::<Vec<_>>();
    let classes = class_sources
        .iter()
        .map(|(class, _)| *class)
        .collect::<Vec<_>>();
    let member_lookup = |class: &ClassIdentity, member: &str| {
        narrowing_member_lookup(workspace, adapter, field_slots, class, member)
    };
    let mut cfg_budget = CfgAlgorithmBudget::default();
    for procedure in procedures {
        let Some(bindings) = guard_bindings.get(&procedure.durable_key()) else {
            continue;
        };
        let mut joins = None;
        for (guard_index, guard) in procedure.semantics().guard_facts().iter().enumerate() {
            if classes.is_empty() || (guard.true_edge.is_none() && guard.false_edge.is_none()) {
                continue;
            }
            let (binding, call_verdicts) = match guard.predicate {
                GuardPredicate::InstanceOf { .. }
                | GuardPredicate::ExactClass { .. }
                | GuardPredicate::HasMember { .. }
                | GuardPredicate::Truthy { .. }
                | GuardPredicate::NullComparison { .. } => {
                    (bindings.binding_for_guard(guard_index), None)
                }
                GuardPredicate::Opaque { .. } => {
                    let Some((value, verdicts)) = adapter.call_guard_narrowing(
                        workspace,
                        procedure,
                        guard,
                        &classes,
                        &member_lookup,
                    ) else {
                        continue;
                    };
                    (
                        bindings.binding_at_point(guard.point, value),
                        Some(verdicts),
                    )
                }
                GuardPredicate::ConstantBoolean { .. }
                | GuardPredicate::ConstantEquality { .. } => continue,
            };
            let Some(binding) = binding else {
                continue;
            };
            let carrier = binding_carrier(procedure, binding);
            let verdicts = call_verdicts.unwrap_or_else(|| {
                adapter.narrowing_verdicts(workspace, procedure, guard, &classes, &member_lookup)
            });
            assert_eq!(
                verdicts.len(),
                classes.len(),
                "one guard verdict per candidate class"
            );
            let mut remainders = HashMap::<UnknownReason, Vec<ValueFlowEventKey>>::default();
            for ((_, atom_sources), verdict) in class_sources.iter().zip(&verdicts) {
                if let NarrowingVerdict::Incomplete(reason) = verdict {
                    remainders
                        .entry(reason.clone())
                        .or_default()
                        .extend(atom_sources.iter().cloned());
                }
            }
            if guard.true_edge.is_some() && !remainders.is_empty() {
                let semantics = procedure.semantics();
                if joins.is_none() {
                    joins = Some(
                        postdominators(
                            semantics,
                            semantics.entry_point(),
                            semantics.normal_exit_point(),
                            semantics.exceptional_exit_point(),
                            &mut CfgAlgorithmRequest::new(&mut cfg_budget, cancellation),
                        )
                        .map_err(TypeFlowPlanError::GuardControl)?,
                    );
                }
                let join = joins
                    .as_ref()
                    .expect("guard postdominators were computed")
                    .immediate_postdominator(semantics, guard.point);
                let point = procedure
                    .point_handle(guard.point)
                    .expect("a retained guard point is live");
                let mut remainders = remainders.into_iter().collect::<Vec<_>>();
                remainders.sort_unstable_by(|(left, _), (right, _)| left.cmp(right));
                for (reason, inputs) in remainders {
                    let site = source_site(
                        workspace,
                        procedure,
                        mapping_span(procedure, guard.source),
                        SourceSiteKind::Unknown,
                    )
                    .expect("a workspace guard retains its source file");
                    let key = tables.event_key(&point, ValueFlowEventKind::Source);
                    tables.sources.push((
                        ValueFlowSourceSpec::new(
                            key.clone(),
                            point.clone(),
                            ValueFlowObservationPhase::AfterEffects,
                            carrier.clone(),
                            ProofStatus::Proven,
                            EvidenceCompleteness::Complete,
                        )
                        .when_sources_reach(inputs),
                        ClassAtom::Unknown(reason),
                        site,
                    ));
                    // The source requires an undecidable candidate on the
                    // guarded binding. Zero can reach an infeasible arm, but
                    // must not manufacture a remainder there.
                    for (edge_id, edge) in semantics.successor_edges(guard.point) {
                        if Some(edge_id) != guard.true_edge {
                            kills.push(ValueFlowEdgeKillSpec {
                                point: point.clone(),
                                target: edge.target_point,
                                kind: edge.kind,
                                carrier: carrier.clone(),
                                sources: vec![key.clone()],
                            });
                        }
                    }
                    // The guard conditions this binding only until its false
                    // arm or reconvergence. A later conjunct can also reach
                    // the false arm. Copies made inside the protected arm keep
                    // their remainder on their own carriers.
                    let false_target = guard
                        .false_edge
                        .and_then(|edge| semantics.control_edge(edge))
                        .map(|edge| edge.target_point);
                    for target in [false_target, join].into_iter().flatten() {
                        for (_, edge) in semantics.predecessor_edges(target) {
                            kills.push(ValueFlowEdgeKillSpec {
                                point: procedure
                                    .point_handle(edge.source_point)
                                    .expect("a retained predecessor point is live"),
                                target,
                                kind: edge.kind,
                                carrier: carrier.clone(),
                                sources: vec![key.clone()],
                            });
                        }
                    }
                }
            }
            for (dropped_verdict, edge_id) in [
                (NarrowingVerdict::Drop, guard.true_edge),
                (NarrowingVerdict::Keep, guard.false_edge),
            ] {
                let Some(edge) = edge_id.and_then(|id| procedure.semantics().control_edge(id))
                else {
                    continue;
                };
                let mut dropped = Vec::new();
                for ((_, atom_sources), verdict) in class_sources.iter().zip(&verdicts) {
                    if *verdict == dropped_verdict {
                        dropped.extend(atom_sources.iter().cloned());
                    }
                }
                if !dropped.is_empty() {
                    kills.push(ValueFlowEdgeKillSpec {
                        point: procedure
                            .point_handle(guard.point)
                            .expect("a validated guard point remains live"),
                        target: edge.target_point,
                        kind: edge.kind,
                        carrier: carrier.clone(),
                        sources: dropped,
                    });
                }
            }
        }
        for call in procedure.semantics().call_sites() {
            let Some(normal) = call.normal_continuation.target() else {
                continue;
            };
            let point = procedure
                .semantics()
                .point(normal)
                .expect("a normal continuation is retained");
            // Apply a reviewed return condition before the next operation.
            // Python publishes a dedicated continuation marker. Other shapes
            // remain open rather than killing facts after a use or overwrite.
            if !point.events.iter().all(|event| {
                matches!(event.effect, SemanticEffect::CallContinuation {
                    call_site,
                    kind: crate::analyzer::semantic::CallContinuationKind::Normal,
                } if call_site == call.id)
            }) {
                continue;
            }
            for constraint in adapter.normal_return_type_constraints(workspace, procedure, call) {
                if constraint.provenance.ambiguous
                    || constraint.provenance.completeness
                        != crate::analyzer::semantic_model::SemanticModelCompleteness::Complete
                    || constraint.classes.is_empty()
                {
                    continue;
                }
                let Some(binding) = bindings.binding_at_point(normal, constraint.subject) else {
                    continue;
                };
                let mut dropped = Vec::new();
                for (atom, atom_sources) in &sources_by_class {
                    if adapter.instance_of_verdict(workspace, atom, &constraint.classes)
                        == NarrowingVerdict::Drop
                    {
                        dropped.extend(atom_sources.iter().cloned());
                    }
                }
                if dropped.is_empty() {
                    continue;
                }
                let carrier = binding_carrier(procedure, binding);
                for (_, edge) in procedure.semantics().successor_edges(normal) {
                    if edge.kind != crate::analyzer::semantic::ControlEdgeKind::Normal {
                        continue;
                    }
                    kills.push(ValueFlowEdgeKillSpec {
                        point: procedure
                            .point_handle(normal)
                            .expect("the continuation is live"),
                        target: edge.target_point,
                        kind: edge.kind,
                        carrier: carrier.clone(),
                        sources: dropped.clone(),
                    });
                }
            }
        }
    }
    Ok(kills)
}

fn binding_carrier(
    procedure: &ProcedureHandle,
    binding: crate::analyzer::semantic::ValueId,
) -> ValueFlowCarrier {
    ValueFlowCarrier::from(ValueFlowEndpoint::for_value(
        procedure
            .value_handle(binding)
            .expect("a binding origin is live in its procedure"),
    ))
}

/// Procedure-local refinements derived once for one root's solve.
///
/// One root solve builds its plan more than once: a summary-cut build whose
/// sources still need refinement is discarded and rebuilt in full, and every
/// feedback iteration rebuilds the plan again. Binding refinement is a pure
/// function of the procedure's semantic identity, and field refinement of
/// that identity together with the gaps the procedure's snapshot discharges,
/// which the local structure digest already records. Deriving them once per
/// build repeats the work and charges the root's semantic budget for it once
/// per build: one `uvicorn/config.py` root spent 837k of its 1,000,000
/// nested-entry budget deriving `Config.__init__` for a plan it then threw
/// away, leaving too little for the plan it kept (#3163).
///
/// Reuse is charged once per ledger rather than once per process. A ledger
/// that has not yet paid for a reused refinement is charged the work the
/// derivation measured, so an attempt whose staged charge is rolled back
/// pays again on the attempt that replaces it.
#[derive(Debug, Default)]
pub struct ProcedureRefinements {
    bindings: HashMap<StableDigest, DerivedRefinement<GuardBindings>>,
    correlations: HashMap<StableDigest, DerivedRefinement<CorrelationAnalysis>>,
    fields: HashMap<StableDigest, DerivedRefinement<Vec<FieldLoadRefinement>>>,
}

#[derive(Debug)]
struct DerivedRefinement<T> {
    value: T,
    work: SemanticWork,
}

/// Answer one refinement from the cache, deriving it on the first request.
fn reused_or_derived<T: Clone>(
    cache: &mut HashMap<StableDigest, DerivedRefinement<T>>,
    identity: StableDigest,
    budget: &mut SemanticBudget,
    derive: impl FnOnce(&mut SemanticBudget) -> Result<T, CorrelationError>,
) -> Result<T, CorrelationError> {
    if let Some(derived) = cache.get(&identity) {
        if !budget.has_charged_artifact(identity) {
            budget
                .charge(derived.work)
                .map_err(CorrelationError::Budget)?;
            budget.record_charged_artifact(identity);
        }
        return Ok(derived.value.clone());
    }
    if budget.has_charged_artifact(identity) {
        // This accounting scope already paid for this exact derivation under
        // an earlier root whose cache did not outlive it. Deriving it again
        // must not charge the scope twice, so it runs against a scratch child
        // ledger that starts at zero and is discarded.
        let mut scratch = SemanticBudget::new_child(budget.limits(), &budget.scope_snapshot());
        let value = derive(&mut scratch)?;
        cache.insert(
            identity,
            DerivedRefinement {
                value: value.clone(),
                work: scratch.used(),
            },
        );
        return Ok(value);
    }
    let before = budget.used();
    let value = derive(budget)?;
    let work = budget.used().saturating_sub(before);
    budget.record_charged_artifact(identity);
    cache.insert(
        identity,
        DerivedRefinement {
            value: value.clone(),
            work,
        },
    );
    Ok(value)
}

/// The identity of one procedure's semantics. The artifact key already fixes
/// the file's content, the adapter version, the IR version, the configuration,
/// and the dependency fingerprint, so the key and the procedure's dense id
/// name one exact lowered procedure.
fn procedure_semantics_identity(
    domain: &[u8],
    procedure: &ProcedureHandle,
) -> LengthDelimitedDigest {
    let mut digest = LengthDelimitedDigest::new(domain);
    digest.push(procedure.artifact().key().fingerprint().as_bytes());
    digest.push(
        &u64::try_from(procedure.id().index())
            .expect("a dense procedure id fits in u64")
            .to_le_bytes(),
    );
    digest
}

impl TypeFlowPlan {
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        workspace: &WorkspaceAnalyzer,
        adapter: &dyn TypeFlowAdapter,
        field_slots: &FieldSlotIndex,
        root: &ProcedureHandle,
        provider: &WorkspaceValueFlowProvider<'_>,
        limits: ClosureLimits,
        semantic_budget: &mut SemanticBudget,
        cancellation: &CancellationToken,
        refinements: &mut ProcedureRefinements,
    ) -> Result<Self, TypeFlowPlanError> {
        struct NoSummaryCuts;
        impl ClosureCutDecider for NoSummaryCuts {
            fn should_cut(
                &mut self,
                _procedure: &ProcedureHandle,
                _snapshot: &crate::value_flow::ValueFlowInput<
                    crate::analyzer::semantic::ValueFlowSnapshot,
                >,
                _coverage: &HashMap<(DurableProcedureKey, CallSiteId), CallSiteCoverage>,
                _request: &mut crate::analyzer::semantic::SemanticRequest<'_>,
            ) -> bool {
                false
            }
        }
        Self::build_with_summary_cuts(
            workspace,
            adapter,
            field_slots,
            root,
            provider,
            limits,
            semantic_budget,
            cancellation,
            refinements,
            &mut NoSummaryCuts,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn build_with_summary_cuts<C: ClosureCutDecider>(
        workspace: &WorkspaceAnalyzer,
        adapter: &dyn TypeFlowAdapter,
        field_slots: &FieldSlotIndex,
        root: &ProcedureHandle,
        provider: &WorkspaceValueFlowProvider<'_>,
        limits: ClosureLimits,
        semantic_budget: &mut SemanticBudget,
        cancellation: &CancellationToken,
        refinements: &mut ProcedureRefinements,
        cuts: &mut C,
    ) -> Result<Self, TypeFlowPlanError> {
        let dispatch_reads = DispatchReadCollector::default();
        let mut closure = {
            let _scope = profiling::scope("type_flow.discovery");
            let observed_provider = provider.observing_dispatch_reads(dispatch_reads.clone());
            discover_closure_with_cuts(
                &observed_provider,
                root,
                limits,
                semantic_budget,
                cancellation,
                cuts,
            )
            .map_err(TypeFlowPlanError::Discovery)?
        };
        let _scope = profiling::scope("type_flow.plan_build");
        if closure.root_snapshot.is_none() {
            return Err(TypeFlowPlanError::RootRelationsUnavailable);
        }
        let provider_failure_observed = closure_has_provider_failure(&closure);
        let dispatch_reads = canonical_dispatch_read_contracts(
            &closure.procedures,
            dispatch_reads.observations(),
            std::mem::take(&mut closure.certified_dispatch_reads),
        );
        let local_structure_digests = closure
            .snapshots
            .iter()
            .map(|snapshot| {
                Ok((
                    snapshot.value().procedure().durable_key(),
                    class_set_local_structure_digest(snapshot)?,
                ))
            })
            .collect::<Result<HashMap<_, _>, ValueFlowPlanError>>()?;
        let root_key = root.durable_key();
        let summary_cuts = closure
            .summary_cuts
            .iter()
            .map(ProcedureHandle::durable_key)
            .collect();
        let mut unmaterialized_external_targets = closure
            .boundaries
            .iter()
            .filter_map(|boundary| boundary.unmaterialized_external_target().cloned())
            .collect::<Vec<_>>();
        unmaterialized_external_targets.sort_unstable();
        unmaterialized_external_targets.dedup();
        let mut tables = SeedTables::new();
        let mut field_refinements = Vec::new();
        let mut refinement_budget_exhausted = false;
        let mut correlations = Vec::new();
        let mut guard_bindings = HashMap::default();
        for procedure in &closure.procedures {
            let bindings = reused_or_derived(
                &mut refinements.bindings,
                procedure_semantics_identity(b"bifrost-type-flow-binding-refinement-v1", procedure)
                    .finish(),
                semantic_budget,
                |budget| {
                    binding_refinement::derive(workspace, adapter, procedure, budget, cancellation)
                },
            );
            match bindings {
                Ok(bindings) => {
                    guard_bindings.insert(procedure.durable_key(), bindings);
                }
                Err(CorrelationError::Budget(_)) => refinement_budget_exhausted = true,
                Err(CorrelationError::Cancelled { .. }) => {
                    return Err(TypeFlowPlanError::Cancelled);
                }
            }
            let correlation = reused_or_derived(
                &mut refinements.correlations,
                procedure_semantics_identity(b"bifrost-type-flow-correlations-v1", procedure)
                    .finish(),
                semantic_budget,
                |budget| {
                    let mut analysis = analyze_correlations(procedure, budget, Some(cancellation))?;
                    // Only an exclusion with an incompatible definition can
                    // remove a source, so the rest is state the cache would
                    // carry for nothing.
                    analysis
                        .guard_edge_exclusions
                        .retain(|candidate| !candidate.incompatible_data_defs.is_empty());
                    Ok(analysis)
                },
            );
            match correlation {
                Ok(analysis) => {
                    if !analysis.guard_edge_exclusions.is_empty() {
                        correlations.push((procedure.clone(), analysis));
                    }
                }
                Err(CorrelationError::Budget(_)) => refinement_budget_exhausted = true,
                Err(CorrelationError::Cancelled { .. }) => {
                    return Err(TypeFlowPlanError::Cancelled);
                }
            }
            let fields = if let Some(class) = adapter.enclosing_class(workspace, procedure) {
                let snapshot = closure
                    .snapshots
                    .iter()
                    .find(|snapshot| snapshot.value().procedure() == procedure)
                    .map(|snapshot| snapshot.value());
                // The enclosing class and the field-slot index are fixed for
                // one root solve, so the snapshot's local structure -- which
                // records exactly the gap discharges field refinement reads --
                // completes the procedure's identity here.
                let mut identity = procedure_semantics_identity(
                    b"bifrost-type-flow-field-refinement-v1",
                    procedure,
                );
                match local_structure_digests.get(&procedure.durable_key()) {
                    Some(local_structure) => identity.push(local_structure.as_bytes()),
                    None => identity.push(b"no-snapshot"),
                }
                match reused_or_derived(
                    &mut refinements.fields,
                    identity.finish(),
                    semantic_budget,
                    |budget| {
                        field_refinement::derive(
                            workspace,
                            adapter,
                            procedure,
                            snapshot,
                            &class,
                            field_slots,
                            budget,
                            cancellation,
                        )
                    },
                ) {
                    Ok(fields) => fields,
                    Err(CorrelationError::Budget(_)) => {
                        refinement_budget_exhausted = true;
                        Vec::new()
                    }
                    Err(CorrelationError::Cancelled { .. }) => {
                        return Err(TypeFlowPlanError::Cancelled);
                    }
                }
            } else {
                Vec::new()
            };
            if cancellation.is_cancelled() {
                return Err(TypeFlowPlanError::Cancelled);
            }
            seed_procedure(
                workspace,
                adapter,
                field_slots,
                &closure,
                root_key.clone(),
                procedure,
                &mut tables,
                &fields,
            );
            field_refinements.extend(fields.into_iter().map(|field| (procedure.clone(), field)));
        }
        let edge_kills = guard_transfers(
            workspace,
            adapter,
            field_slots,
            &closure.procedures,
            &mut tables,
            &guard_bindings,
            cancellation,
        )?;
        let SeedTables {
            sources,
            sinks,
            member_surface_sources,
            ..
        } = tables;
        // The ValueFlowPlan sorts specs by event key and rejects duplicates,
        // so the atom and site of every spec stay recoverable by key.
        let mut source_specs = Vec::with_capacity(sources.len());
        let mut atoms_by_key = HashMap::default();
        for (spec, atom, site) in sources {
            atoms_by_key.insert(spec.key().clone(), (atom, site));
            source_specs.push(spec);
        }
        let mut sink_specs = Vec::with_capacity(sinks.len());
        let mut sites_by_key = HashMap::default();
        for (spec, site) in sinks {
            sites_by_key.insert(spec.key().clone(), site);
            sink_specs.push(spec);
        }
        let call_behavior = UnmodeledCallBehavior::Optimistic;
        let mut value_flow = ValueFlowPlan::with_call_behavior_and_edge_kills(
            root.clone(),
            closure
                .snapshots
                .into_iter()
                .map(|input| {
                    let (snapshot, status) = input.into_parts();
                    let procedure = snapshot.procedure().clone();
                    // Field versions supply these load results, including
                    // explicit open alternatives. Ordinary heap loads would
                    // bypass that replacement and resurrect overwritten values
                    // whenever repeated accesses share a canonical location.
                    let snapshot = snapshot.without_memory_loads_into(
                        field_refinements
                            .iter()
                            .filter(|(owner, _)| owner == &procedure)
                            .map(|(_, field)| (field.point, field.result)),
                    );
                    class_set_snapshot(ValueFlowInput::new(snapshot, status))
                })
                .collect(),
            closure.bindings,
            source_specs,
            sink_specs,
            edge_kills,
            call_behavior,
        )?;
        if let Some(active) = provider.oracle().active_semantic_models()
            && !unmaterialized_external_targets.is_empty()
        {
            let compatibility = ExternalSummaryCompatibilityKey::new(
                SummarySchemaVersion::CURRENT,
                SummarySemanticsVersion::hash_bytes(
                    b"bifrost.production-value-flow.semantic-pack.v1",
                ),
                SummaryContextKey::hash_bytes(
                    b"bifrost.production-value-flow.empty-call-context.v1",
                ),
                SummaryBehaviorKey::hash_bytes(
                    b"bifrost.production-value-flow.external-boundary.v1",
                )
                .with_unmodeled_call_behavior(call_behavior),
                root.artifact().key().dependencies(),
                call_behavior,
            );
            if let Some(summaries) = bind_active_unmaterialized_procedure_summaries(
                active,
                &unmaterialized_external_targets,
                root.artifact().key(),
                compatibility,
            )
            .map_err(TypeFlowPlanError::ExternalSummary)?
            {
                value_flow = value_flow.with_external_summaries(summaries)?;
            }
        }
        let mut atoms = Vec::with_capacity(value_flow.sources().len());
        let mut source_sites = Vec::with_capacity(value_flow.sources().len());
        for (id, spec) in value_flow.sources() {
            debug_assert_eq!(
                id.index(),
                atoms.len(),
                "source ids are dense in plan order"
            );
            let (atom, site) = atoms_by_key
                .remove(spec.key())
                .expect("every plan source was seeded");
            atoms.push(atom);
            source_sites.push(site);
        }
        let mut member_sites = Vec::with_capacity(value_flow.sinks().len());
        for (id, spec) in value_flow.sinks() {
            debug_assert_eq!(
                id.index(),
                member_sites.len(),
                "sink ids are dense in plan order"
            );
            member_sites.push(
                sites_by_key
                    .remove(spec.key())
                    .expect("every plan sink was seeded"),
            );
        }
        Ok(Self {
            value_flow,
            atoms,
            source_sites,
            member_surface_sources,
            sinks: member_sites,
            coverage: closure.coverage,
            dispatch_reads,
            local_structure_digests,
            summary_cuts,
            field_slot_semantic_budget_exhausted: field_slots.semantic_budget_exhausted()
                || refinement_budget_exhausted,
            provider_failure_observed,
            field_refinements,
            refinement_budget_exhausted,
            correlations,
            guard_bindings,
        })
    }

    pub(super) fn discovery_boundary(&self) -> Option<UnknownReason> {
        if self.field_slot_semantic_budget_exhausted || self.refinement_budget_exhausted {
            Some(UnknownReason::SemanticBudget)
        } else if self.provider_failure_observed {
            Some(UnknownReason::IncompleteRoot)
        } else if self.coverage.values().any(|coverage| coverage.truncated) {
            Some(UnknownReason::Truncated)
        } else {
            None
        }
    }

    pub fn value_flow(&self) -> &ValueFlowPlan {
        &self.value_flow
    }

    pub(crate) fn needs_source_refinement(&self) -> bool {
        !self.correlations.is_empty()
            || self.field_refinements.iter().any(|(_, field)| {
                field
                    .alternatives
                    .iter()
                    .any(|alternative| matches!(alternative.version, FieldVersion::Store { .. }))
            })
    }

    pub(crate) fn mark_refinement_budget_exhausted(&mut self) {
        self.field_slot_semantic_budget_exhausted = true;
        self.refinement_budget_exhausted = true;
    }

    /// These sources and exclusions depend on a preliminary solve of this
    /// request's closure. A reusable body cut cannot reconstruct that evidence.
    pub(super) fn procedure_requires_source_refinement(&self, procedure: &ProcedureHandle) -> bool {
        self.correlations
            .iter()
            .any(|(owner, _)| owner == procedure)
            || self.field_refinements.iter().any(|(owner, field)| {
                owner == procedure
                    && field.alternatives.iter().any(|alternative| {
                        matches!(alternative.version, FieldVersion::Store { .. })
                    })
            })
    }

    pub(crate) fn refinement_budget_exhausted(&self) -> bool {
        self.refinement_budget_exhausted
    }

    /// The points [`refine_sources`](Self::refine_sources) can ask evidence
    /// about: the definition points of every correlated guard exclusion, and
    /// the store point of every field version a load may still observe.
    pub(super) fn source_refinement_points(&self) -> HashSet<ProgramPointHandle> {
        let mut points = HashSet::default();
        for (procedure, analysis) in &self.correlations {
            for candidate in &analysis.guard_edge_exclusions {
                for definition in &candidate.all_reaching_data_defs {
                    points.insert(
                        procedure
                            .point_handle(definition.point)
                            .expect("a definition point is live"),
                    );
                }
            }
        }
        for (procedure, field) in &self.field_refinements {
            for alternative in &field.alternatives {
                if let FieldVersion::Store { point, .. } = alternative.version {
                    points.insert(
                        procedure
                            .point_handle(point)
                            .expect("a field store point is live"),
                    );
                }
            }
        }
        points
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn refine_sources(
        &mut self,
        workspace: &WorkspaceAnalyzer,
        adapter: &dyn TypeFlowAdapter,
        field_slots: &FieldSlotIndex,
        evidence: &DefinitionSources,
        budget: &mut SemanticBudget,
        cancellation: &CancellationToken,
    ) -> Result<bool, TypeFlowPlanError> {
        budget
            .charge(SemanticWork {
                nested_entries: self.value_flow.sources().len(),
                ..SemanticWork::default()
            })
            .map_err(TypeFlowPlanError::RefinementBudget)?;
        let mut correlated_kills = Vec::new();
        for (procedure, analysis) in &self.correlations {
            if cancellation.is_cancelled() {
                return Err(TypeFlowPlanError::Cancelled);
            }
            for candidate in &analysis.guard_edge_exclusions {
                let mut sources = HashMap::<ValueFlowEventKey, bool>::default();
                let mut complete = true;
                for definition in &candidate.all_reaching_data_defs {
                    let point = procedure
                        .point_handle(definition.point)
                        .expect("a definition point is live");
                    let (event, carrier) = if let Some(value) = definition.rhs {
                        (
                            definition.event_index,
                            ValueFlowCarrier::Value(
                                procedure
                                    .value_handle(value)
                                    .expect("a definition source is live"),
                            ),
                        )
                    } else if definition.is_entry() {
                        (0, binding_carrier(procedure, definition.binding))
                    } else {
                        complete = false;
                        break;
                    };
                    let Some(reaching) = evidence.before(
                        &self.value_flow,
                        &point,
                        event,
                        &carrier,
                        budget,
                        cancellation,
                    )?
                    else {
                        complete = false;
                        break;
                    };
                    let incompatible = candidate.incompatible_data_defs.contains(definition);
                    for (source, uncertain) in reaching {
                        if uncertain {
                            complete = false;
                            break;
                        }
                        let key = self
                            .value_flow
                            .source(source)
                            .expect("a reaching source is retained")
                            .key()
                            .clone();
                        let removable =
                            incompatible && matches!(self.atom(source), ClassAtom::Class(_));
                        sources
                            .entry(key)
                            .and_modify(|old| *old &= removable)
                            .or_insert(removable);
                    }
                    if !complete {
                        break;
                    }
                }
                if !complete {
                    continue;
                }
                let sources = sources
                    .into_iter()
                    .filter_map(|(key, remove)| remove.then_some(key))
                    .collect::<Vec<_>>();
                if sources.is_empty() {
                    continue;
                }
                let edge = procedure
                    .semantics()
                    .control_edge(candidate.edge)
                    .expect("a candidate edge is live");
                correlated_kills.push(ValueFlowEdgeKillSpec {
                    point: procedure
                        .point_handle(edge.source_point)
                        .expect("a guard point is live"),
                    target: edge.target_point,
                    kind: edge.kind,
                    carrier: binding_carrier(procedure, candidate.data_binding),
                    sources,
                });
            }
        }
        let mut tables = SeedTables::new();
        for (id, spec) in self.value_flow.sources() {
            let replaced = self.field_refinements.iter().any(|(procedure, field)| {
                spec.point().procedure() == procedure && spec.point().id() == field.point
                    && matches!(spec.carrier(), ValueFlowCarrier::Value(value) if value.id() == field.result)
            });
            if !replaced && spec.activation_triggers().is_none() {
                tables.sources.push((
                    spec.clone(),
                    self.atom(id).clone(),
                    self.source_site(id).clone(),
                ));
            }
        }
        let mut seen_procedures = HashSet::default();
        let procedures = self
            .value_flow
            .summary_procedures()
            .filter(|procedure| seen_procedures.insert(procedure.durable_key()))
            .cloned()
            .collect::<Vec<_>>();
        for procedure in &procedures {
            if cancellation.is_cancelled() {
                return Err(TypeFlowPlanError::Cancelled);
            }
            for (_, spec) in self
                .value_flow
                .sources()
                .filter(|(_, spec)| spec.point().procedure() == procedure)
            {
                tables
                    .ordinals
                    .entry((spec.key().site().clone(), ValueFlowEventKind::Source))
                    .and_modify(|ordinal| *ordinal = (*ordinal).max(spec.key().ordinal() + 1))
                    .or_insert(spec.key().ordinal() + 1);
            }
            for (_, field) in self
                .field_refinements
                .iter()
                .filter(|(owner, _)| owner == procedure)
            {
                let point = procedure
                    .point_handle(field.point)
                    .expect("a refined load is live");
                let span = mapping_span(
                    procedure,
                    procedure
                        .semantics()
                        .point(field.point)
                        .expect("a load point is live")
                        .source,
                );
                let unknown_site =
                    || source_site(workspace, procedure, span, SourceSiteKind::Unknown);
                let mut candidates = Vec::new();
                for alternative in &field.alternatives {
                    if cancellation.is_cancelled() {
                        return Err(TypeFlowPlanError::Cancelled);
                    }
                    let mut values = Vec::new();
                    match alternative.version {
                        FieldVersion::Entry | FieldVersion::Open { .. } => {
                            if let Some(class) = adapter.enclosing_class(workspace, procedure)
                                && let Some(slot) = field_slots.slot(&class, &field.member)
                            {
                                budget
                                    .charge(SemanticWork {
                                        nested_entries: slot.atoms.len(),
                                        ..SemanticWork::default()
                                    })
                                    .map_err(TypeFlowPlanError::RefinementBudget)?;
                                values.extend(slot.atoms.iter().cloned());
                            } else if let Some(site) = unknown_site() {
                                values
                                    .push((ClassAtom::Unknown(UnknownReason::UnmodeledLoad), site));
                            }
                            if matches!(alternative.version, FieldVersion::Open { .. })
                                && let Some(site) = unknown_site()
                            {
                                values.push((
                                    ClassAtom::Unknown(UnknownReason::FieldSlotIncomplete),
                                    site,
                                ));
                            }
                        }
                        FieldVersion::Store {
                            point: store,
                            event,
                            value,
                        } => {
                            let store = procedure
                                .point_handle(store)
                                .expect("a field store point is live");
                            let carrier = ValueFlowCarrier::Value(
                                procedure
                                    .value_handle(value)
                                    .expect("a store value is live"),
                            );
                            if let Some(sources) = evidence.before(
                                &self.value_flow,
                                &store,
                                event,
                                &carrier,
                                budget,
                                cancellation,
                            )? {
                                for (source, uncertain) in sources {
                                    values.push((
                                        self.atom(source).clone(),
                                        self.source_site(source).clone(),
                                    ));
                                    if uncertain && let Some(site) = unknown_site() {
                                        values.push((
                                            ClassAtom::Unknown(UnknownReason::UncertainFlow),
                                            site,
                                        ));
                                    }
                                }
                            } else if let Some(site) = unknown_site() {
                                values
                                    .push((ClassAtom::Unknown(UnknownReason::UncertainFlow), site));
                            }
                        }
                    }
                    let restriction = FieldLoadRefinement {
                        point: field.point,
                        result: field.result,
                        member: field.member.clone(),
                        alternatives: vec![alternative.clone()],
                    };
                    for (atom, site) in values {
                        if field_atom_survives(
                            workspace,
                            adapter,
                            field_slots,
                            procedure,
                            &restriction,
                            &atom,
                        ) && !candidates.contains(&(atom.clone(), site.clone()))
                        {
                            candidates.push((atom, site));
                        }
                    }
                }
                for (atom, site) in candidates {
                    tables.push_source(
                        &point,
                        ValueFlowObservationPhase::AfterEffects,
                        ValueFlowCarrier::Value(
                            procedure
                                .value_handle(field.result)
                                .expect("a load result is live"),
                        ),
                        atom,
                        site,
                    );
                }
            }
        }
        // Field refinement replaces source keys. Rebuild conditional guard
        // sources from the new candidates instead of retaining stale triggers.
        let mut kills = guard_transfers(
            workspace,
            adapter,
            field_slots,
            &procedures,
            &mut tables,
            &self.guard_bindings,
            cancellation,
        )?;
        let mut atoms_by_key = HashMap::default();
        let mut sources = Vec::new();
        budget
            .charge(SemanticWork {
                nested_entries: tables.sources.len(),
                ..SemanticWork::default()
            })
            .map_err(TypeFlowPlanError::RefinementBudget)?;
        // Compare semantic source observations, excluding their temporary
        // ordinal identities. Dependent field stores may need another solve
        // after an upstream load's candidate set changes.
        let previous = self
            .value_flow
            .sources()
            .map(|(id, spec)| {
                (
                    spec.point(),
                    spec.phase(),
                    spec.carrier(),
                    self.atom(id),
                    self.source_site(id),
                )
            })
            .collect::<HashSet<_>>();
        let replacement = tables
            .sources
            .iter()
            .map(|(spec, atom, site)| (spec.point(), spec.phase(), spec.carrier(), atom, site))
            .collect::<HashSet<_>>();
        let sources_changed = previous != replacement;
        for (spec, atom, site) in tables.sources {
            atoms_by_key.insert(spec.key().clone(), (atom, site));
            sources.push(spec);
        }
        for mut kill in correlated_kills {
            kill.sources.retain(|key| atoms_by_key.contains_key(key));
            if !kill.sources.is_empty() {
                kills.push(kill);
            }
        }
        let value_flow = self
            .value_flow
            .with_replaced_sources_and_edge_kills(sources, kills)?;
        let mut atoms = Vec::new();
        let mut sites = Vec::new();
        for (_, spec) in value_flow.sources() {
            let (atom, site) = atoms_by_key
                .remove(spec.key())
                .expect("a rebuilt source retains its atom");
            atoms.push(atom);
            sites.push(site);
        }
        self.value_flow = value_flow;
        self.atoms = atoms;
        self.source_sites = sites;
        Ok(sources_changed)
    }

    /// Unknown member-surface annotations on a base do not describe its
    /// runtime class. A load-result unknown remains a class source.
    pub(super) fn is_member_surface_source(&self, source: ValueFlowSourceId) -> bool {
        self.member_surface_sources.contains(
            self.value_flow
                .source(source)
                .expect("a retained source belongs to the plan")
                .key(),
        )
    }

    pub fn atom(&self, source: ValueFlowSourceId) -> &ClassAtom {
        &self.atoms[source.index()]
    }

    pub fn source_site(&self, source: ValueFlowSourceId) -> &SourceSite {
        &self.source_sites[source.index()]
    }

    pub fn sink(&self, sink: ValueFlowSinkId) -> &MemberAccessSite {
        &self.sinks[sink.index()]
    }

    /// The canonical dispatch-read contract for one procedure in this plan's
    /// discovered closure. A procedure outside the closure has no contract.
    pub fn dispatch_read_contract(
        &self,
        procedure: &DurableProcedureKey,
    ) -> Option<&ProcedureDispatchReadContract> {
        self.dispatch_reads.get(procedure)
    }

    pub(crate) fn local_structure_digest(
        &self,
        procedure: &ProcedureHandle,
    ) -> Option<StableDigest> {
        self.local_structure_digests
            .get(&procedure.durable_key())
            .copied()
    }

    /// Every structurally entered callee certified for summary dependency
    /// construction. This includes persisted surface edges whose executable
    /// `CallBindings` are intentionally absent from a cut plan.
    pub(crate) fn summary_callees_of<'a>(
        &'a self,
        procedure: &'a ProcedureHandle,
    ) -> impl Iterator<Item = &'a ProcedureHandle> + 'a {
        let caller = procedure.durable_key();
        self.coverage
            .iter()
            .filter(move |((candidate, _), _)| candidate == &caller)
            .flat_map(|(_, coverage)| coverage.entered.iter())
    }

    /// The call site in `procedure` whose result is `value`, when one exists.
    /// This is how `interpret` finds the call that produced a sink's
    /// receiver.
    pub(crate) fn call_producing(
        procedure: &ProcedureHandle,
        value: crate::analyzer::semantic::ValueId,
    ) -> Option<CallSiteId> {
        procedure
            .semantics()
            .call_sites()
            .iter()
            .find(|call| call.result == Some(value))
            .map(|call| call.id)
    }

    /// The closure's coverage of one of `procedure`'s call sites. A call in a
    /// procedure whose relations were unavailable is absent; every call site
    /// the closure actually visited has a row, including provider failures.
    pub(crate) fn coverage_of(
        &self,
        procedure: &ProcedureHandle,
        call: CallSiteId,
    ) -> Option<&CallSiteCoverage> {
        self.coverage.get(&(procedure.durable_key(), call))
    }

    pub(crate) fn is_summary_cut(&self, procedure: &ProcedureHandle) -> bool {
        self.summary_cuts.contains(&procedure.durable_key())
    }

    pub(crate) fn has_summary_cuts(&self) -> bool {
        !self.summary_cuts.is_empty()
    }

    pub(crate) const fn field_slot_semantic_budget_exhausted(&self) -> bool {
        self.field_slot_semantic_budget_exhausted
    }

    pub(crate) const fn provider_failure_observed(&self) -> bool {
        self.provider_failure_observed
    }
}

/// Why a call's result carries no classified value: the closure could not
/// cover every arm of the call. `Truncated` when the walk was stopped (a
/// truncated dispatch enumeration, or an entered candidate the procedure cap
/// left unprocessed), `SemanticBudget` when dispatch or binding discovery hit
/// a semantic-work ceiling, and `UnresolvedCall` when an arm is an unentered
/// boundary, the call entered nothing, or no coverage row exists. `None` when
/// the closure covers the call. The seeds and `interpret` share this
/// derivation so an uncovered call is named identically at seed time and at a
/// sink.
pub(crate) fn uncovered_reason(coverage: Option<&CallSiteCoverage>) -> Option<UnknownReason> {
    match coverage {
        Some(coverage) => {
            if coverage.truncated {
                Some(UnknownReason::Truncated)
            } else if dispatch_status(&coverage.dispatch)
                .budget_exceeded()
                .is_some()
                || coverage.bindings.iter().any(|binding| {
                    matches!(
                        binding,
                        BindingCoverage::Answered { status }
                            if status.budget_exceeded().is_some()
                    )
                })
            {
                Some(UnknownReason::SemanticBudget)
            } else if coverage.has_uncovered_boundary
                || (coverage.entered.is_empty()
                    && !matches!(
                        coverage.dispatch,
                        DispatchStatus::Resolved {
                            coverage: crate::analyzer::semantic::CandidateCoverage::Exhaustive,
                            ..
                        }
                    ))
            {
                Some(UnknownReason::UnresolvedCall)
            } else {
                None
            }
        }
        None => Some(UnknownReason::UnresolvedCall),
    }
}

fn dispatch_status(dispatch: &DispatchStatus) -> SemanticInputStatus {
    match dispatch {
        DispatchStatus::Resolved { status, .. } | DispatchStatus::Unavailable { status } => *status,
        DispatchStatus::ProviderError { .. } => SemanticInputStatus::Unknown,
    }
}

#[allow(clippy::too_many_arguments)]
fn seed_procedure(
    workspace: &WorkspaceAnalyzer,
    adapter: &dyn TypeFlowAdapter,
    field_slots: &FieldSlotIndex,
    closure: &DiscoveredClosure,
    root_key: DurableProcedureKey,
    procedure: &ProcedureHandle,
    tables: &mut SeedTables,
    field_refinements: &[FieldLoadRefinement],
) {
    let semantics = procedure.semantics();
    let is_root = procedure.durable_key() == root_key;
    let receiver_values = receiver_values(procedure);
    let enclosing_class = adapter.enclosing_class(workspace, procedure);
    let entry = procedure
        .point_handle(semantics.entry_point())
        .expect("a procedure's entry point is live");
    let callee_values = semantics
        .call_sites()
        .iter()
        .map(|call| call.callee)
        .collect::<HashSet<_>>();

    for call in semantics.call_sites() {
        seed_call(workspace, adapter, closure, procedure, call, tables);
    }
    for value in semantics.values() {
        match &value.kind {
            SemanticValueKind::Constant | SemanticValueKind::Boolean(_) => {
                let span = mapping_span(procedure, value.source);
                for atom in adapter
                    .constant_class(workspace, procedure, value)
                    .into_atoms()
                {
                    let kind = source_kind_for_atom(&atom, SourceSiteKind::Literal);
                    let Some(site) = source_site(workspace, procedure, span, kind) else {
                        continue;
                    };
                    let carrier = ValueFlowCarrier::Value(
                        procedure
                            .value_handle(value.id)
                            .expect("a retained value is live"),
                    );
                    tables.push_source(
                        &entry,
                        ValueFlowObservationPhase::AfterEffects,
                        carrier,
                        atom,
                        site,
                    );
                }
            }
            SemanticValueKind::Parameter {
                ordinal,
                multiplicity,
                ..
            } => {
                let span = mapping_span(procedure, value.source);
                if multiplicity.is_rest() {
                    // A rest parameter collects caller values into a container
                    // this engine does not model element-wise, under every
                    // caller and with no caller.
                    seed_port(
                        workspace,
                        procedure,
                        *ordinal,
                        &entry,
                        ClassAtom::Unknown(UnknownReason::VariadicParameter),
                        span,
                        SourceSiteKind::Unknown,
                        tables,
                    );
                    continue;
                }
                let seed = adapter.declared_parameter_class(workspace, procedure, *ordinal);
                if matches!(seed, ClassSeed::NotApplicable) {
                    if is_root {
                        seed_port(
                            workspace,
                            procedure,
                            *ordinal,
                            &entry,
                            ClassAtom::Unknown(UnknownReason::RootParameter),
                            span,
                            SourceSiteKind::Unknown,
                            tables,
                        );
                    }
                } else {
                    for atom in seed.into_atoms() {
                        let kind = source_kind_for_atom(&atom, SourceSiteKind::DeclaredParameter);
                        seed_port(
                            workspace, procedure, *ordinal, &entry, atom, span, kind, tables,
                        );
                    }
                }
            }
            SemanticValueKind::Receiver { .. } => {
                if is_root {
                    let span = mapping_span(procedure, value.source);
                    let port = ProcedurePortHandle::receiver(procedure.clone())
                        .expect("a Receiver value exists, so the receiver port is valid");
                    let safe_class = enclosing_class.clone().and_then(|class| {
                        let hierarchy = adapter.class_hierarchy(workspace, &class);
                        (matches!(
                            class,
                            crate::analyzer::semantic::ClassIdentity::Workspace(_)
                        ) && hierarchy.descendants.as_deref() == Some(&[])
                            && !hierarchy.unresolved_base
                            && !hierarchy.dynamic_attributes)
                            .then_some(class)
                    });
                    let (atom, kind) = safe_class.map_or(
                        (
                            ClassAtom::Unknown(UnknownReason::SelfReceiver),
                            SourceSiteKind::Unknown,
                        ),
                        |class| (ClassAtom::Class(class), SourceSiteKind::RootReceiver),
                    );
                    let Some(site) = source_site(workspace, procedure, span, kind) else {
                        continue;
                    };
                    tables.push_source(
                        &entry,
                        ValueFlowObservationPhase::AfterEffects,
                        ValueFlowCarrier::Port(port),
                        atom,
                        site,
                    );
                }
            }
            SemanticValueKind::AwaitResult => {
                let span = mapping_span(procedure, value.source);
                let Some(site) = source_site(workspace, procedure, span, SourceSiteKind::Unknown)
                else {
                    continue;
                };
                let carrier = ValueFlowCarrier::Value(
                    procedure
                        .value_handle(value.id)
                        .expect("a retained value is live"),
                );
                tables.push_source(
                    &entry,
                    ValueFlowObservationPhase::AfterEffects,
                    carrier,
                    ClassAtom::Unknown(UnknownReason::Await),
                    site,
                );
            }
            SemanticValueKind::DefaultArgument { .. } => {
                let span = mapping_span(procedure, value.source);
                let seed = adapter.retained_value_class(workspace, procedure, value);
                let seed = if matches!(seed, ClassSeed::NotApplicable) {
                    ClassSeed::Unknown(UnknownReason::UncertainFlow)
                } else {
                    seed
                };
                for atom in seed.into_atoms() {
                    let kind = source_kind_for_atom(&atom, SourceSiteKind::Unknown);
                    let Some(site) = source_site(workspace, procedure, span, kind) else {
                        continue;
                    };
                    tables.push_source(
                        &entry,
                        ValueFlowObservationPhase::AfterEffects,
                        ValueFlowCarrier::Value(
                            procedure
                                .value_handle(value.id)
                                .expect("a saved default is live"),
                        ),
                        atom,
                        site,
                    );
                }
            }
            SemanticValueKind::LanguageDefined(_) => {
                let span = mapping_span(procedure, value.source);
                let Some(site) = source_site(workspace, procedure, span, SourceSiteKind::Unknown)
                else {
                    continue;
                };
                let carrier = ValueFlowCarrier::Value(
                    procedure
                        .value_handle(value.id)
                        .expect("a retained value is live"),
                );
                tables.push_source(
                    &entry,
                    ValueFlowObservationPhase::AfterEffects,
                    carrier,
                    ClassAtom::Unknown(UnknownReason::UnmodeledLoad),
                    site,
                );
            }
            SemanticValueKind::Local
            | SemanticValueKind::Return
            | SemanticValueKind::Temporary
            | SemanticValueKind::Address
            | SemanticValueKind::Null
            | SemanticValueKind::UnsignedInteger(_)
            | SemanticValueKind::Exception
            | SemanticValueKind::Callable => {
                if callee_values.contains(&value.id) {
                    continue;
                }
                let span = mapping_span(procedure, value.source);
                for atom in adapter
                    .retained_value_class(workspace, procedure, value)
                    .into_atoms()
                {
                    let kind = source_kind_for_atom(&atom, SourceSiteKind::Unknown);
                    let Some(site) = source_site(workspace, procedure, span, kind) else {
                        continue;
                    };
                    let carrier = ValueFlowCarrier::Value(
                        procedure
                            .value_handle(value.id)
                            .expect("a retained value is live"),
                    );
                    tables.push_source(
                        &entry,
                        ValueFlowObservationPhase::AfterEffects,
                        carrier,
                        atom,
                        site,
                    );
                }
            }
        }
    }
    for allocation in semantics.allocations() {
        let span = mapping_span(procedure, allocation.source);
        let point = procedure
            .point_handle(allocation.point)
            .expect("an allocation's point is live");
        for atom in adapter
            .allocation_class(workspace, procedure, allocation)
            .into_atoms()
        {
            let kind = source_kind_for_atom(&atom, SourceSiteKind::ContainerLiteral);
            let Some(site) = source_site(workspace, procedure, span, kind) else {
                continue;
            };
            let carrier = ValueFlowCarrier::Value(
                procedure
                    .value_handle(allocation.result)
                    .expect("an allocation's result value is live"),
            );
            tables.push_source(
                &point,
                ValueFlowObservationPhase::AfterEffects,
                carrier,
                atom,
                site,
            );
        }
    }
    for point in semantics.points() {
        let mut computed_results = HashSet::default();
        for event in &point.events {
            match &event.effect {
                SemanticEffect::ValueFlow { kind, target, .. }
                    if !kind.preserves_runtime_class() && computed_results.insert(*target) =>
                {
                    let result = semantics
                        .value(*target)
                        .expect("a computed value is retained");
                    let span = mapping_span(procedure, result.source);
                    let point_handle = procedure
                        .point_handle(point.id)
                        .expect("a retained computation point is live");
                    let seed = adapter.computed_class(workspace, procedure, result);
                    let seed = if matches!(seed, ClassSeed::NotApplicable) {
                        ClassSeed::Unknown(UnknownReason::UncertainFlow)
                    } else {
                        seed
                    };
                    for atom in seed.into_atoms() {
                        let kind = source_kind_for_atom(&atom, SourceSiteKind::Unknown);
                        let Some(site) = source_site(workspace, procedure, span, kind) else {
                            continue;
                        };
                        tables.push_source(
                            &point_handle,
                            ValueFlowObservationPhase::AfterEffects,
                            ValueFlowCarrier::Value(
                                procedure
                                    .value_handle(*target)
                                    .expect("a computed result is live"),
                            ),
                            atom,
                            site,
                        );
                    }
                }
                SemanticEffect::MemoryLoad {
                    location, result, ..
                } => {
                    let span = mapping_span(procedure, event.source);
                    let point_handle = procedure
                        .point_handle(point.id)
                        .expect("a retained point is live");
                    let location_row = semantics
                        .memory_location(*location)
                        .expect("a load effect's location is retained");
                    let member = adapter.accessed_member(
                        workspace,
                        procedure,
                        MemberAccessQuery::Load(location_row),
                    );
                    let refinement = field_refinements
                        .iter()
                        .find(|field| field.point == point.id && field.result == *result);
                    let modeled_slot = if let Some(field) = refinement
                        && let Some(class) = enclosing_class.as_ref()
                    {
                        field_slots.slot(class, &field.member)
                    } else if let MemoryLocationKind::Field { base, .. } = &location_row.kind
                        && receiver_values.contains(base)
                        && let Some(class) = enclosing_class.as_ref()
                        && let Some(member) = member.as_deref()
                    {
                        field_slots.slot(class, member)
                    } else {
                        None
                    };
                    let carrier = ValueFlowCarrier::Value(
                        procedure
                            .value_handle(*result)
                            .expect("a load's result value is live"),
                    );
                    if let Some(slot) = modeled_slot {
                        for (atom, site) in &slot.atoms {
                            if let Some(refinement) = refinement
                                && !field_atom_survives(
                                    workspace,
                                    adapter,
                                    field_slots,
                                    procedure,
                                    refinement,
                                    atom,
                                )
                            {
                                continue;
                            }
                            tables.push_source(
                                &point_handle,
                                ValueFlowObservationPhase::AfterEffects,
                                carrier.clone(),
                                atom.clone(),
                                site.clone(),
                            );
                        }
                        if refinement.is_some_and(|field| {
                            field.alternatives.iter().any(|alternative| {
                                matches!(alternative.version, FieldVersion::Open { .. })
                            })
                        }) && let Some(site) =
                            source_site(workspace, procedure, span, SourceSiteKind::Unknown)
                        {
                            tables.push_source(
                                &point_handle,
                                ValueFlowObservationPhase::AfterEffects,
                                carrier.clone(),
                                ClassAtom::Unknown(UnknownReason::FieldSlotIncomplete),
                                site,
                            );
                        }
                        if let MemoryLocationKind::Field { base, .. } = &location_row.kind {
                            let base_carrier = ValueFlowCarrier::Value(
                                procedure
                                    .value_handle(*base)
                                    .expect("a field base value is live"),
                            );
                            for (atom, site) in &slot.atoms {
                                if matches!(atom, ClassAtom::Unknown(_)) {
                                    tables.push_member_surface_source(
                                        &point_handle,
                                        base_carrier.clone(),
                                        atom.clone(),
                                        site.clone(),
                                    );
                                }
                            }
                        }
                    } else if let Some(site) =
                        source_site(workspace, procedure, span, SourceSiteKind::Unknown)
                    {
                        tables.push_source(
                            &point_handle,
                            ValueFlowObservationPhase::AfterEffects,
                            carrier,
                            ClassAtom::Unknown(UnknownReason::UnmodeledLoad),
                            site,
                        );
                    }
                    if let MemoryLocationKind::Field { base, .. } = &location_row.kind
                        && let Some(member) = member
                    {
                        push_member_sink(
                            workspace,
                            procedure,
                            &point_handle,
                            *base,
                            member,
                            MemberAccessKind::Load,
                            None,
                            tables,
                        );
                    }
                }
                SemanticEffect::AsyncResume {
                    result: Some(value),
                    ..
                } => {
                    let span = mapping_span(procedure, event.source);
                    let point_handle = procedure
                        .point_handle(point.id)
                        .expect("a retained point is live");
                    if let Some(site) =
                        source_site(workspace, procedure, span, SourceSiteKind::Unknown)
                    {
                        let carrier = ValueFlowCarrier::Value(
                            procedure
                                .value_handle(*value)
                                .expect("an async resume result is live"),
                        );
                        tables.push_source(
                            &point_handle,
                            ValueFlowObservationPhase::AfterEffects,
                            carrier,
                            ClassAtom::Unknown(UnknownReason::Await),
                            site,
                        );
                    }
                }
                SemanticEffect::CaptureBind { capture } => {
                    let binding = semantics
                        .capture(*capture)
                        .expect("a capture-bind effect's binding is retained");
                    if let crate::analyzer::semantic::CaptureSource::Value(value) = binding.captured
                    {
                        let span = mapping_span(procedure, event.source);
                        if let Some(site) =
                            source_site(workspace, procedure, span, SourceSiteKind::Unknown)
                        {
                            let carrier = ValueFlowCarrier::Value(
                                procedure
                                    .value_handle(value)
                                    .expect("a captured value is live"),
                            );
                            tables.push_source(
                                &entry,
                                ValueFlowObservationPhase::AfterEffects,
                                carrier,
                                ClassAtom::Unknown(UnknownReason::Capture),
                                site,
                            );
                        }
                    }
                }
                _ => {}
            }
        }
    }
}

fn seed_call_result(
    workspace: &WorkspaceAnalyzer,
    procedure: &ProcedureHandle,
    call: &SemanticCallSite,
    atom: ClassAtom,
    kind: SourceSiteKind,
    tables: &mut SeedTables,
) {
    let Some((point, carrier)) = call_result_anchor(procedure, call) else {
        return;
    };
    let Some(site) = source_site(
        workspace,
        procedure,
        mapping_span(procedure, call.source),
        kind,
    ) else {
        return;
    };
    tables.push_source(
        &point,
        ValueFlowObservationPhase::BeforeEffects,
        carrier,
        atom,
        site,
    );
}

fn source_kind_for_atom(atom: &ClassAtom, class_kind: SourceSiteKind) -> SourceSiteKind {
    match atom {
        ClassAtom::Class(_) => class_kind,
        ClassAtom::Unknown(_) => SourceSiteKind::Unknown,
    }
}

fn seed_call(
    workspace: &WorkspaceAnalyzer,
    adapter: &dyn TypeFlowAdapter,
    closure: &DiscoveredClosure,
    procedure: &ProcedureHandle,
    call: &SemanticCallSite,
    tables: &mut SeedTables,
) {
    let seed = adapter.constructed_class(workspace, procedure, call);
    if matches!(seed, ClassSeed::NotApplicable) {
        let key = (procedure.durable_key(), call.id);
        if let Some(reason) = uncovered_reason(closure.coverage.get(&key)) {
            seed_call_result(
                workspace,
                procedure,
                call,
                ClassAtom::Unknown(reason),
                SourceSiteKind::Unknown,
                tables,
            );
        }
    } else {
        for atom in seed.into_atoms() {
            let kind = source_kind_for_atom(&atom, SourceSiteKind::ConstructorCall);
            seed_call_result(workspace, procedure, call, atom, kind, tables);
        }
    }
    if let Some(receiver) = call.receiver
        && let Some(member) =
            adapter.accessed_member(workspace, procedure, MemberAccessQuery::Call(call))
    {
        let point = procedure
            .point_handle(call.point)
            .expect("a call site's point is live");
        push_member_sink(
            workspace,
            procedure,
            &point,
            receiver,
            member,
            MemberAccessKind::Call,
            Some(call.id),
            tables,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn seed_port(
    workspace: &WorkspaceAnalyzer,
    procedure: &ProcedureHandle,
    ordinal: u32,
    entry: &ProgramPointHandle,
    atom: ClassAtom,
    span: SourceSpan,
    kind: SourceSiteKind,
    tables: &mut SeedTables,
) {
    let Some(site) = source_site(workspace, procedure, span, kind) else {
        return;
    };
    let port = ProcedurePortHandle::parameter(procedure.clone(), ordinal)
        .expect("the ordinal comes from a retained parameter value");
    tables.push_source(
        entry,
        ValueFlowObservationPhase::AfterEffects,
        ValueFlowCarrier::Port(port),
        atom,
        site,
    );
}

#[allow(clippy::too_many_arguments)]
fn push_member_sink(
    workspace: &WorkspaceAnalyzer,
    procedure: &ProcedureHandle,
    point: &ProgramPointHandle,
    base: crate::analyzer::semantic::ValueId,
    member: Box<str>,
    kind: MemberAccessKind,
    call: Option<CallSiteId>,
    tables: &mut SeedTables,
) {
    assert_eq!(
        matches!(kind, MemberAccessKind::Call),
        call.is_some(),
        "only a call-shaped member sink owns a call-site ID"
    );
    let base_value = procedure
        .semantics()
        .value(base)
        .expect("a receiver or field base value is retained");
    let Some(file) = file_for_locator(
        workspace,
        &procedure
            .semantics()
            .source_mapping(base_value.source)
            .expect("a base value retains a source mapping")
            .locator,
    ) else {
        return;
    };
    let span = mapping_span(procedure, base_value.source);
    let carrier =
        ValueFlowCarrier::Value(procedure.value_handle(base).expect("a base value is live"));
    tables.push_sink(
        point,
        carrier,
        MemberAccessSite {
            procedure: procedure.clone(),
            point: point.clone(),
            call,
            file,
            span,
            member,
            kind,
        },
    );
}

fn source_site(
    workspace: &WorkspaceAnalyzer,
    procedure: &ProcedureHandle,
    span: SourceSpan,
    kind: SourceSiteKind,
) -> Option<SourceSite> {
    let file = file_for_locator(workspace, procedure.semantics().locator())?;
    Some(SourceSite { file, span, kind })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::semantic::{SemanticWork, StableDigest};

    fn test_read(label: &[u8]) -> ReadKey {
        ReadKey::Models(StableDigest::sha256(label))
    }

    fn nested(entries: usize) -> SemanticWork {
        SemanticWork {
            nested_entries: entries,
            ..SemanticWork::default()
        }
    }

    /// One root solve builds its plan several times. Every build after the
    /// first must reuse the refinement the first build derived, and must not
    /// charge the ledger for it again (#3163).
    #[test]
    fn repeated_refinement_lookups_charge_one_derivation() {
        let identity = StableDigest::sha256(b"one-refinement");
        let mut cache = HashMap::default();
        let mut budget = SemanticBudget::uniform(1_000).expect("a finite budget");
        let mut derivations = 0_usize;
        for _ in 0..5 {
            let value = reused_or_derived(&mut cache, identity, &mut budget, |budget| {
                derivations += 1;
                budget
                    .charge(nested(400))
                    .map_err(CorrelationError::Budget)?;
                Ok(7_u32)
            })
            .expect("the refinement derives and then reuses");
            assert_eq!(value, 7);
        }
        assert_eq!(derivations, 1, "one ledger derives the refinement once");
        assert_eq!(
            budget.used().nested_entries,
            400,
            "five lookups charge one derivation, not five"
        );
    }

    /// The near miss: this ledger holds one derivation of this size and no
    /// more, so charging the same refinement a second time would exhaust it.
    #[test]
    fn one_ledger_holds_only_one_derivation_of_this_size() {
        let mut budget = SemanticBudget::uniform(1_000).expect("a finite budget");
        for (round, label) in [b"first".as_slice(), b"second".as_slice()]
            .into_iter()
            .enumerate()
        {
            let mut cache = HashMap::default();
            let outcome = reused_or_derived(
                &mut cache,
                StableDigest::sha256(label),
                &mut budget,
                |budget| {
                    budget
                        .charge(nested(600))
                        .map_err(CorrelationError::Budget)?;
                    Ok(7_u32)
                },
            );
            assert_eq!(
                outcome.is_ok(),
                round == 0,
                "a second derivation of this size does not fit"
            );
        }
    }

    /// A ledger that has not paid for a reused refinement is charged the work
    /// the derivation measured, so a rolled-back attempt pays again.
    #[test]
    fn an_unpaid_ledger_is_charged_for_a_reused_refinement() {
        let identity = StableDigest::sha256(b"one-refinement");
        let mut cache = HashMap::default();
        let mut first = SemanticBudget::uniform(1_000).expect("a finite budget");
        reused_or_derived(&mut cache, identity, &mut first, |budget| {
            budget
                .charge(nested(400))
                .map_err(CorrelationError::Budget)?;
            Ok(7_u32)
        })
        .expect("the first ledger derives the refinement");

        let mut fresh = SemanticBudget::uniform(1_000).expect("a finite budget");
        let mut derivations = 0_usize;
        reused_or_derived(&mut cache, identity, &mut fresh, |budget| {
            derivations += 1;
            budget
                .charge(nested(400))
                .map_err(CorrelationError::Budget)?;
            Ok(7_u32)
        })
        .expect("the fresh ledger reuses the refinement");
        assert_eq!(derivations, 0, "the cached value is reused, not rederived");
        assert_eq!(
            fresh.used().nested_entries,
            400,
            "a ledger that never paid is charged the measured work"
        );
    }

    #[test]
    fn dispatch_read_contract_sorts_and_deduplicates_two_calls() {
        let first = test_read(b"first-call");
        let second = test_read(b"second-call");
        let left = canonical_dispatch_read_contract([
            DispatchReadAttribution::Attributed(second.clone()),
            DispatchReadAttribution::Attributed(first.clone()),
            DispatchReadAttribution::Attributed(first.clone()),
        ]);
        let right = canonical_dispatch_read_contract([
            DispatchReadAttribution::Attributed(first.clone()),
            DispatchReadAttribution::Attributed(second.clone()),
        ]);
        let mut expected = vec![first, second];
        expected.sort_unstable();

        assert_eq!(left, right, "discovery order is not contract identity");
        assert_eq!(
            left,
            ProcedureDispatchReadContract::Complete(expected.into_boxed_slice())
        );
        assert_eq!(
            canonical_dispatch_read_contract([]),
            ProcedureDispatchReadContract::Complete(Box::new([])),
            "a discovered procedure with no calls has an explicit empty contract"
        );
    }

    #[test]
    fn unattributed_dispatch_read_fails_closed() {
        let reason = DispatchReadUnattributedReason::SourceRangeUnavailable;
        let contract = canonical_dispatch_read_contract([
            DispatchReadAttribution::Attributed(test_read(b"attributed-call")),
            DispatchReadAttribution::Unattributed(reason),
            DispatchReadAttribution::Unattributed(reason),
        ]);

        assert_eq!(
            contract,
            ProcedureDispatchReadContract::Unattributed(Box::new([reason])),
            "partial exact reads must not masquerade as a complete contract"
        );
    }

    fn budget_status() -> SemanticInputStatus {
        let mut limits = SemanticBudget::default().limits();
        limits.procedures = 1;
        let exceeded = SemanticBudget::new(limits)
            .expect("positive semantic budget")
            .check(SemanticWork {
                procedures: 2,
                ..SemanticWork::default()
            })
            .expect_err("procedure work exceeds the test budget");
        SemanticInputStatus::ExceededBudget { exceeded }
    }

    fn coverage(dispatch: DispatchStatus, bindings: Vec<BindingCoverage>) -> CallSiteCoverage {
        CallSiteCoverage {
            entered: Vec::new(),
            has_uncovered_boundary: false,
            truncated: false,
            complete_receiver_hint_refinable: false,
            dispatch,
            bindings,
        }
    }

    #[test]
    fn discovery_budget_status_has_precedence_over_an_unresolved_call() {
        let dispatch_budget = coverage(
            DispatchStatus::Unavailable {
                status: budget_status(),
            },
            Vec::new(),
        );
        assert_eq!(
            uncovered_reason(Some(&dispatch_budget)),
            Some(UnknownReason::SemanticBudget)
        );

        let binding_budget = coverage(
            DispatchStatus::Resolved {
                status: SemanticInputStatus::Complete,
                coverage: crate::analyzer::semantic::CandidateCoverage::Open,
            },
            vec![BindingCoverage::Answered {
                status: budget_status(),
            }],
        );
        assert_eq!(
            uncovered_reason(Some(&binding_budget)),
            Some(UnknownReason::SemanticBudget)
        );

        let mut truncated_budget = binding_budget;
        truncated_budget.truncated = true;
        assert_eq!(
            uncovered_reason(Some(&truncated_budget)),
            Some(UnknownReason::Truncated)
        );
    }

    #[test]
    fn exhaustive_dispatch_with_no_target_is_covered() {
        let absent_member = coverage(
            DispatchStatus::Resolved {
                status: SemanticInputStatus::Complete,
                coverage: crate::analyzer::semantic::CandidateCoverage::Exhaustive,
            },
            Vec::new(),
        );

        assert_eq!(uncovered_reason(Some(&absent_member)), None);
    }

    #[test]
    fn persistence_observes_every_typed_provider_failure_channel() {
        let stable_open = coverage(
            DispatchStatus::Unavailable {
                status: SemanticInputStatus::Unknown,
            },
            vec![BindingCoverage::Answered {
                status: SemanticInputStatus::Unknown,
            }],
        );
        assert!(
            !provider_failure_observed(std::iter::empty(), [&stable_open]),
            "stable open semantic outcomes are not transient provider failures"
        );

        let skipped = SkipReason::ProviderError {
            detail: "snapshot failed".to_owned(),
        };
        assert!(provider_failure_observed([&skipped], [&stable_open]));

        let dispatch = coverage(
            DispatchStatus::ProviderError {
                detail: "dispatch failed".to_owned(),
            },
            Vec::new(),
        );
        assert!(provider_failure_observed(std::iter::empty(), [&dispatch]));

        let binding = coverage(
            DispatchStatus::Resolved {
                status: SemanticInputStatus::Complete,
                coverage: crate::analyzer::semantic::CandidateCoverage::Exhaustive,
            },
            vec![BindingCoverage::ProviderError {
                detail: "binding failed".to_owned(),
            }],
        );
        assert!(provider_failure_observed(std::iter::empty(), [&binding]));
    }
}
