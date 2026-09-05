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
use crate::analyzer::semantic::{
    CallSiteId, CancellationToken, ClassAtom, ClassIdentity, ClassSeed, DispatchReadAttribution,
    DispatchReadUnattributedReason, EvidenceCompleteness, GuardArmSide, GuardPredicate,
    MemberAccessKind, MemberAccessQuery, MemoryLocationKind, NarrowingVerdict, ProcedureHandle,
    ProcedurePortHandle, ProgramPointHandle, ProgramPointId, ProofStatus, SemanticBudget,
    SemanticCallSite, SemanticEffect, SemanticLocator, SemanticProviderError, SemanticValueKind,
    SourceSite, SourceSiteKind, SourceSpan, TypeFlowAdapter, UnknownReason,
};
use crate::analyzer::{ProjectFile, WorkspaceAnalyzer};
use crate::dataflow::SemanticInputStatus;
use crate::dataflow::{
    ExternalSummaryCompatibilityKey, SummaryBehaviorKey, SummaryContextKey, SummarySchemaVersion,
    SummarySemanticsVersion, UnmodeledCallBehavior,
};
use crate::hash::HashMap;
use crate::value_flow::{
    BindingCoverage, CallSiteCoverage, ClosureLimits, DiscoveredClosure, DispatchReadCollector,
    DispatchStatus, DurableProcedureKey, ProcedureDispatchRead, ValueFlowCarrier,
    ValueFlowEdgeKillSpec, ValueFlowEventKey, ValueFlowEventKind, ValueFlowObservationPhase,
    ValueFlowPlan, ValueFlowPlanError, ValueFlowSinkId, ValueFlowSinkSpec, ValueFlowSourceId,
    ValueFlowSourceSpec, WorkspaceValueFlowProvider, discover_closure_with,
};
use crate::{ProcedureSummaryBindingError, bind_active_unmaterialized_procedure_summaries};

use super::field_slots::{FieldSlotIndex, receiver_values};
use crate::scalar_state::BindingOriginIndex;

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
    sinks: Vec<MemberAccessSite>,
    coverage: HashMap<(DurableProcedureKey, CallSiteId), CallSiteCoverage>,
    dispatch_reads: HashMap<DurableProcedureKey, ProcedureDispatchReadContract>,
    field_slot_semantic_budget_exhausted: bool,
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
    pending
        .into_iter()
        .map(|(procedure, attributions)| {
            (procedure, canonical_dispatch_read_contract(attributions))
        })
        .collect()
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
    Flow(ValueFlowPlanError),
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
            Self::Cancelled => formatter.write_str("type-flow field-slot scan was cancelled"),
            Self::Flow(error) => write!(formatter, "type-flow value-flow plan failed: {error}"),
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

impl From<ValueFlowPlanError> for TypeFlowPlanError {
    fn from(error: ValueFlowPlanError) -> Self {
        Self::Flow(error)
    }
}

/// One spec under construction plus the reporting record parallel to it.
struct SeedTables {
    sources: Vec<(ValueFlowSourceSpec, ClassAtom, SourceSite)>,
    sinks: Vec<(ValueFlowSinkSpec, MemberAccessSite)>,
    /// Distinct ordinals for several specs at one program point, reset per
    /// procedure because `ProgramPointId` is procedure-local.
    ordinals: HashMap<(ProgramPointId, ValueFlowEventKind), u32>,
}

impl SeedTables {
    fn new() -> Self {
        Self {
            sources: Vec::new(),
            sinks: Vec::new(),
            ordinals: HashMap::default(),
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
        let ordinal = self.ordinals.entry((point.id(), kind)).or_insert(0);
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

fn guard_edge_kills(
    workspace: &WorkspaceAnalyzer,
    adapter: &dyn TypeFlowAdapter,
    procedures: &[ProcedureHandle],
    sources: &[ValueFlowSourceSpec],
    atoms_by_key: &HashMap<ValueFlowEventKey, (ClassAtom, SourceSite)>,
) -> Vec<ValueFlowEdgeKillSpec> {
    let mut sources_by_class = HashMap::<ClassIdentity, Vec<ValueFlowEventKey>>::default();
    for source in sources {
        let (ClassAtom::Class(atom), _) = atoms_by_key
            .get(source.key())
            .expect("every source spec retains its class atom")
        else {
            continue;
        };
        sources_by_class
            .entry(atom.clone())
            .or_default()
            .push(source.key().clone());
    }
    let mut kills = Vec::new();
    for procedure in procedures {
        let origins = BindingOriginIndex::new(procedure);
        for guard in procedure.semantics().guard_facts() {
            let constrained = match guard.predicate {
                GuardPredicate::InstanceOf { value, .. }
                | GuardPredicate::HasMember { value, .. } => Some(value),
                GuardPredicate::NullComparison { .. } => guard.subject,
                GuardPredicate::ConstantBoolean { .. }
                | GuardPredicate::ConstantEquality { .. }
                | GuardPredicate::Opaque { .. } => None,
            };
            let Some(binding) = constrained.and_then(|value| origins.unique_binding_origin(value))
            else {
                continue;
            };
            let carrier = match &procedure
                .semantics()
                .value(binding)
                .expect("a binding origin is live in its procedure")
                .kind
            {
                SemanticValueKind::Parameter { ordinal, .. } => ValueFlowCarrier::Port(
                    ProcedurePortHandle::parameter(procedure.clone(), *ordinal)
                        .expect("the ordinal comes from a retained parameter value"),
                ),
                SemanticValueKind::Receiver { .. } => ValueFlowCarrier::Port(
                    ProcedurePortHandle::receiver(procedure.clone())
                        .expect("the procedure retains its receiver value"),
                ),
                SemanticValueKind::Local => ValueFlowCarrier::Value(
                    procedure
                        .value_handle(binding)
                        .expect("a local binding origin is live in its procedure"),
                ),
                kind => unreachable!("binding origin has unsupported kind: {kind:?}"),
            };
            for (side, edge_id) in [
                (GuardArmSide::True, guard.true_edge),
                (GuardArmSide::False, guard.false_edge),
            ] {
                let Some(edge) = edge_id.and_then(|id| procedure.semantics().control_edge(id))
                else {
                    continue;
                };
                let mut dropped = Vec::new();
                for (atom, atom_sources) in &sources_by_class {
                    if adapter.narrowing_verdict(workspace, procedure, guard, atom, side)
                        == NarrowingVerdict::Drop
                    {
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
    }
    kills
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
    ) -> Result<Self, TypeFlowPlanError> {
        let dispatch_reads = DispatchReadCollector::default();
        let closure = {
            let _scope = profiling::scope("type_flow.discovery");
            let observed_provider = provider.observing_dispatch_reads(dispatch_reads.clone());
            discover_closure_with(
                &observed_provider,
                root,
                limits,
                semantic_budget,
                cancellation,
            )
            .map_err(TypeFlowPlanError::Discovery)?
        };
        let _scope = profiling::scope("type_flow.plan_build");
        if closure.root_snapshot.is_none() {
            return Err(TypeFlowPlanError::RootRelationsUnavailable);
        }
        let dispatch_reads =
            canonical_dispatch_read_contracts(&closure.procedures, dispatch_reads.observations());
        let root_key = root.durable_key();
        let mut unmaterialized_external_targets = closure
            .boundaries
            .iter()
            .filter_map(|boundary| boundary.unmaterialized_external_target().cloned())
            .collect::<Vec<_>>();
        unmaterialized_external_targets.sort_unstable();
        unmaterialized_external_targets.dedup();
        let mut tables = SeedTables::new();
        for procedure in &closure.procedures {
            tables.ordinals.clear();
            seed_procedure(
                workspace,
                adapter,
                field_slots,
                &closure,
                root_key.clone(),
                procedure,
                &mut tables,
            );
        }
        let SeedTables { sources, sinks, .. } = tables;
        // The ValueFlowPlan sorts specs by event key and rejects duplicates,
        // so the atom and site of every spec stay recoverable by key.
        let mut source_specs = Vec::with_capacity(sources.len());
        let mut atoms_by_key = HashMap::default();
        for (spec, atom, site) in sources {
            atoms_by_key.insert(spec.key().clone(), (atom, site));
            source_specs.push(spec);
        }
        let edge_kills = guard_edge_kills(
            workspace,
            adapter,
            &closure.procedures,
            &source_specs,
            &atoms_by_key,
        );
        let mut sink_specs = Vec::with_capacity(sinks.len());
        let mut sites_by_key = HashMap::default();
        for (spec, site) in sinks {
            sites_by_key.insert(spec.key().clone(), site);
            sink_specs.push(spec);
        }
        let call_behavior = UnmodeledCallBehavior::Optimistic;
        let mut value_flow = ValueFlowPlan::with_call_behavior_and_edge_kills(
            root.clone(),
            closure.snapshots,
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
            sinks: member_sites,
            coverage: closure.coverage,
            dispatch_reads,
            field_slot_semantic_budget_exhausted: field_slots.semantic_budget_exhausted(),
        })
    }

    pub fn value_flow(&self) -> &ValueFlowPlan {
        &self.value_flow
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

    pub(crate) const fn field_slot_semantic_budget_exhausted(&self) -> bool {
        self.field_slot_semantic_budget_exhausted
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

fn seed_procedure(
    workspace: &WorkspaceAnalyzer,
    adapter: &dyn TypeFlowAdapter,
    field_slots: &FieldSlotIndex,
    closure: &DiscoveredClosure,
    root_key: DurableProcedureKey,
    procedure: &ProcedureHandle,
    tables: &mut SeedTables,
) {
    let semantics = procedure.semantics();
    let is_root = procedure.durable_key() == root_key;
    let receiver_values = receiver_values(procedure);
    let enclosing_class = adapter.enclosing_class(workspace, procedure);
    let entry = procedure
        .point_handle(semantics.entry_point())
        .expect("a procedure's entry point is live");

    for call in semantics.call_sites() {
        seed_call(workspace, adapter, closure, procedure, call, tables);
    }
    for value in semantics.values() {
        match &value.kind {
            SemanticValueKind::Constant => {
                let span = mapping_span(procedure, value.source);
                match adapter.constant_class(workspace, procedure, value) {
                    ClassSeed::Class(identity) => {
                        let Some(site) =
                            source_site(workspace, procedure, span, SourceSiteKind::Literal)
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
                            ClassAtom::Class(identity),
                            site,
                        );
                    }
                    ClassSeed::Unknown(reason) => {
                        let Some(site) =
                            source_site(workspace, procedure, span, SourceSiteKind::Unknown)
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
                            ClassAtom::Unknown(reason),
                            site,
                        );
                    }
                    ClassSeed::NotApplicable => {}
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
                match adapter.declared_parameter_class(workspace, procedure, *ordinal) {
                    ClassSeed::Class(identity) => {
                        seed_port(
                            workspace,
                            procedure,
                            *ordinal,
                            &entry,
                            ClassAtom::Class(identity),
                            span,
                            SourceSiteKind::DeclaredParameter,
                            tables,
                        );
                    }
                    ClassSeed::Unknown(reason) => {
                        seed_port(
                            workspace,
                            procedure,
                            *ordinal,
                            &entry,
                            ClassAtom::Unknown(reason),
                            span,
                            SourceSiteKind::Unknown,
                            tables,
                        );
                    }
                    ClassSeed::NotApplicable => {
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
            _ => {}
        }
    }
    for allocation in semantics.allocations() {
        let span = mapping_span(procedure, allocation.source);
        let atom = match adapter.allocation_class(workspace, procedure, allocation) {
            ClassSeed::Class(identity) => ClassAtom::Class(identity),
            ClassSeed::Unknown(reason) => ClassAtom::Unknown(reason),
            ClassSeed::NotApplicable => continue,
        };
        let kind = if matches!(atom, ClassAtom::Class(_)) {
            SourceSiteKind::ContainerLiteral
        } else {
            SourceSiteKind::Unknown
        };
        let Some(site) = source_site(workspace, procedure, span, kind) else {
            continue;
        };
        let point = procedure
            .point_handle(allocation.point)
            .expect("an allocation's point is live");
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
    for point in semantics.points() {
        for event in &point.events {
            match &event.effect {
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
                    let modeled_slot = if let MemoryLocationKind::Field { base, .. } =
                        &location_row.kind
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
                            tables.push_source(
                                &point_handle,
                                ValueFlowObservationPhase::AfterEffects,
                                carrier.clone(),
                                atom.clone(),
                                site.clone(),
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
                                    tables.push_source(
                                        &point_handle,
                                        ValueFlowObservationPhase::BeforeEffects,
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

fn seed_call(
    workspace: &WorkspaceAnalyzer,
    adapter: &dyn TypeFlowAdapter,
    closure: &DiscoveredClosure,
    procedure: &ProcedureHandle,
    call: &SemanticCallSite,
    tables: &mut SeedTables,
) {
    match adapter.constructed_class(workspace, procedure, call) {
        ClassSeed::Class(identity) => seed_call_result(
            workspace,
            procedure,
            call,
            ClassAtom::Class(identity),
            SourceSiteKind::ConstructorCall,
            tables,
        ),
        ClassSeed::Unknown(reason) => seed_call_result(
            workspace,
            procedure,
            call,
            ClassAtom::Unknown(reason),
            SourceSiteKind::Unknown,
            tables,
        ),
        ClassSeed::NotApplicable => {
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
}
