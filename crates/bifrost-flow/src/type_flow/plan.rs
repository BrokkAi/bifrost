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

use crate::analyzer::semantic::{
    CallSiteId, CancellationToken, ClassAtom, ClassSeed, EvidenceCompleteness, GuardArmSide,
    GuardPredicate, MemberAccessKind, MemberAccessQuery, MemoryLocationKind, NarrowingVerdict,
    ProcedureHandle, ProcedurePortHandle, ProgramPointHandle, ProgramPointId, ProofStatus,
    SemanticBudget, SemanticCallSite, SemanticEffect, SemanticLocator, SemanticProviderError,
    SemanticValueKind, SourceSpan, TypeFlowAdapter, UnknownReason,
};
use crate::analyzer::{ProjectFile, WorkspaceAnalyzer};
use crate::dataflow::SemanticInputStatus;
use crate::hash::HashMap;
use crate::value_flow::{
    BindingCoverage, CallSiteCoverage, ClosureLimits, DiscoveredClosure, DispatchStatus,
    DurableProcedureKey, ValueFlowCarrier, ValueFlowEdgeKillSpec, ValueFlowEventKey,
    ValueFlowEventKind, ValueFlowObservationPhase, ValueFlowPlan, ValueFlowPlanError,
    ValueFlowSinkId, ValueFlowSinkSpec, ValueFlowSourceId, ValueFlowSourceSpec, discover_closure,
};

use super::field_slots::{FieldSlotIndex, receiver_values};
use crate::scalar_state::BindingOriginIndex;

/// Where one class-carrying source was seeded, for reporting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceSite {
    pub file: ProjectFile,
    pub span: SourceSpan,
    pub kind: SourceSiteKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceSiteKind {
    ConstructorCall,
    Literal,
    ContainerLiteral,
    DeclaredParameter,
    RootReceiver,
    Unknown,
}

/// One member access whose receiver's class set the solve computes.
#[derive(Debug, Clone)]
pub struct MemberAccessSite {
    pub procedure: ProcedureHandle,
    pub point: ProgramPointHandle,
    pub file: ProjectFile,
    pub span: SourceSpan,
    pub member: Box<str>,
    pub kind: MemberAccessKind,
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
    field_slot_semantic_budget_exhausted: bool,
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
                let dropped = sources
                    .iter()
                    .filter_map(|source| {
                        let (ClassAtom::Class(atom), _) = atoms_by_key
                            .get(source.key())
                            .expect("every source spec retains its class atom")
                        else {
                            return None;
                        };
                        (adapter.narrowing_verdict(workspace, procedure, guard, atom, side)
                            == NarrowingVerdict::Drop)
                            .then(|| source.key().clone())
                    })
                    .collect::<Vec<_>>();
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
    pub fn build(
        workspace: &WorkspaceAnalyzer,
        adapter: &dyn TypeFlowAdapter,
        field_slots: &FieldSlotIndex,
        root: &ProcedureHandle,
        limits: ClosureLimits,
        semantic_budget: &mut SemanticBudget,
        cancellation: &CancellationToken,
    ) -> Result<Self, TypeFlowPlanError> {
        let closure = {
            let _scope = profiling::scope("type_flow.discovery");
            discover_closure(workspace, root, limits, semantic_budget, cancellation)
                .map_err(TypeFlowPlanError::Discovery)?
        };
        let _scope = profiling::scope("type_flow.plan_build");
        if closure.root_snapshot.is_none() {
            return Err(TypeFlowPlanError::RootRelationsUnavailable);
        }
        let root_key = root.durable_key();
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
        let value_flow = ValueFlowPlan::with_call_behavior_and_edge_kills(
            root.clone(),
            closure.snapshots,
            closure.bindings,
            source_specs,
            sink_specs,
            edge_kills,
            crate::dataflow::UnmodeledCallBehavior::Optimistic,
        )?;
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
            } else if coverage.has_boundary || coverage.entered.is_empty() {
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
        DispatchStatus::Resolved { status } | DispatchStatus::Unavailable { status } => *status,
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

fn push_member_sink(
    workspace: &WorkspaceAnalyzer,
    procedure: &ProcedureHandle,
    point: &ProgramPointHandle,
    base: crate::analyzer::semantic::ValueId,
    member: Box<str>,
    kind: MemberAccessKind,
    tables: &mut SeedTables,
) {
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
    use crate::analyzer::semantic::SemanticWork;

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
            has_boundary: false,
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
}
