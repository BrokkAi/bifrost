//! One root's class-set plan.
//!
//! A [`TypeFlowPlan`] is a [`ValueFlowPlan`] whose sources are the
//! class-producing sites of every procedure in the root's discovered closure
//! (constructor calls, literals, container literals, declared parameters, and
//! one explicit Unknown source wherever the engine cannot classify a value)
//! and whose sinks are member accesses plus the root Python `__iter__`
//! return values selected by the iterator-protocol query. A side table maps
//! each source id to its class atom and each sink id to its typed site, so the
//! solver's meetings answer which classes reach that value.

use crate::analyzer::store::cache_budget::{RetainedHeap, retained_read_key};
use std::error::Error;
use std::fmt;
use std::sync::Arc;

use super::mapping_span;
use brokk_bifrost_core::profiling;

use crate::analyzer::read_ledger::ReadKey;
use crate::analyzer::semantic::cfg_algorithms::{
    CfgAlgorithmBudget, CfgAlgorithmError, CfgAlgorithmRequest, Postdominators, postdominators,
};
use crate::analyzer::semantic::{
    CallGuardOutcome, CallSiteId, CancellationToken, ClassAtom, ClassIdentity, ClassSeed,
    DispatchReadAttribution, DispatchReadUnattributedReason, EvidenceCompleteness, GuardFact,
    GuardPredicate, LengthDelimitedDigest, MemberAccessKind, MemberAccessQuery, MemberLookup,
    MemoryLocationId, MemoryLocationKind, NarrowingVerdict, ProcedureHandle, ProcedurePortHandle,
    ProgramPointHandle, ProgramPointId, ProofStatus, SemanticBudget, SemanticBudgetExceeded,
    SemanticCallSite, SemanticCapability, SemanticEffect, SemanticGapDischarge, SemanticLocator,
    SemanticProviderError, SemanticValueKind, SemanticWork, SourceSite, SourceSiteKind, SourceSpan,
    StableDigest, TypeFlowAdapter, UnknownReason, ValueFlowRelationKind, ValueFlowSnapshot,
    ValueId, source_site_kind_tag,
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
    ValueFlowSinkSpec, ValueFlowSourceId, ValueFlowSourceListId, ValueFlowSourceLists,
    ValueFlowSourceSpec, ValueFlowSources, WorkspaceValueFlowProvider, discover_closure_with_cuts,
};
use crate::{ProcedureSummaryBindingError, bind_active_unmaterialized_procedure_summaries};
use brokk_bifrost_analysis::analyzer::semantic::type_flow::file_for_locator;

use super::binding_refinement::{self, GuardBindings};
use super::class_seed_has_open_bound;
use super::correlations::{
    CorrelationAnalysis, CorrelationError, analyze_correlations_with_boolean_bindings,
};
use super::field_refinement::{self, FieldLoadRefinement, FieldVersion};
use super::field_slots::{FieldSlotIndex, MemberStoreEvidence, receiver_values};
use super::refinement_sources::DefinitionSources;
use super::summary::{class_atom_fingerprint, class_set_local_structure_digest};

/// Restrict the dependency relation to transfers that preserve runtime class.
/// Computation result seeds are added separately by `seed_procedure`.
pub(super) fn class_set_snapshot(
    input: ValueFlowInput<ValueFlowSnapshot>,
) -> ValueFlowInput<ValueFlowSnapshot> {
    let (snapshot, status) = input.into_parts();
    ValueFlowInput::new(snapshot.into_class_identity_projection(), status)
}

/// The purpose of one class-set observation site.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TypeFlowSitePurpose {
    MemberAccess,
    PythonIteratorReturn,
}

/// One member access or Python iterator-return value observed by the solve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberAccessSite {
    pub procedure: ProcedureHandle,
    pub point: ProgramPointHandle,
    /// The semantic value whose class set this member access reads.
    pub receiver: ValueId,
    /// The explicit call site when one backs this member operation. Synthetic
    /// implicit-protocol checks are call-shaped but have no source call site.
    pub call: Option<CallSiteId>,
    pub file: ProjectFile,
    pub span: SourceSpan,
    pub member: Box<str>,
    pub kind: MemberAccessKind,
    pub purpose: TypeFlowSitePurpose,
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

/// What one `refine_sources` round did to the plan it refined.
///
/// The caller solves the plan to collect the evidence each round reads, so it
/// needs to know whether the plan it solved is still the plan it holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SourceRefinement {
    /// The rebuild reproduced the plan exactly and installed nothing. The
    /// evidence solve that fed this round is a solve of the current plan.
    Unchanged,
    /// The plan changed, but its semantic source observations did not, so
    /// another round would derive the same sources again.
    Settled,
    /// New source observations. Another round can refine further.
    Refined,
}

/// A root's value-flow plan plus the class-set tables keyed by its ids.
///
/// The discovered closure is consumed by construction: its snapshots and
/// bindings move into the value-flow plan. Its per-call coverage is retained
/// beside them so `interpret` can attribute an unreached sink to the boundary
/// (`UnresolvedCall`, `Truncated`) the coverage names, the same derivation
/// the seeds already use.
///
/// Every field below is an input the solve or `interpret` reads, and
/// `TypeFlowPlan::feedback_fixpoint_matches` is the feedback loop's fixpoint
/// test: two iterations whose plans agree on those inputs cannot solve to
/// different results, so the later one must not solve again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeFlowPlan {
    value_flow: ValueFlowPlan,
    atoms: Vec<ClassAtom>,
    source_sites: Vec<SourceSite>,
    open_bound_class_origins: Vec<bool>,
    member_surface_sources: HashSet<ValueFlowEventKey>,
    sinks: Vec<MemberAccessSite>,
    coverage: HashMap<(DurableProcedureKey, CallSiteId), CallSiteCoverage>,
    dispatch_reads: HashMap<DurableProcedureKey, ProcedureDispatchReadContract>,
    local_structure_digests: HashMap<DurableProcedureKey, StableDigest>,
    summary_cuts: HashSet<DurableProcedureKey>,
    /// The workspace field-slot index this plan read stopped short. The typed
    /// charge is present whenever the index named one; the index also reports
    /// an untyped transient resolver-budget stop, which sets the flag alone.
    field_slot_semantic_exhausted: bool,
    field_slot_semantic_exhaustion: Option<SemanticBudgetExceeded>,
    discovery_failure: Option<UnknownReason>,
    field_refinements: Vec<(ProcedureHandle, FieldLoadRefinement)>,
    class_closed_load_refinements: Vec<(ProcedureHandle, ClassClosedLoadRefinement)>,
    field_store_receivers: Vec<FieldStoreReceiver>,
    refinement_budget_exhausted: bool,
    /// The first semantic charge a procedure-local refinement could not pay.
    refinement_exhaustion: Option<SemanticBudgetExceeded>,
    correlations: Vec<(ProcedureHandle, CorrelationAnalysis)>,
    guard_bindings: HashMap<DurableProcedureKey, GuardBindings>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ClassClosedLoadRefinement {
    point: ProgramPointId,
    event: usize,
    location: MemoryLocationId,
    result: ValueId,
    base: ValueId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FieldStoreReceiver {
    procedure: ProcedureHandle,
    point: ProgramPointHandle,
    event: usize,
    base: ValueId,
    origins: Vec<ValueId>,
    location: MemoryLocationId,
}

fn field_store_origin_values(
    base: ValueId,
    predecessors: &HashMap<ValueId, Vec<ValueId>>,
) -> Vec<ValueId> {
    let mut pending = vec![base];
    let mut seen = HashSet::default();
    let mut origins = Vec::new();
    while let Some(value) = pending.pop() {
        if !seen.insert(value) {
            continue;
        }
        match predecessors.get(&value) {
            Some(sources) if !sources.is_empty() => pending.extend(sources.iter().copied()),
            _ => origins.push(value),
        }
    }
    origins
}

fn retained_field_store_receivers(value_flow: &ValueFlowPlan) -> Vec<FieldStoreReceiver> {
    let mut stores = Vec::new();
    let mut seen = HashSet::default();
    for procedure in value_flow.mounted_procedures() {
        let semantics = procedure.semantics();
        let mut copy_predecessors = HashMap::<ValueId, Vec<ValueId>>::default();
        for (source, target) in local_copy_edges(procedure) {
            copy_predecessors.entry(target).or_default().push(source);
        }
        let mut origins_by_base = HashMap::default();
        for point in semantics.points() {
            let point_handle = procedure
                .point_handle(point.id)
                .expect("a retained point is live");
            for rule in value_flow.local_rule_views(&point_handle) {
                if rule.kind != ValueFlowRelationKind::MemoryStore
                    || !seen.insert((point_handle.clone(), rule.event_index))
                {
                    continue;
                }
                let event_index = rule.event_index as usize;
                let event = point
                    .events
                    .get(event_index)
                    .expect("a retained memory-store relation names a live event");
                let SemanticEffect::MemoryStore { location, .. } = event.effect else {
                    unreachable!("a memory-store relation names a MemoryStore event");
                };
                let location = semantics
                    .memory_location(location)
                    .expect("a retained memory store has a live location");
                let MemoryLocationKind::Field { base, .. } = &location.kind else {
                    continue;
                };
                stores.push(FieldStoreReceiver {
                    procedure: procedure.clone(),
                    point: point_handle.clone(),
                    event: event_index,
                    base: *base,
                    origins: origins_by_base
                        .entry(*base)
                        .or_insert_with(|| field_store_origin_values(*base, &copy_predecessors))
                        .clone(),
                    location: match event.effect {
                        SemanticEffect::MemoryStore { location, .. } => location,
                        _ => unreachable!("the event was checked as a MemoryStore"),
                    },
                });
            }
        }
    }
    stores
}

fn local_copy_edges(procedure: &ProcedureHandle) -> Vec<(ValueId, ValueId)> {
    procedure
        .semantics()
        .points()
        .iter()
        .flat_map(|point| &point.events)
        .filter_map(|event| match event.effect {
            SemanticEffect::Assignment {
                target,
                value: source,
            }
            | SemanticEffect::ValueFlow {
                kind: crate::analyzer::semantic::ValueFlowKind::Local,
                source,
                target,
            } => Some((source, target)),
            _ => None,
        })
        .collect()
}

fn call_result_aliases(procedure: &ProcedureHandle) -> HashSet<ValueId> {
    let mut aliases = procedure
        .semantics()
        .call_sites()
        .iter()
        .flat_map(SemanticCallSite::normal_result_values)
        .collect::<HashSet<_>>();
    let mut copies = HashMap::<ValueId, Vec<ValueId>>::default();
    for (source, target) in local_copy_edges(procedure) {
        copies.entry(source).or_default().push(target);
    }
    let mut pending = aliases.iter().copied().collect::<Vec<_>>();
    while let Some(source) = pending.pop() {
        for &target in copies.get(&source).into_iter().flatten() {
            if aliases.insert(target) {
                pending.push(target);
            }
        }
    }
    aliases
}

/// Values whose classes can affect behavior outside a chain of ordinary local
/// copies. Class-driven load refinement cannot affect a result when that result
/// and all its copies are dead, so exclude those loads before asking the
/// reaching-definition oracle about their bases.
fn observable_value_dependencies(procedure: &ProcedureHandle) -> HashSet<ValueId> {
    let semantics = procedure.semantics();
    let mut relevant = HashSet::default();
    for call in semantics.call_sites() {
        relevant.insert(call.callee);
        relevant.extend(call.receiver);
        relevant.extend(call.arguments.iter().map(|argument| argument.value));
    }
    for location in semantics.memory_locations() {
        match location.kind {
            MemoryLocationKind::Field { base, .. } | MemoryLocationKind::Property { base, .. } => {
                relevant.insert(base);
            }
            MemoryLocationKind::Dereference { address } => {
                relevant.insert(address);
            }
            MemoryLocationKind::Index { base, index, .. } => {
                relevant.insert(base);
                relevant.extend(index);
            }
            MemoryLocationKind::LexicalCell { binding } => {
                relevant.insert(binding);
            }
            MemoryLocationKind::Capture { binding, .. } => {
                relevant.extend(binding);
            }
            MemoryLocationKind::Static { .. } => {}
        }
    }
    for point in semantics.points() {
        for event in &point.events {
            match event.effect {
                SemanticEffect::AggregateInitializer { value, .. }
                | SemanticEffect::ValueUse { value, .. }
                | SemanticEffect::MemoryStore { value, .. } => {
                    relevant.insert(value);
                }
                SemanticEffect::ValueFlow {
                    kind,
                    source,
                    target,
                } if kind != crate::analyzer::semantic::ValueFlowKind::Local => {
                    relevant.insert(source);
                    relevant.insert(target);
                }
                SemanticEffect::ProcedureReturn { value }
                | SemanticEffect::Throw { value }
                | SemanticEffect::AsyncSuspend { awaited: value, .. } => {
                    relevant.extend(value);
                }
                SemanticEffect::CaptureBind { capture } => {
                    let binding = semantics
                        .capture(capture)
                        .expect("a capture-bind effect has a live capture");
                    if let crate::analyzer::semantic::CaptureSource::Value(value) = binding.captured
                    {
                        relevant.insert(value);
                    }
                }
                _ => {}
            }
        }
    }
    let mut reverse = HashMap::<ValueId, Vec<ValueId>>::default();
    for (source, target) in local_copy_edges(procedure) {
        reverse.entry(target).or_default().push(source);
    }
    let mut pending = relevant.iter().copied().collect::<Vec<_>>();
    while let Some(target) = pending.pop() {
        for &source in reverse.get(&target).into_iter().flatten() {
            if relevant.insert(source) {
                pending.push(source);
            }
        }
    }
    relevant
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

/// Whether two dispatch read contracts name the same reads.
///
/// A read row is a question and the canonical digest of the answer it
/// returned. Two contracts with the same questions and the same attribution
/// are the same dependency set even when the answers those questions returned
/// differ; see `TypeFlowPlan::feedback_fixpoint_matches` for why that
/// difference cannot reach the solve.
fn dispatch_read_contracts_name_the_same_reads(
    left: &HashMap<DurableProcedureKey, ProcedureDispatchReadContract>,
    right: &HashMap<DurableProcedureKey, ProcedureDispatchReadContract>,
) -> bool {
    left.len() == right.len()
        && left.iter().all(|(procedure, left)| {
            right
                .get(procedure)
                .is_some_and(|right| dispatch_read_rows_name_the_same_reads(left, right))
        })
}

fn dispatch_read_rows_name_the_same_reads(
    left: &ProcedureDispatchReadContract,
    right: &ProcedureDispatchReadContract,
) -> bool {
    match (left, right) {
        (
            ProcedureDispatchReadContract::Complete(left),
            ProcedureDispatchReadContract::Complete(right),
        ) => {
            // `canonical_dispatch_read_contract` sorts and deduplicates both
            // slices by the whole key, so rows naming equal questions are
            // contiguous in both and pairing by position compares the two
            // question sets.
            left.len() == right.len()
                && left
                    .iter()
                    .zip(right.iter())
                    .all(|(left, right)| asks_the_same_question(left, right))
        }
        (
            ProcedureDispatchReadContract::Unattributed(left),
            ProcedureDispatchReadContract::Unattributed(right),
        ) => left == right,
        (
            ProcedureDispatchReadContract::Complete(_),
            ProcedureDispatchReadContract::Unattributed(_),
        )
        | (
            ProcedureDispatchReadContract::Unattributed(_),
            ProcedureDispatchReadContract::Complete(_),
        ) => false,
    }
}

/// Whether two read keys asked the workspace the same question.
///
/// [`ReadKey::Lookup`] is the one read key that carries an answer: its
/// `digest` is the canonical digest of what the question returned. Every other
/// key already is a question about the workspace's content, so those compare
/// exactly.
fn asks_the_same_question(left: &ReadKey, right: &ReadKey) -> bool {
    match (left, right) {
        (
            ReadKey::Lookup {
                kind: left_kind,
                question: left_question,
                ..
            },
            ReadKey::Lookup {
                kind: right_kind,
                question: right_question,
                ..
            },
        ) => left_kind == right_kind && left_question == right_question,
        _ => left == right,
    }
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
    RefinementBudget(SemanticBudgetExceeded),
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

/// Domain separator for [`SeedTables::content_keyed_event_key`].
const CONTENT_KEYED_EVENT: &[u8] = b"bifrost-type-flow-content-keyed-event-v1";

/// Set on every content-derived ordinal so it cannot collide with a counter
/// ordinal, which starts at zero and counts up.
const CONTENT_KEYED_ORDINAL_BIT: u32 = 1 << 31;

/// One spec under construction plus the reporting record parallel to it.
struct SeedTables {
    sources: Vec<(ValueFlowSourceSpec, ClassAtom, SourceSite)>,
    source_lists: ValueFlowSourceLists,
    open_bound_class_sources: HashSet<ValueFlowSourceId>,
    sinks: Vec<(ValueFlowSinkSpec, MemberAccessSite)>,
    member_surface_sources: HashSet<ValueFlowEventKey>,
    /// Python's `*args` and `**kwargs` values are containers. Their element
    /// arguments remain ordinary value-flow inputs for other clients, but do
    /// not define the container's runtime class in this class-set plan.
    container_parameter_ports: HashSet<ProcedurePortHandle>,
    /// Distinct ordinals at each stable source location. Several program
    /// points can share a source mapping.
    ordinals: HashMap<(SemanticLocator, ValueFlowEventKind), u32>,
}

impl SeedTables {
    fn new() -> Self {
        Self {
            sources: Vec::new(),
            source_lists: ValueFlowSourceLists::default(),
            open_bound_class_sources: HashSet::default(),
            sinks: Vec::new(),
            ordinals: HashMap::default(),
            member_surface_sources: HashSet::default(),
            container_parameter_ports: HashSet::default(),
        }
    }

    fn push_source(
        &mut self,
        point: &ProgramPointHandle,
        phase: ValueFlowObservationPhase,
        carrier: ValueFlowCarrier,
        atom: ClassAtom,
        site: SourceSite,
    ) -> ValueFlowSourceId {
        let key = self.event_key(point, ValueFlowEventKind::Source);
        let id = ValueFlowSourceId::try_from_index(self.sources.len()).expect("source ID fits u32");
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
        id
    }

    fn mark_open_bound_class_source(&mut self, id: ValueFlowSourceId) {
        assert!(
            self.open_bound_class_sources.insert(id),
            "a class source is marked open-bound only once"
        );
    }

    fn push_class_seed_source(
        &mut self,
        point: &ProgramPointHandle,
        phase: ValueFlowObservationPhase,
        carrier: ValueFlowCarrier,
        atom: ClassAtom,
        site: SourceSite,
        open_bound_class: bool,
    ) {
        assert!(
            !open_bound_class || matches!(atom, ClassAtom::Class(_)),
            "only a class atom can carry an open class bound"
        );
        let id = self.push_source(point, phase, carrier, atom, site);
        if open_bound_class {
            self.mark_open_bound_class_source(id);
        }
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
        match site.purpose {
            TypeFlowSitePurpose::MemberAccess => assert_eq!(
                matches!(site.kind, MemberAccessKind::Call),
                site.call.is_some(),
                "only an explicit call-shaped member sink owns a call-site ID"
            ),
            TypeFlowSitePurpose::PythonIteratorReturn => {
                assert_eq!(
                    site.kind,
                    MemberAccessKind::Call,
                    "an iterator-protocol return checks for methods"
                );
                assert!(
                    site.call.is_none(),
                    "an implicit iterator-protocol call has no source call-site ID"
                );
            }
        }
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

    /// An event key whose ordinal states what the event is, not how many
    /// events the plan had already seeded at its site.
    ///
    /// [`Self::event_key`] numbers an event with a per-plan counter over
    /// (site, kind). A guard publishes an admitted narrowing source only when
    /// an input reaching it independently admits the proven class, and that
    /// depends on the root the guard was reached from, so the same guard seeds
    /// a different number of sources under different roots and renumbers every
    /// later event at its site. A persisted summary names its events by this
    /// key, so under the counter a restored fact could name no live source, or
    /// worse, silently name the wrong one (#3430). A guard source therefore
    /// derives its ordinal from its own content: its arm classification, the
    /// class it states, the binding it states it about, and the program point
    /// that states it. The high bit separates the two spaces, so a content
    /// ordinal can never equal a counter ordinal at one site.
    ///
    /// `discriminator` separates the seeding roles that share this space.
    fn content_keyed_event_key(
        &self,
        point: &ProgramPointHandle,
        discriminator: &[u8],
        site_kind: SourceSiteKind,
        atom: &ClassAtom,
        carrier: &ValueFlowCarrier,
        procedure: &SemanticLocator,
    ) -> ValueFlowEventKey {
        let mut digest = LengthDelimitedDigest::new(CONTENT_KEYED_EVENT);
        digest.push(discriminator);
        digest.push(&point.id().get().to_le_bytes());
        digest.push(&[source_site_kind_tag(site_kind)]);
        digest.push(class_atom_fingerprint(atom).as_bytes());
        carrier
            .stable_key()
            .expect("a guarded binding carrier has a stable key")
            .push_procedure_local_identity(&mut digest, procedure);
        let ordinal = u32::from_le_bytes(
            digest.finish().as_bytes()[..4]
                .try_into()
                .expect("a digest yields four leading bytes"),
        ) | CONTENT_KEYED_ORDINAL_BIT;
        ValueFlowEventKey::at_point(point, ordinal, ValueFlowEventKind::Source)
            .expect("a live point with a retained source mapping yields an event key")
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
    let carrier = ValueFlowCarrier::for_value(
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
            if field_slots
                .dynamic_write_evidence(workspace, adapter, class, member)
                .next()
                .is_some() =>
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
    let mut sources_by_class = HashMap::<ClassIdentity, Vec<ValueFlowSourceId>>::default();
    // Every source the domain could not name. A verdict classifies a class
    // against the guard's predicate, and an Unknown has no hierarchy to test,
    // so narrowing alone carries a remainder straight into an arm that has
    // already established what the value is. The guards that do establish it
    // answer for these sources instead (issue #3296). The list grows with the
    // remainders the loop installs, so a later guard sees an earlier guard's.
    let mut unknown_sources = Vec::<ValueFlowSourceId>::new();
    let mut source_evidence = tables
        .sources
        .iter()
        .enumerate()
        .map(|(index, (_, atom, site))| {
            (
                ValueFlowSourceId::try_from_index(index).expect("source ID fits u32"),
                (atom.clone(), site.kind),
            )
        })
        .collect::<HashMap<_, _>>();
    for (index, (_, atom, _)) in tables.sources.iter().enumerate() {
        let id = ValueFlowSourceId::try_from_index(index).expect("source ID fits u32");
        match atom {
            ClassAtom::Class(class) => sources_by_class.entry(class.clone()).or_default().push(id),
            ClassAtom::Unknown(_) => unknown_sources.push(id),
        }
    }
    let mut kills = Vec::new();
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
            if (sources_by_class.is_empty() && unknown_sources.is_empty())
                || (guard.true_edge.is_none() && guard.false_edge.is_none())
            {
                continue;
            }
            // The candidates this guard classifies, including the classes an
            // earlier guard's arm proved: those are ordinary plan sources and
            // a later guard must be able to drop them.
            let class_sources = sources_by_class.iter().collect::<Vec<_>>();
            let classes = class_sources
                .iter()
                .map(|(class, _)| *class)
                .collect::<Vec<_>>();
            let mut predicate_target = None;
            let mut replacement_inputs = None;
            let (binding, call_verdicts) = match guard.predicate {
                GuardPredicate::InstanceOf { .. }
                | GuardPredicate::ExactClass { .. }
                | GuardPredicate::HasMember { .. }
                | GuardPredicate::Truthy { .. }
                | GuardPredicate::NullComparison { .. } => {
                    (bindings.binding_for_guard(guard_index), None)
                }
                GuardPredicate::Opaque { .. } => {
                    match adapter.call_guard_narrowing(
                        workspace,
                        procedure,
                        guard,
                        &classes,
                        &member_lookup,
                    ) {
                        CallGuardOutcome::NoConstraint => continue,
                        CallGuardOutcome::Narrowed { value, verdicts } => (
                            bindings.binding_at_point(guard.point, value),
                            Some(verdicts),
                        ),
                        CallGuardOutcome::Intersected {
                            value,
                            verdicts,
                            target,
                        } => {
                            predicate_target = Some(target);
                            (
                                bindings.binding_at_point(guard.point, value),
                                Some(verdicts),
                            )
                        }
                        CallGuardOutcome::Replaced { value, target } => {
                            predicate_target = Some(target);
                            replacement_inputs = Some(
                                class_sources
                                    .iter()
                                    .flat_map(|(_, sources)| sources.iter().copied())
                                    .chain(unknown_sources.iter().copied())
                                    .collect::<Vec<_>>(),
                            );
                            (
                                bindings.binding_at_point(guard.point, value),
                                Some(vec![NarrowingVerdict::Drop; classes.len()]),
                            )
                        }
                        // The developer's condition constrains this value in a
                        // way the engine cannot name. That holds on both arms:
                        // `if p(x)` and `if not p(x)` each say something the
                        // candidate set does not express. The remainder rides
                        // the guarded binding until the arms reconverge.
                        CallGuardOutcome::Unmodeled { values } => {
                            // With no named candidate there is no completeness
                            // claim to weaken. Keep the existing unknown atoms;
                            // a conditional remainder needs a concrete trigger.
                            if class_sources.is_empty() {
                                continue;
                            }
                            for value in values {
                                let Some(binding) = bindings.binding_at_point(guard.point, value)
                                else {
                                    continue;
                                };
                                let carrier = binding_carrier(procedure, binding);
                                let point = procedure
                                    .point_handle(guard.point)
                                    .expect("a retained guard point is live");
                                let id = push_guard_remainder(
                                    workspace,
                                    procedure,
                                    tables,
                                    guard,
                                    &point,
                                    &carrier,
                                    UnknownReason::UnmodeledPredicate,
                                    class_sources
                                        .iter()
                                        .flat_map(|(_, sources)| sources.iter().copied())
                                        .collect(),
                                );
                                source_evidence.insert(
                                    id,
                                    (
                                        ClassAtom::Unknown(UnknownReason::UnmodeledPredicate),
                                        SourceSiteKind::ConditionalNarrowingGuard,
                                    ),
                                );
                                unknown_sources.push(id);
                                if let Some(join) = guard_join(
                                    procedure,
                                    &mut joins,
                                    &mut cfg_budget,
                                    cancellation,
                                    guard.point,
                                )? {
                                    kill_at_predecessors(
                                        procedure,
                                        &mut kills,
                                        join,
                                        &carrier,
                                        tables.source_lists.intern(vec![id]),
                                    );
                                }
                            }
                            continue;
                        }
                    }
                }
                GuardPredicate::ConstantBoolean { .. }
                | GuardPredicate::ConstantEquality { .. }
                | GuardPredicate::OrderedIntegerComparison { .. }
                | GuardPredicate::OrderedFloatComparison { .. }
                | GuardPredicate::NanComparison { .. } => continue,
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
            let mut remainders = HashMap::<UnknownReason, Vec<ValueFlowSourceId>>::default();
            for ((_, atom_sources), verdict) in class_sources.iter().zip(&verdicts) {
                if let NarrowingVerdict::Incomplete(reason) = verdict {
                    remainders
                        .entry(reason.clone())
                        .or_default()
                        .extend(atom_sources.iter().copied());
                }
            }
            let mut remainders = remainders.into_iter().collect::<Vec<_>>();
            remainders.sort_unstable_by(|(left, _), (right, _)| left.cmp(right));
            let mut true_arm_sources = remainders
                .into_iter()
                .map(|(reason, inputs)| (ClassAtom::Unknown(reason), inputs, false))
                .collect::<Vec<_>>();
            // What this arm proves about the values the domain could not
            // name. A guard that establishes the subject's class states the
            // atoms the remainder becomes there; every other guard answers
            // with no atoms and the remainder is carried through unchanged.
            let proved_seed = if unknown_sources.is_empty() && replacement_inputs.is_none() {
                ClassSeed::NotApplicable
            } else {
                predicate_target
                    .unwrap_or_else(|| adapter.guard_proves_classes(workspace, procedure, guard))
            };
            let proved_has_open_bound = class_seed_has_open_bound(&proved_seed);
            let proved = proved_seed.into_atoms().collect::<Vec<_>>();
            let proved_replaces_remainder = !proved.is_empty();
            true_arm_sources.extend(proved.into_iter().map(|atom| {
                let open_bound_class =
                    proved_has_open_bound && matches!(&atom, ClassAtom::Class(_));
                (
                    atom,
                    replacement_inputs
                        .as_ref()
                        .unwrap_or(&unknown_sources)
                        .clone(),
                    open_bound_class,
                )
            }));
            // Every kill this guard emits reads the candidate tables as they
            // reached it, so they are all emitted before the arm's own
            // sources are installed: a guard never drops what it just proved.
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
                        dropped.extend(atom_sources.iter().copied());
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
                        sources: tables.source_lists.intern(dropped),
                        labels: None,
                    });
                }
            }
            if proved_replaces_remainder
                && let Some(edge) = guard
                    .true_edge
                    .and_then(|id| procedure.semantics().control_edge(id))
            {
                // The arm establishes what the value is, so the remainder
                // that reached the guard states nothing further about it
                // there. Only this binding loses it: a copy taken before the
                // guard keeps its own.
                kills.push(ValueFlowEdgeKillSpec {
                    point: procedure
                        .point_handle(guard.point)
                        .expect("a validated guard point remains live"),
                    target: edge.target_point,
                    kind: edge.kind,
                    carrier: carrier.clone(),
                    sources: tables.source_lists.intern(unknown_sources.clone()),
                    labels: None,
                });
            }
            if guard.true_edge.is_some() && !true_arm_sources.is_empty() {
                let semantics = procedure.semantics();
                let join = guard_join(
                    procedure,
                    &mut joins,
                    &mut cfg_budget,
                    cancellation,
                    guard.point,
                )?;
                let point = procedure
                    .point_handle(guard.point)
                    .expect("a retained guard point is live");
                // Separate activations: an unrelated admitted source in the
                // plan must not certify a different input that reaches here.
                let mut classified_sources = Vec::new();
                for (atom, inputs, target_has_open_bound) in true_arm_sources {
                    let (admitted, conditional): (Vec<_>, Vec<_>) =
                        inputs.into_iter().partition(|input| {
                            let (input_atom, kind) = &source_evidence[input];
                            if *kind == SourceSiteKind::ConditionalNarrowingGuard
                                || tables.open_bound_class_sources.contains(input)
                            {
                                return false;
                            }
                            match (&atom, input_atom) {
                                (ClassAtom::Class(target), ClassAtom::Class(source)) => {
                                    target == source
                                }
                                (
                                    ClassAtom::Class(_),
                                    ClassAtom::Unknown(UnknownReason::RootParameter),
                                ) => true,
                                _ => false,
                            }
                        });
                    if !admitted.is_empty() {
                        let exact_input_for_class = match &atom {
                            ClassAtom::Class(target) => admitted.iter().any(|input| {
                                matches!(
                                    &source_evidence[input].0,
                                    ClassAtom::Class(source) if source == target
                                ) && !tables.open_bound_class_sources.contains(input)
                            }),
                            ClassAtom::Unknown(_) => false,
                        };
                        classified_sources.push((
                            atom.clone(),
                            admitted,
                            SourceSiteKind::NarrowingGuard,
                            target_has_open_bound && !exact_input_for_class,
                        ));
                    }
                    if !conditional.is_empty() {
                        classified_sources.push((
                            atom.clone(),
                            conditional,
                            SourceSiteKind::ConditionalNarrowingGuard,
                            target_has_open_bound,
                        ));
                    }
                }
                for (atom, inputs, kind, open_bound_class) in classified_sources {
                    assert!(
                        !open_bound_class || matches!(atom, ClassAtom::Class(_)),
                        "only a class atom can carry an open class bound"
                    );
                    let site = source_site(
                        workspace,
                        procedure,
                        mapping_span(procedure, guard.source),
                        kind,
                    )
                    .expect("a workspace guard retains its source file");
                    let key = tables.content_keyed_event_key(
                        &point,
                        b"guard-arm",
                        kind,
                        &atom,
                        &carrier,
                        procedure.semantics().locator(),
                    );
                    let id = ValueFlowSourceId::try_from_index(tables.sources.len())
                        .expect("source ID fits u32");
                    source_evidence.insert(id, (atom.clone(), kind));
                    // The arm's own source is an ordinary plan source: a
                    // later guard classifies it like any other. The atom also
                    // decides where the source stops: a proven class reaches
                    // the reconvergence, an unknown remainder ends there.
                    let ends_at_join = match &atom {
                        ClassAtom::Class(class) => {
                            sources_by_class.entry(class.clone()).or_default().push(id);
                            None
                        }
                        ClassAtom::Unknown(_) => {
                            unknown_sources.push(id);
                            join
                        }
                    };
                    tables.sources.push((
                        ValueFlowSourceSpec::new(
                            key,
                            point.clone(),
                            ValueFlowObservationPhase::AfterEffects,
                            carrier.clone(),
                            ProofStatus::Proven,
                            EvidenceCompleteness::Complete,
                        )
                        .when_sources_reach(tables.source_lists.intern(inputs)),
                        atom,
                        site,
                    ));
                    if open_bound_class {
                        tables.mark_open_bound_class_source(id);
                    }
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
                                sources: tables.source_lists.intern(vec![id]),
                                labels: None,
                            });
                        }
                    }
                    // The guard conditions this binding only until its false
                    // arm, where a later conjunct can also reach it. Copies
                    // made inside the protected arm keep their remainder on
                    // their own carriers.
                    //
                    // What ends at the reconvergence depends on what the arm
                    // established. An unknown remainder is conditional on the
                    // arm being taken, so it stops where the arms merge. A
                    // class the arm proved is an ordinary value on that path
                    // and merges at the reconvergence like any other reaching
                    // value, exactly as a replacement does; killing it there
                    // would leave only the other arms' candidates (#3431).
                    let false_target = guard
                        .false_edge
                        .and_then(|edge| semantics.control_edge(edge))
                        .map(|edge| edge.target_point);
                    if replacement_inputs.is_none() {
                        for target in [false_target, ends_at_join].into_iter().flatten() {
                            kill_at_predecessors(
                                procedure,
                                &mut kills,
                                target,
                                &carrier,
                                tables.source_lists.intern(vec![id]),
                            );
                        }
                    }
                    // A replacement contributes its type to later joins just
                    // like any other reaching value. Dropping it at the join
                    // would leave only the false arm's original candidates.
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
                        dropped.extend(atom_sources.iter().copied());
                    }
                }
                if dropped.is_empty() {
                    continue;
                }
                let carrier = binding_carrier(procedure, binding);
                let dropped = tables.source_lists.intern(dropped);
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
                        sources: dropped,
                        labels: None,
                    });
                }
            }
        }
    }
    Ok(kills)
}

/// The guard's immediate postdominator: the point where its arms reconverge
/// and a conditional remainder stops applying. Postdominators are derived once
/// per procedure and reused by every guard in it.
///
/// Only the ordinary flow reconverges. An abnormal exit inside one arm -- a
/// lowered implicit abort, a throw, or a call's exceptional continuation that
/// no handler catches -- ends that path at the procedure's exceptional exit
/// without ever reaching the code after the guard, so it carries no value into
/// the merge there. The exceptional exit therefore does not take part, which
/// the request states by naming the normal exit as both exits: a point that can
/// reach only the exceptional exit is not analyzable and the reconvergence
/// intersection skips it. Counting that path would strip the arms' join of its
/// postdominance, drop the kill that ends the remainder, and let an unmodeled
/// guard keep weakening every later use of the binding (#3410).
fn guard_join(
    procedure: &ProcedureHandle,
    joins: &mut Option<Postdominators<ProgramPointId>>,
    cfg_budget: &mut CfgAlgorithmBudget,
    cancellation: &CancellationToken,
    point: ProgramPointId,
) -> Result<Option<ProgramPointId>, TypeFlowPlanError> {
    let semantics = procedure.semantics();
    if joins.is_none() {
        let normal_exit = semantics.normal_exit_point();
        *joins = Some(
            postdominators(
                semantics,
                semantics.entry_point(),
                normal_exit,
                normal_exit,
                &mut CfgAlgorithmRequest::new(cfg_budget, cancellation),
            )
            .map_err(TypeFlowPlanError::GuardControl)?,
        );
    }
    Ok(joins
        .as_ref()
        .expect("guard postdominators were computed")
        .immediate_postdominator(semantics, point))
}

/// Seed an undecidable candidate on the guarded binding at the guard point.
/// The remainder is conditional on the candidate classes reaching the guard:
/// zero classes can reach an infeasible arm, and must not manufacture one.
#[allow(clippy::too_many_arguments)]
fn push_guard_remainder(
    workspace: &WorkspaceAnalyzer,
    procedure: &ProcedureHandle,
    tables: &mut SeedTables,
    guard: &GuardFact,
    point: &ProgramPointHandle,
    carrier: &ValueFlowCarrier,
    reason: UnknownReason,
    inputs: Vec<ValueFlowSourceId>,
) -> ValueFlowSourceId {
    let site = source_site(
        workspace,
        procedure,
        mapping_span(procedure, guard.source),
        SourceSiteKind::ConditionalNarrowingGuard,
    )
    .expect("a workspace guard retains its source file");
    let atom = ClassAtom::Unknown(reason);
    let key = tables.content_keyed_event_key(
        point,
        b"guard-remainder",
        SourceSiteKind::ConditionalNarrowingGuard,
        &atom,
        carrier,
        procedure.semantics().locator(),
    );
    let id = ValueFlowSourceId::try_from_index(tables.sources.len()).expect("source ID fits u32");
    tables.sources.push((
        ValueFlowSourceSpec::new(
            key,
            point.clone(),
            ValueFlowObservationPhase::AfterEffects,
            carrier.clone(),
            ProofStatus::Proven,
            EvidenceCompleteness::Complete,
        )
        .when_sources_reach(tables.source_lists.intern(inputs)),
        atom,
        site,
    ));
    id
}

/// Stop a guard remainder on every edge that enters `target`.
fn kill_at_predecessors(
    procedure: &ProcedureHandle,
    kills: &mut Vec<ValueFlowEdgeKillSpec>,
    target: ProgramPointId,
    carrier: &ValueFlowCarrier,
    sources: ValueFlowSourceListId,
) {
    for (_, edge) in procedure.semantics().predecessor_edges(target) {
        kills.push(ValueFlowEdgeKillSpec {
            point: procedure
                .point_handle(edge.source_point)
                .expect("a retained predecessor point is live"),
            target,
            kind: edge.kind,
            carrier: carrier.clone(),
            sources,
            labels: None,
        });
    }
}

fn binding_carrier(
    procedure: &ProcedureHandle,
    binding: crate::analyzer::semantic::ValueId,
) -> ValueFlowCarrier {
    ValueFlowCarrier::for_value(
        procedure
            .value_handle(binding)
            .expect("a binding origin is live in its procedure"),
    )
}

/// Procedure-local refinements derived once for one request's root solves.
///
/// One root solve builds its plan more than once: a summary-cut build whose
/// sources still need refinement is discarded and rebuilt in full, and every
/// feedback iteration rebuilds the plan again. Binding refinement is a pure
/// function of the procedure's semantic identity, and field refinement of
/// that identity together with the gaps the procedure's snapshot discharges
/// and the workspace field-slot surface. Deriving them once per build repeats
/// the work and charges the root's semantic budget for it once per build: one
/// `uvicorn/config.py` root spent 837k of its 1,000,000
/// nested-entry budget deriving `Config.__init__` for a plan it then threw
/// away, leaving too little for the plan it kept (#3163).
///
/// Reuse admits a retained refinement once per ledger, while every replay
/// imports its measured work. A live holder can cross a root boundary, but
/// its admission never suppresses the new root's work telemetry.
#[derive(Debug, Default)]
pub struct ProcedureRefinements {
    bindings: HashMap<StableDigest, DerivedRefinement<GuardBindings>>,
    correlations: HashMap<StableDigest, DerivedRefinement<CorrelationAnalysis>>,
    fields: HashMap<StableDigest, DerivedRefinement<Vec<FieldLoadRefinement>>>,
    closed_loads: HashMap<StableDigest, DerivedRefinement<HashSet<(ProgramPointId, ValueId)>>>,
}

#[derive(Debug)]
struct DerivedRefinement<T> {
    keys: Option<Arc<[crate::analyzer::ReadKey]>>,
    unattributed_reads: usize,
    execution_dependences: usize,
    value: T,
    owner: Arc<()>,
    work: crate::analyzer::semantic::SemanticBudgetReplay,
}

/// Census the rows and text that actually leave a refinement derivation.
/// Scratch admission history cannot describe the cache's retained value.
trait RefinementCensus {
    fn census(&self) -> SemanticWork;
}

impl RefinementCensus for GuardBindings {
    fn census(&self) -> SemanticWork {
        GuardBindings::census(self)
    }
}

impl RefinementCensus for Vec<FieldLoadRefinement> {
    fn census(&self) -> SemanticWork {
        SemanticWork {
            nested_entries: self.len()
                + self
                    .iter()
                    .map(|load| {
                        load.alternatives.len()
                            + load
                                .alternatives
                                .iter()
                                .map(|alternative| alternative.guards.len())
                                .sum::<usize>()
                    })
                    .sum::<usize>(),
            owned_text_bytes: self.iter().map(|load| load.member.len()).sum(),
            ..SemanticWork::default()
        }
    }
}

impl RefinementCensus for CorrelationAnalysis {
    fn census(&self) -> SemanticWork {
        SemanticWork {
            nested_entries: self.definitions.len()
                + self.guard_edge_exclusions.len()
                + self
                    .guard_edge_exclusions
                    .iter()
                    .map(|candidate| {
                        candidate.all_reaching_data_defs.len()
                            + candidate.compatible_data_defs.len()
                            + candidate.incompatible_data_defs.len()
                            + candidate.unknown_data_defs.len()
                    })
                    .sum::<usize>()
                + self.data_reaching_at_event.len()
                + self
                    .data_reaching_at_event
                    .iter()
                    .map(|row| row.definitions.len())
                    .sum::<usize>(),
            ..SemanticWork::default()
        }
    }
}

impl RefinementCensus for HashSet<(ProgramPointId, ValueId)> {
    fn census(&self) -> SemanticWork {
        SemanticWork {
            nested_entries: self.len(),
            ..SemanticWork::default()
        }
    }
}

fn refinement_census(
    value: &impl RefinementCensus,
    keys: &Option<Arc<[crate::analyzer::ReadKey]>>,
) -> SemanticWork {
    let mut heap = RetainedHeap::default();
    if let Some(keys) = keys {
        heap.arc(keys, |keys, heap| {
            for key in keys {
                retained_read_key(heap, key);
            }
        });
    }
    let (bytes, entries) = heap.totals();
    let mut census = value.census();
    census.owned_text_bytes = census.owned_text_bytes.saturating_add(bytes);
    census.nested_entries = census.nested_entries.saturating_add(entries);
    census
}

/// Answer one refinement from the cache, deriving it on the first request.
fn reused_or_derived<T: Clone + RefinementCensus>(
    cache: &mut HashMap<StableDigest, DerivedRefinement<T>>,
    workspace: &WorkspaceAnalyzer,
    identity: StableDigest,
    budget: &mut SemanticBudget,
    cancellation: &CancellationToken,
    derive: impl FnOnce(&mut SemanticBudget) -> Result<T, CorrelationError>,
) -> Result<T, CorrelationError> {
    if cancellation.is_cancelled() {
        return Err(CorrelationError::Cancelled {
            timed_out: cancellation.is_timed_out(),
        });
    }
    if let Some(derived) = cache.get(&identity) {
        if let Some(keys) = &derived.keys {
            workspace.analyzer().record_read_receipt(keys);
        }
        crate::analyzer::replay_query_read_receipt(
            workspace.analyzer(),
            [],
            derived.unattributed_reads,
            derived.execution_dependences,
        );
        debug_assert_eq!(
            derived.work.retained,
            refinement_census(&derived.value, &derived.keys)
        );
        let already_held = budget.has_replay_holder(&derived.owner);
        let mut replay = derived.work;
        if already_held {
            replay.retained = SemanticWork::default();
        }
        budget
            .replay_continuation(replay)
            .map_err(CorrelationError::Budget)?;
        if !already_held {
            budget.track_replay_holder(&derived.owner, derived.work.retained);
            budget.record_charged_artifact(identity);
        }
        return Ok(derived.value.clone());
    }
    let _derivation = profiling::scope_with(|| {
        format!(
            "type_flow.refinement_derive[{}]",
            std::any::type_name::<T>()
        )
    });
    let before = budget.replay_snapshot();
    let (value, reads) = crate::analyzer::capture_query_reads(workspace.analyzer(), || {
        budget.with_temporary_admissions(derive)
    });
    let value = value?;
    let keys = reads.unordered_keys();
    // Empty receipts must retain no allocation or residency entry.
    let keys = (!keys.is_empty()).then(|| Arc::from(keys));
    let unattributed_reads = reads.unattributed_reads();
    let execution_dependences = reads.execution_dependences();
    let census = refinement_census(&value, &keys);
    budget.admit(census).map_err(CorrelationError::Budget)?;
    let mut work = budget.replay_since(&before);
    work.retained = census;
    let owner = Arc::new(());
    let bound = budget.bind_replay_holder(&owner, &before);
    debug_assert_eq!(
        bound, census,
        "a refinement holder pays its returned census"
    );
    budget.record_charged_artifact(identity);
    cache.insert(
        identity,
        DerivedRefinement {
            keys,
            unattributed_reads,
            execution_dependences,
            value: value.clone(),
            owner,
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

fn field_refinement_identity(
    procedure: &ProcedureHandle,
    local_structure: Option<StableDigest>,
    field_slot_digest: StableDigest,
) -> StableDigest {
    let mut identity =
        procedure_semantics_identity(b"bifrost-type-flow-field-refinement-v1", procedure);
    match local_structure {
        Some(local_structure) => identity.push(local_structure.as_bytes()),
        None => identity.push(b"no-snapshot"),
    }
    identity.push(field_slot_digest.as_bytes());
    identity.finish()
}

/// Closure discovery is independent of class seeding and field refinement.
/// Surveys can establish that a root has no relevant snapshot before paying
/// to construct the source and sink universe for that root.
pub(super) struct TypeFlowDiscovery<'provider, 'workspace> {
    root: ProcedureHandle,
    provider: &'provider WorkspaceValueFlowProvider<'workspace>,
    closure: DiscoveredClosure,
    dispatch_reads: DispatchReadCollector,
    demands: Vec<ValueFlowCarrier>,
}

struct NoSummaryCuts;
impl ClosureCutDecider for NoSummaryCuts {}

impl<'provider, 'workspace> TypeFlowDiscovery<'provider, 'workspace> {
    pub(super) fn new(
        root: &ProcedureHandle,
        provider: &'provider WorkspaceValueFlowProvider<'workspace>,
        limits: ClosureLimits,
        semantic_budget: &mut SemanticBudget,
        cancellation: &CancellationToken,
    ) -> Result<Self, TypeFlowPlanError> {
        Self::with_summary_cuts(
            root,
            provider,
            limits,
            semantic_budget,
            cancellation,
            &mut NoSummaryCuts,
        )
    }

    fn with_summary_cuts<C: ClosureCutDecider>(
        root: &ProcedureHandle,
        provider: &'provider WorkspaceValueFlowProvider<'workspace>,
        limits: ClosureLimits,
        semantic_budget: &mut SemanticBudget,
        cancellation: &CancellationToken,
        cuts: &mut C,
    ) -> Result<Self, TypeFlowPlanError> {
        let _scope = profiling::scope("type_flow.discovery");
        let dispatch_reads = DispatchReadCollector::default();
        let observed_provider = provider.observing_dispatch_reads(dispatch_reads.clone());
        let closure = discover_closure_with_cuts(
            &observed_provider,
            root,
            limits,
            semantic_budget,
            cancellation,
            cuts,
        )
        .map_err(TypeFlowPlanError::Discovery)?;
        Ok(Self {
            root: root.clone(),
            provider,
            closure,
            dispatch_reads,
            demands: Vec::new(),
        })
    }

    pub(super) fn discovery_boundary(&self) -> Option<UnknownReason> {
        if closure_has_provider_failure(&self.closure) {
            Some(UnknownReason::IncompleteRoot)
        } else if self
            .closure
            .coverage
            .values()
            .any(|coverage| coverage.truncated)
        {
            Some(UnknownReason::Truncated)
        } else {
            None
        }
    }

    pub(super) fn procedure_reference(
        &self,
        reference: &crate::analyzer::semantic::SemanticProcedureReference,
    ) -> Option<&ProcedureHandle> {
        self.closure
            .snapshots
            .iter()
            .map(|input| input.value().procedure())
            .find(|procedure| {
                procedure.artifact().key() == &reference.key
                    && procedure.semantics().locator() == &reference.locator
            })
    }

    pub(super) fn excludes_procedures<'a>(
        &self,
        procedures: impl IntoIterator<Item = &'a crate::analyzer::semantic::SemanticProcedureReference>,
    ) -> bool {
        // A stopped discovery or missing control topology is not a negative
        // answer about omitted work. Incomplete value relations alone do not
        // omit procedures: discovery enumerates the IR call-site inventory,
        // and class seeding cannot add a procedure to that closure.
        self.closure.root_snapshot.is_some()
            && !self.closure.truncated
            && self.closure.skipped.is_empty()
            && !closure_has_provider_failure(&self.closure)
            && self
                .closure
                .snapshots
                .iter()
                .map(ValueFlowInput::status)
                .chain(self.closure.bindings.iter().map(ValueFlowInput::status))
                .all(|status| {
                    !matches!(
                        status,
                        SemanticInputStatus::ExceededBudget { .. } | SemanticInputStatus::Cancelled
                    )
                })
            && self.closure.snapshots.iter().all(|input| {
                let snapshot = input.value();
                snapshot.procedure().semantics().gaps().iter().all(|gap| {
                    gap.capability != SemanticCapability::NormalControlFlow
                        || gap.discharge == SemanticGapDischarge::RetainedControlTopology
                        || snapshot.gap_is_discharged(gap.id)
                })
            })
            && self.closure.coverage.values().all(|coverage| {
                !coverage.truncated
                    && dispatch_status(&coverage.dispatch)
                        .budget_exceeded()
                        .is_none()
                    && coverage.bindings.iter().all(|binding| {
                        !matches!(binding,
                        BindingCoverage::Answered { status } if status.budget_exceeded().is_some())
                    })
            })
            && !procedures.into_iter().any(|procedure| {
                self.closure.snapshots.iter().any(|input| {
                    input.value().procedure().artifact().key() == &procedure.key
                        && input.value().procedure().semantics().locator() == &procedure.locator
                })
            })
    }

    pub(super) fn into_plan(
        self,
        workspace: &WorkspaceAnalyzer,
        adapter: &dyn TypeFlowAdapter,
        field_slots: &FieldSlotIndex,
        semantic_budget: &mut SemanticBudget,
        cancellation: &CancellationToken,
        refinements: &mut ProcedureRefinements,
    ) -> Result<TypeFlowPlan, TypeFlowPlanError> {
        TypeFlowPlan::from_discovery(
            workspace,
            adapter,
            field_slots,
            self,
            semantic_budget,
            cancellation,
            refinements,
        )
    }

    pub(super) fn demanding(mut self, demands: impl IntoIterator<Item = ValueFlowCarrier>) -> Self {
        self.demands.extend(demands);
        self
    }
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
        TypeFlowDiscovery::new(root, provider, limits, semantic_budget, cancellation)?.into_plan(
            workspace,
            adapter,
            field_slots,
            semantic_budget,
            cancellation,
            refinements,
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
        TypeFlowDiscovery::with_summary_cuts(
            root,
            provider,
            limits,
            semantic_budget,
            cancellation,
            cuts,
        )?
        .into_plan(
            workspace,
            adapter,
            field_slots,
            semantic_budget,
            cancellation,
            refinements,
        )
    }

    fn from_discovery(
        workspace: &WorkspaceAnalyzer,
        adapter: &dyn TypeFlowAdapter,
        field_slots: &FieldSlotIndex,
        discovery: TypeFlowDiscovery<'_, '_>,
        semantic_budget: &mut SemanticBudget,
        cancellation: &CancellationToken,
        refinements: &mut ProcedureRefinements,
    ) -> Result<Self, TypeFlowPlanError> {
        let discovery_failure = discovery.discovery_boundary();
        let TypeFlowDiscovery {
            root,
            provider,
            mut closure,
            dispatch_reads,
            mut demands,
        } = discovery;
        let _scope = profiling::scope("type_flow.plan_build");
        if closure.root_snapshot.is_none() {
            return Err(TypeFlowPlanError::RootRelationsUnavailable);
        }
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
        let mut class_closed_load_refinements = Vec::new();
        let mut refinement_exhaustion: Option<SemanticBudgetExceeded> = None;
        let mut correlations = Vec::new();
        let mut guard_bindings = HashMap::default();
        for procedure in &closure.procedures {
            let bindings = reused_or_derived(
                &mut refinements.bindings,
                workspace,
                procedure_semantics_identity(b"bifrost-type-flow-binding-refinement-v1", procedure)
                    .finish(),
                semantic_budget,
                cancellation,
                |budget| {
                    binding_refinement::derive(workspace, adapter, procedure, budget, cancellation)
                },
            );
            let correlation_bindings = match bindings {
                Ok(bindings) => {
                    let correlation_bindings = bindings.correlation_bindings().to_vec();
                    let data_bindings = bindings.data_bindings().to_vec();
                    let open_bindings = bindings.open_bindings().clone();
                    let correlation_events = bindings.correlation_events().to_vec();
                    guard_bindings.insert(procedure.durable_key(), bindings);
                    Some((
                        correlation_bindings,
                        data_bindings,
                        open_bindings,
                        correlation_events,
                    ))
                }
                Err(CorrelationError::Budget(exceeded)) => {
                    refinement_exhaustion.get_or_insert(exceeded);
                    None
                }
                Err(CorrelationError::Cancelled { .. }) => {
                    return Err(TypeFlowPlanError::Cancelled);
                }
            };
            let correlation = correlation_bindings.map(
                |(correlation_bindings, data_bindings, open_bindings, correlation_events)| {
                    reused_or_derived(
                        &mut refinements.correlations,
                        workspace,
                        procedure_semantics_identity(
                            b"bifrost-type-flow-correlations-v1",
                            procedure,
                        )
                        .finish(),
                        semantic_budget,
                        cancellation,
                        |budget| {
                            let mut analysis = analyze_correlations_with_boolean_bindings(
                                procedure,
                                &correlation_bindings,
                                &data_bindings,
                                &open_bindings,
                                &correlation_events,
                                budget,
                                Some(cancellation),
                            )?;
                            // Only an exclusion with an incompatible definition can
                            // remove a source, so the rest is state the cache would
                            // carry for nothing.
                            analysis
                                .guard_edge_exclusions
                                .retain(|candidate| !candidate.incompatible_data_defs.is_empty());
                            Ok(analysis)
                        },
                    )
                },
            );
            match correlation {
                Some(Ok(analysis)) => {
                    if !analysis.guard_edge_exclusions.is_empty() {
                        correlations.push((procedure.clone(), analysis));
                    }
                }
                Some(Err(CorrelationError::Budget(exceeded))) => {
                    refinement_exhaustion.get_or_insert(exceeded);
                }
                Some(Err(CorrelationError::Cancelled { .. })) => {
                    return Err(TypeFlowPlanError::Cancelled);
                }
                None => {}
            }
            let fields = if let Some(class) = adapter.enclosing_class(workspace, procedure) {
                let snapshot = closure
                    .snapshots
                    .iter()
                    .find(|snapshot| snapshot.value().procedure() == procedure)
                    .map(|snapshot| snapshot.value());
                match reused_or_derived(
                    &mut refinements.fields,
                    workspace,
                    field_refinement_identity(
                        procedure,
                        local_structure_digests
                            .get(&procedure.durable_key())
                            .copied(),
                        field_slots.digest(),
                    ),
                    semantic_budget,
                    cancellation,
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
                    Err(CorrelationError::Budget(exceeded)) => {
                        refinement_exhaustion.get_or_insert(exceeded);
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
            let closed_loads = match reused_or_derived(
                &mut refinements.closed_loads,
                workspace,
                procedure_semantics_identity(b"bifrost-type-flow-closed-loads-v1", procedure)
                    .finish(),
                semantic_budget,
                cancellation,
                |budget| {
                    let loads = adapter
                        .closed_memory_loads(
                            workspace,
                            procedure,
                            &mut crate::analyzer::semantic::SemanticRequest::new(
                                budget,
                                cancellation,
                            ),
                        )
                        .map_err(CorrelationError::Budget)?;
                    if cancellation.is_cancelled() {
                        return Err(CorrelationError::Cancelled {
                            timed_out: cancellation.is_timed_out(),
                        });
                    }
                    budget
                        .admit(SemanticWork {
                            nested_entries: loads.len(),
                            ..SemanticWork::default()
                        })
                        .map_err(CorrelationError::Budget)?;
                    Ok(loads.into_iter().collect())
                },
            ) {
                Ok(loads) => loads,
                Err(CorrelationError::Budget(exceeded)) => {
                    refinement_exhaustion.get_or_insert(exceeded);
                    HashSet::default()
                }
                Err(CorrelationError::Cancelled { .. }) => {
                    return Err(TypeFlowPlanError::Cancelled);
                }
            };
            let call_result_aliases = call_result_aliases(procedure);
            let observable_values = observable_value_dependencies(procedure);
            for point in procedure.semantics().points() {
                for (event, effect) in point.events.iter().enumerate() {
                    let SemanticEffect::MemoryLoad {
                        location, result, ..
                    } = effect.effect
                    else {
                        continue;
                    };
                    if closed_loads.contains(&(point.id, result)) {
                        continue;
                    }
                    if !observable_values.contains(&result) {
                        continue;
                    }
                    let Some(location_row) = procedure.semantics().memory_location(location) else {
                        continue;
                    };
                    let MemoryLocationKind::Index {
                        base,
                        constant_index: Some(_),
                        ..
                    } = &location_row.kind
                    else {
                        continue;
                    };
                    if call_result_aliases.contains(base)
                        && adapter.memory_load_supports_class_closure(location_row)
                    {
                        class_closed_load_refinements.push((
                            procedure.clone(),
                            ClassClosedLoadRefinement {
                                point: point.id,
                                event,
                                location,
                                result,
                                base: *base,
                            },
                        ));
                    }
                }
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
                &closed_loads,
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
            source_lists,
            sources,
            open_bound_class_sources,
            sinks,
            member_surface_sources,
            container_parameter_ports,
            ..
        } = tables;
        let open_bound_class_sources = open_bound_class_sources
            .iter()
            .map(|id| sources[id.index()].0.key().clone())
            .collect::<HashSet<_>>();
        // Source IDs follow insertion order; reporting metadata remains
        // recoverable through the durable event key.
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
            ValueFlowSources::from_parts(source_specs, source_lists),
            sink_specs,
            edge_kills,
            call_behavior,
        )?;
        value_flow = value_flow.without_call_value_inputs_to(&container_parameter_ports);
        let field_store_receivers = retained_field_store_receivers(&value_flow);
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
        // Refinement evidence is queried on carriers that need not have an
        // ordinary transfer edge to the value the refinement replaces. For
        // example, an indexed load from a call result asks which classes reach
        // the call-result base before deciding whether its unknown load source
        // can be removed. Make those structured query inputs explicit slice
        // demands so the preliminary solve retains the proof it needs.
        for (procedure, analysis) in &correlations {
            for candidate in &analysis.guard_edge_exclusions {
                demands.extend(
                    candidate
                        .all_reaching_data_defs
                        .iter()
                        .filter_map(|definition| {
                            if let Some(value) = definition.rhs {
                                Some(ValueFlowCarrier::for_value(
                                    procedure
                                        .value_handle(value)
                                        .expect("a definition source is live"),
                                ))
                            } else if definition.is_entry() {
                                Some(binding_carrier(procedure, definition.binding))
                            } else {
                                None
                            }
                        }),
                );
            }
        }
        demands.extend(field_refinements.iter().flat_map(|(procedure, field)| {
            field.alternatives.iter().filter_map(|alternative| {
                let FieldVersion::Store { value, .. } = alternative.version else {
                    return None;
                };
                Some(ValueFlowCarrier::for_value(
                    procedure
                        .value_handle(value)
                        .expect("a field store value is live"),
                ))
            })
        }));
        demands.extend(
            class_closed_load_refinements
                .iter()
                .map(|(procedure, load)| {
                    ValueFlowCarrier::for_value(
                        procedure
                            .value_handle(load.base)
                            .expect("a class-refined load base is live"),
                    )
                }),
        );

        // Class-set observations exist only at member receivers. Keep the full
        // discovery result and its typed boundaries, but do not tabulate
        // transfer chains that cannot reach one of those observations. Source
        // refinement inputs above are explicit demands; the plan method also
        // conservatively retains edge-kill carriers, summary locations, and
        // fallback call inputs whose result is demanded.
        value_flow = value_flow.retain_flows_reaching(demands);
        let mut atoms = Vec::with_capacity(value_flow.sources().len());
        let mut source_sites = Vec::with_capacity(value_flow.sources().len());
        let mut open_bound_class_origins = Vec::with_capacity(value_flow.sources().len());
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
            open_bound_class_origins.push(open_bound_class_sources.contains(spec.key()));
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
            open_bound_class_origins,
            member_surface_sources,
            sinks: member_sites,
            coverage: closure.coverage,
            dispatch_reads,
            local_structure_digests,
            summary_cuts,
            field_slot_semantic_exhausted: field_slots.semantic_budget_exhausted(),
            field_slot_semantic_exhaustion: field_slots.semantic_budget_exhaustion(),
            discovery_failure,
            field_refinements,
            class_closed_load_refinements,
            field_store_receivers,
            refinement_budget_exhausted: refinement_exhaustion.is_some(),
            refinement_exhaustion,
            correlations,
            guard_bindings,
        })
    }

    pub(super) fn discovery_boundary(&self) -> Option<UnknownReason> {
        if self.field_slot_semantic_budget_exhausted() {
            Some(UnknownReason::SemanticBudget)
        } else {
            self.discovery_failure.clone()
        }
    }

    pub fn value_flow(&self) -> &ValueFlowPlan {
        &self.value_flow
    }

    pub(crate) fn needs_source_refinement(&self) -> bool {
        !self.correlations.is_empty()
            || !self.class_closed_load_refinements.is_empty()
            || !self.field_store_receivers.is_empty()
            || self.field_refinements.iter().any(|(_, field)| {
                field
                    .alternatives
                    .iter()
                    .any(|alternative| matches!(alternative.version, FieldVersion::Store { .. }))
            })
    }

    /// Record that a refinement round could not pay for the evidence the plan
    /// still needs, with the charge that failed when the caller knows it.
    pub(crate) fn mark_refinement_budget_exhausted(
        &mut self,
        exhaustion: Option<SemanticBudgetExceeded>,
    ) {
        self.refinement_budget_exhausted = true;
        if self.refinement_exhaustion.is_none() {
            self.refinement_exhaustion = exhaustion;
        }
    }

    /// The first semantic charge a procedure-local refinement could not pay.
    pub(crate) const fn refinement_exhaustion(&self) -> Option<SemanticBudgetExceeded> {
        self.refinement_exhaustion
    }

    /// The charge the workspace field-slot index could not pay, when it named
    /// one. `None` with [`Self::field_slot_semantic_exhausted`] set is the
    /// index's untyped transient resolver-budget stop.
    pub(crate) const fn field_slot_semantic_exhaustion(&self) -> Option<SemanticBudgetExceeded> {
        self.field_slot_semantic_exhaustion
    }

    pub(crate) const fn field_slot_semantic_exhausted(&self) -> bool {
        self.field_slot_semantic_exhausted
    }

    /// These sources and exclusions depend on a preliminary solve of this
    /// request's closure. A reusable body cut cannot reconstruct that evidence.
    pub(super) fn procedure_requires_source_refinement(&self, procedure: &ProcedureHandle) -> bool {
        self.correlations
            .iter()
            .any(|(owner, _)| owner == procedure)
            || self
                .class_closed_load_refinements
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
        for store in &self.field_store_receivers {
            points.insert(store.point.clone());
        }
        for (procedure, load) in &self.class_closed_load_refinements {
            points.insert(
                procedure
                    .point_handle(load.point)
                    .expect("a class-refined load point is live"),
            );
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
    ) -> Result<SourceRefinement, TypeFlowPlanError> {
        budget.charge_work(SemanticWork {
            nested_entries: self.value_flow.sources().len(),
            ..SemanticWork::default()
        });
        let mut correlated_kills = Vec::new();
        for (procedure, analysis) in &self.correlations {
            if cancellation.is_cancelled() {
                return Err(TypeFlowPlanError::Cancelled);
            }
            for candidate in &analysis.guard_edge_exclusions {
                let mut sources = HashMap::<ValueFlowSourceId, bool>::default();
                let mut complete = true;
                for definition in &candidate.all_reaching_data_defs {
                    let point = procedure
                        .point_handle(definition.point)
                        .expect("a definition point is live");
                    let (event, carrier) = if let Some(value) = definition.rhs {
                        (
                            definition.event_index,
                            ValueFlowCarrier::for_value(
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
                        let removable =
                            incompatible && matches!(self.atom(source), ClassAtom::Class(_));
                        sources
                            .entry(source)
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
                    .filter_map(|(id, remove)| remove.then_some(id))
                    .collect::<Vec<_>>();
                if sources.is_empty() {
                    continue;
                }
                let edge = procedure
                    .semantics()
                    .control_edge(candidate.edge)
                    .expect("a candidate edge is live");
                correlated_kills.push((
                    procedure
                        .point_handle(edge.source_point)
                        .expect("a guard point is live"),
                    edge.target_point,
                    edge.kind,
                    binding_carrier(procedure, candidate.data_binding),
                    sources,
                ));
            }
        }
        let mut class_closed_loads = HashSet::default();
        for (procedure, load) in &self.class_closed_load_refinements {
            if cancellation.is_cancelled() {
                return Err(TypeFlowPlanError::Cancelled);
            }
            let point = procedure
                .point_handle(load.point)
                .expect("a class-refined load point is live");
            let base = ValueFlowCarrier::for_value(
                procedure
                    .value_handle(load.base)
                    .expect("a class-refined load base is live"),
            );
            let Some(reaching) = evidence.before(
                &self.value_flow,
                &point,
                load.event,
                &base,
                budget,
                cancellation,
            )?
            else {
                continue;
            };
            let mut classes = Vec::new();
            let mut complete = !reaching.is_empty();
            for (source, uncertain) in reaching {
                let ClassAtom::Class(class) = self.atom(source) else {
                    complete = false;
                    break;
                };
                if uncertain {
                    complete = false;
                    break;
                }
                if !classes.contains(class) {
                    classes.push(class.clone());
                }
            }
            let location = procedure
                .semantics()
                .memory_location(load.location)
                .expect("a class-refined load location is live");
            if complete
                && adapter
                    .memory_load_is_closed_for_classes(workspace, procedure, location, &classes)
            {
                class_closed_loads.insert((procedure.durable_key(), load.point, load.result));
            }
        }
        let mut tables = SeedTables::new();
        for (id, spec) in self.value_flow.sources() {
            let replaced = self.field_refinements.iter().any(|(procedure, field)| {
                spec.point().procedure() == procedure && spec.point().id() == field.point
                    && matches!(spec.carrier(), ValueFlowCarrier::Value(value) if value.id() == field.result)
            });
            let class_closed = matches!(
                self.atom(id),
                ClassAtom::Unknown(UnknownReason::UnmodeledLoad)
            ) && matches!(spec.carrier(), ValueFlowCarrier::Value(value)
            if class_closed_loads.contains(&(
                spec.point().procedure().durable_key(),
                spec.point().id(),
                value.id(),
            )));
            if !replaced && !class_closed && spec.activation_triggers().is_none() {
                tables.sources.push((
                    spec.clone(),
                    self.atom(id).clone(),
                    self.source_site(id).clone(),
                ));
                if self.open_bound_class_origins[id.index()] {
                    let id = ValueFlowSourceId::try_from_index(tables.sources.len() - 1)
                        .expect("source ID fits u32");
                    tables.mark_open_bound_class_source(id);
                }
            }
        }
        let mut seen_procedures = HashSet::default();
        let procedures = self
            .value_flow
            .summary_procedures()
            .filter(|procedure| seen_procedures.insert(procedure.durable_key()))
            .cloned()
            .collect::<Vec<_>>();
        let mut uncertain_field_stores = HashSet::default();
        let mut descriptor_field_stores = HashSet::default();
        for store in &self.field_store_receivers {
            if cancellation.is_cancelled() {
                return Err(TypeFlowPlanError::Cancelled);
            }
            let receiver = ValueFlowCarrier::for_value(
                store
                    .procedure
                    .value_handle(store.base)
                    .expect("a field store receiver is live"),
            );
            let sources = evidence.after(
                &self.value_flow,
                &store.point,
                &receiver,
                budget,
                cancellation,
            )?;
            let member = store
                .procedure
                .semantics()
                .memory_location(store.location)
                .and_then(|location| {
                    adapter.accessed_member(
                        workspace,
                        &store.procedure,
                        MemberAccessQuery::Load(location),
                    )
                });
            let mut classes = Vec::new();
            let mut atoms = sources
                .as_deref()
                .unwrap_or_default()
                .iter()
                .map(|(source, uncertain)| (self.atom(*source).clone(), *uncertain))
                .collect::<Vec<_>>();
            let semantics = store.procedure.semantics();
            if atoms.is_empty() {
                for origin in &store.origins {
                    let call_seed = semantics
                        .call_sites()
                        .iter()
                        .find(|call| call.normal_result_values().any(|result| result == *origin))
                        .map(|call| adapter.constructed_class(workspace, &store.procedure, call));
                    let allocation_seed = semantics
                        .allocations()
                        .iter()
                        .find(|allocation| allocation.result == *origin)
                        .map(|allocation| {
                            adapter.allocation_class(workspace, &store.procedure, allocation)
                        });
                    let seed = call_seed.or(allocation_seed).unwrap_or_else(|| {
                        let value = semantics
                            .value(*origin)
                            .expect("a field-store receiver origin is retained");
                        match &value.kind {
                            SemanticValueKind::Parameter {
                                ordinal: _,
                                multiplicity,
                                ..
                            } if multiplicity.is_rest() => {
                                ClassSeed::Unknown(UnknownReason::VariadicParameter)
                            }
                            SemanticValueKind::Parameter { ordinal, .. } => adapter
                                .declared_parameter_class(workspace, &store.procedure, *ordinal),
                            SemanticValueKind::Receiver { .. } => {
                                let safe_class = adapter
                                    .enclosing_class(workspace, &store.procedure)
                                    .and_then(|class| {
                                        let hierarchy = adapter.class_hierarchy(workspace, &class);
                                        (matches!(class, ClassIdentity::Workspace(_))
                                            && hierarchy.descendants.as_deref() == Some(&[])
                                            && !hierarchy.unresolved_base
                                            && !hierarchy.dynamic_attributes)
                                            .then_some(class)
                                    });
                                safe_class.map_or(
                                    ClassSeed::Unknown(UnknownReason::SelfReceiver),
                                    ClassSeed::Class,
                                )
                            }
                            _ => adapter.retained_value_class(workspace, &store.procedure, value),
                        }
                    });
                    let seed = if matches!(seed, ClassSeed::NotApplicable) {
                        ClassSeed::Unknown(UnknownReason::UncertainFlow)
                    } else {
                        seed
                    };
                    atoms.extend(seed.into_atoms().map(|atom| (atom, false)));
                }
            }
            let mut complete = !atoms.is_empty();
            for (atom, uncertain) in atoms {
                if uncertain {
                    complete = false;
                    continue;
                }
                match atom {
                    ClassAtom::Class(class) => {
                        if adapter.class_hierarchy(workspace, &class).unresolved_base {
                            complete = false;
                        } else if !classes.contains(&class) {
                            classes.push(class);
                        }
                    }
                    ClassAtom::Unknown(_) => complete = false,
                }
            }
            let key = (
                store.point.clone(),
                u32::try_from(store.event).expect("a semantic event index fits u32"),
            );
            if !complete || classes.is_empty() || member.is_none() {
                uncertain_field_stores.insert(key);
                continue;
            }
            let descriptor_classes = classes
                .iter()
                .filter(|class| {
                    adapter.field_access_may_use_descriptor(
                        workspace,
                        class,
                        member.as_deref().expect("the member was checked above"),
                    )
                })
                .count();
            if descriptor_classes == classes.len() {
                descriptor_field_stores.insert(key);
            } else if descriptor_classes > 0 {
                uncertain_field_stores.insert(key);
            }
        }
        for procedure in &procedures {
            if cancellation.is_cancelled() {
                return Err(TypeFlowPlanError::Cancelled);
            }
            // Mint refined candidates above the sources that survive this
            // rebuild, not above the sources it replaces. Taking the
            // high-water mark from the whole current plan counted the
            // previous round's candidates, so every round minted strictly
            // higher ordinals for the same observation and rebuilt a plan
            // that differed from the one the round had just solved.
            for (spec, _, _) in tables
                .sources
                .iter()
                .filter(|(spec, _, _)| spec.point().procedure() == procedure)
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
                                && let Some(slot) =
                                    field_slots.slot(workspace, adapter, &class, &field.member)
                            {
                                budget
                                    .admit(SemanticWork {
                                        nested_entries: slot.atoms.len(),
                                        ..SemanticWork::default()
                                    })
                                    .map_err(TypeFlowPlanError::RefinementBudget)?;
                                values.extend(slot.atoms.iter().enumerate().map(
                                    |(atom_index, (atom, site))| {
                                        (
                                            atom.clone(),
                                            site.clone(),
                                            field_slots.atom_is_open_bound(
                                                workspace, adapter, slot, atom_index,
                                            ),
                                        )
                                    },
                                ));
                            } else if let Some(site) = unknown_site() {
                                values.push((
                                    ClassAtom::Unknown(UnknownReason::UnmodeledLoad),
                                    site,
                                    false,
                                ));
                            }
                            if matches!(alternative.version, FieldVersion::Open { .. })
                                && let Some(site) = unknown_site()
                            {
                                values.push((
                                    ClassAtom::Unknown(UnknownReason::FieldSlotIncomplete),
                                    site,
                                    false,
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
                            let carrier = ValueFlowCarrier::for_value(
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
                                        self.class_source_is_open_bound(source),
                                    ));
                                    if uncertain && let Some(site) = unknown_site() {
                                        values.push((
                                            ClassAtom::Unknown(UnknownReason::UncertainFlow),
                                            site,
                                            false,
                                        ));
                                    }
                                }
                            } else if let Some(site) = unknown_site() {
                                values.push((
                                    ClassAtom::Unknown(UnknownReason::UncertainFlow),
                                    site,
                                    false,
                                ));
                            }
                        }
                    }
                    let restriction = FieldLoadRefinement {
                        point: field.point,
                        result: field.result,
                        member: field.member.clone(),
                        alternatives: vec![alternative.clone()],
                    };
                    for (atom, site, open_bound_class) in values {
                        if field_atom_survives(
                            workspace,
                            adapter,
                            field_slots,
                            procedure,
                            &restriction,
                            &atom,
                        ) && !candidates.contains(&(
                            atom.clone(),
                            site.clone(),
                            open_bound_class,
                        )) {
                            candidates.push((atom, site, open_bound_class));
                        }
                    }
                }
                for (atom, site, open_bound_class) in candidates {
                    tables.push_class_seed_source(
                        &point,
                        ValueFlowObservationPhase::AfterEffects,
                        ValueFlowCarrier::for_value(
                            procedure
                                .value_handle(field.result)
                                .expect("a load result is live"),
                        ),
                        atom,
                        site,
                        open_bound_class,
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
            .admit(SemanticWork {
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
                    self.open_bound_class_origins[id.index()],
                )
            })
            .collect::<HashSet<_>>();
        let replacement = tables
            .sources
            .iter()
            .enumerate()
            .map(|(index, (spec, atom, site))| {
                (
                    spec.point(),
                    spec.phase(),
                    spec.carrier(),
                    atom,
                    site,
                    tables.open_bound_class_sources.contains(
                        &ValueFlowSourceId::try_from_index(index).expect("source ID fits u32"),
                    ),
                )
            })
            .collect::<HashSet<_>>();
        let sources_changed = previous != replacement;
        let open_bound_class_sources = tables
            .open_bound_class_sources
            .iter()
            .map(|id| tables.sources[id.index()].0.key().clone())
            .collect::<HashSet<_>>();
        for (spec, atom, site) in tables.sources {
            atoms_by_key.insert(spec.key().clone(), (atom, site));
            sources.push(spec);
        }
        let mut sources = ValueFlowSources::from_parts(sources, tables.source_lists);
        let ids_by_key = sources
            .specs
            .iter()
            .enumerate()
            .map(|(index, spec)| {
                (
                    spec.key(),
                    ValueFlowSourceId::try_from_index(index).expect("source ID fits u32"),
                )
            })
            .collect::<HashMap<_, _>>();
        let old_to_new = self
            .value_flow
            .sources()
            .map(|(_, source)| ids_by_key.get(source.key()).copied())
            .collect::<Vec<_>>();
        drop(ids_by_key);
        for (point, target, kind, carrier, old_ids) in correlated_kills {
            let ids = old_ids
                .into_iter()
                .filter_map(|id| old_to_new[id.index()])
                .collect::<Vec<_>>();
            if !ids.is_empty() {
                let list = sources.intern_list(ids);
                kills.push(ValueFlowEdgeKillSpec {
                    point,
                    target,
                    kind,
                    carrier,
                    sources: list,
                    labels: None,
                });
            }
        }
        let value_flow = self.value_flow.with_replaced_sources_and_edge_kills(
            sources,
            kills,
            &uncertain_field_stores,
            &descriptor_field_stores,
        )?;
        let mut atoms = Vec::new();
        let mut sites = Vec::new();
        let mut open_bound_class_origins = Vec::new();
        for (_, spec) in value_flow.sources() {
            let (atom, site) = atoms_by_key
                .remove(spec.key())
                .expect("a rebuilt source retains its atom");
            atoms.push(atom);
            sites.push(site);
            open_bound_class_origins.push(open_bound_class_sources.contains(spec.key()));
        }
        if value_flow.has_same_inputs(&self.value_flow)
            && value_flow.sources().all(|(id, spec)| {
                let previous = self
                    .value_flow
                    .source_id_for_key(spec.key())
                    .expect("equal plan inputs retain every source key");
                atoms[id.index()] == self.atoms[previous.index()]
                    && sites[id.index()] == self.source_sites[previous.index()]
                    && open_bound_class_origins[id.index()]
                        == self.open_bound_class_origins[previous.index()]
            })
        {
            // Keep the original source coordinates with the preliminary facts.
            // A rebuilt table may assign different IDs to identical inputs.
            return Ok(SourceRefinement::Unchanged);
        }
        self.value_flow = value_flow;
        self.atoms = atoms;
        self.source_sites = sites;
        self.open_bound_class_origins = open_bound_class_origins;
        if sources_changed {
            Ok(SourceRefinement::Refined)
        } else {
            Ok(SourceRefinement::Settled)
        }
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

    pub(crate) fn class_source_is_open_bound(&self, source: ValueFlowSourceId) -> bool {
        self.open_bound_class_origins[source.index()]
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

    /// The feedback fixpoint identity: whether a later iteration that rebuilt
    /// this plan can reach a different result from the one this plan solved
    /// to.
    ///
    /// [`PartialEq`] says "the same plan". This says "the same solve", which
    /// is exactly as strict about every input the solve and `interpret`
    /// read, and deliberately not strict about one thing that is not an input:
    /// the answer digest each dispatch read row records.
    ///
    /// A dispatch read row is `ReadKey::Lookup { kind, question, digest }`:
    /// the question one call site was asked of the dispatch funnel, and the
    /// canonical digest of the answer it returned. Every consequence of a
    /// dispatch answer that this plan can hand to the solve or to the
    /// interpretation -- the callees discovery entered, the coverage each call
    /// site published, the provider status, the dispatched class atoms, the
    /// unmaterialized external targets that were bound as external summaries,
    /// the summary-cut decision -- is a field this comparison requires to be
    /// equal. The digest itself is an observation, not an input: it records
    /// what the question answered at the time it was asked, and hint-driven
    /// refinement can change it for one call site while leaving everything the
    /// solve reads byte-identical.
    ///
    /// The questions do stay in the identity. A dispatch read set is the
    /// dependency record a published summary reuses, so reusing rows under a
    /// different read set would record the wrong dependencies: a contract that
    /// gained a question, lost one, or stopped being fully attributed is a
    /// different dependency set and its iteration still solves (#3471).
    pub(crate) fn feedback_fixpoint_matches(&self, other: &Self) -> bool {
        // Destructuring exhaustively rather than reading fields off `self` is
        // what keeps this identity honest: a new plan field is a compile error
        // here until it is either compared or deliberately excluded.
        let Self {
            value_flow,
            atoms,
            source_sites,
            open_bound_class_origins,
            member_surface_sources,
            sinks,
            coverage,
            dispatch_reads,
            local_structure_digests,
            summary_cuts,
            field_slot_semantic_exhausted,
            field_slot_semantic_exhaustion,
            discovery_failure,
            field_refinements,
            class_closed_load_refinements,
            field_store_receivers,
            refinement_budget_exhausted,
            refinement_exhaustion,
            correlations,
            guard_bindings,
        } = self;
        value_flow == &other.value_flow
            && atoms == &other.atoms
            && source_sites == &other.source_sites
            && open_bound_class_origins == &other.open_bound_class_origins
            && member_surface_sources == &other.member_surface_sources
            && sinks == &other.sinks
            && coverage == &other.coverage
            && dispatch_read_contracts_name_the_same_reads(dispatch_reads, &other.dispatch_reads)
            && local_structure_digests == &other.local_structure_digests
            && summary_cuts == &other.summary_cuts
            && field_slot_semantic_exhausted == &other.field_slot_semantic_exhausted
            && field_slot_semantic_exhaustion == &other.field_slot_semantic_exhaustion
            && discovery_failure == &other.discovery_failure
            && field_refinements == &other.field_refinements
            && class_closed_load_refinements == &other.class_closed_load_refinements
            && field_store_receivers == &other.field_store_receivers
            && refinement_budget_exhausted == &other.refinement_budget_exhausted
            && refinement_exhaustion == &other.refinement_exhaustion
            && correlations == &other.correlations
            && guard_bindings == &other.guard_bindings
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
        self.field_slot_semantic_exhausted || self.refinement_budget_exhausted
    }

    pub(crate) const fn provider_failure_observed(&self) -> bool {
        matches!(self.discovery_failure, Some(UnknownReason::IncompleteRoot))
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
/// sink. An entered callee with unsupported normal control flow retains an
/// `IncompleteRoot` return alternative even when dispatch is exhaustive.
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
            } else if coverage.entered.iter().any(|callee| {
                callee.semantics().gaps().iter().any(|gap| {
                    gap.capability == SemanticCapability::NormalControlFlow
                        && gap.discharge != SemanticGapDischarge::RetainedControlTopology
                })
            }) {
                // An unsupported continuation can hide a normal return even
                // when dispatch and argument binding are exhaustive. Retain
                // that return alternative at the caller rather than treating
                // the callee's remaining return classes as a complete set.
                Some(UnknownReason::IncompleteRoot)
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
    closed_loads: &HashSet<(ProgramPointId, ValueId)>,
) {
    let semantics = procedure.semantics();
    let is_root = procedure.durable_key() == root_key;
    let receiver_values = receiver_values(procedure);
    let enclosing_class = adapter.enclosing_class(workspace, procedure);
    let is_python_iterator_method = is_root
        && adapter.language() == crate::analyzer::Language::Python
        && enclosing_class.is_some()
        && procedure
            .semantics()
            .locator()
            .declaration()
            .segments()
            .last()
            .and_then(|segment| segment.name())
            == Some("__iter__");
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
            SemanticValueKind::Constant
            | SemanticValueKind::ConstantString(_)
            | SemanticValueKind::Boolean(_) => {
                let span = mapping_span(procedure, value.source);
                let seed = adapter.constant_class(workspace, procedure, value);
                let has_open_bound = class_seed_has_open_bound(&seed);
                for atom in seed.into_atoms() {
                    let kind = source_kind_for_atom(&atom, SourceSiteKind::Literal);
                    let Some(site) = source_site(workspace, procedure, span, kind) else {
                        continue;
                    };
                    let carrier = ValueFlowCarrier::for_value(
                        procedure
                            .value_handle(value.id)
                            .expect("a retained value is live"),
                    );
                    let open_bound_class = has_open_bound && matches!(atom, ClassAtom::Class(_));
                    tables.push_class_seed_source(
                        &entry,
                        ValueFlowObservationPhase::AfterEffects,
                        carrier,
                        atom,
                        site,
                        open_bound_class,
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
                    let container = if adapter.language() == crate::analyzer::Language::Python {
                        adapter.declared_parameter_class(workspace, procedure, *ordinal)
                    } else {
                        ClassSeed::NotApplicable
                    };
                    if matches!(container, ClassSeed::NotApplicable) {
                        // An unmodeled rest formal collects caller values into
                        // a container whose class this adapter cannot state.
                        seed_port(
                            workspace,
                            procedure,
                            *ordinal,
                            &entry,
                            ClassAtom::Unknown(UnknownReason::VariadicParameter),
                            span,
                            SourceSiteKind::Unknown,
                            false,
                            tables,
                        );
                    } else {
                        let has_open_bound = class_seed_has_open_bound(&container);
                        tables.container_parameter_ports.insert(
                            ProcedurePortHandle::parameter(procedure.clone(), *ordinal)
                                .expect("a retained parameter has a valid parameter port"),
                        );
                        for atom in container.into_atoms() {
                            let kind =
                                source_kind_for_atom(&atom, SourceSiteKind::DeclaredParameter);
                            let open_bound_class =
                                has_open_bound && matches!(atom, ClassAtom::Class(_));
                            seed_port(
                                workspace,
                                procedure,
                                *ordinal,
                                &entry,
                                atom,
                                span,
                                kind,
                                open_bound_class,
                                tables,
                            );
                        }
                    }
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
                            false,
                            tables,
                        );
                    }
                } else {
                    let has_open_bound = class_seed_has_open_bound(&seed);
                    for atom in seed.into_atoms() {
                        let kind = source_kind_for_atom(&atom, SourceSiteKind::DeclaredParameter);
                        let open_bound_class =
                            has_open_bound && matches!(atom, ClassAtom::Class(_));
                        seed_port(
                            workspace,
                            procedure,
                            *ordinal,
                            &entry,
                            atom,
                            span,
                            kind,
                            open_bound_class,
                            tables,
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
                let carrier = ValueFlowCarrier::for_value(
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
                let has_open_bound = class_seed_has_open_bound(&seed);
                for atom in seed.into_atoms() {
                    let kind = source_kind_for_atom(&atom, SourceSiteKind::Unknown);
                    let Some(site) = source_site(workspace, procedure, span, kind) else {
                        continue;
                    };
                    let open_bound_class = has_open_bound && matches!(atom, ClassAtom::Class(_));
                    tables.push_class_seed_source(
                        &entry,
                        ValueFlowObservationPhase::AfterEffects,
                        ValueFlowCarrier::for_value(
                            procedure
                                .value_handle(value.id)
                                .expect("a saved default is live"),
                        ),
                        atom,
                        site,
                        open_bound_class,
                    );
                }
            }
            SemanticValueKind::LanguageDefined(_) => {
                let span = mapping_span(procedure, value.source);
                let Some(site) = source_site(workspace, procedure, span, SourceSiteKind::Unknown)
                else {
                    continue;
                };
                let carrier = ValueFlowCarrier::for_value(
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
            | SemanticValueKind::SignedInteger(_)
            | SemanticValueKind::FloatingPoint { .. }
            | SemanticValueKind::Exception
            | SemanticValueKind::Callable => {
                if callee_values.contains(&value.id) {
                    continue;
                }
                let span = mapping_span(procedure, value.source);
                let seed = adapter.retained_value_class(workspace, procedure, value);
                let has_open_bound = class_seed_has_open_bound(&seed);
                for atom in seed.into_atoms() {
                    let kind = source_kind_for_atom(&atom, SourceSiteKind::Unknown);
                    let Some(site) = source_site(workspace, procedure, span, kind) else {
                        continue;
                    };
                    let carrier = ValueFlowCarrier::for_value(
                        procedure
                            .value_handle(value.id)
                            .expect("a retained value is live"),
                    );
                    let open_bound_class = has_open_bound && matches!(atom, ClassAtom::Class(_));
                    tables.push_class_seed_source(
                        &entry,
                        ValueFlowObservationPhase::AfterEffects,
                        carrier,
                        atom,
                        site,
                        open_bound_class,
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
        let seed = adapter.allocation_class(workspace, procedure, allocation);
        let has_open_bound = class_seed_has_open_bound(&seed);
        for atom in seed.into_atoms() {
            let kind = source_kind_for_atom(&atom, SourceSiteKind::ContainerLiteral);
            let Some(site) = source_site(workspace, procedure, span, kind) else {
                continue;
            };
            let carrier = ValueFlowCarrier::for_value(
                procedure
                    .value_handle(allocation.result)
                    .expect("an allocation's result value is live"),
            );
            let open_bound_class = has_open_bound && matches!(atom, ClassAtom::Class(_));
            tables.push_class_seed_source(
                &point,
                ValueFlowObservationPhase::AfterEffects,
                carrier,
                atom,
                site,
                open_bound_class,
            );
        }
    }
    for point in semantics.points() {
        let mut computed_results = HashSet::default();
        for event in &point.events {
            match &event.effect {
                SemanticEffect::ProcedureReturn { value: Some(value) }
                    if is_python_iterator_method =>
                {
                    let point_handle = procedure
                        .point_handle(point.id)
                        .expect("a retained return point is live");
                    // Python materializes a return-value carrier and relates
                    // it to the expression with a Return flow edge. Observe
                    // the expression carrier directly so constructor facts
                    // at the call continuation remain visible at this sink.
                    let returned_value = point.events.iter().find_map(|candidate| match &candidate
                        .effect
                    {
                        SemanticEffect::ValueFlow {
                            kind: crate::analyzer::semantic::ValueFlowKind::Return,
                            source,
                            target,
                        } if *target == *value => Some(*source),
                        _ => None,
                    });
                    for member in ["__iter__", "__next__"] {
                        push_python_iterator_return_sink(
                            workspace,
                            procedure,
                            &point_handle,
                            returned_value.unwrap_or(*value),
                            event.source,
                            member,
                            tables,
                        );
                    }
                }
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
                    let has_open_bound = class_seed_has_open_bound(&seed);
                    for atom in seed.into_atoms() {
                        let kind = source_kind_for_atom(&atom, SourceSiteKind::Unknown);
                        let Some(site) = source_site(workspace, procedure, span, kind) else {
                            continue;
                        };
                        let open_bound_class =
                            has_open_bound && matches!(atom, ClassAtom::Class(_));
                        tables.push_class_seed_source(
                            &point_handle,
                            ValueFlowObservationPhase::AfterEffects,
                            ValueFlowCarrier::for_value(
                                procedure
                                    .value_handle(*target)
                                    .expect("a computed result is live"),
                            ),
                            atom,
                            site,
                            open_bound_class,
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
                    if adapter.memory_load_presents_name_read(location_row) {
                        continue;
                    }
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
                        field_slots.slot(workspace, adapter, class, &field.member)
                    } else if let MemoryLocationKind::Field { base, .. } = &location_row.kind
                        && receiver_values.contains(base)
                        && let Some(class) = enclosing_class.as_ref()
                        && let Some(member) = member.as_deref()
                    {
                        field_slots.slot(workspace, adapter, class, member)
                    } else {
                        None
                    };
                    let carrier = ValueFlowCarrier::for_value(
                        procedure
                            .value_handle(*result)
                            .expect("a load's result value is live"),
                    );
                    let access_seed = adapter.memory_load_result_class(
                        workspace,
                        procedure,
                        location_row,
                        *result,
                    );
                    let access_origin_present = !matches!(access_seed, ClassSeed::NotApplicable);
                    let access_has_open_bound = class_seed_has_open_bound(&access_seed);
                    for atom in access_seed.into_atoms() {
                        let kind = source_kind_for_atom(&atom, SourceSiteKind::ExactAccessResult);
                        if let Some(site) = source_site(workspace, procedure, span, kind) {
                            let open_bound_class =
                                access_has_open_bound && matches!(atom, ClassAtom::Class(_));
                            tables.push_class_seed_source(
                                &point_handle,
                                ValueFlowObservationPhase::AfterEffects,
                                carrier.clone(),
                                atom,
                                site,
                                open_bound_class,
                            );
                        }
                    }
                    if let Some(slot) = modeled_slot {
                        for (atom_index, (atom, site)) in slot.atoms.iter().enumerate() {
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
                            tables.push_class_seed_source(
                                &point_handle,
                                ValueFlowObservationPhase::AfterEffects,
                                carrier.clone(),
                                atom.clone(),
                                site.clone(),
                                field_slots
                                    .atom_is_open_bound(workspace, adapter, slot, atom_index),
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
                            let base_carrier = ValueFlowCarrier::for_value(
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
                    } else if !access_origin_present
                        && !closed_loads.contains(&(point.id, *result))
                        && let Some(site) =
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
                        let carrier = ValueFlowCarrier::for_value(
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
                            let carrier = ValueFlowCarrier::for_value(
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
    open_bound_class: bool,
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
    tables.push_class_seed_source(
        &point,
        ValueFlowObservationPhase::BeforeEffects,
        carrier,
        atom,
        site,
        open_bound_class,
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
    if let Some(classes) = adapter.exact_call_result_class(workspace, procedure, call) {
        for class in classes.iter().cloned() {
            seed_call_result(
                workspace,
                procedure,
                call,
                ClassAtom::Class(class),
                SourceSiteKind::ExactCallResult,
                false,
                tables,
            );
        }
    } else {
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
                    false,
                    tables,
                );
            }
        } else {
            let has_open_bound = class_seed_has_open_bound(&seed);
            for atom in seed.into_atoms() {
                let kind = source_kind_for_atom(&atom, SourceSiteKind::ConstructorCall);
                let open_bound_class = has_open_bound && matches!(atom, ClassAtom::Class(_));
                seed_call_result(
                    workspace,
                    procedure,
                    call,
                    atom,
                    kind,
                    open_bound_class,
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
    open_bound_class: bool,
    tables: &mut SeedTables,
) {
    let Some(site) = source_site(workspace, procedure, span, kind) else {
        return;
    };
    let port = ProcedurePortHandle::parameter(procedure.clone(), ordinal)
        .expect("the ordinal comes from a retained parameter value");
    tables.push_class_seed_source(
        entry,
        ValueFlowObservationPhase::AfterEffects,
        ValueFlowCarrier::Port(port),
        atom,
        site,
        open_bound_class,
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
        ValueFlowCarrier::for_value(procedure.value_handle(base).expect("a base value is live"));
    tables.push_sink(
        point,
        carrier,
        MemberAccessSite {
            procedure: procedure.clone(),
            point: point.clone(),
            receiver: base,
            call,
            file,
            span,
            member,
            kind,
            purpose: TypeFlowSitePurpose::MemberAccess,
        },
    );
}

fn push_python_iterator_return_sink(
    workspace: &WorkspaceAnalyzer,
    procedure: &ProcedureHandle,
    point: &ProgramPointHandle,
    returned: ValueId,
    source: crate::analyzer::semantic::SourceMappingId,
    member: &'static str,
    tables: &mut SeedTables,
) {
    let locator = &procedure
        .semantics()
        .source_mapping(source)
        .expect("a return effect retains a source mapping")
        .locator;
    let Some(file) = file_for_locator(workspace, locator) else {
        return;
    };
    let span = mapping_span(procedure, source);
    let carrier = ValueFlowCarrier::for_value(
        procedure
            .value_handle(returned)
            .expect("a return effect's value is live"),
    );
    tables.push_sink(
        point,
        carrier,
        MemberAccessSite {
            procedure: procedure.clone(),
            point: point.clone(),
            receiver: returned,
            call: None,
            file,
            span,
            member: member.into(),
            // Iteration invokes these methods implicitly. Keep the call kind
            // so adapters look up methods, while the site purpose records
            // that there is no explicit call-site identity to attach.
            kind: MemberAccessKind::Call,
            purpose: TypeFlowSitePurpose::PythonIteratorReturn,
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
    use brokk_bifrost_test_macros::hardwon;

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct TestRefinement(usize);

    impl RefinementCensus for TestRefinement {
        fn census(&self) -> SemanticWork {
            nested(self.0)
        }
    }

    fn test_read(label: &[u8]) -> ReadKey {
        ReadKey::Models(StableDigest::sha256(label))
    }

    fn nested(entries: usize) -> SemanticWork {
        SemanticWork {
            nested_entries: entries,
            ..SemanticWork::default()
        }
    }

    #[test]
    fn refinement_hits_replay_inputs_into_later_captures() {
        let project = crate::inline_project::InlineTestProject::with_language(
            crate::analyzer::Language::Python,
        )
        .file("a.py", "pass\n")
        .build();
        let workspace = project.workspace_analyzer(crate::analyzer::AnalyzerConfig::default());
        let identity = StableDigest::sha256(b"captured-refinement");
        let key = test_read(b"refinement-input");
        let cancellation = CancellationToken::default();
        let mut cache = HashMap::default();
        let mut first_budget = SemanticBudget::default();
        let (first, reads) = crate::analyzer::capture_query_reads(workspace.analyzer(), || {
            reused_or_derived(
                &mut cache,
                &workspace,
                identity,
                &mut first_budget,
                &cancellation,
                |_| {
                    workspace.analyzer().record_read(key.clone());
                    workspace.analyzer().record_unattributed_read();
                    Ok(TestRefinement(3))
                },
            )
            .expect("derive the refinement")
        });
        assert_eq!(first, TestRefinement(3));
        assert_eq!(reads.keys(), vec![key.clone()]);
        assert_eq!(reads.unattributed_reads(), 1);
        let mut later_budget = SemanticBudget::default();
        let (later, reads) = crate::analyzer::capture_query_reads(workspace.analyzer(), || {
            reused_or_derived(
                &mut cache,
                &workspace,
                identity,
                &mut later_budget,
                &cancellation,
                |_| panic!("a retained refinement must hit in the later capture"),
            )
            .expect("reuse the refinement")
        });
        assert_eq!(later, first);
        assert_eq!(reads.keys(), vec![key]);
        assert_eq!(reads.unattributed_reads(), 1);
    }

    /// One root solve builds its plan several times. Every build after the
    /// first must reuse the refinement the first build derived, and must not
    /// admit another retained copy (#3163).
    #[test]
    #[hardwon(
        "#2295+#3124+#3129+#3163+#3165+3e81228fb0ab: repeated root-plan construction duplicated procedure refinements, so repeated lookups must retain one derivation."
    )]
    fn repeated_refinement_lookups_hold_one_derivation() {
        let project = crate::inline_project::InlineTestProject::with_language(
            crate::analyzer::Language::Python,
        )
        .file("a.py", "pass\n")
        .build();
        let workspace = project.workspace_analyzer(crate::analyzer::AnalyzerConfig::default());
        let identity = StableDigest::sha256(b"one-refinement");
        let mut cache = HashMap::default();
        let mut budget = SemanticBudget::uniform(1_000).expect("a finite budget");
        let cancellation = CancellationToken::default();
        let mut derivations = 0_usize;
        for _ in 0..5 {
            let value = reused_or_derived(
                &mut cache,
                &workspace,
                identity,
                &mut budget,
                &cancellation,
                |budget| {
                    derivations += 1;
                    budget
                        .admit(nested(400))
                        .map_err(CorrelationError::Budget)?;
                    Ok(TestRefinement(400))
                },
            )
            .expect("the refinement derives and then reuses");
            assert_eq!(value, TestRefinement(400));
        }
        assert_eq!(derivations, 1, "one ledger derives the refinement once");
        assert_eq!(
            budget.resident().nested_entries,
            400,
            "five lookups hold one derivation, not five"
        );
        assert_eq!(budget.used().nested_entries, 4_000);
    }

    /// The near miss: this ledger holds one derivation of this size and no
    /// more. Keep both caches alive so the second entry must coexist with the first.
    #[test]
    #[hardwon("#3163: separate refinement identities must each debit the shared request budget")]
    fn one_ledger_holds_only_one_derivation_of_this_size() {
        let project = crate::inline_project::InlineTestProject::with_language(
            crate::analyzer::Language::Python,
        )
        .file("a.py", "pass\n")
        .build();
        let workspace = project.workspace_analyzer(crate::analyzer::AnalyzerConfig::default());
        let mut budget = SemanticBudget::uniform(1_000).expect("a finite budget");
        let cancellation = CancellationToken::default();
        let mut held_caches = Vec::new();
        for (round, label) in [b"first".as_slice(), b"second".as_slice()]
            .into_iter()
            .enumerate()
        {
            let mut cache = HashMap::default();
            let outcome = reused_or_derived(
                &mut cache,
                &workspace,
                StableDigest::sha256(label),
                &mut budget,
                &cancellation,
                |budget| {
                    budget
                        .admit(nested(600))
                        .map_err(CorrelationError::Budget)?;
                    Ok(TestRefinement(600))
                },
            );
            assert_eq!(
                outcome.is_ok(),
                round == 0,
                "two retained derivations do not fit"
            );
            held_caches.push(cache);
        }
    }

    /// A later root has its own child ledger. It reuses the request cache
    /// without deriving again, while still paying the measured semantic work.
    #[test]
    #[hardwon("#5113: a live refinement holder skipped traversal work in a fresh root")]
    fn a_later_root_ledger_reuses_and_pays_for_the_refinement() {
        let project = crate::inline_project::InlineTestProject::with_language(
            crate::analyzer::Language::Python,
        )
        .file("a.py", "pass\n")
        .build();
        let workspace = project.workspace_analyzer(crate::analyzer::AnalyzerConfig::default());
        let identity = StableDigest::sha256(b"one-refinement");
        let mut cache = HashMap::default();
        let mut first = SemanticBudget::uniform(1_000).expect("a finite budget");
        let cancellation = CancellationToken::default();
        reused_or_derived(
            &mut cache,
            &workspace,
            identity,
            &mut first,
            &cancellation,
            |budget| {
                budget
                    .admit(nested(400))
                    .map_err(CorrelationError::Budget)?;
                budget.charge_work(SemanticWork {
                    events: 300,
                    ..SemanticWork::default()
                });
                Ok(TestRefinement(400))
            },
        )
        .expect("the first ledger derives the refinement");

        let mut fresh = SemanticBudget::new_root_child(&first);
        let mut derivations = 0_usize;
        reused_or_derived(
            &mut cache,
            &workspace,
            identity,
            &mut fresh,
            &cancellation,
            |budget| {
                derivations += 1;
                budget
                    .admit(nested(400))
                    .map_err(CorrelationError::Budget)?;
                Ok(TestRefinement(400))
            },
        )
        .expect("the fresh ledger reuses the refinement");
        assert_eq!(derivations, 0, "the cached value is reused, not rederived");
        assert_eq!(fresh.resident().nested_entries, 400);
        assert_eq!(fresh.root_work_peak().events, 300);
        assert_eq!(
            fresh.used().nested_entries,
            800,
            "the later root ledger is charged the measured work"
        );
        fresh.charge_work(SemanticWork {
            events: 500,
            ..SemanticWork::default()
        });
        let replayed = reused_or_derived(
            &mut cache,
            &workspace,
            identity,
            &mut fresh,
            &cancellation,
            |_| panic!("the cached refinement must not be rederived"),
        );
        assert_eq!(replayed.unwrap(), TestRefinement(400));
        assert_eq!(fresh.root_work_peak().events, 1_100);
        assert_eq!(fresh.resident().nested_entries, 400);
        assert!(fresh.first_refusal().is_none());
    }

    #[test]
    fn field_refinement_identity_includes_the_slot_index() {
        use crate::analyzer::semantic::SemanticRequest;
        use crate::analyzer::{AnalyzerConfig, Language};
        use crate::inline_project::InlineTestProject;

        let project = InlineTestProject::with_language(Language::Python)
            .file(
                "app.py",
                "class Box:\n    def read(self):\n        return self.value\n",
            )
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let artifact = workspace
            .materialize_program_semantics(
                &project.file("app.py"),
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
                    == Some("read")
            })
            .and_then(|procedure| artifact.procedure_handle(procedure.id()))
            .expect("fixture declares Box.read");
        let structure = StableDigest::sha256(b"same-local-structure");

        assert_ne!(
            field_refinement_identity(
                &procedure,
                Some(structure),
                StableDigest::sha256(b"field-slots-a"),
            ),
            field_refinement_identity(
                &procedure,
                Some(structure),
                StableDigest::sha256(b"field-slots-b"),
            ),
            "different field-slot surfaces cannot share a refinement"
        );
    }

    #[test]
    fn overlapping_roots_share_request_refinements_without_changing_plans() {
        use crate::analyzer::semantic::{SemanticRequest, type_flow_adapter};
        use crate::analyzer::{AnalyzerConfig, Language};
        use crate::inline_project::InlineTestProject;
        use crate::value_flow::ValueFlowCache;

        let project = InlineTestProject::with_language(Language::Python)
            .file(
                "app.py",
                "def shared(value):\n    if isinstance(value, str):\n        return value.upper()\n    return value\n\ndef first(value):\n    return shared(value)\n\ndef second(value):\n    return shared(value)\n",
            )
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let cancellation = CancellationToken::default();
        let mut materialization_budget = SemanticBudget::default();
        let artifact = workspace
            .materialize_program_semantics(
                &project.file("app.py"),
                &mut SemanticRequest::new(&mut materialization_budget, &cancellation),
            )
            .expect("fixture semantics materialize")
            .available_value()
            .cloned()
            .expect("fixture semantics remain available");
        let root = |name: &str| {
            artifact
                .procedures()
                .iter()
                .find(|procedure| {
                    procedure
                        .locator()
                        .declaration()
                        .segments()
                        .last()
                        .and_then(|segment| segment.name())
                        == Some(name)
                })
                .and_then(|procedure| artifact.procedure_handle(procedure.id()))
                .unwrap_or_else(|| panic!("fixture declares {name}"))
        };
        let first = root("first");
        let second = root("second");
        let adapter =
            type_flow_adapter(Language::Python).expect("Python registers a type-flow adapter");
        let mut field_budget = SemanticBudget::default();
        let field_slots =
            FieldSlotIndex::build(&workspace, adapter, &mut field_budget, &cancellation)
                .expect("fixture field slots build");
        let provider = WorkspaceValueFlowProvider::new(&workspace, ValueFlowCache::default());
        let build = |root: &ProcedureHandle, refinements: &mut ProcedureRefinements| {
            let mut budget = SemanticBudget::default();
            TypeFlowPlan::build(
                &workspace,
                adapter,
                &field_slots,
                root,
                &provider,
                ClosureLimits { max_procedures: 16 },
                &mut budget,
                &cancellation,
                refinements,
            )
            .unwrap_or_else(|error| panic!("plan for {root:?} builds: {error}"))
        };

        let mut shared = ProcedureRefinements::default();
        let shared_first = build(&first, &mut shared);
        let after_first = (
            shared.bindings.len(),
            shared.correlations.len(),
            shared.closed_loads.len(),
        );
        let shared_second = build(&second, &mut shared);
        let after_second = (
            shared.bindings.len(),
            shared.correlations.len(),
            shared.closed_loads.len(),
        );
        assert!(
            after_first.0 >= 2,
            "first root reaches shared: {after_first:?}"
        );
        assert_eq!(
            after_second,
            (after_first.0 + 1, after_first.1 + 1, after_first.2 + 1),
            "the second root adds only itself; the shared closure is reused"
        );

        assert_eq!(
            shared_first,
            build(&first, &mut ProcedureRefinements::default()),
            "request reuse does not change the first root plan"
        );
        assert_eq!(
            shared_second,
            build(&second, &mut ProcedureRefinements::default()),
            "request reuse does not change the second root plan"
        );
    }

    /// #3430: a guard seeds an admitted narrowing source only when an input
    /// reaching it independently admits the proven class, so the root a guard
    /// is reached from decides how many sources its site seeds. Under the
    /// per-site counter, that renumbered every later source at the site, and a
    /// summary persisted under one root then named the wrong live source under
    /// the other, or none. A guard source's key must state what the source is.
    #[test]
    #[hardwon(
        "#3430+#3430: #3430: guard source identity must follow source content across discovery-order changes"
    )]
    fn guard_sources_key_by_content_not_by_seeding_position() {
        use crate::analyzer::semantic::{SemanticRequest, type_flow_adapter};
        use crate::analyzer::{AnalyzerConfig, Language};
        use crate::inline_project::InlineTestProject;
        use crate::value_flow::ValueFlowCache;

        let project = InlineTestProject::with_language(Language::Python)
            .file(
                "app.py",
                "class Tag:\n    def label(self):\n        return \"tag\"\n\ndef get_logger(module, name=None):\n    logger_fqn = module\n    if name is not None:\n        if isinstance(name, Tag):\n            name = name.label()\n        logger_fqn += \".\" + name\n    return logger_fqn\n\nclass Middleware:\n    def __init__(self, worker):\n        self.logger = get_logger(\"m\", type(self))\n        self.worker = worker\n\nclass Worker:\n    def start(self):\n        return Middleware(self)\n\ndef worker_process(broker):\n    worker = Worker()\n    return worker.start()\n"
            )
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let cancellation = CancellationToken::default();
        let mut materialization_budget = SemanticBudget::default();
        let artifact = workspace
            .materialize_program_semantics(
                &project.file("app.py"),
                &mut SemanticRequest::new(&mut materialization_budget, &cancellation),
            )
            .expect("fixture semantics materialize")
            .available_value()
            .cloned()
            .expect("fixture semantics remain available");
        let root = |name: &str| {
            artifact
                .procedures()
                .iter()
                .find(|procedure| {
                    procedure
                        .locator()
                        .declaration()
                        .segments()
                        .last()
                        .and_then(|segment| segment.name())
                        == Some(name)
                })
                .and_then(|procedure| artifact.procedure_handle(procedure.id()))
                .unwrap_or_else(|| panic!("fixture declares {name}"))
        };
        let guarded = root("get_logger");
        let adapter =
            type_flow_adapter(Language::Python).expect("Python registers a type-flow adapter");
        let mut field_budget = SemanticBudget::default();
        let field_slots =
            FieldSlotIndex::build(&workspace, adapter, &mut field_budget, &cancellation)
                .expect("fixture field slots build");
        let provider = WorkspaceValueFlowProvider::new(&workspace, ValueFlowCache::default());
        let build = |root: &ProcedureHandle| {
            let mut budget = SemanticBudget::default();
            TypeFlowPlan::build(
                &workspace,
                adapter,
                &field_slots,
                root,
                &provider,
                ClosureLimits { max_procedures: 16 },
                &mut budget,
                &cancellation,
                &mut ProcedureRefinements::default(),
            )
            .unwrap_or_else(|error| panic!("plan for {root:?} builds: {error}"))
        };
        // Every guard source the guarded procedure seeds, by what it states.
        let guard_sources = |plan: &TypeFlowPlan| {
            plan.value_flow()
                .sources()
                .filter(|(_, spec)| *spec.point().procedure() == guarded)
                .filter(|(source, _)| {
                    matches!(
                        plan.source_site(*source).kind,
                        SourceSiteKind::NarrowingGuard | SourceSiteKind::ConditionalNarrowingGuard
                    )
                })
                .map(|(source, spec)| {
                    (
                        plan.source_site(source).kind,
                        format!("{:?}", plan.atom(source)),
                        spec.key().clone(),
                    )
                })
                .collect::<Vec<_>>()
        };

        let from_guarded = guard_sources(&build(&guarded));
        let from_chain = guard_sources(&build(&root("worker_process")));
        assert!(
            from_guarded.len() >= 2,
            "the guard site seeds an admitted source beside its remainder: {from_guarded:?}"
        );
        assert_eq!(
            from_guarded, from_chain,
            "one guard source keeps one key whichever root reaches its site"
        );
        // The property the keys must have: each states what its source is, so
        // a plan that seeds one fewer source here leaves the others' keys
        // alone. Under the per-plan counter these were 0 and 1, and dropping
        // the admitted source moved every later source's key onto its sibling.
        for (kind, atom, key) in &from_guarded {
            assert_ne!(
                key.ordinal() & CONTENT_KEYED_ORDINAL_BIT,
                0,
                "a guard source states its own identity, not its position: {kind:?} {atom}"
            );
        }
        let mut ordinals = from_guarded
            .iter()
            .map(|(.., key)| key.ordinal())
            .collect::<Vec<_>>();
        ordinals.sort_unstable();
        ordinals.dedup();
        assert_eq!(
            ordinals.len(),
            from_guarded.len(),
            "sources that state different things keep different keys: {from_guarded:?}"
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
        SemanticInputStatus::ExceededBudget {
            exceeded: crate::test_support::procedure_budget_error(1, 2),
        }
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
    #[hardwon(
        "8e24853a0915: exhaustive receiver dispatch must retain unsupported callee return alternatives"
    )]
    fn exhaustive_dispatch_does_not_prove_unsupported_callee_returns_complete() {
        use crate::analyzer::semantic::SemanticRequest;
        use crate::analyzer::{AnalyzerConfig, Language};
        use crate::inline_project::InlineTestProject;

        let project = InlineTestProject::with_language(Language::Python)
            .file(
                "app.py",
                "def incomplete():\n    class Local:\n        pass\n    return []\ndef comprehension():\n    return [x for x in ()]\ndef complete():\n    return []\n",
            )
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let artifact = workspace
            .materialize_program_semantics(
                &project.file("app.py"),
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("source semantics materialize")
            .available_value()
            .cloned()
            .expect("source semantics are available");
        for (name, expected) in [
            ("incomplete", Some(UnknownReason::IncompleteRoot)),
            ("comprehension", None),
            ("complete", None),
        ] {
            let callee = artifact
                .procedures()
                .iter()
                .find(|procedure| {
                    procedure
                        .locator()
                        .declaration()
                        .segments()
                        .last()
                        .and_then(|segment| segment.name())
                        == Some(name)
                })
                .and_then(|procedure| artifact.procedure_handle(procedure.id()))
                .expect("source declares the callee");
            let mut call = coverage(
                DispatchStatus::Resolved {
                    status: SemanticInputStatus::Complete,
                    coverage: crate::analyzer::semantic::CandidateCoverage::Exhaustive,
                },
                Vec::new(),
            );
            call.entered.push(callee);
            assert_eq!(uncovered_reason(Some(&call)), expected, "{name}");
        }
    }
}
