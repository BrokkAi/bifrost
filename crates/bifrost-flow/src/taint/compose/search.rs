//! Stage 1 of the composition: a backward search from every bound sink over
//! the port graph, finding the bound sources that can reach it.
//!
//! The search is a tabulation over path items. A path item says that a value
//! at `node` of `procedure` reaches `root`, where the root is either a bound
//! sink or an output port of the item's procedure. A callee is entered from a
//! call result by opening a root at the callee's return port; what reaches
//! that root (the callee's formals and sources) is mapped back through the
//! one call that opened it, so a value passed in by one caller never returns
//! to another. Only sink roots and capture-binding roots leave a procedure
//! through its callers.
//!
//! Items are keyed by their root, node and the label function of the path
//! from the node to the root, so that two paths with different sanitizers,
//! transforms or models are both retained; labels themselves are evaluated
//! in stage 2. A sanitizer never deletes a hop here.
//!
//! Each item and reach keeps the best proof and the best completeness of its
//! paths, axis by axis. The work list is explicit and every derivation names
//! items that existed before it, or, for the derivation that first gave an
//! axis, items that had that axis before it, so reconstruction of a path is
//! iterative and terminates.

mod refinement;

use super::inputs::{adopt_interior_clone, interior_clone_bytes};
use crate::analyzer::store::cache_budget::RetainedHeap;
use std::sync::{Arc, OnceLock};

use crate::analyzer::semantic::cfg_algorithms::{
    CfgAlgorithmBudget, CfgAlgorithmError, CfgAlgorithmRequest, reverse_reachability,
};
use crate::analyzer::semantic::icfg::invoked_call_at;
use crate::analyzer::semantic::partial_flow::ports::heap_ports_overlap;
use crate::analyzer::semantic::partial_flow::{
    CrossedCalls, HeapSelector, PartialFlowOutcome, PartialFlowPort, ProcedurePartialFlows,
    call_input_value, heap_selectors,
};
use crate::analyzer::semantic::{
    AbstractLocation, AccessPathRoot, AccessPathTail, BindingOriginIndex, CallSiteId,
    CallStorageSharing, ControlContinuation, EvidenceCompleteness, ProcedureHandle,
    ProgramPointHandle, ProgramPointId, ProofStatus, SemanticCallSite, SemanticRequest, ValueId,
};
use crate::dataflow::{SemanticInputStatus, UnmodeledCallBehavior};
use crate::hash::{HashMap, HashSet};
use crate::value_flow::{
    DurableCallSiteKey, DurableProcedureKey, ValueFlowCarrier, ValueFlowObservationPhase,
    ValueFlowPlan, ValueFlowSinkId,
};

use super::graph::{ComposedSourceId, Endpoint, ExecutionTarget, Hop, HopQuality, ObjectAnchor};
use super::labels::{ComposeLabels, LabelFunctionId, LabelFunctions};
use super::provider::{
    BlockedGap, BoundSanitizer, BoundSource, BoundTransform, CallModel, CallerLocation,
    Completeness, CompositionProvider, DispatchCandidate, EndpointEvidence, ExecutionArmContext,
    ExecutionCertificate, ExecutionCertificateStep, ExecutionEndpointStatus, ExecutionSource,
    InteriorObservation, InteriorSeed, InteriorTarget, Openness, StoreChannelLink,
    StoreWriteObservation,
};
use super::provider::{ModelOutputRefusal, bound_return_member_matches, projected_model_actual};
use super::{ComposeError, CompositionBudget};

// Keep the CFG algorithm's typed stop when its ordering proof is unavailable.
// The same cause controls reporting and whether the answer can be reused.
fn reader_ordering_failure<Node>(
    error: CfgAlgorithmError<Node>,
) -> (super::IncompleteCause, &'static str) {
    use super::{IncompleteCause, OperationalCause};
    let (cause, reason) = match error {
        CfgAlgorithmError::InvalidNode(_) => (
            OperationalCause::Provider,
            "reader ordering cannot be proven: invalid node",
        ),
        CfgAlgorithmError::Cancelled { .. } => (
            OperationalCause::Cancelled,
            "reader ordering cannot be proven: cancelled",
        ),
        CfgAlgorithmError::ExceededBudget(_) => (
            OperationalCause::Budget(BudgetLane::Semantic),
            "reader ordering cannot be proven: budget exceeded",
        ),
    };
    (IncompleteCause::Operational(cause), reason)
}

/// A source that reaches a sink, with one path per distinct label function.
/// Each path comes with the best quality of the paths that share its label
/// function; the path itself is one of them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceSinkPair {
    pub source: ComposedSourceId,
    pub sink: ValueFlowSinkId,
    pub certificate: Option<ExecutionCertificate>,
    pub paths: Vec<(Vec<Hop>, HopQuality)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionReach {
    pub root: DurableProcedureKey,
    pub target: ExecutionReachTarget,
    pub function: LabelFunctionId,
    pub quality: HopQuality,
    pub hops: Vec<Hop>,
    pub incoming: Option<ExecutionArmContext>,
    pub certificate: ExecutionCertificate,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ExecutionReachTarget {
    Source(usize),
    Procedure(Box<DurableProcedureKey>),
}

#[derive(Debug, Clone)]
pub struct ExecutionOutcome<L: ComposeLabels> {
    pub sources: Vec<ExecutionSource<L::Fact>>,
    pub reaches: Vec<ExecutionReach>,
    pub procedure_reaches: Vec<ExecutionReach>,
    pub functions: LabelFunctions<L>,
    pub incomplete: Vec<Incompleteness>,
    pub stats: SearchStats,
}

#[derive(Debug, Clone)]
pub struct ObjectReach<Fact> {
    pub root: ObjectAnchor,
    pub source: ExecutionSource<Fact>,
    pub function: LabelFunctionId,
    pub quality: HopQuality,
    pub hops: Vec<Hop>,
}

/// A budget lane of [`CompositionBudget`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum BudgetLane {
    Procedures,
    Hops,
    CallersPerProcedure,
    Semantic,
}

/// Why the composed result may miss a flow.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Incompleteness {
    ExecutionRoots {
        reason: Box<str>,
        cause: super::IncompleteCause,
    },
    Execution {
        procedure: DurableProcedureKey,
        reason: Box<str>,
        cause: super::IncompleteCause,
    },
    /// A dispatch on the frontier was open, unproven or exceeded.
    Dispatch {
        call: DurableCallSiteKey,
        reason: Box<str>,
        cause: super::IncompleteCause,
    },
    /// A model's override closure covers a call, but an accepted path uses
    /// receiver or argument storage whose concrete implementation is unknown.
    ModelOutputStorage {
        call: DurableCallSiteKey,
        source_call: Option<DurableCallSiteKey>,
    },
    /// An incoming-call enumeration was truncated or incomplete.
    Callers {
        procedure: DurableProcedureKey,
        reason: Box<str>,
        cause: super::IncompleteCause,
    },
    /// A model replaced a call but is not complete.
    Model {
        call: DurableCallSiteKey,
        reason: Box<str>,
        cause: super::IncompleteCause,
    },
    /// A selected partial summary contributes its stated edges while all
    /// unspecified effects of this exact call remain unknown.
    UnknownSummaryEffects {
        call: DurableCallSiteKey,
        summary: Box<crate::dataflow::ProcedureSummaryKey>,
        target: crate::analyzer::semantic::DispatchBoundaryKind,
    },
    /// An interior run was not complete.
    Interior {
        procedure: DurableProcedureKey,
        reason: Box<str>,
        cause: super::IncompleteCause,
    },
    /// A procedure's partial flows were not projected completely.
    PartialFlows {
        procedure: DurableProcedureKey,
        outcome: PartialFlowOutcome,
    },
    /// A visited procedure keeps a gap the workspace cannot discharge.
    /// `residual` lists the calls whose incomplete dispatch keeps it open;
    /// `blocked` is the first gap no dispatch answers; `status` is the
    /// procedure's snapshot input status.
    Open {
        procedure: DurableProcedureKey,
        residual: Box<[DurableCallSiteKey]>,
        residual_causes: Box<[super::IncompleteCause]>,
        relation_cause: Option<super::IncompleteCause>,
        cause: super::IncompleteCause,
        blocked: Option<BlockedGap>,
        status: SemanticInputStatus,
        reason: Box<str>,
    },
    /// A capture slot whose closure has no lexical parent with a matching
    /// capture binding.
    MissingCaptureBinding {
        procedure: DurableProcedureKey,
        slot: PartialFlowPort,
    },
    /// A sanitizer or transform whose carriers are not ports of one call.
    UnplacedTransfer {
        procedure: DurableProcedureKey,
        carrier: ValueFlowCarrier,
    },
    /// The provider's match of policy endpoints in a procedure may have
    /// missed one.
    Endpoints {
        procedure: DurableProcedureKey,
        reason: Box<str>,
        cause: super::IncompleteCause,
    },
    /// The selected write inventory for a demanded store read was incomplete.
    StoreInventory {
        procedure: DurableProcedureKey,
        reason: Box<str>,
        cause: super::IncompleteCause,
    },
    /// A source, of the plan or matched on the frontier, at `point` whose
    /// selector evidence is not proven and complete, as the ICFG engine's
    /// plan reports it.
    SourceEvidence {
        point: ProgramPointHandle,
        cause: super::IncompleteCause,
    },
    /// A bound sink of the plan at `point` whose selector evidence is not
    /// proven and complete.
    SinkEvidence {
        point: ProgramPointHandle,
        cause: super::IncompleteCause,
    },
    /// A budget lane was exhausted.
    Budget(BudgetLane),
    /// The request was cancelled.
    Cancelled,
    Object {
        anchor: Box<ObjectAnchor>,
        reason: Box<str>,
        cause: super::IncompleteCause,
    },
}

impl Incompleteness {
    pub fn cause(&self) -> super::IncompleteCause {
        use super::{IncompleteCause as Cause, OperationalCause as Operational};
        match self {
            Self::Dispatch { cause, .. }
            | Self::Open { cause, .. }
            | Self::ExecutionRoots { cause, .. }
            | Self::Execution { cause, .. }
            | Self::Callers { cause, .. }
            | Self::Model { cause, .. }
            | Self::Interior { cause, .. }
            | Self::Endpoints { cause, .. }
            | Self::StoreInventory { cause, .. }
            | Self::SourceEvidence { cause, .. }
            | Self::SinkEvidence { cause, .. }
            | Self::Object { cause, .. } => *cause,
            Self::Budget(lane) => Cause::Operational(Operational::Budget(*lane)),
            Self::Cancelled => Cause::Operational(Operational::Cancelled),
            Self::PartialFlows { outcome, .. } => match outcome {
                PartialFlowOutcome::ExceededBudget | PartialFlowOutcome::Truncated => {
                    Cause::Operational(Operational::Budget(BudgetLane::Semantic))
                }
                PartialFlowOutcome::Error => Cause::Operational(Operational::Provider),
                PartialFlowOutcome::Complete => {
                    unreachable!("complete partial flows do not emit incompleteness")
                }
            },
            // The selected summary's authored content leaves these effects
            // unknown; no budget or provider stop produced them.
            Self::ModelOutputStorage { .. }
            | Self::UnknownSummaryEffects { .. }
            | Self::MissingCaptureBinding { .. }
            | Self::UnplacedTransfer { .. } => Cause::Content,
        }
    }
}

/// The result of stage 1.
#[derive(Debug, Clone)]
pub struct SearchOutcome<L: ComposeLabels> {
    pub effective_budget: CompositionBudget,
    pub object_reaches: Vec<ObjectReach<L::Fact>>,
    pub execution_sources: Vec<ExecutionSource<L::Fact>>,
    pub execution_reaches: Vec<ExecutionReach>,
    pub execution_procedure_reaches: Vec<ExecutionReach>,
    pub pairs: Vec<SourceSinkPair>,
    pub strict_pairs: Vec<SourceSinkPair>,
    /// The source table the pairs index: the plan's sources, then those the
    /// provider matched on the frontier.
    pub sources: Vec<BoundSource<L::Fact>>,
    /// The label functions the pairs' hops name.
    pub functions: LabelFunctions<L>,
    /// Whether every sanitizer of the plan and every sanitizer the provider
    /// matched on the frontier is resolved.
    pub sanitizers_resolved: bool,
    /// Distinct reasons, in the order they were found.
    pub incomplete: Vec<Incompleteness>,
    /// Distinct calls a require-model policy abstained at, in the order they
    /// were found.
    pub abstained: Vec<DurableCallSiteKey>,
    pub stats: SearchStats,
    pub barrier_notes: Vec<super::ValueTypeBarrierFindingNotes>,
    /// The model each dispatched call returned, for the report's reads of
    /// the calls on reported paths.
    pub call_models: HashMap<DurableCallSiteKey, Option<Arc<CallModel<L::Function>>>>,
}

/// What stage 1 did, for the run's timing notes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SearchStats {
    /// Procedures whose flows the search read.
    pub procedures: usize,
    /// Path items and reaches the search created.
    pub hops: usize,
    /// Call dispatches the frontier resolved.
    pub dispatches: usize,
    /// Incoming calls enumerated, summed over the procedures asked.
    pub callers: usize,
    pub recorded_supports: usize,
    pub recorded_edges: usize,
    pub chop_procedures: usize,
    pub extra_proof_lookups: usize,
    pub changed_edge_qualities: usize,
    pub baseline_candidate_pairs: usize,
    pub strict_replays: usize,
}

/// What a set of path items reaches: a bound sink, or an output port of one
/// procedure.
/// What one composition asks, in the client's labels: the value-flow plan
/// whose points and carriers the endpoints name, the bound sinks in order
/// with what each accepts, and the client's own sources, sanitizers and
/// in-place transforms. The provider adds the endpoints it matches on the
/// frontier.
pub(super) struct ComposeQuery<'a, L: ComposeLabels> {
    pub(super) execution_roots: Vec<DurableProcedureKey>,
    pub(super) object_roots: Vec<ObjectAnchor>,
    pub(super) certified_procedure_reaches: Option<Vec<ExecutionReach>>,
    pub(super) value_flow: Option<&'a ValueFlowPlan>,
    pub(super) labels: L,
    pub(super) sinks: Vec<(ValueFlowSinkId, L::Fact)>,
    pub(super) sources: Vec<BoundSource<L::Fact>>,
    pub(super) sanitizers: Vec<BoundSanitizer<L::Function>>,
    pub(super) transforms: Vec<InPlaceTransform<L::Function>>,
}

/// A transform applied in place on the paths through its call, as opposed to
/// a matched [`BoundTransform`], which is a flow of its own.
pub struct InPlaceTransform<Function> {
    pub point: ProgramPointHandle,
    pub carrier: ValueFlowCarrier,
    pub function: Function,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Root {
    Execution(Box<DurableProcedureKey>),
    Object(Box<ObjectAnchor>),
    Sink(ValueFlowSinkId, Option<ExecutionCertificate>),
    Port(
        Box<(DurableProcedureKey, PartialFlowPort)>,
        Option<ExecutionCertificate>,
    ),
    StoreWrite(usize),
}

impl Root {
    /// A root whose demand is not tied to one call: reaching a formal leaves
    /// the procedure through every caller.
    fn unbalanced(&self) -> bool {
        match self {
            Self::Execution(_) => false,
            Self::Object(_) => false,
            Self::Sink(..) => true,
            Self::Port(port, _) => matches!(port.1, PartialFlowPort::CaptureOut { .. }),
            Self::StoreWrite(_) => true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ItemKey {
    procedure: DurableProcedureKey,
    root: Root,
    node: Endpoint,
    /// Label function of the path from `node` to `root`.
    function: LabelFunctionId,
    execution_arm: Option<ExecutionArmContext>,
    certificate: Option<ExecutionCertificate>,
}

/// How an item was derived. Every index names an item or reach that existed
/// before this derivation.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Derivation {
    /// The root's own node.
    Root,
    /// `hops`, then the path of item `next`.
    Step { hops: Vec<Hop>, next: usize },
    /// A callee summary applied at a call.
    Summary(Box<SummaryStep>),
}

/// Into a callee through `caller`, the callee path of item `inner`, out
/// through `callee` and `annotations`, then the path of item `next`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SummaryStep {
    caller: Hop,
    inner: usize,
    callee: Hop,
    annotations: Vec<Hop>,
    next: usize,
}

/// One path item. `quality` is the best, axis by axis, over the paths from
/// the node to the root found so far.
#[derive(Debug)]
struct Item {
    key: ItemKey,
    quality: HopQuality,
    derivations: Derivations<Derivation>,
    alternatives: Vec<Derivation>,
    active: bool,
    root_quality: HopQuality,
}

/// The derivations an item or reach keeps: its first, and the first that gave
/// it each quality axis. The items an axis's derivation names had that axis
/// before it, so following one axis's derivations never returns to where it
/// started, and the path they rebuild has that axis.
#[derive(Debug)]
struct Derivations<D> {
    first: D,
    proven: Option<D>,
    complete: Option<D>,
    certain: Option<D>,
}

/// Which derivations a path reconstruction follows.
#[derive(Debug, Clone, Copy)]
enum Chain {
    First,
    Proven,
    Complete,
    Certain,
}

impl<D: Clone> Derivations<D> {
    fn new(quality: HopQuality, derivation: D) -> Self {
        Self {
            proven: quality.proven.then(|| derivation.clone()),
            complete: quality.complete.then(|| derivation.clone()),
            certain: quality.is_certain().then(|| derivation.clone()),
            first: derivation,
        }
    }

    /// Record a derivation of `quality` for a holder whose quality is `held`.
    /// Returns whether it gave the holder an axis it lacked.
    fn improve(&mut self, held: HopQuality, quality: HopQuality, derivation: D) -> bool {
        let proven = quality.proven && !held.proven;
        let complete = quality.complete && !held.complete;
        let certain = quality.is_certain() && !held.is_certain();
        if proven {
            self.proven = Some(derivation.clone());
        }
        if complete {
            self.complete = Some(derivation.clone());
        }
        if certain {
            self.certain = Some(derivation);
        }
        proven || complete || certain
    }

    fn get(&self, chain: Chain) -> &D {
        match chain {
            Chain::First => &self.first,
            Chain::Certain => self
                .certain
                .as_ref()
                .expect("a certain path's items are certain"),
            Chain::Proven => self
                .proven
                .as_ref()
                .expect("a proven path's items are proven"),
            Chain::Complete => self
                .complete
                .as_ref()
                .expect("a complete path's items are complete"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ReachKey {
    root: Root,
    source: ComposedSourceId,
    store_origin: Option<crate::taint::SourceEventKey>,
    /// Label function of the path from the source to the root.
    function: LabelFunctionId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ReachDerivation {
    /// `hops` from the source, then the path of item `next`.
    Direct { hops: Vec<Hop>, next: usize },
    /// The path of reach `inner`, then `hops`, then the path of item `next`.
    Through {
        inner: usize,
        hops: Vec<Hop>,
        next: usize,
    },
}

#[derive(Debug)]
struct Reach {
    key: ReachKey,
    quality: HopQuality,
    derivations: Derivations<ReachDerivation>,
    alternatives: Vec<ReachDerivation>,
    active: bool,
}

/// A caller-side item waiting on a callee root opened from a call.
#[derive(Debug, Clone)]
struct CallWaiter {
    item: usize,
    call: DurableCallSiteKey,
    candidate: Arc<DispatchCandidate>,
    callee_port: PartialFlowPort,
    uncertain: bool,
}

/// A closure-side item waiting on its parent's capture-binding root.
#[derive(Debug, Clone)]
struct CaptureWaiter {
    item: usize,
    hop: Hop,
}

#[derive(Debug, Clone)]
struct StoreWaiter {
    item: usize,
    link: StoreChannelLink,
}

/// One flow into a position of a procedure: where it starts, whether its
/// relations are uncertain, and the calls its path classes crossed.
#[derive(Debug, Clone)]
pub struct Inflow<From> {
    pub from: From,
    pub function: LabelFunctionId,
    pub uncertain: bool,
    pub crossed: CrossedCalls,
}

#[derive(Debug, Clone)]
pub struct ProjectedProcedureInput {
    pub function: LabelFunctionId,
    pub flows: Arc<ProcedurePartialFlows>,
}

#[derive(Debug)]
pub struct ProcedureEndpointInputs<Function> {
    pub sources: std::ops::Range<usize>,
    pub sanitizers: Vec<BoundSanitizer<Function>>,
    pub transforms: Vec<BoundTransform<Function>>,
    pub completeness: Completeness,
    pub causes: Vec<super::IncompleteCause>,
}

#[derive(Debug)]
pub struct ProcedureData<Function> {
    pub flows: Arc<ProcedurePartialFlows>,
    pub projections: Option<Box<[Option<ProjectedProcedureInput>]>>,
    pub endpoints: OnceLock<ProcedureEndpointInputs<Function>>,
    into: HashMap<PartialFlowPort, Vec<Inflow<PartialFlowPort>>>,
}

#[derive(Debug, Clone)]
pub struct InteriorPartitionInput {
    pub function: LabelFunctionId,
    pub flows: super::provider::InteriorFlows,
}

#[derive(Debug)]
pub enum InteriorObservations {
    Many(Vec<InteriorObservation>),
    One([InteriorObservation; 1]),
    Empty,
}
impl InteriorObservations {
    pub fn as_slice(&self) -> &[InteriorObservation] {
        match self {
            Self::Many(rows) => rows,
            Self::One(row) => row,
            Self::Empty => &[],
        }
    }
}

#[derive(Debug)]
pub struct InteriorInput {
    pub seeds: Vec<InteriorSeed>,
    pub seed_ends: Vec<Endpoint>,
    pub observations: InteriorObservations,
    pub partitions: Box<[Option<InteriorPartitionInput>]>,
}

type InteriorRun = (
    Vec<(LabelFunctionId, super::provider::InteriorFlow)>,
    Option<InteriorInput>,
);

#[derive(Debug)]
pub struct CallerInput {
    pub answer: super::provider::Callers,
    pub retained_len: usize,
    pub clipped: bool,
}

impl std::ops::Deref for CallerInput {
    type Target = [DurableCallSiteKey];
    fn deref(&self) -> &Self::Target {
        &self.answer.calls[..self.retained_len]
    }
}

type Reaching = Arc<[Inflow<Endpoint>]>;

#[derive(Debug, Default)]
pub struct InteriorIndex {
    pub input: Option<InteriorInput>,
    into: HashMap<Endpoint, Vec<Inflow<Endpoint>>>,
}

#[derive(Debug)]
pub struct LocationInteriorInput {
    pub input: Option<InteriorInput>,
    reaching: Option<Reaching>,
}

#[derive(Debug)]
pub struct DispatchAnswer {
    pub candidates: Vec<Arc<DispatchCandidate>>,
    pub uncertain: bool,
    pub incomplete_reason: Option<Box<str>>,
    pub incomplete_cause: Option<super::IncompleteCause>,
    pub external_body_unavailable: Option<super::provider::ExternalBodyUnavailableGap>,
    /// The best quality of the call's own continuation edges.
    pub continuation: HopQuality,
}

/// A sanitizer or transform placed on the ports of one call. `None` matches
/// any input or output.
#[derive(Debug, Clone)]
pub struct Annotation {
    pub input: Option<PartialFlowPort>,
    pub output: Option<PartialFlowPort>,
    pub hop: Hop,
}

/// A matched transform: its own flow from a call input to a call output.
#[derive(Debug, Clone)]
pub struct Link {
    pub input: PartialFlowPort,
    pub output: PartialFlowPort,
    pub hop: Hop,
}

#[derive(Debug, Clone, Copy)]
enum Work {
    Item(usize),
    Reach(usize),
}

fn capture_completeness(
    heap: &mut RetainedHeap,
    completeness: &Completeness,
) -> Option<Completeness> {
    match completeness {
        Completeness::Complete => (!heap.is_refused()).then_some(Completeness::Complete),
        Completeness::Incomplete { cause, reason } => {
            if !heap.reserve_scratch(reason.len()) {
                return None;
            }
            let copied = reason.clone();
            if !copied.is_empty() {
                heap.adopt_allocation(copied.as_ptr() as usize, copied.len(), copied.len());
            }
            if heap.is_refused() {
                let bytes = copied.len();
                drop(copied);
                heap.release_scratch(bytes);
                None
            } else {
                Some(Completeness::Incomplete {
                    cause: *cause,
                    reason: copied,
                })
            }
        }
    }
}

fn capture_slots<T: Clone>(
    heap: &mut RetainedHeap,
    len: usize,
    nested_bytes: usize,
) -> Option<(Box<[Option<T>]>, usize)> {
    let Some(bytes) = len
        .checked_mul(std::mem::size_of::<Option<T>>())
        .and_then(|bytes| bytes.checked_add(nested_bytes))
    else {
        heap.refuse();
        return None;
    };
    if !heap.reserve_scratch(bytes) {
        return None;
    }
    // Exact one-shot storage: no growth or replacement while a registered owner lives.
    let mut slots = Box::<[Option<T>]>::new_uninit_slice(len);
    for slot in &mut slots {
        slot.write(None);
    }
    // SAFETY: every slot was initialized to None above.
    let slots = unsafe { slots.assume_init() };
    Some((slots, bytes))
}

fn finish_capture<T>(
    heap: &mut RetainedHeap,
    slots: Box<[Option<T>]>,
    bytes: usize,
) -> Option<Box<[Option<T>]>> {
    if bytes == 0 {
        return Some(slots);
    }
    let root_bytes = std::mem::size_of_val(slots.as_ref());
    if !heap.is_refused() {
        // Nested clones have already transferred each actual allocation. Any
        // unused Vec-capacity allowance belongs to this grant and is refunded.
        heap.adopt_allocation(slots.as_ptr() as usize, root_bytes, bytes);
    }
    if heap.is_refused() {
        drop(slots);
        heap.release_scratch(bytes);
        None
    } else {
        Some(slots)
    }
}

#[derive(Debug)]
pub struct SearchInputs<Fact, Function> {
    pub execution_roots: Vec<DurableProcedureKey>,
    pub object_roots: Vec<ObjectAnchor>,
    pub endpoint_projections: bool,
    pub accepted: HashMap<ValueFlowSinkId, Fact>,
    pub sources: Vec<BoundSource<Fact>>,
    pub sources_in: HashMap<DurableProcedureKey, Vec<ComposedSourceId>>,
    pub sinks_in: HashMap<DurableProcedureKey, Vec<ValueFlowSinkId>>,
    pub annotations: HashMap<DurableCallSiteKey, Vec<Annotation>>,
    pub links: HashMap<DurableCallSiteKey, Vec<Link>>,
    pub sanitizers_resolved: bool,
    pub procedures: HashMap<DurableProcedureKey, Option<Arc<ProcedureData<Function>>>>,
    pub interiors: HashMap<DurableProcedureKey, Option<Arc<InteriorIndex>>>,
    pub location_interiors: HashMap<(DurableProcedureKey, CallerLocation), LocationInteriorInput>,
    pub modeled_reader_origins:
        HashMap<(DurableProcedureKey, CallerLocation), Vec<AbstractLocation>>,
    pub handles: HashMap<DurableProcedureKey, ProcedureHandleInput>,
    pub dispatches: HashMap<DurableCallSiteKey, Arc<DispatchAnswer>>,
    pub dispatched_models: HashMap<DurableCallSiteKey, Option<Arc<CallModel<Function>>>>,
    pub models: HashMap<DurableCallSiteKey, Option<Arc<CallModel<Function>>>>,
    pub callers: HashMap<DurableProcedureKey, Arc<CallerInput>>,
    pub parents: HashMap<DurableProcedureKey, Option<DurableProcedureKey>>,
    pub store_writes: Vec<StoreWriteObservation>,
    pub store_writes_in: HashMap<DurableProcedureKey, Vec<usize>>,
}

#[derive(Debug)]
pub struct ProcedureHandleInput {
    pub procedure: ProcedureHandle,
    /// The original empty request used solely to acquire a live handle.
    pub acquisition: Option<InteriorInput>,
}

struct Search<'a, 'capture, Provider, L>
where
    Provider: CompositionProvider,
    L: ComposeLabels<Fact = Provider::Fact, Function = Provider::Function>,
{
    inputs: SearchInputs<L::Fact, L::Function>,
    capture: Option<&'capture mut RetainedHeap>,

    object_reaches: Vec<ObjectReach<L::Fact>>,
    certified_procedure_reaches: Option<Vec<ExecutionReach>>,
    value_flow: Option<&'a ValueFlowPlan>,
    provider: &'a Provider,
    budget: CompositionBudget,
    /// The label functions of every path key and hop of this search.
    functions: LabelFunctions<L>,
    /// Every source the search can reach: the query's, then those matched on
    /// the frontier.
    execution_sources: Vec<ExecutionSource<L::Fact>>,
    execution_source_ids: HashMap<(ExecutionTarget, Box<str>, Option<ExecutionArmContext>), usize>,
    execution_reaches: Vec<ExecutionReach>,
    execution_procedure_reaches: Vec<ExecutionReach>,
    execution_procedure_reach_ids: HashMap<(ExecutionCertificate, DurableProcedureKey), usize>,
    execution_reach_ids: HashMap<
        (
            DurableProcedureKey,
            usize,
            LabelFunctionId,
            Option<ExecutionArmContext>,
        ),
        usize,
    >,
    execution_visited: HashSet<DurableProcedureKey>,
    /// Procedures in the order their flows were read.
    visited: Vec<DurableProcedureKey>,
    /// Proven origins already read for component consumption. Reuse them for
    /// modeled-writer checks instead of asking for a second storage binding.
    modeled_reader_origin_count: usize,
    items: Vec<Item>,
    item_ids: HashMap<ItemKey, usize>,
    reaches: Vec<Reach>,
    reach_ids: HashMap<ReachKey, usize>,
    reaches_by_root: HashMap<Root, Vec<usize>>,
    /// Items at a formal of their root's own procedure, by root.
    summaries: HashMap<Root, Vec<usize>>,
    summary_items: HashSet<usize>,
    call_waiters: HashMap<Root, Vec<CallWaiter>>,
    registered_call_waiters: HashSet<(usize, Root)>,
    capture_waiters: HashMap<Root, Vec<CaptureWaiter>>,
    registered_capture_waiters: HashSet<(usize, Root)>,
    store_waiters: HashMap<Root, Vec<StoreWaiter>>,
    registered_store_waiters: HashSet<(usize, Root)>,
    work: Vec<Work>,
    incomplete: Vec<Incompleteness>,
    incomplete_seen: HashSet<Incompleteness>,
    abstained: Vec<DurableCallSiteKey>,
    abstained_seen: HashSet<DurableCallSiteKey>,
    stopped: bool,
    refined_pairs: Option<Vec<SourceSinkPair>>,
    strict_pairs: Vec<SourceSinkPair>,
    barrier_notes: Vec<super::ValueTypeBarrierFindingNotes>,
    recorded_supports: usize,
    recorded_edges: usize,
    chop_procedures: usize,
    refinement_chop: std::collections::HashSet<DurableProcedureKey>,
    extra_proof_lookups: usize,
    changed_edge_qualities: usize,
    baseline_candidate_pairs: usize,
    strict_replays: usize,
    changed_edges: HashSet<Hop>,
}

/// Run stage 1 over every bound sink of the query.
pub(super) fn search_pairs<'a, Provider, L>(
    query: ComposeQuery<'a, L>,
    provider: &'a Provider,
    budget: CompositionBudget,
    request: &mut SemanticRequest<'_>,
) -> Result<SearchOutcome<L>, ComposeError>
where
    Provider: CompositionProvider,
    L: ComposeLabels<Fact = Provider::Fact, Function = Provider::Function>,
{
    let (search, stats, refused) = run_search(query, provider, budget, request, None)?;
    Ok(finish_search(search, stats, refused).0)
}

pub(super) struct RetainedSearch<L: ComposeLabels> {
    pub outcome: SearchOutcome<L>,
    pub inputs: SearchInputs<L::Fact, L::Function>,
}

pub(super) fn search_pairs_retaining<'a, Provider, L>(
    query: ComposeQuery<'a, L>,
    provider: &'a Provider,
    budget: CompositionBudget,
    request: &mut SemanticRequest<'_>,
    capture: &mut RetainedHeap,
) -> Result<RetainedSearch<L>, ComposeError>
where
    Provider: CompositionProvider,
    L: ComposeLabels<Fact = Provider::Fact, Function = Provider::Function>,
{
    let (search, stats, refused) = run_search(query, provider, budget, request, Some(capture))?;
    let (outcome, inputs) = finish_search(search, stats, refused);
    Ok(RetainedSearch { outcome, inputs })
}

fn run_search<'a, 'capture, Provider, L>(
    query: ComposeQuery<'a, L>,
    provider: &'a Provider,
    budget: CompositionBudget,
    request: &mut SemanticRequest<'_>,
    capture: Option<&'capture mut RetainedHeap>,
) -> Result<(Search<'a, 'capture, Provider, L>, SearchStats, bool), ComposeError>
where
    Provider: CompositionProvider,
    L: ComposeLabels<Fact = Provider::Fact, Function = Provider::Function>,
{
    let value_flow = query.value_flow;
    let sinks = query
        .sinks
        .iter()
        .map(|(sink, _)| *sink)
        .collect::<Vec<_>>();
    let mut search = Search::new(query, provider, budget, capture);
    let acquisition = (|| -> Result<(), ComposeError> {
        for anchor in search.inputs.object_roots.clone() {
            search.add_item(
                anchor.procedure.clone(),
                Root::Object(Box::new(anchor.clone())),
                Endpoint::Object(Box::new(anchor)),
                LabelFunctionId::IDENTITY,
                HopQuality::CERTAIN,
                Derivation::Root,
            );
        }
        for procedure in search.inputs.execution_roots.clone() {
            search.add_item(
                procedure.clone(),
                Root::Execution(Box::new(procedure.clone())),
                Endpoint::Execution(Box::new(ExecutionTarget::Procedure(Box::new(procedure)))),
                LabelFunctionId::IDENTITY,
                HopQuality::CERTAIN,
                Derivation::Root,
            );
        }
        // Every bound endpoint must carry proven and complete selector evidence,
        // as the ICFG engine's plan requires of its endpoints, whether or not a
        // path reaches them. The plan's sources are noted as `Search::new` adds
        // them, and a source matched on the frontier as the search enters its
        // procedure.
        for sink in &sinks {
            let spec = value_flow
                .expect("a value sink has a value plan")
                .sink(*sink)
                .expect("a selected sink names a bound sink of the plan");
            if !evidence_quality(spec.proof(), spec.completeness()).is_certain() {
                search.note(Incompleteness::SinkEvidence {
                    cause: super::IncompleteCause::Operational(super::OperationalCause::Provider),
                    point: spec.point().clone(),
                });
            }
        }
        for sink in sinks {
            let spec = value_flow
                .expect("a value sink has a value plan")
                .sink(sink)
                .expect("a bound sink names a sink of its plan");
            let procedure = spec.point().procedure().durable_key();
            // The ICFG engine materializes a meeting on the edges that leave the
            // sink's point. At a call's point those are the call's own edges, and
            // their best quality is the call's continuation quality: a call with
            // an entered body or a replacing model also has the caller's proven
            // and complete continuation edge, which no call edge can improve on.
            let quality = match invoked_call_at(spec.point()).map_err(provider_error)? {
                Some(call) => {
                    search
                        .dispatch(&(procedure.clone(), call), request)?
                        .continuation
                }
                None => HopQuality::CERTAIN,
            }
            .conjoin(evidence_quality(spec.proof(), spec.completeness()));
            if spec
                .point()
                .procedure()
                .semantics()
                .lexical_parent()
                .is_some()
                && let Some(reaches) = &search.certified_procedure_reaches
            {
                let matching = reaches
                .iter()
                .filter(|reach| {
                    matches!(&reach.target, ExecutionReachTarget::Procedure(target) if target.as_ref() == &procedure)
                })
                .cloned()
                .collect::<Vec<_>>();
                if matching.is_empty() {
                    search.note(Incompleteness::Execution {
                        cause: super::IncompleteCause::Operational(
                            super::OperationalCause::Provider,
                        ),
                        procedure: procedure.clone(),
                        reason: "nested sink has no admitted invoked instance".into(),
                    });
                    search.add_item(
                        procedure,
                        Root::Sink(sink, None),
                        Endpoint::Sink(sink),
                        LabelFunctionId::IDENTITY,
                        quality.conjoin(HopQuality::UNCERTAIN),
                        Derivation::Root,
                    );
                } else {
                    // One invoked returned instance does not certify other calls
                    // of the same factory. Keep an open seed for each unmatched
                    // creation prefix so its source path cannot disappear.
                    let unmatched_factory = matching.iter().any(|invoked| {
                    let Some(instance) = invoked
                        .certificate
                        .prefix
                        .last()
                        .and_then(|step| step.instance.as_ref())
                    else {
                        return false;
                    };
                    reaches.iter().any(|producer| {
                        producer.certificate.root == invoked.certificate.root
                            && matches!(&producer.target, ExecutionReachTarget::Procedure(target) if target.as_ref() == &instance.producer)
                            && producer.certificate.prefix.last().is_some_and(|step| {
                                Some(&step.call) != instance.factory_call.as_ref()
                            })
                    })
                });
                    if unmatched_factory {
                        search.note(Incompleteness::Execution {
                            cause: super::IncompleteCause::Operational(
                                super::OperationalCause::Provider,
                            ),
                            procedure: procedure.clone(),
                            reason:
                                "factory has a creation prefix without this callable invocation"
                                    .into(),
                        });
                        search.add_item(
                            procedure.clone(),
                            Root::Sink(sink, None),
                            Endpoint::Sink(sink),
                            LabelFunctionId::IDENTITY,
                            quality.conjoin(HopQuality::UNCERTAIN),
                            Derivation::Root,
                        );
                    }
                    for reach in matching {
                        let certified = reach.certificate.prefix.last().is_some_and(|step| {
                            step.target == ExecutionTarget::Procedure(Box::new(procedure.clone()))
                                && step.instance.is_some()
                        }) || (reach.certificate.root == procedure
                            && reach.certificate.prefix.is_empty());
                        if !certified {
                            search.note(Incompleteness::Execution {
                                cause: super::IncompleteCause::Operational(
                                    super::OperationalCause::Provider,
                                ),
                                procedure: procedure.clone(),
                                reason: "nested sink instance has no exact creation certificate"
                                    .into(),
                            });
                        }
                        search.add_item(
                            procedure.clone(),
                            Root::Sink(sink, Some(reach.certificate)),
                            Endpoint::Sink(sink),
                            LabelFunctionId::IDENTITY,
                            quality.conjoin(if certified {
                                reach.quality
                            } else {
                                HopQuality::UNCERTAIN
                            }),
                            Derivation::Root,
                        );
                    }
                }
            } else {
                search.add_item(
                    procedure,
                    Root::Sink(sink, None),
                    Endpoint::Sink(sink),
                    LabelFunctionId::IDENTITY,
                    quality,
                    Derivation::Root,
                );
            }
        }
        let trace_search = std::env::var_os("BIFROST_TIMING").is_some();
        let mut traced_items = 0usize;
        let search_start = std::time::Instant::now();
        while let Some(work) = search.work.pop() {
            traced_items += 1;
            if trace_search && (traced_items == 1 || traced_items.is_multiple_of(100)) {
                eprintln!(
                    "[bifrost-timing] NOTE composition.search items={traced_items} queued={} retained={} elapsed={:?}",
                    search.work.len(),
                    search.items.len(),
                    search_start.elapsed()
                );
            }
            if search.stopped {
                break;
            }
            if request.cancellation.is_cancelled() {
                search.note(Incompleteness::Cancelled);
                break;
            }
            if request.stop_observed() {
                search.note(Incompleteness::Budget(BudgetLane::Semantic));
                break;
            }
            match work {
                Work::Item(item) => search.process_item(item, request)?,
                Work::Reach(reach) => search.process_reach(reach),
            }
            if request.cancellation.is_cancelled() {
                search.note(Incompleteness::Cancelled);
                break;
            }
            if request.stop_observed() {
                search.note(Incompleteness::Budget(BudgetLane::Semantic));
                break;
            }
            if trace_search && traced_items == 1 {
                eprintln!(
                    "[bifrost-timing] NOTE composition.search first_item_done elapsed={:?}",
                    search_start.elapsed()
                );
            }
        }
        if trace_search {
            eprintln!(
                "[bifrost-timing] NOTE composition.search complete items={traced_items} limits={budget:?} elapsed={:?}",
                search_start.elapsed()
            );
        }
        if !request.stop_observed() {
            for procedure in search.visited.clone() {
                if let Openness::Open {
                    residual,
                    residual_causes,
                    relation_cause,
                    cause,
                    blocked,
                    status,
                    reason,
                } = provider
                    .openness(&procedure, request)
                    .map_err(|error| classified_provider_error(provider, error))?
                {
                    search.note(Incompleteness::Open {
                        procedure,
                        residual,
                        residual_causes,
                        relation_cause,
                        cause,
                        blocked,
                        status,
                        reason,
                    });
                }
            }
        }
        // Refinement uses recorded derivations only. It cannot spend a fresh
        // topology budget or discover another source, edge or procedure.
        if !request.stop_observed() && provider.has_value_type_barriers() {
            search.refine(request)?;
        }
        if trace_search {
            eprintln!(
                "[bifrost-timing] NOTE composition.search reasons={:?} limits={budget:?}",
                search
                    .incomplete
                    .iter()
                    .map(|reason| (reason.cause(), reason))
                    .collect::<Vec<_>>()
            );
        }
        Ok(())
    })();
    let refused = match acquisition {
        Ok(()) => false,
        Err(ComposeError::AcquisitionRefused(refusal)) => {
            search.note(Incompleteness::ExecutionRoots {
                reason: refusal.to_string().into_boxed_str(),
                cause: super::IncompleteCause::Content,
            });
            true
        }
        Err(error) => {
            // Adopted cache owners drop on this error path; terminal refusal
            // prevents address reuse in another candidate's shared census.
            if let Some(heap) = search.capture.as_deref_mut() {
                heap.refuse();
            }
            return Err(error);
        }
    };
    let stats = SearchStats {
        recorded_supports: search.recorded_supports,
        recorded_edges: search.recorded_edges,
        chop_procedures: search.chop_procedures,
        extra_proof_lookups: search.extra_proof_lookups,
        changed_edge_qualities: search.changed_edge_qualities,
        baseline_candidate_pairs: search.baseline_candidate_pairs,
        strict_replays: search.strict_replays,
        procedures: search.visited.len() + search.execution_visited.len(),
        hops: search.items.len()
            + search.reaches.len()
            + search.execution_reaches.len()
            + search.object_reaches.len()
            + search.execution_procedure_reaches.len(),
        dispatches: search.inputs.dispatches.len(),
        callers: search
            .inputs
            .callers
            .values()
            .map(|calls| calls.len())
            .sum(),
    };
    Ok((search, stats, refused))
}

fn finish_search<Provider, L>(
    mut search: Search<'_, '_, Provider, L>,
    stats: SearchStats,
    refused: bool,
) -> (SearchOutcome<L>, SearchInputs<L::Fact, L::Function>)
where
    Provider: CompositionProvider,
    L: ComposeLabels<Fact = Provider::Fact, Function = Provider::Function>,
{
    let pairs = if refused { Vec::new() } else { search.pairs() };
    let mut outcome = SearchOutcome {
        effective_budget: search.budget,
        object_reaches: search.object_reaches,
        execution_sources: search.execution_sources,
        execution_reaches: search.execution_reaches,
        execution_procedure_reaches: search.execution_procedure_reaches,
        pairs,
        strict_pairs: search.strict_pairs,
        sources: std::mem::take(&mut search.inputs.sources),
        functions: search.functions,
        sanitizers_resolved: search.inputs.sanitizers_resolved,
        incomplete: search.incomplete,
        abstained: search.abstained,
        stats,
        barrier_notes: search.barrier_notes,
        call_models: std::mem::take(&mut search.inputs.dispatched_models),
    };
    if refused {
        outcome.object_reaches.clear();
        outcome.execution_reaches.clear();
        outcome.execution_procedure_reaches.clear();
        outcome.strict_pairs.clear();
        outcome.sanitizers_resolved = false;
    }
    (outcome, search.inputs)
}

fn classified_provider_error<P: CompositionProvider>(
    provider: &P,
    error: P::Error,
) -> ComposeError {
    match provider.acquisition_refusal(&error) {
        Some(refusal) => ComposeError::AcquisitionRefused(refusal),
        None => provider_error(error),
    }
}

pub(super) fn provider_error(error: impl std::fmt::Display) -> ComposeError {
    ComposeError::Provider(error.to_string().into_boxed_str())
}

impl<'a, 'capture, Provider, L> Search<'a, 'capture, Provider, L>
where
    Provider: CompositionProvider,
    L: ComposeLabels<Fact = Provider::Fact, Function = Provider::Function>,
{
    fn new(
        query: ComposeQuery<'a, L>,
        provider: &'a Provider,
        budget: CompositionBudget,
        capture: Option<&'capture mut RetainedHeap>,
    ) -> Self {
        let ComposeQuery {
            execution_roots,
            object_roots,
            certified_procedure_reaches,
            value_flow,
            labels,
            sinks,
            sources,
            sanitizers,
            transforms,
        } = query;
        let endpoint_projections = super::endpoint_projections_enabled(value_flow, provider);
        let store_writes = provider.store_writes();
        let mut store_writes_in: HashMap<DurableProcedureKey, Vec<usize>> = HashMap::default();
        for (index, write) in store_writes.iter().enumerate() {
            store_writes_in
                .entry(write.procedure.clone())
                .or_default()
                .push(index);
        }
        let mut sinks_in: HashMap<DurableProcedureKey, Vec<ValueFlowSinkId>> = HashMap::default();
        for (sink, _) in &sinks {
            let spec = value_flow
                .expect("a value sink has a value plan")
                .sink(*sink)
                .expect("a bound sink names a sink of its plan");
            sinks_in
                .entry(spec.point().procedure().durable_key())
                .or_default()
                .push(*sink);
        }
        let mut search = Self {
            capture,
            inputs: SearchInputs {
                execution_roots,
                object_roots,
                endpoint_projections,
                accepted: sinks.into_iter().collect(),
                sources: Vec::new(),
                sources_in: HashMap::default(),
                sinks_in,
                annotations: HashMap::default(),
                links: HashMap::default(),
                sanitizers_resolved: true,
                procedures: HashMap::default(),
                interiors: HashMap::default(),
                location_interiors: HashMap::default(),
                modeled_reader_origins: HashMap::default(),
                handles: HashMap::default(),
                dispatches: HashMap::default(),
                dispatched_models: HashMap::default(),
                models: HashMap::default(),
                callers: HashMap::default(),
                parents: HashMap::default(),
                store_writes,
                store_writes_in,
            },
            object_reaches: Vec::new(),
            certified_procedure_reaches,
            value_flow,
            provider,
            budget,
            functions: LabelFunctions::new(labels),
            execution_sources: Vec::new(),
            execution_source_ids: HashMap::default(),
            execution_reaches: Vec::new(),
            execution_procedure_reaches: Vec::new(),
            execution_procedure_reach_ids: HashMap::default(),
            execution_reach_ids: HashMap::default(),
            execution_visited: HashSet::default(),
            visited: Vec::new(),
            modeled_reader_origin_count: 0,
            items: Vec::new(),
            item_ids: HashMap::default(),
            reaches: Vec::new(),
            reach_ids: HashMap::default(),
            reaches_by_root: HashMap::default(),
            summaries: HashMap::default(),
            summary_items: HashSet::default(),
            call_waiters: HashMap::default(),
            registered_call_waiters: HashSet::default(),
            capture_waiters: HashMap::default(),
            registered_capture_waiters: HashSet::default(),
            store_waiters: HashMap::default(),
            registered_store_waiters: HashSet::default(),
            work: Vec::new(),
            incomplete: Vec::new(),
            incomplete_seen: HashSet::default(),
            abstained: Vec::new(),
            abstained_seen: HashSet::default(),
            stopped: false,
            refined_pairs: None,
            strict_pairs: Vec::new(),
            barrier_notes: Vec::new(),
            recorded_supports: 0,
            recorded_edges: 0,
            chop_procedures: 0,
            refinement_chop: Default::default(),
            extra_proof_lookups: 0,
            changed_edge_qualities: 0,
            baseline_candidate_pairs: 0,
            strict_replays: 0,
            changed_edges: HashSet::default(),
        };
        for source in sources {
            search.add_source(source);
        }
        for sanitizer in &sanitizers {
            search.place_sanitizer(sanitizer);
        }
        for transform in transforms {
            search.place_in_place_transform(transform);
        }
        search
    }

    fn add_source(&mut self, source: BoundSource<L::Fact>) {
        if matches!(source.evidence, EndpointEvidence::Known(quality) if !quality.is_certain()) {
            self.note(Incompleteness::SourceEvidence {
                cause: super::IncompleteCause::Operational(super::OperationalCause::Provider),
                point: source.point.clone(),
            });
        }
        let id = ComposedSourceId(
            u32::try_from(self.inputs.sources.len()).expect("a composition's sources fit u32"),
        );
        self.inputs
            .sources_in
            .entry(source.point.procedure().durable_key())
            .or_default()
            .push(id);
        self.inputs.sources.push(source);
    }

    /// Ask the provider for the endpoints of a procedure the search enters
    /// for the first time: sources become seeds of its interior runs,
    /// sanitizers annotate the hops through their calls, and transforms
    /// become flows of their own at their calls.
    fn enter(
        &mut self,
        procedure: &DurableProcedureKey,
        request: &mut SemanticRequest<'_>,
    ) -> Result<Option<ProcedureEndpointInputs<L::Function>>, ComposeError> {
        let answer = self
            .provider
            .endpoints_with_causes(procedure, request)
            .map_err(|error| classified_provider_error(self.provider, error))?;
        let mut endpoints = answer.endpoints;
        // Keep the actual consulted inventory, not only its projected primary cause.
        let causes = answer.causes;
        let completeness = self.capture.as_deref_mut().and_then(|heap| {
            heap.vec(&causes);
            capture_completeness(heap, &endpoints.completeness)
        });
        if !causes.is_empty() || !endpoints.completeness.is_complete() {
            let aggregate_cause = match &endpoints.completeness {
                Completeness::Incomplete { cause, .. } => Some(*cause),
                Completeness::Complete => None,
            };
            let operational = causes
                .iter()
                .chain(aggregate_cause.iter())
                .any(|cause| matches!(cause, super::IncompleteCause::Operational(_)));
            let reason =
                match std::mem::replace(&mut endpoints.completeness, Completeness::Complete) {
                    Completeness::Incomplete { reason, .. } => reason,
                    Completeness::Complete => {
                        "the policy endpoints of this procedure may be incomplete".into()
                    }
                };
            for (index, cause) in causes.iter().copied().chain(aggregate_cause).enumerate() {
                if (operational && cause == super::IncompleteCause::Content)
                    || causes[..index.min(causes.len())].contains(&cause)
                {
                    continue;
                }
                self.note(Incompleteness::Endpoints {
                    cause,
                    procedure: procedure.clone(),
                    reason: reason.clone(),
                });
            }
        }
        let first_source = self.inputs.sources.len();
        for source in endpoints.sources {
            assert_eq!(
                &source.point.procedure().durable_key(),
                procedure,
                "a provider answers the endpoints of the procedure it was asked about"
            );
            self.add_source(source);
        }
        for sanitizer in &endpoints.sanitizers {
            self.place_sanitizer(sanitizer);
        }
        for transform in &endpoints.transforms {
            self.place_link(transform);
        }
        Ok(completeness.map(|completeness| ProcedureEndpointInputs {
            sources: first_source..self.inputs.sources.len(),
            sanitizers: endpoints.sanitizers,
            transforms: endpoints.transforms,
            completeness,
            causes,
        }))
    }

    fn note(&mut self, reason: Incompleteness) {
        if self.incomplete_seen.insert(reason.clone()) {
            self.incomplete.push(reason);
        }
    }

    /// Place one in-place transform on the ports of the call whose carrier
    /// it binds.
    fn place_in_place_transform(&mut self, transform: InPlaceTransform<L::Function>) {
        let function = self.functions.intern(transform.function);
        let hop_for = |call: DurableCallSiteKey| Hop::Transform {
            call,
            function,
            uncertain: false,
        };
        let placed = place_transfer(
            &transform.point,
            &transform.carrier,
            &transform.carrier,
            hop_for,
        );
        self.annotate_many(placed, &transform.point, &transform.carrier);
    }

    /// Place one sanitizer on the ports of the call whose input or output
    /// carrier it binds. A sanitizer that is not resolved leaves the run
    /// incomplete.
    fn place_sanitizer(&mut self, sanitizer: &BoundSanitizer<L::Function>) {
        self.inputs.sanitizers_resolved &= sanitizer.resolved;
        let function = if sanitizer.proven {
            self.functions.intern(sanitizer.function.clone())
        } else {
            LabelFunctionId::IDENTITY
        };
        let hop_for = |call: DurableCallSiteKey| Hop::Sanitizer {
            call,
            function,
            proven: sanitizer.proven,
            uncertain: !sanitizer.resolved,
        };
        let placed = place_transfer(
            &sanitizer.point,
            &sanitizer.input,
            &sanitizer.output,
            hop_for,
        );
        self.annotate_many(placed, &sanitizer.point, &sanitizer.input);
    }

    /// Place one matched transform as a flow of its own from the call input
    /// it reads to the call output it produces.
    fn place_link(&mut self, transform: &BoundTransform<L::Function>) {
        let function = self.functions.intern(transform.function.clone());
        let hop_for = |call: DurableCallSiteKey| Hop::Transform {
            call,
            function,
            uncertain: transform.uncertain,
        };
        let placed = place_transfer(
            &transform.point,
            &transform.input,
            &transform.output,
            hop_for,
        );
        let mut links = 0;
        for (call, Annotation { input, output, hop }) in placed {
            if let (Some(input), Some(output)) = (input, output) {
                self.inputs
                    .links
                    .entry(call)
                    .or_default()
                    .push(Link { input, output, hop });
                links += 1;
            }
        }
        if links == 0 {
            self.note(Incompleteness::UnplacedTransfer {
                procedure: transform.point.procedure().durable_key(),
                carrier: transform.input.clone(),
            });
        }
    }

    fn annotate_many(
        &mut self,
        placed: Vec<(DurableCallSiteKey, Annotation)>,
        point: &ProgramPointHandle,
        carrier: &ValueFlowCarrier,
    ) {
        if placed.is_empty() {
            self.note(Incompleteness::UnplacedTransfer {
                procedure: point.procedure().durable_key(),
                carrier: carrier.clone(),
            });
            return;
        }
        for (call, annotation) in placed {
            self.inputs
                .annotations
                .entry(call)
                .or_default()
                .push(annotation);
        }
    }

    /// Annotations of `call` on a path from `input` (if the path enters the
    /// call through an input port) to the result port `output`.
    fn annotations_for(
        &self,
        call: &DurableCallSiteKey,
        input: Option<&PartialFlowPort>,
        output: &Endpoint,
    ) -> Vec<Hop> {
        let Endpoint::Port(output) = output else {
            return Vec::new();
        };
        self.inputs
            .annotations
            .get(call)
            .into_iter()
            .flatten()
            .filter(|annotation| {
                annotation
                    .input
                    .as_ref()
                    .is_none_or(|wanted| input == Some(wanted))
                    && annotation
                        .output
                        .as_ref()
                        .is_none_or(|wanted| wanted == output)
            })
            .map(|annotation| annotation.hop.clone())
            .collect()
    }

    /// Annotations on the input port where a matched-value sink is rooted.
    /// The path ends at this port, so it does not cross the call result and
    /// cannot pick up the annotation through `annotations_for`.
    fn sink_annotations(&self, sink: ValueFlowSinkId) -> Vec<Hop> {
        let spec = self
            .value_flow
            .expect("value observation has a value plan")
            .sink(sink)
            .expect("a sink item names a sink of its plan");
        let ValueFlowCarrier::Value(value) = spec.carrier() else {
            return Vec::new();
        };
        let point = spec.point();
        let procedure = point.procedure().durable_key();
        let semantics = point.procedure().semantics();
        let mut placed = Vec::new();
        for call in semantics
            .call_sites()
            .iter()
            .filter(|call| call.point == point.id())
        {
            let Some(input) = call_input_port(call, value.id()) else {
                continue;
            };
            let Some(annotations) = self.inputs.annotations.get(&(procedure.clone(), call.id))
            else {
                continue;
            };
            placed.extend(
                annotations
                    .iter()
                    .filter(|annotation| {
                        annotation.input.as_ref() == Some(&input) && annotation.output.is_none()
                    })
                    .map(|annotation| annotation.hop.clone()),
            );
        }
        placed
    }

    fn exhaust(&mut self, lane: BudgetLane) {
        self.note(Incompleteness::Budget(lane));
    }

    /// Add the item, or improve an existing item's quality. An improvement
    /// records the new derivation for the axes it gave and processes the item
    /// again, so every item derived from it is improved in turn.
    fn add_item(
        &mut self,
        procedure: DurableProcedureKey,
        root: Root,
        node: Endpoint,
        function: LabelFunctionId,
        quality: HopQuality,
        derivation: Derivation,
    ) {
        let certificate = match &derivation {
            Derivation::Root => match &root {
                Root::Sink(_, certificate) | Root::Port(_, certificate) => certificate.clone(),
                // Object roots, like execution and store roots, do not carry
                // a value-root invocation certificate. They use typed
                // handoffs and cannot enter the capture-hop path.
                Root::Execution(_) | Root::Object(_) | Root::StoreWrite(_) => None,
            },
            Derivation::Step { next, .. } => self.items[*next].key.certificate.clone(),
            Derivation::Summary(summary) => self.items[summary.next].key.certificate.clone(),
        };
        self.add_item_with_arm(
            ItemKey {
                procedure,
                root,
                node,
                function,
                execution_arm: None,
                certificate,
            },
            quality,
            derivation,
        );
    }

    fn add_item_with_arm(&mut self, key: ItemKey, quality: HopQuality, derivation: Derivation) {
        if let Some(&id) = self.item_ids.get(&key) {
            if self.provider.has_value_type_barriers()
                && !self.items[id].alternatives.contains(&derivation)
            {
                if !self.reserve_support(refinement::item_edges(&derivation)) {
                    return;
                }
                self.items[id].alternatives.push(derivation.clone());
            }
            let item = &mut self.items[id];
            if item.derivations.improve(item.quality, quality, derivation) {
                item.quality = item.quality.join(quality);
                self.work.push(Work::Item(id));
            }
            return;
        }
        if self.items.len()
            + self.reaches.len()
            + self.execution_reaches.len()
            + self.execution_procedure_reaches.len()
            + self.modeled_reader_origin_count
            >= self.budget.max_hops
        {
            self.exhaust(BudgetLane::Hops);
            self.stopped = true;
            return;
        }
        if self.provider.has_value_type_barriers()
            && !self.reserve_support(refinement::item_edges(&derivation))
        {
            return;
        }
        let id = self.items.len();
        self.item_ids.insert(key.clone(), id);
        self.items.push(Item {
            alternatives: if self.provider.has_value_type_barriers() {
                vec![derivation.clone()]
            } else {
                Vec::new()
            },
            active: true,
            root_quality: quality,
            key,
            quality,
            derivations: Derivations::new(quality, derivation),
        });
        self.work.push(Work::Item(id));
    }

    fn add_reach(
        &mut self,
        root: Root,
        source: ComposedSourceId,
        function: LabelFunctionId,
        quality: HopQuality,
        derivation: ReachDerivation,
    ) {
        let store_origin = match &derivation {
            ReachDerivation::Direct { .. } => None,
            ReachDerivation::Through { inner, hops, .. } => hops
                .iter()
                .find_map(|hop| match hop {
                    Hop::Store { read_origin, .. } => Some(read_origin.clone()),
                    _ => None,
                })
                .or_else(|| self.reaches[*inner].key.store_origin.clone()),
        };
        let key = ReachKey {
            root,
            source,
            store_origin,
            function,
        };
        if let Some(&id) = self.reach_ids.get(&key) {
            if self.provider.has_value_type_barriers()
                && !self.reaches[id].alternatives.contains(&derivation)
            {
                if !self.reserve_support(refinement::reach_edges(&derivation)) {
                    return;
                }
                self.reaches[id].alternatives.push(derivation.clone());
            }
            let reach = &mut self.reaches[id];
            if reach
                .derivations
                .improve(reach.quality, quality, derivation)
            {
                reach.quality = reach.quality.join(quality);
                self.work.push(Work::Reach(id));
            }
            return;
        }
        if self.items.len() + self.reaches.len() + self.modeled_reader_origin_count
            >= self.budget.max_hops
        {
            self.exhaust(BudgetLane::Hops);
            self.stopped = true;
            return;
        }
        if self.provider.has_value_type_barriers()
            && !self.reserve_support(refinement::reach_edges(&derivation))
        {
            return;
        }
        let id = self.reaches.len();
        self.reach_ids.insert(key.clone(), id);
        self.reaches_by_root
            .entry(key.root.clone())
            .or_default()
            .push(id);
        self.reaches.push(Reach {
            alternatives: if self.provider.has_value_type_barriers() {
                vec![derivation.clone()]
            } else {
                Vec::new()
            },
            active: true,
            key,
            quality,
            derivations: Derivations::new(quality, derivation),
        });
        self.work.push(Work::Reach(id));
    }

    /// The flows of one procedure, read once. `None` when the procedure
    /// budget refuses a new procedure.
    fn procedure(
        &mut self,
        procedure: &DurableProcedureKey,
        request: &mut SemanticRequest<'_>,
    ) -> Result<Option<Arc<ProcedureData<L::Function>>>, ComposeError> {
        if let Some(data) = self.inputs.procedures.get(procedure) {
            return Ok(data.clone());
        }
        if self.visited.len() >= self.budget.max_procedures {
            self.exhaust(BudgetLane::Procedures);
            self.inputs.procedures.insert(procedure.clone(), None);
            return Ok(None);
        }
        let projections = self
            .provider
            .projected_partial_flows(procedure, request)
            .map_err(|error| classified_provider_error(self.provider, error))?;
        assert!(
            !projections.is_empty(),
            "a procedure has at least one label partition"
        );
        let flows = self
            .provider
            .partial_flows(procedure, request)
            .map_err(|error| classified_provider_error(self.provider, error))?;
        let mut into: HashMap<PartialFlowPort, Vec<Inflow<PartialFlowPort>>> = HashMap::default();
        let mut captured = self
            .capture
            .as_deref_mut()
            .and_then(|heap| capture_slots::<ProjectedProcedureInput>(heap, projections.len(), 0));
        for (ordinal, (function, projection)) in projections.into_iter().enumerate() {
            if projection.outcome != PartialFlowOutcome::Complete {
                self.note(Incompleteness::PartialFlows {
                    procedure: procedure.clone(),
                    outcome: projection.outcome,
                });
            }
            // The stored (or ordinary fresh) rows retain the usual path-sensitive
            // openness refinement. An extra-kill projection may remove a path
            // before it reaches that worklist, so its relation proof and any
            // *new* openness must be checked here. Openness already present in
            // the baseline is still handled by the dispatch/gap sweep. A fresh
            // snapshot may discharge fewer gaps than the stored one, so verify
            // that it did not lose a baseline discharge certificate.
            if !Arc::ptr_eq(&projection, &flows)
                && (!projection.relations_proven()
                    || (projection.has_undischarged_gap() && !flows.has_undischarged_gap())
                    || flows
                        .discharged_gaps
                        .iter()
                        .any(|gap| !projection.discharged_gaps.contains(gap)))
            {
                self.note(Incompleteness::Interior {
                    cause: super::IncompleteCause::Operational(super::OperationalCause::Provider),
                    procedure: procedure.clone(),
                    reason: "a label-group projection has open relations".into(),
                });
            }
            let function = function.map_or(LabelFunctionId::IDENTITY, |function| {
                self.functions.intern(function)
            });
            if let Some((slots, _)) = &mut captured {
                slots[ordinal] = Some(ProjectedProcedureInput {
                    function,
                    flows: Arc::clone(&projection),
                });
            }
            for flow in &projection.flows {
                into.entry(projection.ports[flow.to.index()].clone())
                    .or_default()
                    .push(Inflow {
                        from: projection.ports[flow.from.index()].clone(),
                        function,
                        uncertain: flow.uncertain,
                        crossed: flow.crossed.clone(),
                    });
            }
        }
        let projections = captured.and_then(|(slots, bytes)| {
            finish_capture(
                self.capture.as_deref_mut().expect("capture has funding"),
                slots,
                bytes,
            )
        });
        let data = Arc::new(ProcedureData {
            flows,
            into,
            projections,
            endpoints: OnceLock::new(),
        });
        self.visited.push(procedure.clone());
        self.inputs
            .procedures
            .insert(procedure.clone(), Some(Arc::clone(&data)));
        if let Some(endpoints) = self.enter(procedure, request)? {
            data.endpoints
                .set(endpoints)
                .expect("procedure endpoints are entered once");
        }
        Ok(Some(data))
    }

    fn dispatch(
        &mut self,
        call: &DurableCallSiteKey,
        request: &mut SemanticRequest<'_>,
    ) -> Result<Arc<DispatchAnswer>, ComposeError> {
        if let Some(answer) = self.inputs.dispatches.get(call) {
            return Ok(Arc::clone(answer));
        }
        let (dispatch, model) = self
            .provider
            .dispatch(call, request)
            .map_err(|error| classified_provider_error(self.provider, error))?;
        self.inputs
            .dispatched_models
            .insert(call.clone(), model.map(Arc::new));
        let (incomplete_cause, incomplete_reason) = match dispatch.completeness {
            Completeness::Complete => (None, None),
            Completeness::Incomplete { cause, reason } => (Some(cause), Some(reason)),
        };
        let uncertain = incomplete_reason.is_some();
        let answer = Arc::new(DispatchAnswer {
            candidates: dispatch.candidates.into_iter().map(Arc::new).collect(),
            uncertain,
            incomplete_reason,
            incomplete_cause,
            external_body_unavailable: dispatch.external_body_unavailable,
            continuation: dispatch.continuation,
        });
        self.inputs
            .dispatches
            .insert(call.clone(), Arc::clone(&answer));
        Ok(answer)
    }

    fn note_dispatch_incomplete(&mut self, call: &DurableCallSiteKey, answer: &DispatchAnswer) {
        if let Some(reason) = &answer.incomplete_reason {
            self.note(Incompleteness::Dispatch {
                call: call.clone(),
                reason: reason.clone(),
                cause: answer
                    .incomplete_cause
                    .expect("incomplete dispatch has a cause"),
            });
        }
    }

    fn dispatch_noted(
        &mut self,
        call: &DurableCallSiteKey,
        request: &mut SemanticRequest<'_>,
    ) -> Result<Arc<DispatchAnswer>, ComposeError> {
        let answer = self.dispatch(call, request)?;
        self.note_dispatch_incomplete(call, &answer);
        Ok(answer)
    }

    /// The quality of a stored or interior flow of `procedure`: uncertain
    /// when its relations are, and otherwise the best, over its path classes,
    /// of the conjoined continuation qualities of the calls the class
    /// crossed, as the ICFG engine degrades every fact on a call's
    /// continuation edge. Every crossed call is dispatched, so the calls a
    /// composition dispatches do not depend on the order it finds paths in.
    ///
    /// Also returns one path class for the hop to name: the first whose
    /// quality is best, preferring a certain class and otherwise counting
    /// proof and completeness alike. A witness names the calls of one path,
    /// and a certain flow must retain a class that supplies both axes.
    fn flow_quality(
        &mut self,
        procedure: &DurableProcedureKey,
        uncertain: bool,
        crossed: &[Box<[CallSiteId]>],
        target: &Endpoint,
        request: &mut SemanticRequest<'_>,
    ) -> Result<(HopQuality, Box<[CallSiteId]>), ComposeError> {
        assert!(!crossed.is_empty(), "a flow has at least one path class");
        let score = |quality: HopQuality| {
            u8::from(quality.proven) + u8::from(quality.complete) + u8::from(quality.is_certain())
        };
        let mut best = HopQuality::UNCERTAIN;
        let mut named: Option<(HopQuality, &Box<[CallSiteId]>)> = None;
        for class in crossed {
            let mut quality = HopQuality::CERTAIN;
            for &call in class.iter() {
                let dispatch = self.dispatch_noted(&(procedure.clone(), call), request)?;
                quality = quality.conjoin(dispatch.continuation);
                if let Some(members) = self.crossed_returned_members(procedure, call, target)
                    && !members.is_empty()
                    && let Some(model) = self.model(&(procedure.clone(), call), request)?
                {
                    for member in members {
                        if let Some(reason) =
                            model.returned_member_refusal(&member, self.inputs.endpoint_projections)
                        {
                            self.note_model_content_refusal(
                                &(procedure.clone(), call),
                                &model,
                                &dispatch,
                                reason,
                                request,
                            );
                            quality = quality.conjoin(HopQuality::new(true, false));
                        }
                    }
                }
            }
            best = best.join(quality);
            if named.is_none_or(|(held, _)| score(quality) > score(held)) {
                named = Some((quality, class));
            }
        }
        let (_, class) = named.expect("a flow has at least one path class");
        let quality = if uncertain {
            HopQuality::UNCERTAIN
        } else {
            best
        };
        Ok((quality, class.clone()))
    }

    /// The model that replaces `call`, which returns with the call's dispatch.
    /// A call this search has not dispatched yet is dispatched here.
    fn model(
        &mut self,
        call: &DurableCallSiteKey,
        request: &mut SemanticRequest<'_>,
    ) -> Result<Option<Arc<CallModel<L::Function>>>, ComposeError> {
        if let Some(model) = self.inputs.models.get(call) {
            return Ok(model.clone());
        }
        let model = self.model_for_discovery(call, request)?;
        if let Some(model) = &model
            && model.retains_dispatch
        {
            self.note(Incompleteness::UnknownSummaryEffects {
                call: call.clone(),
                summary: model
                    .summary
                    .clone()
                    .map(Box::new)
                    .expect("an open authored model names its summary"),
                target: model
                    .summary_target
                    .clone()
                    .expect("an open authored model names its target"),
            });
        }
        if let Some(model) = &model
            && let Completeness::Incomplete { reason, cause } = &model.completeness
        {
            self.note(Incompleteness::Model {
                cause: *cause,
                call: call.clone(),
                reason: reason.clone(),
            });
        }
        self.inputs.models.insert(call.clone(), model.clone());
        Ok(model)
    }

    /// Inspect candidate component producers without consuming their quality.
    /// The same cached dispatch supplies `model` when a discovered frontier
    /// actually contributes; only that use records model incompleteness.
    fn model_for_discovery(
        &mut self,
        call: &DurableCallSiteKey,
        request: &mut SemanticRequest<'_>,
    ) -> Result<Option<Arc<CallModel<L::Function>>>, ComposeError> {
        self.dispatch(call, request)?;
        Ok(self
            .inputs
            .dispatched_models
            .get(call)
            .expect("dispatch records the call's model")
            .clone())
    }

    fn callers(
        &mut self,
        procedure: &DurableProcedureKey,
        request: &mut SemanticRequest<'_>,
    ) -> Result<Arc<CallerInput>, ComposeError> {
        if let Some(callers) = self.inputs.callers.get(procedure) {
            return Ok(Arc::clone(callers));
        }
        let mut answer = self
            .provider
            .callers(procedure, request)
            .map_err(|error| classified_provider_error(self.provider, error))?;
        let completeness = self
            .capture
            .as_deref_mut()
            .and_then(|heap| capture_completeness(heap, &answer.completeness));
        if let Completeness::Incomplete { reason, cause } =
            std::mem::replace(&mut answer.completeness, Completeness::Complete)
        {
            self.note(Incompleteness::Callers {
                cause,
                procedure: procedure.clone(),
                reason,
            });
        }
        let clipped = answer.calls.len() > self.budget.max_callers_per_procedure;
        let retained_len = answer
            .calls
            .len()
            .min(self.budget.max_callers_per_procedure);
        if clipped {
            if self.capture.is_none() {
                answer.calls.truncate(retained_len);
            }
            self.exhaust(BudgetLane::CallersPerProcedure);
        }
        if let Some(completeness) = completeness {
            answer.completeness = completeness;
        }
        let callers = Arc::new(CallerInput {
            answer,
            retained_len,
            clipped,
        });
        self.inputs
            .callers
            .insert(procedure.clone(), Arc::clone(&callers));
        Ok(callers)
    }

    /// The seeds of an interior run of `procedure`: its bound sources and,
    /// when `with_ports`, its input ports.
    fn interior_seeds(
        &self,
        procedure: &DurableProcedureKey,
        data: &ProcedureData<L::Function>,
        with_ports: bool,
    ) -> (Vec<InteriorSeed>, Vec<Endpoint>) {
        let mut seeds = Vec::new();
        let mut ends = Vec::new();
        for &id in self.inputs.sources_in.get(procedure).into_iter().flatten() {
            let source = &self.inputs.sources[id.index()];
            seeds.push(InteriorSeed::Source {
                selected_entry: source.selected_entry.clone(),
                point: source.point.id(),
                phase: source.phase,
                carrier: source.carrier.clone(),
            });
            ends.push(Endpoint::Source(id));
        }
        if with_ports {
            for port in data.flows.ports.iter().filter(|port| is_input_port(port)) {
                seeds.push(InteriorSeed::Port(port.clone()));
                ends.push(Endpoint::Port(port.clone()));
            }
        }
        (seeds, ends)
    }

    /// Seed only callee heap outputs that can write shared caller storage.
    /// The provider places these at the normal-return continuation, before
    /// that point's events, so earlier reads never see the write.
    fn writeback_seeds(
        &mut self,
        handle: &ProcedureHandle,
        data: &ProcedureData<L::Function>,
        seeds: &mut Vec<InteriorSeed>,
        ends: &mut Vec<Endpoint>,
        request: &mut SemanticRequest<'_>,
    ) -> Result<(), ComposeError> {
        let endpoint_projections = self.inputs.endpoint_projections;
        let caller = handle.durable_key();
        for call in handle.semantics().call_sites() {
            if !self
                .provider
                .may_share_call_storage(handle, call.id, request)
                .map_err(|error| classified_provider_error(self.provider, error))?
            {
                continue;
            }
            let call_key = (caller.clone(), call.id);
            let dispatch = self.dispatch_noted(&call_key, request)?;
            if let Some(model) = self.model_for_discovery(&call_key, request)? {
                for binding in model.writeback.iter() {
                    let whole_storage = PartialFlowPort::Heap {
                        root: Box::new(binding.actual.clone()),
                        selectors: Box::default(),
                        tail: AccessPathTail::Exact,
                    };
                    for heap in std::iter::once(&whole_storage).chain(data.flows.ports.iter().filter(|port| {
                        matches!(port, PartialFlowPort::Heap { root, .. } if root.as_ref() == &binding.actual)
                    })).chain(model.transfers.iter().filter_map(|transfer| {
                        (endpoint_projections && model.endpoint_projections && matches!(&transfer.output, PartialFlowPort::Heap { root, .. }
                            if root.as_ref() == &binding.actual)).then_some(&transfer.output)
                    })) {
                        let PartialFlowPort::Heap { selectors, tail, .. } = heap else { unreachable!() };
                        match heap_sharing(binding, selectors, *tail) {
                            crate::analyzer::semantic::CallStorageSharing::Isolated => continue,
                            crate::analyzer::semantic::CallStorageSharing::Unknown => {
                                self.note(Incompleteness::Model {
                    cause: super::IncompleteCause::Operational(super::OperationalCause::Provider),
                                    call: call_key.clone(),
                                    reason: "a model writeback has unknown storage sharing".into(),
                                });
                                continue;
                            }
                            crate::analyzer::semantic::CallStorageSharing::Shares => {}
                        }
                        if !binding.complete {
                            self.note(Incompleteness::Model {
                    cause: super::IncompleteCause::Operational(super::OperationalCause::Provider),
                                call: call_key.clone(),
                                reason: "a model writeback has incomplete caller storage".into(),
                            });
                        }
                        if !binding.proven || !binding.conversion_preserves_identity || binding.storage.is_empty() {
                            self.note(Incompleteness::Model {
                    cause: super::IncompleteCause::Operational(super::OperationalCause::Provider),
                                call: call_key.clone(),
                                reason: "a model writeback has unproven shared storage".into(),
                            });
                            continue;
                        }
                        for storage in &binding.storage {
                            seeds.push(InteriorSeed::Writeback {
                                call: call.id,
                                storage: Box::new(storage.clone()),
                                selectors: selectors.clone(),
                                tail: *tail,
                            });
                            ends.push(Endpoint::Port(heap.clone()));
                        }
                    }
                }
                continue;
            }
            for candidate in &dispatch.candidates {
                let Some(data) = self.procedure(&candidate.procedure, request)? else {
                    continue;
                };
                for heap in data.into.keys() {
                    let PartialFlowPort::Heap {
                        root,
                        selectors,
                        tail,
                    } = heap
                    else {
                        continue;
                    };
                    if candidate
                        .written_heap_ports
                        .as_ref()
                        .is_some_and(|written| {
                            !written.iter().any(|port| heap_ports_overlap(heap, port))
                        })
                    {
                        continue;
                    }
                    for binding in candidate
                        .writeback
                        .iter()
                        .filter(|binding| &binding.formal == root.as_ref())
                    {
                        match heap_sharing(binding, selectors, *tail) {
                            crate::analyzer::semantic::CallStorageSharing::Isolated => continue,
                            crate::analyzer::semantic::CallStorageSharing::Unknown => {
                                self.note(Incompleteness::Dispatch {
                                    cause: super::IncompleteCause::Content,
                                    call: call_key.clone(),
                                    reason: "a call writeback has unknown storage sharing".into(),
                                });
                                continue;
                            }
                            crate::analyzer::semantic::CallStorageSharing::Shares => {}
                        }
                        if !binding.proven
                            || !binding.complete
                            || !binding.conversion_preserves_identity
                        {
                            self.note(Incompleteness::Dispatch {
                                cause: super::IncompleteCause::Content,
                                call: call_key.clone(),
                                reason: "a call writeback has unproven shared storage".into(),
                            });
                            continue;
                        }
                        for storage in &binding.storage {
                            seeds.push(InteriorSeed::Writeback {
                                call: call.id,
                                storage: Box::new(storage.clone()),
                                selectors: selectors.clone(),
                                tail: *tail,
                            });
                            ends.push(Endpoint::Writeback {
                                call: call.id,
                                candidate: Box::new((**candidate).clone()),
                                heap: heap.clone(),
                                storage: Box::new(storage.clone()),
                                uncertain: dispatch.uncertain,
                            });
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Run one interior run and note its incompleteness.
    fn run_interior(
        &mut self,
        procedure: &DurableProcedureKey,
        seeds: Vec<InteriorSeed>,
        observations: InteriorObservations,
        request: &mut SemanticRequest<'_>,
    ) -> Result<InteriorRun, ComposeError> {
        let projections = self
            .provider
            .projected_interior_flows(procedure, &seeds, observations.as_slice(), false, request)
            .map_err(|error| classified_provider_error(self.provider, error))?;
        let mut captured = self.capture.as_deref_mut().and_then(|heap| {
            let nested = projections.iter().fold(0usize, |bytes, (_, flows)| {
                bytes.saturating_add(interior_clone_bytes(flows))
            });
            capture_slots::<InteriorPartitionInput>(heap, projections.len(), nested)
        });
        let mut answer = Vec::new();
        for (ordinal, (function, mut flows)) in projections.into_iter().enumerate() {
            let original = if let Some((_, remaining)) = captured.as_mut()
                && !self
                    .capture
                    .as_deref()
                    .expect("capture funding")
                    .is_refused()
            {
                let original = flows.clone();
                adopt_interior_clone(
                    &original,
                    self.capture.as_deref_mut().expect("capture funding"),
                    remaining,
                );
                Some(original)
            } else {
                None
            };
            if let Completeness::Incomplete { reason, cause } =
                std::mem::replace(&mut flows.completeness, Completeness::Complete)
            {
                self.note(Incompleteness::Interior {
                    cause,
                    procedure: procedure.clone(),
                    reason,
                });
            }
            self.inputs
                .handles
                .entry(procedure.clone())
                .and_modify(|input| input.procedure = flows.procedure.clone())
                .or_insert(ProcedureHandleInput {
                    procedure: flows.procedure,
                    acquisition: None,
                });
            let function = function.map_or(LabelFunctionId::IDENTITY, |function| {
                self.functions.intern(function)
            });
            if let Some(original) = original {
                captured.as_mut().expect("funded partitions").0[ordinal] =
                    Some(InteriorPartitionInput {
                        function,
                        flows: original,
                    });
            }
            answer.extend(flows.flows.into_iter().map(|flow| (function, flow)));
        }
        let input = captured.and_then(|(slots, bytes)| {
            finish_capture(
                self.capture.as_deref_mut().expect("capture has funding"),
                slots,
                bytes,
            )
            .map(|partitions| InteriorInput {
                seeds,
                seed_ends: Vec::new(),
                observations,
                partitions,
            })
        });
        Ok((answer, input))
    }

    /// The interior flows of one procedure, run once with its sources and,
    /// when it holds a sink, its input ports as seeds. `None` when the
    /// procedure has neither sources nor sinks.
    fn interior(
        &mut self,
        procedure: &DurableProcedureKey,
        data: &ProcedureData<L::Function>,
        request: &mut SemanticRequest<'_>,
    ) -> Result<Option<Arc<InteriorIndex>>, ComposeError> {
        if let Some(interior) = self.inputs.interiors.get(procedure) {
            return Ok(interior.clone());
        }
        let sinks = self
            .inputs
            .sinks_in
            .get(procedure)
            .cloned()
            .unwrap_or_default();
        let writes = self
            .inputs
            .store_writes_in
            .get(procedure)
            .cloned()
            .unwrap_or_default();
        if sinks.is_empty() && writes.is_empty() && !self.inputs.sources_in.contains_key(procedure)
        {
            self.inputs.interiors.insert(procedure.clone(), None);
            return Ok(None);
        }
        let (mut seeds, mut seed_ends) =
            self.interior_seeds(procedure, data, !sinks.is_empty() || !writes.is_empty());
        let value_flow = self.value_flow.expect("an interior run has a value plan");
        let mut observations = sinks
            .iter()
            .map(|&sink| {
                let spec = value_flow
                    .sink(sink)
                    .expect("a sink binding names a sink of its plan");
                InteriorObservation::Sink {
                    point: spec.point().id(),
                    phase: spec.phase(),
                    carrier: spec.carrier().clone(),
                }
            })
            .collect::<Vec<_>>();
        observations.extend(writes.iter().map(|&write| {
            let write = &self.inputs.store_writes[write];
            InteriorObservation::Sink {
                point: write.point,
                phase: write.phase,
                carrier: write.carrier.clone(),
            }
        }));
        if !sinks.is_empty() || !writes.is_empty() {
            let handle = if let Some(&sink) = sinks.first() {
                value_flow
                    .sink(sink)
                    .expect("a bound sink exists")
                    .point()
                    .procedure()
                    .clone()
            } else {
                self.inputs.store_writes[writes[0]].owner.clone()
            };
            self.writeback_seeds(&handle, data, &mut seeds, &mut seed_ends, request)?;
        }
        let (flows, input) = self.run_interior(
            procedure,
            seeds,
            InteriorObservations::Many(observations),
            request,
        )?;
        let mut index = InteriorIndex {
            input,
            into: HashMap::default(),
        };
        for (function, flow) in flows {
            let seed = seed_ends[flow.seed].clone();
            let target = match flow.target {
                InteriorTarget::Observation(observation) if observation < sinks.len() => {
                    Endpoint::Sink(sinks[observation])
                }
                InteriorTarget::Observation(observation) => {
                    Endpoint::StoreWrite(writes[observation - sinks.len()])
                }
                // Port-to-port flows are the stored flows.
                InteriorTarget::Port(_) if matches!(seed, Endpoint::Port(_)) => continue,
                InteriorTarget::Port(port) => Endpoint::Port(port),
            };
            index.into.entry(target).or_default().push(Inflow {
                from: seed,
                function,
                uncertain: flow.uncertain,
                crossed: flow.crossed,
            });
        }
        if let Some(input) = &mut index.input {
            input.seed_ends = seed_ends;
        }
        let index = Arc::new(index);
        self.inputs
            .interiors
            .insert(procedure.clone(), Some(Arc::clone(&index)));
        Ok(Some(index))
    }

    /// What reaches one caller-side location of `procedure`: an interior run
    /// seeded at its sources, input ports, and earlier call writebacks,
    /// observing that location. Run once per location. The writeback seeds
    /// let local member copies carry a callee write to a later call's input.
    fn location_interior(
        &mut self,
        procedure: &DurableProcedureKey,
        data: &ProcedureData<L::Function>,
        location: &CallerLocation,
        request: &mut SemanticRequest<'_>,
    ) -> Result<Reaching, ComposeError> {
        let key = (procedure.clone(), location.clone());
        if let Some(reaching) = self.inputs.location_interiors.get(&key) {
            return Ok(Arc::clone(
                reaching.reaching.as_ref().expect("live search index"),
            ));
        }
        let (mut seeds, mut seed_ends) = self.interior_seeds(procedure, data, true);
        if !self.inputs.handles.contains_key(procedure) {
            let (_, acquisition) =
                self.run_interior(procedure, Vec::new(), InteriorObservations::Empty, request)?;
            if let Some(handle) = self.inputs.handles.get_mut(procedure) {
                handle.acquisition = acquisition;
            }
        }
        let Some(handle) = self
            .inputs
            .handles
            .get(procedure)
            .map(|input| input.procedure.clone())
        else {
            self.note(Incompleteness::Interior {
                cause: super::IncompleteCause::Content,
                procedure: procedure.clone(),
                reason: "component observation has no live procedure handle".into(),
            });
            return Ok(Arc::from([]));
        };
        if self.inputs.endpoint_projections {
            // Retain explicit component productions and demanded whole-return
            // frontiers. A frontier reaches the model before any component flow
            // can be established; it never asserts positional identity.
            for row in handle.semantics().call_sites() {
                let call = (procedure.clone(), row.id);
                let model = self.model_for_discovery(&call, request)?;
                if model.as_ref().is_none_or(|model| model.retains_dispatch) {
                    let dispatch = self.dispatch(&call, request)?;
                    for candidate in &dispatch.candidates {
                        let Some(callee) = self.procedure(&candidate.procedure, request)? else {
                            continue;
                        };
                        for port in &callee.flows.ports {
                            let PartialFlowPort::Heap {
                                root,
                                selectors,
                                tail,
                            } = port
                            else {
                                continue;
                            };
                            if !matches!(root.as_ref(), PartialFlowPort::NormalReturn) {
                                continue;
                            }
                            for (formal, actual) in &candidate.returns {
                                if formal != root.as_ref()
                                    || !matches!(actual, PartialFlowPort::CallResult { .. })
                                {
                                    continue;
                                }
                                let output = PartialFlowPort::Heap {
                                    root: Box::new(actual.clone()),
                                    selectors: selectors.clone(),
                                    tail: *tail,
                                };
                                let endpoint = Endpoint::Port(output.clone());
                                // This is a search frontier, not a taint fact. The
                                // return pairing and callee flow still have to prove it.
                                if !seed_ends.contains(&endpoint)
                                    && let Some(seed) =
                                        crate::composition::projected_return_seed(&handle, &output)
                                {
                                    seeds.push(seed);
                                    seed_ends.push(endpoint);
                                }
                            }
                        }
                    }
                }
                let Some(model) = model else {
                    continue;
                };
                if !location.selectors.is_empty() {
                    // A whole-return frontier is not evidence that the returned
                    // aggregate is tainted. Letting it cover a child read before
                    // visiting the model would bypass the preservation check.
                    let is_return = |endpoint: &Endpoint| match endpoint {
                        Endpoint::Port(PartialFlowPort::CallResult { call, .. }) => *call == row.id,
                        Endpoint::Port(PartialFlowPort::Heap { root, .. }) => {
                            matches!(root.as_ref(), PartialFlowPort::CallResult { call, .. } if *call == row.id)
                        }
                        _ => false,
                    };
                    let mut index = 0;
                    seeds.retain(|_| {
                        let retain = !is_return(&seed_ends[index]);
                        index += 1;
                        retain
                    });
                    seed_ends.retain(|endpoint| !is_return(endpoint));
                }
                let outputs = if !location.selectors.is_empty() {
                    // Native field reads may have already selected a prefix of a
                    // returned aggregate before the final modeled read. Extend
                    // only structured ports of this procedure; the interior run
                    // must still prove the connection to this observation.
                    let mut outputs = Vec::new();
                    for root in row
                        .result
                        .into_iter()
                        .map(|_| PartialFlowPort::CallResult {
                            call: row.id,
                            ordinal: None,
                        })
                        .chain(row.normal_results.iter().enumerate().map(|(ordinal, _)| {
                            PartialFlowPort::CallResult {
                                call: row.id,
                                ordinal: Some(
                                    u32::try_from(ordinal).expect("result count fits u32"),
                                ),
                            }
                        }))
                    {
                        let mut prefixes = vec![&[][..]];
                        for (index, port) in data.flows.ports.iter().enumerate() {
                            let PartialFlowPort::Heap {
                                root: native_root,
                                selectors,
                                tail,
                            } = port
                            else {
                                continue;
                            };
                            if native_root.as_ref() != &root || selectors.is_empty() {
                                continue;
                            }
                            let exact = *tail == AccessPathTail::Exact
                                && !selectors
                                    .iter()
                                    .any(|selector| matches!(selector, HeapSelector::AnyIndex))
                                && data.flows.relations_proven()
                                && !data.flows.flows.iter().any(|flow| {
                                    flow.uncertain
                                        && (flow.from.index() == index || flow.to.index() == index)
                                });
                            if !exact {
                                self.note(Incompleteness::Model {
                                    cause: super::IncompleteCause::Content,
                                    call: (procedure.clone(), row.id),
                                    reason: "a native modeled-return frontier is not proven exact"
                                        .into(),
                                });
                                continue;
                            }
                            // A renamed local copy can connect this exact native
                            // path directly, independently of the consumer's name.
                            if !outputs.contains(port) {
                                outputs.push(port.clone());
                            }
                            prefixes.push(selectors.as_ref());
                        }
                        for prefix in prefixes {
                            let mut selectors = prefix.to_vec();
                            selectors.extend_from_slice(&location.selectors);
                            let output = PartialFlowPort::Heap {
                                root: Box::new(root.clone()),
                                selectors: selectors.into_boxed_slice(),
                                tail: location.tail,
                            };
                            if !outputs.contains(&output) {
                                outputs.push(output);
                            }
                        }
                    }
                    outputs
                } else if model.endpoint_projections {
                    model
                        .transfers
                        .iter()
                        .map(|transfer| transfer.output.clone())
                        .collect()
                } else {
                    Vec::new()
                };
                for output in outputs {
                    let endpoint = Endpoint::Port(output.clone());
                    if !seed_ends.contains(&endpoint)
                        && let Some(seed) =
                            crate::composition::projected_return_seed(&handle, &output)
                    {
                        seeds.push(seed);
                        seed_ends.push(endpoint);
                    }
                }
            }
        }
        self.writeback_seeds(&handle, data, &mut seeds, &mut seed_ends, request)?;
        let observations =
            InteriorObservations::One([InteriorObservation::Location(location.clone())]);
        let (flows, mut input) = self.run_interior(procedure, seeds, observations, request)?;
        let reaching: Reaching = flows
            .into_iter()
            .filter(|(_, flow)| flow.target == InteriorTarget::Observation(0))
            .map(|(function, flow)| Inflow {
                from: seed_ends[flow.seed].clone(),
                function,
                uncertain: flow.uncertain,
                crossed: flow.crossed,
            })
            .collect();
        if let Some(input) = &mut input {
            input.seed_ends = seed_ends;
        }
        self.inputs.location_interiors.insert(
            key,
            LocationInteriorInput {
                input,
                reaching: Some(Arc::clone(&reaching)),
            },
        );
        Ok(reaching)
    }

    fn process_execution_item(
        &mut self,
        id: usize,
        target: ExecutionTarget,
        request: &mut SemanticRequest<'_>,
    ) -> Result<(), ComposeError> {
        let key = self.items[id].key.clone();
        let Root::Execution(root) = &key.root else {
            unreachable!("execution items have execution roots");
        };
        let root = root.as_ref().clone();
        let certificate = key
            .certificate
            .clone()
            .unwrap_or_else(|| ExecutionCertificate {
                root: root.clone(),
                prefix: Box::new([]),
            });
        let quality = self.items[id].quality;
        let endpoints = self
            .provider
            .execution_endpoints(&target, key.execution_arm.as_ref(), request)
            .map_err(|error| classified_provider_error(self.provider, error))?;
        // An authored external summary can close a body-incomplete dispatch arm;
        // its raw arm quality remains on the invocation hop and reach.
        let closed = matches!(endpoints.status, ExecutionEndpointStatus::Complete)
            && match &target {
                ExecutionTarget::External(identity) => {
                    matches!(
                        identity.as_ref(),
                        super::graph::ExternalTargetIdentity::Exact { .. }
                    ) || endpoints.covers_overrides
                }
                ExecutionTarget::Procedure(_) => key
                    .execution_arm
                    .as_ref()
                    .is_none_or(|arm| arm.quality.complete),
            };
        if !closed
            && (matches!(target, ExecutionTarget::External(_))
                || !matches!(endpoints.status, ExecutionEndpointStatus::Absent))
        {
            self.note(Incompleteness::Execution {
                cause: super::IncompleteCause::Operational(super::OperationalCause::Provider),
                procedure: key.procedure.clone(),
                reason: format!(
                    "execution endpoints are open: {}",
                    match endpoints.status {
                        ExecutionEndpointStatus::Complete => "complete",
                        ExecutionEndpointStatus::Partial(_) => "partial",
                        ExecutionEndpointStatus::Conflict(_) => "conflict",
                        ExecutionEndpointStatus::Absent => "absent",
                    }
                )
                .into(),
            });
        }
        for source in endpoints.sources {
            let source_key = (
                target.clone(),
                source.identity.clone(),
                key.execution_arm.clone(),
            );
            let source_id = if let Some(&source_id) = self.execution_source_ids.get(&source_key) {
                source_id
            } else {
                let source_id = self.execution_sources.len();
                self.execution_sources.push(source);
                self.execution_source_ids.insert(source_key, source_id);
                source_id
            };
            let reach_key = (
                root.clone(),
                source_id,
                key.function,
                key.execution_arm.clone(),
            );
            let reach_quality = quality.conjoin(HopQuality::new(true, closed));
            if let Some(&reach_id) = self.execution_reach_ids.get(&reach_key) {
                if !self.execution_reaches[reach_id]
                    .quality
                    .dominates(reach_quality)
                {
                    let hops = self.execution_item_path(id, reach_quality);
                    let reach = &mut self.execution_reaches[reach_id];
                    reach.quality = reach.quality.join(reach_quality);
                    reach.hops = hops;
                }
                continue;
            }
            if self.items.len()
                + self.reaches.len()
                + self.execution_reaches.len()
                + self.execution_procedure_reaches.len()
                + self.modeled_reader_origin_count
                >= self.budget.max_hops
            {
                self.exhaust(BudgetLane::Hops);
                self.stopped = true;
                return Ok(());
            }
            self.execution_reach_ids
                .insert(reach_key, self.execution_reaches.len());
            self.execution_reaches.push(ExecutionReach {
                root: root.clone(),
                target: ExecutionReachTarget::Source(source_id),
                function: key.function,
                quality: reach_quality,
                hops: self.execution_item_path(id, reach_quality),
                incoming: key.execution_arm.clone(),
                certificate: certificate.clone(),
            });
        }
        let ExecutionTarget::Procedure(procedure) = target else {
            return Ok(());
        };
        let procedure = *procedure;
        let procedure_key = (certificate.clone(), procedure.clone());
        if let Some(&reach_id) = self.execution_procedure_reach_ids.get(&procedure_key) {
            if !self.execution_procedure_reaches[reach_id]
                .quality
                .dominates(quality)
            {
                let hops = self.execution_item_path(id, quality);
                let reach = &mut self.execution_procedure_reaches[reach_id];
                reach.quality = reach.quality.join(quality);
                reach.hops = hops;
            }
        } else {
            if self.items.len()
                + self.reaches.len()
                + self.execution_reaches.len()
                + self.execution_procedure_reaches.len()
                + self.modeled_reader_origin_count
                >= self.budget.max_hops
            {
                self.exhaust(BudgetLane::Hops);
                self.stopped = true;
                return Ok(());
            }
            self.execution_procedure_reach_ids
                .insert(procedure_key, self.execution_procedure_reaches.len());
            self.execution_procedure_reaches.push(ExecutionReach {
                root: root.clone(),
                target: ExecutionReachTarget::Procedure(Box::new(procedure.clone())),
                function: key.function,
                quality,
                hops: self.execution_item_path(id, quality),
                incoming: key.execution_arm.clone(),
                certificate: certificate.clone(),
            });
        }
        if self.execution_visited.insert(procedure.clone())
            && self.execution_visited.len() > self.budget.max_procedures
        {
            self.exhaust(BudgetLane::Procedures);
            self.stopped = true;
            return Ok(());
        }
        let inventory = self
            .provider
            .invocations(&procedure, request)
            .map_err(|error| classified_provider_error(self.provider, error))?;
        if let Completeness::Incomplete { reason, cause } = inventory.coverage {
            self.note(Incompleteness::Execution {
                cause,
                procedure: procedure.clone(),
                reason,
            });
        }
        for site in inventory.sites {
            let dispatch = self
                .provider
                .execution_dispatch(&site.call, key.execution_arm.as_ref(), request)
                .map_err(|error| classified_provider_error(self.provider, error))?;
            let residual_discharged = !dispatch.arms.is_empty()
                && dispatch.coverage != crate::analyzer::semantic::CandidateCoverage::Truncated
                && matches!(
                    dispatch.residuals.as_slice(),
                    [crate::analyzer::semantic::DispatchBoundaryKind::Unresolved]
                )
                && self
                    .provider
                    .discharge_execution_residual(&site.call, &dispatch);
            let dispatch_closed = dispatch.outcome
                == super::provider::ExecutionDispatchOutcome::Complete
                && !dispatch.arms.is_empty()
                && ((dispatch.coverage.is_exhaustive() && dispatch.residuals.is_empty())
                    || residual_discharged);
            if !dispatch_closed {
                self.note(Incompleteness::Execution {
                    cause: match &dispatch.outcome {
                        super::provider::ExecutionDispatchOutcome::Budget(_) => {
                            super::IncompleteCause::Operational(super::OperationalCause::Budget(
                                BudgetLane::Semantic,
                            ))
                        }
                        super::provider::ExecutionDispatchOutcome::Cancelled(_) => {
                            super::IncompleteCause::Operational(super::OperationalCause::Cancelled)
                        }
                        // Candidates cut off at a finite bound are a budget
                        // stop even when the dispatch itself completed.
                        super::provider::ExecutionDispatchOutcome::Complete
                        | super::provider::ExecutionDispatchOutcome::Unsupported(_)
                            if dispatch.coverage
                                == crate::analyzer::semantic::CandidateCoverage::Truncated =>
                        {
                            super::IncompleteCause::Operational(super::OperationalCause::Budget(
                                BudgetLane::Semantic,
                            ))
                        }
                        super::provider::ExecutionDispatchOutcome::Complete
                        | super::provider::ExecutionDispatchOutcome::Unsupported(_) => {
                            super::IncompleteCause::Content
                        }
                    },
                    procedure: procedure.clone(),
                    reason: {
                        let mut residuals = dispatch
                            .residuals
                            .iter()
                            .map(|residual| residual.label())
                            .collect::<Vec<_>>();
                        residuals.sort_unstable();
                        format!(
                            "execution dispatch {} is open: outcome={} coverage={:?} residuals={residuals:?}",
                            call_site_text(&site.call),
                            match dispatch.outcome {
                                super::provider::ExecutionDispatchOutcome::Complete => "complete",
                                super::provider::ExecutionDispatchOutcome::Unsupported(_) => "unsupported",
                                super::provider::ExecutionDispatchOutcome::Cancelled(_) => "cancelled",
                                super::provider::ExecutionDispatchOutcome::Budget(_) => "budget",
                            },
                            dispatch.coverage
                        )
                        .into()
                    },
                });
            }
            for (ordinal, arm) in dispatch.arms.into_iter().enumerate() {
                let step = ExecutionCertificateStep {
                    call: site.call.clone(),
                    ordinal,
                    target: arm.target.clone(),
                    instance: arm.instance.clone(),
                    context: arm.context.clone(),
                };
                // A named recursive call revisits the same procedure inventory;
                // it does not create another callable instance to certify.
                if step.instance.is_none()
                    && certificate.prefix.iter().any(|old| {
                        old.instance.is_none()
                            && old.target == step.target
                            && old.context == step.context
                    })
                {
                    continue;
                }
                if certificate.prefix.iter().any(|old| {
                    old.context == step.context
                        && match (&old.instance, &step.instance) {
                            (Some(old), Some(new)) => old == new,
                            _ => false,
                        }
                }) {
                    self.note(Incompleteness::Execution {
                        cause: super::IncompleteCause::Operational(
                            super::OperationalCause::Provider,
                        ),
                        procedure: procedure.clone(),
                        reason: format!(
                            "repeated instance and context on execution path at {}",
                            call_site_text(&step.call)
                        )
                        .into(),
                    });
                    continue;
                }
                let mut prefix = certificate.prefix.to_vec();
                prefix.push(step);
                let next_certificate = ExecutionCertificate {
                    root: root.clone(),
                    prefix: prefix.into_boxed_slice(),
                };
                let function = self.functions.intern(arm.function);
                let composed = self.functions.then(function, key.function);
                let hop = Hop::Invocation {
                    call: site.call.clone(),
                    ordinal,
                    target: Box::new(arm.target.clone()),
                    function,
                    quality: arm.quality,
                    certificate: next_certificate.clone(),
                };
                let owner = match &arm.target {
                    ExecutionTarget::Procedure(procedure) => procedure.as_ref().clone(),
                    ExecutionTarget::External(_) => procedure.clone(),
                };
                self.add_item_with_arm(
                    ItemKey {
                        procedure: owner,
                        root: key.root.clone(),
                        node: Endpoint::Execution(Box::new(arm.target)),
                        function: composed,
                        execution_arm: Some(ExecutionArmContext {
                            call: site.call.clone(),
                            ordinal,
                            quality: arm.quality,
                            certificate: next_certificate.clone(),
                        }),
                        certificate: Some(next_certificate),
                    },
                    quality.conjoin(arm.quality),
                    Derivation::Step {
                        hops: vec![hop],
                        next: id,
                    },
                );
            }
        }
        Ok(())
    }

    fn execution_item_path(&self, id: usize, quality: HopQuality) -> Vec<Hop> {
        let mut path = Vec::new();
        let mut next = id;
        let chain = if quality.is_certain() {
            Chain::Certain
        } else if quality.proven {
            Chain::Proven
        } else if quality.complete {
            Chain::Complete
        } else {
            Chain::First
        };
        loop {
            match self.items[next].derivations.get(chain) {
                Derivation::Root => return path,
                Derivation::Step { hops, next: outer } => {
                    path.extend(hops.iter().cloned());
                    next = *outer;
                }
                Derivation::Summary(_) => unreachable!("execution has no value summary"),
            }
        }
    }

    fn call_boundary_label(
        &mut self,
        call: &DurableCallSiteKey,
        callee: &DurableProcedureKey,
        from: &Endpoint,
        to: &Endpoint,
    ) -> (LabelFunctionId, HopQuality) {
        self.provider
            .call_boundary_function(call, callee, from, to)
            .map_or(
                (LabelFunctionId::IDENTITY, HopQuality::CERTAIN),
                |(function, quality)| (self.functions.intern(function), quality),
            )
    }

    fn process_object_item(
        &mut self,
        id: usize,
        root: &ObjectAnchor,
        request: &mut SemanticRequest<'_>,
    ) -> Result<bool, ComposeError> {
        let key = self.items[id].key.clone();
        let relation = self
            .provider
            .object_relation(&key.procedure, &key.node, request)
            .map_err(|error| classified_provider_error(self.provider, error))?;
        if !relation.complete {
            self.note(Incompleteness::Object {
                cause: super::IncompleteCause::Operational(super::OperationalCause::Provider),
                anchor: Box::new(root.clone()),
                reason: format!("object relation at {:?} is incomplete", key.node).into(),
            });
        }
        let quality = self.items[id]
            .quality
            .conjoin(HopQuality::from_uncertain(!relation.complete));
        for source in relation.sources {
            if self.items.len()
                + self.reaches.len()
                + self.execution_reaches.len()
                + self.object_reaches.len()
                + self.modeled_reader_origin_count
                >= self.budget.max_hops
            {
                self.exhaust(BudgetLane::Hops);
                self.stopped = true;
                return Ok(relation.cross_call);
            }
            self.object_reaches.push(ObjectReach {
                root: root.clone(),
                source,
                function: key.function,
                quality,
                hops: self.execution_item_path(id, quality),
            });
        }
        for predecessor in relation.predecessors {
            let function = self.functions.intern(predecessor.function);
            let hop = Hop::Interior {
                procedure: key.procedure.clone(),
                from: predecessor.from.clone(),
                to: key.node.clone(),
                quality: predecessor.quality,
                function,
                crossed: Box::new([]),
            };
            let next_function = self.functions.then(function, key.function);
            self.add_item(
                key.procedure.clone(),
                key.root.clone(),
                predecessor.from,
                next_function,
                quality.conjoin(predecessor.quality),
                Derivation::Step {
                    hops: vec![hop],
                    next: id,
                },
            );
        }
        Ok(relation.cross_call)
    }

    fn process_call_handoff(&mut self, id: usize, key: &ItemKey, quality: HopQuality) {
        let Endpoint::CallHandoff {
            call,
            candidate,
            binding,
            function,
            quality: handoff_quality,
        } = &key.node
        else {
            unreachable!("only a typed handoff enters this method")
        };
        let (actual, formal) = candidate
            .arguments
            .get(binding.argument_index)
            .expect("a client handoff indexes its selected candidate");
        let hop = Hop::CallHandoff {
            call: (key.procedure.clone(), *call),
            callee: candidate.procedure.clone(),
            actual: actual.clone(),
            formal: formal.clone(),
            exit: binding.exit,
            continuity: binding.continuity,
            function: *function,
            quality: *handoff_quality,
        };
        let function = self.functions.then(*function, key.function);
        self.add_item(
            key.procedure.clone(),
            key.root.clone(),
            Endpoint::Port(actual.clone()),
            function,
            quality.conjoin(*handoff_quality),
            Derivation::Step {
                hops: vec![hop],
                next: id,
            },
        );
    }

    fn process_item(
        &mut self,
        id: usize,
        request: &mut SemanticRequest<'_>,
    ) -> Result<(), ComposeError> {
        let key = self.items[id].key.clone();
        let quality = self.items[id].quality;
        if let Root::Object(root) = &key.root {
            let cross_call = self.process_object_item(id, root, request)?;
            match &key.node {
                Endpoint::Port(
                    PartialFlowPort::CallResult { call, .. } | PartialFlowPort::CallThrown { call },
                ) => {
                    return if cross_call {
                        self.descend(id, *call, request)
                    } else {
                        Ok(())
                    };
                }
                Endpoint::Object(_) | Endpoint::Port(_) => return Ok(()),
                Endpoint::CallHandoff { .. } => {
                    self.process_call_handoff(id, &key, quality);
                    return Ok(());
                }
                _ => {}
            }
        }
        if let Endpoint::Execution(target) = &key.node {
            self.process_execution_item(id, target.as_ref().clone(), request)?;
            return Ok(());
        }
        let Some(data) = self.procedure(&key.procedure, request)? else {
            return Ok(());
        };
        if matches!(key.node, Endpoint::CallHandoff { .. }) {
            self.process_call_handoff(id, &key, quality);
            return Ok(());
        }
        if let Endpoint::Port(port @ PartialFlowPort::CallResult { .. }) = &key.node {
            self.open_store_read(id, port);
        }
        if let Endpoint::Port(port) = &key.node {
            for flow in data.into.get(port).cloned().unwrap_or_default() {
                let (flow_quality, crossed) = self.flow_quality(
                    &key.procedure,
                    flow.uncertain,
                    &flow.crossed,
                    &key.node,
                    request,
                )?;
                let local = self
                    .provider
                    .local_function(
                        &key.procedure,
                        &Endpoint::Port(flow.from.clone()),
                        &Endpoint::Port(port.clone()),
                        request,
                    )
                    .map_err(|error| classified_provider_error(self.provider, error))?;
                let (local, local_quality) = local.map_or(
                    (LabelFunctionId::IDENTITY, HopQuality::CERTAIN),
                    |(function, quality)| (self.functions.intern(function), quality),
                );
                let flow_quality = flow_quality.conjoin(local_quality);
                let along = self.functions.then(flow.function, local);
                let hop = Hop::Stored {
                    procedure: key.procedure.clone(),
                    from: flow.from.clone(),
                    to: port.clone(),
                    function: along,
                    quality: flow_quality,
                    crossed,
                };
                let along = self.functions.hops(std::slice::from_ref(&hop));
                let function = self.functions.then(along, key.function);
                self.add_item(
                    key.procedure.clone(),
                    key.root.clone(),
                    Endpoint::Port(flow.from),
                    function,
                    flow_quality.conjoin(quality),
                    Derivation::Step {
                        hops: vec![hop],
                        next: id,
                    },
                );
            }
        }
        let reaching = match &key.node {
            Endpoint::Location(location) => self
                .location_interior(&key.procedure, &data, location, request)?
                .to_vec(),
            _ => self
                .interior(&key.procedure, &data, request)?
                .and_then(|interior| interior.into.get(&key.node).cloned())
                .unwrap_or_default(),
        };
        let sink_annotations = match &key.node {
            Endpoint::Sink(sink) => self.sink_annotations(*sink),
            _ => Vec::new(),
        };
        {
            for flow in reaching {
                let (flow_quality, crossed) = self.flow_quality(
                    &key.procedure,
                    flow.uncertain,
                    &flow.crossed,
                    &key.node,
                    request,
                )?;
                let seed = flow.from;
                let local = self
                    .provider
                    .local_function(&key.procedure, &seed, &key.node, request)
                    .map_err(|error| classified_provider_error(self.provider, error))?;
                let (local, local_quality) = local.map_or(
                    (LabelFunctionId::IDENTITY, HopQuality::CERTAIN),
                    |(function, quality)| (self.functions.intern(function), quality),
                );
                let flow_quality = flow_quality.conjoin(local_quality);
                let along = self.functions.then(flow.function, local);
                let mut hops = vec![Hop::Interior {
                    procedure: key.procedure.clone(),
                    from: seed.clone(),
                    to: key.node.clone(),
                    function: along,
                    quality: flow_quality,
                    crossed,
                }];
                hops.extend(sink_annotations.iter().cloned());
                let path_quality = Hop::path_quality(&hops).conjoin(quality);
                let along = self.functions.hops(&hops);
                let function = self.functions.then(along, key.function);
                match seed {
                    Endpoint::Source(source) => self.add_reach(
                        key.root.clone(),
                        source,
                        function,
                        path_quality.conjoin(match self.inputs.sources[source.index()].evidence {
                            EndpointEvidence::Known(quality) => quality,
                            // Judged at stage 3, for the sources that
                            // reach a sink.
                            EndpointEvidence::Unknown => HopQuality::CERTAIN,
                        }),
                        ReachDerivation::Direct { hops, next: id },
                    ),
                    Endpoint::Port(_) | Endpoint::Writeback { .. } => self.add_item(
                        key.procedure.clone(),
                        key.root.clone(),
                        seed,
                        function,
                        path_quality,
                        Derivation::Step { hops, next: id },
                    ),
                    Endpoint::Sink(_)
                    | Endpoint::Object(_)
                    | Endpoint::CallHandoff { .. }
                    | Endpoint::StoreWrite(_)
                    | Endpoint::Location(_)
                    | Endpoint::Execution(_) => {
                        unreachable!("sinks and locations are never interior seeds")
                    }
                }
            }
        }
        match &key.node {
            Endpoint::Writeback {
                call,
                candidate,
                heap,
                uncertain,
                ..
            } => {
                let call_key = (key.procedure.clone(), *call);
                self.open_callee_root(
                    id,
                    &call_key,
                    &Arc::new((**candidate).clone()),
                    heap.clone(),
                    *uncertain,
                );
                Ok(())
            }
            Endpoint::Port(
                PartialFlowPort::CallResult { call, .. } | PartialFlowPort::CallThrown { call },
            ) => self.descend(id, *call, request),
            Endpoint::Port(PartialFlowPort::Heap { root, .. })
                if matches!(
                    root.as_ref(),
                    PartialFlowPort::CallReceiver { .. } | PartialFlowPort::CallArgument { .. }
                ) =>
            {
                self.descend_heap(id, request)
            }
            Endpoint::Port(PartialFlowPort::Heap { root, .. })
                if matches!(root.as_ref(), PartialFlowPort::CallResult { .. }) =>
            {
                let PartialFlowPort::CallResult { call, .. } = root.as_ref() else {
                    unreachable!()
                };
                self.descend(id, *call, request)
            }
            Endpoint::Port(
                port @ (PartialFlowPort::CallReceiver { call }
                | PartialFlowPort::CallArgument { call, .. }),
            ) => {
                let call_key = (key.procedure.clone(), *call);
                if self.model(&call_key, request)?.is_some_and(|model| {
                    model
                        .receiver_reads
                        .iter()
                        .any(|binding| &binding.actual == port)
                }) {
                    if !self.inputs.handles.contains_key(&key.procedure) {
                        let (_, acquisition) = self.run_interior(
                            &key.procedure,
                            Vec::new(),
                            InteriorObservations::Empty,
                            request,
                        )?;
                        if let Some(handle) = self.inputs.handles.get_mut(&key.procedure) {
                            handle.acquisition = acquisition;
                        }
                    }
                    let handle = self.inputs.handles[&key.procedure].procedure.clone();
                    let site = handle
                        .semantics()
                        .call_site(*call)
                        .expect("a modeled call input belongs to its procedure");
                    let value = call_input_value(site, port)
                        .expect("a modeled call input has a live value");
                    self.written_location(
                        id,
                        &handle,
                        value,
                        site.point,
                        &[],
                        AccessPathTail::Exact,
                        Some(*call),
                        request,
                    )?;
                }
                Ok(())
            }
            Endpoint::Port(port) if is_formal_or_heap_input(port) => self.formal(id, request),
            Endpoint::Location(location) => {
                let Some(handle) = self
                    .inputs
                    .handles
                    .get(&key.procedure)
                    .map(|input| input.procedure.clone())
                else {
                    self.note(Incompleteness::Interior {
                        cause: super::IncompleteCause::Content,
                        procedure: key.procedure.clone(),
                        reason: "component observation has no live procedure handle".into(),
                    });
                    return Ok(());
                };
                let site = handle
                    .semantics()
                    .call_site(location.call)
                    .expect("a caller-side location names a call of its procedure");
                let value = call_input_value(site, &location.actual)
                    .expect("a caller-side location is rooted at a call input of its call");
                self.written_location(
                    id,
                    &handle,
                    value,
                    site.point,
                    &location.selectors,
                    location.tail,
                    Some(location.call),
                    request,
                )
            }
            Endpoint::Sink(sink) => {
                let spec = self
                    .value_flow
                    .expect("value observation has a value plan")
                    .sink(*sink)
                    .expect("a sink item names a sink of its plan");
                let ValueFlowCarrier::Location(location) = spec.carrier() else {
                    return Ok(());
                };
                let AccessPathRoot::Value(value) = location.path().root() else {
                    return Ok(());
                };
                let handle = spec.point().procedure().clone();
                let selectors = heap_selectors(location.path().selectors());
                self.written_location(
                    id,
                    &handle,
                    value.id(),
                    spec.point().id(),
                    &selectors,
                    location.path().tail(),
                    None,
                    request,
                )
            }
            Endpoint::Port(PartialFlowPort::Capture { .. }) => self.closure(id, request),
            _ => Ok(()),
        }
    }

    fn note_model_content_refusal(
        &mut self,
        call: &DurableCallSiteKey,
        model: &CallModel<L::Function>,
        dispatch: &DispatchAnswer,
        reason: ModelOutputRefusal,
        request: &mut SemanticRequest<'_>,
    ) {
        // The missing capability is a verdict about the selected model
        // only when its provider records that input for this consult.
        // Union every contributing typed cause before report retention;
        // a content certificate cannot erase an operational dependency.
        // A refused demand remains incomplete even when another path reaches
        // the sink: silently dropping a sibling demand is no proof (#12846).
        let mut causes = vec![self.provider.certify_model_content_refusal(request)];
        if let Completeness::Incomplete { cause, .. } = &model.completeness
            && !causes.contains(cause)
        {
            causes.push(*cause);
        }
        if let Some(cause) = dispatch.incomplete_cause
            && !causes.contains(&cause)
        {
            causes.push(cause);
        }
        let operational = causes
            .iter()
            .any(|cause| matches!(cause, super::IncompleteCause::Operational(_)));
        for cause in causes {
            if operational && cause == super::IncompleteCause::Content {
                continue;
            }
            self.note(Incompleteness::Model {
                cause,
                call: call.clone(),
                reason: reason.reason().into(),
            });
        }
    }

    /// A projected caller input can be rooted in a crossed call's return.
    /// Read existing call/reader-origin evidence only; never infer ownership
    /// from a shared type or from an unrelated call on the path.
    fn crossed_returned_members(
        &self,
        procedure: &DurableProcedureKey,
        call: CallSiteId,
        target: &Endpoint,
    ) -> Option<Vec<PartialFlowPort>> {
        if let Endpoint::Port(port @ PartialFlowPort::Heap { root, .. }) = target {
            return matches!(root.as_ref(), PartialFlowPort::CallResult { call: owner, .. }
                if *owner == call)
            .then(|| vec![port.clone()]);
        }
        let handle = &self.inputs.handles.get(procedure)?.procedure;
        let semantic = handle.semantics();
        let (actual, selectors, tail, reader) = match target {
            Endpoint::Location(location) => {
                let consumer = semantic.call_site(location.call)?;
                (
                    call_input_value(consumer, &location.actual)?,
                    location.selectors.clone(),
                    location.tail,
                    Some(location),
                )
            }
            Endpoint::Sink(sink) => {
                let spec = self.value_flow?.sink(*sink)?;
                let ValueFlowCarrier::Location(location) = spec.carrier() else {
                    return None;
                };
                let AccessPathRoot::Value(value) = location.path().root() else {
                    return None;
                };
                if value.procedure() != handle {
                    return None;
                }
                (
                    value.id(),
                    heap_selectors(location.path().selectors()),
                    location.path().tail(),
                    None,
                )
            }
            _ => return None,
        };
        let producer = semantic.call_site(call)?;
        let origins = reader
            .and_then(|location| {
                self.inputs
                    .modeled_reader_origins
                    .get(&(procedure.clone(), location.clone()))
            })
            .map_or(&[][..], Vec::as_slice);
        Some(returned_member_demands(
            handle, producer, actual, &selectors, tail, origins,
        ))
    }

    /// Backward through a call result: through the call's model when one
    /// replaces the call, otherwise into each candidate's return port and,
    /// when the dispatch has no candidate or is not complete, through the
    /// policy's unmodeled-call behavior.
    fn descend(
        &mut self,
        id: usize,
        call: CallSiteId,
        request: &mut SemanticRequest<'_>,
    ) -> Result<(), ComposeError> {
        let key = self.items[id].key.clone();
        let call_key = (key.procedure.clone(), call);
        self.linked(id, &call_key);
        let dispatch = self.dispatch(&call_key, request)?;
        if let Some(model) = self.model(&call_key, request)? {
            self.note_dispatch_incomplete(&call_key, &dispatch);
            let Endpoint::Port(output) = &key.node else {
                unreachable!("only call results descend")
            };
            if let Some(reason) =
                model.returned_member_refusal(output, self.inputs.endpoint_projections)
            {
                if !model.describes_returned_member(output, self.inputs.endpoint_projections) {
                    self.note_model_content_refusal(&call_key, &model, &dispatch, reason, request);
                    if !model.retains_dispatch {
                        return Ok(());
                    }
                } else {
                    self.apply_model(id, &call_key, &model, &dispatch, output, request)?;
                }
            } else {
                let Endpoint::Port(output) = &key.node else {
                    unreachable!()
                };
                self.apply_model(id, &call_key, &model, &dispatch, output, request)?;
            }
            if !model.retains_dispatch {
                return Ok(());
            }
        }
        let Endpoint::Port(result) = &key.node else {
            unreachable!("only call results descend");
        };
        if matches!(key.root, Root::Object(_))
            && matches!(result, PartialFlowPort::CallResult { .. })
        {
            for continuation in self
                .provider
                .unproven_object_continuations(&call_key, request)
                .map_err(|error| classified_provider_error(self.provider, error))?
            {
                let function = self.functions.intern(continuation.function);
                let function = self.functions.then(function, key.function);
                self.add_item(
                    key.procedure.clone(),
                    key.root.clone(),
                    continuation.from,
                    function,
                    self.items[id].quality.conjoin(continuation.quality),
                    Derivation::Step {
                        hops: Vec::new(),
                        next: id,
                    },
                );
            }
        }
        let mut object_handoffs = 0_usize;
        let mut absent_exits_complete = !dispatch.candidates.is_empty();
        for candidate in &dispatch.candidates {
            let exit = match result {
                PartialFlowPort::CallResult { .. } => {
                    Some(super::provider::CallHandoffExit::Normal)
                }
                PartialFlowPort::CallThrown { .. } => {
                    Some(super::provider::CallHandoffExit::Exceptional)
                }
                // A returned-member heap port also descends here. Its value
                // path uses returned_member_callee_ports below, not an object
                // handoff at the call's scalar continuation.
                PartialFlowPort::Heap { .. } => None,
                _ => unreachable!("only call continuations or returned members descend"),
            };
            if let Some(exit) = exit {
                let inventory = self
                    .provider
                    .call_handoffs(&call_key, candidate, exit, request)
                    .map_err(|error| classified_provider_error(self.provider, error))?;
                absent_exits_complete &= inventory.complete;
                for handoff in inventory.handoffs {
                    assert_eq!(handoff.binding.exit, exit);
                    assert!(
                        handoff.binding.argument_index < candidate.arguments.len(),
                        "a client handoff indexes its selected candidate"
                    );
                    if handoff.binding.continuity == super::provider::CallObjectContinuity::Copy {
                        continue;
                    }
                    object_handoffs += 1;
                    let handoff_quality =
                        handoff.binding.quality.conjoin(HopQuality::from_uncertain(
                            dispatch.uncertain
                                || dispatch.candidates.len() != 1
                                || !handoff.binding.continuity.is_exact(),
                        ));
                    let function = self.functions.intern(handoff.function);
                    self.add_item(
                        key.procedure.clone(),
                        key.root.clone(),
                        Endpoint::CallHandoff {
                            call,
                            candidate: Box::new((**candidate).clone()),
                            binding: handoff.binding,
                            function,
                            quality: handoff_quality,
                        },
                        key.function,
                        self.items[id].quality,
                        Derivation::Step {
                            hops: Vec::new(),
                            next: id,
                        },
                    );
                }
            }
            if !matches!(key.root, Root::Object(_)) {
                let rows = self
                    .provider
                    .partial_flows(&candidate.procedure, request)
                    .map_err(|error| classified_provider_error(self.provider, error))?;
                let callee_ports =
                    returned_member_callee_ports(candidate, result, &rows.ports, |declared| {
                        self.provider.canonical_returned_field(
                            &candidate.procedure,
                            &call_key.0,
                            declared,
                            request,
                        )
                    });
                for callee_port in callee_ports {
                    self.open_callee_root(
                        id,
                        &call_key,
                        candidate,
                        callee_port,
                        dispatch.uncertain,
                    );
                }
            }
        }
        if let Root::Object(root) = &key.root
            && object_handoffs == 0
            && let Some(gap) = &dispatch.external_body_unavailable
            && self
                .provider
                .certified_object_origin(root, &call_key, result, gap, request)
                .map_err(|error| classified_provider_error(self.provider, error))?
                .is_some()
        {
            return Ok(());
        }
        self.note_dispatch_incomplete(&call_key, &dispatch);
        if matches!(key.root, Root::Object(_))
            && ((object_handoffs == 0 && !absent_exits_complete) || dispatch.uncertain)
        {
            let Root::Object(root) = &key.root else {
                unreachable!()
            };
            self.note(Incompleteness::Object {
                cause: dispatch
                    .incomplete_cause
                    .unwrap_or(super::IncompleteCause::Content),
                anchor: root.clone(),
                reason: format!(
                    "call {} has unresolved or ambiguous dispatch",
                    call_site_text(&call_key)
                )
                .into(),
            });
        } else if dispatch.candidates.is_empty() || dispatch.uncertain {
            self.unmodeled(id, &call_key, request)?;
        }
        Ok(())
    }

    /// Bind a caller-side stored call heap port to each matching callee heap
    /// output. The producer publishes this port only for a call writeback;
    /// the search still checks each candidate's storage-sharing evidence.
    fn descend_heap(
        &mut self,
        id: usize,
        request: &mut SemanticRequest<'_>,
    ) -> Result<(), ComposeError> {
        let key = self.items[id].key.clone();
        let Endpoint::Port(PartialFlowPort::Heap {
            root,
            selectors,
            tail,
        }) = &key.node
        else {
            unreachable!("only a call heap port descends here");
        };
        let call = match root.as_ref() {
            PartialFlowPort::CallReceiver { call } | PartialFlowPort::CallArgument { call, .. } => {
                *call
            }
            _ => unreachable!("a caller heap port is rooted at a call input"),
        };
        let call_key = (key.procedure.clone(), call);
        let dispatch = self.dispatch_noted(&call_key, request)?;
        if let Some(model) = self.model(&call_key, request)? {
            for binding in model
                .writeback
                .iter()
                .filter(|binding| &binding.actual == root.as_ref())
            {
                match heap_sharing(binding, selectors, *tail) {
                    crate::analyzer::semantic::CallStorageSharing::Isolated => continue,
                    crate::analyzer::semantic::CallStorageSharing::Unknown => {
                        self.note(Incompleteness::Model {
                            cause: super::IncompleteCause::Operational(
                                super::OperationalCause::Provider,
                            ),
                            call: call_key.clone(),
                            reason: "a modeled heap output has unknown storage sharing".into(),
                        });
                        continue;
                    }
                    crate::analyzer::semantic::CallStorageSharing::Shares => {}
                }
                if !binding.complete {
                    self.note(Incompleteness::Model {
                        cause: super::IncompleteCause::Operational(
                            super::OperationalCause::Provider,
                        ),
                        call: call_key.clone(),
                        reason: "a modeled heap output has incomplete caller storage".into(),
                    });
                }
                if !binding.proven
                    || !binding.conversion_preserves_identity
                    || binding.storage.is_empty()
                {
                    self.note(Incompleteness::Model {
                        cause: super::IncompleteCause::Operational(
                            super::OperationalCause::Provider,
                        ),
                        call: call_key.clone(),
                        reason: "a modeled heap output has unproven shared storage".into(),
                    });
                    continue;
                }
                let Endpoint::Port(output) = &key.node else {
                    unreachable!()
                };
                self.apply_model(id, &call_key, &model, &dispatch, output, request)?;
            }
            if !model.retains_dispatch {
                return Ok(());
            }
        }
        for candidate in &dispatch.candidates {
            for binding in candidate
                .writeback
                .iter()
                .filter(|binding| &binding.actual == root.as_ref())
            {
                let sharing = heap_sharing(binding, selectors, *tail);
                match sharing {
                    crate::analyzer::semantic::CallStorageSharing::Isolated => continue,
                    crate::analyzer::semantic::CallStorageSharing::Unknown => {
                        self.note(Incompleteness::Dispatch {
                            cause: super::IncompleteCause::Content,
                            call: call_key.clone(),
                            reason: "a stored call heap port has unknown storage sharing".into(),
                        });
                    }
                    crate::analyzer::semantic::CallStorageSharing::Shares => {}
                }
                if !binding.proven
                    || !binding.complete
                    || !binding.conversion_preserves_identity
                    || binding.storage.is_empty()
                {
                    self.note(Incompleteness::Dispatch {
                        cause: super::IncompleteCause::Content,
                        call: call_key.clone(),
                        reason: "a stored call heap port has unproven shared storage".into(),
                    });
                    continue;
                }
                let heap = PartialFlowPort::Heap {
                    root: Box::new(binding.formal.clone()),
                    selectors: selectors.clone(),
                    tail: *tail,
                };
                let Some(data) = self.procedure(&candidate.procedure, request)? else {
                    continue;
                };
                if data.into.contains_key(&heap) {
                    self.open_callee_root(
                        id,
                        &call_key,
                        candidate,
                        heap,
                        dispatch.uncertain
                            || sharing == crate::analyzer::semantic::CallStorageSharing::Unknown,
                    );
                } else if data.flows.may_omit_flows() {
                    self.note(Incompleteness::Dispatch {
                        cause: super::IncompleteCause::Content,
                        call: call_key.clone(),
                        reason: "a callee heap output is not fully covered".into(),
                    });
                }
            }
        }
        if dispatch.candidates.is_empty() {
            self.note(Incompleteness::Dispatch {
                cause: super::IncompleteCause::Content,
                call: call_key.clone(),
                reason: "a post-call heap demand has no proven callee binding".into(),
            });
        }
        if dispatch.candidates.is_empty() || dispatch.uncertain {
            // Scalar fallback ports cannot describe a member of shared storage.
            // Still record the policy's unmodeled-call abstention when required.
            self.unmodeled(id, &call_key, request)?;
        }
        Ok(())
    }

    /// Backward through the matched transforms at `call` whose output is the
    /// item's node. Each is a flow beside the call's other edges, as the ICFG
    /// engine's policy-local relation is, so a model or a callee body does
    /// not replace it.
    fn linked(&mut self, id: usize, call: &DurableCallSiteKey) {
        let Some(links) = self.inputs.links.get(call).cloned() else {
            return;
        };
        let key = self.items[id].key.clone();
        let item_quality = self.items[id].quality;
        let Endpoint::Port(output) = &key.node else {
            unreachable!("only call results descend");
        };
        for link in links.into_iter().filter(|link| &link.output == output) {
            let hops = vec![link.hop];
            let along = self.functions.hops(&hops);
            let function = self.functions.then(along, key.function);
            let quality = Hop::path_quality(&hops).conjoin(item_quality);
            self.add_item(
                key.procedure.clone(),
                key.root.clone(),
                Endpoint::Port(link.input),
                function,
                quality,
                Derivation::Step { hops, next: id },
            );
        }
    }

    /// A call no model covers whose dispatch has no candidate or leaves a
    /// boundary beside its candidates, crossed as the ICFG engine crosses it
    /// (`ValueFlowPlan::visit_boundary_transfers`). Paranoid links the
    /// demanded result or thrown value to every call input with an
    /// uncertain hop. Optimistic adds nothing. Require-model adds nothing
    /// and records the abstention; in the ICFG engine an abstention only
    /// marks a fact kept on a call input uncertain, and the run's completion
    /// and diagnostics come from the call's dispatch, which the search
    /// already noted.
    fn unmodeled(
        &mut self,
        id: usize,
        call: &DurableCallSiteKey,
        request: &mut SemanticRequest<'_>,
    ) -> Result<(), ComposeError> {
        match self.provider.unmodeled_call_behavior() {
            UnmodeledCallBehavior::Optimistic => {}
            UnmodeledCallBehavior::RequireModel => {
                if self.abstained_seen.insert(call.clone()) {
                    self.abstained.push(call.clone());
                }
            }
            UnmodeledCallBehavior::Paranoid => {
                let key = self.items[id].key.clone();
                let Endpoint::Port(output) = &key.node else {
                    unreachable!("only call results descend");
                };
                let ports = self
                    .provider
                    .fallback_ports(call, request)
                    .map_err(|error| classified_provider_error(self.provider, error))?;
                if !ports.outputs.contains(output) {
                    return Ok(());
                }
                for input in ports.inputs.iter() {
                    let mut hops = vec![Hop::Unmodeled {
                        call: call.clone(),
                        input: input.clone(),
                        output: output.clone(),
                    }];
                    hops.extend(self.annotations_for(call, Some(input), &key.node));
                    let along = self.functions.hops(&hops);
                    let function = self.functions.then(along, key.function);
                    self.add_item(
                        key.procedure.clone(),
                        key.root.clone(),
                        Endpoint::Port(input.clone()),
                        function,
                        HopQuality::UNCERTAIN,
                        Derivation::Step { hops, next: id },
                    );
                }
            }
        }
        Ok(())
    }

    /// Open a callee root at `callee_port` for the item `id` waiting at the
    /// caller side of `call`, and apply what already reaches the root.
    fn open_callee_root(
        &mut self,
        id: usize,
        call: &DurableCallSiteKey,
        candidate: &Arc<DispatchCandidate>,
        callee_port: PartialFlowPort,
        uncertain: bool,
    ) {
        let root = Root::Port(
            Box::new((candidate.procedure.clone(), callee_port.clone())),
            self.items[id].key.certificate.clone(),
        );
        let waiter = CallWaiter {
            item: id,
            call: call.clone(),
            candidate: Arc::clone(candidate),
            callee_port: callee_port.clone(),
            uncertain,
        };
        if self.registered_call_waiters.insert((id, root.clone())) {
            self.call_waiters
                .entry(root.clone())
                .or_default()
                .push(waiter.clone());
        }
        self.add_item(
            candidate.procedure.clone(),
            root.clone(),
            Endpoint::Port(callee_port),
            LabelFunctionId::IDENTITY,
            HopQuality::CERTAIN,
            Derivation::Root,
        );
        for summary in self.summaries.get(&root).cloned().unwrap_or_default() {
            self.apply_summary(&waiter, summary);
        }
        for reach in self.reaches_by_root.get(&root).cloned().unwrap_or_default() {
            self.apply_reach(&waiter, reach);
        }
    }

    /// Backward from a demanded location rooted at `value` of the item's
    /// procedure: a callee may have written it through a call input bound to
    /// `value` (or to a value with the same binding origin). Only those
    /// calls are dispatched, and each candidate's `Heap` output port on the
    /// bound formal is opened as a callee root that returns to this call
    /// only. `excluded` is the call the location is observed at, whose own
    /// effects come after the observation.
    #[allow(
        clippy::too_many_arguments,
        reason = "the location is a value, its selectors and tail, and the call it is observed at"
    )]
    fn written_location(
        &mut self,
        id: usize,
        procedure: &ProcedureHandle,
        value: ValueId,
        read_point: ProgramPointId,
        selectors: &[HeapSelector],
        tail: AccessPathTail,
        excluded: Option<CallSiteId>,
        request: &mut SemanticRequest<'_>,
    ) -> Result<(), ComposeError> {
        // Storage origins matter only when a modeled writer could reach
        // this read. The local interior already accounts for ordinary reads.
        if self.inputs.endpoint_projections
            && !procedure.semantics().call_sites().iter().any(|call| {
                Some(call.id) != excluded
                    && self
                        .provider
                        .may_have_modeled_storage_output(procedure, call.id)
            })
        {
            return Ok(());
        }
        let origins = BindingOriginIndex::new(procedure);
        let origin = |value: ValueId| {
            origins
                .unique_binding_origin(value)
                .or_else(|| origins.addressed_binding_origins(value).unique_binding())
        };
        let wanted = origin(value);
        let caller = procedure.durable_key();
        let before_read = {
            let mut budget = CfgAlgorithmBudget::default();
            let mut reach_request = CfgAlgorithmRequest::new(&mut budget, request.cancellation);
            match reverse_reachability(procedure.semantics(), read_point, &mut reach_request) {
                Ok(reachable) => reachable,
                Err(error) => {
                    let (cause, reason) = reader_ordering_failure(error);
                    self.note(Incompleteness::Interior {
                        cause,
                        procedure: caller.clone(),
                        reason: reason.into(),
                    });
                    return Ok(());
                }
            }
        };
        // Ordinary callee reads and writes are already represented by the
        // stored partial-flow path. This extra search serves only a modeled
        // receiver input whose model did not publish a local body.
        let Some(read_call) = excluded else {
            return Ok(());
        };
        let read_key = (caller.clone(), read_call);
        let Some(read_model) = self.model(&read_key, request)? else {
            return Ok(());
        };
        let read_site = procedure
            .semantics()
            .call_site(read_call)
            .expect("a modeled receiver read names a live call");
        let mut reader_storage = read_model
            .receiver_reads
            .iter()
            .filter(|binding| call_input_value(read_site, &binding.actual) == Some(value))
            .flat_map(|binding| binding.storage.iter().cloned())
            .collect::<Vec<_>>();
        for (location, storage) in &self.inputs.modeled_reader_origins {
            if location.0 == caller
                && location.1.call == read_call
                && call_input_value(read_site, &location.1.actual) == Some(value)
                && location.1.selectors.as_ref() == selectors
                && location.1.tail == tail
            {
                for origin in storage {
                    if !reader_storage.contains(origin) {
                        reader_storage.push(origin.clone());
                    }
                }
            }
        }
        if reader_storage.is_empty() {
            self.note(Incompleteness::Model {
                cause: super::IncompleteCause::Operational(super::OperationalCause::Provider),
                call: read_key,
                reason: "a modeled receiver read has no proven caller storage".into(),
            });
            return Ok(());
        }
        for call in procedure.semantics().call_sites() {
            if Some(call.id) == excluded {
                continue;
            }
            if !self
                .provider
                .may_have_modeled_storage_output(procedure, call.id)
            {
                continue;
            }
            let call_key = (caller.clone(), call.id);
            let between = match call.normal_continuation {
                ControlContinuation::Target(point) => {
                    before_read.contains(procedure.semantics(), point)
                }
                ControlContinuation::Absent => false,
                _ => true,
            };
            if !between {
                continue;
            }
            let sharing = self
                .provider
                .call_input_storage_overlap(procedure, value, selectors, tail, call.id, request)
                .map_err(|error| classified_provider_error(self.provider, error))?;
            if sharing == CallStorageSharing::Isolated {
                continue;
            }
            // Selection may still reject a same-named summary. Only the
            // selected model's concrete receiver/argument outputs qualify.
            let (raw_dispatch, model) = self
                .provider
                .dispatch(&call_key, request)
                .map_err(|error| classified_provider_error(self.provider, error))?;
            let Some(model) = model.map(Arc::new) else {
                continue;
            };
            if model.writeback.is_empty() {
                continue;
            }
            if sharing == CallStorageSharing::Unknown {
                self.note(Incompleteness::Model {
                    cause: super::IncompleteCause::Operational(super::OperationalCause::Provider),
                    call: call_key.clone(),
                    reason: "a modeled writer's storage overlap is unknown".into(),
                });
                continue;
            }
            if !matches!(call.normal_continuation, ControlContinuation::Target(_)) {
                self.note(Incompleteness::Dispatch {
                    cause: super::IncompleteCause::Content,
                    call: call_key.clone(),
                    reason: "a modeled writer has no proven normal-return point".into(),
                });
                continue;
            }
            if !raw_dispatch.completeness.is_complete() {
                self.note(Incompleteness::Dispatch {
                    cause: match &raw_dispatch.completeness {
                        Completeness::Incomplete { cause, .. } => *cause,
                        Completeness::Complete => unreachable!("checked incomplete dispatch"),
                    },
                    call: call_key.clone(),
                    reason: "a modeled writer's dispatch is incomplete".into(),
                });
            }
            for binding in model.writeback.iter() {
                let may_reach_read = binding.storage.iter().any(|storage| {
                        matches!(storage.path().root(), AccessPathRoot::Value(root) if Some(root.id()) == wanted)
                            || reader_storage.contains(storage)
                    });
                if !may_reach_read {
                    if wanted.is_none() || !binding.complete {
                        self.note(Incompleteness::Model {
                            cause: super::IncompleteCause::Operational(
                                super::OperationalCause::Provider,
                            ),
                            call: call_key.clone(),
                            reason: "a model output has unmapped caller storage".into(),
                        });
                    }
                    continue;
                }
                match heap_sharing(binding, selectors, tail) {
                    crate::analyzer::semantic::CallStorageSharing::Isolated => continue,
                    crate::analyzer::semantic::CallStorageSharing::Unknown => {
                        self.note(Incompleteness::Model {
                            cause: super::IncompleteCause::Operational(
                                super::OperationalCause::Provider,
                            ),
                            call: call_key.clone(),
                            reason: "a model output has unknown storage sharing".into(),
                        });
                        continue;
                    }
                    crate::analyzer::semantic::CallStorageSharing::Shares => {}
                }
                if !binding.complete {
                    self.note(Incompleteness::Model {
                        cause: super::IncompleteCause::Operational(
                            super::OperationalCause::Provider,
                        ),
                        call: call_key.clone(),
                        reason: "a model output has incomplete caller storage".into(),
                    });
                }
                if !binding.proven
                    || !binding.conversion_preserves_identity
                    || binding.storage.is_empty()
                {
                    self.note(Incompleteness::Model {
                        cause: super::IncompleteCause::Operational(
                            super::OperationalCause::Provider,
                        ),
                        call: call_key.clone(),
                        reason: "a model output has unproven shared storage".into(),
                    });
                    continue;
                }
                for storage in &binding.storage {
                    let value_origin_matches = matches!(storage.path().root(),
                            AccessPathRoot::Value(root) if Some(root.id()) == wanted);
                    if !value_origin_matches && !reader_storage.contains(storage) {
                        continue;
                    }
                    if !storage.path().selectors().is_empty() {
                        self.note(Incompleteness::Model {
                            cause: super::IncompleteCause::Operational(
                                super::OperationalCause::Provider,
                            ),
                            call: call_key.clone(),
                            reason: "a model output location cannot be substituted".into(),
                        });
                        continue;
                    }
                    let heap = PartialFlowPort::Heap {
                        root: Box::new(binding.actual.clone()),
                        selectors: selectors.into(),
                        tail,
                    };
                    let dispatch = self.dispatch_noted(&call_key, request)?;
                    self.model(&call_key, request)?;
                    self.apply_model(id, &call_key, &model, &dispatch, &heap, request)?;
                }
            }
        }
        Ok(())
    }

    /// A model replaces the call: link its output to the caller-side
    /// inputs its transfers read. A model that covers the call is not a
    /// boundary, so its hops are uncertain only through the model itself.
    fn apply_model(
        &mut self,
        id: usize,
        call: &DurableCallSiteKey,
        model: &CallModel<L::Function>,
        dispatch: &DispatchAnswer,
        output: &PartialFlowPort,
        request: &mut SemanticRequest<'_>,
    ) -> Result<(), ComposeError> {
        let key = self.items[id].key.clone();
        let item_quality = self.items[id].quality;
        for transfer in &model.transfers {
            let actual = if self.inputs.endpoint_projections {
                match projected_model_actual(transfer, output) {
                    Ok(Some(actual)) => actual,
                    Ok(None) => continue,
                    Err(reason) => {
                        self.note_model_content_refusal(call, model, dispatch, reason, request);
                        continue;
                    }
                }
            } else {
                let matches_output = &transfer.output == output
                    || matches!(output, PartialFlowPort::Heap { root, .. } if root.as_ref() == &transfer.output);
                if !matches_output {
                    continue;
                }
                transfer.actual.clone()
            };
            let mut actuals = vec![actual.clone()];
            // A whole input consumes known components of the same aggregate,
            // independently of projected siblings. Observe concrete members at invocation rather than
            // collapsing them into a shared whole-value fact, which would
            // contaminate the projected sibling and survive child overwrites.
            if self.inputs.endpoint_projections
                && matches!(
                    actual,
                    PartialFlowPort::CallReceiver { .. } | PartialFlowPort::CallArgument { .. }
                )
            {
                'components: {
                    let Some(handle) = self
                        .inputs
                        .handles
                        .get(&key.procedure)
                        .map(|input| input.procedure.clone())
                    else {
                        self.note(Incompleteness::Model {
                            cause: super::IncompleteCause::Content,
                            call: call.clone(),
                            reason: "component input binding has no live procedure handle".into(),
                        });
                        break 'components;
                    };
                    let reads_projected_sibling = model.endpoint_projections
                        && model.transfers.iter().any(|transfer| {
                            matches!(
                            &transfer.actual, PartialFlowPort::Heap { root, .. }
                                if root.as_ref() == &actual)
                        });
                    let mut produced_locations = Vec::new();
                    let mut proven_modeled_locations = Vec::new();
                    for row in handle.semantics().call_sites() {
                        let Some(producer) =
                            self.model_for_discovery(&(key.procedure.clone(), row.id), request)?
                        else {
                            continue;
                        };
                        if !producer.endpoint_projections {
                            continue;
                        }
                        let first_produced = produced_locations.len();
                        for produced in &producer.transfers {
                            if let Some(InteriorSeed::Source {
                                carrier: ValueFlowCarrier::Location(location),
                                ..
                            }) =
                                crate::composition::projected_return_seed(&handle, &produced.output)
                            {
                                produced_locations.push(*location);
                            }
                            if let PartialFlowPort::Heap {
                                root,
                                selectors,
                                tail,
                            } = &produced.output
                            {
                                for binding in producer
                                    .writeback
                                    .iter()
                                    .filter(|binding| &binding.actual == root.as_ref())
                                {
                                    if !binding.proven
                                        || !binding.complete
                                        || !binding.conversion_preserves_identity
                                        || heap_sharing(binding, selectors, *tail)
                                            != CallStorageSharing::Shares
                                    {
                                        continue;
                                    }
                                    for origin in &binding.storage {
                                        if let Some(location) = crate::analyzer::semantic::partial_flow::caller_exact_read_location(
                                            &handle, origin, selectors, *tail) { produced_locations.push(location); }
                                    }
                                }
                            }
                        }
                        let quality = producer.quality();
                        if quality.proven && quality.complete {
                            proven_modeled_locations
                                .extend(produced_locations[first_produced..].iter().cloned());
                        }
                    }
                    // One owner observes native and modeled components. A
                    // schema-35 whole consumer needs this even without a
                    // modeled producer; legacy calls retain lazy behavior.
                    if produced_locations.is_empty() && !reads_projected_sibling {
                        break 'components;
                    }
                    let quality = model.quality();
                    if !produced_locations.is_empty() && (!quality.proven || !quality.complete) {
                        self.note(Incompleteness::Model {
                            cause: super::IncompleteCause::Content,
                            call: call.clone(),
                            reason:
                                "component consumption requires a proven complete input binding"
                                    .into(),
                        });
                        break 'components;
                    }
                    let answer = match self
                        .provider
                        .modeled_input_locations(&handle, call.1, &actual, request)
                    {
                        Ok(answer) => answer,
                        Err(error) => {
                            self.note(Incompleteness::Model {
                                cause: super::IncompleteCause::Operational(
                                    super::OperationalCause::Provider,
                                ),
                                call: call.clone(),
                                reason: format!("modeled input origins failed: {error}").into(),
                            });
                            None
                        }
                    };
                    if let Some(answer) = &answer {
                        // Every actual origin needs membership evidence. A
                        // known component on one alias branch cannot classify
                        // another branch, and complete producers cannot repair
                        // weak or dropped native observations.
                        let membership_known = !answer.locations.is_empty()
                            && answer.locations.iter().all(|origin| origin.proven_complete
                                && answer.components.iter().filter(|member| member.proven_complete)
                                    .map(|member| &member.location)
                                    .chain(proven_modeled_locations.iter())
                                    .any(|member| crate::analyzer::semantic::partial_flow::exact_location_covers_read(&origin.location, member)));
                        if !answer.complete
                            || (reads_projected_sibling
                                && (!answer.components_complete || !membership_known))
                        {
                            self.note(Incompleteness::Model {
                                cause: super::IncompleteCause::Content,
                                call: call.clone(),
                                reason: "modeled whole-input component membership is incomplete"
                                    .into(),
                            });
                        }
                        if reads_projected_sibling {
                            produced_locations.extend(
                                answer
                                    .components
                                    .iter()
                                    .filter(|item| item.proven_complete)
                                    .map(|item| item.location.clone()),
                            );
                        }
                    }
                    if !produced_locations.is_empty() && (!quality.proven || !quality.complete) {
                        self.note(Incompleteness::Model {
                            cause: super::IncompleteCause::Content,
                            call: call.clone(),
                            reason:
                                "component consumption requires a proven complete input binding"
                                    .into(),
                        });
                        break 'components;
                    }
                    let origins = match &answer {
                        Some(answer) => answer.locations.iter().filter(|origin| origin.proven_complete).map(|origin| &origin.location).collect::<Vec<_>>(),
                        None if model.endpoint_projections && model.transfers.iter().any(|transfer|
                            matches!(&transfer.actual, PartialFlowPort::Heap { root, .. } if root.as_ref() == &actual)) => model.receiver_reads.iter()
                                .filter(|binding| binding.actual == actual).flat_map(|binding| binding.storage.iter()).collect(),
                        None => Vec::new(),
                    };
                    for produced_location in produced_locations {
                        for origin in &origins {
                            if !crate::analyzer::semantic::partial_flow::exact_location_covers_read(
                                origin,
                                &produced_location,
                            ) {
                                continue;
                            }
                            let Some(selectors) =
                                crate::semantic_summary::substitute_projection_prefix(
                                    &heap_selectors(produced_location.path().selectors()),
                                    &heap_selectors(origin.path().selectors()),
                                    &[],
                                )
                            else {
                                continue;
                            };
                            if selectors.is_empty() {
                                continue;
                            }
                            let component = PartialFlowPort::Heap {
                                root: Box::new(actual.clone()),
                                selectors: selectors.into_boxed_slice(),
                                tail: AccessPathTail::Exact,
                            };
                            let PartialFlowPort::Heap {
                                root,
                                selectors,
                                tail,
                            } = &component
                            else {
                                unreachable!("component input is a heap port");
                            };
                            let origin_key = (
                                key.procedure.clone(),
                                CallerLocation {
                                    call: call.1,
                                    actual: *root.clone(),
                                    selectors: selectors.clone(),
                                    tail: *tail,
                                },
                            );
                            if !self
                                .inputs
                                .modeled_reader_origins
                                .get(&origin_key)
                                .is_some_and(|storage| storage.contains(origin))
                            {
                                if self.items.len()
                                    + self.reaches.len()
                                    + self.execution_reaches.len()
                                    + self.execution_procedure_reaches.len()
                                    + self.modeled_reader_origin_count
                                    >= self.budget.max_hops
                                {
                                    self.exhaust(BudgetLane::Hops);
                                    self.stopped = true;
                                    return Ok(());
                                }
                                self.inputs
                                    .modeled_reader_origins
                                    .entry(origin_key)
                                    .or_default()
                                    .push((*origin).clone());
                                self.modeled_reader_origin_count += 1;
                            }
                            if !actuals.contains(&component) {
                                actuals.push(component);
                            }
                        }
                    }
                }
            }

            for actual in actuals {
                let model_function = transfer.function.clone();
                let hop = Hop::Model {
                    call: call.clone(),
                    actual: actual.clone(),
                    result: output.clone(),
                    summary: model.summary.clone().map(Box::new),
                    retains_dispatch: model.retains_dispatch,
                    function: self.functions.intern(model_function),
                    quality: if model.retains_dispatch {
                        HopQuality::new(transfer.proven, false)
                    } else {
                        model.quality()
                    },
                };
                let mut hops = vec![hop];
                hops.extend(self.annotations_for(call, Some(&actual), &key.node));
                let along = self.functions.hops(&hops);
                let function = self.functions.then(along, key.function);
                let quality = Hop::path_quality(&hops).conjoin(item_quality);
                self.add_item(
                    key.procedure.clone(),
                    key.root.clone(),
                    match actual {
                        PartialFlowPort::Heap {
                            root,
                            selectors,
                            tail,
                        } if self.inputs.endpoint_projections
                            && matches!(
                                root.as_ref(),
                                PartialFlowPort::CallReceiver { .. }
                                    | PartialFlowPort::CallArgument { .. }
                            ) =>
                        {
                            Endpoint::Location(CallerLocation {
                                call: call.1,
                                actual: *root,
                                selectors,
                                tail,
                            })
                        }
                        actual => Endpoint::Port(actual),
                    },
                    function,
                    quality,
                    Derivation::Step { hops, next: id },
                );
            }
        }
        Ok(())
    }

    /// A callee formal reached a callee root: map it back through the call
    /// that opened the root.
    fn apply_summary(&mut self, waiter: &CallWaiter, summary: usize) {
        let inner = &self.items[summary];
        let Endpoint::Port(formal) = &inner.key.node else {
            unreachable!("a summary item is at a formal");
        };
        let formal = formal.clone();
        let inner_function = inner.key.function;
        let inner_quality = inner.quality;
        let next = self.items[waiter.item].key.clone();
        let next_quality = self.items[waiter.item].quality;
        for (actual, caller_node) in caller_side(&waiter.candidate, waiter.call.1, &formal) {
            let (caller_function, caller_quality) = self.call_boundary_label(
                &waiter.call,
                &waiter.candidate.procedure,
                &Endpoint::Port(actual.clone()),
                &Endpoint::Port(formal.clone()),
            );
            let (callee_function, callee_quality) = self.call_boundary_label(
                &waiter.call,
                &waiter.candidate.procedure,
                &Endpoint::Port(waiter.callee_port.clone()),
                &next.node,
            );
            let caller = Hop::Caller {
                call: waiter.call.clone(),
                callee: waiter.candidate.procedure.clone(),
                actual: actual.clone(),
                formal: formal.clone(),
                uncertain: waiter.uncertain || !caller_quality.is_certain(),
                function: caller_function,
            };
            let callee = Hop::Callee {
                call: waiter.call.clone(),
                callee: waiter.candidate.procedure.clone(),
                from: waiter.callee_port.clone(),
                to: next.node.clone(),
                uncertain: waiter.uncertain || !callee_quality.is_certain(),
                function: callee_function,
            };
            let annotations = self.annotations_for(&waiter.call, Some(&actual), &next.node);
            let along = self.functions.hops(&annotations);
            let along = self.functions.then(callee_function, along);
            let along = self.functions.then(inner_function, along);
            let along = self.functions.then(caller_function, along);
            let function = self.functions.then(along, next.function);
            let quality = HopQuality::from_uncertain(waiter.uncertain)
                .conjoin(caller_quality)
                .conjoin(inner_quality)
                .conjoin(callee_quality)
                .conjoin(Hop::path_quality(&annotations))
                .conjoin(next_quality);
            self.add_item(
                next.procedure.clone(),
                next.root.clone(),
                caller_node,
                function,
                quality,
                Derivation::Summary(Box::new(SummaryStep {
                    caller,
                    inner: summary,
                    callee,
                    annotations,
                    next: waiter.item,
                })),
            );
        }
    }

    /// A source reached a callee root: it reaches the caller-side item that
    /// opened the root.
    fn apply_reach(&mut self, waiter: &CallWaiter, reach: usize) {
        let reached = &self.reaches[reach];
        let source = reached.key.source;
        let reach_function = reached.key.function;
        let reach_quality = reached.quality;
        let next = self.items[waiter.item].key.clone();
        let next_quality = self.items[waiter.item].quality;
        let (callee_function, callee_quality) = self.call_boundary_label(
            &waiter.call,
            &waiter.candidate.procedure,
            &Endpoint::Port(waiter.callee_port.clone()),
            &next.node,
        );
        let callee = Hop::Callee {
            call: waiter.call.clone(),
            callee: waiter.candidate.procedure.clone(),
            from: waiter.callee_port.clone(),
            to: next.node.clone(),
            uncertain: waiter.uncertain || !callee_quality.is_certain(),
            function: callee_function,
        };
        let mut hops = vec![callee];
        hops.extend(self.annotations_for(&waiter.call, None, &next.node));
        let along = self.functions.hops(&hops);
        let along = self.functions.then(reach_function, along);
        let function = self.functions.then(along, next.function);
        let quality = reach_quality
            .conjoin(callee_quality)
            .conjoin(Hop::path_quality(&hops))
            .conjoin(next_quality);
        self.add_reach(
            next.root,
            source,
            function,
            quality,
            ReachDerivation::Through {
                inner: reach,
                hops,
                next: waiter.item,
            },
        );
    }

    /// A formal or heap input port of the item's procedure: record a summary
    /// for a root of the same procedure, and leave through every caller for
    /// an unbalanced root. A heap input climbs to the caller-side location
    /// rooted at the actual, which the caller's interior run observes.
    fn formal(&mut self, id: usize, request: &mut SemanticRequest<'_>) -> Result<(), ComposeError> {
        let key = self.items[id].key.clone();
        let quality = self.items[id].quality;
        let Endpoint::Port(formal) = &key.node else {
            unreachable!("a formal item is at a port");
        };
        if let Root::Port(port, _) = &key.root
            && port.0 == key.procedure
        {
            if self.summary_items.insert(id) {
                self.summaries.entry(key.root.clone()).or_default().push(id);
            }
            for waiter in self
                .call_waiters
                .get(&key.root)
                .cloned()
                .unwrap_or_default()
            {
                self.apply_summary(&waiter, id);
            }
        }
        if !key.root.unbalanced() {
            return Ok(());
        }
        let anchored_caller = if self.certified_procedure_reaches.is_some() {
            key.certificate.as_ref().map(|certificate| {
                certificate.prefix.iter().rev().find_map(|step| {
                    (step.target == ExecutionTarget::Procedure(Box::new(key.procedure.clone())))
                        .then(|| step.call.clone())
                })
            })
        } else {
            None
        };
        let callers = match anchored_caller {
            Some(Some(call)) => vec![call],
            Some(None) => {
                // An admitted root has no caller prefix to leave through.
                return Ok(());
            }
            None => self.callers(&key.procedure, request)?.to_vec(),
        };
        for call in callers.iter() {
            let dispatch = self.dispatch_noted(call, request)?;
            for candidate in dispatch
                .candidates
                .iter()
                .filter(|candidate| candidate.procedure == key.procedure)
            {
                for (actual, caller_node) in caller_side(candidate, call.1, formal) {
                    let (caller_function, caller_quality) = self.call_boundary_label(
                        call,
                        &key.procedure,
                        &Endpoint::Port(actual.clone()),
                        &Endpoint::Port(formal.clone()),
                    );
                    let hop = Hop::Caller {
                        call: call.clone(),
                        callee: key.procedure.clone(),
                        actual,
                        formal: formal.clone(),
                        uncertain: dispatch.uncertain || !caller_quality.is_certain(),
                        function: caller_function,
                    };
                    let function = self.functions.then(caller_function, key.function);
                    self.add_item(
                        call.0.clone(),
                        key.root.clone(),
                        caller_node,
                        function,
                        HopQuality::from_uncertain(dispatch.uncertain)
                            .conjoin(caller_quality)
                            .conjoin(quality),
                        Derivation::Step {
                            hops: vec![hop],
                            next: id,
                        },
                    );
                }
            }
        }
        Ok(())
    }

    /// A capture slot of a closure: its value comes from the parent's
    /// capture binding for that slot.
    fn closure(
        &mut self,
        id: usize,
        request: &mut SemanticRequest<'_>,
    ) -> Result<(), ComposeError> {
        let key = self.items[id].key.clone();
        let quality = self.items[id].quality;
        let Endpoint::Port(slot @ PartialFlowPort::Capture { slot: destination }) = &key.node
        else {
            unreachable!("a closure item is at a capture slot");
        };
        let parent = match self.inputs.parents.get(&key.procedure) {
            Some(parent) => parent.clone(),
            None => {
                let parent = self
                    .provider
                    .lexical_parent(&key.procedure, request)
                    .map_err(|error| classified_provider_error(self.provider, error))?;
                self.inputs
                    .parents
                    .insert(key.procedure.clone(), parent.clone());
                parent
            }
        };
        let binding = PartialFlowPort::CaptureOut {
            target: key.procedure.1,
            destination: *destination,
        };
        let parent_data = match &parent {
            Some(parent) => self.procedure(parent, request)?,
            None => None,
        };
        let (Some(parent), Some(parent_data)) = (parent, parent_data) else {
            self.note(Incompleteness::MissingCaptureBinding {
                procedure: key.procedure.clone(),
                slot: slot.clone(),
            });
            return Ok(());
        };
        if !parent_data.flows.ports.contains(&binding) {
            self.note(Incompleteness::MissingCaptureBinding {
                procedure: key.procedure.clone(),
                slot: slot.clone(),
            });
            return Ok(());
        }
        let certified = self.certified_procedure_reaches.is_none()
            || key.certificate.as_ref().is_some_and(|certificate| {
                certificate.prefix.iter().rev().any(|step| {
                    step.target == ExecutionTarget::Procedure(Box::new(key.procedure.clone()))
                        && step.instance.as_ref().is_some_and(|instance| {
                            instance.producer == parent
                                && instance.capture_bindings.iter().any(|row| {
                                    row.target == key.procedure.1 && row.destination == *destination
                                })
                        })
                })
            });
        if !certified {
            self.note(Incompleteness::Execution {
                cause: super::IncompleteCause::Operational(super::OperationalCause::Provider),
                procedure: key.procedure.clone(),
                reason: "capture hop has no equal invoked instance and binding".into(),
            });
        }
        let quality = quality.conjoin(HopQuality::from_uncertain(!certified));
        let hop = Hop::Closure {
            parent: parent.clone(),
            closure: key.procedure.clone(),
            binding: binding.clone(),
            slot: slot.clone(),
            uncertain: !certified,
            certificate: key.certificate.clone(),
        };
        if key.root.unbalanced() {
            self.add_item(
                parent,
                key.root.clone(),
                Endpoint::Port(binding),
                key.function,
                quality,
                Derivation::Step {
                    hops: vec![hop],
                    next: id,
                },
            );
            return Ok(());
        }
        // A balanced root cannot leave through the parent's callers on its
        // own: open the parent's capture binding as a root of its own.
        let root = Root::Port(
            Box::new((parent.clone(), binding.clone())),
            key.certificate.clone(),
        );
        if self.registered_capture_waiters.insert((id, root.clone())) {
            self.capture_waiters
                .entry(root.clone())
                .or_default()
                .push(CaptureWaiter {
                    item: id,
                    hop: hop.clone(),
                });
        }
        self.add_item(
            parent,
            root.clone(),
            Endpoint::Port(binding),
            LabelFunctionId::IDENTITY,
            HopQuality::CERTAIN,
            Derivation::Root,
        );
        let waiter = CaptureWaiter { item: id, hop };
        for reach in self.reaches_by_root.get(&root).cloned().unwrap_or_default() {
            self.apply_capture_reach(&waiter, reach);
        }
        Ok(())
    }

    fn apply_capture_reach(&mut self, waiter: &CaptureWaiter, reach: usize) {
        let reached = &self.reaches[reach];
        let source = reached.key.source;
        let function = self
            .functions
            .then(reached.key.function, self.items[waiter.item].key.function);
        let quality = reached
            .quality
            .conjoin(self.items[waiter.item].quality)
            .conjoin(Hop::path_quality(std::slice::from_ref(&waiter.hop)));
        let root = self.items[waiter.item].key.root.clone();
        self.add_reach(
            root,
            source,
            function,
            quality,
            ReachDerivation::Through {
                inner: reach,
                hops: vec![waiter.hop.clone()],
                next: waiter.item,
            },
        );
    }

    fn process_reach(&mut self, id: usize) {
        let root = self.reaches[id].key.root.clone();
        if matches!(root, Root::Sink(..)) {
            return;
        }
        for waiter in self.call_waiters.get(&root).cloned().unwrap_or_default() {
            self.apply_reach(&waiter, id);
        }
        for waiter in self.capture_waiters.get(&root).cloned().unwrap_or_default() {
            self.apply_capture_reach(&waiter, id);
        }
        for waiter in self.store_waiters.get(&root).cloned().unwrap_or_default() {
            self.apply_store_reach(&waiter, id);
        }
    }

    /// A read output demands every may-alias write observation. The root is
    /// separate from ordinary procedure output roots, so cycles have no
    /// origin unless a source independently reaches one of their writes.
    fn open_store_read(&mut self, item: usize, output: &PartialFlowPort) {
        let procedure = self.items[item].key.procedure.clone();
        let links = self.provider.store_links(&procedure, output);
        if let Some(reason) = links.incomplete {
            self.note(Incompleteness::StoreInventory {
                cause: super::IncompleteCause::Operational(super::OperationalCause::Provider),
                procedure,
                reason,
            });
        }
        for link in links.writes {
            assert!(
                link.write < self.inputs.store_writes.len(),
                "a store link names a selected write"
            );
            let root = Root::StoreWrite(link.write);
            let waiter = StoreWaiter { item, link };
            if self.registered_store_waiters.insert((item, root.clone())) {
                self.store_waiters
                    .entry(root.clone())
                    .or_default()
                    .push(waiter.clone());
            }
            let write = &self.inputs.store_writes[waiter.link.write];
            self.add_item(
                write.procedure.clone(),
                root.clone(),
                Endpoint::StoreWrite(waiter.link.write),
                LabelFunctionId::IDENTITY,
                HopQuality::CERTAIN,
                Derivation::Root,
            );
            for reach in self.reaches_by_root.get(&root).cloned().unwrap_or_default() {
                self.apply_store_reach(&waiter, reach);
            }
        }
    }

    /// A reached write grows the linked read with its original source,
    /// classes, quality, and both sides of the witness path.
    fn apply_store_reach(&mut self, waiter: &StoreWaiter, reach: usize) {
        let inner = &self.reaches[reach];
        let outer = &self.items[waiter.item];
        let hop = Hop::Store {
            write_call: waiter.link.write_call.clone(),
            read_call: waiter.link.read_call.clone(),
            write_site: Box::new(waiter.link.write_site.clone()),
            read_site: Box::new(waiter.link.read_site.clone()),
            read_origin: waiter.link.read_origin.clone(),
            read_phase: waiter.link.read_phase,
            read_carrier: waiter.link.read_carrier.clone(),
            uncertain: waiter.link.uncertain,
        };
        let function = self.functions.then(inner.key.function, outer.key.function);
        let inner = &self.reaches[reach];
        let outer = &self.items[waiter.item];
        self.add_reach(
            outer.key.root.clone(),
            inner.key.source,
            function,
            inner.quality.conjoin(hop.quality()).conjoin(outer.quality),
            ReachDerivation::Through {
                inner: reach,
                hops: vec![hop],
                next: waiter.item,
            },
        );
    }

    /// The hops of one reach's path, from its source to its root: a certain
    /// path when present, else a proven path, else a complete path, else its first.
    fn reach_path(&self, reach: usize) -> Vec<Hop> {
        enum Piece<'p> {
            Reach(usize),
            Item(usize),
            Hops(&'p [Hop]),
            Hop(&'p Hop),
        }
        let quality = self.reaches[reach].quality;
        let chain = if quality.is_certain() {
            Chain::Certain
        } else if quality.proven {
            Chain::Proven
        } else if quality.complete {
            Chain::Complete
        } else {
            Chain::First
        };
        let mut hops = Vec::new();
        let mut stack = vec![Piece::Reach(reach)];
        while let Some(piece) = stack.pop() {
            match piece {
                Piece::Hop(hop) => hops.push(hop.clone()),
                Piece::Hops(run) => hops.extend(run.iter().cloned()),
                Piece::Reach(id) => match self.reaches[id].derivations.get(chain) {
                    ReachDerivation::Direct { hops, next } => {
                        stack.push(Piece::Item(*next));
                        stack.push(Piece::Hops(hops));
                    }
                    ReachDerivation::Through { inner, hops, next } => {
                        stack.push(Piece::Item(*next));
                        stack.push(Piece::Hops(hops));
                        stack.push(Piece::Reach(*inner));
                    }
                },
                Piece::Item(id) => match self.items[id].derivations.get(chain) {
                    Derivation::Root => {}
                    Derivation::Step { hops, next } => {
                        stack.push(Piece::Item(*next));
                        stack.push(Piece::Hops(hops));
                    }
                    Derivation::Summary(summary) => {
                        let SummaryStep {
                            caller,
                            inner,
                            callee,
                            annotations,
                            next,
                        } = summary.as_ref();
                        stack.push(Piece::Item(*next));
                        stack.push(Piece::Hops(annotations));
                        stack.push(Piece::Hop(callee));
                        stack.push(Piece::Item(*inner));
                        stack.push(Piece::Hop(caller));
                    }
                },
            }
        }
        hops
    }

    /// Group the reaches of sink roots into source-sink pairs, one path per
    /// distinct label function, in plan order.
    fn pairs(&self) -> Vec<SourceSinkPair> {
        self.refined_pairs
            .clone()
            .unwrap_or_else(|| self.current_pairs())
    }

    fn current_pairs(&self) -> Vec<SourceSinkPair> {
        let mut by_pair: HashMap<
            (
                ValueFlowSinkId,
                ComposedSourceId,
                Option<ExecutionCertificate>,
            ),
            Vec<usize>,
        > = HashMap::default();
        let mut keys = Vec::new();
        for (id, reach) in self.reaches.iter().enumerate() {
            if !reach.active {
                continue;
            }
            if let Root::Sink(sink, certificate) = &reach.key.root {
                let key = (*sink, reach.key.source, certificate.clone());
                if !by_pair.contains_key(&key) {
                    keys.push(key.clone());
                }
                by_pair.entry(key).or_default().push(id);
            }
        }
        keys.sort_by_key(|(sink, source, _)| (*sink, *source));
        keys.into_iter()
            .map(|(sink, source, certificate)| {
                let reaches = &by_pair[&(sink, source, certificate.clone())];
                SourceSinkPair {
                    source,
                    sink,
                    certificate,
                    paths: reaches
                        .iter()
                        .map(|&reach| (self.reach_path(reach), self.reaches[reach].quality))
                        .collect(),
                }
            })
            .collect()
    }
}

/// The quality of an endpoint's selector evidence, axis by axis.
pub(super) fn evidence_quality(
    proof: &ProofStatus,
    completeness: &EvidenceCompleteness,
) -> HopQuality {
    HopQuality::new(
        matches!(proof, ProofStatus::Proven),
        matches!(completeness, EvidenceCompleteness::Complete),
    )
}

/// Names a call site by its file and its procedure-local ids. A durable call
/// key also carries the workspace mount and artifact fingerprints, and replayed
/// diagnostic text must not depend on the mount.
fn call_site_text(((artifact, procedure, _interpretation), call): &DurableCallSiteKey) -> String {
    format!("{} {procedure:?} {call:?}", artifact.path())
}

/// Whether a value enters the procedure's interior at this port.
fn heap_sharing(
    binding: &super::provider::WritebackBinding,
    selectors: &[HeapSelector],
    tail: AccessPathTail,
) -> crate::analyzer::semantic::CallStorageSharing {
    if tail == AccessPathTail::Exact
        && matches!(selectors, [HeapSelector::Field(field)] if binding.direct_fields.contains(field))
    {
        binding.direct_field_sharing
    } else {
        binding.shares_storage
    }
}

fn is_input_port(port: &PartialFlowPort) -> bool {
    matches!(
        port,
        PartialFlowPort::Capture { .. }
            | PartialFlowPort::CallResult { .. }
            | PartialFlowPort::CallThrown { .. }
    ) || is_formal_or_heap_input(port)
        || matches!(port, PartialFlowPort::Heap { root, .. }
            if matches!(root.as_ref(), PartialFlowPort::CallResult { .. }))
}

/// Match the selected call result to its callee return, preserving the member
/// path. The return pairing supplies the boundary proof; the path is content,
/// not an alias certificate for the callee's storage.
fn returned_member_callee_ports(
    candidate: &DispatchCandidate,
    result: &PartialFlowPort,
    ports: &[PartialFlowPort],
    mut canonical_field: impl FnMut(
        &crate::analyzer::semantic::SemanticLocator,
    ) -> Option<crate::analyzer::semantic::SemanticLocator>,
) -> Vec<PartialFlowPort> {
    candidate
        .returns
        .iter()
        .filter_map(|(returned, caller)| match result {
            PartialFlowPort::Heap {
                root,
                selectors,
                tail,
            } if root.as_ref() == caller
                && matches!(
                    returned,
                    PartialFlowPort::NormalReturn | PartialFlowPort::IndexedNormalReturn { .. }
                ) =>
            {
                Some(
                    ports
                        .iter()
                        .filter(|port| {
                            bound_return_member_matches(result, port, caller, returned, |field| {
                                canonical_field(field)
                            })
                        })
                        .cloned()
                        .collect::<Vec<_>>(),
                )
            }
            _ if caller == result => Some(vec![returned.clone()]),
            _ => None,
        })
        .flatten()
        .collect()
}

/// A formal (receiver or parameter), or a heap input port rooted at one. A
/// value reaches either from the caller's side of a call.
fn is_formal_or_heap_input(port: &PartialFlowPort) -> bool {
    match port {
        PartialFlowPort::Receiver | PartialFlowPort::Parameter { .. } => true,
        PartialFlowPort::Heap { root, .. } => matches!(
            root.as_ref(),
            PartialFlowPort::Receiver | PartialFlowPort::Parameter { .. }
        ),
        _ => false,
    }
}

/// The caller-side positions of a callee formal or heap input port at one
/// call: the actual bound to the formal, or the location rooted at that
/// actual with the heap port's selectors. Each comes with its actual port.
fn caller_side(
    candidate: &DispatchCandidate,
    call: CallSiteId,
    port: &PartialFlowPort,
) -> Vec<(PartialFlowPort, Endpoint)> {
    let (formal, heap) = match port {
        PartialFlowPort::Heap {
            root,
            selectors,
            tail,
        } => (root.as_ref(), Some((selectors, *tail))),
        formal => (formal, None),
    };
    candidate
        .arguments
        .iter()
        .filter(|(_, bound)| bound == formal)
        .map(|(actual, _)| {
            let node = match &heap {
                None => Endpoint::Port(actual.clone()),
                Some((selectors, tail)) => Endpoint::Location(CallerLocation {
                    call,
                    actual: actual.clone(),
                    selectors: (*selectors).clone(),
                    tail: *tail,
                }),
            };
            (actual.clone(), node)
        })
        .collect()
}

/// Place an in-place matched-value transfer on every call use of its value,
/// and a two-carrier transfer on the one call whose ports carry both.
/// `input` and `output` are its carriers; an in-place binding sits on
/// whichever one call port its carrier is. `point` names the procedure.
fn place_transfer(
    point: &ProgramPointHandle,
    input: &ValueFlowCarrier,
    output: &ValueFlowCarrier,
    hop_for: impl Fn(DurableCallSiteKey) -> Hop,
) -> Vec<(DurableCallSiteKey, Annotation)> {
    let procedure = point.procedure().durable_key();
    let value_of = |carrier: &ValueFlowCarrier| match carrier {
        ValueFlowCarrier::Value(value) => Some(value.id()),
        _ => None,
    };
    let semantics = point.procedure().semantics();
    // Ports alone place a transfer; the selected observation point only
    // determines phase. Every use of an in-place matched value follows its
    // definition, even at a different point. A two-carrier transfer's output
    // is a value that exactly one call defines, and its observation point is
    // the output's: a result of a call with arguments is observed at the
    // call's normal continuation, not at the call's own point (#9987).
    let mut placements = Vec::new();
    for call in semantics.call_sites() {
        let input_port = value_of(input).and_then(|value| call_input_port(call, value));
        let output_port = value_of(output).and_then(|value| call_output_port(call, value));
        let placement = match (input == output, input_port, output_port) {
            (false, Some(input_port), Some(output_port)) => (Some(input_port), Some(output_port)),
            (true, Some(input_port), None) => (Some(input_port), None),
            (true, None, Some(output_port)) => (None, Some(output_port)),
            _ => continue,
        };
        let key = (procedure.clone(), call.id);
        placements.push((
            key.clone(),
            Annotation {
                input: placement.0,
                output: placement.1,
                hop: hop_for(key),
            },
        ));
    }
    debug_assert!(
        input == output || placements.len() <= 1,
        "a call output value has exactly one defining call"
    );
    placements
}

/// Map a reader-relative projection back to every owning return path.
/// Dropping an alias prefix can certify a sibling transfer instead (#12846).
pub(super) fn returned_member_demands(
    procedure: &ProcedureHandle,
    producer: &SemanticCallSite,
    actual: ValueId,
    selectors: &[HeapSelector],
    tail: AccessPathTail,
    origins: &[AbstractLocation],
) -> Vec<PartialFlowPort> {
    let mut demands = Vec::new();
    let mut add = |value, prefix: &[HeapSelector], origin_tail| {
        if prefix.is_empty()
            && selectors.is_empty()
            && origin_tail == AccessPathTail::Exact
            && tail == AccessPathTail::Exact
        {
            return;
        }
        let Some(root @ PartialFlowPort::CallResult { .. }) = call_output_port(producer, value)
        else {
            return;
        };
        let demand = PartialFlowPort::Heap {
            root: Box::new(root),
            // A summary boundary precedes the relative read. Moving that
            // read before the unknown suffix would certify a narrower member.
            selectors: if origin_tail == AccessPathTail::Summary {
                prefix.into()
            } else {
                prefix.iter().chain(selectors).cloned().collect()
            },
            tail: if tail == AccessPathTail::Summary || origin_tail == AccessPathTail::Summary {
                AccessPathTail::Summary
            } else {
                AccessPathTail::Exact
            },
        };
        if !demands.contains(&demand) {
            demands.push(demand);
        }
    };
    // The direct value is its own path; alias prefixes belong only to their
    // recorded origins, never to this independently known identity.
    add(actual, &[], AccessPathTail::Exact);
    for origin in origins {
        if let AccessPathRoot::Value(value) = origin.path().root()
            && value.procedure() == procedure
        {
            add(
                value.id(),
                &heap_selectors(origin.path().selectors()),
                origin.path().tail(),
            );
        }
    }
    demands
}

fn call_input_port(call: &SemanticCallSite, value: ValueId) -> Option<PartialFlowPort> {
    if call.receiver == Some(value) {
        return Some(PartialFlowPort::CallReceiver { call: call.id });
    }
    call.arguments
        .iter()
        .position(|argument| argument.value == value)
        .map(|ordinal| PartialFlowPort::CallArgument {
            call: call.id,
            ordinal: u32::try_from(ordinal).expect("a call's argument count fits u32"),
        })
}

fn call_output_port(call: &SemanticCallSite, value: ValueId) -> Option<PartialFlowPort> {
    if call.result == Some(value) {
        return Some(PartialFlowPort::CallResult {
            call: call.id,
            ordinal: None,
        });
    }
    if call.thrown == Some(value) {
        return Some(PartialFlowPort::CallThrown { call: call.id });
    }
    call.normal_results
        .iter()
        .position(|&result| result == value)
        .map(|ordinal| PartialFlowPort::CallResult {
            call: call.id,
            ordinal: Some(u32::try_from(ordinal).expect("a call's result count fits u32")),
        })
}

impl<Fact, Function> SearchInputs<Fact, Function> {
    pub(super) fn discard_indexes(&mut self) {
        for data in self.procedures.values_mut().flatten() {
            let data = Arc::get_mut(data).expect("search owns its procedure cache after finishing");
            data.into = HashMap::default();
        }
        for data in self.interiors.values_mut().flatten() {
            let data = Arc::get_mut(data).expect("search owns its interior cache after finishing");
            data.into = HashMap::default();
        }
        for data in self.location_interiors.values_mut() {
            data.reaching = None;
        }
    }
}

#[cfg(test)]
mod reader_ordering_tests {
    use super::*;
    use crate::analyzer::semantic::cfg_algorithms::{
        CfgAlgorithmBudgetExceeded, CfgAlgorithmLimit, CfgAlgorithmWork,
    };
    use brokk_bifrost_test_macros::hardwon;

    #[test]
    #[hardwon("#12107: interrupted reader ordering proofs lost their typed CFG execution cause")]
    fn reader_ordering_preserves_typed_stops() {
        let cases = [
            (
                CfgAlgorithmError::InvalidNode(0u32),
                super::super::OperationalCause::Provider,
            ),
            (
                CfgAlgorithmError::Cancelled {
                    work: CfgAlgorithmWork::default(),
                },
                super::super::OperationalCause::Cancelled,
            ),
            (
                CfgAlgorithmError::ExceededBudget(CfgAlgorithmBudgetExceeded {
                    limit_kind: CfgAlgorithmLimit::NodeVisits,
                    limit: 0,
                    attempted: 1,
                    work: CfgAlgorithmWork::default(),
                }),
                super::super::OperationalCause::Budget(BudgetLane::Semantic),
            ),
        ];
        for (error, expected) in cases {
            let (cause, _) = reader_ordering_failure(error);
            assert_eq!(cause, super::super::IncompleteCause::Operational(expected));
        }
    }
}
