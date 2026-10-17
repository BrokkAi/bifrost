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

use std::sync::Arc;

use crate::analyzer::semantic::icfg::invoked_call_at;
use crate::analyzer::semantic::partial_flow::{
    CrossedCalls, HeapSelector, PartialFlowOutcome, PartialFlowPort, ProcedurePartialFlows,
    call_input_value, heap_selectors,
};
use crate::analyzer::semantic::{
    AccessPathRoot, AccessPathTail, BindingOriginIndex, CallSiteId, EvidenceCompleteness,
    ProcedureHandle, ProgramPointHandle, ProofStatus, SemanticCallSite, SemanticRequest, ValueId,
};
use crate::dataflow::{SemanticInputStatus, UnmodeledCallBehavior};
use crate::hash::{HashMap, HashSet};
use crate::taint::{TaintAnalysisPlan, TaintEdgeFunction};
use crate::value_flow::{
    DurableCallSiteKey, DurableProcedureKey, ValueFlowCarrier, ValueFlowObservationPhase,
    ValueFlowSinkId,
};

use super::graph::{ComposedSourceId, Endpoint, Hop, HopQuality};
use super::labels::{hops_function, label_classes};
use super::provider::{
    BlockedGap, BoundSanitizer, BoundSource, BoundTransform, CallModel, CallerLocation,
    Completeness, CompositionProvider, DispatchCandidate, EndpointEvidence, InteriorObservation,
    InteriorSeed, InteriorTarget, Openness,
};
use super::{ComposeError, CompositionBudget};

/// A source that reaches a sink, with one path per distinct label function.
/// Each path comes with the best quality of the paths that share its label
/// function; the path itself is one of them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceSinkPair {
    pub source: ComposedSourceId,
    pub sink: ValueFlowSinkId,
    pub paths: Vec<(Vec<Hop>, HopQuality)>,
}

/// A budget lane of [`CompositionBudget`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BudgetLane {
    Procedures,
    Hops,
    CallersPerProcedure,
}

/// Why the composed result may miss a flow.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Incompleteness {
    /// A dispatch on the frontier was open, unproven or exceeded.
    Dispatch {
        call: DurableCallSiteKey,
        reason: Box<str>,
    },
    /// An incoming-call enumeration was truncated or incomplete.
    Callers {
        procedure: DurableProcedureKey,
        reason: Box<str>,
    },
    /// A model replaced a call but is not complete.
    Model {
        call: DurableCallSiteKey,
        reason: Box<str>,
    },
    /// An interior run was not complete.
    Interior {
        procedure: DurableProcedureKey,
        reason: Box<str>,
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
    },
    /// A source, of the plan or matched on the frontier, at `point` whose
    /// selector evidence is not proven and complete, as the ICFG engine's
    /// plan reports it.
    SourceEvidence { point: ProgramPointHandle },
    /// A bound sink of the plan at `point` whose selector evidence is not
    /// proven and complete.
    SinkEvidence { point: ProgramPointHandle },
    /// A budget lane was exhausted.
    Budget(BudgetLane),
    /// The request was cancelled.
    Cancelled,
}

/// The result of stage 1.
#[derive(Debug, Clone)]
pub struct SearchOutcome {
    pub pairs: Vec<SourceSinkPair>,
    pub strict_pairs: Vec<SourceSinkPair>,
    /// The source table the pairs index: the plan's sources, then those the
    /// provider matched on the frontier.
    pub sources: Vec<BoundSource>,
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
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Root {
    Sink(ValueFlowSinkId),
    Port(Box<(DurableProcedureKey, PartialFlowPort)>),
}

impl Root {
    /// A root whose demand is not tied to one call: reaching a formal leaves
    /// the procedure through every caller.
    fn unbalanced(&self) -> bool {
        match self {
            Self::Sink(_) => true,
            Self::Port(port) => matches!(port.1, PartialFlowPort::CaptureOut { .. }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ItemKey {
    procedure: DurableProcedureKey,
    root: Root,
    node: Endpoint,
    /// Label function of the path from `node` to `root`.
    function: TaintEdgeFunction,
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
}

/// Which derivations a path reconstruction follows.
#[derive(Debug, Clone, Copy)]
enum Chain {
    First,
    Proven,
    Complete,
}

impl<D: Clone> Derivations<D> {
    fn new(quality: HopQuality, derivation: D) -> Self {
        Self {
            proven: quality.proven.then(|| derivation.clone()),
            complete: quality.complete.then(|| derivation.clone()),
            first: derivation,
        }
    }

    /// Record a derivation of `quality` for a holder whose quality is `held`.
    /// Returns whether it gave the holder an axis it lacked.
    fn improve(&mut self, held: HopQuality, quality: HopQuality, derivation: D) -> bool {
        let proven = quality.proven && !held.proven;
        let complete = quality.complete && !held.complete;
        if proven {
            self.proven = Some(derivation.clone());
        }
        if complete {
            self.complete = Some(derivation);
        }
        proven || complete
    }

    fn get(&self, chain: Chain) -> &D {
        match chain {
            Chain::First => &self.first,
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
    /// Label function of the path from the source to the root.
    function: TaintEdgeFunction,
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

/// One flow into a position of a procedure: where it starts, whether its
/// relations are uncertain, and the calls its path classes crossed.
#[derive(Debug, Clone)]
struct Inflow<From> {
    from: From,
    uncertain: bool,
    crossed: CrossedCalls,
}

#[derive(Debug)]
struct ProcedureData {
    flows: Arc<ProcedurePartialFlows>,
    /// Stored flows by target port.
    into: HashMap<PartialFlowPort, Vec<Inflow<PartialFlowPort>>>,
}

/// The seeds that reach one interior target.
type Reaching = Arc<[Inflow<Endpoint>]>;

/// Interior flows of one procedure by target.
#[derive(Debug, Default)]
struct InteriorIndex {
    into: HashMap<Endpoint, Vec<Inflow<Endpoint>>>,
}

#[derive(Debug)]
struct DispatchAnswer {
    candidates: Vec<Arc<DispatchCandidate>>,
    uncertain: bool,
    /// The best quality of the call's own continuation edges.
    continuation: HopQuality,
}

/// A sanitizer or transform placed on the ports of one call. `None` matches
/// any input or output.
#[derive(Debug, Clone)]
struct Annotation {
    input: Option<PartialFlowPort>,
    output: Option<PartialFlowPort>,
    hop: Hop,
}

/// A matched transform: its own flow from a call input to a call output.
#[derive(Debug, Clone)]
struct Link {
    input: PartialFlowPort,
    output: PartialFlowPort,
    hop: Hop,
}

#[derive(Debug, Clone, Copy)]
enum Work {
    Item(usize),
    Reach(usize),
}

struct Search<'a, Provider: CompositionProvider> {
    plan: &'a TaintAnalysisPlan,
    provider: &'a Provider,
    budget: CompositionBudget,
    identity: TaintEdgeFunction,
    /// Every source the search can reach: the plan's, then those matched on
    /// the frontier.
    sources: Vec<BoundSource>,
    sources_in: HashMap<DurableProcedureKey, Vec<ComposedSourceId>>,
    sinks_in: HashMap<DurableProcedureKey, Vec<ValueFlowSinkId>>,
    annotations: HashMap<DurableCallSiteKey, Vec<Annotation>>,
    links: HashMap<DurableCallSiteKey, Vec<Link>>,
    /// Whether every sanitizer placed so far is resolved.
    sanitizers_resolved: bool,
    procedures: HashMap<DurableProcedureKey, Option<Arc<ProcedureData>>>,
    /// Procedures in the order their flows were read.
    visited: Vec<DurableProcedureKey>,
    interiors: HashMap<DurableProcedureKey, Option<Arc<InteriorIndex>>>,
    location_interiors: HashMap<(DurableProcedureKey, CallerLocation), Reaching>,
    /// Live handles of procedures an interior run has served.
    handles: HashMap<DurableProcedureKey, ProcedureHandle>,
    dispatches: HashMap<DurableCallSiteKey, Arc<DispatchAnswer>>,
    models: HashMap<DurableCallSiteKey, Option<Arc<CallModel>>>,
    callers: HashMap<DurableProcedureKey, Arc<[DurableCallSiteKey]>>,
    parents: HashMap<DurableProcedureKey, Option<DurableProcedureKey>>,
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

/// Run stage 1 over every bound sink of the plan.
pub(super) fn search_pairs<Provider: CompositionProvider>(
    plan: &TaintAnalysisPlan,
    provider: &Provider,
    budget: CompositionBudget,
    request: &mut SemanticRequest<'_>,
) -> Result<SearchOutcome, ComposeError> {
    let mut search = Search::new(plan, provider, budget);
    // Every bound endpoint must carry proven and complete selector evidence,
    // as the ICFG engine's plan requires of its endpoints, whether or not a
    // path reaches them. The plan's sources are noted as `Search::new` adds
    // them, and a source matched on the frontier as the search enters its
    // procedure.
    for (_, spec) in plan.value_flow().sinks() {
        if !evidence_quality(spec.proof(), spec.completeness()).is_certain() {
            search.note(Incompleteness::SinkEvidence {
                point: spec.point().clone(),
            });
        }
    }
    for binding in plan.sinks() {
        let sink = binding.sink();
        let spec = plan
            .value_flow()
            .sink(sink)
            .expect("a sink binding names a sink of its plan");
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
        let identity = search.identity.clone();
        search.add_item(
            procedure,
            Root::Sink(sink),
            Endpoint::Sink(sink),
            identity,
            quality,
            Derivation::Root,
        );
    }
    while let Some(work) = search.work.pop() {
        if search.stopped {
            break;
        }
        if request.cancellation.is_cancelled() {
            search.note(Incompleteness::Cancelled);
            break;
        }
        match work {
            Work::Item(item) => search.process_item(item, request)?,
            Work::Reach(reach) => search.process_reach(reach),
        }
    }
    for procedure in search.visited.clone() {
        if let Openness::Open {
            residual,
            blocked,
            status,
            reason,
        } = provider
            .openness(&procedure, request)
            .map_err(provider_error)?
        {
            search.note(Incompleteness::Open {
                procedure,
                residual,
                blocked,
                status,
                reason,
            });
        }
    }
    // Refinement uses recorded derivations only. It cannot spend a fresh
    // topology budget or discover another source, edge or procedure.
    if provider.has_value_type_barriers() {
        search.refine(request)?;
    }
    let stats = SearchStats {
        recorded_supports: search.recorded_supports,
        recorded_edges: search.recorded_edges,
        chop_procedures: search.chop_procedures,
        extra_proof_lookups: search.extra_proof_lookups,
        changed_edge_qualities: search.changed_edge_qualities,
        baseline_candidate_pairs: search.baseline_candidate_pairs,
        strict_replays: search.strict_replays,
        procedures: search.visited.len(),
        hops: search.items.len() + search.reaches.len(),
        dispatches: search.dispatches.len(),
        callers: search.callers.values().map(|calls| calls.len()).sum(),
    };
    Ok(SearchOutcome {
        pairs: search.pairs(),
        strict_pairs: search.strict_pairs,
        sources: search.sources,
        sanitizers_resolved: search.sanitizers_resolved,
        incomplete: search.incomplete,
        abstained: search.abstained,
        stats,
        barrier_notes: search.barrier_notes,
    })
}

pub(super) fn provider_error(error: impl std::fmt::Display) -> ComposeError {
    ComposeError::Provider(error.to_string().into_boxed_str())
}

impl<'a, Provider: CompositionProvider> Search<'a, Provider> {
    fn new(plan: &'a TaintAnalysisPlan, provider: &'a Provider, budget: CompositionBudget) -> Self {
        let mut sinks_in: HashMap<DurableProcedureKey, Vec<ValueFlowSinkId>> = HashMap::default();
        for binding in plan.sinks() {
            let spec = plan
                .value_flow()
                .sink(binding.sink())
                .expect("a sink binding names a sink of its plan");
            sinks_in
                .entry(spec.point().procedure().durable_key())
                .or_default()
                .push(binding.sink());
        }
        let mut search = Self {
            plan,
            provider,
            budget,
            identity: TaintEdgeFunction::identity(plan.universe()),
            sources: Vec::new(),
            sources_in: HashMap::default(),
            sinks_in,
            annotations: HashMap::default(),
            links: HashMap::default(),
            sanitizers_resolved: true,
            procedures: HashMap::default(),
            visited: Vec::new(),
            interiors: HashMap::default(),
            location_interiors: HashMap::default(),
            handles: HashMap::default(),
            dispatches: HashMap::default(),
            models: HashMap::default(),
            callers: HashMap::default(),
            parents: HashMap::default(),
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
        for binding in plan.sources() {
            let spec = plan
                .value_flow()
                .source(binding.source())
                .expect("a source binding names a source of its plan");
            search.add_source(BoundSource {
                point: spec.point().clone(),
                phase: spec.phase(),
                carrier: spec.carrier().clone(),
                classes: binding.classes().clone(),
                origin: binding.origin().clone(),
                evidence: EndpointEvidence::Known(evidence_quality(
                    spec.proof(),
                    spec.completeness(),
                )),
            });
        }
        search.place_annotations();
        search
    }

    fn add_source(&mut self, source: BoundSource) {
        if matches!(source.evidence, EndpointEvidence::Known(quality) if !quality.is_certain()) {
            self.note(Incompleteness::SourceEvidence {
                point: source.point.clone(),
            });
        }
        let id = ComposedSourceId(
            u32::try_from(self.sources.len()).expect("a composition's sources fit u32"),
        );
        self.sources_in
            .entry(source.point.procedure().durable_key())
            .or_default()
            .push(id);
        self.sources.push(source);
    }

    /// Ask the provider for the endpoints of a procedure the search enters
    /// for the first time: sources become seeds of its interior runs,
    /// sanitizers annotate the hops through their calls, and transforms
    /// become flows of their own at their calls.
    fn enter(
        &mut self,
        procedure: &DurableProcedureKey,
        request: &mut SemanticRequest<'_>,
    ) -> Result<(), ComposeError> {
        let endpoints = self
            .provider
            .endpoints(procedure, request)
            .map_err(provider_error)?;
        if let Completeness::Incomplete { reason } = endpoints.completeness {
            self.note(Incompleteness::Endpoints {
                procedure: procedure.clone(),
                reason,
            });
        }
        for source in endpoints.sources {
            assert_eq!(
                &source.point.procedure().durable_key(),
                procedure,
                "a provider answers the endpoints of the procedure it was asked about"
            );
            self.add_source(source);
        }
        for sanitizer in endpoints.sanitizers {
            self.place_sanitizer(&sanitizer);
        }
        for transform in endpoints.transforms {
            self.place_link(&transform);
        }
        Ok(())
    }

    fn note(&mut self, reason: Incompleteness) {
        if self.incomplete_seen.insert(reason.clone()) {
            self.incomplete.push(reason);
        }
    }

    /// Place every sanitizer and in-place transform of the plan on the ports
    /// of the call whose input or output carrier it binds.
    fn place_annotations(&mut self) {
        let plan = self.plan;
        let carrier = |id| {
            plan.value_flow()
                .carrier(id)
                .expect("a bound carrier is a carrier of its plan")
                .clone()
        };
        for sanitizer in plan.sanitizers() {
            self.place_sanitizer(&BoundSanitizer {
                point: sanitizer.point().clone(),
                input: carrier(sanitizer.carrier()),
                output: carrier(sanitizer.output()),
                removed: sanitizer.removed().clone(),
                proven: sanitizer.is_proven(),
                resolved: sanitizer.is_resolved(),
            });
        }
        for transform in plan.transforms() {
            let hop_for = |call: DurableCallSiteKey| Hop::Transform {
                call,
                function: transform.function().clone(),
                uncertain: false,
            };
            let carrier = carrier(transform.carrier());
            let placed = place_transfer(transform.point(), &carrier, &carrier, hop_for);
            self.annotate_many(placed, transform.point(), &carrier);
        }
    }

    /// Place one sanitizer on the ports of the call whose input or output
    /// carrier it binds. A sanitizer that is not resolved leaves the run
    /// incomplete.
    fn place_sanitizer(&mut self, sanitizer: &BoundSanitizer) {
        self.sanitizers_resolved &= sanitizer.resolved;
        let hop_for = |call: DurableCallSiteKey| Hop::Sanitizer {
            call,
            removed: sanitizer.removed.clone(),
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
    fn place_link(&mut self, transform: &BoundTransform) {
        let hop_for = |call: DurableCallSiteKey| Hop::Transform {
            call,
            function: transform.function.clone(),
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
                self.links
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
            self.annotations.entry(call).or_default().push(annotation);
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
        self.annotations
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
            .plan
            .value_flow()
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
            let Some(annotations) = self.annotations.get(&(procedure.clone(), call.id)) else {
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
        function: TaintEdgeFunction,
        quality: HopQuality,
        derivation: Derivation,
    ) {
        let key = ItemKey {
            procedure,
            root,
            node,
            function,
        };
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
        if self.items.len() + self.reaches.len() >= self.budget.max_hops {
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
        function: TaintEdgeFunction,
        quality: HopQuality,
        derivation: ReachDerivation,
    ) {
        let key = ReachKey {
            root,
            source,
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
        if self.items.len() + self.reaches.len() >= self.budget.max_hops {
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
    ) -> Result<Option<Arc<ProcedureData>>, ComposeError> {
        if let Some(data) = self.procedures.get(procedure) {
            return Ok(data.clone());
        }
        if self.visited.len() >= self.budget.max_procedures {
            self.exhaust(BudgetLane::Procedures);
            self.procedures.insert(procedure.clone(), None);
            return Ok(None);
        }
        let flows = self
            .provider
            .partial_flows(procedure, request)
            .map_err(provider_error)?;
        if flows.outcome != PartialFlowOutcome::Complete {
            self.note(Incompleteness::PartialFlows {
                procedure: procedure.clone(),
                outcome: flows.outcome,
            });
        }
        let mut into: HashMap<PartialFlowPort, Vec<Inflow<PartialFlowPort>>> = HashMap::default();
        for flow in &flows.flows {
            into.entry(flows.ports[flow.to.index()].clone())
                .or_default()
                .push(Inflow {
                    from: flows.ports[flow.from.index()].clone(),
                    uncertain: flow.uncertain,
                    crossed: flow.crossed.clone(),
                });
        }
        let data = Arc::new(ProcedureData { flows, into });
        self.visited.push(procedure.clone());
        self.procedures
            .insert(procedure.clone(), Some(Arc::clone(&data)));
        self.enter(procedure, request)?;
        Ok(Some(data))
    }

    fn dispatch(
        &mut self,
        call: &DurableCallSiteKey,
        request: &mut SemanticRequest<'_>,
    ) -> Result<Arc<DispatchAnswer>, ComposeError> {
        if let Some(answer) = self.dispatches.get(call) {
            return Ok(Arc::clone(answer));
        }
        let dispatch = self
            .provider
            .dispatch(call, request)
            .map_err(provider_error)?;
        let uncertain = match dispatch.completeness {
            Completeness::Complete => false,
            Completeness::Incomplete { reason } => {
                self.note(Incompleteness::Dispatch {
                    call: call.clone(),
                    reason,
                });
                true
            }
        };
        let answer = Arc::new(DispatchAnswer {
            candidates: dispatch.candidates.into_iter().map(Arc::new).collect(),
            uncertain,
            continuation: dispatch.continuation,
        });
        self.dispatches.insert(call.clone(), Arc::clone(&answer));
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
    /// quality is best, counting proof and completeness alike. A witness
    /// names the calls of one path, and this is the class a path of the
    /// flow's best quality takes when one class gives both axes.
    fn flow_quality(
        &mut self,
        procedure: &DurableProcedureKey,
        uncertain: bool,
        crossed: &[Box<[CallSiteId]>],
        request: &mut SemanticRequest<'_>,
    ) -> Result<(HopQuality, Box<[CallSiteId]>), ComposeError> {
        assert!(!crossed.is_empty(), "a flow has at least one path class");
        let score = |quality: HopQuality| u8::from(quality.proven) + u8::from(quality.complete);
        let mut best = HopQuality::UNCERTAIN;
        let mut named: Option<(HopQuality, &Box<[CallSiteId]>)> = None;
        for class in crossed {
            let mut quality = HopQuality::CERTAIN;
            for &call in class.iter() {
                let dispatch = self.dispatch(&(procedure.clone(), call), request)?;
                quality = quality.conjoin(dispatch.continuation);
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

    fn model(&mut self, call: &DurableCallSiteKey) -> Option<Arc<CallModel>> {
        if let Some(model) = self.models.get(call) {
            return model.clone();
        }
        let model = self.provider.model(call).map(Arc::new);
        if let Some(model) = &model
            && let Completeness::Incomplete { reason } = &model.completeness
        {
            self.note(Incompleteness::Model {
                call: call.clone(),
                reason: reason.clone(),
            });
        }
        self.models.insert(call.clone(), model.clone());
        model
    }

    fn callers(
        &mut self,
        procedure: &DurableProcedureKey,
        request: &mut SemanticRequest<'_>,
    ) -> Result<Arc<[DurableCallSiteKey]>, ComposeError> {
        if let Some(callers) = self.callers.get(procedure) {
            return Ok(Arc::clone(callers));
        }
        let mut answer = self
            .provider
            .callers(procedure, request)
            .map_err(provider_error)?;
        if let Completeness::Incomplete { reason } = answer.completeness {
            self.note(Incompleteness::Callers {
                procedure: procedure.clone(),
                reason,
            });
        }
        if answer.calls.len() > self.budget.max_callers_per_procedure {
            answer.calls.truncate(self.budget.max_callers_per_procedure);
            self.exhaust(BudgetLane::CallersPerProcedure);
        }
        let callers: Arc<[DurableCallSiteKey]> = answer.calls.into();
        self.callers.insert(procedure.clone(), Arc::clone(&callers));
        Ok(callers)
    }

    /// The seeds of an interior run of `procedure`: its bound sources and,
    /// when `with_ports`, its input ports.
    fn interior_seeds(
        &self,
        procedure: &DurableProcedureKey,
        data: &ProcedureData,
        with_ports: bool,
    ) -> (Vec<InteriorSeed>, Vec<Endpoint>) {
        let mut seeds = Vec::new();
        let mut ends = Vec::new();
        for &id in self.sources_in.get(procedure).into_iter().flatten() {
            let source = &self.sources[id.index()];
            seeds.push(InteriorSeed::Source {
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

    /// Run one interior run and note its incompleteness.
    fn run_interior(
        &mut self,
        procedure: &DurableProcedureKey,
        seeds: &[InteriorSeed],
        observations: &[InteriorObservation],
        request: &mut SemanticRequest<'_>,
    ) -> Result<Vec<super::provider::InteriorFlow>, ComposeError> {
        let flows = self
            .provider
            .interior_flows(procedure, seeds, observations, false, request)
            .map_err(provider_error)?;
        if let Completeness::Incomplete { reason } = flows.completeness {
            self.note(Incompleteness::Interior {
                procedure: procedure.clone(),
                reason,
            });
        }
        self.handles.insert(procedure.clone(), flows.procedure);
        Ok(flows.flows)
    }

    /// The interior flows of one procedure, run once with its sources and,
    /// when it holds a sink, its input ports as seeds. `None` when the
    /// procedure has neither sources nor sinks.
    fn interior(
        &mut self,
        procedure: &DurableProcedureKey,
        data: &ProcedureData,
        request: &mut SemanticRequest<'_>,
    ) -> Result<Option<Arc<InteriorIndex>>, ComposeError> {
        if let Some(interior) = self.interiors.get(procedure) {
            return Ok(interior.clone());
        }
        let sinks = self.sinks_in.get(procedure).cloned().unwrap_or_default();
        if sinks.is_empty() && !self.sources_in.contains_key(procedure) {
            self.interiors.insert(procedure.clone(), None);
            return Ok(None);
        }
        let (seeds, seed_ends) = self.interior_seeds(procedure, data, !sinks.is_empty());
        let value_flow = self.plan.value_flow();
        let observations = sinks
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
        let mut index = InteriorIndex::default();
        for flow in self.run_interior(procedure, &seeds, &observations, request)? {
            let seed = seed_ends[flow.seed].clone();
            let target = match flow.target {
                InteriorTarget::Observation(observation) => Endpoint::Sink(sinks[observation]),
                // Port-to-port flows are the stored flows.
                InteriorTarget::Port(_) if matches!(seed, Endpoint::Port(_)) => continue,
                InteriorTarget::Port(port) => Endpoint::Port(port),
            };
            index.into.entry(target).or_default().push(Inflow {
                from: seed,
                uncertain: flow.uncertain,
                crossed: flow.crossed,
            });
        }
        let index = Arc::new(index);
        self.interiors
            .insert(procedure.clone(), Some(Arc::clone(&index)));
        Ok(Some(index))
    }

    /// What reaches one caller-side location of `procedure`: an interior run
    /// seeded at its sources and input ports, observing that location. Run
    /// once per location.
    fn location_interior(
        &mut self,
        procedure: &DurableProcedureKey,
        data: &ProcedureData,
        location: &CallerLocation,
        request: &mut SemanticRequest<'_>,
    ) -> Result<Reaching, ComposeError> {
        let key = (procedure.clone(), location.clone());
        if let Some(reaching) = self.location_interiors.get(&key) {
            return Ok(Arc::clone(reaching));
        }
        let (seeds, seed_ends) = self.interior_seeds(procedure, data, true);
        let observations = [InteriorObservation::Location(location.clone())];
        let reaching: Reaching = self
            .run_interior(procedure, &seeds, &observations, request)?
            .into_iter()
            .filter(|flow| flow.target == InteriorTarget::Observation(0))
            .map(|flow| Inflow {
                from: seed_ends[flow.seed].clone(),
                uncertain: flow.uncertain,
                crossed: flow.crossed,
            })
            .collect();
        self.location_interiors.insert(key, Arc::clone(&reaching));
        Ok(reaching)
    }

    fn process_item(
        &mut self,
        id: usize,
        request: &mut SemanticRequest<'_>,
    ) -> Result<(), ComposeError> {
        let key = self.items[id].key.clone();
        let quality = self.items[id].quality;
        let Some(data) = self.procedure(&key.procedure, request)? else {
            return Ok(());
        };
        if let Endpoint::Port(port) = &key.node {
            for flow in data.into.get(port).cloned().unwrap_or_default() {
                let (flow_quality, crossed) =
                    self.flow_quality(&key.procedure, flow.uncertain, &flow.crossed, request)?;
                let hop = Hop::Stored {
                    procedure: key.procedure.clone(),
                    from: flow.from.clone(),
                    to: port.clone(),
                    quality: flow_quality,
                    crossed,
                };
                self.add_item(
                    key.procedure.clone(),
                    key.root.clone(),
                    Endpoint::Port(flow.from),
                    key.function.clone(),
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
                let (flow_quality, crossed) =
                    self.flow_quality(&key.procedure, flow.uncertain, &flow.crossed, request)?;
                let seed = flow.from;
                let mut hops = vec![Hop::Interior {
                    procedure: key.procedure.clone(),
                    from: seed.clone(),
                    to: key.node.clone(),
                    quality: flow_quality,
                    crossed,
                }];
                hops.extend(sink_annotations.iter().cloned());
                let path_quality = Hop::path_quality(&hops).conjoin(quality);
                let function = hops_function(&hops, self.plan.universe()).compose(&key.function);
                match seed {
                    Endpoint::Source(source) => self.add_reach(
                        key.root.clone(),
                        source,
                        function,
                        path_quality.conjoin(match self.sources[source.index()].evidence {
                            EndpointEvidence::Known(quality) => quality,
                            // Judged at stage 3, for the sources that
                            // reach a sink.
                            EndpointEvidence::Unknown => HopQuality::CERTAIN,
                        }),
                        ReachDerivation::Direct { hops, next: id },
                    ),
                    Endpoint::Port(_) => self.add_item(
                        key.procedure.clone(),
                        key.root.clone(),
                        seed,
                        function,
                        path_quality,
                        Derivation::Step { hops, next: id },
                    ),
                    Endpoint::Sink(_) | Endpoint::Location(_) => {
                        unreachable!("sinks and locations are never interior seeds")
                    }
                }
            }
        }
        match &key.node {
            Endpoint::Port(
                PartialFlowPort::CallResult { call, .. } | PartialFlowPort::CallThrown { call },
            ) => self.descend(id, *call, request),
            Endpoint::Port(port) if is_formal_or_heap_input(port) => self.formal(id, request),
            Endpoint::Location(location) => {
                let handle = self.handles[&key.procedure].clone();
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
                    &location.selectors,
                    location.tail,
                    Some(location.call),
                    request,
                )
            }
            Endpoint::Sink(sink) => {
                let spec = self
                    .plan
                    .value_flow()
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
        if let Some(model) = self.model(&call_key) {
            self.apply_model(id, &call_key, &model);
            return Ok(());
        }
        let Endpoint::Port(result) = &key.node else {
            unreachable!("only call results descend");
        };
        for candidate in &dispatch.candidates {
            let callee_ports = candidate
                .returns
                .iter()
                .filter(|(_, caller_side)| caller_side == result)
                .map(|(callee_side, _)| callee_side.clone())
                .collect::<Vec<_>>();
            for callee_port in callee_ports {
                self.open_callee_root(id, &call_key, candidate, callee_port, dispatch.uncertain);
            }
        }
        if dispatch.candidates.is_empty() || dispatch.uncertain {
            self.unmodeled(id, &call_key, request)?;
        }
        Ok(())
    }

    /// Backward through the matched transforms at `call` whose output is the
    /// item's node. Each is a flow beside the call's other edges, as the ICFG
    /// engine's policy-local relation is, so a model or a callee body does
    /// not replace it.
    fn linked(&mut self, id: usize, call: &DurableCallSiteKey) {
        let Some(links) = self.links.get(call).cloned() else {
            return;
        };
        let key = self.items[id].key.clone();
        let item_quality = self.items[id].quality;
        let Endpoint::Port(output) = &key.node else {
            unreachable!("only call results descend");
        };
        let universe = self.plan.universe();
        for link in links.into_iter().filter(|link| &link.output == output) {
            let hops = vec![link.hop];
            let function = hops_function(&hops, universe).compose(&key.function);
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
                    .map_err(provider_error)?;
                if !ports.outputs.contains(output) {
                    return Ok(());
                }
                let universe = self.plan.universe();
                for input in ports.inputs.iter() {
                    let mut hops = vec![Hop::Unmodeled {
                        call: call.clone(),
                        input: input.clone(),
                        output: output.clone(),
                    }];
                    hops.extend(self.annotations_for(call, Some(input), &key.node));
                    let function = hops_function(&hops, universe).compose(&key.function);
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
        let root = Root::Port(Box::new((candidate.procedure.clone(), callee_port.clone())));
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
        let identity = self.identity.clone();
        self.add_item(
            candidate.procedure.clone(),
            root.clone(),
            Endpoint::Port(callee_port),
            identity,
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
        selectors: &[HeapSelector],
        tail: AccessPathTail,
        excluded: Option<CallSiteId>,
        request: &mut SemanticRequest<'_>,
    ) -> Result<(), ComposeError> {
        let origins = BindingOriginIndex::new(procedure);
        let origin = |value: ValueId| {
            origins
                .unique_binding_origin(value)
                .or_else(|| origins.addressed_binding_origins(value).unique_binding())
        };
        let wanted = origin(value);
        let bound = |candidate: ValueId| {
            candidate == value || (wanted.is_some() && origin(candidate) == wanted)
        };
        let mut actuals = Vec::new();
        for call in procedure.semantics().call_sites() {
            if Some(call.id) == excluded {
                continue;
            }
            if call.receiver.is_some_and(bound) {
                actuals.push(PartialFlowPort::CallReceiver { call: call.id });
            }
            for (ordinal, argument) in call.arguments.iter().enumerate() {
                if bound(argument.value) {
                    actuals.push(PartialFlowPort::CallArgument {
                        call: call.id,
                        ordinal: u32::try_from(ordinal).expect("a call's argument count fits u32"),
                    });
                }
            }
        }
        let caller = procedure.durable_key();
        for actual in actuals {
            let call = actual_call(&actual);
            let call_key = (caller.clone(), call);
            let dispatch = self.dispatch(&call_key, request)?;
            // A model replaces the body and writes no heap location.
            if self.model(&call_key).is_some() {
                continue;
            }
            for candidate in &dispatch.candidates {
                let formals = candidate
                    .arguments
                    .iter()
                    .filter(|(bound_actual, _)| bound_actual == &actual)
                    .map(|(_, formal)| formal.clone())
                    .collect::<Vec<_>>();
                for formal in formals {
                    let heap = PartialFlowPort::Heap {
                        root: Box::new(formal),
                        selectors: selectors.into(),
                        tail,
                    };
                    self.open_callee_root(id, &call_key, candidate, heap, dispatch.uncertain);
                }
            }
        }
        Ok(())
    }

    /// A model replaces the call: link the call's result to the caller-side
    /// inputs its transfers read. A model that covers the call is not a
    /// boundary, so its hops are uncertain only through the model itself.
    fn apply_model(&mut self, id: usize, call: &DurableCallSiteKey, model: &CallModel) {
        let key = self.items[id].key.clone();
        let item_quality = self.items[id].quality;
        // Model transfers end at the normal return, which is the singular
        // call result; no other result port and no heap location is modeled.
        let Endpoint::Port(result @ PartialFlowPort::CallResult { ordinal: None, .. }) = &key.node
        else {
            return;
        };
        let universe = self.plan.universe();
        for transfer in &model.transfers {
            let actual = transfer.actual.clone();
            let hop = Hop::Model {
                call: call.clone(),
                actual: actual.clone(),
                result: result.clone(),
                moved: transfer
                    .moved
                    .as_deref()
                    .map(|labels| label_classes(universe, labels)),
                removed: label_classes(universe, &transfer.removed),
                quality: model.quality(),
            };
            let mut hops = vec![hop];
            hops.extend(self.annotations_for(call, Some(&actual), &key.node));
            let function = hops_function(&hops, universe).compose(&key.function);
            let quality = Hop::path_quality(&hops).conjoin(item_quality);
            self.add_item(
                key.procedure.clone(),
                key.root.clone(),
                Endpoint::Port(actual),
                function,
                quality,
                Derivation::Step { hops, next: id },
            );
        }
    }

    /// A callee formal reached a callee root: map it back through the call
    /// that opened the root.
    fn apply_summary(&mut self, waiter: &CallWaiter, summary: usize) {
        let inner = &self.items[summary];
        let Endpoint::Port(formal) = &inner.key.node else {
            unreachable!("a summary item is at a formal");
        };
        let formal = formal.clone();
        let inner_function = inner.key.function.clone();
        let inner_quality = inner.quality;
        let next = self.items[waiter.item].key.clone();
        let next_quality = self.items[waiter.item].quality;
        let universe = self.plan.universe();
        for (actual, caller_node) in caller_side(&waiter.candidate, waiter.call.1, &formal) {
            let caller = Hop::Caller {
                call: waiter.call.clone(),
                callee: waiter.candidate.procedure.clone(),
                actual: actual.clone(),
                formal: formal.clone(),
                uncertain: waiter.uncertain,
            };
            let callee = Hop::Callee {
                call: waiter.call.clone(),
                callee: waiter.candidate.procedure.clone(),
                from: waiter.callee_port.clone(),
                to: next.node.clone(),
                uncertain: waiter.uncertain,
            };
            let annotations = self.annotations_for(&waiter.call, Some(&actual), &next.node);
            let function = inner_function
                .compose(&hops_function(&annotations, universe))
                .compose(&next.function);
            let quality = HopQuality::from_uncertain(waiter.uncertain)
                .conjoin(inner_quality)
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
        let reach_function = reached.key.function.clone();
        let reach_quality = reached.quality;
        let next = self.items[waiter.item].key.clone();
        let next_quality = self.items[waiter.item].quality;
        let callee = Hop::Callee {
            call: waiter.call.clone(),
            callee: waiter.candidate.procedure.clone(),
            from: waiter.callee_port.clone(),
            to: next.node.clone(),
            uncertain: waiter.uncertain,
        };
        let mut hops = vec![callee];
        hops.extend(self.annotations_for(&waiter.call, None, &next.node));
        let function = reach_function
            .compose(&hops_function(&hops, self.plan.universe()))
            .compose(&next.function);
        let quality = reach_quality
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
        if let Root::Port(port) = &key.root
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
        let callers = self.callers(&key.procedure, request)?;
        for call in callers.iter() {
            let dispatch = self.dispatch(call, request)?;
            for candidate in dispatch
                .candidates
                .iter()
                .filter(|candidate| candidate.procedure == key.procedure)
            {
                for (actual, caller_node) in caller_side(candidate, call.1, formal) {
                    let hop = Hop::Caller {
                        call: call.clone(),
                        callee: key.procedure.clone(),
                        actual,
                        formal: formal.clone(),
                        uncertain: dispatch.uncertain,
                    };
                    self.add_item(
                        call.0.clone(),
                        key.root.clone(),
                        caller_node,
                        key.function.clone(),
                        HopQuality::from_uncertain(dispatch.uncertain).conjoin(quality),
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
        let parent = match self.parents.get(&key.procedure) {
            Some(parent) => parent.clone(),
            None => {
                let parent = self
                    .provider
                    .lexical_parent(&key.procedure, request)
                    .map_err(provider_error)?;
                self.parents.insert(key.procedure.clone(), parent.clone());
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
        let hop = Hop::Closure {
            parent: parent.clone(),
            closure: key.procedure.clone(),
            binding: binding.clone(),
            slot: slot.clone(),
            uncertain: false,
        };
        if key.root.unbalanced() {
            self.add_item(
                parent,
                key.root.clone(),
                Endpoint::Port(binding),
                key.function.clone(),
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
        let root = Root::Port(Box::new((parent.clone(), binding.clone())));
        if self.registered_capture_waiters.insert((id, root.clone())) {
            self.capture_waiters
                .entry(root.clone())
                .or_default()
                .push(CaptureWaiter {
                    item: id,
                    hop: hop.clone(),
                });
        }
        let identity = self.identity.clone();
        self.add_item(
            parent,
            root.clone(),
            Endpoint::Port(binding),
            identity,
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
        let function = reached
            .key
            .function
            .compose(&self.items[waiter.item].key.function);
        let quality = reached.quality.conjoin(self.items[waiter.item].quality);
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
        if matches!(root, Root::Sink(_)) {
            return;
        }
        for waiter in self.call_waiters.get(&root).cloned().unwrap_or_default() {
            self.apply_reach(&waiter, id);
        }
        for waiter in self.capture_waiters.get(&root).cloned().unwrap_or_default() {
            self.apply_capture_reach(&waiter, id);
        }
    }

    /// The hops of one reach's path, from its source to its root: a proven
    /// path when the reach has one, else a complete path, else its first.
    fn reach_path(&self, reach: usize) -> Vec<Hop> {
        enum Piece<'p> {
            Reach(usize),
            Item(usize),
            Hops(&'p [Hop]),
            Hop(&'p Hop),
        }
        let quality = self.reaches[reach].quality;
        let chain = if quality.proven {
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
        let mut by_pair: HashMap<(ValueFlowSinkId, ComposedSourceId), Vec<usize>> =
            HashMap::default();
        for (id, reach) in self.reaches.iter().enumerate() {
            if !reach.active {
                continue;
            }
            if let Root::Sink(sink) = reach.key.root {
                by_pair
                    .entry((sink, reach.key.source))
                    .or_default()
                    .push(id);
            }
        }
        let mut keys = by_pair.keys().copied().collect::<Vec<_>>();
        keys.sort_unstable();
        keys.into_iter()
            .map(|(sink, source)| {
                let reaches = &by_pair[&(sink, source)];
                SourceSinkPair {
                    source,
                    sink,
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
fn evidence_quality(proof: &ProofStatus, completeness: &EvidenceCompleteness) -> HopQuality {
    HopQuality {
        proven: matches!(proof, ProofStatus::Proven),
        complete: matches!(completeness, EvidenceCompleteness::Complete),
    }
}

/// The call of a call input port.
fn actual_call(port: &PartialFlowPort) -> CallSiteId {
    match port {
        PartialFlowPort::CallReceiver { call } | PartialFlowPort::CallArgument { call, .. } => {
            *call
        }
        _ => unreachable!("an actual is a call input port"),
    }
}

/// Whether a value enters the procedure's interior at this port.
fn is_input_port(port: &PartialFlowPort) -> bool {
    matches!(
        port,
        PartialFlowPort::Capture { .. }
            | PartialFlowPort::CallResult { .. }
            | PartialFlowPort::CallThrown { .. }
    ) || is_formal_or_heap_input(port)
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

/// Place an in-place matched-value transfer on every call use of its value;
/// all other transfers stay on the call at the observation point. `input` and
/// `output` are its carriers; an in-place binding sits on whichever one call
/// port its carrier is.
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
    // The selected observation point still determines phase; every use of
    // its matched value follows the definition, even at a different point.
    let matched_value = input == output && matches!(input, ValueFlowCarrier::Value(_));
    let mut placements = Vec::new();
    for call in semantics
        .call_sites()
        .iter()
        .filter(|call| matched_value || call.point == point.id())
    {
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
    placements
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
