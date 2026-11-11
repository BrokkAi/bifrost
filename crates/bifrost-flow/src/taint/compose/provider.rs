//! The questions the composition engine asks about procedures and calls, and
//! the values that answer them. A production provider reads partial-flow rows
//! and resolves calls through the workspace; tests use a hand-written fake
//! over small in-memory graphs.

use std::sync::Arc;

use crate::analyzer::semantic::partial_flow::{
    CrossedCalls, HeapSelector, PartialFlowPort, ProcedurePartialFlows,
};
use crate::analyzer::semantic::{
    AbstractLocation, AccessPathTail, BarrierObservation, CallInvocationMode, CallSiteId,
    CandidateCoverage, CaptureBinding, DispatchBoundaryKind, DurableCallContext, ExecutionTiming,
    ObservationPhase, ProcedureHandle, ProgramPointHandle, ProgramPointId, SemanticCapability,
    SemanticGapHandle, SemanticLocator, SemanticRequest, ValueId, ValueTypeBarrierDecision,
    ValueTypePredicate,
};
use crate::dataflow::{SemanticInputStatus, UnmodeledCallBehavior};
use crate::taint::{SourceEventKey, TaintClassSet, TaintEdgeFunction};
use crate::value_flow::{
    AuthoredArmClosure, DurableCallSiteKey, DurableProcedureKey, ValueFlowCarrier,
    ValueFlowObservationPhase,
};

use super::graph::{Endpoint, ExecutionTarget, HopQuality, ObjectAnchor};

/// One query-local predecessor of a tracked object, with the state function
/// applied while moving forward from that predecessor to the observation.
#[derive(Debug, Clone)]
pub struct ObjectPredecessor<Function> {
    pub from: Endpoint,
    pub function: Function,
    pub quality: HopQuality,
}

#[derive(Debug, Clone)]
pub struct ObjectRelation<Fact, Function> {
    pub sources: Vec<ExecutionSource<Fact>>,
    pub predecessors: Vec<ObjectPredecessor<Function>>,
    pub complete: bool,
    /// Whether a tracked object can exist before a call result at this node.
    /// A result that creates the object ends the backward search here.
    pub cross_call: bool,
}

impl<Fact, Function> ObjectRelation<Fact, Function> {
    pub const fn none() -> Self {
        Self {
            sources: Vec::new(),
            predecessors: Vec::new(),
            complete: true,
            cross_call: true,
        }
    }
}

pub use crate::analyzer::semantic::partial_flow::ports::bound_return_selector_matches;

/// Match one member demand after a return pairing proves object identity.
pub fn bound_return_member_matches(
    actual: &PartialFlowPort,
    returned: &PartialFlowPort,
    caller_root: &PartialFlowPort,
    callee_root: &PartialFlowPort,
    mut canonical_field: impl FnMut(&SemanticLocator) -> Option<SemanticLocator>,
) -> bool {
    let (
        PartialFlowPort::Heap {
            root: actual_root,
            selectors: actual_selectors,
            tail: actual_tail,
        },
        PartialFlowPort::Heap {
            root: returned_root,
            selectors: returned_selectors,
            tail: returned_tail,
        },
    ) = (actual, returned)
    else {
        return false;
    };
    actual_root.as_ref() == caller_root
        && returned_root.as_ref() == callee_root
        && actual_tail == returned_tail
        && actual_selectors.len() == returned_selectors.len()
        && actual_selectors
            .iter()
            .zip(returned_selectors)
            .all(|(actual, formal)| {
                bound_return_selector_matches(actual, formal, |field| canonical_field(field))
            })
}

/// Exact body-owned calls; lexical containment alone is not an invocation.
#[derive(Debug, Clone)]
pub struct Invocations {
    pub sites: Vec<InvocationSite>,
    pub coverage: Completeness,
}

/// Positively admitted roots and whether the bounded reader covered its inventory.
#[derive(Debug, Clone)]
pub struct ExecutionRootInventory {
    pub roots: Vec<DurableProcedureKey>,
    pub coverage: Completeness,
}

#[derive(Debug, Clone)]
pub struct InvocationSite {
    pub call: DurableCallSiteKey,
    pub source_site: CallSiteId,
    pub mode: CallInvocationMode,
}

/// The result's status is independent of its arm and residual counts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutionDispatchOutcome {
    Complete,
    Unsupported(Box<str>),
    Cancelled(Box<str>),
    Budget(Box<str>),
}

#[derive(Debug, Clone)]
pub struct ExecutionDispatch<Function> {
    pub arms: Vec<ExecutionArm<Function>>,
    pub residuals: Vec<DispatchBoundaryKind>,
    pub coverage: CandidateCoverage,
    pub outcome: ExecutionDispatchOutcome,
}

/// Per-arm proof is carried into the item key, including for shared external targets.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ExecutionCallableInstance {
    pub producer: DurableProcedureKey,
    pub creation_point: ProgramPointId,
    pub creation_event_index: usize,
    pub creation_value: ValueId,
    pub capture_bindings: Box<[CaptureBinding]>,
    pub factory_call: Option<DurableCallSiteKey>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ExecutionCertificateStep {
    pub call: DurableCallSiteKey,
    pub ordinal: usize,
    pub target: ExecutionTarget,
    pub instance: Option<ExecutionCallableInstance>,
    pub context: DurableCallContext,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ExecutionCertificate {
    pub root: DurableProcedureKey,
    pub prefix: Box<[ExecutionCertificateStep]>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ExecutionArmContext {
    pub call: DurableCallSiteKey,
    pub ordinal: usize,
    pub quality: HopQuality,
    pub certificate: ExecutionCertificate,
}

#[derive(Debug, Clone)]
pub struct ExecutionArm<Function> {
    pub target: ExecutionTarget,
    pub function: Function,
    pub quality: HopQuality,
    pub timing: ExecutionTiming,
    pub instance: Option<ExecutionCallableInstance>,
    pub context: DurableCallContext,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutionEndpointStatus {
    Complete,
    Partial(Box<str>),
    Conflict(Box<str>),
    Absent,
}

/// A declaration with no fabricated value carrier.
#[derive(Debug, Clone)]
pub struct ExecutionSource<Fact> {
    pub identity: Box<str>,
    pub fact: Fact,
    pub provenance: Box<str>,
    /// Bound origin for a source whose witness needs an explicit seed step.
    pub seed_point: Option<crate::analyzer::semantic::ProgramPointHandle>,
}

#[derive(Debug, Clone)]
pub struct ExecutionEndpoints<Fact> {
    pub sources: Vec<ExecutionSource<Fact>>,
    pub status: ExecutionEndpointStatus,
    pub covers_overrides: bool,
}

/// Answers the composition engine needs from outside the plan. `Fact` and
/// `Function` are the label types of the client's
/// [`ComposeLabels`](super::labels::ComposeLabels), which the provider's
/// bound endpoints carry.
pub type ProjectedPartialFlows<F> = Vec<(Option<F>, Arc<ProcedurePartialFlows>)>;
pub type ProjectedInteriorFlows<F> = Vec<(Option<F>, InteriorFlows)>;

pub trait CompositionProvider {
    type Error: std::fmt::Display;
    type Fact: Clone + Eq + std::hash::Hash + std::fmt::Debug;
    type Function: Clone + Eq + std::hash::Hash + std::fmt::Debug;

    /// A request-local execution discovery shared by selected sink searches.
    fn execution_discovery<E>(
        &self,
        _budget: super::CompositionBudget,
        request: &mut SemanticRequest<'_>,
        build: impl FnOnce(
            &mut SemanticRequest<'_>,
        )
            -> Result<(Vec<super::ExecutionReach>, Vec<super::Incompleteness>), E>,
    ) -> Result<(Vec<super::ExecutionReach>, Vec<super::Incompleteness>), E> {
        build(request)
    }

    fn object_relation(
        &self,
        _procedure: &DurableProcedureKey,
        _at: &Endpoint,
        _request: &mut SemanticRequest<'_>,
    ) -> Result<ObjectRelation<Self::Fact, Self::Function>, Self::Error> {
        Ok(ObjectRelation::none())
    }

    /// Positive entry evidence only. An incomplete inventory cannot refute
    /// a root already admitted by an authored or language entry fact.
    fn admitted_execution_roots(
        &self,
        _max_examined: usize,
        _request: &mut SemanticRequest<'_>,
    ) -> Result<ExecutionRootInventory, Self::Error> {
        Ok(ExecutionRootInventory {
            roots: Vec::new(),
            coverage: Completeness::Complete,
        })
    }

    fn invocations(
        &self,
        _procedure: &DurableProcedureKey,
        _request: &mut SemanticRequest<'_>,
    ) -> Result<Invocations, Self::Error> {
        unimplemented!("this client has no execution relation")
    }

    fn execution_dispatch(
        &self,
        _call: &DurableCallSiteKey,
        _incoming: Option<&ExecutionArmContext>,
        _request: &mut SemanticRequest<'_>,
    ) -> Result<ExecutionDispatch<Self::Function>, Self::Error> {
        unimplemented!("this client has no execution relation")
    }

    fn execution_endpoints(
        &self,
        _target: &ExecutionTarget,
        _incoming: Option<&ExecutionArmContext>,
        _request: &mut SemanticRequest<'_>,
    ) -> Result<ExecutionEndpoints<Self::Fact>, Self::Error> {
        unimplemented!("this client has no execution relation")
    }

    /// Only an exact named arm or the guarded single-residual rule may close
    /// a residual. The search never treats an empty residual list as proof.
    fn discharge_execution_residual(
        &self,
        _call: &DurableCallSiteKey,
        _dispatch: &ExecutionDispatch<Self::Function>,
    ) -> bool {
        false
    }

    /// Write observations in this query's selected store inventory.
    fn store_writes(&self) -> Vec<StoreWriteObservation> {
        Vec::new()
    }

    /// May-alias writes for a selected read output. Incomplete coverage never
    /// proves an empty channel; the search keeps the dependent answer open.
    fn store_links(
        &self,
        _procedure: &DurableProcedureKey,
        _output: &PartialFlowPort,
    ) -> StoreChannelLinks {
        StoreChannelLinks::default()
    }

    /// A declared field and a canonical field may name one slot only after
    /// this call's returned object has been paired with its caller result.
    fn canonical_returned_field(
        &self,
        _callee: &DurableProcedureKey,
        _caller: &DurableProcedureKey,
        _declared: &SemanticLocator,
        _request: &mut SemanticRequest<'_>,
    ) -> Option<SemanticLocator> {
        None
    }

    /// Whether this policy declares value-type barriers. False preserves the
    /// stored-summary path and performs no barrier type lookup.
    fn has_value_type_barriers(&self) -> bool {
        false
    }

    /// Cheap pre-dispatch check for a call that may share caller storage.
    /// Production providers can use snapshot origins for local references.
    fn may_share_call_storage(
        &self,
        procedure: &ProcedureHandle,
        call: CallSiteId,
        _request: &mut SemanticRequest<'_>,
    ) -> Result<bool, Self::Error> {
        let call = procedure
            .semantics()
            .call_site(call)
            .expect("a call belongs to its procedure");
        if call
            .member_selection
            .as_ref()
            .is_some_and(|selection| selection.receiver_place.is_some())
        {
            return Ok(true);
        }
        Ok(call
            .receiver
            .into_iter()
            .chain(call.arguments.iter().map(|argument| argument.value))
            .any(|value| {
                procedure.semantics().value(value).is_some_and(|value| {
                    value.kind == crate::analyzer::semantic::SemanticValueKind::Address
                })
            }))
    }

    /// Whether a sibling call's inputs can name the exact caller storage
    /// read by `value`. This is asked before dispatching that sibling.
    fn call_input_storage_overlap(
        &self,
        _procedure: &ProcedureHandle,
        _value: ValueId,
        _selectors: &[HeapSelector],
        _tail: AccessPathTail,
        _call: CallSiteId,
        _request: &mut SemanticRequest<'_>,
    ) -> Result<crate::analyzer::semantic::CallStorageSharing, Self::Error> {
        Ok(crate::analyzer::semantic::CallStorageSharing::Unknown)
    }

    /// Whether an activated model could write receiver or argument storage
    /// at this call. This prefilter must not dispatch an ordinary sibling.
    fn may_have_modeled_storage_output(
        &self,
        _procedure: &ProcedureHandle,
        _call: CallSiteId,
    ) -> bool {
        false
    }

    /// Install the lenient observation filter for this query's candidate
    /// source-to-sink chop. Procedures outside it retain stored summaries.
    fn filter_value_type_barriers(&self, _chop: &std::collections::HashSet<DurableProcedureKey>) {}

    /// Install the separate strict filter for one concrete source/sink pair's recorded chop.
    fn strict_value_type_barriers(&self, _chop: &std::collections::HashSet<DurableProcedureKey>) {}

    fn permits_value_type_barrier(&self, decision: ValueTypeBarrierDecision) -> bool {
        !matches!(decision, ValueTypeBarrierDecision::ProvenMatch)
    }

    /// Classify exact observations on a selected witness, never another path.
    fn value_type_barrier_checks(
        &self,
        _observations: &[BarrierObservation],
        _request: &mut SemanticRequest<'_>,
    ) -> Result<Vec<ValueTypeBarrierCheck>, Self::Error> {
        Ok(Vec::new())
    }

    /// Values on either side of a call/model/capture boundary.
    fn value_type_barrier_port_checks(
        &self,
        _procedure: &DurableProcedureKey,
        _port: &PartialFlowPort,
        _request: &mut SemanticRequest<'_>,
    ) -> Result<Vec<ValueTypeBarrierCheck>, Self::Error> {
        Ok(Vec::new())
    }

    /// Clear request-local witness choices before producing lenient evidence.
    fn reset_value_type_witnesses(&self) {}

    fn retain_strict_value_type_witness(
        &self,
        _source: &BoundSource<Self::Fact>,
        _sink: crate::value_flow::ValueFlowSinkId,
    ) {
    }

    fn prepare_value_type_witness(
        &self,
        _source: &BoundSource<Self::Fact>,
        _sink: crate::value_flow::ValueFlowSinkId,
    ) {
    }

    /// A client's query-local label for a local port hop. The default keeps
    /// existing taint flows as identity. A stateful client may derive a finite
    /// relation from ordered procedure events, including alternative paths.
    fn local_function(
        &self,
        _procedure: &DurableProcedureKey,
        _from: &super::graph::Endpoint,
        _to: &super::graph::Endpoint,
        _request: &mut SemanticRequest<'_>,
    ) -> Result<Option<(Self::Function, HopQuality)>, Self::Error> {
        Ok(None)
    }

    /// Caller/callee object transport for one port boundary. The client
    /// supplies evidence quality with the relation; no proof means an open
    /// boundary. The default keeps existing taint labels unchanged.
    fn call_boundary_function(
        &self,
        _call: &DurableCallSiteKey,
        _callee: &DurableProcedureKey,
        _from: &super::graph::Endpoint,
        _to: &super::graph::Endpoint,
    ) -> Option<(Self::Function, HopQuality)> {
        None
    }

    /// Caller inputs that retain an object-local normal continuation when
    /// dispatch or argument conversion has an unresolved effect. The client must establish exact subject
    /// identity and retain the unresolved effect in its label and quality.
    fn unproven_object_continuations(
        &self,
        _call: &DurableCallSiteKey,
        _request: &mut SemanticRequest<'_>,
    ) -> Result<Vec<ObjectPredecessor<Self::Function>>, Self::Error> {
        Ok(Vec::new())
    }

    /// State carried by the same object from a call input to one caller
    /// continuation. A stateful client supplies a callee entry-to-exit
    /// relation for each selected binding. Value-flow clients have no such
    /// relation, so their existing call and writeback paths are unchanged.
    fn call_handoffs(
        &self,
        _call: &DurableCallSiteKey,
        _candidate: &DispatchCandidate,
        _exit: CallHandoffExit,
        _request: &mut SemanticRequest<'_>,
    ) -> Result<CallHandoffInventory<Self::Function>, Self::Error> {
        Ok(CallHandoffInventory {
            handoffs: Vec::new(),
            complete: false,
        })
    }

    /// Stored or recomputed port-to-port flows of one procedure.
    fn partial_flows(
        &self,
        procedure: &DurableProcedureKey,
        request: &mut SemanticRequest<'_>,
    ) -> Result<Arc<ProcedurePartialFlows>, Self::Error>;

    /// Query-local label partitions of one procedure's port relation. `None`
    /// is the identity label function. A partition may contain the stored
    /// rows or a policy-local projection; the union is the procedure answer.
    /// A partition without extra edge kills must reuse the `Arc` returned by
    /// `partial_flows` so the search can retain its path-sensitive openness
    /// refinement. A fresh projection with extra kills has to certify its
    /// entire relation before any removed path can count as absent.
    fn projected_partial_flows(
        &self,
        procedure: &DurableProcedureKey,
        request: &mut SemanticRequest<'_>,
    ) -> Result<ProjectedPartialFlows<Self::Function>, Self::Error> {
        Ok(vec![(None, self.partial_flows(procedure, request)?)])
    }

    /// The M2 fixpoint on one procedure with extra seeds (bound source
    /// carriers) and extra observations (sink carriers, caller-side
    /// locations), with optional witness recording. Every output port of the
    /// procedure is observed as the stored fixpoint observes it.
    fn interior_flows(
        &self,
        procedure: &DurableProcedureKey,
        seeds: &[InteriorSeed],
        observations: &[InteriorObservation],
        witnesses: bool,
        request: &mut SemanticRequest<'_>,
    ) -> Result<InteriorFlows, Self::Error>;

    /// Interior runs use the same label partitions as port relations.
    fn projected_interior_flows(
        &self,
        procedure: &DurableProcedureKey,
        seeds: &[InteriorSeed],
        observations: &[InteriorObservation],
        witnesses: bool,
        request: &mut SemanticRequest<'_>,
    ) -> Result<ProjectedInteriorFlows<Self::Function>, Self::Error> {
        Ok(vec![(
            None,
            self.interior_flows(procedure, seeds, observations, witnesses, request)?,
        )])
    }

    /// A stored edge's witness uses the same file-local relations as its
    /// producer; it must not silently acquire workspace refinements.
    fn stored_interior_flows(
        &self,
        procedure: &DurableProcedureKey,
        seeds: &[InteriorSeed],
        observations: &[InteriorObservation],
        witnesses: bool,
        request: &mut SemanticRequest<'_>,
    ) -> Result<InteriorFlows, Self::Error> {
        self.interior_flows(procedure, seeds, observations, witnesses, request)
    }

    fn projected_stored_interior_flows(
        &self,
        procedure: &DurableProcedureKey,
        seeds: &[InteriorSeed],
        observations: &[InteriorObservation],
        witnesses: bool,
        request: &mut SemanticRequest<'_>,
    ) -> Result<ProjectedInteriorFlows<Self::Function>, Self::Error> {
        Ok(vec![(
            None,
            self.stored_interior_flows(procedure, seeds, observations, witnesses, request)?,
        )])
    }

    /// Dispatch candidates of one call with their bindings and the
    /// boundary's completeness, and the model that replaces the call, if any.
    /// A model wins over every candidate body, and a call it covers is not a
    /// boundary: its dispatch answer is complete. The model comes back with
    /// its dispatch so that no provider has to retain one for a later lookup.
    fn dispatch(
        &self,
        call: &DurableCallSiteKey,
        request: &mut SemanticRequest<'_>,
    ) -> Result<DispatchWithModel<Self::Function>, Self::Error>;

    /// Incoming calls to one procedure, with completeness.
    fn callers(
        &self,
        procedure: &DurableProcedureKey,
        request: &mut SemanticRequest<'_>,
    ) -> Result<Callers, Self::Error>;

    /// The procedure whose body creates the closure `procedure`, read from
    /// the IR (`lexical_parent`). `None` for a procedure that is not a
    /// closure. A `Capture` port has exactly this one predecessor procedure.
    fn lexical_parent(
        &self,
        procedure: &DurableProcedureKey,
        request: &mut SemanticRequest<'_>,
    ) -> Result<Option<DurableProcedureKey>, Self::Error>;

    /// Certify only the selected normal-result origin of this object root.
    /// This does not replace the call's dispatch or model other subjects.
    fn certified_object_origin(
        &self,
        _root: &ObjectAnchor,
        _call: &DurableCallSiteKey,
        _port: &PartialFlowPort,
        _gap: &ExternalBodyUnavailableGap,
        _request: &mut SemanticRequest<'_>,
    ) -> Result<Option<()>, Self::Error> {
        Ok(None)
    }

    /// What the policy does at a call that no model covers and whose
    /// dispatch has no candidate or leaves a boundary beside its candidates:
    /// the plan's `unmodeled_call_behavior`, which the ICFG engine applies at
    /// the same calls.
    fn unmodeled_call_behavior(&self) -> UnmodeledCallBehavior;

    /// The ports the unmodeled-call fallback links at one call, as the ICFG
    /// engine's fallback profile lists them.
    fn fallback_ports(
        &self,
        call: &DurableCallSiteKey,
        request: &mut SemanticRequest<'_>,
    ) -> Result<FallbackPorts, Self::Error>;

    /// The authored closures of every call this provider dispatched, for
    /// the openness sweep included, whose model is an authored external
    /// summary: one entry per such call, possibly empty. A composition that
    /// is otherwise complete is proven only by authored summaries exactly
    /// when this is not empty, as the ICFG engine's run is when an authored
    /// summary closes one of its boundaries.
    fn authored_models(&self) -> Vec<Box<[AuthoredArmClosure]>>;

    /// Whether the procedure is open (gap discharges recomputed with the
    /// workspace host).
    fn openness(
        &self,
        procedure: &DurableProcedureKey,
        request: &mut SemanticRequest<'_>,
    ) -> Result<Openness, Self::Error>;

    /// The policy sources, sanitizers and transforms that lie in one
    /// procedure, matched when the search first enters it. They
    /// add to the plan's own bound endpoints; a provider never answers an
    /// endpoint the plan already binds.
    fn endpoints(
        &self,
        procedure: &DurableProcedureKey,
        request: &mut SemanticRequest<'_>,
    ) -> Result<ProcedureEndpoints<Self::Fact, Self::Function>, Self::Error>;

    /// The selector evidence of a source whose `evidence` is
    /// [`EndpointEvidence::Unknown`], judged the way the ICFG engine judges
    /// every source it binds. Asked once per source, and only for a source on
    /// a path the composition reports (stage 3), so the cost of judging it
    /// (a points-to question for a matched value) is paid only where a
    /// finding depends on it.
    fn source_evidence(
        &self,
        source: &BoundSource<Self::Fact>,
        request: &mut SemanticRequest<'_>,
    ) -> Result<HopQuality, Self::Error>;
}

/// An internal observation of a selected store-write input.
#[derive(Debug, Clone)]
pub struct StoreWriteObservation {
    pub procedure: DurableProcedureKey,
    pub owner: ProcedureHandle,
    pub point: ProgramPointId,
    pub phase: ValueFlowObservationPhase,
    pub carrier: ValueFlowCarrier,
}

/// A selected read output's may-alias write observations.
#[derive(Debug, Clone, Default)]
pub struct StoreChannelLinks {
    pub writes: Vec<StoreChannelLink>,
    pub incomplete: Option<Box<str>>,
}

#[derive(Debug, Clone)]
pub struct StoreChannelLink {
    pub write: usize,
    pub write_call: DurableCallSiteKey,
    pub read_call: DurableCallSiteKey,
    pub write_site: SemanticLocator,
    pub read_site: SemanticLocator,
    pub read_origin: crate::taint::SourceEventKey,
    pub read_phase: ValueFlowObservationPhase,
    pub read_carrier: ValueFlowCarrier,
    pub uncertain: bool,
}

/// Query-local proof for a named policy barrier and exact value observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValueTypeBarrierCheck {
    pub id: Box<str>,
    pub observation: BarrierObservation,
    pub predicate: ValueTypePredicate,
    pub decision: ValueTypeBarrierDecision,
}

/// Undecided observations of the actual retained lenient witnesses. Strict
/// survivors have no entry. The omission count is an explicit lower bound.
#[derive(Debug, Clone)]
pub struct ValueTypeBarrierFindingNotes {
    pub source: SourceEventKey,
    pub sink: crate::value_flow::ValueFlowEventKey,
    pub checks: Vec<ValueTypeBarrierCheck>,
    pub omitted_lower_bound: u64,
}

/// The policy endpoints matched in one procedure. `completeness` is
/// incomplete when the match may have missed an endpoint there: a selector
/// row the binding refused, or a selector evaluation that did not finish.
#[derive(Debug, Clone)]
pub struct ProcedureEndpoints<Fact = TaintClassSet, Function = TaintEdgeFunction> {
    pub sources: Vec<BoundSource<Fact>>,
    pub sanitizers: Vec<BoundSanitizer<Function>>,
    pub transforms: Vec<BoundTransform<Function>>,
    pub completeness: Completeness,
}

impl<Fact, Function> ProcedureEndpoints<Fact, Function> {
    /// No endpoint, and nothing missed.
    pub const fn none() -> Self {
        Self {
            sources: Vec::new(),
            sanitizers: Vec::new(),
            transforms: Vec::new(),
            completeness: Completeness::Complete,
        }
    }
}

/// The proof and completeness of an endpoint's selector evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointEvidence {
    /// Judged: the provider knows the evidence's quality.
    Known(HopQuality),
    /// Not judged. The provider binds the endpoint without the question that
    /// judges it, because that question is expensive and most endpoints the
    /// search reaches lie on no finding. The composition asks
    /// [`CompositionProvider::source_evidence`] when a finding depends on it.
    Unknown,
}

/// A policy source: the carrier at a point and phase that generates the
/// labels `classes`. `origin` is the source event a finding names. `evidence` is the
/// proof and completeness of its selector evidence: a source without proven
/// and complete evidence leaves the run incomplete and enters every path that
/// starts at it, as the ICFG engine's plan treats it. The search treats an
/// `Unknown` evidence as neutral; the report stage judges it for the sources
/// that reach a sink.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundSource<Fact = TaintClassSet> {
    pub point: ProgramPointHandle,
    pub phase: ValueFlowObservationPhase,
    pub carrier: ValueFlowCarrier,
    pub classes: Fact,
    pub origin: SourceEventKey,
    pub evidence: EndpointEvidence,
}

/// A policy sanitizer bound to one call at `point`: the call input carrier
/// it reads and the call output carrier it produces, or one carrier for an
/// in-place sanitizer. Only a proven sanitizer removes `removed`; one that is
/// not resolved makes the run incomplete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundSanitizer<Function = TaintEdgeFunction> {
    pub point: ProgramPointHandle,
    pub input: ValueFlowCarrier,
    pub output: ValueFlowCarrier,
    pub function: Function,
    pub proven: bool,
    pub resolved: bool,
}

/// A policy transform bound to one call at `point`: a flow from the call
/// input carrier `input` to the call output carrier `output` that applies
/// `function`, beside the call's other edges, as the ICFG engine's
/// policy-local relation is. `uncertain` when its binding is not proven and
/// complete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundTransform<Function = TaintEdgeFunction> {
    pub point: ProgramPointHandle,
    pub input: ValueFlowCarrier,
    pub output: ValueFlowCarrier,
    pub function: Function,
    pub uncertain: bool,
}

/// Whether an answer covers everything it should, and if not, why.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Completeness {
    Complete,
    Incomplete {
        cause: IncompleteCause,
        reason: Box<str>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum IncompleteCause {
    Content,
    Operational(OperationalCause),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum OperationalCause {
    Budget(super::search::BudgetLane),
    Cancelled,
    Provider,
}

impl Completeness {
    pub fn content(reason: impl Into<Box<str>>) -> Self {
        Self::Incomplete {
            cause: IncompleteCause::Content,
            reason: reason.into(),
        }
    }

    pub fn operational(cause: OperationalCause, reason: impl Into<Box<str>>) -> Self {
        Self::Incomplete {
            cause: IncompleteCause::Operational(cause),
            reason: reason.into(),
        }
    }

    /// Keep the latest diagnostic text while retaining an earlier operational stop.
    pub fn preserving_operational_cause(self, previous: &Self) -> Self {
        match (previous, self) {
            (
                Self::Incomplete {
                    cause: IncompleteCause::Operational(cause),
                    ..
                },
                Self::Incomplete {
                    cause: IncompleteCause::Content,
                    reason,
                },
            ) => Self::operational(*cause, reason),
            (
                Self::Incomplete {
                    cause: IncompleteCause::Operational(cause),
                    ..
                },
                Self::Incomplete {
                    cause: IncompleteCause::Operational(OperationalCause::Provider),
                    reason,
                },
            ) if *cause != OperationalCause::Provider => Self::operational(*cause, reason),
            (_, next) => next,
        }
    }

    pub const fn is_complete(&self) -> bool {
        matches!(self, Self::Complete)
    }
}

/// A location in the caller that a callee's `Heap` input port reads: the
/// access path `selectors` with `tail`, rooted at the caller-side value bound
/// to the call input port `actual` (`CallReceiver` or `CallArgument` of
/// `call`), observed at the call's invocation, before the call's effects.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CallerLocation {
    pub call: CallSiteId,
    pub actual: PartialFlowPort,
    pub selectors: Box<[HeapSelector]>,
    pub tail: AccessPathTail,
}

/// Where a value enters one interior run.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum InteriorSeed {
    /// A bound policy source: the carrier at a point and phase.
    Source {
        point: ProgramPointId,
        phase: ValueFlowObservationPhase,
        carrier: ValueFlowCarrier,
    },
    /// An input port of the procedure (receiver, parameter, capture slot,
    /// heap input, call result or thrown value).
    Port(PartialFlowPort),
    /// A callee heap output written into shared caller storage on normal return.
    Writeback {
        call: CallSiteId,
        storage: Box<AbstractLocation>,
        selectors: Box<[HeapSelector]>,
        tail: AccessPathTail,
    },
}

/// What one interior run observes besides the procedure's output ports.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum InteriorObservation {
    /// A bound sink carrier at a point and phase.
    Sink {
        point: ProgramPointId,
        phase: ValueFlowObservationPhase,
        carrier: ValueFlowCarrier,
    },
    /// A caller-side location a callee reads through a heap input port.
    Location(CallerLocation),
}

/// Where one interior flow arrives.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum InteriorTarget {
    /// The observation with this index in the request's `observations`.
    Observation(usize),
    /// An output port of the procedure.
    Port(PartialFlowPort),
}

/// One step of an interior witness: a program point and the ordinal of the
/// event at that point that moved the value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct InteriorWitnessStep {
    pub point: ProgramPointId,
    pub event: u32,
    pub source: Option<ValueId>,
    pub target: Option<ValueId>,
    pub phase: ObservationPhase,
}

/// One flow of an interior run, from the seed with index `seed` in the
/// request's `seeds`. `crossed` are the calls its paths crossed, as a stored
/// flow records them. `witness` is `Some` exactly when witnesses were
/// requested.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InteriorFlow {
    pub seed: usize,
    pub target: InteriorTarget,
    pub uncertain: bool,
    pub crossed: CrossedCalls,
    pub witness: Option<Box<[InteriorWitnessStep]>>,
}

/// The result of one interior run. `procedure` is the live handle the run
/// used; witness steps name points of it.
#[derive(Debug, Clone)]
pub struct InteriorFlows {
    pub procedure: ProcedureHandle,
    pub flows: Vec<InteriorFlow>,
    pub completeness: Completeness,
}

/// One dispatch candidate of a call.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DispatchCandidate {
    pub procedure: DurableProcedureKey,
    /// Callee heap ports backed by a real member store. None means the
    /// callee's store inventory is incomplete, so writeback remains open.
    pub written_heap_ports: Option<Box<[PartialFlowPort]>>,
    /// Caller-side actual port (`CallReceiver`, `CallArgument`) to callee
    /// formal port (`Receiver`, `Parameter`), implicit arguments included.
    pub arguments: Box<[(PartialFlowPort, PartialFlowPort)]>,
    /// Storage shared by a bound actual and formal, with the binding evidence
    /// needed before a callee heap output may be written back to the caller.
    pub writeback: Box<[WritebackBinding]>,
    /// Callee return port (`NormalReturn`, `IndexedNormalReturn`,
    /// `ExceptionalReturn`) to caller-side result port (`CallResult`,
    /// `CallThrown`).
    pub returns: Box<[(PartialFlowPort, PartialFlowPort)]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CallObjectContinuity {
    Reference,
    Move,
    Copy,
    Unknown,
}

impl CallObjectContinuity {
    pub const fn is_exact(self) -> bool {
        matches!(self, Self::Reference | Self::Move)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CallHandoffExit {
    Normal,
    Exceptional,
}

/// A candidate-specific object handoff. `argument_index` names the shared
/// actual/formal binding; `quality` proves that binding independently of the
/// dispatch's target coverage. The client still checks the tracked subject's
/// object evidence before applying its callee entry-to-exit label function.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CallHandoffBinding {
    pub argument_index: usize,
    pub exit: CallHandoffExit,
    pub continuity: CallObjectContinuity,
    pub quality: HopQuality,
}

/// A selected candidate's object binding and its ordered callee summary.
/// The binding indexes `DispatchCandidate::arguments`; target coverage is
/// checked by the search independently of this binding's proof axes.
#[derive(Debug, Clone)]
pub struct CallHandoff<Function> {
    pub binding: CallHandoffBinding,
    pub function: Function,
}

/// Completeness of one candidate's handoff exit, including an absent exit.
pub struct CallHandoffInventory<Function> {
    pub handoffs: Vec<CallHandoff<Function>>,
    pub complete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WritebackBinding {
    pub actual: PartialFlowPort,
    pub formal: PartialFlowPort,
    pub shares_storage: crate::analyzer::semantic::CallStorageSharing,
    pub direct_field_sharing: crate::analyzer::semantic::CallStorageSharing,
    /// Callee fields whose every matching store is proven to target this
    /// formal's own cell rather than a promoted or dereferenced referent.
    pub direct_fields: Box<[crate::analyzer::semantic::SemanticLocator]>,
    pub conversion_preserves_identity: bool,
    pub proven: bool,
    pub complete: bool,
    pub storage: Box<[AbstractLocation]>,
}

/// The dispatch of one call. An open, unproven or exceeded dispatch is
/// `Incomplete` with the dispatch reason.
///
/// `continuation` is the best proof and the best completeness of the call's
/// own continuation edges: the edges the ICFG engine gives a value that is
/// live across the call without entering a callee. Each dispatch boundary
/// projects one such edge with its own proof and completeness, and a call
/// with a candidate body or a model replacing it also has the caller's own
/// proven and complete edge. A value may take any of them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalBodyUnavailableGap {
    pub target: crate::analyzer::store::active_models::UnmaterializedExternalTarget,
    pub raw_coverage: CandidateCoverage,
}

impl ExternalBodyUnavailableGap {
    /// A selected Fresh origin discharges only the same exhaustive raw target.
    pub fn matches_origin_target(
        &self,
        target: &crate::analyzer::store::active_models::UnmaterializedExternalTarget,
    ) -> bool {
        self.raw_coverage == CandidateCoverage::Exhaustive && &self.target == target
    }
}

/// One call's dispatch with the model that replaces the call, if any.
pub type DispatchWithModel<Function> = (Dispatch, Option<CallModel<Function>>);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dispatch {
    pub candidates: Vec<DispatchCandidate>,
    pub completeness: Completeness,
    pub continuation: HopQuality,
    /// The one typed raw external-body gap, when it is the sole dispatch loss.
    pub external_body_unavailable: Option<ExternalBodyUnavailableGap>,
}

/// Incoming calls to one procedure. A truncated enumeration is `Incomplete`
/// with the truncation reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Callers {
    pub calls: Vec<DurableCallSiteKey>,
    pub completeness: Completeness,
}

/// One model transfer from a caller-side input port of the call (its
/// `CallReceiver` or a `CallArgument`) to a caller-side output. Labels are
/// stable policy label names. `moved` is the set of labels the transfer
/// carries, `None` for every label; `removed` are the labels a sanitize effect
/// of the model removes on this transfer.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ModelTransfer<Function = TaintEdgeFunction> {
    pub actual: PartialFlowPort,
    pub output: PartialFlowPort,
    pub function: Function,
    /// Proof of this transfer, independent of the model's coverage claim.
    pub proven: bool,
    /// An override-family closure covers the member, but does not prove
    /// which concrete receiver or argument storage receives this output.
    /// Only a source/sink path through this transfer is left incomplete.
    pub unresolved_output_storage: bool,
}

/// A model that replaces one call to one candidate.
///
/// `authored` is present for a model from an authored external summary: the
/// closures that summary gives the call's dispatch boundaries, possibly none
/// when the closure guards refuse it. Such a model is an authored claim, not
/// derived proof (#1916): a composition that rests on one is proven only by
/// authored summaries, and a path through it is certain only when the
/// closure guards admitted at least one closure, as the ICFG engine's
/// `certain_witness_closures` requires. A curated or inferred model is
/// `None`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallModel<Function = TaintEdgeFunction> {
    pub transfers: Vec<ModelTransfer<Function>>,
    /// Identity of the selected procedure summary, retained as provenance.
    pub summary: Option<crate::dataflow::ProcedureSummaryKey>,
    /// Exact dispatch boundary whose selected summary contributed transfers.
    pub summary_target: Option<crate::analyzer::semantic::DispatchBoundaryKind>,
    /// Declared transfers supplement the original dispatch and its residual.
    /// The call's ordinary continuation and obligations remain live.
    pub retains_dispatch: bool,
    /// Caller storage reached by modeled receiver or argument outputs.
    pub writeback: Box<[WritebackBinding]>,
    /// Caller storage read through modeled receiver inputs.
    pub receiver_reads: Box<[WritebackBinding]>,
    pub proven: bool,
    pub completeness: Completeness,
    pub authored: Option<Box<[AuthoredArmClosure]>>,
}

impl<Function> CallModel<Function> {
    /// The quality of a path through the model. A curated or inferred model
    /// is proven and complete or neither. An authored model's transfers are
    /// unproven unless the closure guards admitted at least one closure, and
    /// complete when the model is.
    pub fn quality(&self) -> HopQuality {
        let complete = self.completeness.is_complete();
        if self.retains_dispatch {
            return HopQuality::new(self.proven, false);
        }
        match &self.authored {
            None => HopQuality::from_uncertain(!self.proven || !complete),
            Some(closures) => HopQuality::new(self.proven && !closures.is_empty(), complete),
        }
    }
}

/// The call ports the paranoid unmodeled-call fallback links: every input
/// (`CallReceiver` and each `CallArgument`) reaches every output (the
/// singular `CallResult` and `CallThrown`). Heap locations and globals the
/// ICFG engine's fallback also links are not ports here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FallbackPorts {
    pub inputs: Box<[PartialFlowPort]>,
    pub outputs: Box<[PartialFlowPort]>,
}

/// Whether a procedure keeps a value-flow gap the workspace cannot
/// discharge. `residual` names the calls whose incomplete dispatch keeps it
/// open. `blocked` is the first gap that no call dispatch answers; a
/// procedure open with neither keeps a gap that the value-flow capabilities
/// leave open. `status` is the procedure's snapshot input status, which the
/// ICFG engine's first cause prints for a blocked gap and for a residual
/// call alike.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Openness {
    Closed,
    Open {
        residual: Box<[DurableCallSiteKey]>,
        /// Cause aligned with each residual call.
        residual_causes: Box<[IncompleteCause]>,
        cause: IncompleteCause,
        blocked: Option<BlockedGap>,
        status: SemanticInputStatus,
        reason: Box<str>,
    },
}

/// A gap of one procedure that keeps it open and that no dispatch answers.
/// The handle and capability are what the ICFG engine's first cause carries
/// for the same gap.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BlockedGap {
    pub gap: SemanticGapHandle,
    pub capability: SemanticCapability,
}
