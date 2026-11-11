//! Composition over small hand-built port graphs. The procedures, points and
//! carriers are real (the plan validates them), but every flow, dispatch and
//! caller comes from a hand-written fake provider.

use std::sync::Arc;

use brokk_bifrost_test_macros::hardwon;

use super::*;
use crate::analyzer::semantic::partial_flow::{
    HeapSelector, PartialFlow, PartialFlowOutcome, PartialFlowPort, PortId, ProcedurePartialFlows,
};
use crate::analyzer::semantic::{
    AbstractObject, AbstractObjectIdentity, AccessPathTail, CallSiteId, CandidateCoverage,
    EvidenceCompleteness, MemoryLocationId, ObjectCardinality, OracleCallContext, ProcedureHandle,
    ProofStatus, SemanticBudget, SemanticCallSite, SemanticRequest, ValueFlowOracle,
    ValueFlowRelation, ValueFlowSnapshot,
};
use crate::analyzer::{AnalyzerConfig, Language};
use crate::cancellation::CancellationToken;
use crate::dataflow::{SemanticInputStatus, SolverTermination, UnmodeledCallBehavior};
use crate::hash::HashMap;
use crate::inline_project::InlineTestProject;
use crate::taint::output_product::{OutputProductError, OutputReportRow};
use crate::taint::{
    SourceClassId, SourceEventKey, TaintAnalysisPlan, TaintClassSet, TaintEdgeFunction,
    TaintFindingReport, TaintSanitizerBinding, TaintSinkBinding, TaintSourceBinding, TaintUniverse,
};
use crate::value_flow::{
    AuthoredArmClosure, DurableCallSiteKey, DurableProcedureKey, ValueFlowCarrier,
    ValueFlowEventKey, ValueFlowEventKind, ValueFlowInput, ValueFlowObservationPhase,
    ValueFlowPlan, ValueFlowSinkSpec, ValueFlowSourceSpec,
};

const SOURCE: &str = r#"fn origin(seed: i32) -> i32 {
    let made = seed;
    made
}

fn helper(input: i32) -> i32 {
    let kept = input;
    kept
}

fn caller(arg: i32) -> i32 {
    let before = arg;
    let cleaned = helper(before);
    cleaned
}

fn target(value: i32) -> i32 {
    let seen = value;
    seen
}

fn other(v: i32) -> i32 {
    let w = v;
    w
}

fn fill(slot: &mut i32, made: i32) {
    let value = made;
    *slot = value;
}

fn show(slot: &i32) -> i32 {
    let seen = *slot;
    seen
}

fn pair(input: i32) -> i32 {
    let mut cell = input;
    fill(&mut cell, 1);
    show(&cell)
}
"#;

const NAMES: [&str; 8] = [
    "origin", "helper", "caller", "target", "other", "fill", "show", "pair",
];

const BUDGET: CompositionBudget = CompositionBudget {
    max_procedures: 64,
    max_hops: 4096,
    max_callers_per_procedure: 16,
};

/// The fixture's procedures with their relation snapshots.
struct Fixture {
    procedures: HashMap<&'static str, ProcedureHandle>,
    inputs: Vec<ValueFlowInput<ValueFlowSnapshot>>,
    first_relation: HashMap<&'static str, ValueFlowRelation>,
}

fn fixture() -> Fixture {
    let project = InlineTestProject::with_language(Language::Rust)
        .file("src/lib.rs", SOURCE)
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let cancellation = CancellationToken::default();
    let mut budget = SemanticBudget::default();
    let artifact = workspace
        .materialize_program_semantics(
            &project.file("src/lib.rs"),
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("fixture semantics materialize")
        .available_value()
        .cloned()
        .expect("fixture semantics remain available");
    let oracle = workspace.semantic_oracle_provider();
    let mut procedures = HashMap::default();
    let mut inputs = Vec::new();
    let mut first_relation = HashMap::default();
    for name in NAMES {
        let handle = artifact
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
            .expect("the fixture declares every named procedure");
        let mut budget = SemanticBudget::default();
        let outcome = oracle
            .procedure_relations(
                &handle,
                &OracleCallContext::empty(),
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("relations project");
        let status = SemanticInputStatus::from_outcome(&outcome);
        let snapshot = outcome
            .available_value()
            .expect("relations are available")
            .clone();
        first_relation.insert(
            name,
            snapshot
                .relations()
                .first()
                .expect("every fixture procedure has a relation")
                .clone(),
        );
        inputs.push(ValueFlowInput::new(snapshot, status));
        procedures.insert(name, handle);
    }
    Fixture {
        procedures,
        inputs,
        first_relation,
    }
}

fn class(name: &str) -> SourceClassId {
    SourceClassId::new(name).expect("valid class")
}

impl Fixture {
    /// `pair`'s calls of `fill` and `show`, in source order.
    fn pair_calls(&self) -> (CallSiteId, CallSiteId) {
        let calls = self.procedures["pair"]
            .semantics()
            .call_sites()
            .iter()
            .filter(|call| !call.arguments.is_empty())
            .collect::<Vec<_>>();
        let [into_fill, into_show] = calls.as_slice() else {
            panic!("pair calls fill and show: {calls:#?}");
        };
        (into_fill.id, into_show.id)
    }

    /// The fixture's one real call: `helper(before)` in `caller`.
    fn helper_call(&self) -> &SemanticCallSite {
        self.procedures["caller"]
            .semantics()
            .call_sites()
            .iter()
            .find(|call| call.arguments.len() == 1 && call.result.is_some())
            .expect("caller calls helper with one argument")
    }

    /// A plan with a source of class `alpha` in each of `sources` and a sink
    /// accepting `alpha` and `beta` in each of `sinks`. `removed` adds a
    /// sanitizer at `helper(before)` that removes those classes.
    fn plan(
        &self,
        sources: &[&'static str],
        sinks: &[&'static str],
        removed: Option<&[&str]>,
    ) -> TaintAnalysisPlan {
        let source_specs = sources
            .iter()
            .map(|name| {
                let relation = &self.first_relation[name];
                ValueFlowSourceSpec::new(
                    ValueFlowEventKey::at_point(relation.point(), 0, ValueFlowEventKind::Source)
                        .expect("source key"),
                    relation.point().clone(),
                    ValueFlowObservationPhase::BeforeEffects,
                    ValueFlowCarrier::from(&relation.source),
                    ProofStatus::Proven,
                    EvidenceCompleteness::Complete,
                )
            })
            .collect::<Vec<_>>();
        let sink_specs = sinks
            .iter()
            .map(|name| {
                let relation = &self.first_relation[name];
                ValueFlowSinkSpec::new(
                    ValueFlowEventKey::at_point(relation.point(), 0, ValueFlowEventKind::Sink)
                        .expect("sink key"),
                    relation.point().clone(),
                    ValueFlowObservationPhase::AfterEffects,
                    ValueFlowCarrier::from(&relation.target),
                    ProofStatus::Proven,
                    EvidenceCompleteness::Complete,
                )
            })
            .collect::<Vec<_>>();
        let value_flow = ValueFlowPlan::try_new(
            self.procedures[sinks[0]].clone(),
            self.inputs.clone(),
            Vec::new(),
            source_specs,
            sink_specs,
        )
        .expect("the value-flow plan builds");
        let universe = TaintUniverse::new(vec![class("alpha"), class("beta")]).expect("universe");
        let alpha = universe.class_set([&class("alpha")]).expect("alpha");
        let every = universe.class_set(universe.classes()).expect("every class");
        let sources = value_flow
            .sources()
            .map(|(id, spec)| {
                TaintSourceBinding::new(id, alpha.clone(), SourceEventKey::new(spec.key().clone()))
            })
            .collect();
        let sinks = value_flow
            .sinks()
            .map(|(id, _)| TaintSinkBinding::new(id, every.clone()))
            .collect();
        let sanitizers = removed
            .map(|removed| {
                let caller = &self.procedures["caller"];
                let call = self.helper_call();
                let carrier = |value| {
                    value_flow
                        .carrier_id(&ValueFlowCarrier::Value(
                            caller.value_handle(value).expect("call value"),
                        ))
                        .expect("the call's values are plan carriers")
                };
                let removed = removed.iter().map(|name| class(name)).collect::<Vec<_>>();
                TaintSanitizerBinding::resolved_with_output(
                    caller.point_handle(call.point).expect("call point"),
                    ValueFlowObservationPhase::AfterEffects,
                    0,
                    carrier(call.arguments[0].value),
                    carrier(call.result.expect("helper returns")),
                    universe.class_set(removed.iter()).expect("removed classes"),
                )
            })
            .into_iter()
            .collect();
        TaintAnalysisPlan::new(value_flow, universe, sources, sinks, sanitizers, Vec::new())
            .expect("the taint plan builds")
    }
}

fn seed_of_source(plan: &TaintAnalysisPlan, procedure: &ProcedureHandle) -> InteriorSeed {
    let (_, spec) = plan
        .value_flow()
        .sources()
        .find(|(_, spec)| spec.point().procedure() == procedure)
        .expect("the procedure holds a source");
    InteriorSeed::Source {
        point: spec.point().id(),
        phase: spec.phase(),
        carrier: spec.carrier().clone(),
    }
}

fn sink_in(plan: &TaintAnalysisPlan, procedure: &ProcedureHandle) -> FakeTarget {
    let (_, spec) = plan
        .value_flow()
        .sinks()
        .find(|(_, spec)| spec.point().procedure() == procedure)
        .expect("the procedure holds a sink");
    FakeTarget::Observe(InteriorObservation::Sink {
        point: spec.point().id(),
        phase: spec.phase(),
        carrier: spec.carrier().clone(),
    })
}

/// Where a fake interior flow arrives.
#[derive(Debug, Clone)]
enum FakeTarget {
    Observe(InteriorObservation),
    Port(PartialFlowPort),
}

/// A hand-written provider over in-memory graphs. Anything not configured is
/// empty and complete; the unmodeled-call behavior is the default, paranoid,
/// and a call has no fallback ports unless they are configured.
#[derive(Default)]
struct FakeGraph {
    handles: HashMap<DurableProcedureKey, ProcedureHandle>,
    flows: HashMap<DurableProcedureKey, Arc<ProcedurePartialFlows>>,
    barriers: bool,
    filtering: std::cell::Cell<bool>,
    strict: std::cell::Cell<bool>,
    undecided: std::collections::HashSet<DurableProcedureKey>,
    strict_alternative: std::collections::HashSet<DurableProcedureKey>,
    check_reads: std::cell::Cell<usize>,
    strict_witnesses: std::cell::RefCell<std::collections::HashSet<SourceEventKey>>,
    blocked: std::collections::HashSet<DurableProcedureKey>,
    filtered_flows: HashMap<DurableProcedureKey, Arc<ProcedurePartialFlows>>,
    filtered_crossed: HashMap<DurableProcedureKey, Box<[CallSiteId]>>,
    proof_reads: std::cell::RefCell<Vec<DurableCallSiteKey>>,
    store_writes: Vec<StoreWriteObservation>,
    store_links: HashMap<(DurableProcedureKey, PartialFlowPort), StoreChannelLinks>,

    interior: HashMap<DurableProcedureKey, Vec<(InteriorSeed, FakeTarget)>>,
    interior_completeness: HashMap<DurableProcedureKey, Completeness>,
    /// Interiors whose witness runs fail with this completeness, while the
    /// search's runs without witnesses still answer.
    witness_run_failures: HashMap<DurableProcedureKey, Completeness>,
    /// When set, witness runs after the first `n` fail with this completeness,
    /// so a later report pass fails where the main one answered.
    witness_runs_before_failure: Option<(usize, Completeness)>,
    witness_runs_made: std::cell::Cell<usize>,
    openness: HashMap<DurableProcedureKey, Openness>,
    uncertain_interior: bool,
    dispatches: HashMap<DurableCallSiteKey, Dispatch>,
    object_predecessors: Vec<(ObjectAnchorSite, PartialFlowPort, TaintEdgeFunction)>,
    certified_object_port: Option<PartialFlowPort>,
    selected_origin_target: Option<crate::analyzer::semantic::UnmaterializedExternalTarget>,
    handoffs: HashMap<DurableCallSiteKey, Vec<CallHandoff<TaintEdgeFunction>>>,
    callers: HashMap<DurableProcedureKey, Callers>,
    parents: HashMap<DurableProcedureKey, DurableProcedureKey>,
    models: HashMap<DurableCallSiteKey, CallModel>,
    behavior: UnmodeledCallBehavior,
    fallbacks: HashMap<DurableCallSiteKey, FallbackPorts>,
    endpoints: HashMap<DurableProcedureKey, ProcedureEndpoints>,
    /// Procedures whose endpoints the search asked for, in order.
    entered: std::cell::RefCell<Vec<DurableProcedureKey>>,
    /// The quality `source_evidence` answers for a source with unknown
    /// evidence.
    judgment: Option<HopQuality>,
    /// The sources whose evidence the report stage asked for, in order.
    judged: std::cell::RefCell<Vec<SourceEventKey>>,
}

fn partial_flows(ports: &[PartialFlowPort], flows: &[(usize, usize)]) -> ProcedurePartialFlows {
    ProcedurePartialFlows::new(
        PartialFlowOutcome::Complete,
        None,
        ports.to_vec(),
        flows
            .iter()
            .map(|&(from, to)| PartialFlow {
                from: PortId::try_from_index(from).expect("port id"),
                to: PortId::try_from_index(to).expect("port id"),
                uncertain: false,
                crossed: vec![Box::default()].into_boxed_slice(),
            })
            .collect(),
        false,
        true,
        Vec::new(),
    )
}

impl FakeGraph {
    fn new(fixture: &Fixture) -> Self {
        Self {
            handles: fixture
                .procedures
                .values()
                .map(|handle| (handle.durable_key(), handle.clone()))
                .collect(),
            ..Self::default()
        }
    }

    /// Stored flows of one procedure over `ports`, as `(from, to)` indexes.
    fn stored(
        &mut self,
        procedure: &ProcedureHandle,
        ports: &[PartialFlowPort],
        flows: &[(usize, usize)],
    ) {
        self.flows.insert(
            procedure.durable_key(),
            Arc::new(partial_flows(ports, flows)),
        );
    }

    fn interior(&mut self, procedure: &ProcedureHandle, seed: InteriorSeed, target: FakeTarget) {
        self.interior
            .entry(procedure.durable_key())
            .or_default()
            .push((seed, target));
    }

    fn route(
        &mut self,
        caller: &ProcedureHandle,
        call: CallSiteId,
        candidates: Vec<DispatchCandidate>,
        completeness: Completeness,
    ) {
        self.dispatches.insert(
            (caller.durable_key(), call),
            Dispatch {
                candidates,
                completeness,
                continuation: HopQuality::CERTAIN,
                external_body_unavailable: None,
            },
        );
    }
}

impl CompositionProvider for FakeGraph {
    type Error = String;
    type Fact = TaintClassSet;
    type Function = TaintEdgeFunction;

    fn object_relation(
        &self,
        _procedure: &DurableProcedureKey,
        at: &Endpoint,
        _request: &mut SemanticRequest<'_>,
    ) -> Result<ObjectRelation<Self::Fact, Self::Function>, Self::Error> {
        let Endpoint::Object(anchor) = at else {
            return Ok(ObjectRelation::none());
        };
        Ok(ObjectRelation {
            sources: Vec::new(),
            predecessors: self
                .object_predecessors
                .iter()
                .filter(|(site, _, _)| site == &anchor.site)
                .map(|(_, port, function)| ObjectPredecessor {
                    from: Endpoint::Port(port.clone()),
                    function: function.clone(),
                    quality: HopQuality::CERTAIN,
                })
                .collect(),
            complete: true,
            cross_call: true,
        })
    }

    fn certified_object_origin(
        &self,
        _root: &ObjectAnchor,
        _call: &DurableCallSiteKey,
        port: &PartialFlowPort,
        gap: &ExternalBodyUnavailableGap,
        _request: &mut SemanticRequest<'_>,
    ) -> Result<Option<()>, Self::Error> {
        Ok((self.certified_object_port.as_ref() == Some(port)
            && self
                .selected_origin_target
                .as_ref()
                .is_some_and(|target| gap.matches_origin_target(target)))
        .then_some(()))
    }

    fn call_handoffs(
        &self,
        call: &DurableCallSiteKey,
        _candidate: &DispatchCandidate,
        exit: CallHandoffExit,
        _request: &mut SemanticRequest<'_>,
    ) -> Result<CallHandoffInventory<Self::Function>, Self::Error> {
        Ok(CallHandoffInventory {
            handoffs: self
                .handoffs
                .get(call)
                .into_iter()
                .flatten()
                .filter(|handoff| handoff.binding.exit == exit)
                .cloned()
                .collect(),
            complete: false,
        })
    }

    fn store_writes(&self) -> Vec<StoreWriteObservation> {
        self.store_writes.clone()
    }

    fn store_links(
        &self,
        procedure: &DurableProcedureKey,
        output: &PartialFlowPort,
    ) -> StoreChannelLinks {
        self.store_links
            .get(&(procedure.clone(), output.clone()))
            .cloned()
            .unwrap_or_default()
    }

    fn has_value_type_barriers(&self) -> bool {
        self.barriers
    }

    fn filter_value_type_barriers(&self, _chop: &std::collections::HashSet<DurableProcedureKey>) {
        self.filtering.set(true);
        self.strict.set(false);
    }

    fn strict_value_type_barriers(&self, _chop: &std::collections::HashSet<DurableProcedureKey>) {
        self.strict.set(true);
    }

    fn value_type_barrier_checks(
        &self,
        observations: &[crate::analyzer::semantic::BarrierObservation],
        _request: &mut SemanticRequest<'_>,
    ) -> Result<Vec<ValueTypeBarrierCheck>, Self::Error> {
        self.check_reads
            .set(self.check_reads.get() + observations.len());
        Ok(observations
            .iter()
            .map(|observation| ValueTypeBarrierCheck {
                id: "boolean".into(),
                observation: observation.clone(),
                predicate: crate::analyzer::semantic::ValueTypePredicate::IntrinsicBool,
                decision: if self
                    .undecided
                    .contains(&observation.point().procedure().durable_key())
                    && observation.value()
                        == observation.point().procedure().semantics().values()[1].id
                {
                    crate::analyzer::semantic::ValueTypeBarrierDecision::Undecided(
                        crate::analyzer::semantic::ValueTypeBarrierReason::UnknownType,
                    )
                } else {
                    crate::analyzer::semantic::ValueTypeBarrierDecision::ProvenNonMatch
                },
            })
            .collect())
    }

    fn reset_value_type_witnesses(&self) {
        self.strict_witnesses.borrow_mut().clear();
    }

    fn retain_strict_value_type_witness(
        &self,
        source: &BoundSource,
        _sink: crate::value_flow::ValueFlowSinkId,
    ) {
        self.strict_witnesses
            .borrow_mut()
            .insert(source.origin.clone());
    }

    fn prepare_value_type_witness(
        &self,
        source: &BoundSource,
        _sink: crate::value_flow::ValueFlowSinkId,
    ) {
        self.strict
            .set(self.strict_witnesses.borrow().contains(&source.origin));
    }

    fn partial_flows(
        &self,
        procedure: &DurableProcedureKey,
        _request: &mut SemanticRequest<'_>,
    ) -> Result<Arc<ProcedurePartialFlows>, Self::Error> {
        if self.filtering.get()
            && let Some(flows) = self.filtered_flows.get(procedure)
        {
            return Ok(Arc::clone(flows));
        }
        Ok(self
            .flows
            .get(procedure)
            .cloned()
            .unwrap_or_else(|| Arc::new(partial_flows(&[], &[]))))
    }

    fn interior_flows(
        &self,
        procedure: &DurableProcedureKey,
        seeds: &[InteriorSeed],
        observations: &[InteriorObservation],
        witnesses: bool,
        _request: &mut SemanticRequest<'_>,
    ) -> Result<InteriorFlows, Self::Error> {
        let handle = self.handles[procedure].clone();
        if witnesses && let Some(failure) = self.witness_run_failures.get(procedure) {
            return Ok(InteriorFlows {
                procedure: handle,
                flows: Vec::new(),
                completeness: failure.clone(),
            });
        }
        if witnesses && let Some((answered, failure)) = &self.witness_runs_before_failure {
            let made = self.witness_runs_made.get();
            self.witness_runs_made.set(made + 1);
            if made >= *answered {
                return Ok(InteriorFlows {
                    procedure: handle,
                    flows: Vec::new(),
                    completeness: failure.clone(),
                });
            }
        }
        let entry = handle.semantics().entry_point();
        let mut flows = Vec::new();
        for (seed, target) in self.interior.get(procedure).into_iter().flatten() {
            if self.filtering.get() && self.blocked.contains(procedure) {
                continue;
            }
            if self.strict.get()
                && self.undecided.contains(procedure)
                && !self.strict_alternative.contains(procedure)
            {
                continue;
            }
            let Some(seed) = seeds.iter().position(|requested| requested == seed) else {
                continue;
            };
            let target = match target {
                FakeTarget::Observe(observation) => {
                    let Some(index) = observations
                        .iter()
                        .position(|requested| requested == observation)
                    else {
                        continue;
                    };
                    InteriorTarget::Observation(index)
                }
                FakeTarget::Port(port) => InteriorTarget::Port(port.clone()),
            };
            flows.push(InteriorFlow {
                seed,
                target,
                uncertain: self.uncertain_interior,
                crossed: vec![if self.filtering.get() {
                    self.filtered_crossed
                        .get(procedure)
                        .cloned()
                        .unwrap_or_default()
                } else {
                    Box::default()
                }]
                .into_boxed_slice(),
                witness: witnesses.then(|| {
                    vec![InteriorWitnessStep {
                        point: entry,
                        event: 0,
                        source: None,
                        target: self.undecided.contains(procedure).then(|| {
                            // Strict selection chooses a different value
                            // path; the classifier's answer never depends
                            // on which filter consumes it.
                            let index = usize::from(!self.strict.get());
                            handle.semantics().values()[index].id
                        }),
                        phase: crate::analyzer::semantic::ObservationPhase::BeforeEffects,
                    }]
                    .into_boxed_slice()
                }),
            });
        }
        Ok(InteriorFlows {
            procedure: handle,
            flows,
            completeness: self
                .interior_completeness
                .get(procedure)
                .cloned()
                .unwrap_or(Completeness::Complete),
        })
    }

    fn dispatch(
        &self,
        call: &DurableCallSiteKey,
        _request: &mut SemanticRequest<'_>,
    ) -> Result<(Dispatch, Option<CallModel>), Self::Error> {
        self.proof_reads.borrow_mut().push(call.clone());
        let dispatch = self.dispatches.get(call).cloned().unwrap_or(Dispatch {
            candidates: Vec::new(),
            completeness: Completeness::Complete,
            continuation: HopQuality::CERTAIN,
            external_body_unavailable: None,
        });
        Ok((dispatch, self.models.get(call).cloned()))
    }

    fn callers(
        &self,
        procedure: &DurableProcedureKey,
        _request: &mut SemanticRequest<'_>,
    ) -> Result<Callers, Self::Error> {
        Ok(self.callers.get(procedure).cloned().unwrap_or(Callers {
            calls: Vec::new(),
            completeness: Completeness::Complete,
        }))
    }

    fn lexical_parent(
        &self,
        procedure: &DurableProcedureKey,
        _request: &mut SemanticRequest<'_>,
    ) -> Result<Option<DurableProcedureKey>, Self::Error> {
        Ok(self.parents.get(procedure).cloned())
    }

    fn authored_models(&self) -> Vec<Box<[AuthoredArmClosure]>> {
        self.models
            .values()
            .filter_map(|model| model.authored.clone())
            .collect()
    }

    fn unmodeled_call_behavior(&self) -> UnmodeledCallBehavior {
        self.behavior
    }

    fn fallback_ports(
        &self,
        call: &DurableCallSiteKey,
        _request: &mut SemanticRequest<'_>,
    ) -> Result<FallbackPorts, Self::Error> {
        Ok(self.fallbacks.get(call).cloned().unwrap_or(FallbackPorts {
            inputs: Box::default(),
            outputs: Box::default(),
        }))
    }

    fn openness(
        &self,
        procedure: &DurableProcedureKey,
        _request: &mut SemanticRequest<'_>,
    ) -> Result<Openness, Self::Error> {
        Ok(self
            .openness
            .get(procedure)
            .cloned()
            .unwrap_or(Openness::Closed))
    }

    fn endpoints(
        &self,
        procedure: &DurableProcedureKey,
        _request: &mut SemanticRequest<'_>,
    ) -> Result<ProcedureEndpoints, Self::Error> {
        self.entered.borrow_mut().push(procedure.clone());
        Ok(self
            .endpoints
            .get(procedure)
            .cloned()
            .unwrap_or_else(ProcedureEndpoints::none))
    }

    fn source_evidence(
        &self,
        source: &BoundSource,
        _request: &mut SemanticRequest<'_>,
    ) -> Result<HopQuality, Self::Error> {
        self.judged.borrow_mut().push(source.origin.clone());
        Ok(self
            .judgment
            .expect("a test that leaves evidence unknown configures its judgment"))
    }
}

fn compose(
    plan: &TaintAnalysisPlan,
    graph: &FakeGraph,
    budget: CompositionBudget,
) -> ComposeOutcome {
    let cancellation = CancellationToken::default();
    let mut semantic_budget = SemanticBudget::default();
    compose_taint_batch(
        plan,
        graph,
        budget,
        &mut SemanticRequest::new(&mut semantic_budget, &cancellation),
    )
    .expect("composition runs")
}

fn classes(plan: &TaintAnalysisPlan, names: &[&str]) -> TaintClassSet {
    let names = names.iter().map(|name| class(name)).collect::<Vec<_>>();
    plan.universe()
        .class_set(names.iter())
        .expect("classes of the universe")
}

fn result(call: CallSiteId) -> PartialFlowPort {
    PartialFlowPort::CallResult {
        call,
        ordinal: None,
    }
}

fn argument(call: CallSiteId, ordinal: u32) -> PartialFlowPort {
    PartialFlowPort::CallArgument { call, ordinal }
}

fn parameter(ordinal: u32) -> PartialFlowPort {
    PartialFlowPort::Parameter { ordinal }
}

/// A candidate that binds argument 0 to parameter 0 and returns its normal
/// return as the call's result.
fn plain_candidate(procedure: &ProcedureHandle, call: CallSiteId) -> DispatchCandidate {
    DispatchCandidate {
        procedure: procedure.durable_key(),
        written_heap_ports: None,
        arguments: vec![(argument(call, 0), parameter(0))].into_boxed_slice(),
        writeback: Box::default(),
        returns: vec![(PartialFlowPort::NormalReturn, result(call))].into_boxed_slice(),
    }
}

/// One finding of class `alpha` at the only sink, from the only source.
fn assert_single_alpha_finding(plan: &TaintAnalysisPlan, report: &TaintFindingReport) {
    assert_eq!(report.findings().len(), 1, "{report:#?}");
    let finding = &report.findings()[0];
    assert_eq!(finding.classes(), &classes(plan, &["alpha"]));
    assert_eq!(finding.origins().origins().len(), 1);
}

#[test]
#[hardwon("#8896: older Output rows could bypass the typed modeled-receiver payload contract")]
fn output_product_round_trips_two_origins_and_a_witness() {
    let fixture = fixture();
    let plan = fixture.plan(&["origin", "target"], &["target"], None);
    let target = &fixture.procedures["target"];
    let mut graph = callee_return_graph(&fixture, &plan, Completeness::Complete);
    graph.interior(
        target,
        seed_of_source(&plan, target),
        sink_in(&plan, target),
    );
    let report = compose(&plan, &graph, BUDGET).report;
    assert_eq!(report.findings().len(), 1, "{report:#?}");
    let finding = &report.findings()[0];
    assert_eq!(finding.origins().evidence().len(), 2, "{finding:#?}");
    assert!(
        finding
            .origins()
            .evidence()
            .iter()
            .flat_map(|origin| origin.witnesses())
            .any(|witness| !witness.steps().is_empty())
    );
    let encoded = OutputReportRow::encode(&plan, finding.key().sink().site(), &report)
        .expect("encode complete composed report");
    let decoded = OutputReportRow::decode_for_plan(&plan, encoded.clone())
        .expect("decode output product for its compile");
    assert!(
        !decoded.report_evidence_complete(),
        "missing witness evidence stays open"
    );
    assert_eq!(serde_json::to_value(decoded).unwrap(), encoded);
    assert_eq!(encoded["version"], 8);
    let mut empty = encoded.clone();
    empty["findings"] = serde_json::json!([]);
    empty["witnesses"] = serde_json::json!([]);
    empty["retained_witnesses"] = 0.into();
    empty["retained_witness_steps"] = 0.into();
    assert!(OutputReportRow::decode(empty.clone()).is_ok());
    // The version is an exact fence: the previous version 6 is rejected too.
    for old_version in [1, 2, 3, 4, 5, 6] {
        let mut old = encoded.clone();
        old["version"] = old_version.into();
        assert_eq!(
            OutputReportRow::decode(old).unwrap_err(),
            OutputProductError::Corrupt
        );

        let mut old_empty = empty.clone();
        old_empty["version"] = old_version.into();
        assert_eq!(
            OutputReportRow::decode(old_empty).unwrap_err(),
            OutputProductError::Corrupt
        );
    }

    assert!(encoded["findings"][0].get("model_receipt").is_none());
    let receipt = crate::model_attribution::model_receipt_from_full(
        vec![crate::model_attribution::ModelContributor {
            role: crate::model_attribution::ModelContributorRole::Summary,
            pack_digest: "a".repeat(64),
            record_id: "selected-summary".into(),
            built_from: "0.4.23".into(),
            resolved: "0.4.25".into(),
            direction: "older_artifact".into(),
            mismatch_kinds: vec!["version_nearby".into()],
            selection_rule_id: "cargo-compatible-nearest".into(),
            selection_rule_version: 1,
        }],
        crate::model_attribution::SUMMARY_RECEIPT_CAP,
    );
    let mut attributed = encoded.clone();
    attributed["findings"][0]["model_receipt"] = serde_json::to_value(&receipt).unwrap();
    let replayed = OutputReportRow::decode_for_plan(&plan, attributed.clone())
        .expect("persisted attributed output row replays");
    assert_eq!(replayed.findings[0].model_receipt.as_ref(), Some(&receipt));
    assert_eq!(serde_json::to_value(replayed).unwrap(), attributed);
    for (built, resolved, direction) in [
        ("invalid", "0.4.25", "older_artifact"),
        ("0.4.23", "invalid", "older_artifact"),
        ("0.4.23", "0.4.25", "newer_artifact"),
        ("0.4.25", "0.4.23", "older_artifact"),
        ("0.4.23", "0.4.23", "older_artifact"),
    ] {
        let mut malformed = attributed.clone();
        let contributor = &mut malformed["findings"][0]["model_receipt"]["contributors"][0];
        contributor["built_from"] = built.into();
        contributor["resolved"] = resolved.into();
        contributor["direction"] = direction.into();
        assert_eq!(
            OutputReportRow::decode(malformed).unwrap_err(),
            OutputProductError::Corrupt
        );
    }

    let mut modeled = encoded.clone();
    let call = modeled["anchor"].clone();
    let mut operand = call.clone();
    let start = operand["anchor"]["start"]["byte_offset"].as_u64().unwrap();
    let column = operand["anchor"]["start"]["byte_column"].as_u64().unwrap();
    operand["anchor"]["start"]["byte_offset"] = (start + 1).into();
    operand["anchor"]["start"]["byte_column"] = (column + 1).into();
    let step = &mut modeled["witnesses"][0]["steps"][0];
    step["kind"] = "edge:modeled_receiver".into();
    step["origin"] = call.clone();
    step["typed"] = serde_json::json!({"ModeledReceiver": {"operand": operand}});
    let modeled_row = OutputReportRow::decode(modeled.clone()).expect("modeled receiver codec");
    let modeled_again = serde_json::to_value(modeled_row).unwrap();
    assert_eq!(modeled_again["witnesses"][0]["steps"][0]["origin"], call);
    assert_eq!(
        modeled_again["witnesses"][0]["steps"][0]["typed"]["ModeledReceiver"]["operand"],
        operand
    );
    let mut missing_typed = modeled.clone();
    missing_typed["witnesses"][0]["steps"][0]
        .as_object_mut()
        .unwrap()
        .remove("typed");
    assert_eq!(
        OutputReportRow::decode(missing_typed).unwrap_err(),
        OutputProductError::Corrupt
    );
    let mut mismatched = modeled.clone();
    mismatched["witnesses"][0]["steps"][0]["typed"] = "None".into();
    assert_eq!(
        OutputReportRow::decode(mismatched).unwrap_err(),
        OutputProductError::Corrupt
    );
    let mut wrong_call = modeled;
    wrong_call["witnesses"][0]["steps"][0]["origin"] = serde_json::Value::Null;
    assert_eq!(
        OutputReportRow::decode(wrong_call).unwrap_err(),
        OutputProductError::Corrupt
    );

    let mut remounted = encoded.clone();
    let stored_mount = serde_json::to_value(crate::analyzer::semantic::StableDigest::sha256(
        b"stored output report mount",
    ))
    .unwrap();
    let mut pending = vec![&mut remounted];
    while let Some(value) = pending.pop() {
        match value {
            serde_json::Value::Object(fields) => {
                if let Some(mount) = fields.get_mut("mount") {
                    *mount = stored_mount.clone();
                }
                pending.extend(fields.values_mut());
            }
            serde_json::Value::Array(values) => pending.extend(values.iter_mut()),
            _ => {}
        }
    }
    assert_eq!(
        OutputReportRow::decode_for_plan(&plan, remounted).unwrap(),
        OutputReportRow::decode(encoded.clone()).unwrap()
    );
    let mut corrupt = encoded.clone();
    let origins = corrupt["findings"][0]["origins"].as_array_mut().unwrap();
    let witness = origins
        .iter_mut()
        .find(|origin| !origin["witness_paths"].as_array().unwrap().is_empty())
        .expect("at least one retained witness");
    witness["witness_paths"][0] = serde_json::json!(usize::MAX);
    assert!(OutputReportRow::decode(corrupt).is_err());
    let (_, source) = plan.value_flow().sources().next().expect("a bound source");
    let key = source
        .carrier()
        .stable_key()
        .expect("stable source carrier");
    let row = super::super::output_product::OutputCarrierRow::encode(&key);
    assert_eq!(row.decode_key().expect("decode stable carrier"), key);
    let source_event = super::super::output_product::OutputEventRow::encode(source.key());
    assert_eq!(
        source_event.decode_key().expect("decode stable event"),
        source.key().clone()
    );
}

/// `origin`'s source returns into `target`'s sink through call 40.
fn callee_return_graph(
    fixture: &Fixture,
    plan: &TaintAnalysisPlan,
    completeness: Completeness,
) -> FakeGraph {
    let target = &fixture.procedures["target"];
    let origin = &fixture.procedures["origin"];
    let call = CallSiteId::new(40);
    let mut graph = FakeGraph::new(fixture);
    graph.stored(target, &[result(call)], &[]);
    graph.interior(
        target,
        InteriorSeed::Port(result(call)),
        sink_in(plan, target),
    );
    graph.route(
        target,
        call,
        vec![plain_candidate(origin, call)],
        completeness,
    );
    graph.interior(
        origin,
        seed_of_source(plan, origin),
        FakeTarget::Port(PartialFlowPort::NormalReturn),
    );
    graph
}

#[test]
fn later_content_gap_keeps_an_earlier_operational_stop() {
    let stopped = Completeness::operational(
        OperationalCause::Budget(BudgetLane::Semantic),
        "semantic budget stopped",
    );
    let combined =
        Completeness::content("later content gap").preserving_operational_cause(&stopped);
    assert_eq!(
        combined,
        Completeness::operational(
            OperationalCause::Budget(BudgetLane::Semantic),
            "later content gap",
        )
    );
    assert_eq!(
        Completeness::operational(OperationalCause::Provider, "later unknown gap")
            .preserving_operational_cause(&stopped),
        Completeness::operational(
            OperationalCause::Budget(BudgetLane::Semantic),
            "later unknown gap",
        )
    );
}

#[test]
fn a_source_reaches_a_sink_in_the_same_procedure() {
    let fixture = fixture();
    let plan = fixture.plan(&["target"], &["target"], None);
    let target = &fixture.procedures["target"];
    let mut graph = FakeGraph::new(&fixture);
    graph.interior(
        target,
        seed_of_source(&plan, target),
        sink_in(&plan, target),
    );
    // An unrelated call whose dispatch is open: the search never asks for it,
    // because nothing it looks for passes through that call.
    let unrelated = CallSiteId::new(49);
    graph.stored(target, &[argument(unrelated, 0), result(unrelated)], &[]);
    graph.route(
        target,
        unrelated,
        vec![plain_candidate(&fixture.procedures["other"], unrelated)],
        Completeness::content("open dispatch"),
    );
    let ComposeOutcome {
        report,
        incompleteness,
        ..
    } = compose(&plan, &graph, BUDGET);
    assert!(incompleteness.is_empty(), "{incompleteness:#?}");
    assert_single_alpha_finding(&plan, &report);
    let finding = &report.findings()[0];
    assert!(finding.is_proven() && finding.is_complete() && report.is_complete());
    assert_eq!(finding.origins().evidence()[0].witnesses().len(), 1);
    assert!(finding.origins().is_complete());
}

#[test]
#[hardwon("#9947: a witness run's provider failure was typed as answer content")]
fn a_failed_witness_run_reports_its_cause() {
    let fixture = fixture();
    let plan = fixture.plan(&["target"], &["target"], None);
    let target = &fixture.procedures["target"];
    let mut graph = FakeGraph::new(&fixture);
    graph.interior(
        target,
        seed_of_source(&plan, target),
        sink_in(&plan, target),
    );
    let failure = Completeness::operational(
        OperationalCause::Provider,
        "the procedure's value-flow snapshot is unavailable",
    );
    graph
        .witness_run_failures
        .insert(target.durable_key(), failure);
    let ComposeOutcome {
        report,
        incompleteness,
        finding_incompleteness,
        ..
    } = compose(&plan, &graph, BUDGET);
    assert!(incompleteness.is_empty(), "{incompleteness:#?}");
    assert_single_alpha_finding(&plan, &report);
    assert!(report.findings()[0].origins().witness_unavailable());
    assert_eq!(
        finding_incompleteness,
        vec![Incompleteness::Interior {
            procedure: target.durable_key(),
            reason: "the procedure's value-flow snapshot is unavailable".into(),
            cause: IncompleteCause::Operational(OperationalCause::Provider),
        }]
    );
}

#[test]
#[hardwon("#9947: a budget-exceeded snapshot loss was typed Provider and skipped the cold loop")]
fn a_lost_snapshot_keeps_its_budget_or_cancellation_cause() {
    // The slice fallback takes the full cold loop only on a Budget cause.
    let fixture = fixture();
    let target = &fixture.procedures["target"];
    let cause = |status| match crate::composition::unavailable_snapshot_interior(
        target.clone(),
        status,
        "lost",
    )
    .completeness
    {
        Completeness::Incomplete { cause, .. } => cause,
        Completeness::Complete => panic!("a lost snapshot leaves its interior incomplete"),
    };
    assert_eq!(
        cause(SemanticInputStatus::ExceededBudget {
            exceeded: crate::test_support::procedure_budget_error(2, 3),
        }),
        IncompleteCause::Operational(OperationalCause::Budget(BudgetLane::Semantic))
    );
    assert_eq!(
        cause(SemanticInputStatus::Cancelled),
        IncompleteCause::Operational(OperationalCause::Cancelled)
    );
    assert_eq!(
        cause(SemanticInputStatus::Unknown),
        IncompleteCause::Operational(OperationalCause::Provider)
    );
}

#[test]
fn report_dispatches_a_sink_call_not_seen_by_search() {
    let fixture = fixture();
    let caller = &fixture.procedures["caller"];
    let call = fixture.helper_call();
    let source = &fixture.first_relation["caller"];
    let source_spec = ValueFlowSourceSpec::new(
        ValueFlowEventKey::at_point(source.point(), 0, ValueFlowEventKind::Source)
            .expect("source key"),
        source.point().clone(),
        ValueFlowObservationPhase::BeforeEffects,
        ValueFlowCarrier::from(&source.source),
        ProofStatus::Proven,
        EvidenceCompleteness::Complete,
    );
    let sink_point = caller.point_handle(call.point).expect("call point");
    let sink_carrier = ValueFlowCarrier::Value(
        caller
            .value_handle(call.result.expect("call result"))
            .expect("result value"),
    );
    let sink_spec = ValueFlowSinkSpec::new(
        ValueFlowEventKey::at_point(&sink_point, 0, ValueFlowEventKind::Sink).expect("sink key"),
        sink_point,
        ValueFlowObservationPhase::AfterEffects,
        sink_carrier,
        ProofStatus::Proven,
        EvidenceCompleteness::Complete,
    );
    let value_flow = ValueFlowPlan::try_new(
        caller.clone(),
        fixture.inputs.clone(),
        Vec::new(),
        vec![source_spec],
        vec![sink_spec],
    )
    .expect("plan");
    let universe = TaintUniverse::new(vec![class("alpha")]).expect("universe");
    let alpha = universe.class_set([&class("alpha")]).expect("class");
    let source_id = value_flow.sources().next().expect("source").0;
    let source_key = value_flow
        .source(source_id)
        .expect("source spec")
        .key()
        .clone();
    let sink_id = value_flow.sinks().next().expect("sink").0;
    let plan = TaintAnalysisPlan::new(
        value_flow,
        universe,
        vec![TaintSourceBinding::new(
            source_id,
            alpha.clone(),
            SourceEventKey::new(source_key),
        )],
        vec![TaintSinkBinding::new(sink_id, alpha)],
        Vec::new(),
        Vec::new(),
    )
    .expect("taint plan");
    let mut graph = FakeGraph::new(&fixture);
    graph.uncertain_interior = true;
    graph.interior(
        caller,
        seed_of_source(&plan, caller),
        sink_in(&plan, caller),
    );
    graph.models.insert(
        (caller.durable_key(), call.id),
        CallModel {
            summary: None,
            summary_target: None,
            transfers: Vec::new(),
            writeback: Box::default(),
            receiver_reads: Box::default(),
            proven: true,
            completeness: Completeness::Complete,
            retains_dispatch: false,
            authored: Some(Box::default()),
        },
    );
    let outcome = compose(&plan, &graph, BUDGET);
    assert_single_alpha_finding(&plan, &outcome.report);
    assert_eq!(
        graph.proof_reads.borrow().as_slice(),
        &[(caller.durable_key(), call.id)],
        "the report must dispatch the sink call that search did not encounter"
    );
    assert!(matches!(
        outcome.finding_incompleteness.as_slice(),
        [Incompleteness::Model { call: modeled, .. }] if modeled == &(caller.durable_key(), call.id)
    ));
}

#[test]
fn a_store_read_wakes_only_after_a_source_reaches_a_linked_write() {
    let fixture = fixture();
    let plan = fixture.plan(&["origin"], &["caller"], None);
    let origin = &fixture.procedures["origin"];
    let caller = &fixture.procedures["caller"];
    let call = fixture.helper_call().id;
    let relation = &fixture.first_relation["origin"];
    let write = StoreWriteObservation {
        procedure: origin.durable_key(),
        owner: origin.clone(),
        point: relation.point().id(),
        phase: ValueFlowObservationPhase::AfterEffects,
        carrier: ValueFlowCarrier::from(&relation.target),
    };
    let observation = InteriorObservation::Sink {
        point: write.point,
        phase: write.phase,
        carrier: write.carrier.clone(),
    };
    let mut graph = FakeGraph::new(&fixture);
    graph.store_writes.push(write);
    graph.store_links.insert(
        (caller.durable_key(), result(call)),
        StoreChannelLinks {
            writes: vec![StoreChannelLink {
                write: 0,
                write_call: (origin.durable_key(), CallSiteId::new(77)),
                read_call: (caller.durable_key(), call),
                write_site: plan.sources()[0].origin().value_flow_key().site().clone(),
                read_site: plan.sources()[0].origin().value_flow_key().site().clone(),
                read_origin: plan.sources()[0].origin().clone(),
                read_phase: ValueFlowObservationPhase::AfterEffects,
                read_carrier: ValueFlowCarrier::from(&relation.target),
                uncertain: false,
            }],
            incomplete: None,
        },
    );
    graph.stored(origin, &[], &[]);
    graph.stored(caller, &[result(call)], &[]);
    graph.interior(
        caller,
        InteriorSeed::Port(result(call)),
        sink_in(&plan, caller),
    );
    assert!(compose(&plan, &graph, BUDGET).report.findings().is_empty());
    graph.interior(
        origin,
        seed_of_source(&plan, origin),
        FakeTarget::Observe(observation),
    );
    let outcome = compose(&plan, &graph, BUDGET);
    assert!(
        outcome.incompleteness.is_empty(),
        "{:#?}",
        outcome.incompleteness
    );
    assert_single_alpha_finding(&plan, &outcome.report);
    graph
        .store_links
        .get_mut(&(caller.durable_key(), result(call)))
        .expect("the read has selected store links")
        .incomplete = Some("write selector stopped before inventory closure".into());
    let incomplete = compose(&plan, &graph, BUDGET);
    assert!(!incomplete.report.is_complete());
    assert!(
        incomplete
            .incompleteness
            .iter()
            .any(|reason| matches!(reason, Incompleteness::StoreInventory { .. }))
    );
}

#[test]
fn a_source_in_a_callee_returns_into_the_sink_procedure() {
    let fixture = fixture();
    let plan = fixture.plan(&["origin"], &["target"], None);
    let graph = callee_return_graph(&fixture, &plan, Completeness::Complete);
    let ComposeOutcome {
        report,
        incompleteness,
        ..
    } = compose(&plan, &graph, BUDGET);
    assert!(incompleteness.is_empty(), "{incompleteness:#?}");
    assert_single_alpha_finding(&plan, &report);
    assert!(report.findings()[0].is_complete() && report.is_complete());
}

#[test]
fn a_source_in_a_caller_is_passed_as_an_argument() {
    let fixture = fixture();
    let plan = fixture.plan(&["origin"], &["target"], None);
    let target = &fixture.procedures["target"];
    let origin = &fixture.procedures["origin"];
    let call = CallSiteId::new(41);
    let mut graph = FakeGraph::new(&fixture);
    graph.stored(target, &[parameter(0)], &[]);
    graph.interior(
        target,
        InteriorSeed::Port(parameter(0)),
        sink_in(&plan, target),
    );
    graph.callers.insert(
        target.durable_key(),
        Callers {
            calls: vec![(origin.durable_key(), call)],
            completeness: Completeness::Complete,
        },
    );
    graph.route(
        origin,
        call,
        vec![plain_candidate(target, call)],
        Completeness::Complete,
    );
    graph.interior(
        origin,
        seed_of_source(&plan, origin),
        FakeTarget::Port(argument(call, 0)),
    );
    let ComposeOutcome {
        report,
        incompleteness,
        ..
    } = compose(&plan, &graph, BUDGET);
    assert!(incompleteness.is_empty(), "{incompleteness:#?}");
    assert_single_alpha_finding(&plan, &report);
}

#[test]
fn object_handoff_requires_exact_continuity_and_unique_dispatch() {
    let fixture = fixture();
    let plan = fixture.plan(&["caller"], &["caller"], None);
    let caller = &fixture.procedures["caller"];
    let helper = &fixture.procedures["helper"];
    let call = fixture.helper_call().id;
    let call_key = (caller.durable_key(), call);
    let mut graph = FakeGraph::new(&fixture);
    graph.stored(caller, &[argument(call, 0), result(call)], &[]);
    graph.interior(
        caller,
        seed_of_source(&plan, caller),
        FakeTarget::Port(argument(call, 0)),
    );
    graph.interior(
        caller,
        InteriorSeed::Port(result(call)),
        sink_in(&plan, caller),
    );
    let mut candidate = plain_candidate(helper, call);
    candidate.returns = Box::default();
    graph.route(caller, call, vec![candidate], Completeness::Complete);
    graph.handoffs.insert(
        call_key,
        vec![CallHandoff {
            binding: CallHandoffBinding {
                argument_index: 0,
                exit: CallHandoffExit::Normal,
                continuity: CallObjectContinuity::Reference,
                quality: HopQuality::CERTAIN,
            },
            function: TaintEdgeFunction::identity(plan.universe()),
        }],
    );

    let run = |graph: &FakeGraph| {
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        search::search_pairs(
            taint_query(&plan),
            graph,
            BUDGET,
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("object handoff search")
    };
    let certain = run(&graph);
    let [pair] = certain.pairs.as_slice() else {
        panic!("expected one object path: {:#?}", certain.pairs);
    };
    assert!(pair.paths.iter().any(|(hops, quality)| {
        quality.is_certain()
            && hops
                .iter()
                .any(|hop| matches!(hop, Hop::CallHandoff { .. }))
    }));

    graph.handoffs.values_mut().next().expect("one call")[0]
        .binding
        .continuity = CallObjectContinuity::Unknown;
    let uncertain = run(&graph);
    assert!(
        uncertain.pairs[0]
            .paths
            .iter()
            .all(|(_, quality)| !quality.is_certain())
    );
}

/// A value passed to a helper by one caller does not return from that
/// helper into another caller: a callee root maps formals back only through
/// the call that opened it.
#[test]
fn a_helper_does_not_return_one_callers_argument_to_another() {
    let fixture = fixture();
    let plan = fixture.plan(&["origin"], &["target"], None);
    let target = &fixture.procedures["target"];
    let origin = &fixture.procedures["origin"];
    let helper = &fixture.procedures["helper"];
    let from_origin = CallSiteId::new(42);
    let from_target = CallSiteId::new(43);
    let mut graph = FakeGraph::new(&fixture);
    graph.stored(
        helper,
        &[parameter(0), PartialFlowPort::NormalReturn],
        &[(0, 1)],
    );
    graph.callers.insert(
        helper.durable_key(),
        Callers {
            calls: vec![
                (origin.durable_key(), from_origin),
                (target.durable_key(), from_target),
            ],
            completeness: Completeness::Complete,
        },
    );
    // origin passes its source to helper and drops the result.
    graph.interior(
        origin,
        seed_of_source(&plan, origin),
        FakeTarget::Port(argument(from_origin, 0)),
    );
    graph.route(
        origin,
        from_origin,
        vec![plain_candidate(helper, from_origin)],
        Completeness::Complete,
    );
    // target passes a clean value to helper and logs the result.
    graph.stored(
        target,
        &[argument(from_target, 0), result(from_target)],
        &[],
    );
    graph.interior(
        target,
        InteriorSeed::Port(result(from_target)),
        sink_in(&plan, target),
    );
    graph.route(
        target,
        from_target,
        vec![plain_candidate(helper, from_target)],
        Completeness::Complete,
    );
    let ComposeOutcome {
        report,
        incompleteness,
        ..
    } = compose(&plan, &graph, BUDGET);
    assert!(incompleteness.is_empty(), "{incompleteness:#?}");
    assert!(report.findings().is_empty(), "{report:#?}");
    assert!(report.is_complete());
}

#[test]
fn a_cycle_between_two_procedures_terminates() {
    let fixture = fixture();
    let plan = fixture.plan(&["other"], &["target"], None);
    let target = &fixture.procedures["target"];
    let other = &fixture.procedures["other"];
    let into_other = CallSiteId::new(44);
    let into_target = CallSiteId::new(45);
    let mut graph = FakeGraph::new(&fixture);
    // target logs and returns the result of other(); other returns the
    // result of target() or its own source.
    graph.stored(
        target,
        &[result(into_other), PartialFlowPort::NormalReturn],
        &[(0, 1)],
    );
    graph.interior(
        target,
        InteriorSeed::Port(result(into_other)),
        sink_in(&plan, target),
    );
    graph.route(
        target,
        into_other,
        vec![plain_candidate(other, into_other)],
        Completeness::Complete,
    );
    graph.stored(
        other,
        &[result(into_target), PartialFlowPort::NormalReturn],
        &[(0, 1)],
    );
    graph.route(
        other,
        into_target,
        vec![plain_candidate(target, into_target)],
        Completeness::Complete,
    );
    graph.interior(
        other,
        seed_of_source(&plan, other),
        FakeTarget::Port(PartialFlowPort::NormalReturn),
    );
    let ComposeOutcome {
        report,
        incompleteness,
        ..
    } = compose(&plan, &graph, BUDGET);
    assert!(incompleteness.is_empty(), "{incompleteness:#?}");
    assert_single_alpha_finding(&plan, &report);
    assert!(report.is_complete());
}

/// `caller` passes its source through `helper(before)` to its sink, and a
/// sanitizer at that call removes `removed`. With `direct`, the source also
/// reaches the sink without the call.
fn sanitized_through_helper(
    removed: &[&str],
    direct: bool,
) -> (TaintAnalysisPlan, TaintFindingReport) {
    let fixture = fixture();
    let plan = fixture.plan(&["caller"], &["caller"], Some(removed));
    let caller = &fixture.procedures["caller"];
    let helper = &fixture.procedures["helper"];
    let call = fixture.helper_call().id;
    let mut graph = FakeGraph::new(&fixture);
    graph.stored(caller, &[argument(call, 0), result(call)], &[]);
    graph.interior(
        caller,
        seed_of_source(&plan, caller),
        FakeTarget::Port(argument(call, 0)),
    );
    graph.interior(
        caller,
        InteriorSeed::Port(result(call)),
        sink_in(&plan, caller),
    );
    if direct {
        graph.interior(
            caller,
            seed_of_source(&plan, caller),
            sink_in(&plan, caller),
        );
    }
    graph.route(
        caller,
        call,
        vec![plain_candidate(helper, call)],
        Completeness::Complete,
    );
    graph.stored(
        helper,
        &[parameter(0), PartialFlowPort::NormalReturn],
        &[(0, 1)],
    );
    let ComposeOutcome {
        report,
        incompleteness,
        ..
    } = compose(&plan, &graph, BUDGET);
    assert!(incompleteness.is_empty(), "{incompleteness:#?}");
    (plan, report)
}

#[test]
fn a_sanitizer_that_removes_the_only_label_leaves_no_finding() {
    let (_, report) = sanitized_through_helper(&["alpha"], false);
    assert!(report.findings().is_empty(), "{report:#?}");
}

#[test]
fn a_sanitizer_that_removes_another_label_keeps_the_finding() {
    let (plan, report) = sanitized_through_helper(&["beta"], false);
    assert_single_alpha_finding(&plan, &report);
}

/// Both paths reach the sink in one procedure; the sanitized one must not
/// hide the other, so the search keeps one path per label function.
#[test]
fn a_sanitized_path_does_not_hide_an_unsanitized_one() {
    let (plan, report) = sanitized_through_helper(&["alpha"], true);
    assert_single_alpha_finding(&plan, &report);
}

#[test]
#[hardwon("eeaf43935461: concluded authored-model runs dropped their partial finding causes")]
fn a_model_replaces_the_callee_with_a_receiver_to_result_transfer() {
    let fixture = fixture();
    let plan = fixture.plan(&["target"], &["target"], None);
    let target = &fixture.procedures["target"];
    let modeled = &fixture.procedures["other"];
    let call = CallSiteId::new(46);
    let receiver = PartialFlowPort::CallReceiver { call };
    let mut graph = FakeGraph::new(&fixture);
    graph.stored(target, &[receiver.clone(), result(call)], &[]);
    graph.interior(
        target,
        seed_of_source(&plan, target),
        FakeTarget::Port(receiver.clone()),
    );
    graph.interior(
        target,
        InteriorSeed::Port(result(call)),
        sink_in(&plan, target),
    );
    graph.route(
        target,
        call,
        vec![DispatchCandidate {
            procedure: modeled.durable_key(),
            written_heap_ports: None,
            arguments: vec![(receiver.clone(), PartialFlowPort::Receiver)].into_boxed_slice(),
            writeback: Box::default(),
            returns: vec![(PartialFlowPort::NormalReturn, result(call))].into_boxed_slice(),
        }],
        Completeness::Complete,
    );
    // The modeled body has no flows; only the model links the ports.
    graph.models.insert(
        (target.durable_key(), call),
        CallModel {
            summary: None,
            summary_target: None,
            transfers: vec![ModelTransfer {
                actual: receiver.clone(),
                output: result(call),
                function: TaintEdgeFunction::identity(plan.universe()),
                proven: true,
                unresolved_output_storage: false,
            }],
            writeback: Box::default(),
            receiver_reads: Box::default(),
            proven: true,
            completeness: Completeness::Complete,
            retains_dispatch: false,
            authored: None,
        },
    );
    let ComposeOutcome {
        report,
        incompleteness,
        ..
    } = compose(&plan, &graph, BUDGET);
    assert!(incompleteness.is_empty(), "{incompleteness:#?}");
    assert_single_alpha_finding(&plan, &report);
    assert!(report.is_complete());
    // An unreviewed authored claim concludes the run but leaves its finding
    // partial. Keep the external call cause independently of run completion.
    graph
        .models
        .get_mut(&(target.durable_key(), call))
        .unwrap()
        .authored = Some(Box::default());
    let outcome = compose(&plan, &graph, BUDGET);
    assert!(outcome.incompleteness.is_empty());
    assert!(outcome.report.is_proven_by_authored_summaries());
    assert!(!outcome.report.findings()[0].is_complete());
    let [Incompleteness::Model { call: retained, .. }] = outcome.finding_incompleteness.as_slice()
    else {
        panic!(
            "one external finding cause: {:?}",
            outcome.finding_incompleteness
        );
    };
    assert_eq!(retained, &(target.durable_key(), call));
    for cause in [
        IncompleteCause::Content,
        IncompleteCause::Operational(OperationalCause::Budget(BudgetLane::Semantic)),
    ] {
        let model = graph.models.get_mut(&(target.durable_key(), call)).unwrap();
        model.authored = None;
        model.completeness = match cause {
            IncompleteCause::Content => Completeness::content("model open"),
            IncompleteCause::Operational(operational) => {
                Completeness::operational(operational, "model open")
            }
        };
        let outcome = compose(&plan, &graph, BUDGET);
        assert!(
            outcome.incompleteness.iter().any(|reason| matches!(
                reason,
                Incompleteness::Model { cause: actual, .. } if *actual == cause
            )),
            "{:#?}",
            outcome.incompleteness
        );
    }
}

/// Two findings in one batch. The sink in `target` is reached through a call
/// with a complete dispatch and the sink in `other` through a call whose
/// dispatch is open, so each finding's completeness follows its own path while
/// the run as a whole stays incomplete.
#[test]
#[hardwon(
    "19e12caa354f: a finding with a complete path was partial because the whole run was incomplete"
)]
fn each_finding_is_complete_only_when_its_own_path_is() {
    let fixture = fixture();
    let plan = fixture.plan(&["origin"], &["target", "other"], None);
    let origin = &fixture.procedures["origin"];
    let target = &fixture.procedures["target"];
    let other = &fixture.procedures["other"];
    let complete_call = CallSiteId::new(40);
    let open_call = CallSiteId::new(41);
    let mut graph = FakeGraph::new(&fixture);
    graph.stored(target, &[result(complete_call)], &[]);
    graph.interior(
        target,
        InteriorSeed::Port(result(complete_call)),
        sink_in(&plan, target),
    );
    graph.route(
        target,
        complete_call,
        vec![plain_candidate(origin, complete_call)],
        Completeness::Complete,
    );
    graph.stored(other, &[result(open_call)], &[]);
    graph.interior(
        other,
        InteriorSeed::Port(result(open_call)),
        sink_in(&plan, other),
    );
    graph.route(
        other,
        open_call,
        vec![plain_candidate(origin, open_call)],
        Completeness::content("open dispatch"),
    );
    graph.interior(
        origin,
        seed_of_source(&plan, origin),
        FakeTarget::Port(PartialFlowPort::NormalReturn),
    );
    let ComposeOutcome {
        report,
        incompleteness,
        ..
    } = compose(&plan, &graph, BUDGET);
    assert_eq!(incompleteness.len(), 1, "{incompleteness:#?}");
    assert_eq!(report.findings().len(), 2, "{report:#?}");
    let finding_at = |sink: &str| {
        let sink = plan
            .value_flow()
            .sinks()
            .find(|(_, spec)| {
                spec.point().procedure().durable_key() == fixture.procedures[sink].durable_key()
            })
            .map(|(id, _)| id)
            .expect("the plan holds the sink");
        report
            .findings()
            .iter()
            .find(|finding| finding.sink() == sink)
            .expect("the sink has a finding")
    };
    let through_complete = finding_at("target");
    assert!(through_complete.is_complete(), "{through_complete:#?}");
    assert!(through_complete.is_proven(), "{through_complete:#?}");
    let through_open = finding_at("other");
    assert!(!through_open.is_complete(), "{through_open:#?}");
    assert!(!through_open.is_proven(), "{through_open:#?}");
    assert!(!report.is_complete());
}

#[test]
fn an_uncertain_dispatch_marks_the_finding_incomplete() {
    let fixture = fixture();
    let plan = fixture.plan(&["origin"], &["target"], None);
    let graph = callee_return_graph(&fixture, &plan, Completeness::content("open dispatch"));
    let ComposeOutcome {
        report,
        incompleteness,
        ..
    } = compose(&plan, &graph, BUDGET);
    assert!(
        matches!(
            incompleteness.as_slice(),
            [Incompleteness::Dispatch { reason, cause, ..}]
                if reason.as_ref() == "open dispatch" && *cause == IncompleteCause::Content
        ),
        "{incompleteness:#?}"
    );
    assert_single_alpha_finding(&plan, &report);
    let finding = &report.findings()[0];
    assert!(!finding.is_complete() && !finding.is_proven());
    assert!(!report.is_complete());
}

#[test]
fn endpoint_inventory_retains_content_and_operational_causes() {
    let fixture = fixture();
    let plan = fixture.plan(&["target"], &["target"], None);
    let target = &fixture.procedures["target"];
    for cause in [
        IncompleteCause::Content,
        IncompleteCause::Operational(OperationalCause::Budget(BudgetLane::Semantic)),
    ] {
        let mut graph = FakeGraph::new(&fixture);
        graph.interior(
            target,
            seed_of_source(&plan, target),
            sink_in(&plan, target),
        );
        let mut endpoints = ProcedureEndpoints::none();
        endpoints.completeness = match cause {
            IncompleteCause::Content => Completeness::content("endpoint inventory open"),
            IncompleteCause::Operational(operational) => {
                Completeness::operational(operational, "endpoint inventory open")
            }
        };
        graph.endpoints.insert(target.durable_key(), endpoints);
        let outcome = compose(&plan, &graph, BUDGET);
        assert!(
            outcome.incompleteness.iter().any(|reason| matches!(
                reason,
                Incompleteness::Endpoints { cause: actual, .. } if *actual == cause
            )),
            "{:#?}",
            outcome.incompleteness
        );
    }
}

#[test]
fn caller_inventory_retains_content_and_operational_causes() {
    let fixture = fixture();
    let plan = fixture.plan(&["origin"], &["target"], None);
    let target = &fixture.procedures["target"];
    let origin = &fixture.procedures["origin"];
    let call = CallSiteId::new(41);
    for cause in [
        IncompleteCause::Content,
        IncompleteCause::Operational(OperationalCause::Budget(BudgetLane::CallersPerProcedure)),
    ] {
        let mut graph = FakeGraph::new(&fixture);
        graph.stored(target, &[parameter(0)], &[]);
        graph.interior(
            target,
            InteriorSeed::Port(parameter(0)),
            sink_in(&plan, target),
        );
        graph.callers.insert(
            target.durable_key(),
            Callers {
                calls: vec![(origin.durable_key(), call)],
                completeness: match cause {
                    IncompleteCause::Content => Completeness::content("caller inventory open"),
                    IncompleteCause::Operational(operational) => {
                        Completeness::operational(operational, "caller inventory open")
                    }
                },
            },
        );
        graph.route(
            origin,
            call,
            vec![plain_candidate(target, call)],
            Completeness::Complete,
        );
        graph.interior(
            origin,
            seed_of_source(&plan, origin),
            FakeTarget::Port(argument(call, 0)),
        );
        let outcome = compose(&plan, &graph, BUDGET);
        assert!(
            outcome.incompleteness.iter().any(|reason| matches!(
                reason,
                Incompleteness::Callers { cause: actual, .. } if *actual == cause
            )),
            "{:#?}",
            outcome.incompleteness
        );
    }
}

#[test]
fn interior_run_retains_content_and_operational_causes() {
    let fixture = fixture();
    let plan = fixture.plan(&["target"], &["target"], None);
    let target = &fixture.procedures["target"];
    for cause in [
        IncompleteCause::Content,
        IncompleteCause::Operational(OperationalCause::Budget(BudgetLane::Semantic)),
    ] {
        let mut graph = FakeGraph::new(&fixture);
        graph.interior(
            target,
            seed_of_source(&plan, target),
            sink_in(&plan, target),
        );
        graph.interior_completeness.insert(
            target.durable_key(),
            match cause {
                IncompleteCause::Content => Completeness::content("interior open"),
                IncompleteCause::Operational(operational) => {
                    Completeness::operational(operational, "interior open")
                }
            },
        );
        let outcome = compose(&plan, &graph, BUDGET);
        assert!(
            outcome.incompleteness.iter().any(|reason| matches!(
                reason,
                Incompleteness::Interior { cause: actual, .. } if *actual == cause
            )),
            "{:#?}",
            outcome.incompleteness
        );
    }
}

#[test]
fn openness_retains_each_residual_cause() {
    let fixture = fixture();
    let plan = fixture.plan(&["target"], &["target"], None);
    let target = &fixture.procedures["target"];
    let residual = (target.durable_key(), CallSiteId::new(40));
    for cause in [
        IncompleteCause::Content,
        IncompleteCause::Operational(OperationalCause::Budget(BudgetLane::Semantic)),
    ] {
        let mut graph = FakeGraph::new(&fixture);
        graph.interior(
            target,
            seed_of_source(&plan, target),
            sink_in(&plan, target),
        );
        graph.openness.insert(
            target.durable_key(),
            Openness::Open {
                residual: vec![residual.clone()].into_boxed_slice(),
                residual_causes: vec![cause].into_boxed_slice(),
                cause,
                blocked: None,
                status: SemanticInputStatus::Complete,
                reason: "residual call open".into(),
            },
        );
        let outcome = compose(&plan, &graph, BUDGET);
        assert!(
            outcome.incompleteness.iter().any(|reason| matches!(
                reason,
                Incompleteness::Open { cause: actual, residual_causes, .. }
                    if *actual == cause && residual_causes.as_ref() == [cause]
            )),
            "{:#?}",
            outcome.incompleteness
        );
    }
}

#[test]
fn budget_limited_dispatch_retains_operational_cause() {
    let fixture = fixture();
    let plan = fixture.plan(&["origin"], &["target"], None);
    let graph = callee_return_graph(
        &fixture,
        &plan,
        Completeness::operational(
            OperationalCause::Budget(BudgetLane::Semantic),
            "open dispatch",
        ),
    );
    let outcome = compose(&plan, &graph, BUDGET);
    assert_eq!(outcome.effective_budget, BUDGET);
    assert!(
        matches!(
            outcome.incompleteness.as_slice(),
            [Incompleteness::Dispatch {
                cause: IncompleteCause::Operational(OperationalCause::Budget(BudgetLane::Semantic)),
                ..
            }]
        ),
        "{:#?}",
        outcome.incompleteness
    );
}

#[test]
fn a_certified_object_requires_the_same_s1_target_and_does_not_suppress_other_cached_uses() {
    use crate::analyzer::semantic::{
        CandidateCoverage, SemanticLanguage, UnmaterializedExternalTarget,
    };
    let fixture = fixture();
    let plan = fixture.plan(&["origin"], &["target"], None);
    let caller = fixture.procedures["caller"].clone();
    let call = fixture.helper_call().id;
    let call_key = (caller.durable_key(), call);
    let value = caller
        .value_handle(caller.semantics().values()[0].id)
        .expect("fixture value");
    let object = AbstractObject::new(
        AbstractObjectIdentity::Value(value),
        ObjectCardinality::Unknown,
    )
    .expect("object root");
    let root = |site| ObjectAnchor {
        procedure: caller.durable_key(),
        site,
        role: ObjectAnchorRole::CurrentObject,
        object: object.clone(),
    };
    for (sites, selected_owner, expected_dispatch) in [
        (vec![ObjectAnchorSite::NormalExit], "toy.External", false),
        (vec![ObjectAnchorSite::NormalExit], "toy.Other", true),
        (
            vec![
                ObjectAnchorSite::NormalExit,
                ObjectAnchorSite::ExceptionalExit,
            ],
            "toy.External",
            true,
        ),
        (
            vec![
                ObjectAnchorSite::ExceptionalExit,
                ObjectAnchorSite::NormalExit,
            ],
            "toy.External",
            true,
        ),
    ] {
        let mut graph = FakeGraph::new(&fixture);
        graph.dispatches.insert(
            call_key.clone(),
            Dispatch {
                candidates: Vec::new(),
                completeness: Completeness::content("external body unavailable"),
                continuation: HopQuality::UNCERTAIN,
                external_body_unavailable: Some(ExternalBodyUnavailableGap {
                    target: UnmaterializedExternalTarget::new_modeled(
                        "toy.External",
                        "open",
                        SemanticLanguage::Standard(Language::Rust),
                        0,
                        false,
                    )
                    .expect("typed external target"),
                    raw_coverage: CandidateCoverage::Exhaustive,
                }),
            },
        );
        let normal_port = result(call);
        graph.object_predecessors = vec![
            (
                ObjectAnchorSite::NormalExit,
                normal_port.clone(),
                TaintEdgeFunction::identity(plan.universe()),
            ),
            (
                ObjectAnchorSite::ExceptionalExit,
                PartialFlowPort::CallThrown { call },
                TaintEdgeFunction::identity(plan.universe()),
            ),
        ];
        graph.certified_object_port = Some(normal_port);
        // This stands for the selected S1 Fresh origin. The second case
        // deliberately disagrees with the one typed dispatch boundary.
        graph.selected_origin_target = Some(
            UnmaterializedExternalTarget::new_modeled(
                selected_owner,
                "open",
                SemanticLanguage::Standard(Language::Rust),
                0,
                false,
            )
            .expect("selected origin target"),
        );
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let outcome = search_object_roots(
            sites.iter().cloned().map(root).collect(),
            super::labels::TaintLabels::new(plan.universe()),
            &graph,
            BUDGET,
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .expect("object search");
        let has_dispatch_reason = outcome.incomplete.iter().any(|reason| {
            matches!(reason, Incompleteness::Dispatch { call, reason, ..}
                if call == &call_key && reason.as_ref() == "external body unavailable")
        });
        assert_eq!(
            has_dispatch_reason, expected_dispatch,
            "{sites:?}, {selected_owner}: {:?}",
            outcome.incomplete
        );
        assert_eq!(
            graph
                .proof_reads
                .borrow()
                .iter()
                .filter(|read| *read == &call_key)
                .count(),
            1,
            "both items must consume one cached dispatch"
        );
        if selected_owner == "toy.Other" {
            assert!(
                outcome.incomplete.iter().any(|reason| matches!(
                    reason,
                    Incompleteness::Object {
                        cause: IncompleteCause::Content,
                        ..
                    }
                )),
                "a mismatched selected origin must retain Object uncertainty: {:?}",
                outcome.incomplete
            );
            graph.dispatches.get_mut(&call_key).unwrap().completeness = Completeness::operational(
                OperationalCause::Budget(BudgetLane::Semantic),
                "external body unavailable",
            );
            let cancellation = CancellationToken::default();
            let mut budget = SemanticBudget::default();
            let stopped = search_object_roots(
                sites.iter().cloned().map(root).collect(),
                super::labels::TaintLabels::new(plan.universe()),
                &graph,
                BUDGET,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("object search with budgeted dispatch");
            assert!(
                stopped.incomplete.iter().any(|reason| matches!(
                    reason,
                    Incompleteness::Object {
                        cause: IncompleteCause::Operational(OperationalCause::Budget(
                            BudgetLane::Semantic
                        )),
                        ..
                    }
                )),
                "{:?}",
                stopped.incomplete
            );
        }
    }
}

#[test]
#[hardwon("#9196: lexical capture without an admitted invocation was reported complete")]
fn a_closure_capture_without_invocation_is_uncertain() {
    let fixture = fixture();
    let plan = fixture.plan(&["origin"], &["target"], None);
    // `target` plays the closure and `origin` its lexical parent.
    let closure = &fixture.procedures["target"];
    let parent = &fixture.procedures["origin"];
    let slot = MemoryLocationId::new(3);
    let capture = PartialFlowPort::Capture { slot };
    let binding = PartialFlowPort::CaptureOut {
        target: closure.durable_key().1,
        destination: slot,
    };
    let mut graph = FakeGraph::new(&fixture);
    graph.stored(closure, std::slice::from_ref(&capture), &[]);
    graph.interior(
        closure,
        InteriorSeed::Port(capture),
        sink_in(&plan, closure),
    );
    graph
        .parents
        .insert(closure.durable_key(), parent.durable_key());
    graph.stored(parent, std::slice::from_ref(&binding), &[]);
    graph.interior(
        parent,
        seed_of_source(&plan, parent),
        FakeTarget::Port(binding),
    );
    let ComposeOutcome {
        report,
        incompleteness,
        ..
    } = compose(&plan, &graph, BUDGET);
    assert!(
        incompleteness
            .iter()
            .any(|gap| matches!(gap, Incompleteness::Execution { .. })),
        "{incompleteness:#?}"
    );
    assert_single_alpha_finding(&plan, &report);
    assert!(!report.findings()[0].is_complete());
    assert!(!report.is_complete());
}

#[test]
fn an_exhausted_hop_budget_reports_an_incomplete_batch() {
    let fixture = fixture();
    let plan = fixture.plan(&["origin"], &["target"], None);
    let graph = callee_return_graph(&fixture, &plan, Completeness::Complete);
    // The sink's root, the call result and the callee root fit; the source
    // reaching the callee root does not.
    let ComposeOutcome {
        report,
        incompleteness,
        ..
    } = compose(
        &plan,
        &graph,
        CompositionBudget {
            max_hops: 3,
            ..BUDGET
        },
    );
    assert!(report.findings().is_empty(), "{report:#?}");
    assert!(!report.is_complete());
    assert_eq!(incompleteness, [Incompleteness::Budget(BudgetLane::Hops)]);
    assert!(matches!(
        report.result().termination(),
        SolverTermination::ExceededBudget(_)
    ));
}

#[test]
#[hardwon("#8386: a stopped ownership proof could be reported as Failed or Complete")]
fn a_refused_semantic_proof_stops_composition_without_poisoning_the_next_query() {
    let fixture = fixture();
    let plan = fixture.plan(&["origin"], &["target"], None);
    let graph = callee_return_graph(&fixture, &plan, Completeness::Complete);
    let cancellation = CancellationToken::default();
    let mut semantic_budget = SemanticBudget::default();
    let mut over_limit = semantic_budget.limits();
    over_limit.events = over_limit.events.saturating_add(1);
    assert!(semantic_budget.check_admission(over_limit).is_err());
    let stopped = compose_taint_batch(
        &plan,
        &graph,
        BUDGET,
        &mut SemanticRequest::new(&mut semantic_budget, &cancellation),
    )
    .expect("budget refusal is a normal incomplete result");
    assert!(!stopped.report.is_complete());
    assert!(
        stopped
            .incompleteness
            .contains(&Incompleteness::Budget(BudgetLane::Semantic))
    );
    let fresh = compose(&plan, &graph, BUDGET);
    assert!(
        fresh.incompleteness.is_empty(),
        "{:#?}",
        fresh.incompleteness
    );
    assert!(fresh.report.is_complete());
}

/// `show` logs a field of its parameter; `pair` lends a cell whose field
/// holds the source. The demand at the heap input port climbs to the
/// caller-side location rooted at the actual.
#[test]
fn a_callee_reading_a_tainted_field_of_its_parameter_is_a_finding() {
    let fixture = fixture();
    let plan = fixture.plan(&["pair"], &["show"], None);
    let show = &fixture.procedures["show"];
    let pair = &fixture.procedures["pair"];
    let (_, into_show) = fixture.pair_calls();
    let selectors: Box<[HeapSelector]> = vec![HeapSelector::AnyIndex].into_boxed_slice();
    let field = PartialFlowPort::Heap {
        root: Box::new(parameter(0)),
        selectors: selectors.clone(),
        tail: AccessPathTail::Exact,
    };
    let mut graph = FakeGraph::new(&fixture);
    graph.stored(show, &[parameter(0), field.clone()], &[]);
    graph.interior(show, InteriorSeed::Port(field), sink_in(&plan, show));
    graph.callers.insert(
        show.durable_key(),
        Callers {
            calls: vec![(pair.durable_key(), into_show)],
            completeness: Completeness::Complete,
        },
    );
    graph.route(
        pair,
        into_show,
        vec![plain_candidate(show, into_show)],
        Completeness::Complete,
    );
    graph.interior(
        pair,
        seed_of_source(&plan, pair),
        FakeTarget::Observe(InteriorObservation::Location(CallerLocation {
            call: into_show,
            actual: argument(into_show, 0),
            selectors,
            tail: AccessPathTail::Exact,
        })),
    );
    let ComposeOutcome {
        report,
        incompleteness,
        ..
    } = compose(&plan, &graph, BUDGET);
    assert!(incompleteness.is_empty(), "{incompleteness:#?}");
    assert_single_alpha_finding(&plan, &report);
}

#[test]
#[hardwon("#9028: an unmodeled call silently dropped a post-call heap demand")]
fn empty_dispatch_keeps_a_post_call_heap_demand_incomplete() {
    let fixture = fixture();
    let plan = fixture.plan(&["pair"], &["pair"], None);
    let pair = &fixture.procedures["pair"];
    let (call, _) = fixture.pair_calls();
    let heap = PartialFlowPort::Heap {
        root: Box::new(argument(call, 0)),
        selectors: vec![HeapSelector::AnyIndex].into_boxed_slice(),
        tail: AccessPathTail::Exact,
    };
    let mut graph = FakeGraph::new(&fixture);
    graph.stored(pair, &[heap, parameter(0)], &[(0, 1)]);
    graph.interior(pair, InteriorSeed::Port(parameter(0)), sink_in(&plan, pair));
    graph.route(pair, call, Vec::new(), Completeness::Complete);
    let outcome = compose(&plan, &graph, BUDGET);
    assert!(
        outcome.report.findings().is_empty(),
        "{:#?}",
        outcome.report
    );
    assert!(!outcome.report.is_complete(), "{:#?}", outcome.report);
}

/// `target`'s source is the argument of call 47, whose result reaches the
/// sink. The call has no candidate and its dispatch is open, so only the
/// policy's unmodeled-call behavior can link its argument to its result.
fn unmodeled_call_outcome(behavior: UnmodeledCallBehavior) -> (TaintAnalysisPlan, ComposeOutcome) {
    let fixture = fixture();
    let plan = fixture.plan(&["target"], &["target"], None);
    let target = &fixture.procedures["target"];
    let call = CallSiteId::new(47);
    let thrown = PartialFlowPort::CallThrown { call };
    let mut graph = FakeGraph::new(&fixture);
    graph.stored(
        target,
        &[argument(call, 0), result(call), thrown.clone()],
        &[],
    );
    graph.interior(
        target,
        seed_of_source(&plan, target),
        FakeTarget::Port(argument(call, 0)),
    );
    graph.interior(
        target,
        InteriorSeed::Port(result(call)),
        sink_in(&plan, target),
    );
    graph.route(
        target,
        call,
        Vec::new(),
        Completeness::content("open dispatch"),
    );
    graph.fallbacks.insert(
        (target.durable_key(), call),
        FallbackPorts {
            inputs: vec![argument(call, 0)].into_boxed_slice(),
            outputs: vec![result(call), thrown].into_boxed_slice(),
        },
    );
    graph.behavior = behavior;
    let outcome = compose(&plan, &graph, BUDGET);
    assert!(
        matches!(
            outcome.incompleteness.as_slice(),
            [Incompleteness::Dispatch { reason, ..}] if reason.as_ref() == "open dispatch"
        ),
        "the open dispatch is the only reason under {behavior}: {:#?}",
        outcome.incompleteness
    );
    (plan, outcome)
}

#[test]
fn a_paranoid_policy_carries_an_argument_through_an_unmodeled_call() {
    let (plan, outcome) = unmodeled_call_outcome(UnmodeledCallBehavior::Paranoid);
    assert_single_alpha_finding(&plan, &outcome.report);
    let finding = &outcome.report.findings()[0];
    assert!(!finding.is_proven() && !finding.is_complete());
    assert!(outcome.abstained.is_empty(), "{:#?}", outcome.abstained);
}

#[test]
fn an_optimistic_policy_adds_no_flow_through_an_unmodeled_call() {
    let (_, outcome) = unmodeled_call_outcome(UnmodeledCallBehavior::Optimistic);
    assert!(
        outcome.report.findings().is_empty(),
        "{:#?}",
        outcome.report
    );
    assert!(outcome.abstained.is_empty(), "{:#?}", outcome.abstained);
}

#[test]
fn a_require_model_policy_abstains_at_an_unmodeled_call() {
    let (_, outcome) = unmodeled_call_outcome(UnmodeledCallBehavior::RequireModel);
    assert!(
        outcome.report.findings().is_empty(),
        "{:#?}",
        outcome.report
    );
    assert_eq!(outcome.abstained.len(), 1, "{:#?}", outcome.abstained);
    assert_eq!(outcome.abstained[0].1, CallSiteId::new(47));
}

/// The source the fixture's plan would bind in `name`, as a provider matches
/// it on the frontier instead.
fn frontier_source(fixture: &Fixture, plan: &TaintAnalysisPlan, name: &str) -> BoundSource {
    let relation = &fixture.first_relation[name];
    BoundSource {
        point: relation.point().clone(),
        phase: ValueFlowObservationPhase::BeforeEffects,
        carrier: ValueFlowCarrier::from(&relation.source),
        classes: classes(plan, &["alpha"]),
        origin: SourceEventKey::new(
            ValueFlowEventKey::at_point(relation.point(), 0, ValueFlowEventKind::Source)
                .expect("source key"),
        ),
        evidence: EndpointEvidence::Known(HopQuality::CERTAIN),
    }
}

/// The plan binds no source. `origin`'s source is known only to the
/// provider, which answers it when the search first enters `origin` from the
/// sink's call result, and the finding names it.
#[test]
fn a_source_matched_on_the_frontier_reaches_the_sink() {
    let fixture = fixture();
    let plan = fixture.plan(&[], &["target"], None);
    assert!(plan.sources().is_empty());
    let target = &fixture.procedures["target"];
    let origin = &fixture.procedures["origin"];
    let source = frontier_source(&fixture, &plan, "origin");
    let call = CallSiteId::new(40);
    let mut graph = FakeGraph::new(&fixture);
    graph.stored(target, &[result(call)], &[]);
    graph.interior(
        target,
        InteriorSeed::Port(result(call)),
        sink_in(&plan, target),
    );
    graph.route(
        target,
        call,
        vec![plain_candidate(origin, call)],
        Completeness::Complete,
    );
    graph.interior(
        origin,
        InteriorSeed::Source {
            point: source.point.id(),
            phase: source.phase,
            carrier: source.carrier.clone(),
        },
        FakeTarget::Port(PartialFlowPort::NormalReturn),
    );
    let mut endpoints = ProcedureEndpoints::none();
    endpoints.sources.push(source.clone());
    graph.endpoints.insert(origin.durable_key(), endpoints);
    let ComposeOutcome {
        report,
        incompleteness,
        ..
    } = compose(&plan, &graph, BUDGET);
    assert!(incompleteness.is_empty(), "{incompleteness:#?}");
    assert_single_alpha_finding(&plan, &report);
    let finding = &report.findings()[0];
    assert_eq!(finding.origins().origins(), [source.origin]);
    assert!(finding.is_complete() && report.is_complete());
    assert_eq!(
        *graph.entered.borrow(),
        [target.durable_key(), origin.durable_key()],
        "the search asks for each procedure's endpoints once, when it enters it"
    );
}

/// A frontier source matched without its points-to question carries unknown
/// evidence. The report stage judges it once, for a source on a reported path,
/// and conjoins the judgment into the finding and the run's completion; a
/// source the search reached that reports nothing stays unjudged.
#[test]
#[hardwon(
    "03417980a58f: a frontier matched-value source was reported with evidence the ICFG engine judges incomplete"
)]
fn a_frontier_source_with_unknown_evidence_is_judged_when_it_reaches_a_sink() {
    let fixture = fixture();
    let plan = fixture.plan(&[], &["target"], None);
    let target = &fixture.procedures["target"];
    let origin = &fixture.procedures["origin"];
    let mut source = frontier_source(&fixture, &plan, "origin");
    source.evidence = EndpointEvidence::Unknown;
    let call = CallSiteId::new(40);
    let mut graph = FakeGraph::new(&fixture);
    graph.judgment = Some(HopQuality::new(true, false));
    graph.stored(target, &[result(call)], &[]);
    graph.interior(
        target,
        InteriorSeed::Port(result(call)),
        sink_in(&plan, target),
    );
    graph.route(
        target,
        call,
        vec![plain_candidate(origin, call)],
        Completeness::Complete,
    );
    graph.interior(
        origin,
        InteriorSeed::Source {
            point: source.point.id(),
            phase: source.phase,
            carrier: source.carrier.clone(),
        },
        FakeTarget::Port(PartialFlowPort::NormalReturn),
    );
    let mut endpoints = ProcedureEndpoints::none();
    endpoints.sources.push(source.clone());
    graph.endpoints.insert(origin.durable_key(), endpoints);
    let ComposeOutcome {
        report,
        incompleteness,
        ..
    } = compose(&plan, &graph, BUDGET);
    assert_single_alpha_finding(&plan, &report);
    assert_eq!(*graph.judged.borrow(), [source.origin.clone()]);
    assert_eq!(
        incompleteness,
        [Incompleteness::SourceEvidence {
            point: source.point.clone(),
            cause: IncompleteCause::Operational(OperationalCause::Provider),
        }]
    );
    let finding = &report.findings()[0];
    assert!(finding.is_proven() && !finding.is_complete() && !report.is_complete());
}

#[test]
fn a_frontier_source_that_reaches_no_sink_is_not_judged() {
    let fixture = fixture();
    let plan = fixture.plan(&[], &["target"], None);
    let target = &fixture.procedures["target"];
    let origin = &fixture.procedures["origin"];
    let mut source = frontier_source(&fixture, &plan, "origin");
    source.evidence = EndpointEvidence::Unknown;
    let call = CallSiteId::new(40);
    let mut graph = FakeGraph::new(&fixture);
    graph.stored(target, &[result(call)], &[]);
    graph.interior(
        target,
        InteriorSeed::Port(result(call)),
        sink_in(&plan, target),
    );
    graph.route(
        target,
        call,
        vec![plain_candidate(origin, call)],
        Completeness::Complete,
    );
    // The source's value never leaves `origin`.
    let mut endpoints = ProcedureEndpoints::none();
    endpoints.sources.push(source);
    graph.endpoints.insert(origin.durable_key(), endpoints);
    let ComposeOutcome {
        report,
        incompleteness,
        ..
    } = compose(&plan, &graph, BUDGET);
    assert!(report.findings().is_empty(), "{report:#?}");
    assert!(incompleteness.is_empty(), "{incompleteness:#?}");
    assert!(graph.judged.borrow().is_empty());
}

#[test]
fn barriers_keep_a_truncated_baseline_incomplete_without_expanding_new_paths() {
    let fixture = fixture();
    // The same-procedure source is found before the longer callee path has
    // room to reach its source. Filtering the short branch must not buy a
    // second topology budget for that path.
    let plan = fixture.plan(&["origin", "target"], &["target"], None);
    let target = &fixture.procedures["target"];
    let mut graph = callee_return_graph(&fixture, &plan, Completeness::Complete);
    graph.barriers = true;
    graph.blocked.insert(target.durable_key());
    graph
        .blocked
        .insert(fixture.procedures["origin"].durable_key());
    graph.interior(
        target,
        seed_of_source(&plan, target),
        sink_in(&plan, target),
    );
    let mut exercised = false;
    for max_hops in 2..32 {
        graph.filtering.set(false);
        graph.entered.borrow_mut().clear();
        let outcome = compose(&plan, &graph, CompositionBudget { max_hops, ..BUDGET });
        if outcome.stats.chop_procedures > 0
            && outcome
                .incompleteness
                .contains(&Incompleteness::Budget(BudgetLane::Hops))
        {
            assert!(outcome.report.findings().is_empty());
            assert!(
                !outcome.report.is_complete(),
                "filtering every seen candidate cannot prove a truncated baseline clean"
            );
            assert_eq!(
                outcome.incompleteness,
                [Incompleteness::Budget(BudgetLane::Hops)]
            );
            let entered = graph.entered.borrow();
            let unique = entered.iter().collect::<std::collections::HashSet<_>>();
            assert_eq!(
                entered.len(),
                unique.len(),
                "replay never enters a procedure a second time"
            );
            exercised = true;
            break;
        }
    }
    assert!(
        exercised,
        "the fixture must produce a candidate before truncation"
    );
}

#[test]
fn barriers_refresh_a_surviving_edges_crossed_calls_and_drop_its_quality() {
    let fixture = fixture();
    let plan = fixture.plan(&["caller"], &["caller"], None);
    let target = &fixture.procedures["caller"];
    let mut graph = FakeGraph::new(&fixture);
    graph.barriers = true;
    graph.interior(
        target,
        seed_of_source(&plan, target),
        sink_in(&plan, target),
    );
    // The filtered procedure still has the same endpoint edge, but its
    // surviving support crosses D, hidden by [] in the baseline antichain.
    let crossed = target.semantics().call_sites()[0].id;
    graph
        .filtered_crossed
        .insert(target.durable_key(), vec![crossed].into_boxed_slice());
    graph.route(
        target,
        crossed,
        Vec::new(),
        Completeness::content("D is open"),
    );
    graph
        .dispatches
        .get_mut(&(target.durable_key(), crossed))
        .unwrap()
        .continuation = HopQuality::UNCERTAIN;
    let outcome = compose(&plan, &graph, BUDGET);
    assert_eq!(outcome.report.findings().len(), 1);
    assert!(!outcome.report.findings()[0].is_complete());
    assert_eq!(outcome.stats.extra_proof_lookups, 1);
    assert_eq!(outcome.stats.changed_edge_qualities, 1);
    assert_eq!(
        graph.proof_reads.borrow().as_slice(),
        &[(target.durable_key(), crossed)]
    );
    assert_eq!(graph.entered.borrow().as_slice(), &[target.durable_key()]);
}

#[test]
fn barriers_note_only_undecided_witnesses_without_a_strict_alternative() {
    let fixture = fixture();
    let plan = fixture.plan(&["target", "other"], &["target", "other"], None);
    let mut graph = FakeGraph::new(&fixture);
    graph.barriers = true;
    let target = &fixture.procedures["target"];
    graph.undecided.insert(target.durable_key());
    for name in ["target", "other"] {
        let procedure = &fixture.procedures[name];
        graph.interior(
            procedure,
            seed_of_source(&plan, procedure),
            sink_in(&plan, procedure),
        );
    }
    let outcome = compose(&plan, &graph, BUDGET);
    assert_eq!(outcome.report.findings().len(), 2);
    assert_eq!(
        outcome.barrier_notes.len(),
        1,
        "notes never leak to an independent finding"
    );
    assert!(!outcome.barrier_notes[0].checks.is_empty());
    assert!(
        outcome.barrier_notes[0].checks.iter().all(|check| check
            .observation
            .point()
            .procedure()
            .durable_key()
            == target.durable_key())
    );
    graph.strict_alternative.insert(target.durable_key());
    graph.filtering.set(false);
    let outcome = compose(&plan, &graph, BUDGET);
    assert_eq!(outcome.report.findings().len(), 2);
    assert!(
        outcome
            .barrier_pairs
            .iter()
            .all(|pair| pair.strict.is_some()),
        "projection receives strict alternatives for both concrete pairs"
    );
    assert!(!graph.strict_witnesses.borrow().is_empty());
}

#[test]
#[hardwon("#9947: a lenient barrier witness run's failure was dropped from the finding causes")]
fn a_failed_lenient_barrier_witness_run_reports_its_cause() {
    let fixture = fixture();
    let plan = fixture.plan(&["target", "other"], &["target", "other"], None);
    let mut graph = FakeGraph::new(&fixture);
    graph.barriers = true;
    // No undecided check, so no strict witness run: the lenient pass is the
    // only later pass over the main report's paths.
    for name in ["target", "other"] {
        let procedure = &fixture.procedures[name];
        graph.interior(
            procedure,
            seed_of_source(&plan, procedure),
            sink_in(&plan, procedure),
        );
    }
    // The main report makes two witness runs per finding here, and the
    // lenient pass runs after it; the assertion below checks the split.
    graph.witness_runs_before_failure = Some((
        4,
        Completeness::operational(OperationalCause::Provider, "lenient run failed"),
    ));
    let ComposeOutcome {
        report,
        finding_incompleteness,
        barrier_pairs,
        ..
    } = compose(&plan, &graph, BUDGET);
    assert_eq!(report.findings().len(), 2);
    assert!(
        report
            .findings()
            .iter()
            .all(|finding| !finding.origins().witness_unavailable()),
        "the main report's witnesses answered"
    );
    assert!(!barrier_pairs.is_empty(), "the lenient pass ran");
    assert!(
        finding_incompleteness.iter().any(|reason| matches!(
            reason,
            Incompleteness::Interior {
                cause: IncompleteCause::Operational(OperationalCause::Provider),
                ..
            }
        )),
        "{finding_incompleteness:#?}"
    );
}

#[test]
fn barriers_without_baseline_candidates_make_no_type_queries() {
    let fixture = fixture();
    let plan = fixture.plan(&["origin"], &["target"], None);
    let mut graph = FakeGraph::new(&fixture);
    graph.barriers = true;
    let outcome = compose(&plan, &graph, BUDGET);
    assert!(outcome.report.findings().is_empty());
    assert_eq!(outcome.stats.chop_procedures, 0);
    assert_eq!(graph.check_reads.get(), 0);
    assert!(!graph.filtering.get());
}

/// A closed timing family: SameInvocation is identity, repeated deferred
/// execution is deferred, and a different task absorbs either schedule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum ToyTiming {
    Same,
    Deferred,
    Task,
}

#[derive(Debug, Clone, Copy)]
struct ToyLabels;

impl ComposeLabels for ToyLabels {
    type Fact = bool;
    type Function = ToyTiming;

    fn identity(&self) -> ToyTiming {
        ToyTiming::Same
    }
    fn then(&self, first: &ToyTiming, second: &ToyTiming) -> ToyTiming {
        match (first, second) {
            (ToyTiming::Task, _) | (_, ToyTiming::Task) => ToyTiming::Task,
            (ToyTiming::Deferred, _) | (_, ToyTiming::Deferred) => ToyTiming::Deferred,
            _ => ToyTiming::Same,
        }
    }
    fn apply(&self, _function: &ToyTiming, fact: &bool) -> bool {
        *fact
    }
    fn intersects(&self, left: &bool, right: &bool) -> bool {
        *left && *right
    }
}

#[derive(Default)]
struct ToyGraph {
    inventories: HashMap<DurableProcedureKey, Invocations>,
    dispatches: HashMap<DurableCallSiteKey, ExecutionDispatch<ToyTiming>>,
    declarations: HashMap<ExecutionTarget, ExecutionEndpoints<bool>>,
    arm_declarations: HashMap<(DurableCallSiteKey, usize), ExecutionEndpoints<bool>>,
    allow_discharge: bool,
}

impl ToyGraph {
    fn invoke(&mut self, procedure: &DurableProcedureKey, call: CallSiteId) {
        self.inventories
            .entry(procedure.clone())
            .or_insert_with(|| Invocations {
                sites: Vec::new(),
                coverage: Completeness::Complete,
            })
            .sites
            .push(InvocationSite {
                call: (procedure.clone(), call),
                source_site: call,
                mode: crate::analyzer::semantic::CallInvocationMode::Ordinary,
            });
    }

    fn arm(
        target: ExecutionTarget,
        timing: crate::analyzer::semantic::ExecutionTiming,
        quality: HopQuality,
    ) -> ExecutionArm<ToyTiming> {
        let function = match timing {
            crate::analyzer::semantic::ExecutionTiming::SameInvocation => ToyTiming::Same,
            crate::analyzer::semantic::ExecutionTiming::AfterSuspension => ToyTiming::Deferred,
            crate::analyzer::semantic::ExecutionTiming::DifferentTask => ToyTiming::Task,
            _ => panic!("the toy covers three timings"),
        };
        ExecutionArm {
            target,
            function,
            quality,
            timing,
            instance: None,
            context: crate::analyzer::semantic::DurableCallContext::of(
                &crate::analyzer::semantic::OracleCallContext::empty(),
            )
            .expect("an empty oracle context has a durable identity"),
        }
    }

    fn set_dispatch(&mut self, call: DurableCallSiteKey, arms: Vec<ExecutionArm<ToyTiming>>) {
        self.dispatches.insert(
            call,
            ExecutionDispatch {
                arms,
                residuals: Vec::new(),
                coverage: crate::analyzer::semantic::CandidateCoverage::Exhaustive,
                outcome: ExecutionDispatchOutcome::Complete,
            },
        );
    }

    fn declare(&mut self, target: ExecutionTarget, status: ExecutionEndpointStatus) {
        self.declarations.insert(
            target,
            ExecutionEndpoints {
                sources: vec![ExecutionSource {
                    identity: "declared-effect".into(),
                    fact: true,
                    provenance: "toy".into(),
                    seed_point: None,
                }],
                status,
                covers_overrides: true,
            },
        );
    }
}

impl CompositionProvider for ToyGraph {
    type Error = String;
    type Fact = bool;
    type Function = ToyTiming;

    fn discharge_execution_residual(
        &self,
        _call: &DurableCallSiteKey,
        _dispatch: &ExecutionDispatch<ToyTiming>,
    ) -> bool {
        self.allow_discharge
    }

    fn invocations(
        &self,
        procedure: &DurableProcedureKey,
        _request: &mut SemanticRequest<'_>,
    ) -> Result<Invocations, String> {
        Ok(self
            .inventories
            .get(procedure)
            .cloned()
            .unwrap_or(Invocations {
                sites: Vec::new(),
                coverage: Completeness::Complete,
            }))
    }
    fn execution_dispatch(
        &self,
        call: &DurableCallSiteKey,
        _incoming: Option<&super::ExecutionArmContext>,
        _request: &mut SemanticRequest<'_>,
    ) -> Result<ExecutionDispatch<ToyTiming>, String> {
        Ok(self
            .dispatches
            .get(call)
            .expect("toy dispatch exists")
            .clone())
    }
    fn execution_endpoints(
        &self,
        target: &ExecutionTarget,
        incoming: Option<&ExecutionArmContext>,
        _request: &mut SemanticRequest<'_>,
    ) -> Result<ExecutionEndpoints<bool>, String> {
        Ok(incoming
            .and_then(|arm| self.arm_declarations.get(&(arm.call.clone(), arm.ordinal)))
            .or_else(|| self.declarations.get(target))
            .cloned()
            .unwrap_or(ExecutionEndpoints {
                sources: Vec::new(),
                status: if matches!(target, ExecutionTarget::External(_)) {
                    ExecutionEndpointStatus::Absent
                } else {
                    ExecutionEndpointStatus::Complete
                },
                covers_overrides: true,
            }))
    }
    fn partial_flows(
        &self,
        _: &DurableProcedureKey,
        _: &mut SemanticRequest<'_>,
    ) -> Result<Arc<ProcedurePartialFlows>, String> {
        unimplemented!("execution has no value flows")
    }
    fn interior_flows(
        &self,
        _: &DurableProcedureKey,
        _: &[InteriorSeed],
        _: &[InteriorObservation],
        _: bool,
        _: &mut SemanticRequest<'_>,
    ) -> Result<InteriorFlows, String> {
        unimplemented!("execution has no value flows")
    }
    fn dispatch(
        &self,
        _: &DurableCallSiteKey,
        _: &mut SemanticRequest<'_>,
    ) -> Result<(Dispatch, Option<CallModel<ToyTiming>>), String> {
        unimplemented!("execution has no value dispatch")
    }
    fn callers(
        &self,
        _: &DurableProcedureKey,
        _: &mut SemanticRequest<'_>,
    ) -> Result<Callers, String> {
        unimplemented!("execution has no reverse value search")
    }
    fn lexical_parent(
        &self,
        _: &DurableProcedureKey,
        _: &mut SemanticRequest<'_>,
    ) -> Result<Option<DurableProcedureKey>, String> {
        unimplemented!("execution has no capture binding")
    }
    fn unmodeled_call_behavior(&self) -> UnmodeledCallBehavior {
        unimplemented!("execution has no value fallback")
    }
    fn fallback_ports(
        &self,
        _: &DurableCallSiteKey,
        _: &mut SemanticRequest<'_>,
    ) -> Result<FallbackPorts, String> {
        unimplemented!("execution has no value ports")
    }
    fn authored_models(&self) -> Vec<Box<[AuthoredArmClosure]>> {
        unimplemented!("execution has no value models")
    }
    fn openness(
        &self,
        _: &DurableProcedureKey,
        _: &mut SemanticRequest<'_>,
    ) -> Result<Openness, String> {
        unimplemented!("execution has its own coverage")
    }
    fn endpoints(
        &self,
        _: &DurableProcedureKey,
        _: &mut SemanticRequest<'_>,
    ) -> Result<ProcedureEndpoints<bool, ToyTiming>, String> {
        unimplemented!("execution has no value endpoints")
    }
    fn source_evidence(
        &self,
        _: &BoundSource<bool>,
        _: &mut SemanticRequest<'_>,
    ) -> Result<HopQuality, String> {
        unimplemented!("execution has no value sources")
    }
}

fn toy_execution(root: DurableProcedureKey, graph: &ToyGraph) -> ExecutionOutcome<ToyLabels> {
    let cancellation = CancellationToken::default();
    let mut budget = SemanticBudget::default();
    search_execution(
        vec![root],
        ToyLabels,
        graph,
        BUDGET,
        &mut SemanticRequest::new(&mut budget, &cancellation),
    )
    .expect("toy execution search")
}

#[test]
#[hardwon("#9947: replayed Output diagnostic text embedded the workspace mount")]
fn execution_dispatch_reason_omits_durable_artifact_identity() {
    let fixture = fixture();
    let caller = fixture.procedures["caller"].durable_key();
    let call = fixture.helper_call().id;
    let mut graph = ToyGraph::default();
    graph.invoke(&caller, call);
    graph.set_dispatch((caller.clone(), call), Vec::new());
    let dispatch = graph.dispatches.get_mut(&(caller.clone(), call)).unwrap();
    dispatch.outcome = ExecutionDispatchOutcome::Cancelled("interrupted".into());
    let answer = toy_execution(caller, &graph);
    assert!(
        answer.incomplete.iter().any(|incomplete| matches!(
            incomplete,
            Incompleteness::Execution { reason, .. }
                if reason.contains("execution dispatch ")
                    && !reason.contains("SemanticArtifactKey")
                    && !reason.contains("WorkspaceMountId")
        )),
        "{:#?}",
        answer.incomplete
    );
}

#[test]
#[hardwon("#9196: repeated execution instance and context stayed silently closed")]
fn execution_relation_interns_cycles_and_keeps_timing_paths() {
    use crate::analyzer::semantic::ExecutionTiming;
    let fixture = fixture();
    let caller = fixture.procedures["caller"].durable_key();
    let call = fixture.helper_call().id;
    let target = ExecutionTarget::Procedure(Box::new(caller.clone()));
    let mut graph = ToyGraph::default();
    graph.declare(target.clone(), ExecutionEndpointStatus::Complete);
    graph.invoke(&caller, call);
    let mut arm = ToyGraph::arm(target, ExecutionTiming::SameInvocation, HopQuality::CERTAIN);
    let procedure = &fixture.procedures["caller"];
    arm.instance = Some(ExecutionCallableInstance {
        producer: caller.clone(),
        creation_point: procedure.semantics().points()[0].id,
        creation_event_index: 0,
        creation_value: procedure.semantics().values()[0].id,
        capture_bindings: Box::new([]),
        factory_call: None,
    });
    graph.set_dispatch((caller.clone(), call), vec![arm]);
    let answer = toy_execution(caller.clone(), &graph);
    assert!(
        matches!(answer.incomplete.as_slice(), [Incompleteness::Execution { reason, .. }]
            if reason.contains("repeated instance and context")),
        "{:?}",
        answer.incomplete
    );
    assert!(answer.reaches.iter().any(|reach| reach.root == caller));
    assert!(
        answer
            .reaches
            .iter()
            .any(|reach| matches!(reach.hops.as_slice(), [Hop::Invocation { .. }])),
        "the self invocation must be traversed"
    );
    assert!(
        answer.stats.hops < 12,
        "cycle must intern before the hop budget: {:?}",
        answer.stats
    );

    let pair = fixture.procedures["pair"].durable_key();
    let callee = fixture.procedures["target"].durable_key();
    let (first, second) = fixture.pair_calls();
    let mut graph = ToyGraph::default();
    graph.invoke(&pair, first);
    graph.invoke(&pair, second);
    graph.set_dispatch(
        (pair.clone(), first),
        vec![ToyGraph::arm(
            ExecutionTarget::Procedure(Box::new(callee.clone())),
            ExecutionTiming::AfterSuspension,
            HopQuality::CERTAIN,
        )],
    );
    graph.set_dispatch(
        (pair.clone(), second),
        vec![ToyGraph::arm(
            ExecutionTarget::Procedure(Box::new(callee.clone())),
            ExecutionTiming::DifferentTask,
            HopQuality::CERTAIN,
        )],
    );
    graph.declare(
        ExecutionTarget::Procedure(Box::new(callee)),
        ExecutionEndpointStatus::Complete,
    );
    let answer = toy_execution(pair, &graph);
    assert_eq!(answer.reaches.len(), 2);
    let mut timings = answer
        .reaches
        .iter()
        .map(|reach| *answer.functions.function(reach.function))
        .collect::<Vec<_>>();
    timings.sort_by_key(|timing| match timing {
        ToyTiming::Same => 0,
        ToyTiming::Deferred => 1,
        ToyTiming::Task => 2,
    });
    assert_eq!(timings, vec![ToyTiming::Deferred, ToyTiming::Task]);
    assert!(
        answer
            .reaches
            .iter()
            .all(|reach| matches!(reach.hops.as_slice(), [Hop::Invocation { .. }]))
    );
}

#[test]
fn execution_relation_external_closure_and_interruption_are_per_arm() {
    use crate::analyzer::semantic::{
        CandidateCoverage, ExecutionTiming, SemanticLanguage, UnmaterializedExternalTarget,
    };
    let fixture = fixture();
    let caller = fixture.procedures["caller"].durable_key();
    let call = fixture.helper_call().id;
    let external_target = UnmaterializedExternalTarget::new_modeled(
        "toy.External",
        "run",
        SemanticLanguage::Standard(Language::Rust),
        0,
        false,
    )
    .expect("typed external");
    let external = ExecutionTarget::External(Box::new(ExternalTargetIdentity::Unmaterialized {
        boundary: crate::analyzer::semantic::DispatchBoundaryKind::Unmaterialized(
            external_target.locator.clone(),
        ),
        target: Box::new(external_target),
    }));
    let mut graph = ToyGraph::default();
    graph.invoke(&caller, call);
    graph.set_dispatch(
        (caller.clone(), call),
        vec![ToyGraph::arm(
            external.clone(),
            ExecutionTiming::SameInvocation,
            HopQuality::CERTAIN,
        )],
    );
    graph.declarations.insert(
        external.clone(),
        ExecutionEndpoints {
            sources: Vec::new(),
            status: ExecutionEndpointStatus::Complete,
            covers_overrides: true,
        },
    );
    let answer = toy_execution(caller.clone(), &graph);
    assert!(
        answer.reaches.is_empty() && answer.incomplete.is_empty(),
        "closed empty external: {answer:?}"
    );
    graph.declare(
        external.clone(),
        ExecutionEndpointStatus::Partial("missing summary".into()),
    );
    let answer = toy_execution(caller.clone(), &graph);
    assert_eq!(answer.reaches.len(), 1);
    assert!(!answer.incomplete.is_empty());

    graph.declarations.remove(&external);
    let answer = toy_execution(caller.clone(), &graph);
    assert!(answer.reaches.is_empty());
    assert!(!answer.incomplete.is_empty(), "absent external is open");

    graph.set_dispatch(
        (caller.clone(), call),
        vec![ToyGraph::arm(
            external.clone(),
            ExecutionTiming::SameInvocation,
            HopQuality::new(true, false),
        )],
    );
    graph.declare(external.clone(), ExecutionEndpointStatus::Complete);
    let answer = toy_execution(caller.clone(), &graph);
    assert!(
        answer.incomplete.is_empty(),
        "covering external summary closes"
    );
    assert_eq!(answer.reaches.len(), 1);
    assert!(
        !answer.reaches[0].quality.complete,
        "raw arm remains partial"
    );
    assert!(matches!(
        answer.reaches[0].hops.as_slice(),
        [Hop::Invocation { quality, .. }] if !quality.complete
    ));

    graph
        .dispatches
        .get_mut(&(caller.clone(), call))
        .unwrap()
        .arms
        .clear();
    let dispatch = graph.dispatches.get_mut(&(caller.clone(), call)).unwrap();
    dispatch.outcome = ExecutionDispatchOutcome::Cancelled("interrupted".into());
    dispatch.residuals.clear();
    dispatch.coverage = CandidateCoverage::Exhaustive;
    let answer = toy_execution(caller.clone(), &graph);
    assert!(
        answer.reaches.is_empty() && !answer.incomplete.is_empty(),
        "interruption with zero residuals is open"
    );
    assert!(answer.incomplete.iter().any(|reason| matches!(
        reason,
        Incompleteness::Execution {
            cause: IncompleteCause::Operational(OperationalCause::Cancelled),
            ..
        }
    )));
    let dispatch = graph.dispatches.get_mut(&(caller.clone(), call)).unwrap();
    dispatch.outcome = ExecutionDispatchOutcome::Complete;
    let answer = toy_execution(caller.clone(), &graph);
    assert!(
        answer.reaches.is_empty() && !answer.incomplete.is_empty(),
        "complete exhaustive armless dispatch is open"
    );
    assert!(answer.incomplete.iter().any(|reason| matches!(
        reason,
        Incompleteness::Execution {
            cause: IncompleteCause::Content,
            ..
        }
    )));

    graph.set_dispatch(
        (caller.clone(), call),
        vec![
            ToyGraph::arm(
                external.clone(),
                ExecutionTiming::SameInvocation,
                HopQuality::CERTAIN,
            ),
            ToyGraph::arm(
                external.clone(),
                ExecutionTiming::SameInvocation,
                HopQuality::new(true, false),
            ),
        ],
    );
    graph.declare(external.clone(), ExecutionEndpointStatus::Complete);
    graph.arm_declarations.insert(
        ((caller.clone(), call), 1),
        ExecutionEndpoints {
            sources: vec![ExecutionSource {
                identity: "partial-arm".into(),
                fact: true,
                provenance: "toy".into(),
                seed_point: None,
            }],
            status: ExecutionEndpointStatus::Partial("partial arm".into()),
            covers_overrides: false,
        },
    );
    let answer = toy_execution(caller.clone(), &graph);
    assert_eq!(
        answer.reaches.len(),
        2,
        "the same target has distinct arm paths"
    );
    assert!(answer.reaches.iter().any(|reach| reach.quality.complete));
    assert!(answer.reaches.iter().any(|reach| !reach.quality.complete));
    assert!(!answer.incomplete.is_empty(), "the partial arm stays open");
    let mut witnessed_arms = answer
        .reaches
        .iter()
        .map(|reach| {
            let [
                Hop::Invocation {
                    call: witnessed_call,
                    ordinal,
                    target,
                    ..
                },
            ] = reach.hops.as_slice()
            else {
                panic!("each external reach has one invocation witness");
            };
            assert_eq!(witnessed_call, &(caller.clone(), call));
            assert_eq!(target.as_ref(), &external);
            assert_eq!(reach.incoming.as_ref().unwrap().ordinal, *ordinal);
            *ordinal
        })
        .collect::<Vec<_>>();
    witnessed_arms.sort_unstable();
    assert_eq!(witnessed_arms, vec![0, 1]);

    graph.arm_declarations.clear();
    graph.allow_discharge = true;
    let dispatch = graph.dispatches.get_mut(&(caller.clone(), call)).unwrap();
    dispatch.coverage = CandidateCoverage::Open;
    assert!(
        !toy_execution(caller.clone(), &graph).incomplete.is_empty(),
        "open coverage with no residual cannot be discharged"
    );
    let dispatch = graph.dispatches.get_mut(&(caller.clone(), call)).unwrap();
    dispatch.coverage = CandidateCoverage::Truncated;
    assert!(
        !toy_execution(caller.clone(), &graph).incomplete.is_empty(),
        "truncation cannot be discharged"
    );
    let dispatch = graph.dispatches.get_mut(&(caller.clone(), call)).unwrap();
    dispatch.coverage = CandidateCoverage::Open;
    dispatch.arms.clear();
    assert!(
        !toy_execution(caller, &graph).incomplete.is_empty(),
        "an armless dispatch cannot be discharged"
    );
}

#[test]
#[hardwon("#9947: truncated execution dispatch was classified as content incomplete")]
fn truncated_execution_dispatch_is_operational() {
    use crate::analyzer::semantic::ExecutionTiming;
    let fixture = fixture();
    let caller = fixture.procedures["caller"].durable_key();
    let target = fixture.procedures["target"].durable_key();
    let call = fixture.helper_call().id;
    let mut graph = ToyGraph::default();
    graph.declare(
        ExecutionTarget::Procedure(Box::new(caller.clone())),
        ExecutionEndpointStatus::Complete,
    );
    graph.declare(
        ExecutionTarget::Procedure(Box::new(target.clone())),
        ExecutionEndpointStatus::Complete,
    );
    graph.invoke(&caller, call);
    graph.set_dispatch(
        (caller.clone(), call),
        vec![ToyGraph::arm(
            ExecutionTarget::Procedure(Box::new(target)),
            ExecutionTiming::SameInvocation,
            HopQuality::CERTAIN,
        )],
    );
    for (coverage, expected) in [
        (
            CandidateCoverage::Truncated,
            IncompleteCause::Operational(OperationalCause::Budget(BudgetLane::Semantic)),
        ),
        (CandidateCoverage::Open, IncompleteCause::Content),
    ] {
        graph
            .dispatches
            .get_mut(&(caller.clone(), call))
            .unwrap()
            .coverage = coverage;
        let answer = toy_execution(caller.clone(), &graph);
        assert!(
            answer.incomplete.iter().any(|reason| matches!(
                reason,
                Incompleteness::Execution { cause, .. } if *cause == expected
            )),
            "{coverage:?}: {:?}",
            answer.incomplete
        );
    }
}

#[test]
#[hardwon("#9947: truncated semantic dispatch coverage was classified as content incomplete")]
fn truncated_semantic_dispatch_is_operational() {
    use crate::analyzer::semantic::{DispatchResult, OracleLimits, SemanticOutcome, SemanticWork};
    let fixture = fixture();
    let procedure = &fixture.procedures["caller"];
    let call = procedure
        .call_site_handle(fixture.helper_call().id)
        .unwrap();
    for (coverage, expected) in [
        (
            CandidateCoverage::Truncated,
            IncompleteCause::Operational(OperationalCause::Budget(BudgetLane::Semantic)),
        ),
        (CandidateCoverage::Open, IncompleteCause::Content),
    ] {
        let result =
            DispatchResult::new(&call, vec![], vec![], coverage, OracleLimits::default()).unwrap();
        let answer = SemanticOutcome::Complete {
            value: result.clone(),
            work: SemanticWork::default(),
        };
        assert!(
            matches!(
                crate::composition::dispatch_completeness(&answer, &result),
                Completeness::Incomplete { cause, .. } if cause == expected
            ),
            "{coverage:?}"
        );
    }
}

#[test]
fn execution_relation_declaring_body_still_descends_own_invocations() {
    use crate::analyzer::semantic::ExecutionTiming;
    let fixture = fixture();
    let caller = fixture.procedures["caller"].durable_key();
    let callee = fixture.procedures["target"].durable_key();
    let call = fixture.helper_call().id;
    let mut graph = ToyGraph::default();
    graph.declare(
        ExecutionTarget::Procedure(Box::new(caller.clone())),
        ExecutionEndpointStatus::Complete,
    );
    graph.declare(
        ExecutionTarget::Procedure(Box::new(callee.clone())),
        ExecutionEndpointStatus::Complete,
    );
    graph.invoke(&caller, call);
    graph.set_dispatch(
        (caller.clone(), call),
        vec![ToyGraph::arm(
            ExecutionTarget::Procedure(Box::new(callee)),
            ExecutionTiming::SameInvocation,
            HopQuality::CERTAIN,
        )],
    );
    let answer = toy_execution(caller, &graph);
    assert_eq!(
        answer.reaches.len(),
        2,
        "own declaration and invoked declaration both reach"
    );
    assert!(answer.reaches.iter().any(|reach| reach.hops.is_empty()));
    assert!(answer.reaches.iter().any(|reach| !reach.hops.is_empty()));
}
