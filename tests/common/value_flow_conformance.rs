//! Language-neutral, source-backed value-flow conformance assertions.
//!
//! Case descriptors select semantic procedures, calls, parameters, and call
//! arguments. Source text is attached only after those structured selections
//! have been made so this harness cannot turn into a second language parser.

#![allow(dead_code)]

use std::collections::{BTreeSet, HashMap};
use std::fmt::Write as _;

use brokk_bifrost::analyzer::dataflow::{
    DataflowRequest, PathQuality, SemanticInputStatus, SolverBudget, SummaryWitnessStepKind,
    WitnessReconstructionLimits, WitnessRetentionLimits,
};
use brokk_bifrost::analyzer::semantic::{
    CallSiteHandle, CancellationToken, DeclarationLocator, DispatchOracle, EvidenceCompleteness,
    IcfgEdgeKind, OracleCallContext, ProcedureHandle, ProcedureKind, ProcedurePortKind,
    ProgramPointHandle, ProofStatus, SemanticBudget, SemanticLanguage, SemanticLocator,
    SemanticRequest, SemanticRole, SourceAnchor, ValueFlowOracle, ValueFlowRelationKind,
    WorkspaceRelativePath,
};
use brokk_bifrost::analyzer::value_flow::{
    ValueFlowCarrier, ValueFlowCarrierKey, ValueFlowEventKey, ValueFlowEventKind, ValueFlowInput,
    ValueFlowMayStatus, ValueFlowMustStatus, ValueFlowObservationPhase, ValueFlowPlan,
    ValueFlowScopedRootKind, ValueFlowSelectorKey, ValueFlowSinkOutcome, ValueFlowSinkSpec,
    ValueFlowSourceSpec, ValueFlowSummaryResult, solve_value_flow_with_witnesses,
};
use brokk_bifrost::{AnalyzerConfig, Language, WorkspaceAnalyzer};
use pretty_assertions::assert_eq;

use super::{BuiltInlineTestProject, InlineTestProject, semantic_graph::SemanticGraph};

#[derive(Debug, Clone, Copy)]
pub struct InlineSourceFile<'case> {
    pub path: &'case str,
    pub source: &'case str,
}

#[derive(Debug, Clone, Copy)]
pub struct ProcedureSelector<'case> {
    pub alias: &'case str,
    pub path: &'case str,
    pub name: &'case str,
    pub kind: ProcedureKind,
}

#[derive(Debug, Clone, Copy)]
pub struct CallSelector<'case> {
    pub alias: &'case str,
    pub caller: &'case str,
    pub callee: &'case str,
    pub occurrence: usize,
}

#[derive(Debug, Clone, Copy)]
pub struct ParameterSource<'case> {
    pub procedure: &'case str,
    pub ordinal: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbsentSinkExpectation {
    NotReached,
    Inconclusive,
}

#[derive(Debug, Clone, Copy)]
pub struct CallArgumentSink<'case> {
    pub alias: &'case str,
    pub call: &'case str,
    pub argument: usize,
    pub reached: bool,
    pub absent_outcome: Option<AbsentSinkExpectation>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CarrierMilestone<'case> {
    Value {
        procedure: &'case str,
        role: &'case str,
        ordinal: Option<u32>,
    },
    Port {
        procedure: &'case str,
        kind: brokk_bifrost::analyzer::value_flow::ValueFlowPortKey,
    },
    CallResult {
        caller: &'case str,
        callee: &'case str,
        result: brokk_bifrost::analyzer::value_flow::ValueFlowPortKey,
    },
    CallArgument {
        caller: &'case str,
        callee: &'case str,
        ordinal: usize,
    },
    SinkArgument {
        caller: &'case str,
        callee: &'case str,
        ordinal: usize,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InterproceduralMilestone<'case> {
    pub kind: IcfgEdgeKind,
    pub source_procedure: &'case str,
    pub target_procedure: &'case str,
    pub origin_procedure: &'case str,
}

#[derive(Debug)]
pub struct ValueFlowConformanceCase<'case> {
    pub name: &'case str,
    pub language: Language,
    pub files: &'case [InlineSourceFile<'case>],
    pub procedures: &'case [ProcedureSelector<'case>],
    pub root: &'case str,
    pub calls: &'case [CallSelector<'case>],
    pub source: ParameterSource<'case>,
    pub sinks: &'case [CallArgumentSink<'case>],
    pub expected_complete: bool,
    pub expected_carriers: &'case [CarrierMilestone<'case>],
    pub expected_interprocedural: &'case [InterproceduralMilestone<'case>],
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct StableLocator {
    path: WorkspaceRelativePath,
    language: SemanticLanguage,
    declaration: DeclarationLocator,
    role: SemanticRole,
    anchor: SourceAnchor,
}

impl From<&SemanticLocator> for StableLocator {
    fn from(locator: &SemanticLocator) -> Self {
        Self {
            path: locator.path().clone(),
            language: locator.language(),
            declaration: locator.declaration().clone(),
            role: locator.role(),
            anchor: locator.anchor(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct StableEventKey {
    site: StableLocator,
    ordinal: u32,
    kind: ValueFlowEventKind,
}

impl From<&ValueFlowEventKey> for StableEventKey {
    fn from(key: &ValueFlowEventKey) -> Self {
        Self {
            site: key.site().into(),
            ordinal: key.ordinal(),
            kind: key.kind(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum StableCarrier {
    Value {
        locator: StableLocator,
        role: Box<str>,
        ordinal: Option<u32>,
    },
    Port {
        procedure: StableLocator,
        kind: brokk_bifrost::analyzer::value_flow::ValueFlowPortKey,
    },
    Allocation {
        locator: StableLocator,
    },
    CallResult {
        call: StableLocator,
        result: Box<StableCarrier>,
        callee: StableLocator,
    },
    ScopedRoot {
        kind: ValueFlowScopedRootKind,
        locator: StableLocator,
    },
    Location {
        root: Box<StableCarrier>,
        selectors: Box<[StableSelector]>,
        exact: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum StableSelector {
    Field(StableLocator),
    ExactIndex(Box<StableCarrier>),
    AnyIndex,
}

impl From<&ValueFlowCarrierKey> for StableCarrier {
    fn from(key: &ValueFlowCarrierKey) -> Self {
        match key {
            ValueFlowCarrierKey::Value {
                locator,
                role,
                ordinal,
            } => Self::Value {
                locator: locator.into(),
                role: role.clone(),
                ordinal: *ordinal,
            },
            ValueFlowCarrierKey::Port { procedure, kind } => Self::Port {
                procedure: procedure.into(),
                kind: *kind,
            },
            ValueFlowCarrierKey::Allocation { locator } => Self::Allocation {
                locator: locator.into(),
            },
            ValueFlowCarrierKey::CallResult {
                call,
                result,
                callee,
            } => Self::CallResult {
                call: call.into(),
                result: Box::new(result.as_ref().into()),
                callee: callee.into(),
            },
            ValueFlowCarrierKey::ScopedRoot { kind, locator } => Self::ScopedRoot {
                kind: *kind,
                locator: locator.into(),
            },
            ValueFlowCarrierKey::Location {
                root,
                selectors,
                exact,
            } => Self::Location {
                root: Box::new(root.as_ref().into()),
                selectors: selectors
                    .iter()
                    .map(|selector| match selector {
                        ValueFlowSelectorKey::Field(locator) => {
                            StableSelector::Field(locator.into())
                        }
                        ValueFlowSelectorKey::ExactIndex(index) => {
                            StableSelector::ExactIndex(Box::new(index.as_ref().into()))
                        }
                        ValueFlowSelectorKey::AnyIndex => StableSelector::AnyIndex,
                    })
                    .collect::<Vec<_>>()
                    .into_boxed_slice(),
                exact: *exact,
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProjectedWitnessStep {
    kind: SummaryWitnessStepKind,
    source: StableLocator,
    source_snippet: Box<str>,
    target: Option<StableLocator>,
    target_snippet: Option<Box<str>>,
    origin: Option<StableLocator>,
    input: Option<StableCarrier>,
    output: Option<StableCarrier>,
    proof: ProofStatus,
    completeness: EvidenceCompleteness,
}

struct ResolvedCase {
    _project: BuiltInlineTestProject,
    analyzer: WorkspaceAnalyzer,
    procedures: HashMap<String, ProcedureHandle>,
    calls: HashMap<String, CallSiteHandle>,
    plan: ValueFlowPlan,
    sink_ids: HashMap<String, brokk_bifrost::analyzer::value_flow::ValueFlowSinkId>,
}

pub fn assert_value_flow_conformance(case: &ValueFlowConformanceCase<'_>) {
    let resolved = build_case(case);
    let root = procedure(&resolved.procedures, case.root);
    let cancellation = CancellationToken::default();
    let mut solver_budget = SolverBudget::default();
    let mut semantic_budget = SemanticBudget::default();
    let result = solve_value_flow_with_witnesses(
        root,
        &resolved.analyzer.icfg_provider(),
        &resolved.plan,
        WitnessRetentionLimits::new(8).expect("positive witness retention"),
        &mut semantic_budget,
        &mut DataflowRequest::new(&mut solver_budget, &cancellation),
    )
    .unwrap_or_else(|error| panic!("{} value-flow solve failed: {error}", case.name));

    assert_eq!(
        result.is_complete(),
        case.expected_complete,
        "{} aggregate completeness",
        case.name
    );
    assert_exact_meetings(case, &resolved, &result);
    assert_sink_outcomes(case, &resolved, &result);
    assert_witness(case, &resolved, &result);
}

fn build_case(case: &ValueFlowConformanceCase<'_>) -> ResolvedCase {
    let mut builder = InlineTestProject::with_language(case.language);
    for file in case.files {
        builder = builder.file(file.path, file.source);
    }
    let project = builder.build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graphs = HashMap::new();
    let mut procedures = HashMap::new();
    for selector in case.procedures {
        let graph = graphs
            .entry(selector.path)
            .or_insert_with(|| SemanticGraph::materialize(&project, &analyzer, selector.path));
        let handle = select_procedure(graph, selector);
        assert!(
            procedures
                .insert(selector.alias.to_owned(), handle)
                .is_none(),
            "duplicate procedure alias {}",
            selector.alias
        );
    }

    let cancellation = CancellationToken::default();
    let oracle = analyzer.semantic_oracle_provider();
    let mut semantic_budget = SemanticBudget::default();
    let mut snapshots = Vec::new();
    for selector in case.procedures {
        let selected = procedure(&procedures, selector.alias);
        let outcome = oracle
            .procedure_relations(
                selected,
                &OracleCallContext::empty(),
                &mut SemanticRequest::new(&mut semantic_budget, &cancellation),
            )
            .unwrap_or_else(|error| panic!("{} snapshot failed: {error}", selector.alias));
        snapshots.push(ValueFlowInput::new(
            outcome
                .available_value()
                .unwrap_or_else(|| panic!("{} snapshot has no available value", selector.alias))
                .clone(),
            SemanticInputStatus::from_outcome(&outcome),
        ));
    }

    let mut calls = HashMap::new();
    let mut bindings = Vec::new();
    for selector in case.calls {
        let caller = procedure(&procedures, selector.caller);
        let callee = procedure(&procedures, selector.callee);
        let (call, binding) = select_call_and_bindings(
            &oracle,
            caller,
            callee,
            selector,
            &mut semantic_budget,
            &cancellation,
        );
        assert!(
            calls.insert(selector.alias.to_owned(), call).is_none(),
            "duplicate call alias {}",
            selector.alias
        );
        bindings.push(binding);
    }

    let root = procedure(&procedures, case.root).clone();
    let source_procedure = procedure(&procedures, case.source.procedure);
    let root_snapshot = snapshots
        .iter()
        .find(|input| input.value().procedure() == source_procedure)
        .expect("source procedure snapshot");
    let source_relation = root_snapshot
        .value()
        .relations()
        .iter()
        .find(|relation| {
            if relation.kind != ValueFlowRelationKind::Parameter {
                return false;
            }
            matches!(
                ValueFlowCarrier::from(&relation.source),
                ValueFlowCarrier::Port(port)
                    if port.kind()
                        == (ProcedurePortKind::Parameter {
                            ordinal: case.source.ordinal,
                        })
            )
        })
        .unwrap_or_else(|| {
            panic!(
                "missing parameter {} in {}",
                case.source.ordinal, case.source.procedure
            )
        });
    let source = ValueFlowSourceSpec::new(
        ValueFlowEventKey::at_point(
            source_relation.point(),
            source_relation.event_index(),
            ValueFlowEventKind::Source,
        )
        .expect("stable source event"),
        source_relation.point().clone(),
        ValueFlowObservationPhase::BeforeEffects,
        ValueFlowCarrier::from(&source_relation.source),
        ProofStatus::Proven,
        EvidenceCompleteness::Complete,
    );

    let mut sinks = Vec::new();
    let mut sink_keys = Vec::new();
    for sink in case.sinks {
        let call = calls
            .get(sink.call)
            .unwrap_or_else(|| panic!("missing call alias {}", sink.call));
        let call_row = call
            .procedure()
            .semantics()
            .call_site(call.id())
            .expect("selected call remains live");
        let argument = call_row.arguments.get(sink.argument).unwrap_or_else(|| {
            panic!(
                "call {} has no argument {} for sink {}",
                sink.call, sink.argument, sink.alias
            )
        });
        let call_point = call
            .procedure()
            .point_handle(call_row.point)
            .expect("call point remains live");
        let value = call
            .procedure()
            .value_handle(argument.value)
            .expect("call argument remains live");
        let carrier = ValueFlowCarrier::Value(value);
        let snapshot = snapshots
            .iter()
            .find(|input| input.value().procedure() == call.procedure())
            .expect("call procedure snapshot");
        let producer = snapshot
            .value()
            .relations()
            .iter()
            .find(|relation| ValueFlowCarrier::from(&relation.target) == carrier)
            .unwrap_or_else(|| {
                panic!(
                    "call {} argument {} has no structured producing relation",
                    sink.call, sink.argument
                )
            });
        let key = ValueFlowEventKey::at_point(
            &call_point,
            sink.argument as u32,
            ValueFlowEventKind::Sink,
        )
        .expect("stable sink event");
        sink_keys.push((sink.alias, key.clone()));
        sinks.push(ValueFlowSinkSpec::new(
            key,
            producer.point().clone(),
            ValueFlowObservationPhase::AfterEffects,
            carrier,
            ProofStatus::Proven,
            EvidenceCompleteness::Complete,
        ));
    }

    let plan = ValueFlowPlan::try_new(root, snapshots, bindings, vec![source], sinks)
        .unwrap_or_else(|error| panic!("{} plan failed: {error}", case.name));
    let sink_ids = sink_keys
        .into_iter()
        .map(|(alias, key)| {
            let id = plan
                .sinks()
                .find_map(|(id, sink)| (sink.key() == &key).then_some(id))
                .expect("configured sink remains in plan");
            (alias.to_owned(), id)
        })
        .collect();
    ResolvedCase {
        _project: project,
        analyzer,
        procedures,
        calls,
        plan,
        sink_ids,
    }
}

fn select_procedure(graph: &SemanticGraph, selector: &ProcedureSelector<'_>) -> ProcedureHandle {
    let procedure = graph
        .artifact()
        .procedures()
        .iter()
        .find(|procedure| {
            procedure.kind() == selector.kind
                && procedure
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|segment| segment.name())
                    == Some(selector.name)
        })
        .unwrap_or_else(|| {
            panic!(
                "missing {:?} procedure {} ({})",
                selector.kind, selector.name, selector.alias
            )
        });
    graph
        .artifact()
        .procedure_handle(procedure.id())
        .expect("selected procedure remains live")
}

fn select_call_and_bindings(
    oracle: &(impl DispatchOracle + ValueFlowOracle),
    caller: &ProcedureHandle,
    callee: &ProcedureHandle,
    selector: &CallSelector<'_>,
    semantic_budget: &mut SemanticBudget,
    cancellation: &CancellationToken,
) -> (
    CallSiteHandle,
    ValueFlowInput<brokk_bifrost::analyzer::semantic::CallBindings>,
) {
    let mut matches = Vec::new();
    for row in caller.semantics().call_sites() {
        let call = caller
            .call_site_handle(row.id)
            .expect("call row remains live");
        let dispatch = oracle
            .resolve_call(
                &call,
                &mut SemanticRequest::new(semantic_budget, cancellation),
            )
            .unwrap_or_else(|error| panic!("{} dispatch failed: {error}", selector.alias));
        if let Some(candidate) = dispatch.available_value().and_then(|result| {
            result
                .candidates()
                .iter()
                .find(|item| item.target() == callee)
        }) {
            matches.push((call, candidate.clone()));
        }
    }
    let (call, candidate) = matches
        .into_iter()
        .nth(selector.occurrence)
        .unwrap_or_else(|| {
            panic!(
                "missing occurrence {} of call {} -> {} ({})",
                selector.occurrence, selector.caller, selector.callee, selector.alias
            )
        });
    let outcome = oracle
        .call_bindings(
            &call,
            &candidate,
            &OracleCallContext::empty(),
            &mut SemanticRequest::new(semantic_budget, cancellation),
        )
        .unwrap_or_else(|error| panic!("{} bindings failed: {error}", selector.alias));
    let input = ValueFlowInput::new(
        outcome
            .available_value()
            .unwrap_or_else(|| panic!("{} bindings have no available value", selector.alias))
            .clone(),
        SemanticInputStatus::from_outcome(&outcome),
    );
    (call, input)
}

fn assert_exact_meetings(
    case: &ValueFlowConformanceCase<'_>,
    resolved: &ResolvedCase,
    result: &ValueFlowSummaryResult,
) {
    let source = resolved.plan.sources().next().expect("configured source").1;
    let expected = case
        .sinks
        .iter()
        .filter(|sink| sink.reached)
        .map(|sink| {
            let sink_id = resolved.sink_ids[sink.alias];
            let sink = resolved.plan.sink(sink_id).expect("configured sink");
            (
                StableEventKey::from(source.key()),
                StableEventKey::from(sink.key()),
            )
        })
        .collect::<BTreeSet<_>>();
    let actual = result
        .meetings()
        .iter()
        .map(|meeting| {
            let source = resolved
                .plan
                .source(meeting.source())
                .expect("meeting source belongs to plan");
            let sink = resolved
                .plan
                .sink(meeting.sink())
                .expect("meeting sink belongs to plan");
            (
                StableEventKey::from(source.key()),
                StableEventKey::from(sink.key()),
            )
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(actual, expected, "{} exact meeting set", case.name);
}

fn assert_sink_outcomes(
    case: &ValueFlowConformanceCase<'_>,
    resolved: &ResolvedCase,
    result: &ValueFlowSummaryResult,
) {
    for expected in case.sinks {
        let sink = resolved.sink_ids[expected.alias];
        match (expected.reached, result.sink_outcome(sink)) {
            (true, ValueFlowSinkOutcome::Reached(meetings)) => {
                assert_eq!(
                    meetings.len(),
                    1,
                    "{} {} meeting count",
                    case.name,
                    expected.alias
                );
                let meeting = meetings[0];
                assert_eq!(meeting.may_status(), ValueFlowMayStatus::Proven);
                assert_eq!(meeting.must_status(), ValueFlowMustStatus::NotEstablished);
                assert!(
                    !meeting.is_uncertain(),
                    "{} {} is uncertain",
                    case.name,
                    expected.alias
                );
                assert_eq!(
                    meeting.path_qualities().iter().collect::<Vec<_>>(),
                    vec![PathQuality::PROVEN_COMPLETE],
                    "{} {} path qualities",
                    case.name,
                    expected.alias
                );
            }
            (false, ValueFlowSinkOutcome::NotReached)
                if expected.absent_outcome == Some(AbsentSinkExpectation::NotReached) => {}
            (false, ValueFlowSinkOutcome::Inconclusive)
                if expected.absent_outcome == Some(AbsentSinkExpectation::Inconclusive) => {}
            (_, actual) => panic!(
                "{} sink {} had unexpected outcome {actual:?}",
                case.name, expected.alias
            ),
        }
    }
}

fn assert_witness(
    case: &ValueFlowConformanceCase<'_>,
    resolved: &ResolvedCase,
    result: &ValueFlowSummaryResult,
) {
    let positive_sink = case
        .sinks
        .iter()
        .find(|sink| sink.reached)
        .expect("positive sink");
    let sink_id = resolved.sink_ids[positive_sink.alias];
    let meeting = result
        .meetings()
        .iter()
        .find(|meeting| meeting.sink() == sink_id)
        .expect("positive meeting");
    let witness = result
        .witness_for_meeting(
            meeting,
            PathQuality::PROVEN_COMPLETE,
            WitnessReconstructionLimits::default(),
        )
        .unwrap_or_else(|error| panic!("{} witness reconstruction failed: {error}", case.name));
    assert!(!witness.truncated(), "{} witness was truncated", case.name);
    let projected = witness
        .steps()
        .iter()
        .map(|step| project_step(case, &resolved.plan, result, step))
        .collect::<Vec<_>>();

    let source_carrier_key = resolved
        .plan
        .sources()
        .next()
        .expect("configured source")
        .1
        .carrier()
        .stable_key()
        .expect("source carrier has stable identity");
    let source_carrier = StableCarrier::from(&source_carrier_key);
    let mut actual_carriers = Vec::new();
    append_carrier_milestone(&mut actual_carriers, &source_carrier);
    for step in &projected {
        if matches!(step.kind, SummaryWitnessStepKind::Edge(IcfgEdgeKind::Call)) {
            let (call, callee) = call_for_origin(case, resolved, step);
            let ordinal = call_argument_ordinal(call, step.input.as_ref().expect("call input"));
            actual_carriers.push(CarrierMilestone::CallArgument {
                caller: procedure_name(&step.source),
                callee,
                ordinal,
            });
        }
        if let Some(carrier) = &step.input {
            append_carrier_milestone(&mut actual_carriers, carrier);
        }
        if matches!(
            step.kind,
            SummaryWitnessStepKind::Edge(IcfgEdgeKind::NormalReturn)
        ) {
            actual_carriers.push(CarrierMilestone::CallResult {
                caller: procedure_name(
                    step.origin
                        .as_ref()
                        .expect("normal-return edge has call origin"),
                ),
                callee: procedure_name(&step.source),
                result: brokk_bifrost::analyzer::value_flow::ValueFlowPortKey::NormalReturn,
            });
        }
        if let Some(carrier) = &step.output {
            append_carrier_milestone(&mut actual_carriers, carrier);
        }
    }
    let sink_call = resolved
        .calls
        .get(positive_sink.call)
        .expect("positive sink call");
    let sink_selector = case
        .calls
        .iter()
        .find(|selector| selector.alias == positive_sink.call)
        .expect("positive sink call selector");
    let sink_call_locator = call_locator(sink_call);
    actual_carriers.push(CarrierMilestone::SinkArgument {
        caller: procedure_name(&sink_call_locator),
        callee: sink_selector.callee,
        ordinal: positive_sink.argument,
    });
    assert_eq!(
        actual_carriers,
        case.expected_carriers,
        "{} canonical carrier milestones; projected witness:\n{}",
        case.name,
        render_witness(&projected)
    );

    let interprocedural = projected
        .iter()
        .filter_map(|step| match step.kind {
            SummaryWitnessStepKind::Edge(IcfgEdgeKind::Call | IcfgEdgeKind::NormalReturn) => {
                Some(InterproceduralMilestone {
                    kind: match step.kind {
                        SummaryWitnessStepKind::Edge(kind) => kind,
                        _ => unreachable!(),
                    },
                    source_procedure: procedure_name(&step.source),
                    target_procedure: procedure_name(
                        step.target
                            .as_ref()
                            .expect("interprocedural edge has target"),
                    ),
                    origin_procedure: procedure_name(
                        step.origin
                            .as_ref()
                            .expect("interprocedural edge has call origin"),
                    ),
                })
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(
        interprocedural,
        case.expected_interprocedural,
        "{} context-respecting call/return milestones; projected witness:\n{}",
        case.name,
        render_witness(&projected)
    );
}

fn project_step(
    case: &ValueFlowConformanceCase<'_>,
    plan: &ValueFlowPlan,
    result: &ValueFlowSummaryResult,
    step: &brokk_bifrost::analyzer::dataflow::SummaryWitnessStep,
) -> ProjectedWitnessStep {
    let source = point_locator(step.source());
    let target = step.target().map(point_locator);
    let origin = step.origin().map(call_locator);
    ProjectedWitnessStep {
        source_snippet: source_snippet(case, &source),
        target_snippet: target.as_ref().map(|locator| source_snippet(case, locator)),
        source,
        target,
        origin,
        input: fact_carrier(plan, result, step.input_fact()),
        output: fact_carrier(plan, result, step.output_fact()),
        kind: step.kind(),
        proof: step.proof().clone(),
        completeness: step.completeness().clone(),
    }
}

fn fact_carrier(
    plan: &ValueFlowPlan,
    result: &ValueFlowSummaryResult,
    fact: brokk_bifrost::analyzer::dataflow::FactId,
) -> Option<StableCarrier> {
    let carrier = result.result().fact(fact)?.carrier()?;
    plan.carrier_key(carrier).map(StableCarrier::from)
}

fn point_locator(point: &ProgramPointHandle) -> StableLocator {
    let row = point
        .procedure()
        .semantics()
        .point(point.id())
        .expect("witness point remains live");
    let mapping = point
        .procedure()
        .semantics()
        .source_mapping(row.source)
        .expect("witness point retains source mapping");
    (&mapping.locator).into()
}

fn call_locator(call: &CallSiteHandle) -> StableLocator {
    let row = call
        .procedure()
        .semantics()
        .call_site(call.id())
        .expect("witness call remains live");
    (&call
        .procedure()
        .semantics()
        .source_mapping(row.source)
        .expect("witness call retains source mapping")
        .locator)
        .into()
}

fn source_snippet(case: &ValueFlowConformanceCase<'_>, locator: &StableLocator) -> Box<str> {
    let file = case
        .files
        .iter()
        .find(|file| file.path == locator.path.as_str())
        .unwrap_or_else(|| panic!("missing fixture source for {}", locator.path.as_str()));
    let span = locator.anchor.span();
    let source = file
        .source
        .get(span.start_byte() as usize..span.end_byte() as usize)
        .expect("semantic source span indexes fixture");
    source
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .into_boxed_str()
}

fn render_witness(steps: &[ProjectedWitnessStep]) -> String {
    let mut rendered = String::new();
    for step in steps {
        let target = step.target_snippet.as_deref().unwrap_or("<none>");
        let input = step
            .input
            .as_ref()
            .map(render_carrier)
            .unwrap_or_else(|| "<zero>".to_owned());
        let output = step
            .output
            .as_ref()
            .map(render_carrier)
            .unwrap_or_else(|| "<meeting-or-zero>".to_owned());
        writeln!(
            rendered,
            "{:?}: {:?} -> {:?}; {} -> {}",
            step.kind, step.source_snippet, target, input, output
        )
        .expect("writing to a string cannot fail");
    }
    rendered
}

fn render_carrier(carrier: &StableCarrier) -> String {
    match carrier {
        StableCarrier::Value {
            locator,
            role,
            ordinal,
        } => format!("{}:value({role},{ordinal:?})", procedure_name(locator)),
        StableCarrier::Port { procedure, kind } => {
            format!("{}:port({kind:?})", procedure_name(procedure))
        }
        StableCarrier::CallResult {
            call,
            callee,
            result,
        } => format!(
            "{}:call-result({},{})",
            procedure_name(call),
            procedure_name(callee),
            render_carrier(result)
        ),
        StableCarrier::Allocation { locator } => {
            format!("{}:allocation", procedure_name(locator))
        }
        StableCarrier::ScopedRoot { kind, locator } => {
            format!("{}:root({kind:?})", procedure_name(locator))
        }
        StableCarrier::Location { root, exact, .. } => {
            format!("location({},exact={exact})", render_carrier(root))
        }
    }
}

fn append_carrier_milestone<'carrier>(
    milestones: &mut Vec<CarrierMilestone<'carrier>>,
    carrier: &'carrier StableCarrier,
) {
    let milestone = match carrier {
        StableCarrier::Value { role, .. } if role.as_ref() == "temporary" => return,
        StableCarrier::Value {
            locator,
            role,
            ordinal,
        } => CarrierMilestone::Value {
            procedure: procedure_name(locator),
            role,
            ordinal: *ordinal,
        },
        StableCarrier::Port { procedure, kind } => CarrierMilestone::Port {
            procedure: procedure_name(procedure),
            kind: *kind,
        },
        StableCarrier::CallResult {
            call,
            result,
            callee,
        } => CarrierMilestone::CallResult {
            caller: procedure_name(call),
            callee: procedure_name(callee),
            result: match carrier_milestone(result) {
                Some(CarrierMilestone::Port { kind, .. }) => kind,
                other => panic!("baseline call result is not a return port: {other:?}"),
            },
        },
        other => panic!("baseline witness contains unexpected carrier {other:?}"),
    };
    if milestones.last() != Some(&milestone) {
        milestones.push(milestone);
    }
}

fn carrier_milestone(carrier: &StableCarrier) -> Option<CarrierMilestone<'_>> {
    let mut milestones = Vec::new();
    append_carrier_milestone(&mut milestones, carrier);
    milestones.pop()
}

fn call_for_origin<'resolved, 'case>(
    case: &'resolved ValueFlowConformanceCase<'case>,
    resolved: &'resolved ResolvedCase,
    step: &ProjectedWitnessStep,
) -> (&'resolved CallSiteHandle, &'case str) {
    let origin = step.origin.as_ref().expect("call edge has origin");
    case.calls
        .iter()
        .find_map(|selector| {
            let call = resolved.calls.get(selector.alias)?;
            (call_locator(call) == *origin).then_some((call, selector.callee))
        })
        .expect("witness call origin belongs to configured call")
}

fn call_argument_ordinal(call: &CallSiteHandle, carrier: &StableCarrier) -> usize {
    let row = call
        .procedure()
        .semantics()
        .call_site(call.id())
        .expect("witness call remains live");
    row.arguments
        .iter()
        .position(|argument| {
            let value = call
                .procedure()
                .value_handle(argument.value)
                .expect("call argument remains live");
            ValueFlowCarrier::Value(value)
                .stable_key()
                .is_ok_and(|key| StableCarrier::from(&key) == *carrier)
        })
        .expect("call-edge input is one structured actual argument")
}

fn procedure_name(locator: &StableLocator) -> &str {
    locator
        .declaration
        .segments()
        .last()
        .and_then(|segment| segment.name())
        .expect("baseline locators belong to named procedures")
}

fn procedure<'map>(
    procedures: &'map HashMap<String, ProcedureHandle>,
    alias: &str,
) -> &'map ProcedureHandle {
    procedures
        .get(alias)
        .unwrap_or_else(|| panic!("missing procedure alias {alias}"))
}
