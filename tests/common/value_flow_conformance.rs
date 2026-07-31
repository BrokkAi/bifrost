//! Language-neutral, source-backed value-flow conformance assertions.
//!
//! Case descriptors select semantic procedures, calls, parameters, and call
//! arguments. Source text is attached only after those structured selections
//! have been made so this harness cannot turn into a second language parser.

use std::collections::{BTreeSet, HashMap};
use std::fmt::Write as _;
use std::sync::Arc;

use brokk_bifrost::analyzer::dataflow::{
    DataflowRequest, PathQuality, SemanticInputStatus, SolverBudget, SummaryWitnessStepKind,
    WitnessReconstructionLimits, WitnessRetentionLimits,
};
use brokk_bifrost::analyzer::semantic::{
    CallBinding, CallBindings, CallSiteHandle, CancellationToken, DeclarationLocator,
    DispatchBoundaryKind, DispatchOracle, EvidenceCompleteness, IcfgEdgeKind, OracleCallContext,
    ProcedureHandle, ProcedureKind, ProcedurePortKind, ProgramPointHandle, ProofStatus,
    ReturnTransferKind, SemanticBudget, SemanticLanguage, SemanticLocator, SemanticRequest,
    SemanticRole, SourceAnchor, ValueFlowOracle, ValueFlowRelationKind, WorkspaceRelativePath,
};
use brokk_bifrost::analyzer::value_flow::{
    ValueFlowCarrier, ValueFlowCarrierKey, ValueFlowEventKey, ValueFlowEventKind, ValueFlowInput,
    ValueFlowMayStatus, ValueFlowMeeting, ValueFlowMustStatus, ValueFlowObservationPhase,
    ValueFlowPlan, ValueFlowScopedRootKind, ValueFlowSelectorKey, ValueFlowSinkOutcome,
    ValueFlowSinkSpec, ValueFlowSourceSpec, ValueFlowSummaryResult,
    solve_value_flow_with_witnesses,
};
use brokk_bifrost::{AnalyzerConfig, Language, WorkspaceAnalyzer};
use pretty_assertions::assert_eq;
use serde_json::{Value, json};

use crate::common::{BuiltInlineTestProject, InlineTestProject, semantic_graph::SemanticGraph};

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
pub enum ExpectedSinkOutcome {
    Reached,
    NotReached,
    Inconclusive,
}

#[derive(Debug, Clone, Copy)]
pub struct CallArgumentSink<'case> {
    pub alias: &'case str,
    pub call: &'case str,
    pub argument: usize,
    pub outcome: ExpectedSinkOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CarrierMilestone {
    Value {
        path: Box<str>,
        procedure: Box<str>,
        role: Box<str>,
        ordinal: Option<u32>,
        snippet: Box<str>,
    },
    Port {
        path: Box<str>,
        procedure: Box<str>,
        kind: brokk_bifrost::analyzer::value_flow::ValueFlowPortKey,
    },
    CallResult {
        path: Box<str>,
        caller: Box<str>,
        callee: Box<str>,
        call: Box<str>,
        result: brokk_bifrost::analyzer::value_flow::ValueFlowPortKey,
    },
    CallArgument {
        path: Box<str>,
        caller: Box<str>,
        callee: Box<str>,
        call: Box<str>,
        ordinal: usize,
    },
    SinkArgument {
        path: Box<str>,
        caller: Box<str>,
        callee: Box<str>,
        call: Box<str>,
        ordinal: usize,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InterproceduralMilestone<'case> {
    pub kind: IcfgEdgeKind,
    pub source_procedure: &'case str,
    pub target_procedure: &'case str,
    pub origin_call: &'case str,
}

#[derive(Debug)]
pub struct ExpectedWitness<'case> {
    pub truncated: bool,
    pub carriers: &'case [CarrierMilestone],
    pub interprocedural: &'case [InterproceduralMilestone<'case>],
}

#[derive(Debug)]
pub struct ExpectedMeeting<'case> {
    pub sink: &'case str,
    pub meeting_count: usize,
    pub public_endpoint_count: usize,
    pub may_status: ValueFlowMayStatus,
    pub must_status: ValueFlowMustStatus,
    pub uncertain: bool,
    pub path_qualities: &'case [PathQuality],
    pub witness: ExpectedWitness<'case>,
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
    pub expected_discovery_status: SemanticInputStatus,
    pub expected_discovery_complete: bool,
    pub expected_result_complete: bool,
    pub expected_meetings: &'case [ExpectedMeeting<'case>],
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

pub struct ResolvedValueFlowConformanceCase {
    _project: BuiltInlineTestProject,
    pub analyzer: WorkspaceAnalyzer,
    pub root: ProcedureHandle,
    procedures: HashMap<String, ProcedureHandle>,
    calls: HashMap<String, CallSiteHandle>,
    call_bindings: HashMap<String, CallBindings>,
    pub plan: Arc<ValueFlowPlan>,
    pub witness_plan: Arc<ValueFlowPlan>,
    sink_ids: HashMap<String, brokk_bifrost::analyzer::value_flow::ValueFlowSinkId>,
    witness_sink_ids: HashMap<String, brokk_bifrost::analyzer::value_flow::ValueFlowSinkId>,
}

impl ResolvedValueFlowConformanceCase {
    pub fn sink_event_key(&self, alias: &str) -> &ValueFlowEventKey {
        let sink_id = self.sink_ids[alias];
        self.plan.sink(sink_id).expect("configured sink").key()
    }
}

pub fn assert_value_flow_conformance(case: &ValueFlowConformanceCase<'_>) {
    let resolved = resolve_value_flow_conformance_case(case);
    assert_resolved_value_flow_conformance(case, &resolved);
}

pub fn assert_resolved_value_flow_conformance(
    case: &ValueFlowConformanceCase<'_>,
    resolved: &ResolvedValueFlowConformanceCase,
) {
    let root = &resolved.root;
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
        resolved.plan.discovery_status(),
        case.expected_discovery_status,
        "{} plan discovery status",
        case.name
    );
    assert_eq!(
        resolved.plan.discovery_complete(),
        case.expected_discovery_complete,
        "{} plan discovery completeness",
        case.name
    );
    assert_eq!(
        result.is_complete(),
        case.expected_result_complete,
        "{} aggregate completeness",
        case.name
    );
    assert_exact_meetings(case, &resolved, &result);
    assert_sink_outcomes(case, &resolved, &result);
    assert_witness(case, &resolved);
}

pub fn resolve_value_flow_conformance_case(
    case: &ValueFlowConformanceCase<'_>,
) -> ResolvedValueFlowConformanceCase {
    let mut builder = InlineTestProject::with_language(case.language);
    for file in case.files {
        builder = builder.file(file.path, file.source);
    }
    let project = builder.build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig {
        parallelism: Some(1),
        memo_cache_budget_bytes: Some(16 * 1024 * 1024),
        ..AnalyzerConfig::default()
    });
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
    let mut call_bindings = HashMap::new();
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
        assert!(
            call_bindings
                .insert(selector.alias.to_owned(), binding.value().clone())
                .is_none(),
            "duplicate call-binding alias {}",
            selector.alias
        );
        bindings.push(binding);
    }

    let root = procedure(&procedures, case.root).clone();
    let resolved_root = root.clone();
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
    let mut witness_sinks = Vec::new();
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
            key.clone(),
            call_point,
            ValueFlowObservationPhase::BeforeEffects,
            carrier.clone(),
            ProofStatus::Proven,
            EvidenceCompleteness::Complete,
        ));
        witness_sinks.push(ValueFlowSinkSpec::new(
            key,
            producer.point().clone(),
            ValueFlowObservationPhase::AfterEffects,
            carrier,
            ProofStatus::Proven,
            EvidenceCompleteness::Complete,
        ));
    }

    let plan = ValueFlowPlan::try_new(
        root.clone(),
        snapshots.clone(),
        bindings.clone(),
        vec![source.clone()],
        sinks,
    )
    .unwrap_or_else(|error| panic!("{} plan failed: {error}", case.name));
    let witness_plan =
        ValueFlowPlan::try_new(root, snapshots, bindings, vec![source], witness_sinks)
            .unwrap_or_else(|error| panic!("{} witness plan failed: {error}", case.name));
    let sink_ids = resolve_sink_ids(&plan, &sink_keys);
    let witness_sink_ids = resolve_sink_ids(&witness_plan, &sink_keys);
    ResolvedValueFlowConformanceCase {
        _project: project,
        analyzer,
        root: resolved_root,
        procedures,
        calls,
        call_bindings,
        plan: Arc::new(plan),
        witness_plan: Arc::new(witness_plan),
        sink_ids,
        witness_sink_ids,
    }
}

fn resolve_sink_ids(
    plan: &ValueFlowPlan,
    sink_keys: &[(&str, ValueFlowEventKey)],
) -> HashMap<String, brokk_bifrost::analyzer::value_flow::ValueFlowSinkId> {
    sink_keys
        .iter()
        .map(|(alias, key)| {
            let id = plan
                .sinks()
                .find_map(|(id, sink)| (sink.key() == key).then_some(id))
                .expect("configured sink remains in plan");
            ((*alias).to_owned(), id)
        })
        .collect()
}

fn select_procedure(graph: &SemanticGraph, selector: &ProcedureSelector<'_>) -> ProcedureHandle {
    let mut matches = graph.artifact().procedures().iter().filter(|procedure| {
        procedure.kind() == selector.kind
            && procedure
                .locator()
                .declaration()
                .segments()
                .last()
                .and_then(|segment| segment.name())
                == Some(selector.name)
    });
    let procedure = matches.next().unwrap_or_else(|| {
        panic!(
            "missing {:?} procedure {} ({})",
            selector.kind, selector.name, selector.alias
        )
    });
    assert!(
        matches.next().is_none(),
        "procedure selector {} ({:?} {}) is ambiguous in {}",
        selector.alias,
        selector.kind,
        selector.name,
        selector.path
    );
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
    resolved: &ResolvedValueFlowConformanceCase,
    result: &ValueFlowSummaryResult,
) {
    let source = resolved.plan.sources().next().expect("configured source").1;
    let expected = case
        .expected_meetings
        .iter()
        .map(|meeting| {
            let sink_id = resolved.sink_ids[meeting.sink];
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
    resolved: &ResolvedValueFlowConformanceCase,
    result: &ValueFlowSummaryResult,
) {
    let meeting_sinks = case
        .expected_meetings
        .iter()
        .map(|meeting| meeting.sink)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        meeting_sinks.len(),
        case.expected_meetings.len(),
        "{} meeting expectations use unique sinks",
        case.name
    );
    for expected in case.sinks {
        let sink = resolved.sink_ids[expected.alias];
        match (expected.outcome, result.sink_outcome(sink)) {
            (ExpectedSinkOutcome::Reached, ValueFlowSinkOutcome::Reached(meetings)) => {
                let expectation = case
                    .expected_meetings
                    .iter()
                    .find(|meeting| meeting.sink == expected.alias)
                    .unwrap_or_else(|| {
                        panic!("reached sink {} has no meeting expectation", expected.alias)
                    });
                assert_eq!(
                    meetings.len(),
                    expectation.meeting_count,
                    "{} {} meeting count",
                    case.name,
                    expected.alias
                );
                assert!(
                    meetings
                        .iter()
                        .any(|meeting| meeting_matches(meeting, expectation)),
                    "{} {} has no meeting matching the expected status and path quality",
                    case.name,
                    expected.alias,
                );
            }
            (ExpectedSinkOutcome::NotReached, ValueFlowSinkOutcome::NotReached) => {}
            (ExpectedSinkOutcome::Inconclusive, ValueFlowSinkOutcome::Inconclusive) => {}
            (_, actual) => panic!(
                "{} sink {} had unexpected outcome {actual:?}",
                case.name, expected.alias
            ),
        }
    }
    assert_eq!(
        case.sinks
            .iter()
            .filter(|sink| sink.outcome == ExpectedSinkOutcome::Reached)
            .count(),
        case.expected_meetings.len(),
        "{} every positive sink has exactly one meeting expectation",
        case.name
    );
    assert!(
        case.expected_meetings.iter().all(|meeting| {
            case.sinks.iter().any(|sink| {
                sink.alias == meeting.sink && sink.outcome == ExpectedSinkOutcome::Reached
            })
        }),
        "{} every meeting expectation names a reached sink",
        case.name
    );
}

fn meeting_matches(meeting: &ValueFlowMeeting, expectation: &ExpectedMeeting<'_>) -> bool {
    meeting.may_status() == expectation.may_status
        && meeting.must_status() == expectation.must_status
        && meeting.is_uncertain() == expectation.uncertain
        && meeting.path_qualities().iter().collect::<Vec<_>>() == expectation.path_qualities
}

fn assert_witness(
    case: &ValueFlowConformanceCase<'_>,
    resolved: &ResolvedValueFlowConformanceCase,
) {
    let root = procedure(&resolved.procedures, case.root);
    let cancellation = CancellationToken::default();
    let mut solver_budget = SolverBudget::default();
    let mut semantic_budget = SemanticBudget::default();
    let result = solve_value_flow_with_witnesses(
        root,
        &resolved.analyzer.icfg_provider(),
        &resolved.witness_plan,
        WitnessRetentionLimits::new(8).expect("positive witness retention"),
        &mut semantic_budget,
        &mut DataflowRequest::new(&mut solver_budget, &cancellation),
    )
    .unwrap_or_else(|error| panic!("{} witness solve failed: {error}", case.name));
    for expectation in case.expected_meetings {
        assert_meeting_witness(case, resolved, &result, expectation);
    }
}

fn assert_meeting_witness(
    case: &ValueFlowConformanceCase<'_>,
    resolved: &ResolvedValueFlowConformanceCase,
    result: &ValueFlowSummaryResult,
    expectation: &ExpectedMeeting<'_>,
) {
    let positive_sink = case
        .sinks
        .iter()
        .find(|sink| sink.alias == expectation.sink)
        .expect("meeting sink");
    let sink_id = resolved.witness_sink_ids[positive_sink.alias];
    let meeting = result
        .meetings()
        .iter()
        .find(|meeting| meeting.sink() == sink_id && meeting_matches(meeting, expectation))
        .expect("positive meeting");
    let quality = *expectation
        .path_qualities
        .first()
        .expect("meeting has an expected path quality");
    assert_eq!(
        expectation.path_qualities.len(),
        1,
        "{} {} baseline witness expectation is singular",
        case.name,
        expectation.sink
    );
    let witness = result
        .witness_for_meeting(meeting, quality, WitnessReconstructionLimits::default())
        .unwrap_or_else(|error| panic!("{} witness reconstruction failed: {error}", case.name));
    assert_eq!(
        witness.truncated(),
        expectation.witness.truncated,
        "{} {} witness truncation",
        case.name,
        expectation.sink
    );
    let projected = witness
        .steps()
        .iter()
        .map(|step| project_step(case, &resolved.witness_plan, result, step))
        .collect::<Vec<_>>();
    for step in &projected {
        assert_eq!(
            step.proof,
            ProofStatus::Proven,
            "{} {} witness proof at {:?}",
            case.name,
            expectation.sink,
            step.kind
        );
        assert_eq!(
            step.completeness,
            EvidenceCompleteness::Complete,
            "{} {} witness completeness at {:?}",
            case.name,
            expectation.sink,
            step.kind
        );
    }

    let source_carrier_key = resolved
        .witness_plan
        .sources()
        .next()
        .expect("configured source")
        .1
        .carrier()
        .stable_key()
        .expect("source carrier has stable identity");
    let source_carrier = StableCarrier::from(&source_carrier_key);
    let mut actual_carriers = Vec::new();
    append_carrier_milestone(case, &mut actual_carriers, &source_carrier);
    let mut entered_calls = Vec::new();
    for step in &projected {
        if matches!(step.kind, SummaryWitnessStepKind::Edge(IcfgEdgeKind::Call)) {
            let (selector, call) = configured_call_for_origin(case, resolved, step);
            let ordinal = call_argument_ordinal(call, step.input.as_ref().expect("call input"));
            let origin = step.origin.as_ref().expect("call edge has origin");
            entered_calls.push(origin.clone());
            actual_carriers.push(CarrierMilestone::CallArgument {
                path: origin.path.as_str().into(),
                caller: procedure_name(&step.source).into(),
                callee: selector.callee.into(),
                call: source_snippet(case, origin),
                ordinal,
            });
        }
        if let Some(carrier) = &step.input {
            append_carrier_milestone(case, &mut actual_carriers, carrier);
        }
        if matches!(
            step.kind,
            SummaryWitnessStepKind::Edge(IcfgEdgeKind::NormalReturn)
        ) {
            let origin = step
                .origin
                .as_ref()
                .expect("normal-return edge has call origin");
            let entered = entered_calls.pop().expect("normal return follows a call");
            assert_eq!(
                origin, &entered,
                "{} normal return must match its exact entering call",
                case.name
            );
            append_return_binding_milestone(case, resolved, step, &mut actual_carriers);
        }
        if let Some(carrier) = &step.output {
            append_carrier_milestone(case, &mut actual_carriers, carrier);
        }
    }
    assert!(
        entered_calls.is_empty(),
        "{} witness has unmatched call edges",
        case.name
    );
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
        path: sink_call_locator.path.as_str().into(),
        caller: procedure_name(&sink_call_locator).into(),
        callee: sink_selector.callee.into(),
        call: source_snippet(case, &sink_call_locator),
        ordinal: positive_sink.argument,
    });
    assert_eq!(
        actual_carriers,
        expectation.witness.carriers,
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
                    origin_call: configured_call_for_origin(case, resolved, step).0.alias,
                })
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(
        interprocedural,
        expectation.witness.interprocedural,
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

fn append_carrier_milestone(
    case: &ValueFlowConformanceCase<'_>,
    milestones: &mut Vec<CarrierMilestone>,
    carrier: &StableCarrier,
) {
    let milestone = match carrier {
        StableCarrier::Value { role, .. } if role.as_ref() == "temporary" => return,
        StableCarrier::Value {
            locator,
            role,
            ordinal,
        } => CarrierMilestone::Value {
            path: locator.path.as_str().into(),
            procedure: procedure_name(locator).into(),
            role: role.clone(),
            ordinal: *ordinal,
            snippet: source_snippet(case, locator),
        },
        StableCarrier::Port { procedure, kind } => CarrierMilestone::Port {
            path: procedure.path.as_str().into(),
            procedure: procedure_name(procedure).into(),
            kind: *kind,
        },
        StableCarrier::CallResult {
            call,
            result,
            callee,
        } => {
            let result = match result.as_ref() {
                StableCarrier::Port { kind, .. } => *kind,
                other => panic!("baseline call result is not a return port: {other:?}"),
            };
            CarrierMilestone::CallResult {
                path: call.path.as_str().into(),
                caller: procedure_name(call).into(),
                callee: procedure_name(callee).into(),
                call: source_snippet(case, call),
                result,
            }
        }
        other => panic!("baseline witness contains unexpected carrier {other:?}"),
    };
    if milestones.last() != Some(&milestone) {
        milestones.push(milestone);
    }
}

fn configured_call_for_origin<'resolved, 'case>(
    case: &'resolved ValueFlowConformanceCase<'case>,
    resolved: &'resolved ResolvedValueFlowConformanceCase,
    step: &ProjectedWitnessStep,
) -> (&'resolved CallSelector<'case>, &'resolved CallSiteHandle) {
    let origin = step.origin.as_ref().expect("call edge has origin");
    case.calls
        .iter()
        .find_map(|selector| {
            let call = resolved.calls.get(selector.alias)?;
            (call_locator(call) == *origin).then_some((selector, call))
        })
        .expect("witness call origin belongs to configured call")
}

fn append_return_binding_milestone(
    case: &ValueFlowConformanceCase<'_>,
    resolved: &ResolvedValueFlowConformanceCase,
    step: &ProjectedWitnessStep,
    milestones: &mut Vec<CarrierMilestone>,
) {
    let (selector, _) = configured_call_for_origin(case, resolved, step);
    let bindings = resolved
        .call_bindings
        .get(selector.alias)
        .expect("configured call retains bindings");
    let input = step
        .input
        .as_ref()
        .expect("normal return has an input fact");
    let output = step
        .output
        .as_ref()
        .expect("normal return has an output fact");
    let mut matches = bindings.bindings().iter().filter(|binding| match binding {
        CallBinding::NormalReturn { formal, result, .. } => {
            let formal = ValueFlowCarrier::Port(formal.clone())
                .stable_key()
                .map(|key| StableCarrier::from(&key));
            let result = ValueFlowCarrier::Value(result.clone())
                .stable_key()
                .map(|key| StableCarrier::from(&key));
            formal.as_ref().is_ok_and(|carrier| carrier == input)
                && result.as_ref().is_ok_and(|carrier| carrier == output)
        }
        _ => false,
    });
    matches
        .next()
        .expect("normal-return witness follows one structured call binding");
    assert!(
        matches.next().is_none(),
        "normal-return witness follows one unambiguous call binding"
    );
    let origin = step
        .origin
        .as_ref()
        .expect("normal-return edge has call origin");
    milestones.push(CarrierMilestone::CallResult {
        path: origin.path.as_str().into(),
        caller: procedure_name(origin).into(),
        callee: selector.callee.into(),
        call: source_snippet(case, origin),
        result: brokk_bifrost::analyzer::value_flow::ValueFlowPortKey::NormalReturn,
    });
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

pub fn direct_witness_symbol_sequences(
    case: &ValueFlowConformanceCase<'_>,
    resolved: &ResolvedValueFlowConformanceCase,
) -> BTreeSet<String> {
    let cancellation = CancellationToken::default();
    let mut solver_budget = SolverBudget::default();
    let mut semantic_budget = SemanticBudget::default();
    let result = solve_value_flow_with_witnesses(
        &resolved.root,
        &resolved.analyzer.icfg_provider(),
        &resolved.witness_plan,
        WitnessRetentionLimits::new(8).expect("positive witness retention"),
        &mut semantic_budget,
        &mut DataflowRequest::new(&mut solver_budget, &cancellation),
    )
    .unwrap_or_else(|error| panic!("{} direct symbol solve failed: {error}", case.name));
    let mut sequences = BTreeSet::new();
    for meeting in result.meetings() {
        for quality in meeting.path_qualities().iter() {
            let witness = result
                .witness_for_meeting(meeting, quality, WitnessReconstructionLimits::default())
                .unwrap_or_else(|error| {
                    panic!("{} direct symbol witness failed: {error}", case.name)
                });
            let steps = witness
                .steps()
                .iter()
                .map(|step| direct_step_symbol(&resolved.witness_plan, &result, step))
                .collect::<Vec<_>>();
            sequences.insert(serde_json::to_string(&steps).expect("canonical direct witness JSON"));
        }
    }
    sequences
}

fn direct_step_symbol(
    plan: &ValueFlowPlan,
    result: &ValueFlowSummaryResult,
    step: &brokk_bifrost::analyzer::dataflow::SummaryWitnessStep,
) -> Value {
    let kind = match step.kind() {
        SummaryWitnessStepKind::Seed => json!({"type": "seed"}),
        SummaryWitnessStepKind::Edge(kind) => {
            json!({"type": "edge", "edge_kind": kind.label()})
        }
        SummaryWitnessStepKind::EndSummaryGap(kind) => json!({
            "type": "end_summary_gap",
            "return_kind": match kind {
                ReturnTransferKind::Normal => "normal",
                ReturnTransferKind::Exceptional => "exceptional",
            },
        }),
    };
    let mut symbol = serde_json::Map::from_iter([
        ("kind".to_string(), kind),
        (
            "source_symbol".to_string(),
            direct_locator_symbol(&point_locator(step.source())),
        ),
        (
            "input".to_string(),
            direct_fact_symbol(plan, result, step.input_fact()),
        ),
        (
            "output".to_string(),
            direct_fact_symbol(plan, result, step.output_fact()),
        ),
    ]);
    if let Some(target) = step.target() {
        symbol.insert(
            "target_symbol".to_string(),
            direct_locator_symbol(&point_locator(target)),
        );
    }
    if let Some(origin) = step.origin() {
        symbol.insert(
            "origin_symbol".to_string(),
            direct_locator_symbol(&call_locator(origin)),
        );
    }
    if let Some(boundary) = step.boundary() {
        symbol.insert(
            "boundary".to_string(),
            json!(match boundary {
                DispatchBoundaryKind::External(_) => "external",
                DispatchBoundaryKind::Unmaterialized(_) => "unmaterialized",
                DispatchBoundaryKind::Deferred { .. } => "deferred",
                DispatchBoundaryKind::Unresolved => "unresolved",
                DispatchBoundaryKind::Truncated => "truncated",
            }),
        );
    }
    Value::Object(symbol)
}

fn direct_fact_symbol(
    plan: &ValueFlowPlan,
    result: &ValueFlowSummaryResult,
    fact_id: brokk_bifrost::analyzer::dataflow::FactId,
) -> Value {
    let fact = *result
        .result()
        .fact(fact_id)
        .expect("direct witness fact resolves");
    let uncertain = !fact.uncertainty().is_empty();
    let mut symbol = match (fact.source(), fact.carrier(), fact.sink()) {
        (None, None, None) => return json!({"kind": "zero"}),
        (Some(source), Some(carrier), None) => serde_json::Map::from_iter([
            ("kind".to_string(), json!("carrier")),
            (
                "source".to_string(),
                direct_source_event_symbol(
                    plan.source(source).expect("direct witness source resolves"),
                ),
            ),
            (
                "carrier".to_string(),
                direct_carrier_symbol(
                    plan.carrier_key(carrier)
                        .expect("direct witness carrier resolves"),
                ),
            ),
        ]),
        (Some(source), None, Some(sink)) => serde_json::Map::from_iter([
            ("kind".to_string(), json!("meeting")),
            (
                "source".to_string(),
                direct_source_event_symbol(
                    plan.source(source).expect("direct meeting source resolves"),
                ),
            ),
            (
                "sink".to_string(),
                direct_sink_event_symbol(plan.sink(sink).expect("direct meeting sink resolves")),
            ),
        ]),
        shape => panic!("invalid direct witness fact shape: {shape:?}"),
    };
    if uncertain {
        symbol.insert("uncertain".to_string(), json!(true));
    }
    Value::Object(symbol)
}

fn direct_source_event_symbol(source: &ValueFlowSourceSpec) -> Value {
    direct_event_symbol(
        source.key().site(),
        source.key().ordinal(),
        source.phase(),
        source.carrier(),
    )
}

fn direct_sink_event_symbol(sink: &ValueFlowSinkSpec) -> Value {
    direct_event_symbol(
        sink.key().site(),
        sink.key().ordinal(),
        sink.phase(),
        sink.carrier(),
    )
}

fn direct_event_symbol(
    site: &SemanticLocator,
    ordinal: u32,
    phase: ValueFlowObservationPhase,
    carrier: &ValueFlowCarrier,
) -> Value {
    json!({
        "site": direct_locator_symbol(&site.into()),
        "phase": match phase {
            ValueFlowObservationPhase::BeforeEffects => "before_effects",
            ValueFlowObservationPhase::AfterEffects => "after_effects",
        },
        "ordinal": ordinal,
        "carrier": direct_carrier_symbol(
            &carrier.stable_key().expect("direct event carrier has stable identity")
        ),
    })
}

fn direct_carrier_symbol(carrier: &ValueFlowCarrierKey) -> Value {
    match carrier {
        ValueFlowCarrierKey::Value {
            locator,
            role,
            ordinal,
        } => {
            let mut symbol = serde_json::Map::from_iter([
                ("kind".to_string(), json!("value")),
                ("site".to_string(), direct_locator_symbol(&locator.into())),
                ("role".to_string(), json!(role)),
            ]);
            if let Some(ordinal) = ordinal {
                symbol.insert("ordinal".to_string(), json!(ordinal));
            }
            Value::Object(symbol)
        }
        ValueFlowCarrierKey::Port { procedure, kind } => json!({
            "kind": "port",
            "procedure": direct_locator_symbol(&procedure.into()),
            "port": match kind {
                brokk_bifrost::analyzer::value_flow::ValueFlowPortKey::Receiver => {
                    json!({"kind": "receiver"})
                }
                brokk_bifrost::analyzer::value_flow::ValueFlowPortKey::Parameter { ordinal } => {
                    json!({"kind": "parameter", "ordinal": ordinal})
                }
                brokk_bifrost::analyzer::value_flow::ValueFlowPortKey::NormalReturn => {
                    json!({"kind": "normal_return"})
                }
                brokk_bifrost::analyzer::value_flow::ValueFlowPortKey::ExceptionalReturn => {
                    json!({"kind": "exceptional_return"})
                }
                brokk_bifrost::analyzer::value_flow::ValueFlowPortKey::Capture { slot } => {
                    json!({"kind": "capture", "slot": slot})
                }
            },
        }),
        ValueFlowCarrierKey::Allocation { locator } => json!({
            "kind": "allocation",
            "site": direct_locator_symbol(&locator.into()),
        }),
        ValueFlowCarrierKey::CallResult {
            call,
            result,
            callee,
        } => json!({
            "kind": "call_result",
            "call": direct_locator_symbol(&call.into()),
            "result": direct_carrier_symbol(result),
            "callee": direct_locator_symbol(&callee.into()),
        }),
        ValueFlowCarrierKey::ScopedRoot { kind, locator } => json!({
            "kind": "scoped_root",
            "root_kind": match kind {
                ValueFlowScopedRootKind::Static => "static",
                ValueFlowScopedRootKind::LexicalCell => "lexical_cell",
                ValueFlowScopedRootKind::TypeSummary => "type_summary",
                ValueFlowScopedRootKind::ModuleObject => "module_object",
                ValueFlowScopedRootKind::External => "external",
            },
            "site": direct_locator_symbol(&locator.into()),
        }),
        ValueFlowCarrierKey::Location {
            root,
            selectors,
            exact,
        } => json!({
            "kind": "location",
            "root": direct_carrier_symbol(root),
            "selectors": selectors.iter().map(|selector| match selector {
                ValueFlowSelectorKey::Field(locator) => json!({
                    "kind": "field",
                    "field": direct_locator_symbol(&locator.into()),
                }),
                ValueFlowSelectorKey::ExactIndex(index) => json!({
                    "kind": "exact_index",
                    "index": direct_carrier_symbol(index),
                }),
                ValueFlowSelectorKey::AnyIndex => json!({"kind": "any_index"}),
            }).collect::<Vec<_>>(),
            "exact": exact,
        }),
    }
}

fn direct_locator_symbol(locator: &StableLocator) -> Value {
    let span = locator.anchor.span();
    json!({
        "path": locator.path.as_str(),
        "language": locator.language.stable_label(),
        "declaration": locator.declaration.segments().iter().map(|segment| {
            let span = segment.anchor().span();
            let mut symbol = serde_json::Map::from_iter([
                ("kind".to_string(), json!(segment.kind().stable_label())),
                ("start_byte".to_string(), json!(span.start_byte())),
                ("end_byte".to_string(), json!(span.end_byte())),
                ("occurrence".to_string(), json!(segment.anchor().occurrence())),
                ("sibling_ordinal".to_string(), json!(segment.sibling_ordinal())),
            ]);
            if let Some(name) = segment.name() {
                symbol.insert("name".to_string(), json!(name));
            }
            Value::Object(symbol)
        }).collect::<Vec<_>>(),
        "role": locator.role.stable_label(),
        "start_byte": span.start_byte(),
        "end_byte": span.end_byte(),
        "occurrence": locator.anchor.occurrence(),
    })
}

fn procedure<'map>(
    procedures: &'map HashMap<String, ProcedureHandle>,
    alias: &str,
) -> &'map ProcedureHandle {
    procedures
        .get(alias)
        .unwrap_or_else(|| panic!("missing procedure alias {alias}"))
}
