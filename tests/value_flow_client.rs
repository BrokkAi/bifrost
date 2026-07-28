mod common;

use brokk_bifrost::analyzer::dataflow::{
    DataflowRequest, PathQuality, SemanticInputStatus, SolverBudget, UnmodeledCallBehavior,
    WitnessReconstructionLimits, WitnessRetentionLimits,
};
use brokk_bifrost::analyzer::semantic::{
    CancellationToken, ControlContinuation, EvidenceCompleteness, OracleCallContext, OracleLimits,
    ProcedureHandle, ProcedureKind, ProofStatus, SemanticBudget, SemanticRequest, ValueFlowOracle,
    ValueFlowRelationKind,
};
use brokk_bifrost::analyzer::value_flow::{
    ValueFlowCarrier, ValueFlowEventKey, ValueFlowEventKind, ValueFlowInput, ValueFlowMayStatus,
    ValueFlowMustStatus, ValueFlowObservationPhase, ValueFlowPlan, ValueFlowPlanError,
    ValueFlowSinkOutcome, ValueFlowSinkSpec, ValueFlowSourceSpec, solve_value_flow_with_summaries,
    solve_value_flow_with_witnesses,
};
use brokk_bifrost::{AnalyzerConfig, Language};

use common::{InlineTestProject, semantic_graph::SemanticGraph};

const SOURCE: &str = r#"
final class FlowFixture {
  static String run(String input) {
    String copy = input;
    return copy;
  }
}
"#;

const HELPER_SOURCE: &str = r#"
final class HelperFlowFixture {
  static String relay(String value) {
    String relayed = value;
    return relayed;
  }

  static String run(String input) {
    String copy = relay(input);
    return copy;
  }
}
"#;

const UNMODELED_CALL_SOURCE: &str = r#"
interface ExternalWork {
  String run(String value);
}

final class UnmodeledCallFixture {
  static String caller(ExternalWork work, String input) {
    return work.run(input);
  }
}
"#;

fn procedure_named(graph: &SemanticGraph, name: &str, kind: ProcedureKind) -> ProcedureHandle {
    let procedure = graph
        .artifact()
        .procedures()
        .iter()
        .find(|procedure| {
            procedure.kind() == kind
                && procedure
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|segment| segment.name())
                    == Some(name)
        })
        .unwrap_or_else(|| panic!("missing {kind:?} procedure {name}"));
    graph
        .artifact()
        .procedure_handle(procedure.id())
        .expect("selected procedure remains live")
}

struct Fixture {
    analyzer: brokk_bifrost::WorkspaceAnalyzer,
    root: ProcedureHandle,
    plan: ValueFlowPlan,
}

fn fixture(sink_matches: bool, source_quality: (ProofStatus, EvidenceCompleteness)) -> Fixture {
    let project = InlineTestProject::with_language(Language::Java)
        .file("src/FlowFixture.java", SOURCE)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let graph = SemanticGraph::materialize(&project, &analyzer, "src/FlowFixture.java");
    let root = procedure_named(&graph, "run", ProcedureKind::Method);
    let cancellation = CancellationToken::default();
    let mut semantic_budget = SemanticBudget::default();
    let outcome = analyzer
        .semantic_oracle_provider()
        .procedure_relations(
            &root,
            &OracleCallContext::empty(),
            &mut SemanticRequest::new(&mut semantic_budget, &cancellation),
        )
        .expect("value-flow snapshot");
    let status = SemanticInputStatus::from_outcome(&outcome);
    let snapshot = outcome
        .available_value()
        .expect("source-backed snapshot remains available")
        .clone();
    let relation = snapshot
        .relations()
        .iter()
        .find(|relation| relation.kind == ValueFlowRelationKind::Assignment)
        .expect("local assignment relation")
        .clone();
    let source = ValueFlowSourceSpec::new(
        ValueFlowEventKey::at_point(relation.point(), 0, ValueFlowEventKind::Source)
            .expect("stable source event"),
        relation.point().clone(),
        ValueFlowObservationPhase::BeforeEffects,
        ValueFlowCarrier::from(&relation.source),
        source_quality.0,
        source_quality.1,
    );
    let sink_carrier = if sink_matches {
        ValueFlowCarrier::from(&relation.target)
    } else {
        ValueFlowCarrier::from(&relation.source)
    };
    let sink = ValueFlowSinkSpec::new(
        ValueFlowEventKey::at_point(relation.point(), 0, ValueFlowEventKind::Sink)
            .expect("stable sink event"),
        relation.point().clone(),
        ValueFlowObservationPhase::AfterEffects,
        sink_carrier,
        ProofStatus::Proven,
        EvidenceCompleteness::Complete,
    );
    let plan = ValueFlowPlan::try_new(
        root.clone(),
        vec![ValueFlowInput::new(snapshot, status)],
        Vec::new(),
        vec![source],
        vec![sink],
    )
    .expect("value-flow plan");
    Fixture {
        analyzer,
        root,
        plan,
    }
}

fn solve(fixture: &Fixture) -> brokk_bifrost::analyzer::value_flow::ValueFlowSummaryResult {
    let cancellation = CancellationToken::default();
    let mut solver_budget = SolverBudget::default();
    let mut semantic_budget = SemanticBudget::default();
    solve_value_flow_with_summaries(
        &fixture.root,
        &fixture.analyzer.icfg_provider(),
        &fixture.plan,
        &mut semantic_budget,
        &mut DataflowRequest::new(&mut solver_budget, &cancellation),
    )
    .expect("value-flow solve")
}

fn solve_unmodeled_call(
    behavior: UnmodeledCallBehavior,
) -> (
    brokk_bifrost::analyzer::value_flow::ValueFlowSummaryResult,
    brokk_bifrost::analyzer::value_flow::ValueFlowSinkId,
    brokk_bifrost::analyzer::value_flow::ValueFlowSinkId,
) {
    let project = InlineTestProject::with_language(Language::Java)
        .file("src/UnmodeledCallFixture.java", UNMODELED_CALL_SOURCE)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let graph = SemanticGraph::materialize(&project, &analyzer, "src/UnmodeledCallFixture.java");
    let root = procedure_named(&graph, "caller", ProcedureKind::Method);
    let call = root
        .semantics()
        .call_sites()
        .first()
        .expect("unmodeled call")
        .clone();
    let invoke = root.point_handle(call.point).expect("call point");
    let normal_continuation = match call.normal_continuation {
        ControlContinuation::Target(point) => {
            root.point_handle(point).expect("normal continuation")
        }
        continuation => panic!("expected normal continuation, got {continuation:?}"),
    };
    let input = root
        .value_handle(call.arguments[0].value)
        .expect("argument value");
    let result = root
        .value_handle(call.result.expect("call result"))
        .expect("result value");
    let input_carrier = ValueFlowCarrier::Value(input);
    let result_carrier = ValueFlowCarrier::Value(result);
    let source = ValueFlowSourceSpec::new(
        ValueFlowEventKey::at_point(&invoke, 0, ValueFlowEventKind::Source).expect("source key"),
        invoke,
        ValueFlowObservationPhase::BeforeEffects,
        input_carrier.clone(),
        ProofStatus::Proven,
        EvidenceCompleteness::Complete,
    );
    let result_sink_spec = ValueFlowSinkSpec::new(
        ValueFlowEventKey::at_point(&normal_continuation, 0, ValueFlowEventKind::Sink)
            .expect("result sink key"),
        normal_continuation.clone(),
        ValueFlowObservationPhase::BeforeEffects,
        result_carrier.clone(),
        ProofStatus::Proven,
        EvidenceCompleteness::Complete,
    );
    let preserved_sink_spec = ValueFlowSinkSpec::new(
        ValueFlowEventKey::at_point(&normal_continuation, 1, ValueFlowEventKind::Sink)
            .expect("preserved sink key"),
        normal_continuation,
        ValueFlowObservationPhase::BeforeEffects,
        input_carrier.clone(),
        ProofStatus::Proven,
        EvidenceCompleteness::Complete,
    );
    let plan = ValueFlowPlan::with_call_behavior(
        root.clone(),
        Vec::new(),
        Vec::new(),
        vec![source],
        vec![result_sink_spec, preserved_sink_spec],
        behavior,
    )
    .expect("unmodeled-call plan");
    let result_sink = plan
        .sinks()
        .find_map(|(id, spec)| (spec.carrier() == &result_carrier).then_some(id))
        .expect("bound result sink");
    let preserved_sink = plan
        .sinks()
        .find_map(|(id, spec)| (spec.carrier() == &input_carrier).then_some(id))
        .expect("bound preserved sink");
    let cancellation = CancellationToken::default();
    let mut solver_budget = SolverBudget::default();
    let mut semantic_budget = SemanticBudget::default();
    let result = solve_value_flow_with_summaries(
        &root,
        &analyzer.icfg_provider(),
        &plan,
        &mut semantic_budget,
        &mut DataflowRequest::new(&mut solver_budget, &cancellation),
    )
    .expect("unmodeled-call solve");
    (result, result_sink, preserved_sink)
}

#[test]
fn local_assignment_produces_a_policy_neutral_may_meeting() {
    let fixture = fixture(true, (ProofStatus::Proven, EvidenceCompleteness::Complete));
    let sink = fixture.plan.sinks().next().unwrap().0;
    let result = solve(&fixture);
    let meetings = match result.sink_outcome(sink) {
        ValueFlowSinkOutcome::Reached(meetings) => meetings,
        other => panic!("expected reached sink, got {other:?}"),
    };
    assert_eq!(meetings.len(), 1);
    assert_eq!(meetings[0].may_status(), ValueFlowMayStatus::Proven);
    assert_eq!(
        meetings[0].must_status(),
        ValueFlowMustStatus::NotEstablished
    );
    assert!(!meetings[0].is_uncertain());
}

#[test]
fn uncertain_source_does_not_inflate_a_may_proof() {
    let fixture = fixture(
        true,
        (
            ProofStatus::Unproven("test source".into()),
            EvidenceCompleteness::Partial("test source".into()),
        ),
    );
    let sink = fixture.plan.sinks().next().unwrap().0;
    let result = solve(&fixture);
    let ValueFlowSinkOutcome::Reached(meetings) = result.sink_outcome(sink) else {
        panic!("uncertain positive flow must remain visible");
    };
    assert_eq!(meetings[0].may_status(), ValueFlowMayStatus::Unproven);
    assert!(meetings[0].is_uncertain());
    assert!(!result.is_complete());
}

#[test]
fn witness_retention_is_independent_of_reachability() {
    let fixture = fixture(true, (ProofStatus::Proven, EvidenceCompleteness::Complete));
    let cancellation = CancellationToken::default();
    let mut solver_budget = SolverBudget::default();
    let mut semantic_budget = SemanticBudget::default();
    let result = solve_value_flow_with_witnesses(
        &fixture.root,
        &fixture.analyzer.icfg_provider(),
        &fixture.plan,
        WitnessRetentionLimits::new(1).expect("positive retention"),
        &mut semantic_budget,
        &mut DataflowRequest::new(&mut solver_budget, &cancellation),
    )
    .expect("value-flow solve with witnesses");
    let meeting = result.meetings().first().expect("meeting");
    let witness = result
        .witness_for_meeting(
            meeting,
            PathQuality::PROVEN_COMPLETE,
            WitnessReconstructionLimits::default(),
        )
        .expect("shared summary witness");
    assert!(!witness.steps().is_empty());
}

#[test]
fn omitted_snapshot_closure_keeps_results_incomplete() {
    let fixture = fixture(true, (ProofStatus::Proven, EvidenceCompleteness::Complete));
    let source = fixture.plan.sources().next().unwrap().1.clone();
    let sink = ValueFlowSinkSpec::new(
        ValueFlowEventKey::at_point(source.point(), 99, ValueFlowEventKind::Sink).unwrap(),
        source.point().clone(),
        ValueFlowObservationPhase::BeforeEffects,
        source.carrier().clone(),
        ProofStatus::Proven,
        EvidenceCompleteness::Complete,
    );
    let plan = ValueFlowPlan::try_new(
        fixture.root.clone(),
        Vec::new(),
        Vec::new(),
        vec![source],
        vec![sink],
    )
    .unwrap();
    let sink = plan.sinks().next().unwrap().0;
    let cancellation = CancellationToken::default();
    let mut solver_budget = SolverBudget::default();
    let mut semantic_budget = SemanticBudget::default();
    let result = solve_value_flow_with_summaries(
        &fixture.root,
        &fixture.analyzer.icfg_provider(),
        &plan,
        &mut semantic_budget,
        &mut DataflowRequest::new(&mut solver_budget, &cancellation),
    )
    .unwrap();
    assert!(matches!(
        result.sink_outcome(sink),
        ValueFlowSinkOutcome::Reached(_)
    ));
    assert!(!result.is_complete());
}

#[test]
fn unmodeled_call_profiles_are_distinct_and_paranoid_is_conservative() {
    let (paranoid, paranoid_result, paranoid_preserved) =
        solve_unmodeled_call(UnmodeledCallBehavior::Paranoid);
    let ValueFlowSinkOutcome::Reached(result_meetings) = paranoid.sink_outcome(paranoid_result)
    else {
        panic!("paranoid fallback must propagate the argument to the call result");
    };
    assert!(result_meetings.iter().all(|meeting| meeting.is_uncertain()));
    assert!(matches!(
        paranoid.sink_outcome(paranoid_preserved),
        ValueFlowSinkOutcome::Reached(_)
    ));
    assert!(!paranoid.is_complete());

    let (optimistic, optimistic_result, optimistic_preserved) =
        solve_unmodeled_call(UnmodeledCallBehavior::Optimistic);
    assert!(matches!(
        optimistic.sink_outcome(optimistic_result),
        ValueFlowSinkOutcome::Inconclusive
    ));
    let ValueFlowSinkOutcome::Reached(preserved_meetings) =
        optimistic.sink_outcome(optimistic_preserved)
    else {
        panic!("optimistic fallback must preserve the existing argument fact");
    };
    assert!(
        preserved_meetings
            .iter()
            .all(|meeting| !meeting.is_uncertain())
    );
    assert!(!optimistic.is_complete());

    let (require_model, require_result, require_preserved) =
        solve_unmodeled_call(UnmodeledCallBehavior::RequireModel);
    assert!(matches!(
        require_model.sink_outcome(require_result),
        ValueFlowSinkOutcome::Inconclusive
    ));
    let ValueFlowSinkOutcome::Reached(abstained_meetings) =
        require_model.sink_outcome(require_preserved)
    else {
        panic!("require-model fallback must retain an abstained argument fact");
    };
    assert!(
        abstained_meetings
            .iter()
            .all(|meeting| meeting.is_uncertain())
    );
    assert!(!require_model.is_complete());
}

#[test]
fn context_sensitive_oracle_inputs_are_rejected_instead_of_flattened() {
    let project = InlineTestProject::with_language(Language::Java)
        .file("src/HelperFlowFixture.java", HELPER_SOURCE)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let graph = SemanticGraph::materialize(&project, &analyzer, "src/HelperFlowFixture.java");
    let root = procedure_named(&graph, "run", ProcedureKind::Method);
    let call = root
        .call_site_handle(root.semantics().call_sites().first().unwrap().id)
        .unwrap();
    let context = OracleCallContext::bounded(vec![call], OracleLimits::default());
    let cancellation = CancellationToken::default();
    let mut semantic_budget = SemanticBudget::default();
    let outcome = analyzer
        .semantic_oracle_provider()
        .procedure_relations(
            &root,
            &context,
            &mut SemanticRequest::new(&mut semantic_budget, &cancellation),
        )
        .unwrap();
    let error = ValueFlowPlan::try_new(
        root,
        vec![ValueFlowInput::new(
            outcome.available_value().unwrap().clone(),
            SemanticInputStatus::from_outcome(&outcome),
        )],
        Vec::new(),
        Vec::new(),
        Vec::new(),
    )
    .unwrap_err();
    assert_eq!(error, ValueFlowPlanError::ContextSensitiveInputUnsupported);
}
