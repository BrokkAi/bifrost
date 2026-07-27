mod common;

use brokk_bifrost::analyzer::dataflow::{
    DataflowRequest, PathQuality, SemanticInputStatus, SolverBudget, WitnessReconstructionLimits,
    WitnessRetentionLimits,
};
use brokk_bifrost::analyzer::semantic::{
    CancellationToken, EvidenceCompleteness, OracleCallContext, OracleLimits, ProcedureHandle,
    ProcedureKind, ProofStatus, SemanticBudget, SemanticRequest, ValueFlowOracle,
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
