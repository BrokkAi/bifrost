mod common;

use brokk_bifrost::analyzer::dataflow::{
    DataflowRequest, SolverBudget, WitnessReconstructionLimits, WitnessRetentionLimits,
};
use brokk_bifrost::analyzer::semantic::{
    CancellationToken, EvidenceCompleteness, OracleCallContext, ProcedureHandle, ProcedureKind,
    ProofStatus, SemanticBudget, SemanticRequest, ValueFlowOracle, ValueFlowRelationKind,
};
use brokk_bifrost::analyzer::taint::{
    SourceClassId, SourceEventKey, TaintAnalysisPlan, TaintBatchCompatibilityKey,
    TaintBatchPlanner, TaintClassSet, TaintEdgeFunction, TaintPolicyPlan, TaintSanitizerBinding,
    TaintSinkBinding, TaintSourceBinding, TaintTransformBinding, TaintUniverse,
    collect_taint_findings, solve_taint_batch_with_witnesses,
};
use brokk_bifrost::analyzer::value_flow::{
    ValueFlowCarrier, ValueFlowEventKey, ValueFlowEventKind, ValueFlowInput,
    ValueFlowObservationPhase, ValueFlowPlan, ValueFlowSinkSpec, ValueFlowSourceSpec,
};
use brokk_bifrost::{AnalyzerConfig, Language};

use common::{InlineTestProject, semantic_graph::SemanticGraph};

const SOURCE: &str = r#"
final class TaintFixture {
  static String run(String input) {
    String copy = input;
    return copy;
  }
}
"#;

fn class(value: &str) -> SourceClassId {
    SourceClassId::new(value).unwrap()
}

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
        .unwrap();
    graph.artifact().procedure_handle(procedure.id()).unwrap()
}

struct Fixture {
    analyzer: brokk_bifrost::WorkspaceAnalyzer,
    root: ProcedureHandle,
    plan: TaintAnalysisPlan,
    all_classes: TaintClassSet,
    sanitized_class: SourceClassId,
}

fn fixture(sanitizer: Option<bool>) -> Fixture {
    fixture_with_transfers(sanitizer.map(|resolved| (resolved, 0)), None)
}

fn fixture_with_transfers(sanitizer: Option<(bool, u32)>, transform_index: Option<u32>) -> Fixture {
    let project = InlineTestProject::with_language(Language::Java)
        .file("src/TaintFixture.java", SOURCE)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let graph = SemanticGraph::materialize(&project, &analyzer, "src/TaintFixture.java");
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
        .unwrap();
    let status = brokk_bifrost::analyzer::dataflow::SemanticInputStatus::from_outcome(&outcome);
    let snapshot = outcome.available_value().unwrap().clone();
    let relation = snapshot
        .relations()
        .iter()
        .find(|relation| relation.kind == ValueFlowRelationKind::Assignment)
        .unwrap()
        .clone();

    let source_specs = (0..3)
        .map(|ordinal| {
            ValueFlowSourceSpec::new(
                ValueFlowEventKey::at_point(relation.point(), ordinal, ValueFlowEventKind::Source)
                    .unwrap(),
                relation.point().clone(),
                ValueFlowObservationPhase::BeforeEffects,
                ValueFlowCarrier::from(&relation.source),
                ProofStatus::Proven,
                EvidenceCompleteness::Complete,
            )
        })
        .collect::<Vec<_>>();
    let sink_specs = (0..4)
        .map(|ordinal| {
            ValueFlowSinkSpec::new(
                ValueFlowEventKey::at_point(relation.point(), ordinal, ValueFlowEventKind::Sink)
                    .unwrap(),
                relation.point().clone(),
                ValueFlowObservationPhase::AfterEffects,
                ValueFlowCarrier::from(&relation.target),
                ProofStatus::Proven,
                EvidenceCompleteness::Complete,
            )
        })
        .collect::<Vec<_>>();
    let value_flow = ValueFlowPlan::try_new(
        root.clone(),
        vec![ValueFlowInput::new(snapshot, status)],
        Vec::new(),
        source_specs,
        sink_specs,
    )
    .unwrap();
    let universe = TaintUniverse::new(vec![class("sql"), class("path"), class("html")]).unwrap();
    let all_classes = universe.class_set(universe.classes()).unwrap();
    let sanitized_class = class("sql");
    let taint_sources = value_flow
        .sources()
        .zip(universe.classes())
        .map(|((id, spec), stable)| {
            TaintSourceBinding::new(
                id,
                universe.class_set([stable]).unwrap(),
                SourceEventKey::new(spec.key().clone()),
            )
        })
        .collect();
    let taint_sinks = value_flow
        .sinks()
        .map(|(id, _)| TaintSinkBinding::new(id, all_classes.clone()))
        .collect();
    let target = value_flow
        .carrier_id(&ValueFlowCarrier::from(&relation.target))
        .unwrap();
    let sanitizers = sanitizer
        .map(|(resolved, event_index)| {
            let removed = if transform_index.is_some() {
                universe.class_set([&class("path")]).unwrap()
            } else {
                universe.class_set([&class("sql")]).unwrap()
            };
            if resolved {
                TaintSanitizerBinding::resolved(
                    relation.point().clone(),
                    ValueFlowObservationPhase::AfterEffects,
                    event_index,
                    target,
                    removed,
                )
            } else {
                TaintSanitizerBinding::unresolved(
                    relation.point().clone(),
                    ValueFlowObservationPhase::AfterEffects,
                    event_index,
                    target,
                    removed,
                )
            }
        })
        .into_iter()
        .collect();
    let transforms = transform_index
        .map(|event_index| {
            let targets = universe.class_set([&class("path")]).unwrap();
            let function =
                TaintEdgeFunction::transform(&universe, [(class("sql"), targets)], true).unwrap();
            TaintTransformBinding::new(
                relation.point().clone(),
                ValueFlowObservationPhase::AfterEffects,
                event_index,
                target,
                function,
            )
        })
        .into_iter()
        .collect();
    let plan = TaintAnalysisPlan::new(
        value_flow,
        universe,
        taint_sources,
        taint_sinks,
        sanitizers,
        transforms,
    )
    .unwrap();
    Fixture {
        analyzer,
        root,
        plan,
        all_classes,
        sanitized_class,
    }
}

fn solve(
    fixture: &Fixture,
    witnesses: WitnessRetentionLimits,
) -> brokk_bifrost::analyzer::taint::TaintSummaryResult {
    let cancellation = CancellationToken::default();
    let mut solver_budget = SolverBudget::default();
    let mut semantic_budget = SemanticBudget::default();
    solve_taint_batch_with_witnesses(
        &fixture.root,
        &fixture.analyzer.icfg_provider(),
        &fixture.plan,
        witnesses,
        &mut semantic_budget,
        &mut DataflowRequest::new(&mut solver_budget, &cancellation),
    )
    .unwrap()
}

#[test]
fn class_set_edge_functions_obey_union_and_path_order() {
    let universe = TaintUniverse::new(vec![class("a"), class("b"), class("c")]).unwrap();
    let a = class("a");
    let b = class("b");
    let c = class("c");
    let a_set = universe.class_set([&class("a")]).unwrap();
    let b_set = universe.class_set([&class("b")]).unwrap();
    let c_set = universe.class_set([&class("c")]).unwrap();
    let map =
        TaintEdgeFunction::transform(&universe, [(a, b_set.clone()), (b, c_set.clone())], true)
            .unwrap();
    let kill_b = TaintEdgeFunction::kill(&b_set);
    let composed = map.compose(&kill_b);
    assert!(composed.apply(&a_set).is_empty());
    assert!(universe.set_contains(&composed.apply(&b_set), &c).unwrap());
    let union = a_set.union(&b_set);
    assert_eq!(
        map.apply(&union),
        map.apply(&a_set).union(&map.apply(&b_set))
    );
    assert_eq!(map.meet(&kill_b), kill_b.meet(&map));
}

#[test]
fn edge_functions_reject_duplicate_sources_and_same_width_foreign_universes() {
    let universe = TaintUniverse::new(vec![class("a"), class("b")]).unwrap();
    let foreign = TaintUniverse::new(vec![class("x"), class("y")]).unwrap();
    let targets = universe.class_set([&class("b")]).unwrap();
    assert!(matches!(
        TaintEdgeFunction::transform(
            &universe,
            [(class("a"), targets.clone()), (class("a"), targets.clone()),],
            true,
        ),
        Err(brokk_bifrost::analyzer::taint::TaintSolveError::DuplicateTransformSource)
    ));
    assert!(matches!(
        TaintEdgeFunction::transform(
            &universe,
            [(class("a"), foreign.class_set([&class("x")]).unwrap())],
            true,
        ),
        Err(brokk_bifrost::analyzer::taint::TaintSolveError::UniverseMismatch)
    ));
    assert!(matches!(
        universe.set_contains(&foreign.empty_set(), &class("a")),
        Err(brokk_bifrost::analyzer::taint::TaintModelError::UniverseMismatch)
    ));
}

#[test]
fn three_sources_and_four_sinks_share_one_set_oriented_ide_solve() {
    let fixture = fixture(None);
    let result = solve(&fixture, WitnessRetentionLimits::new(1).unwrap());
    let report = collect_taint_findings(
        &fixture.plan,
        result,
        8,
        WitnessReconstructionLimits::default(),
    )
    .unwrap();
    assert_eq!(report.findings().len(), 4);
    for finding in report.findings() {
        assert_eq!(finding.classes(), &fixture.all_classes);
        assert!(finding.is_proven());
        assert_eq!(finding.origins().origins().len(), 3);
        assert!(finding.origins().is_complete());
    }
}

#[test]
fn resolved_sanitizer_removes_only_its_compatible_class() {
    let fixture = fixture(Some(true));
    let report = collect_taint_findings(
        &fixture.plan,
        solve(&fixture, WitnessRetentionLimits::disabled()),
        8,
        WitnessReconstructionLimits::default(),
    )
    .unwrap();
    for finding in report.findings() {
        assert!(
            !fixture
                .plan
                .universe()
                .set_contains(finding.classes(), &fixture.sanitized_class)
                .unwrap()
        );
        assert_eq!(finding.classes().len(), 2);
        assert!(finding.origins().witness_unavailable());
    }
}

#[test]
fn transformed_classes_retain_their_actual_source_origin() {
    let fixture = fixture_with_transfers(None, Some(0));
    let report = collect_taint_findings(
        &fixture.plan,
        solve(&fixture, WitnessRetentionLimits::new(1).unwrap()),
        8,
        WitnessReconstructionLimits::default(),
    )
    .unwrap();
    for finding in report.findings() {
        assert_eq!(finding.classes().len(), 2);
        assert_eq!(finding.origins().origins().len(), 3);
        assert!(finding.origins().is_complete());
    }
}

#[test]
fn sanitizer_and_transform_follow_their_explicit_event_order() {
    let transform_then_kill = fixture_with_transfers(Some((true, 1)), Some(0));
    let kill_then_transform = fixture_with_transfers(Some((true, 0)), Some(1));
    let first = collect_taint_findings(
        &transform_then_kill.plan,
        solve(&transform_then_kill, WitnessRetentionLimits::disabled()),
        8,
        WitnessReconstructionLimits::default(),
    )
    .unwrap();
    let second = collect_taint_findings(
        &kill_then_transform.plan,
        solve(&kill_then_transform, WitnessRetentionLimits::disabled()),
        8,
        WitnessReconstructionLimits::default(),
    )
    .unwrap();
    assert!(
        first
            .findings()
            .iter()
            .all(|finding| finding.classes().len() == 1)
    );
    assert!(
        second
            .findings()
            .iter()
            .all(|finding| finding.classes().len() == 2)
    );
}

#[test]
fn finding_collection_rejects_a_result_from_another_plan() {
    let first = fixture(None);
    let second = fixture(None);
    assert!(matches!(
        collect_taint_findings(
            &second.plan,
            solve(&first, WitnessRetentionLimits::disabled()),
            8,
            WitnessReconstructionLimits::default(),
        ),
        Err(brokk_bifrost::analyzer::taint::TaintFindingError::PlanMismatch)
    ));
}

#[test]
fn unresolved_sanitizer_preserves_taint_and_marks_the_result_incomplete() {
    let fixture = fixture(Some(false));
    let report = collect_taint_findings(
        &fixture.plan,
        solve(&fixture, WitnessRetentionLimits::disabled()),
        8,
        WitnessReconstructionLimits::default(),
    )
    .unwrap();
    assert!(!report.is_complete());
    for finding in report.findings() {
        assert_eq!(finding.classes(), &fixture.all_classes);
        assert!(!finding.is_proven());
    }
}

#[test]
fn batch_planner_groups_only_identical_propagation_semantics() {
    let fixture = fixture(None);
    let first = fixture.plan.clone();
    let second = fixture.plan.clone();
    let third = fixture.plan.clone();
    let key = TaintBatchCompatibilityKey::new(
        "snapshot",
        "context=2;heap=alloc-site;unknown=conservative",
        first.universe().hash(),
    )
    .unwrap();
    let other_key = TaintBatchCompatibilityKey::new(
        "snapshot",
        "context=1;heap=alloc-site;unknown=conservative",
        third.universe().hash(),
    )
    .unwrap();
    let batches = TaintBatchPlanner::partition(vec![
        TaintPolicyPlan::new("p2", key.clone(), second).unwrap(),
        TaintPolicyPlan::new("p1", key, first).unwrap(),
        TaintPolicyPlan::new("p3", other_key, third).unwrap(),
    ])
    .unwrap();
    assert_eq!(batches.len(), 2);
    assert!(batches.iter().any(|batch| batch.policy_ids().count() == 2));
    assert!(batches.iter().any(|batch| batch.policy_ids().count() == 1));
    let shared = batches
        .iter()
        .find(|batch| batch.policy_ids().count() == 2)
        .unwrap();
    assert_eq!(shared.projections().len(), 2);
    assert_eq!(
        shared
            .projections()
            .iter()
            .map(|projection| projection.policy_id())
            .collect::<Vec<_>>(),
        vec!["p1", "p2"]
    );
}
