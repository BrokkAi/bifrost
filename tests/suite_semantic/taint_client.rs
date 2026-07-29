use brokk_bifrost::analyzer::dataflow::{
    CuratedCallModel, DataflowRequest, ExternalSummaryContentHash, ExternalSummaryModelId,
    ProcedureSummaryIdentity, ProcedureSummaryKey, SemanticInputStatus, SemanticProcedureSummary,
    SolverBudget, SummaryBehaviorKey, SummaryCompleteness, SummaryContextKey, SummaryDependencyKey,
    SummaryEffect, SummaryEffectKey, SummaryEventKey, SummaryEvidence, SummaryExit,
    SummaryExitKind, SummaryOrigin, SummaryPort, SummaryRecursiveEdge, SummaryRecursiveGroupKey,
    SummarySchemaVersion, SummarySemanticsVersion, SummaryTransfer, UnmodeledCallBehavior,
    WitnessReconstructionLimits, WitnessRetentionLimits,
};
use brokk_bifrost::analyzer::semantic::{
    CallBinding, CallBindings, CancellationToken, CandidateCoverage, ControlContinuation,
    DispatchOracle, EvidenceCompleteness, OracleCallContext, OracleLimits, ProcedureHandle,
    ProcedureKind, ProofStatus, SemanticBudget, SemanticRequest, ValueFlowOracle,
    ValueFlowRelationKind, ValueFlowSnapshot,
};
use brokk_bifrost::analyzer::taint::{
    CompleteTaintTransferSummaryRepository, SourceClassId, SourceEventKey, TaintAnalysisPlan,
    TaintBatchCompatibilityKey, TaintBatchPlanner, TaintClassSet, TaintEdgeFunction,
    TaintPolicyPlan, TaintSanitizerBinding, TaintSemanticSummarySet, TaintSinkBinding,
    TaintSourceBinding, TaintTransferSummaryCacheStatus, TaintTransferSummaryRepositoryLimits,
    TaintTransformBinding, TaintUniverse, collect_taint_findings, solve_taint_batch_with_witnesses,
    solve_taint_with_reusable_summaries,
};
use brokk_bifrost::analyzer::value_flow::{
    ValueFlowCarrier, ValueFlowCuratedCallModel, ValueFlowEventKey, ValueFlowEventKind,
    ValueFlowInput, ValueFlowObservationPhase, ValueFlowPlan, ValueFlowSinkSpec,
    ValueFlowSourceSpec,
};
use brokk_bifrost::{AnalyzerConfig, Language};

use crate::common::{InlineTestProject, semantic_graph::SemanticGraph};

const SOURCE: &str = r#"
final class TaintFixture {
  static String run(String input) {
    String copy = input;
    return copy;
  }
}
"#;

const UNMODELED_TAINT_SOURCE: &str = r#"
interface ExternalTaintWork {
  String run(String value);
}

final class UnmodeledTaintFixture {
  static String caller(ExternalTaintWork work, String input) {
    return work.run(input);
  }
}
"#;

const REUSABLE_HELPER_SOURCE: &str = r#"
final class ReusableTaintFixture {
  static String helper(String input) {
    String copy = input;
    return copy;
  }

  static String callerOne(String input) {
    return helper(input);
  }

  static String callerTwo(String input) {
    return helper(input);
  }

  static String wrapper(String input) {
    return callerOne(input);
  }

  static String wrapperTwo(String input) {
    return callerOne(input);
  }
}
"#;

const RECURSIVE_TAINT_SOURCE: &str = r#"
final class RecursiveTaintFixture {
  static String direct(String input) {
    return direct(input);
  }

  static String left(String input) {
    return right(input);
  }

  static String right(String input) {
    return left(input);
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
    fixture_with_behavior(sanitizer, transform_index, UnmodeledCallBehavior::default())
}

fn fixture_with_behavior(
    sanitizer: Option<(bool, u32)>,
    transform_index: Option<u32>,
    unmodeled_call_behavior: UnmodeledCallBehavior,
) -> Fixture {
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
    let value_flow = ValueFlowPlan::with_call_behavior(
        root.clone(),
        vec![ValueFlowInput::new(snapshot, status)],
        Vec::new(),
        source_specs,
        sink_specs,
        unmodeled_call_behavior,
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
fn curated_external_call_flow_is_shared_with_taint_and_witness_replay() {
    let project = InlineTestProject::with_language(Language::Java)
        .file("src/UnmodeledTaintFixture.java", UNMODELED_TAINT_SOURCE)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let graph = SemanticGraph::materialize(&project, &analyzer, "src/UnmodeledTaintFixture.java");
    let root = procedure_named(&graph, "caller", ProcedureKind::Method);
    let call = root.semantics().call_sites().first().unwrap().clone();
    let invoke = root.point_handle(call.point).unwrap();
    let continuation = match call.normal_continuation {
        ControlContinuation::Target(point) => root.point_handle(point).unwrap(),
        ref other => panic!("expected normal continuation, got {other:?}"),
    };
    let input = root.value_handle(call.arguments[0].value).unwrap();
    let output = root.value_handle(call.result.unwrap()).unwrap();
    let source = ValueFlowSourceSpec::new(
        ValueFlowEventKey::at_point(&invoke, 0, ValueFlowEventKind::Source).unwrap(),
        invoke,
        ValueFlowObservationPhase::BeforeEffects,
        ValueFlowCarrier::Value(input),
        ProofStatus::Proven,
        EvidenceCompleteness::Complete,
    );
    let sink = ValueFlowSinkSpec::new(
        ValueFlowEventKey::at_point(&continuation, 0, ValueFlowEventKind::Sink).unwrap(),
        continuation,
        ValueFlowObservationPhase::BeforeEffects,
        ValueFlowCarrier::Value(output),
        ProofStatus::Proven,
        EvidenceCompleteness::Complete,
    );
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
    let status = SemanticInputStatus::from_outcome(&outcome);
    let snapshot = outcome.available_value().unwrap().clone();
    let transfer = SummaryTransfer::try_new(
        SummaryPort::Parameter(0),
        SummaryExit::try_new(SummaryExitKind::Normal, SummaryPort::NormalReturn).unwrap(),
        SummaryEvidence::proven_complete(),
    )
    .unwrap();
    let model = CuratedCallModel::try_new(
        ExternalSummaryModelId::new("test.taint-external-work").unwrap(),
        ExternalSummaryContentHash::hash_bytes(b"taint-parameter-0-to-return-v1"),
        vec![transfer],
    )
    .unwrap();
    let value_flow = ValueFlowPlan::with_call_behavior(
        root.clone(),
        vec![ValueFlowInput::new(snapshot, status)],
        Vec::new(),
        vec![source],
        vec![sink],
        UnmodeledCallBehavior::RequireModel,
    )
    .unwrap()
    .with_curated_call_models(vec![ValueFlowCuratedCallModel::new(
        root.call_site_handle(call.id).unwrap(),
        model,
    )])
    .unwrap();
    let universe = TaintUniverse::new(vec![class("sql")]).unwrap();
    let tainted = universe.class_set(universe.classes()).unwrap();
    let sources = value_flow
        .sources()
        .map(|(id, spec)| {
            TaintSourceBinding::new(id, tainted.clone(), SourceEventKey::new(spec.key().clone()))
        })
        .collect();
    let sinks = value_flow
        .sinks()
        .map(|(id, _)| TaintSinkBinding::new(id, tainted.clone()))
        .collect();
    let plan = TaintAnalysisPlan::new(value_flow, universe, sources, sinks, Vec::new(), Vec::new())
        .unwrap();
    let mut solver_budget = SolverBudget::default();
    let mut semantic_budget = SemanticBudget::default();
    let result = solve_taint_batch_with_witnesses(
        &root,
        &analyzer.icfg_provider(),
        &plan,
        WitnessRetentionLimits::new(2).unwrap(),
        &mut semantic_budget,
        &mut DataflowRequest::new(&mut solver_budget, &cancellation),
    )
    .unwrap();
    let report =
        collect_taint_findings(&plan, result, 2, WitnessReconstructionLimits::default()).unwrap();
    assert_eq!(report.findings().len(), 1);
    assert!(report.findings()[0].origins().is_complete());
}

fn reusable_semantic_identity(root: &ProcedureHandle) -> ProcedureSummaryIdentity {
    reusable_semantic_identity_with(
        root,
        SummaryContextKey::hash_bytes(b"root-context"),
        SummaryBehaviorKey::hash_bytes(b"symbolic-taint-transfer"),
    )
}

fn reusable_semantic_identity_with(
    root: &ProcedureHandle,
    context: SummaryContextKey,
    behavior: SummaryBehaviorKey,
) -> ProcedureSummaryIdentity {
    ProcedureSummaryIdentity::new(
        root.artifact().key().clone(),
        root.semantics().locator().declaration().clone(),
        SummarySchemaVersion::CURRENT,
        SummarySemanticsVersion::hash_bytes(b"taint-transfer-client-v1"),
        context,
        behavior,
        SummaryOrigin::Inferred,
    )
}

fn reusable_semantic_summary(
    root: &ProcedureHandle,
    dependencies: &[&SemanticProcedureSummary],
) -> SemanticProcedureSummary {
    reusable_semantic_summary_with_identity(root, dependencies, reusable_semantic_identity(root))
}

fn reusable_semantic_summary_with_identity(
    root: &ProcedureHandle,
    dependencies: &[&SemanticProcedureSummary],
    identity: ProcedureSummaryIdentity,
) -> SemanticProcedureSummary {
    let dependencies = dependencies
        .iter()
        .map(|summary| SummaryDependencyKey::complete(summary.key().clone()))
        .collect::<Vec<_>>();
    assert_eq!(
        identity.declaration(),
        root.semantics().locator().declaration()
    );
    let key = ProcedureSummaryKey::try_new(identity, &dependencies, None)
        .expect("taint reusable semantic key");
    let effects = dependencies
        .iter()
        .enumerate()
        .map(|(index, dependency)| {
            SummaryEffect::new(
                SummaryEffectKey::Call {
                    event: SummaryEventKey::hash_bytes(index.to_le_bytes()),
                    callee: Box::new(dependency.clone()),
                },
                SummaryEvidence::proven_complete(),
            )
        })
        .collect();
    SemanticProcedureSummary::try_new(
        key,
        Vec::new(),
        effects,
        dependencies,
        SummaryCompleteness::Complete,
    )
    .expect("taint reusable semantic summary")
}

fn recursive_semantic_summaries(
    procedures: &[ProcedureHandle],
    edges: &[(usize, usize)],
) -> Vec<SemanticProcedureSummary> {
    let identities = procedures
        .iter()
        .map(reusable_semantic_identity)
        .collect::<Vec<_>>();
    let topology = edges
        .iter()
        .map(|(source, target)| {
            SummaryRecursiveEdge::new(identities[*source].clone(), identities[*target].clone())
        })
        .collect::<Vec<_>>();
    let group = SummaryRecursiveGroupKey::from_closure(&identities, &topology, &[])
        .expect("recursive taint fixture is one SCC");
    procedures
        .iter()
        .enumerate()
        .map(|(index, _)| {
            let dependencies = edges
                .iter()
                .filter(|(source, _)| *source == index)
                .map(|(_, target)| SummaryDependencyKey::recursive(identities[*target].clone()))
                .collect::<Vec<_>>();
            let effects = edges
                .iter()
                .filter(|(source, _)| *source == index)
                .zip(dependencies.iter())
                .map(|((source, target), dependency)| {
                    SummaryEffect::new(
                        SummaryEffectKey::Call {
                            event: SummaryEventKey::hash_bytes([
                                u8::try_from(*source).unwrap(),
                                u8::try_from(*target).unwrap(),
                            ]),
                            callee: Box::new(dependency.clone()),
                        },
                        SummaryEvidence::proven_complete(),
                    )
                })
                .collect::<Vec<_>>();
            let key =
                ProcedureSummaryKey::try_new(identities[index].clone(), &dependencies, Some(group))
                    .expect("recursive taint semantic key");
            SemanticProcedureSummary::try_new(
                key,
                Vec::new(),
                effects,
                dependencies,
                SummaryCompleteness::Complete,
            )
            .expect("recursive taint semantic summary")
        })
        .collect()
}

fn recursive_taint_plan(
    analyzer: &brokk_bifrost::WorkspaceAnalyzer,
    root: &ProcedureHandle,
    procedures: &[ProcedureHandle],
) -> TaintAnalysisPlan {
    recursive_taint_plan_with_sanitizer(analyzer, root, procedures, None)
}

fn recursive_taint_plan_with_sanitizer(
    analyzer: &brokk_bifrost::WorkspaceAnalyzer,
    root: &ProcedureHandle,
    procedures: &[ProcedureHandle],
    sanitizer_procedure: Option<&ProcedureHandle>,
) -> TaintAnalysisPlan {
    let cancellation = CancellationToken::default();
    let mut semantic_budget = SemanticBudget::default();
    let oracle = analyzer.semantic_oracle_provider();
    let mut snapshots = Vec::new();
    let mut bindings = Vec::new();
    for procedure in procedures {
        let outcome = oracle
            .procedure_relations(
                procedure,
                &OracleCallContext::empty(),
                &mut SemanticRequest::new(&mut semantic_budget, &cancellation),
            )
            .expect("recursive value-flow snapshot");
        let snapshot = outcome
            .available_value()
            .expect("available recursive snapshot");
        snapshots.push(ValueFlowInput::new(
            ValueFlowSnapshot::new(
                procedure.clone(),
                OracleCallContext::empty(),
                snapshot.relations().to_vec(),
                CandidateCoverage::Exhaustive,
                OracleLimits::default(),
            )
            .expect("exhaustive recursive snapshot"),
            SemanticInputStatus::Complete,
        ));
        for call_row in procedure.semantics().call_sites() {
            let call = procedure
                .call_site_handle(call_row.id)
                .expect("live recursive call");
            let dispatch = oracle
                .resolve_call(
                    &call,
                    &mut SemanticRequest::new(&mut semantic_budget, &cancellation),
                )
                .expect("recursive dispatch");
            let candidate = dispatch
                .available_value()
                .expect("available recursive dispatch")
                .candidates()
                .iter()
                .find(|candidate| procedures.contains(candidate.target()))
                .expect("recursive target")
                .clone();
            let outcome = oracle
                .call_bindings(
                    &call,
                    &candidate,
                    &OracleCallContext::empty(),
                    &mut SemanticRequest::new(&mut semantic_budget, &cancellation),
                )
                .expect("recursive bindings");
            let live = outcome
                .available_value()
                .expect("available recursive bindings");
            bindings.push(ValueFlowInput::new(
                CallBindings::new(
                    call,
                    &candidate,
                    OracleCallContext::empty(),
                    live.bindings().to_vec(),
                    CandidateCoverage::Exhaustive,
                    OracleLimits::default(),
                )
                .expect("exhaustive recursive bindings"),
                SemanticInputStatus::Complete,
            ));
        }
    }
    let sanitizer_port = sanitizer_procedure.and_then(|target| {
        snapshots
            .iter()
            .find(|snapshot| snapshot.value().procedure() == target)
            .and_then(|snapshot| snapshot.value().relations().first())
            .map(|relation| {
                (
                    relation.point().clone(),
                    ValueFlowCarrier::from(&relation.target),
                )
            })
    });
    let value_flow =
        ValueFlowPlan::try_new(root.clone(), snapshots, bindings, Vec::new(), Vec::new())
            .expect("recursive value-flow plan");
    let universe = TaintUniverse::new(vec![class("sql")]).unwrap();
    let sanitizers = sanitizer_port
        .map(|(point, carrier)| {
            TaintSanitizerBinding::resolved(
                point,
                ValueFlowObservationPhase::AfterEffects,
                0,
                value_flow
                    .carrier_id(&carrier)
                    .expect("recursive sanitizer carrier"),
                universe.class_set([&class("sql")]).unwrap(),
            )
        })
        .into_iter()
        .collect();
    TaintAnalysisPlan::new(
        value_flow,
        universe,
        Vec::new(),
        Vec::new(),
        sanitizers,
        Vec::new(),
    )
    .expect("recursive taint plan")
}

fn reusable_helper_plan(
    analyzer: &brokk_bifrost::WorkspaceAnalyzer,
    root: &ProcedureHandle,
    helper: &ProcedureHandle,
    sink_accepts_all: bool,
) -> TaintAnalysisPlan {
    reusable_helper_plan_with_changes(analyzer, root, helper, sink_accepts_all, "sql", 0, false)
}

#[allow(clippy::too_many_arguments)]
fn reusable_helper_plan_with_changes(
    analyzer: &brokk_bifrost::WorkspaceAnalyzer,
    root: &ProcedureHandle,
    helper: &ProcedureHandle,
    sink_accepts_all: bool,
    source_class: &str,
    sink_ordinal: u32,
    sanitizer: bool,
) -> TaintAnalysisPlan {
    reusable_chain_plan_with_changes(
        analyzer,
        root,
        &[helper],
        helper,
        sink_accepts_all,
        source_class,
        sink_ordinal,
        sanitizer,
        false,
        ReusableSinkPlacement::HelperAssignment,
    )
}

#[derive(Clone, Copy)]
enum ReusableSinkPlacement {
    HelperAssignment,
    CallerCall,
    HelperExit,
}

#[allow(clippy::too_many_arguments)]
fn reusable_chain_plan_with_changes(
    analyzer: &brokk_bifrost::WorkspaceAnalyzer,
    root: &ProcedureHandle,
    callees: &[&ProcedureHandle],
    helper: &ProcedureHandle,
    sink_accepts_all: bool,
    source_class: &str,
    sink_ordinal: u32,
    sanitizer: bool,
    source_in_root: bool,
    sink_placement: ReusableSinkPlacement,
) -> TaintAnalysisPlan {
    let cancellation = CancellationToken::default();
    let mut semantic_budget = SemanticBudget::default();
    let oracle = analyzer.semantic_oracle_provider();
    let mut bindings = Vec::new();
    let mut caller = root;
    for callee in callees {
        let call = caller
            .call_site_handle(
                caller
                    .semantics()
                    .call_sites()
                    .first()
                    .expect("chain call")
                    .id,
            )
            .expect("live chain call");
        let dispatch = oracle
            .resolve_call(
                &call,
                &mut SemanticRequest::new(&mut semantic_budget, &cancellation),
            )
            .expect("chain dispatch");
        let candidate = dispatch
            .available_value()
            .expect("available chain dispatch")
            .candidates()
            .iter()
            .find(|candidate| candidate.target() == *callee)
            .expect("resolved chain target")
            .clone();
        let outcome = oracle
            .call_bindings(
                &call,
                &candidate,
                &OracleCallContext::empty(),
                &mut SemanticRequest::new(&mut semantic_budget, &cancellation),
            )
            .expect("chain bindings");
        let live = outcome.available_value().expect("available chain bindings");
        bindings.push(ValueFlowInput::new(
            CallBindings::new(
                call,
                &candidate,
                OracleCallContext::empty(),
                live.bindings().to_vec(),
                CandidateCoverage::Exhaustive,
                OracleLimits::default(),
            )
            .expect("exhaustive chain bindings"),
            SemanticInputStatus::Complete,
        ));
        caller = callee;
    }

    let mut snapshots = Vec::new();
    for procedure in std::iter::once(root).chain(callees.iter().copied()) {
        let outcome = oracle
            .procedure_relations(
                procedure,
                &OracleCallContext::empty(),
                &mut SemanticRequest::new(&mut semantic_budget, &cancellation),
            )
            .expect("helper value-flow snapshot");
        let snapshot = outcome.available_value().expect("available snapshot");
        snapshots.push(ValueFlowInput::new(
            ValueFlowSnapshot::new(
                procedure.clone(),
                OracleCallContext::empty(),
                snapshot.relations().to_vec(),
                CandidateCoverage::Exhaustive,
                OracleLimits::default(),
            )
            .expect("exhaustive helper snapshot"),
            SemanticInputStatus::Complete,
        ));
    }
    let helper_snapshot = snapshots
        .iter()
        .find(|snapshot| snapshot.value().procedure() == helper)
        .expect("helper snapshot")
        .value();
    let assignment = helper_snapshot
        .relations()
        .iter()
        .find(|relation| relation.kind == ValueFlowRelationKind::Assignment)
        .expect("helper assignment");
    let (source_point, source_carrier) = if source_in_root {
        let first = bindings.first().expect("root-to-callee bindings").value();
        let actual = first
            .bindings()
            .iter()
            .find_map(|binding| match binding {
                CallBinding::ArgumentGroup(group) => group
                    .mappings()
                    .first()
                    .map(|mapping| mapping.value().actual().value().clone()),
                _ => None,
            })
            .expect("root argument binding");
        let call = first
            .call()
            .procedure()
            .semantics()
            .call_site(first.call().id())
            .expect("root call semantics");
        (
            first
                .call()
                .procedure()
                .point_handle(call.point)
                .expect("root call point"),
            ValueFlowCarrier::Value(actual),
        )
    } else {
        (
            assignment.point().clone(),
            ValueFlowCarrier::from(&assignment.source),
        )
    };
    let source = ValueFlowSourceSpec::new(
        ValueFlowEventKey::at_point(&source_point, 0, ValueFlowEventKind::Source)
            .expect("source key"),
        source_point,
        ValueFlowObservationPhase::BeforeEffects,
        source_carrier,
        ProofStatus::Proven,
        EvidenceCompleteness::Complete,
    );
    let (sink_point, sink_phase, sink_carrier) = match sink_placement {
        ReusableSinkPlacement::HelperAssignment => (
            assignment.point().clone(),
            ValueFlowObservationPhase::AfterEffects,
            ValueFlowCarrier::from(&assignment.target),
        ),
        ReusableSinkPlacement::CallerCall => {
            let call = bindings.last().expect("caller-to-helper binding").value();
            let actual = call
                .bindings()
                .iter()
                .find_map(|binding| match binding {
                    CallBinding::ArgumentGroup(group) => group
                        .mappings()
                        .first()
                        .map(|mapping| mapping.value().actual().value().clone()),
                    _ => None,
                })
                .expect("caller-to-helper actual");
            let call_point = call
                .call()
                .procedure()
                .semantics()
                .call_site(call.call().id())
                .expect("caller call semantics")
                .point;
            let point = call
                .call()
                .procedure()
                .point_handle(call_point)
                .expect("caller call point");
            (
                point,
                ValueFlowObservationPhase::BeforeEffects,
                ValueFlowCarrier::Value(actual),
            )
        }
        ReusableSinkPlacement::HelperExit => (
            helper
                .point_handle(helper.semantics().normal_exit_point())
                .expect("helper normal exit"),
            ValueFlowObservationPhase::BeforeEffects,
            ValueFlowCarrier::from(&assignment.target),
        ),
    };
    let sink = ValueFlowSinkSpec::new(
        ValueFlowEventKey::at_point(&sink_point, sink_ordinal, ValueFlowEventKind::Sink)
            .expect("sink key"),
        sink_point,
        sink_phase,
        sink_carrier,
        ProofStatus::Proven,
        EvidenceCompleteness::Complete,
    );
    let sanitizer_point = assignment.point().clone();
    let sanitizer_carrier = ValueFlowCarrier::from(&assignment.target);
    let value_flow =
        ValueFlowPlan::try_new(root.clone(), snapshots, bindings, vec![source], vec![sink])
            .expect("helper value-flow plan");
    let universe = TaintUniverse::new(vec![class("sql"), class("path")]).unwrap();
    let generated = universe.class_set([&class(source_class)]).unwrap();
    let accepted = if sink_accepts_all {
        universe.class_set(universe.classes()).unwrap()
    } else {
        generated.clone()
    };
    let source_binding = value_flow
        .sources()
        .map(|(id, spec)| {
            TaintSourceBinding::new(
                id,
                generated.clone(),
                SourceEventKey::new(spec.key().clone()),
            )
        })
        .collect();
    let sink_binding = value_flow
        .sinks()
        .map(|(id, _)| TaintSinkBinding::new(id, accepted.clone()))
        .collect();
    let sanitizer_bindings = sanitizer
        .then(|| {
            let carrier = value_flow
                .carrier_id(&sanitizer_carrier)
                .expect("helper sanitizer carrier");
            TaintSanitizerBinding::resolved(
                sanitizer_point,
                ValueFlowObservationPhase::AfterEffects,
                0,
                carrier,
                generated.clone(),
            )
        })
        .into_iter()
        .collect();
    TaintAnalysisPlan::new(
        value_flow,
        universe,
        source_binding,
        sink_binding,
        sanitizer_bindings,
        Vec::new(),
    )
    .expect("helper taint plan")
}

fn solve_reusable_taint(
    analyzer: &brokk_bifrost::WorkspaceAnalyzer,
    root: &ProcedureHandle,
    plan: &TaintAnalysisPlan,
    semantic_summaries: &TaintSemanticSummarySet<'_>,
    repository: &mut CompleteTaintTransferSummaryRepository,
) -> brokk_bifrost::analyzer::taint::TaintTransferSummarySolveResult {
    let cancellation = CancellationToken::default();
    let mut solver_budget = SolverBudget::default();
    let mut semantic_budget = SemanticBudget::default();
    solve_taint_with_reusable_summaries(
        root,
        &analyzer.icfg_provider(),
        plan,
        semantic_summaries,
        repository,
        &mut semantic_budget,
        &mut DataflowRequest::new(&mut solver_budget, &cancellation),
    )
    .expect("reusable taint solve")
}

#[test]
fn two_callers_reuse_internal_helper_transfer_across_sink_acceptance_change() {
    let project = InlineTestProject::with_language(Language::Java)
        .file("src/ReusableTaintFixture.java", REUSABLE_HELPER_SOURCE)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let graph = SemanticGraph::materialize(&project, &analyzer, "src/ReusableTaintFixture.java");
    let helper = procedure_named(&graph, "helper", ProcedureKind::Method);
    let caller_one = procedure_named(&graph, "callerOne", ProcedureKind::Method);
    let caller_two = procedure_named(&graph, "callerTwo", ProcedureKind::Method);
    let helper_semantic = reusable_semantic_summary(&helper, &[]);
    let caller_one_semantic = reusable_semantic_summary(&caller_one, &[&helper_semantic]);
    let caller_two_semantic = reusable_semantic_summary(&caller_two, &[&helper_semantic]);
    let first_plan = reusable_helper_plan(&analyzer, &caller_one, &helper, true);
    let second_plan = reusable_helper_plan(&analyzer, &caller_two, &helper, false);
    let mut repository = CompleteTaintTransferSummaryRepository::default();

    let first_set =
        TaintSemanticSummarySet::try_new(vec![&helper_semantic, &caller_one_semantic]).unwrap();
    let cancellation = CancellationToken::default();
    let mut solver_budget = SolverBudget::default();
    let mut semantic_budget = SemanticBudget::default();
    let first = solve_taint_with_reusable_summaries(
        &caller_one,
        &analyzer.icfg_provider(),
        &first_plan,
        &first_set,
        &mut repository,
        &mut semantic_budget,
        &mut DataflowRequest::new(&mut solver_budget, &cancellation),
    )
    .expect("first caller solve");
    assert!(!first.was_reused());
    assert_eq!(
        first.cache_status(),
        TaintTransferSummaryCacheStatus::Published,
        "termination={:?} coverage={:?}",
        first.computed_result().termination(),
        first.computed_result().coverage(),
    );
    assert_eq!(
        repository.len(),
        2,
        "the helper and its dependency-closed caller both publish"
    );
    let helper_summary = repository
        .keys()
        .find(|key| key.carrier().procedure() == helper_semantic.key())
        .and_then(|key| repository.get(key))
        .expect("published helper summary");
    assert!(
        helper_summary
            .observations()
            .iter()
            .any(|row| row.point() == helper.semantics().entry_point())
    );
    assert!(
        helper_summary
            .observations()
            .iter()
            .any(|row| row.point() == helper.semantics().normal_exit_point()),
        "entry and exit ports must retain distinct point identities even when their source locator is shared"
    );

    let second_set =
        TaintSemanticSummarySet::try_new(vec![&helper_semantic, &caller_two_semantic]).unwrap();
    let cancellation = CancellationToken::default();
    let mut solver_budget = SolverBudget::default();
    let mut semantic_budget = SemanticBudget::default();
    let reused = solve_taint_with_reusable_summaries(
        &caller_two,
        &analyzer.icfg_provider(),
        &second_plan,
        &second_set,
        &mut repository,
        &mut semantic_budget,
        &mut DataflowRequest::new(&mut solver_budget, &cancellation),
    )
    .expect("second caller solve");
    assert!(
        reused.was_reused(),
        "the helper transfer should be injected"
    );

    let cancellation = CancellationToken::default();
    let mut solver_budget = SolverBudget::default();
    let mut semantic_budget = SemanticBudget::default();
    let uncached = brokk_bifrost::analyzer::taint::solve_taint_batch_with_summaries(
        &caller_two,
        &analyzer.icfg_provider(),
        &second_plan,
        &mut semantic_budget,
        &mut DataflowRequest::new(&mut solver_budget, &cancellation),
    )
    .expect("uncached parity solve");
    let reused_report = collect_taint_findings(
        &second_plan,
        reused.into_computed_result(),
        8,
        WitnessReconstructionLimits::default(),
    )
    .unwrap();
    let uncached_report = collect_taint_findings(
        &second_plan,
        uncached,
        8,
        WitnessReconstructionLimits::default(),
    )
    .unwrap();
    assert!(!reused_report.findings().is_empty());
    assert_eq!(reused_report.findings(), uncached_report.findings());
}

#[test]
fn wrapper_reuses_dependency_bearing_caller_with_transitive_sink_observations() {
    let project = InlineTestProject::with_language(Language::Java)
        .file("src/ReusableTaintFixture.java", REUSABLE_HELPER_SOURCE)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let graph = SemanticGraph::materialize(&project, &analyzer, "src/ReusableTaintFixture.java");
    let helper = procedure_named(&graph, "helper", ProcedureKind::Method);
    let caller = procedure_named(&graph, "callerOne", ProcedureKind::Method);
    let wrapper = procedure_named(&graph, "wrapper", ProcedureKind::Method);
    let wrapper_two = procedure_named(&graph, "wrapperTwo", ProcedureKind::Method);
    let helper_semantic = reusable_semantic_summary(&helper, &[]);
    let caller_semantic = reusable_semantic_summary(&caller, &[&helper_semantic]);
    let wrapper_semantic = reusable_semantic_summary(&wrapper, &[&caller_semantic]);
    let wrapper_two_semantic = reusable_semantic_summary(&wrapper_two, &[&caller_semantic]);
    let first_set = TaintSemanticSummarySet::try_new(vec![
        &helper_semantic,
        &caller_semantic,
        &wrapper_semantic,
    ])
    .unwrap();
    let first_plan = reusable_chain_plan_with_changes(
        &analyzer,
        &wrapper,
        &[&caller, &helper],
        &helper,
        true,
        "sql",
        0,
        false,
        true,
        ReusableSinkPlacement::HelperAssignment,
    );
    let mut repository = CompleteTaintTransferSummaryRepository::default();
    let first = solve_reusable_taint(
        &analyzer,
        &wrapper,
        &first_plan,
        &first_set,
        &mut repository,
    );
    assert!(!first.was_reused());
    assert_eq!(repository.len(), 3);

    let wrapper_set = TaintSemanticSummarySet::try_new(vec![
        &helper_semantic,
        &caller_semantic,
        &wrapper_two_semantic,
    ])
    .unwrap();
    let wrapper_plan = reusable_chain_plan_with_changes(
        &analyzer,
        &wrapper_two,
        &[&caller, &helper],
        &helper,
        true,
        "sql",
        1,
        false,
        true,
        ReusableSinkPlacement::HelperAssignment,
    );
    let reused = solve_reusable_taint(
        &analyzer,
        &wrapper_two,
        &wrapper_plan,
        &wrapper_set,
        &mut repository,
    );
    assert!(reused.was_reused());
    assert_eq!(repository.len(), 4);

    let cancellation = CancellationToken::default();
    let mut solver_budget = SolverBudget::default();
    let mut semantic_budget = SemanticBudget::default();
    let uncached = brokk_bifrost::analyzer::taint::solve_taint_batch_with_summaries(
        &wrapper_two,
        &analyzer.icfg_provider(),
        &wrapper_plan,
        &mut semantic_budget,
        &mut DataflowRequest::new(&mut solver_budget, &cancellation),
    )
    .expect("uncached wrapper parity solve");
    let reused_report = collect_taint_findings(
        &wrapper_plan,
        reused.into_computed_result(),
        8,
        WitnessReconstructionLimits::default(),
    )
    .unwrap();
    let uncached_report = collect_taint_findings(
        &wrapper_plan,
        uncached,
        8,
        WitnessReconstructionLimits::default(),
    )
    .unwrap();
    assert!(!reused_report.findings().is_empty());
    let finding_entry = reused_report.findings()[0].entry();
    assert_eq!(finding_entry.procedure(), &helper);
    let finding_carrier = wrapper_plan
        .value_flow()
        .carrier_key(
            finding_entry
                .fact()
                .carrier()
                .expect("helper finding has a formal carrier entry"),
        )
        .expect("stable helper entry carrier");
    let source_carrier = wrapper_plan
        .value_flow()
        .sources()
        .next()
        .expect("wrapper source")
        .1
        .carrier()
        .stable_key()
        .expect("stable wrapper actual carrier");
    assert_ne!(
        finding_carrier, &source_carrier,
        "the cached finding must retain the helper formal rather than the wrapper actual"
    );
    assert_eq!(reused_report.findings(), uncached_report.findings());
}

fn assert_interprocedural_sink_entry_parity(placement: ReusableSinkPlacement) {
    let project = InlineTestProject::with_language(Language::Java)
        .file("src/ReusableTaintFixture.java", REUSABLE_HELPER_SOURCE)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let graph = SemanticGraph::materialize(&project, &analyzer, "src/ReusableTaintFixture.java");
    let helper = procedure_named(&graph, "helper", ProcedureKind::Method);
    let caller = procedure_named(&graph, "callerOne", ProcedureKind::Method);
    let wrapper = procedure_named(&graph, "wrapper", ProcedureKind::Method);
    let wrapper_two = procedure_named(&graph, "wrapperTwo", ProcedureKind::Method);
    let helper_semantic = reusable_semantic_summary(&helper, &[]);
    let caller_semantic = reusable_semantic_summary(&caller, &[&helper_semantic]);
    let wrapper_semantic = reusable_semantic_summary(&wrapper, &[&caller_semantic]);
    let wrapper_two_semantic = reusable_semantic_summary(&wrapper_two, &[&caller_semantic]);
    let first_set = TaintSemanticSummarySet::try_new(vec![
        &helper_semantic,
        &caller_semantic,
        &wrapper_semantic,
    ])
    .unwrap();
    let first_plan = reusable_chain_plan_with_changes(
        &analyzer,
        &wrapper,
        &[&caller, &helper],
        &helper,
        true,
        "sql",
        0,
        false,
        true,
        placement,
    );
    let mut repository = CompleteTaintTransferSummaryRepository::default();
    let first = solve_reusable_taint(
        &analyzer,
        &wrapper,
        &first_plan,
        &first_set,
        &mut repository,
    );
    assert!(!first.was_reused());

    let second_set = TaintSemanticSummarySet::try_new(vec![
        &helper_semantic,
        &caller_semantic,
        &wrapper_two_semantic,
    ])
    .unwrap();
    let second_plan = reusable_chain_plan_with_changes(
        &analyzer,
        &wrapper_two,
        &[&caller, &helper],
        &helper,
        true,
        "sql",
        1,
        false,
        true,
        placement,
    );
    let reused = solve_reusable_taint(
        &analyzer,
        &wrapper_two,
        &second_plan,
        &second_set,
        &mut repository,
    );
    assert!(reused.was_reused());

    let cancellation = CancellationToken::default();
    let mut solver_budget = SolverBudget::default();
    let mut semantic_budget = SemanticBudget::default();
    let uncached = brokk_bifrost::analyzer::taint::solve_taint_batch_with_summaries(
        &wrapper_two,
        &analyzer.icfg_provider(),
        &second_plan,
        &mut semantic_budget,
        &mut DataflowRequest::new(&mut solver_budget, &cancellation),
    )
    .expect("uncached interprocedural sink parity solve");
    let reused_report = collect_taint_findings(
        &second_plan,
        reused.into_computed_result(),
        8,
        WitnessReconstructionLimits::default(),
    )
    .unwrap();
    let uncached_report = collect_taint_findings(
        &second_plan,
        uncached,
        8,
        WitnessReconstructionLimits::default(),
    )
    .unwrap();
    assert!(!reused_report.findings().is_empty());
    let expected_owner = match placement {
        ReusableSinkPlacement::CallerCall => &caller,
        ReusableSinkPlacement::HelperExit => &helper,
        ReusableSinkPlacement::HelperAssignment => unreachable!("boundary placement required"),
    };
    assert!(
        reused_report
            .findings()
            .iter()
            .all(|finding| finding.entry().procedure() == expected_owner)
    );
    assert_eq!(reused_report.findings(), uncached_report.findings());
}

#[test]
fn cached_call_site_sink_retains_the_caller_entry() {
    assert_interprocedural_sink_entry_parity(ReusableSinkPlacement::CallerCall);
}

#[test]
fn cached_callee_exit_sink_retains_the_callee_entry() {
    assert_interprocedural_sink_entry_parity(ReusableSinkPlacement::HelperExit);
}

#[test]
fn propagation_changes_miss_without_overwriting_the_prior_transfer() {
    let project = InlineTestProject::with_language(Language::Java)
        .file("src/ReusableTaintFixture.java", REUSABLE_HELPER_SOURCE)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let graph = SemanticGraph::materialize(&project, &analyzer, "src/ReusableTaintFixture.java");
    let helper = procedure_named(&graph, "helper", ProcedureKind::Method);
    let caller_one = procedure_named(&graph, "callerOne", ProcedureKind::Method);
    let caller_two = procedure_named(&graph, "callerTwo", ProcedureKind::Method);
    let helper_semantic = reusable_semantic_summary(&helper, &[]);
    let caller_one_semantic = reusable_semantic_summary(&caller_one, &[&helper_semantic]);
    let caller_two_semantic = reusable_semantic_summary(&caller_two, &[&helper_semantic]);
    let first_set =
        TaintSemanticSummarySet::try_new(vec![&helper_semantic, &caller_one_semantic]).unwrap();
    let second_set =
        TaintSemanticSummarySet::try_new(vec![&helper_semantic, &caller_two_semantic]).unwrap();
    let first_plan =
        reusable_helper_plan_with_changes(&analyzer, &caller_one, &helper, true, "sql", 0, false);
    let changed_source_plan =
        reusable_helper_plan_with_changes(&analyzer, &caller_two, &helper, true, "path", 0, false);
    let changed_sanitizer_plan =
        reusable_helper_plan_with_changes(&analyzer, &caller_two, &helper, true, "sql", 0, true);
    let mut repository = CompleteTaintTransferSummaryRepository::default();

    let first = solve_reusable_taint(
        &analyzer,
        &caller_one,
        &first_plan,
        &first_set,
        &mut repository,
    );
    assert_eq!(
        first.cache_status(),
        TaintTransferSummaryCacheStatus::Published
    );
    let changed_source = solve_reusable_taint(
        &analyzer,
        &caller_two,
        &changed_source_plan,
        &second_set,
        &mut repository,
    );
    assert!(!changed_source.was_reused());
    assert_eq!(repository.len(), 4);

    let changed_sanitizer = solve_reusable_taint(
        &analyzer,
        &caller_two,
        &changed_sanitizer_plan,
        &second_set,
        &mut repository,
    );
    assert!(!changed_sanitizer.was_reused());
    assert_eq!(repository.len(), 6);
}

#[test]
fn context_and_execution_semantics_changes_miss_the_transfer() {
    let project = InlineTestProject::with_language(Language::Java)
        .file("src/ReusableTaintFixture.java", REUSABLE_HELPER_SOURCE)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let graph = SemanticGraph::materialize(&project, &analyzer, "src/ReusableTaintFixture.java");
    let helper = procedure_named(&graph, "helper", ProcedureKind::Method);
    let caller_one = procedure_named(&graph, "callerOne", ProcedureKind::Method);
    let caller_two = procedure_named(&graph, "callerTwo", ProcedureKind::Method);
    let original_helper = reusable_semantic_summary(&helper, &[]);
    let original_caller = reusable_semantic_summary(&caller_one, &[&original_helper]);
    let original_set =
        TaintSemanticSummarySet::try_new(vec![&original_helper, &original_caller]).unwrap();
    let first_plan = reusable_helper_plan(&analyzer, &caller_one, &helper, true);
    let second_plan = reusable_helper_plan(&analyzer, &caller_two, &helper, true);
    let mut repository = CompleteTaintTransferSummaryRepository::default();
    solve_reusable_taint(
        &analyzer,
        &caller_one,
        &first_plan,
        &original_set,
        &mut repository,
    );

    let changed_context_helper = reusable_semantic_summary_with_identity(
        &helper,
        &[],
        reusable_semantic_identity_with(
            &helper,
            SummaryContextKey::hash_bytes(b"different-access-path-context"),
            SummaryBehaviorKey::hash_bytes(b"symbolic-taint-transfer"),
        ),
    );
    let changed_context_caller = reusable_semantic_summary(&caller_two, &[&changed_context_helper]);
    let changed_context_set =
        TaintSemanticSummarySet::try_new(vec![&changed_context_helper, &changed_context_caller])
            .unwrap();
    let changed_context = solve_reusable_taint(
        &analyzer,
        &caller_two,
        &second_plan,
        &changed_context_set,
        &mut repository,
    );
    assert!(!changed_context.was_reused());
    assert_eq!(repository.len(), 4);

    let changed_behavior_helper = reusable_semantic_summary_with_identity(
        &helper,
        &[],
        reusable_semantic_identity_with(
            &helper,
            SummaryContextKey::hash_bytes(b"root-context"),
            SummaryBehaviorKey::hash_bytes(b"different-escape-or-unknown-call-semantics"),
        ),
    );
    let changed_behavior_caller =
        reusable_semantic_summary(&caller_two, &[&changed_behavior_helper]);
    let changed_behavior_set =
        TaintSemanticSummarySet::try_new(vec![&changed_behavior_helper, &changed_behavior_caller])
            .unwrap();
    let changed_behavior = solve_reusable_taint(
        &analyzer,
        &caller_two,
        &second_plan,
        &changed_behavior_set,
        &mut repository,
    );
    assert!(!changed_behavior.was_reused());
    assert_eq!(repository.len(), 6);
}

#[test]
fn sink_selector_is_a_separate_overlay_and_never_replaces_transfer_state() {
    let project = InlineTestProject::with_language(Language::Java)
        .file("src/ReusableTaintFixture.java", REUSABLE_HELPER_SOURCE)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let graph = SemanticGraph::materialize(&project, &analyzer, "src/ReusableTaintFixture.java");
    let helper = procedure_named(&graph, "helper", ProcedureKind::Method);
    let caller_one = procedure_named(&graph, "callerOne", ProcedureKind::Method);
    let caller_two = procedure_named(&graph, "callerTwo", ProcedureKind::Method);
    let helper_semantic = reusable_semantic_summary(&helper, &[]);
    let caller_one_semantic = reusable_semantic_summary(&caller_one, &[&helper_semantic]);
    let caller_two_semantic = reusable_semantic_summary(&caller_two, &[&helper_semantic]);
    let first_set =
        TaintSemanticSummarySet::try_new(vec![&helper_semantic, &caller_one_semantic]).unwrap();
    let second_set =
        TaintSemanticSummarySet::try_new(vec![&helper_semantic, &caller_two_semantic]).unwrap();
    let first_plan =
        reusable_helper_plan_with_changes(&analyzer, &caller_one, &helper, true, "sql", 0, false);
    let changed_sink_plan =
        reusable_helper_plan_with_changes(&analyzer, &caller_two, &helper, true, "sql", 1, false);
    let mut repository = CompleteTaintTransferSummaryRepository::default();
    solve_reusable_taint(
        &analyzer,
        &caller_one,
        &first_plan,
        &first_set,
        &mut repository,
    );
    let retained_key = repository
        .keys()
        .find(|key| key.carrier().procedure() == helper_semantic.key())
        .unwrap()
        .clone();

    let changed = solve_reusable_taint(
        &analyzer,
        &caller_two,
        &changed_sink_plan,
        &second_set,
        &mut repository,
    );
    assert!(changed.was_reused());
    assert_eq!(
        changed.cache_status(),
        TaintTransferSummaryCacheStatus::Published
    );
    assert_eq!(repository.len(), 3);
    assert!(repository.get(&retained_key).is_some());

    let cancellation = CancellationToken::default();
    let mut solver_budget = SolverBudget::default();
    let mut semantic_budget = SemanticBudget::default();
    let uncached = brokk_bifrost::analyzer::taint::solve_taint_batch_with_summaries(
        &caller_two,
        &analyzer.icfg_provider(),
        &changed_sink_plan,
        &mut semantic_budget,
        &mut DataflowRequest::new(&mut solver_budget, &cancellation),
    )
    .expect("uncached changed-sink solve");
    let reused_report = collect_taint_findings(
        &changed_sink_plan,
        changed.into_computed_result(),
        8,
        WitnessReconstructionLimits::default(),
    )
    .unwrap();
    let uncached_report = collect_taint_findings(
        &changed_sink_plan,
        uncached,
        8,
        WitnessReconstructionLimits::default(),
    )
    .unwrap();
    assert!(!reused_report.findings().is_empty());
    assert_eq!(reused_report.findings(), uncached_report.findings());
}

#[test]
fn incomplete_taint_solve_never_publishes_a_transfer() {
    let fixture = fixture(Some(false));
    let semantic = reusable_semantic_summary(&fixture.root, &[]);
    let summaries = TaintSemanticSummarySet::try_new(vec![&semantic]).unwrap();
    let mut repository = CompleteTaintTransferSummaryRepository::default();
    let result = solve_reusable_taint(
        &fixture.analyzer,
        &fixture.root,
        &fixture.plan,
        &summaries,
        &mut repository,
    );
    assert_eq!(
        result.cache_status(),
        TaintTransferSummaryCacheStatus::Incomplete
    );
    assert!(repository.is_empty());
}

#[test]
fn cancelled_taint_solve_never_publishes_a_transfer() {
    let fixture = fixture(None);
    let semantic = reusable_semantic_summary(&fixture.root, &[]);
    let summaries = TaintSemanticSummarySet::try_new(vec![&semantic]).unwrap();
    let mut repository = CompleteTaintTransferSummaryRepository::default();
    let cancellation = CancellationToken::default();
    cancellation.cancel();
    let mut solver_budget = SolverBudget::default();
    let mut semantic_budget = SemanticBudget::default();
    let result = solve_taint_with_reusable_summaries(
        &fixture.root,
        &fixture.analyzer.icfg_provider(),
        &fixture.plan,
        &summaries,
        &mut repository,
        &mut semantic_budget,
        &mut DataflowRequest::new(&mut solver_budget, &cancellation),
    )
    .expect("cancelled reusable taint solve");
    assert!(!result.computed_result().is_complete());
    assert_eq!(
        result.cache_status(),
        TaintTransferSummaryCacheStatus::Incomplete
    );
    assert!(repository.is_empty());
}

#[test]
fn exhausted_taint_budget_never_publishes_a_transfer() {
    let fixture = fixture(None);
    let semantic = reusable_semantic_summary(&fixture.root, &[]);
    let summaries = TaintSemanticSummarySet::try_new(vec![&semantic]).unwrap();
    let mut repository = CompleteTaintTransferSummaryRepository::default();
    let cancellation = CancellationToken::default();
    let mut solver_budget = SolverBudget::uniform(0);
    let mut semantic_budget = SemanticBudget::default();
    let result = solve_taint_with_reusable_summaries(
        &fixture.root,
        &fixture.analyzer.icfg_provider(),
        &fixture.plan,
        &summaries,
        &mut repository,
        &mut semantic_budget,
        &mut DataflowRequest::new(&mut solver_budget, &cancellation),
    )
    .expect("budgeted reusable taint solve");
    assert!(!result.computed_result().is_complete());
    assert_eq!(
        result.cache_status(),
        TaintTransferSummaryCacheStatus::Incomplete
    );
    assert!(repository.is_empty());
}

#[test]
fn repository_capacity_failure_preserves_the_complete_taint_result() {
    let project = InlineTestProject::with_language(Language::Java)
        .file("src/ReusableTaintFixture.java", REUSABLE_HELPER_SOURCE)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let graph = SemanticGraph::materialize(&project, &analyzer, "src/ReusableTaintFixture.java");
    let helper = procedure_named(&graph, "helper", ProcedureKind::Method);
    let caller = procedure_named(&graph, "callerOne", ProcedureKind::Method);
    let helper_semantic = reusable_semantic_summary(&helper, &[]);
    let caller_semantic = reusable_semantic_summary(&caller, &[&helper_semantic]);
    let summaries =
        TaintSemanticSummarySet::try_new(vec![&helper_semantic, &caller_semantic]).unwrap();
    let plan = reusable_helper_plan(&analyzer, &caller, &helper, true);
    let mut repository =
        CompleteTaintTransferSummaryRepository::with_limits(TaintTransferSummaryRepositoryLimits {
            max_entries: 0,
            max_retained_bytes: 0,
        });
    let result = solve_reusable_taint(&analyzer, &caller, &plan, &summaries, &mut repository);
    assert!(result.computed_result().is_complete());
    assert_eq!(
        result.cache_status(),
        TaintTransferSummaryCacheStatus::CapacityExceeded
    );
    assert!(repository.is_empty());
}

#[test]
fn direct_and_mutual_recursive_transfers_publish_only_as_exact_scc_batches() {
    let project = InlineTestProject::with_language(Language::Java)
        .file("src/RecursiveTaintFixture.java", RECURSIVE_TAINT_SOURCE)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let graph = SemanticGraph::materialize(&project, &analyzer, "src/RecursiveTaintFixture.java");
    let direct = procedure_named(&graph, "direct", ProcedureKind::Method);
    let left = procedure_named(&graph, "left", ProcedureKind::Method);
    let right = procedure_named(&graph, "right", ProcedureKind::Method);

    let direct_semantics = recursive_semantic_summaries(std::slice::from_ref(&direct), &[(0, 0)]);
    let direct_set = TaintSemanticSummarySet::try_new(direct_semantics.iter().collect()).unwrap();
    let direct_plan = recursive_taint_plan(&analyzer, &direct, std::slice::from_ref(&direct));
    let mut direct_repository = CompleteTaintTransferSummaryRepository::default();
    let direct_result = solve_reusable_taint(
        &analyzer,
        &direct,
        &direct_plan,
        &direct_set,
        &mut direct_repository,
    );
    assert_eq!(
        direct_result.cache_status(),
        TaintTransferSummaryCacheStatus::Published
    );
    assert_eq!(direct_result.published_summaries(), 1);
    assert_eq!(direct_repository.len(), 1);

    let mutual_procedures = vec![left.clone(), right.clone()];
    let mutual_semantics = recursive_semantic_summaries(&mutual_procedures, &[(0, 1), (1, 0)]);
    let mutual_set = TaintSemanticSummarySet::try_new(mutual_semantics.iter().collect()).unwrap();
    let mutual_plan = recursive_taint_plan(&analyzer, &left, &mutual_procedures);
    let mut mutual_repository = CompleteTaintTransferSummaryRepository::default();
    let mutual_result = solve_reusable_taint(
        &analyzer,
        &left,
        &mutual_plan,
        &mutual_set,
        &mut mutual_repository,
    );
    assert_eq!(
        mutual_result.cache_status(),
        TaintTransferSummaryCacheStatus::Published
    );
    assert_eq!(mutual_result.published_summaries(), 2);
    assert_eq!(mutual_repository.len(), 2);

    let changed_plan =
        recursive_taint_plan_with_sanitizer(&analyzer, &left, &mutual_procedures, Some(&right));
    let changed = solve_reusable_taint(
        &analyzer,
        &left,
        &changed_plan,
        &mutual_set,
        &mut mutual_repository,
    );
    assert!(
        !changed.was_reused(),
        "a member-local propagation change must invalidate the whole SCC"
    );
    assert_eq!(
        changed.cache_status(),
        TaintTransferSummaryCacheStatus::Published
    );
    assert_eq!(changed.published_summaries(), 2);
    assert_eq!(mutual_repository.len(), 4);
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

#[test]
fn batch_compatibility_partitions_unmodeled_call_behavior_explicitly() {
    let paranoid = fixture(None).plan;
    let optimistic = fixture_with_behavior(None, None, UnmodeledCallBehavior::Optimistic).plan;
    let paranoid_key = TaintBatchCompatibilityKey::new(
        "snapshot",
        "context=2;heap=alloc-site",
        paranoid.universe().hash(),
    )
    .unwrap();
    let optimistic_key = TaintBatchCompatibilityKey::with_call_behavior(
        "snapshot",
        "context=2;heap=alloc-site",
        UnmodeledCallBehavior::Optimistic,
        optimistic.universe().hash(),
    )
    .unwrap();

    assert!(
        TaintPolicyPlan::new("mismatched", paranoid_key.clone(), optimistic.clone()).is_err(),
        "a compatibility key must describe the analysis plan's call behavior"
    );
    let batches = TaintBatchPlanner::partition(vec![
        TaintPolicyPlan::new("paranoid", paranoid_key, paranoid).unwrap(),
        TaintPolicyPlan::new("optimistic", optimistic_key, optimistic).unwrap(),
    ])
    .unwrap();
    assert_eq!(batches.len(), 2);
    assert!(batches.iter().any(|batch| {
        batch.compatibility().unmodeled_call_behavior() == UnmodeledCallBehavior::Paranoid
    }));
    assert!(batches.iter().any(|batch| {
        batch.compatibility().unmodeled_call_behavior() == UnmodeledCallBehavior::Optimistic
    }));
}
