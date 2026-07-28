mod common;

use std::sync::Arc;

use brokk_bifrost::analyzer::dataflow::{
    CuratedCallModel, DataflowRequest, ExternalSemanticSummarySet, ExternalSummaryCompatibilityKey,
    ExternalSummaryContentHash, ExternalSummaryModelId, ExternalSummaryOrigin, PathQuality,
    ProcedureSummaryIdentity, ProcedureSummaryKey, SemanticInputStatus, SemanticProcedureSummary,
    SolverBudget, SummaryBehaviorKey, SummaryCompleteness, SummaryContextKey, SummaryEvidence,
    SummaryExit, SummaryExitKind, SummaryLocationKey, SummaryOrigin, SummaryPort,
    SummarySchemaVersion, SummarySemanticsVersion, SummaryTransfer, UnmodeledCallBehavior,
    WitnessReconstructionLimits, WitnessRetentionLimits,
};
use brokk_bifrost::analyzer::semantic::{
    AbstractLocation, AbstractObject, AbstractObjectIdentity, AccessPath, AccessPathRoot,
    CancellationToken, ControlContinuation, EvidenceCompleteness, IcfgProvider, MemoryLocationKind,
    ObjectCardinality, OracleCallContext, OracleLimits, ProcedureHandle, ProcedureKind,
    ProofStatus, ScopedSemanticLocator, SemanticBudget, SemanticLocator, SemanticRequest,
    SemanticRole, ValueFlowEndpoint, ValueFlowOracle, ValueFlowRelationKind,
};
use brokk_bifrost::analyzer::value_flow::{
    ValueFlowCarrier, ValueFlowCuratedCallModel, ValueFlowEventKey, ValueFlowEventKind,
    ValueFlowInput, ValueFlowMayStatus, ValueFlowMustStatus, ValueFlowObservationPhase,
    ValueFlowPlan, ValueFlowPlanError, ValueFlowSinkOutcome, ValueFlowSinkSpec,
    ValueFlowSourceSpec, ValueFlowSummaryLocationBinding, solve_value_flow_with_summaries,
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

const EXACT_STATIC_CALL_SOURCE: &str = r#"
final class ExactStaticCallFixture {
  static native String external(String value);

  static String caller(String input) {
    return external(input);
  }
}
"#;

const UNMODELED_EXCEPTIONAL_CALL_SOURCE: &str = r#"
interface ExceptionalExternalWork {
  String run(String value);
}

final class UnmodeledExceptionalCallFixture {
  static String caller(ExceptionalExternalWork work, String input) {
    try {
      return work.run(input);
    } catch (RuntimeException failure) {
      return failure.getMessage();
    }
  }
}
"#;

const JAVA_RECEIVER_EFFECT_SOURCE: &str = r#"
abstract class MutableBox {
  String value;
  abstract void mutate(String input);
}

final class JavaReceiverEffectFixture {
  static String caller(MutableBox box, String input) {
    box.mutate(input);
    return box.value;
  }
}
"#;

const TYPESCRIPT_RECEIVER_EFFECT_SOURCE: &str = r#"
interface MutableBox {
  value: string;
  mutate(input: string): void;
}

export function caller(box: MutableBox, input: string): string {
  box.mutate(input);
  return box.value;
}
"#;

const JAVA_GLOBAL_EFFECT_SOURCE: &str = r#"
interface GlobalWork {
  void mutate(String input);
}

final class JavaGlobalEffectFixture {
  static String value;

  static String caller(GlobalWork work, String input) {
    work.mutate(input);
    String copy = JavaGlobalEffectFixture.value;
    return copy;
  }
}
"#;

const JAVA_PRIMITIVE_EFFECT_SOURCE: &str = r#"
interface PrimitiveWork {
  void inspect(int number, String input);
}

final class JavaPrimitiveEffectFixture {
  static int caller(PrimitiveWork work, int number, String input) {
    work.inspect(number, input);
    return number;
  }
}
"#;

const JAVA_OPERATOR_SOURCE: &str = r#"
final class JavaOperatorFixture {
  static String binary(String input) {
    return input + "!";
  }

  static int unary(int input) {
    return -input;
  }
}
"#;

const TYPESCRIPT_OPERATOR_SOURCE: &str = r#"
export function binary(input: string): string {
  return input + "!";
}

export function unary(input: number): number {
  return -input;
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
    exact_external_summary: bool,
    curated_transfers: Option<Vec<SummaryTransfer>>,
) -> (
    brokk_bifrost::analyzer::value_flow::ValueFlowSummaryResult,
    brokk_bifrost::analyzer::value_flow::ValueFlowSinkId,
    brokk_bifrost::analyzer::value_flow::ValueFlowSinkId,
) {
    solve_call_source(
        UNMODELED_CALL_SOURCE,
        behavior,
        exact_external_summary,
        curated_transfers,
    )
}

fn solve_call_source(
    source_text: &str,
    behavior: UnmodeledCallBehavior,
    exact_external_summary: bool,
    curated_transfers: Option<Vec<SummaryTransfer>>,
) -> (
    brokk_bifrost::analyzer::value_flow::ValueFlowSummaryResult,
    brokk_bifrost::analyzer::value_flow::ValueFlowSinkId,
    brokk_bifrost::analyzer::value_flow::ValueFlowSinkId,
) {
    let project = InlineTestProject::with_language(Language::Java)
        .file("src/UnmodeledCallFixture.java", source_text)
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
    let cancellation = CancellationToken::default();
    let mut semantic_budget = SemanticBudget::default();
    let relations = analyzer
        .semantic_oracle_provider()
        .procedure_relations(
            &root,
            &OracleCallContext::empty(),
            &mut SemanticRequest::new(&mut semantic_budget, &cancellation),
        )
        .expect("caller value-flow snapshot");
    let relation_status = SemanticInputStatus::from_outcome(&relations);
    let relation_snapshot = relations
        .available_value()
        .expect("caller snapshot remains available")
        .clone();
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
    let mut plan = ValueFlowPlan::with_call_behavior(
        root.clone(),
        vec![ValueFlowInput::new(relation_snapshot, relation_status)],
        Vec::new(),
        vec![source],
        vec![result_sink_spec, preserved_sink_spec],
        behavior,
    )
    .expect("unmodeled-call plan");
    if let Some(transfers) = curated_transfers {
        let model = CuratedCallModel::try_new(
            ExternalSummaryModelId::new("test.curated-external-work").unwrap(),
            ExternalSummaryContentHash::hash_bytes(b"curated-external-work-v1"),
            transfers,
        )
        .unwrap();
        plan = plan
            .with_curated_call_models(vec![ValueFlowCuratedCallModel::new(
                root.call_site_handle(call.id).unwrap(),
                model,
            )])
            .unwrap();
    }
    if exact_external_summary {
        let cancellation = CancellationToken::default();
        let mut semantic_budget = SemanticBudget::default();
        let transfer_outcome = analyzer
            .icfg_provider()
            .call_transfers(
                &root,
                call.id,
                &mut SemanticRequest::new(&mut semantic_budget, &cancellation),
            )
            .unwrap();
        let target = transfer_outcome
            .available_value()
            .and_then(|transfers| {
                transfers
                    .boundaries
                    .iter()
                    .find_map(|boundary| boundary.dispatch.kind.target_locator())
            })
            .expect("unmaterialized interface target retains its locator");
        let origin = ExternalSummaryOrigin::new(
            ExternalSummaryModelId::new("test.external-work").unwrap(),
            ExternalSummaryContentHash::hash_bytes(b"parameter-0-to-return-v1"),
            1,
        )
        .unwrap();
        let identity = ProcedureSummaryIdentity::new(
            root.artifact().key().clone(),
            target.declaration().clone(),
            SummarySchemaVersion::CURRENT,
            SummarySemanticsVersion::hash_bytes(b"value-flow-test-v1"),
            SummaryContextKey::hash_bytes(b"context-insensitive"),
            SummaryBehaviorKey::hash_bytes(b"external-work-v1")
                .with_unmodeled_call_behavior(behavior),
            SummaryOrigin::External(origin),
        );
        let key = ProcedureSummaryKey::try_new(identity, &[], None).unwrap();
        let transfer = SummaryTransfer::try_new(
            SummaryPort::Parameter(0),
            SummaryExit::try_new(SummaryExitKind::Normal, SummaryPort::NormalReturn).unwrap(),
            SummaryEvidence::proven_complete(),
        )
        .unwrap();
        let summary = SemanticProcedureSummary::try_new(
            key,
            vec![transfer],
            Vec::new(),
            Vec::new(),
            SummaryCompleteness::Complete,
        )
        .unwrap();
        let incompatible_behavior = match behavior {
            UnmodeledCallBehavior::Paranoid => UnmodeledCallBehavior::Optimistic,
            UnmodeledCallBehavior::Optimistic | UnmodeledCallBehavior::RequireModel => {
                UnmodeledCallBehavior::Paranoid
            }
        };
        let incompatible = ExternalSemanticSummarySet::try_new(
            vec![summary.clone()],
            external_compatibility(&summary, incompatible_behavior),
        )
        .unwrap();
        assert_eq!(
            plan.clone().with_external_summaries(incompatible),
            Err(ValueFlowPlanError::IncompatibleExternalSummary)
        );
        plan = plan
            .with_external_summaries(
                ExternalSemanticSummarySet::try_new(
                    vec![summary.clone()],
                    external_compatibility(&summary, behavior),
                )
                .unwrap(),
            )
            .unwrap();
    }
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

fn modeled_return_transfer(input: SummaryPort, evidence: SummaryEvidence) -> SummaryTransfer {
    SummaryTransfer::try_new(
        input,
        SummaryExit::try_new(SummaryExitKind::Normal, SummaryPort::NormalReturn).unwrap(),
        evidence,
    )
    .unwrap()
}

fn external_compatibility(
    summary: &SemanticProcedureSummary,
    behavior: UnmodeledCallBehavior,
) -> ExternalSummaryCompatibilityKey {
    ExternalSummaryCompatibilityKey::new(
        summary.key().schema(),
        summary.key().semantics(),
        summary.key().context(),
        summary.key().behavior(),
        summary.key().artifact().dependencies(),
        behavior,
    )
}

fn unmodeled_exceptional_call_reaches_result(behavior: UnmodeledCallBehavior) -> bool {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "src/UnmodeledExceptionalCallFixture.java",
            UNMODELED_EXCEPTIONAL_CALL_SOURCE,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let graph = SemanticGraph::materialize(
        &project,
        &analyzer,
        "src/UnmodeledExceptionalCallFixture.java",
    );
    let root = procedure_named(&graph, "caller", ProcedureKind::Method);
    let call = root
        .semantics()
        .call_sites()
        .iter()
        .find(|call| !call.arguments.is_empty() && call.thrown.is_some())
        .expect("external call with an exceptional result")
        .clone();
    let invoke = root.point_handle(call.point).expect("call point");
    let exceptional_continuation = match call.exceptional_continuation {
        ControlContinuation::Target(point) => root
            .point_handle(point)
            .expect("exceptional continuation point"),
        continuation => panic!("expected exceptional continuation, got {continuation:?}"),
    };
    let input = root
        .value_handle(call.arguments[0].value)
        .expect("argument value");
    let thrown = root
        .value_handle(call.thrown.expect("exceptional result"))
        .expect("exceptional result value");
    let source = ValueFlowSourceSpec::new(
        ValueFlowEventKey::at_point(&invoke, 0, ValueFlowEventKind::Source).expect("source key"),
        invoke,
        ValueFlowObservationPhase::BeforeEffects,
        ValueFlowCarrier::Value(input),
        ProofStatus::Proven,
        EvidenceCompleteness::Complete,
    );
    let sink = ValueFlowSinkSpec::new(
        ValueFlowEventKey::at_point(&exceptional_continuation, 0, ValueFlowEventKind::Sink)
            .expect("sink key"),
        exceptional_continuation,
        ValueFlowObservationPhase::BeforeEffects,
        ValueFlowCarrier::Value(thrown),
        ProofStatus::Proven,
        EvidenceCompleteness::Complete,
    );
    let plan = ValueFlowPlan::with_call_behavior(
        root.clone(),
        Vec::new(),
        Vec::new(),
        vec![source],
        vec![sink],
        behavior,
    )
    .expect("unmodeled exceptional-call plan");
    let sink = plan.sinks().next().expect("bound sink").0;
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
    .expect("unmodeled exceptional-call solve");
    matches!(result.sink_outcome(sink), ValueFlowSinkOutcome::Reached(_))
}

fn structured_side_effect_reaches_location(
    language: Language,
    path: &str,
    source_text: &str,
    procedure_kind: ProcedureKind,
    global: bool,
    behavior: UnmodeledCallBehavior,
    exact_heap_model: bool,
) -> bool {
    let project = InlineTestProject::with_language(language)
        .file(path, source_text)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let graph = SemanticGraph::materialize(&project, &analyzer, path);
    let root = procedure_named(&graph, "caller", procedure_kind);
    let call = root
        .semantics()
        .call_sites()
        .first()
        .expect("unmodeled mutation call")
        .clone();
    let invoke = root.point_handle(call.point).expect("call point");
    let continuation = match call.normal_continuation {
        ControlContinuation::Target(point) => root.point_handle(point).unwrap(),
        other => panic!("expected normal continuation, got {other:?}"),
    };
    let input = root
        .value_handle(call.arguments[0].value)
        .expect("input argument");

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
    let snapshot = outcome.available_value().unwrap().clone();
    let location = snapshot
        .relations()
        .iter()
        .filter(|relation| relation.kind == ValueFlowRelationKind::MemoryLoad)
        .find_map(|relation| {
            let ValueFlowEndpoint::Location(location) = &relation.source else {
                return None;
            };
            let is_global = matches!(
                location.path().root(),
                AccessPathRoot::Static(_)
                    | AccessPathRoot::TypeSummary(_)
                    | AccessPathRoot::ModuleObject(_)
                    | AccessPathRoot::External(_)
            );
            (is_global == global).then(|| ValueFlowCarrier::from(&relation.source))
        })
        .or_else(|| {
            if !global {
                return None;
            }
            let static_member = root
                .semantics()
                .memory_locations()
                .iter()
                .find_map(|row| match &row.kind {
                    MemoryLocationKind::Static { member } => Some(member.clone()),
                    _ => None,
                })
                .unwrap_or_else(|| {
                    let procedure = root.semantics().locator();
                    SemanticLocator::new(
                        procedure.mount(),
                        procedure.path().clone(),
                        procedure.language(),
                        procedure.declaration().clone(),
                        SemanticRole::MemoryLocation,
                        procedure.anchor(),
                    )
                });
            [static_member].into_iter().find_map(|member| {
                let member =
                    ScopedSemanticLocator::new(Arc::clone(root.artifact()), member).ok()?;
                let object = AbstractObject::new(
                    AbstractObjectIdentity::Static(member.clone()),
                    ObjectCardinality::Singleton,
                )
                .ok()?;
                let path = AccessPath::exact(
                    AccessPathRoot::Static(member),
                    Vec::new(),
                    OracleLimits::default(),
                )
                .ok()?;
                AbstractLocation::new(object, path)
                    .ok()
                    .map(|location| ValueFlowCarrier::Location(Box::new(location)))
            })
        })
        .expect("post-call load retains a structured location");
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
        location.clone(),
        ProofStatus::Proven,
        EvidenceCompleteness::Complete,
    );
    let mut plan = ValueFlowPlan::with_call_behavior(
        root.clone(),
        vec![ValueFlowInput::new(snapshot, status)],
        Vec::new(),
        vec![source],
        vec![sink],
        behavior,
    )
    .unwrap();
    if exact_heap_model {
        let cancellation = CancellationToken::default();
        let mut semantic_budget = SemanticBudget::default();
        let target = analyzer
            .icfg_provider()
            .call_transfers(
                &root,
                call.id,
                &mut SemanticRequest::new(&mut semantic_budget, &cancellation),
            )
            .unwrap()
            .available_value()
            .and_then(|transfers| {
                transfers
                    .boundaries
                    .iter()
                    .find_map(|boundary| boundary.dispatch.kind.target_locator())
            })
            .expect("external target locator")
            .clone();
        let heap = SummaryLocationKey::hash_bytes(b"receiver-state");
        let origin = ExternalSummaryOrigin::new(
            ExternalSummaryModelId::new("test.receiver-state").unwrap(),
            ExternalSummaryContentHash::hash_bytes(b"input-to-receiver-state-v1"),
            1,
        )
        .unwrap();
        let identity = ProcedureSummaryIdentity::new(
            root.artifact().key().clone(),
            target.declaration().clone(),
            SummarySchemaVersion::CURRENT,
            SummarySemanticsVersion::hash_bytes(b"value-flow-test-v1"),
            SummaryContextKey::hash_bytes(b"context-insensitive"),
            SummaryBehaviorKey::hash_bytes(b"receiver-state-v1")
                .with_unmodeled_call_behavior(behavior),
            SummaryOrigin::External(origin),
        );
        let key = ProcedureSummaryKey::try_new(identity, &[], None).unwrap();
        let transfer = SummaryTransfer::try_new(
            SummaryPort::Parameter(0),
            SummaryExit::try_new(SummaryExitKind::Normal, SummaryPort::Heap(heap)).unwrap(),
            SummaryEvidence::proven_complete(),
        )
        .unwrap();
        let summary = SemanticProcedureSummary::try_new(
            key,
            vec![transfer],
            Vec::new(),
            Vec::new(),
            SummaryCompleteness::Complete,
        )
        .unwrap();
        let heap_port = summary.transfers()[0].exit().port().clone();
        plan = plan
            .with_external_summaries(
                ExternalSemanticSummarySet::try_new(
                    vec![summary.clone()],
                    external_compatibility(&summary, behavior),
                )
                .unwrap(),
            )
            .unwrap()
            .with_summary_location_bindings(vec![ValueFlowSummaryLocationBinding::new(
                root.call_site_handle(call.id).unwrap(),
                heap_port,
                location,
            )])
            .unwrap();
    }
    let sink = plan.sinks().next().unwrap().0;
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
    .unwrap();
    matches!(result.sink_outcome(sink), ValueFlowSinkOutcome::Reached(_))
}

fn primitive_argument_is_not_a_side_effect_output(behavior: UnmodeledCallBehavior) -> bool {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "src/JavaPrimitiveEffectFixture.java",
            JAVA_PRIMITIVE_EFFECT_SOURCE,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let graph =
        SemanticGraph::materialize(&project, &analyzer, "src/JavaPrimitiveEffectFixture.java");
    let root = procedure_named(&graph, "caller", ProcedureKind::Method);
    let call = root.semantics().call_sites().first().unwrap().clone();
    let invoke = root.point_handle(call.point).unwrap();
    let continuation = match call.normal_continuation {
        ControlContinuation::Target(point) => root.point_handle(point).unwrap(),
        other => panic!("expected normal continuation, got {other:?}"),
    };
    let number = root.value_handle(call.arguments[0].value).unwrap();
    let input = root.value_handle(call.arguments[1].value).unwrap();
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
        ValueFlowCarrier::Value(number),
        ProofStatus::Proven,
        EvidenceCompleteness::Complete,
    );
    let plan = ValueFlowPlan::with_call_behavior(
        root.clone(),
        Vec::new(),
        Vec::new(),
        vec![source],
        vec![sink],
        behavior,
    )
    .unwrap();
    let sink = plan.sinks().next().unwrap().0;
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
    .unwrap();
    matches!(result.sink_outcome(sink), ValueFlowSinkOutcome::Reached(_))
}

fn language_operator_flow_reaches_result(
    language: Language,
    path: &str,
    source_text: &str,
    name: &str,
    kind: ProcedureKind,
) -> bool {
    let project = InlineTestProject::with_language(language)
        .file(path, source_text)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let graph = SemanticGraph::materialize(&project, &analyzer, path);
    let root = procedure_named(&graph, name, kind);
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
    let relation = snapshot
        .relations()
        .iter()
        .find(|relation| relation.kind == ValueFlowRelationKind::LanguageDefined)
        .expect("operator lowering emits a language-defined value flow")
        .clone();
    let source = ValueFlowSourceSpec::new(
        ValueFlowEventKey::at_point(relation.point(), 0, ValueFlowEventKind::Source).unwrap(),
        relation.point().clone(),
        ValueFlowObservationPhase::BeforeEffects,
        ValueFlowCarrier::from(&relation.source),
        ProofStatus::Proven,
        EvidenceCompleteness::Complete,
    );
    let sink = ValueFlowSinkSpec::new(
        ValueFlowEventKey::at_point(relation.point(), 0, ValueFlowEventKind::Sink).unwrap(),
        relation.point().clone(),
        ValueFlowObservationPhase::AfterEffects,
        ValueFlowCarrier::from(&relation.target),
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
    .unwrap();
    let sink = plan.sinks().next().unwrap().0;
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
    .unwrap();
    matches!(result.sink_outcome(sink), ValueFlowSinkOutcome::Reached(_))
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
        solve_unmodeled_call(UnmodeledCallBehavior::Paranoid, false, None);
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
        solve_unmodeled_call(UnmodeledCallBehavior::Optimistic, false, None);
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
        solve_unmodeled_call(UnmodeledCallBehavior::RequireModel, false, None);
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

    assert!(unmodeled_exceptional_call_reaches_result(
        UnmodeledCallBehavior::Paranoid
    ));
    assert!(!unmodeled_exceptional_call_reaches_result(
        UnmodeledCallBehavior::Optimistic
    ));
}

#[test]
fn paranoid_fallback_models_structured_receiver_effects_in_java_and_typescript() {
    for (language, path, source, kind) in [
        (
            Language::Java,
            "src/JavaReceiverEffectFixture.java",
            JAVA_RECEIVER_EFFECT_SOURCE,
            ProcedureKind::Method,
        ),
        (
            Language::TypeScript,
            "src/typescript-receiver-effect.ts",
            TYPESCRIPT_RECEIVER_EFFECT_SOURCE,
            ProcedureKind::Function,
        ),
    ] {
        assert!(structured_side_effect_reaches_location(
            language,
            path,
            source,
            kind,
            false,
            UnmodeledCallBehavior::Paranoid,
            false,
        ));
        assert!(!structured_side_effect_reaches_location(
            language,
            path,
            source,
            kind,
            false,
            UnmodeledCallBehavior::Optimistic,
            false,
        ));
    }
}

#[test]
fn paranoid_fallback_models_bounded_globals_but_not_primitive_argument_mutation() {
    assert!(structured_side_effect_reaches_location(
        Language::Java,
        "src/JavaGlobalEffectFixture.java",
        JAVA_GLOBAL_EFFECT_SOURCE,
        ProcedureKind::Method,
        true,
        UnmodeledCallBehavior::Paranoid,
        false,
    ));
    assert!(!structured_side_effect_reaches_location(
        Language::Java,
        "src/JavaGlobalEffectFixture.java",
        JAVA_GLOBAL_EFFECT_SOURCE,
        ProcedureKind::Method,
        true,
        UnmodeledCallBehavior::Optimistic,
        false,
    ));
    assert!(!primitive_argument_is_not_a_side_effect_output(
        UnmodeledCallBehavior::Paranoid
    ));
}

#[test]
fn java_and_typescript_unary_and_binary_operations_emit_structured_flows() {
    for (language, path, source, kind) in [
        (
            Language::Java,
            "src/JavaOperatorFixture.java",
            JAVA_OPERATOR_SOURCE,
            ProcedureKind::Method,
        ),
        (
            Language::TypeScript,
            "src/typescript-operator.ts",
            TYPESCRIPT_OPERATOR_SOURCE,
            ProcedureKind::Function,
        ),
    ] {
        assert!(language_operator_flow_reaches_result(
            language, path, source, "binary", kind,
        ));
        assert!(language_operator_flow_reaches_result(
            language, path, source, "unary", kind,
        ));
    }
}

#[test]
fn exact_external_summary_precedes_require_model_fallback() {
    let (result, result_sink, preserved_sink) =
        solve_unmodeled_call(UnmodeledCallBehavior::RequireModel, true, None);
    let ValueFlowSinkOutcome::Reached(meetings) = result.sink_outcome(result_sink) else {
        panic!("the exact external summary must propagate parameter zero to the return value");
    };
    assert!(meetings.iter().all(|meeting| !meeting.is_uncertain()));
    assert!(matches!(
        result.sink_outcome(preserved_sink),
        ValueFlowSinkOutcome::Reached(_)
    ));
    assert!(
        !result.is_complete(),
        "the exact interface target must not erase the independent unresolved override arm"
    );
}

#[test]
fn complete_exact_static_model_discharges_only_the_missing_body_boundary() {
    let (result, result_sink, _) = solve_call_source(
        EXACT_STATIC_CALL_SOURCE,
        UnmodeledCallBehavior::RequireModel,
        true,
        Some(vec![modeled_return_transfer(
            SummaryPort::Parameter(0),
            SummaryEvidence::proven_complete(),
        )]),
    );
    assert!(matches!(
        result.sink_outcome(result_sink),
        ValueFlowSinkOutcome::Reached(_)
    ));
    assert!(
        result.is_complete(),
        "a compatible complete static model should make the missing body conclusive: {:#?}",
        result.result().coverage()
    );
}

#[test]
fn exact_external_summary_binds_a_bounded_heap_effect() {
    assert!(structured_side_effect_reaches_location(
        Language::Java,
        "src/JavaReceiverEffectFixture.java",
        JAVA_RECEIVER_EFFECT_SOURCE,
        ProcedureKind::Method,
        false,
        UnmodeledCallBehavior::RequireModel,
        true,
    ));
}

#[test]
fn curated_call_model_precedes_require_model_fallback() {
    let (result, result_sink, _) = solve_unmodeled_call(
        UnmodeledCallBehavior::RequireModel,
        false,
        Some(vec![modeled_return_transfer(
            SummaryPort::Parameter(0),
            SummaryEvidence::proven_complete(),
        )]),
    );
    let ValueFlowSinkOutcome::Reached(meetings) = result.sink_outcome(result_sink) else {
        panic!("the selector-bound curated model must propagate parameter zero to the return");
    };
    assert!(meetings.iter().all(|meeting| !meeting.is_uncertain()));
    assert!(result.is_complete());
}

#[test]
fn curated_model_keeps_bindable_rows_when_another_port_is_unbound() {
    let (result, result_sink, _) = solve_unmodeled_call(
        UnmodeledCallBehavior::RequireModel,
        false,
        Some(vec![
            modeled_return_transfer(
                SummaryPort::Parameter(0),
                SummaryEvidence::proven_complete(),
            ),
            modeled_return_transfer(
                SummaryPort::Heap(SummaryLocationKey::hash_bytes(b"unbound-test-heap")),
                SummaryEvidence::proven_complete(),
            ),
        ]),
    );
    assert!(matches!(
        result.sink_outcome(result_sink),
        ValueFlowSinkOutcome::Reached(_)
    ));
    assert!(
        !result.is_complete(),
        "an unbound row remains an explicit completeness gap"
    );
}

#[test]
fn modeled_transfer_quality_requires_one_proven_complete_alternative() {
    let proven_partial =
        SummaryEvidence::try_new(Vec::new(), vec!["partial modeled path".to_string()]).unwrap();
    let unproven_complete =
        SummaryEvidence::try_new(vec!["unproven modeled path".to_string()], Vec::new()).unwrap();
    let incomparable = proven_partial.join(&unproven_complete).unwrap();
    let (result, result_sink, _) = solve_unmodeled_call(
        UnmodeledCallBehavior::RequireModel,
        false,
        Some(vec![modeled_return_transfer(
            SummaryPort::Parameter(0),
            incomparable,
        )]),
    );
    let ValueFlowSinkOutcome::Reached(meetings) = result.sink_outcome(result_sink) else {
        panic!("the modeled transfer must remain reachable");
    };
    assert!(meetings.iter().all(|meeting| meeting.is_uncertain()));
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
