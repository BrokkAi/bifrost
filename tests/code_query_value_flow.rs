mod common;

use std::sync::Arc;

use brokk_bifrost::analyzer::dataflow::SemanticInputStatus;
use brokk_bifrost::analyzer::semantic::{
    CancellationToken, EvidenceCompleteness, OracleCallContext, ProcedureHandle, ProcedureKind,
    ProofStatus, SemanticBudget, SemanticRequest, ValueFlowOracle, ValueFlowRelationKind,
};
use brokk_bifrost::analyzer::structural::{
    CodeQuery, CodeQueryDiagnosticCode, CodeQueryExecutionLimits, ProtocolRegistrationSet,
    ValueFlowPlanRegistration, ValueFlowPlanRegistrationSet,
    execute_workspace_request_with_analysis_registration_lease,
};
use brokk_bifrost::analyzer::typestate::ProductionTypestateSummaryRepository;
use brokk_bifrost::analyzer::value_flow::{
    ValueFlowCarrier, ValueFlowEventKey, ValueFlowEventKind, ValueFlowInput,
    ValueFlowObservationPhase, ValueFlowPlan, ValueFlowSinkSpec, ValueFlowSourceSpec,
};
use brokk_bifrost::{AnalyzerConfig, Language, WorkspaceAnalyzer};
use serde_json::json;

use common::semantic_graph::SemanticGraph;
use common::{BuiltInlineTestProject, InlineTestProject};

const WORKSPACE_GENERATION: u64 = 23;
const PLAN_REF: &str = "test:request-to-sink";
const SOURCE: &str = r#"
final class FlowFixture {
  static String run(String input) {
    String copy = input;
    return copy;
  }
}
"#;

struct Fixture {
    _project: BuiltInlineTestProject,
    workspace: WorkspaceAnalyzer,
    registrations: ValueFlowPlanRegistrationSet,
    summaries: Arc<ProductionTypestateSummaryRepository>,
}

impl Fixture {
    fn new(source_proof: ProofStatus, source_completeness: EvidenceCompleteness) -> Self {
        Self::with_shape(
            source_proof,
            source_completeness,
            Some(SemanticInputStatus::Complete),
            true,
            1,
        )
    }

    fn with_status(
        source_proof: ProofStatus,
        source_completeness: EvidenceCompleteness,
        status: Option<SemanticInputStatus>,
    ) -> Self {
        Self::with_shape(source_proof, source_completeness, status, true, 1)
    }

    fn with_shape(
        source_proof: ProofStatus,
        source_completeness: EvidenceCompleteness,
        status: Option<SemanticInputStatus>,
        include_source: bool,
        sink_count: usize,
    ) -> Self {
        let project = InlineTestProject::with_language(Language::Java)
            .file("src/FlowFixture.java", SOURCE)
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let plan = Arc::new(value_flow_plan(
            &project,
            &workspace,
            source_proof,
            source_completeness,
            status,
            include_source,
            sink_count,
        ));
        let mut registrations = ValueFlowPlanRegistrationSet::default();
        registrations
            .register(
                PLAN_REF.parse().unwrap(),
                ValueFlowPlanRegistration::new(WORKSPACE_GENERATION, plan),
            )
            .unwrap();
        Self {
            _project: project,
            workspace,
            registrations,
            summaries: Arc::new(ProductionTypestateSummaryRepository::new()),
        }
    }

    fn execute(&self, query: &CodeQuery, limits: CodeQueryExecutionLimits) -> serde_json::Value {
        self.execute_with_cancellation(query, limits, None)
    }

    fn execute_with_cancellation(
        &self,
        query: &CodeQuery,
        limits: CodeQueryExecutionLimits,
        cancellation: Option<&CancellationToken>,
    ) -> serde_json::Value {
        let response = execute_workspace_request_with_analysis_registration_lease(
            &self.workspace,
            WORKSPACE_GENERATION,
            &ProtocolRegistrationSet::default(),
            &self.registrations,
            query,
            limits,
            cancellation,
            self.summaries.lease(WORKSPACE_GENERATION).unwrap(),
        );
        serde_json::to_value(response).unwrap()
    }
}

fn value_flow_plan(
    project: &BuiltInlineTestProject,
    workspace: &WorkspaceAnalyzer,
    source_proof: ProofStatus,
    source_completeness: EvidenceCompleteness,
    status_override: Option<SemanticInputStatus>,
    include_source: bool,
    sink_count: usize,
) -> ValueFlowPlan {
    let graph = SemanticGraph::materialize(project, workspace, "src/FlowFixture.java");
    let root = procedure_named(&graph, "run");
    let cancellation = CancellationToken::default();
    let mut semantic_budget = SemanticBudget::default();
    let outcome = workspace
        .semantic_oracle_provider()
        .procedure_relations(
            &root,
            &OracleCallContext::empty(),
            &mut SemanticRequest::new(&mut semantic_budget, &cancellation),
        )
        .expect("value-flow snapshot");
    let status = status_override.unwrap_or_else(|| SemanticInputStatus::from_outcome(&outcome));
    let snapshot = outcome.available_value().unwrap().clone();
    let relation = snapshot
        .relations()
        .iter()
        .find(|relation| relation.kind == ValueFlowRelationKind::Assignment)
        .expect("assignment relation")
        .clone();
    let source = ValueFlowSourceSpec::new(
        ValueFlowEventKey::at_point(relation.point(), 0, ValueFlowEventKind::Source).unwrap(),
        relation.point().clone(),
        ValueFlowObservationPhase::BeforeEffects,
        ValueFlowCarrier::from(&relation.source),
        source_proof,
        source_completeness,
    );
    let sources = include_source.then_some(source).into_iter().collect();
    let sinks = (0..sink_count)
        .map(|ordinal| {
            ValueFlowSinkSpec::new(
                ValueFlowEventKey::at_point(
                    relation.point(),
                    u32::try_from(ordinal).unwrap(),
                    ValueFlowEventKind::Sink,
                )
                .unwrap(),
                relation.point().clone(),
                ValueFlowObservationPhase::AfterEffects,
                ValueFlowCarrier::from(&relation.target),
                ProofStatus::Proven,
                EvidenceCompleteness::Complete,
            )
        })
        .collect();
    ValueFlowPlan::try_new(
        root,
        vec![ValueFlowInput::new(snapshot, status)],
        Vec::new(),
        sources,
        sinks,
    )
    .unwrap()
}

fn procedure_named(graph: &SemanticGraph, name: &str) -> ProcedureHandle {
    let procedure = graph
        .artifact()
        .procedures()
        .iter()
        .find(|procedure| {
            procedure.kind() == ProcedureKind::Method
                && procedure
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|segment| segment.name())
                    == Some(name)
        })
        .expect("procedure");
    graph.artifact().procedure_handle(procedure.id()).unwrap()
}

fn json_query(with_witness: bool) -> CodeQuery {
    let mut steps = vec![
        json!({"op": "procedure_of"}),
        json!({"op": "value_flow", "plan_ref": PLAN_REF}),
    ];
    if with_witness {
        steps.push(json!({"op": "witness", "max_steps": 32, "max_bytes": 16_384}));
    }
    CodeQuery::from_json(&json!({
        "schema_version": 6,
        "match": {"kind": "method", "name": "run"},
        "steps": steps,
    }))
    .unwrap()
}

fn profiled_query(with_witness: bool) -> CodeQuery {
    let mut value = json_query(with_witness).to_canonical_json();
    value["execution_mode"] = json!("profile");
    CodeQuery::from_json(&value).unwrap()
}

#[test]
fn json_projects_exact_diagnostic_neutral_endpoint_and_witness_domains() {
    let fixture = Fixture::new(ProofStatus::Proven, EvidenceCompleteness::Complete);
    let endpoint = fixture.execute(&json_query(false), CodeQueryExecutionLimits::default());
    let value = &endpoint["results"][0];
    assert_eq!(value["result_type"], "flow_endpoint", "{endpoint:#}");
    assert_eq!(value["reachability"], "reached", "{endpoint:#}");
    assert_eq!(value["certainty"], "exact");
    assert_eq!(value["must"], "not_established");
    assert!(value.get("ambiguous").is_none());
    assert_eq!(value["completion"], "complete");
    assert!(
        endpoint
            .get("diagnostics")
            .is_none_or(|diagnostics| diagnostics.as_array().unwrap().is_empty()),
        "{endpoint:#}"
    );

    let witness = fixture.execute(&json_query(true), CodeQueryExecutionLimits::default());
    let value = &witness["results"][0];
    assert_eq!(value["result_type"], "flow_witness");
    assert_eq!(value["plan_ref"], PLAN_REF);
    let steps = value["steps"].as_array().unwrap();
    assert_eq!(steps.len(), 7, "{witness:#}");
    assert!(steps.iter().all(|step| step.get("input").is_some()));
    assert!(steps.iter().all(|step| step.get("output").is_some()));
    assert!(
        steps[..steps.len() - 1]
            .iter()
            .all(|step| step["input"]["kind"] == "zero" && step["output"]["kind"] == "zero")
    );
    let meeting = &steps.last().unwrap()["output"];
    assert_eq!(meeting["kind"], "meeting", "{witness:#}");
    assert_eq!(meeting["source"], endpoint["results"][0]["source"]);
    assert_eq!(meeting["sink"], endpoint["results"][0]["sink"]);
    assert!(meeting.get("uncertain").is_none());
}

#[test]
fn rql_preserves_may_and_incomplete_outcomes() {
    let fixture = Fixture::new(
        ProofStatus::Unproven("fixture ambiguity".into()),
        EvidenceCompleteness::Partial("fixture incompleteness".into()),
    );
    let query = CodeQuery::from_sexp(&format!(
        "(value-flow :plan-ref {PLAN_REF} (procedure-of (method :name \"run\")))"
    ))
    .unwrap();
    let result = fixture.execute(&query, CodeQueryExecutionLimits::default());
    let value = &result["results"][0];
    assert_eq!(value["reachability"], "reached", "{result:#}");
    assert_eq!(value["certainty"], "may");
    assert_eq!(value["completion"], "incomplete");
}

#[test]
fn ambiguous_discovery_is_preserved_independently_from_exact_reachability() {
    let fixture = Fixture::with_status(
        ProofStatus::Proven,
        EvidenceCompleteness::Complete,
        Some(SemanticInputStatus::Ambiguous),
    );
    let result = fixture.execute(&json_query(false), CodeQueryExecutionLimits::default());
    let value = &result["results"][0];
    assert_eq!(value["reachability"], "reached");
    assert_eq!(value["certainty"], "exact");
    assert_eq!(value["ambiguous"], true);
    assert_eq!(value["completion"], "incomplete");
}

#[test]
fn missing_registration_and_solver_budget_are_typed_outcomes() {
    let fixture = Fixture::new(ProofStatus::Proven, EvidenceCompleteness::Complete);
    let unresolved = execute_workspace_request_with_analysis_registration_lease(
        &fixture.workspace,
        WORKSPACE_GENERATION,
        &ProtocolRegistrationSet::default(),
        &ValueFlowPlanRegistrationSet::default(),
        &json_query(false),
        CodeQueryExecutionLimits::default(),
        None,
        fixture.summaries.lease(WORKSPACE_GENERATION).unwrap(),
    );
    assert!(
        unresolved
            .result()
            .unwrap()
            .diagnostics
            .iter()
            .any(|diagnostic| {
                diagnostic.code == CodeQueryDiagnosticCode::UnresolvedValueFlowPlanReference
            })
    );

    let mut limits = CodeQueryExecutionLimits::default();
    limits.value_flow.solver_work.reached_states = 1;
    let exhausted = fixture.execute(&json_query(false), limits);
    let diagnostics = exhausted["diagnostics"].as_array().unwrap();
    assert!(
        diagnostics
            .iter()
            .any(|diagnostic| { diagnostic["code"] == "value_flow_solver_budget_exhausted" }),
        "{exhausted:#}"
    );
    if let Some(value) = exhausted["results"]
        .as_array()
        .and_then(|results| results.first())
    {
        assert_eq!(value["completion"], "budget_exhausted");
    }
}

#[test]
fn runtime_semantic_budget_status_is_preserved_on_endpoints() {
    let fixture = Fixture::new(ProofStatus::Proven, EvidenceCompleteness::Complete);
    let mut limits = CodeQueryExecutionLimits::default();
    limits.semantic.max_rows_per_dimension = 86;
    let result = fixture.execute(&json_query(false), limits);
    let endpoints = result["results"].as_array().unwrap();
    assert!(!endpoints.is_empty(), "{result:#}");
    assert_eq!(
        endpoints[0]["semantic_status"], "exceeded_budget",
        "{result:#}"
    );
    assert_eq!(endpoints[0]["completion"], "budget_exhausted", "{result:#}");
    assert!(
        result["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|diagnostic| { diagnostic["code"] == "semantic_budget_exhausted" })
    );
}

#[test]
fn complete_negative_and_file_projection_remain_queryable() {
    let fixture = Fixture::with_shape(
        ProofStatus::Proven,
        EvidenceCompleteness::Complete,
        Some(SemanticInputStatus::Complete),
        false,
        1,
    );
    let negative = fixture.execute(&json_query(false), CodeQueryExecutionLimits::default());
    assert_eq!(negative["results"][0]["reachability"], "not_reached");
    assert!(negative["results"][0].get("source").is_none());
    assert_eq!(negative["results"][0]["completion"], "complete");

    let query = CodeQuery::from_json(&json!({
        "schema_version": 6,
        "match": {"kind": "method", "name": "run"},
        "steps": [
            {"op": "procedure_of"},
            {"op": "value_flow", "plan_ref": PLAN_REF},
            {"op": "file_of"}
        ]
    }))
    .unwrap();
    let file = fixture.execute(&query, CodeQueryExecutionLimits::default());
    assert_eq!(file["results"][0]["result_type"], "file", "{file:#}");
    assert_eq!(file["results"][0]["path"], "src/FlowFixture.java");
}

#[test]
fn witness_projection_clamps_query_limits_and_downgrades_completeness() {
    let fixture = Fixture::new(ProofStatus::Proven, EvidenceCompleteness::Complete);
    let query = CodeQuery::from_json(&json!({
        "schema_version": 6,
        "match": {"kind": "method", "name": "run"},
        "steps": [
            {"op": "procedure_of"},
            {"op": "value_flow", "plan_ref": PLAN_REF},
            {"op": "witness", "max_steps": 0, "max_bytes": 16_777_216}
        ]
    }))
    .unwrap();
    let mut limits = CodeQueryExecutionLimits::default();
    limits.value_flow.max_witness_bytes = 1;
    let result = fixture.execute(&query, limits);
    let witness = &result["results"][0];
    assert!(
        witness["steps"].as_array().unwrap().is_empty(),
        "{result:#}"
    );
    assert_eq!(witness["truncated"], true);
    assert_eq!(witness["quality"]["completeness"], "partial");
    assert!(witness["quality"]["completeness_reason"].is_string());
    assert!(
        result["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|diagnostic| { diagnostic["code"] == "value_flow_witness_truncated" })
    );
}

#[test]
fn exact_and_may_meetings_have_distinct_stable_ids() {
    let exact_fixture = Fixture::new(ProofStatus::Proven, EvidenceCompleteness::Complete);
    let exact = exact_fixture.execute(&json_query(false), CodeQueryExecutionLimits::default());
    let same_exact = Fixture::new(ProofStatus::Proven, EvidenceCompleteness::Complete)
        .execute(&json_query(false), CodeQueryExecutionLimits::default());
    let may = Fixture::new(
        ProofStatus::Unproven("fixture uncertainty".into()),
        EvidenceCompleteness::Complete,
    )
    .execute(&json_query(false), CodeQueryExecutionLimits::default());

    assert_eq!(exact["results"][0]["certainty"], "exact");
    assert_eq!(exact["results"][0]["id"], same_exact["results"][0]["id"]);
    assert_eq!(may["results"][0]["certainty"], "may");
    assert_ne!(exact["results"][0]["id"], may["results"][0]["id"]);
}

#[test]
fn cancellation_and_stale_generation_never_become_clean_negatives() {
    let fixture = Fixture::new(ProofStatus::Proven, EvidenceCompleteness::Complete);
    let cancellation = CancellationToken::default();
    cancellation.cancel();
    let cancelled = fixture.execute_with_cancellation(
        &json_query(false),
        CodeQueryExecutionLimits::default(),
        Some(&cancellation),
    );
    assert!(cancelled["results"].as_array().unwrap().is_empty());
    assert!(
        cancelled["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|diagnostic| { diagnostic["code"] == "cancelled" })
    );

    let stale_summaries = Arc::new(ProductionTypestateSummaryRepository::new());
    let stale = execute_workspace_request_with_analysis_registration_lease(
        &fixture.workspace,
        WORKSPACE_GENERATION + 1,
        &ProtocolRegistrationSet::default(),
        &fixture.registrations,
        &json_query(false),
        CodeQueryExecutionLimits::default(),
        None,
        stale_summaries.lease(WORKSPACE_GENERATION + 1).unwrap(),
    );
    let stale = serde_json::to_value(stale).unwrap();
    assert!(stale["results"].as_array().unwrap().is_empty());
    assert!(
        stale["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|diagnostic| { diagnostic["code"] == "value_flow_registration_stale" })
    );
}

#[test]
fn endpoint_and_aggregate_witness_budgets_stop_before_excess_projection() {
    let fixture = Fixture::with_shape(
        ProofStatus::Proven,
        EvidenceCompleteness::Complete,
        Some(SemanticInputStatus::Complete),
        true,
        2,
    );
    let mut endpoint_limits = CodeQueryExecutionLimits::default();
    endpoint_limits.value_flow.max_endpoints = 1;
    let endpoints = fixture.execute(&profiled_query(false), endpoint_limits);
    assert_eq!(endpoints["result"]["results"].as_array().unwrap().len(), 1);
    assert_eq!(endpoints["result"]["truncated"], true);
    assert_eq!(
        endpoints.pointer("/work/semantic/value_flow/endpoint_truncated"),
        Some(&json!(true))
    );
    assert!(
        endpoints
            .pointer("/work/semantic/value_flow/omitted_endpoints")
            .and_then(serde_json::Value::as_u64)
            .is_some_and(|omitted| omitted >= 1)
    );

    let mut witness_limits = CodeQueryExecutionLimits::default();
    witness_limits.value_flow.max_witnesses = 1;
    let witnesses = fixture.execute(&profiled_query(true), witness_limits);
    assert_eq!(witnesses["result"]["results"].as_array().unwrap().len(), 1);
    assert_eq!(witnesses["result"]["truncated"], true);
    assert!(
        witnesses
            .pointer("/work/semantic/value_flow/omitted_witnesses")
            .and_then(serde_json::Value::as_u64)
            .is_some_and(|omitted| omitted >= 1)
    );
}

#[test]
fn duplicate_analysis_branches_share_one_solve() {
    let fixture = Fixture::new(ProofStatus::Proven, EvidenceCompleteness::Complete);
    let branch = json!({
        "match": {"kind": "method", "name": "run"},
        "steps": [
            {"op": "procedure_of"},
            {"op": "value_flow", "plan_ref": PLAN_REF}
        ]
    });
    let query = CodeQuery::from_json(&json!({
        "schema_version": 6,
        "union": [branch.clone(), branch],
        "execution_mode": "profile"
    }))
    .unwrap();
    let report = fixture.execute(&query, CodeQueryExecutionLimits::default());
    assert_eq!(
        report.pointer("/work/semantic/value_flow/solves"),
        Some(&json!(1))
    );
    assert_eq!(
        report.pointer("/work/semantic/value_flow/cache_hits"),
        Some(&json!(1))
    );
}

#[test]
fn independently_allocated_equal_plans_share_registration_identity() {
    let project = InlineTestProject::with_language(Language::Java)
        .file("src/FlowFixture.java", SOURCE)
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let first = Arc::new(value_flow_plan(
        &project,
        &workspace,
        ProofStatus::Proven,
        EvidenceCompleteness::Complete,
        Some(SemanticInputStatus::Complete),
        true,
        1,
    ));
    let second = Arc::new(value_flow_plan(
        &project,
        &workspace,
        ProofStatus::Proven,
        EvidenceCompleteness::Complete,
        Some(SemanticInputStatus::Complete),
        true,
        1,
    ));
    let mut registrations = ValueFlowPlanRegistrationSet::default();
    registrations
        .register(
            "test:first".parse().unwrap(),
            ValueFlowPlanRegistration::new(WORKSPACE_GENERATION, first),
        )
        .unwrap();
    let outcome = registrations
        .register(
            "test:second".parse().unwrap(),
            ValueFlowPlanRegistration::new(WORKSPACE_GENERATION, second),
        )
        .unwrap();
    assert_eq!(
        outcome,
        brokk_bifrost::analyzer::structural::ValueFlowPlanRegistrationOutcome::Aliased
    );
    assert_eq!(registrations.reference_count(), 2);
    assert_eq!(registrations.registration_count(), 1);
}
