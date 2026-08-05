use std::collections::BTreeSet;
use std::sync::Arc;

use brokk_bifrost::analyzer::dataflow::{SemanticInputStatus, SolverBudgetDimension, SolverWork};
use brokk_bifrost::analyzer::semantic::{
    CancellationToken, EvidenceCompleteness, OracleCallContext, ProcedureHandle, ProcedureKind,
    ProofStatus, SemanticBudget, SemanticCapability, SemanticRequest, ValueFlowOracle,
    ValueFlowRelationKind,
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

use crate::common::semantic_graph::SemanticGraph;
use crate::common::{BuiltInlineTestProject, InlineTestProject};
use crate::value_flow_conformance::{
    ExpectedSinkOutcome, ProcedureSelector, ResolvedValueFlowConformanceCase,
    ValueFlowConformanceCase, assert_resolved_value_flow_conformance, direct_solver_work,
    direct_witness_symbol_sequences, resolve_value_flow_conformance_case,
};
use crate::value_flow_scenarios::{
    DirectReadyValueFlowScenario, assert_direct_ready_value_flow_scenario_inventory,
    direct_ready_value_flow_scenario_entries, with_java_ambiguous_call_negative,
    with_java_branch_merge, with_java_capture_flow, with_java_cleanup_flow, with_java_early_return,
    with_java_exact_helper, with_java_exceptional_flow, with_java_field_access_flow,
    with_java_field_alias_flow, with_java_index_access_flow, with_java_loop_exit,
    with_java_over_bound_field_flow, with_java_receiver_flow, with_java_split_exact_helper,
    with_java_two_matched_calls, with_java_unresolved_call_negative,
    with_typescript_ambiguous_call_negative, with_typescript_branch_merge,
    with_typescript_capture_flow, with_typescript_cleanup_flow, with_typescript_early_return,
    with_typescript_exceptional_flow, with_typescript_field_access_flow,
    with_typescript_field_alias_flow, with_typescript_index_access_flow, with_typescript_loop_exit,
    with_typescript_over_bound_field_flow, with_typescript_receiver_flow,
    with_typescript_two_matched_calls, with_typescript_unresolved_call_negative,
};

const WORKSPACE_GENERATION: u64 = 23;
const PLAN_REF: &str = "test:request-to-sink";
const SHARED_PLAN_REF: &str = "test:shared-helper-flow";
const SHARED_WITNESS_PLAN_REF: &str = "test:shared-helper-flow-witness";
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
        "schema_version": 1,
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
        "schema_version": 1,
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
        "schema_version": 1,
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
fn fact_only_solver_budget_inventory_classifies_every_dimension() {
    with_java_exact_helper(|case| {
        let resolved = resolve_value_flow_conformance_case(case);
        let exact_work = direct_solver_work(&resolved);
        let incomplete_work = with_java_unresolved_call_negative(|case| {
            direct_solver_work(&resolve_value_flow_conformance_case(case))
        });
        let fact_only = [
            SolverBudgetDimension::InternedFacts,
            SolverBudgetDimension::ReachedStates,
            SolverBudgetDimension::FlowEvaluations,
            SolverBudgetDimension::CallbackRows,
            SolverBudgetDimension::PropagatedOutputs,
            SolverBudgetDimension::EndSummaries,
            SolverBudgetDimension::IncomingCalls,
            SolverBudgetDimension::ProviderMaterializations,
            SolverBudgetDimension::SummaryApplications,
            SolverBudgetDimension::CoverageRows,
            SolverBudgetDimension::WitnessRelations,
        ];
        let ide_only = [
            SolverBudgetDimension::IdeRelations,
            SolverBudgetDimension::EdgeFunctions,
            SolverBudgetDimension::EdgeFunctionOperations,
            SolverBudgetDimension::IdeValues,
            SolverBudgetDimension::ValueOperations,
            SolverBudgetDimension::IdePropagations,
        ];
        assert!(
            fact_only.into_iter().all(|dimension| {
                exact_work.get(dimension) > 0 || incomplete_work.get(dimension) > 0
            }),
            "fact-only value-flow scenarios must charge every applicable dimension: exact={exact_work:#?}; incomplete={incomplete_work:#?}"
        );
        assert!(
            ide_only.into_iter().all(|dimension| {
                exact_work.get(dimension) == 0 && incomplete_work.get(dimension) == 0
            }),
            "fact-only value flow must explicitly leave IDE-only dimensions unused: exact={exact_work:#?}; incomplete={incomplete_work:#?}"
        );
    });
}

#[test]
fn every_fact_only_solver_budget_has_an_exact_public_boundary() {
    with_java_exact_helper(|case| {
        assert_solver_budget_boundaries(
            case,
            &[
                SolverBudgetDimension::InternedFacts,
                SolverBudgetDimension::ReachedStates,
                SolverBudgetDimension::FlowEvaluations,
                SolverBudgetDimension::CallbackRows,
                SolverBudgetDimension::PropagatedOutputs,
                SolverBudgetDimension::EndSummaries,
                SolverBudgetDimension::IncomingCalls,
                SolverBudgetDimension::ProviderMaterializations,
                SolverBudgetDimension::SummaryApplications,
            ],
        );
    });
    with_java_unresolved_call_negative(|case| {
        assert_solver_budget_boundaries(case, &[SolverBudgetDimension::CoverageRows]);
    });
}

#[test]
fn witness_relation_solver_budget_proves_its_minimum_public_boundary() {
    with_java_exact_helper(|case| {
        let resolved = resolve_value_flow_conformance_case(case);
        let mut registrations = ValueFlowPlanRegistrationSet::default();
        registrations
            .register(
                PLAN_REF.parse().unwrap(),
                ValueFlowPlanRegistration::new(WORKSPACE_GENERATION, Arc::clone(&resolved.plan)),
            )
            .unwrap();
        let summaries = Arc::new(ProductionTypestateSummaryRepository::new());

        let exact = execute_solver_limit(
            &resolved,
            &registrations,
            &summaries,
            SolverBudgetDimension::WitnessRelations,
            1,
        );
        assert!(
            !has_diagnostic(&exact["result"], "value_flow_solver_budget_exhausted"),
            "minimum positive witness-relation boundary: {exact:#}"
        );

        let invalid = execute_solver_limit(
            &resolved,
            &registrations,
            &summaries,
            SolverBudgetDimension::WitnessRelations,
            0,
        );
        assert!(
            has_diagnostic(&invalid, "invalid_plan"),
            "one step beyond the minimum valid witness-relation limit: {invalid:#}"
        );
        assert!(invalid["results"].as_array().unwrap().is_empty());
    });
}

#[derive(Debug, Clone, Copy)]
enum RequestBudgetDimension {
    ScannedFiles,
    ScannedSourceBytes,
    FactNodes,
    PipelineRows,
    SemanticMaterializedFiles,
    SemanticSourceBytes,
    SemanticRows,
    SemanticRetainedBytes,
    SemanticTraversalSteps,
}

impl RequestBudgetDimension {
    const ALL: [Self; 9] = [
        Self::ScannedFiles,
        Self::ScannedSourceBytes,
        Self::FactNodes,
        Self::PipelineRows,
        Self::SemanticMaterializedFiles,
        Self::SemanticSourceBytes,
        Self::SemanticRows,
        Self::SemanticRetainedBytes,
        Self::SemanticTraversalSteps,
    ];

    const fn label(self) -> &'static str {
        match self {
            Self::ScannedFiles => "scanned files",
            Self::ScannedSourceBytes => "scanned source bytes",
            Self::FactNodes => "fact nodes",
            Self::PipelineRows => "pipeline rows",
            Self::SemanticMaterializedFiles => "semantic materialized files",
            Self::SemanticSourceBytes => "semantic source bytes",
            Self::SemanticRows => "semantic rows per dimension",
            Self::SemanticRetainedBytes => "semantic retained bytes",
            Self::SemanticTraversalSteps => "semantic traversal steps",
        }
    }

    const fn expected_diagnostic(self) -> &'static str {
        match self {
            Self::ScannedFiles | Self::ScannedSourceBytes | Self::FactNodes => {
                "execution_budget_exhausted"
            }
            Self::PipelineRows => "pipeline_budget_exhausted",
            Self::SemanticMaterializedFiles
            | Self::SemanticSourceBytes
            | Self::SemanticRows
            | Self::SemanticRetainedBytes
            | Self::SemanticTraversalSteps => "semantic_budget_exhausted",
        }
    }

    const fn upper_limit(self, limits: &CodeQueryExecutionLimits) -> usize {
        match self {
            Self::ScannedFiles => limits.max_scanned_files,
            Self::ScannedSourceBytes => limits.max_scanned_source_bytes,
            Self::FactNodes => limits.max_fact_nodes,
            Self::PipelineRows => limits.max_pipeline_rows,
            Self::SemanticMaterializedFiles => limits.semantic.max_materialized_files,
            Self::SemanticSourceBytes => limits.semantic.max_source_bytes,
            Self::SemanticRows => limits.semantic.max_rows_per_dimension,
            Self::SemanticRetainedBytes => limits.semantic.max_retained_bytes,
            Self::SemanticTraversalSteps => limits.semantic.max_traversal_steps,
        }
    }

    fn set_limit(self, limits: &mut CodeQueryExecutionLimits, limit: usize) {
        match self {
            Self::ScannedFiles => limits.max_scanned_files = limit,
            Self::ScannedSourceBytes => limits.max_scanned_source_bytes = limit,
            Self::FactNodes => limits.max_fact_nodes = limit,
            Self::PipelineRows => limits.max_pipeline_rows = limit,
            Self::SemanticMaterializedFiles => limits.semantic.max_materialized_files = limit,
            Self::SemanticSourceBytes => limits.semantic.max_source_bytes = limit,
            Self::SemanticRows => limits.semantic.max_rows_per_dimension = limit,
            Self::SemanticRetainedBytes => limits.semantic.max_retained_bytes = limit,
            Self::SemanticTraversalSteps => limits.semantic.max_traversal_steps = limit,
        }
    }

    const fn is_semantic(self) -> bool {
        matches!(
            self,
            Self::SemanticMaterializedFiles
                | Self::SemanticSourceBytes
                | Self::SemanticRows
                | Self::SemanticRetainedBytes
                | Self::SemanticTraversalSteps
        )
    }
}

#[test]
fn outer_and_semantic_budget_inventory_has_exact_public_boundaries() {
    with_java_split_exact_helper(|case| {
        let resolved = resolve_value_flow_conformance_case(case);
        let mut registrations = ValueFlowPlanRegistrationSet::default();
        registrations
            .register(
                PLAN_REF.parse().unwrap(),
                ValueFlowPlanRegistration::new(WORKSPACE_GENERATION, Arc::clone(&resolved.plan)),
            )
            .unwrap();
        let summaries = Arc::new(ProductionTypestateSummaryRepository::new());
        let query = profiled_shared_scenario_query(case, PLAN_REF, false);

        for dimension in RequestBudgetDimension::ALL {
            let defaults = CodeQueryExecutionLimits::default();
            let upper_limit = dimension.upper_limit(&defaults);
            let mut low = 1;
            let mut high = upper_limit;
            while low < high {
                let middle = low + (high - low) / 2;
                let response = execute_request_budget_limit(
                    &resolved,
                    &registrations,
                    &summaries,
                    &query,
                    dimension,
                    middle,
                );
                if has_diagnostic(&response["result"], dimension.expected_diagnostic()) {
                    low = middle + 1;
                } else {
                    high = middle;
                }
            }
            let boundary = low;
            assert!(
                boundary > 0,
                "{} must have a positive boundary",
                dimension.label()
            );
            let exact = execute_request_budget_limit(
                &resolved,
                &registrations,
                &summaries,
                &query,
                dimension,
                boundary,
            );
            assert!(
                !has_diagnostic(&exact["result"], dimension.expected_diagnostic()),
                "{} exact boundary {boundary}: {exact:#}",
                dimension.label()
            );

            if boundary == 1 && dimension.is_semantic() {
                let invalid = execute_request_budget_limit(
                    &resolved,
                    &registrations,
                    &summaries,
                    &query,
                    dimension,
                    0,
                );
                assert!(
                    has_diagnostic(&invalid, dimension.expected_diagnostic()),
                    "{} one below the minimum valid limit: {invalid:#}",
                    dimension.label()
                );
                assert!(invalid["results"].as_array().unwrap().is_empty());
                assert_eq!(invalid["truncated"], true);
                continue;
            }

            let exceeded = execute_request_budget_limit(
                &resolved,
                &registrations,
                &summaries,
                &query,
                dimension,
                boundary - 1,
            );
            assert!(
                has_diagnostic(&exceeded["result"], dimension.expected_diagnostic()),
                "{} one beyond {}: {exceeded:#}",
                dimension.label(),
                boundary - 1
            );
            assert!(
                exceeded["result"]["results"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|row| row["reachability"] != "not_reached"
                        || row["completion"] != "complete"),
                "{} exhaustion became a clean negative: {exceeded:#}",
                dimension.label()
            );
            if dimension.is_semantic() {
                assert_eq!(
                    exceeded.pointer("/work/semantic/budget_exhausted"),
                    Some(&json!(true))
                );
            } else {
                assert_eq!(exceeded["result"]["truncated"], true);
            }
        }
    });
}

fn execute_request_budget_limit(
    resolved: &ResolvedValueFlowConformanceCase,
    registrations: &ValueFlowPlanRegistrationSet,
    summaries: &Arc<ProductionTypestateSummaryRepository>,
    query: &CodeQuery,
    dimension: RequestBudgetDimension,
    limit: usize,
) -> serde_json::Value {
    let mut limits = CodeQueryExecutionLimits::default();
    dimension.set_limit(&mut limits, limit);
    let result = execute_workspace_request_with_analysis_registration_lease(
        &resolved.analyzer,
        WORKSPACE_GENERATION,
        &ProtocolRegistrationSet::default(),
        registrations,
        query,
        limits,
        None,
        summaries.lease(WORKSPACE_GENERATION).unwrap(),
    );
    serde_json::to_value(result).unwrap()
}

#[derive(Debug, Clone, Copy)]
enum RetentionBudgetDimension {
    Relations,
    Bytes,
}

impl RetentionBudgetDimension {
    const ALL: [Self; 2] = [Self::Relations, Self::Bytes];

    const fn label(self) -> &'static str {
        match self {
            Self::Relations => "retained witness relations",
            Self::Bytes => "retained witness bytes",
        }
    }

    const fn upper_limit(self, limits: &CodeQueryExecutionLimits) -> usize {
        match self {
            Self::Relations => limits.value_flow.max_retained_relations,
            Self::Bytes => limits.value_flow.max_retained_bytes,
        }
    }

    fn set_limit(self, limits: &mut CodeQueryExecutionLimits, limit: usize) {
        match self {
            Self::Relations => limits.value_flow.max_retained_relations = limit,
            Self::Bytes => limits.value_flow.max_retained_bytes = limit,
        }
    }
}

#[test]
fn retained_witness_budget_inventory_has_exact_contiguous_boundaries() {
    with_java_exact_helper(|case| {
        let resolved = resolve_value_flow_conformance_case(case);
        let mut registrations = ValueFlowPlanRegistrationSet::default();
        registrations
            .register(
                PLAN_REF.parse().unwrap(),
                ValueFlowPlanRegistration::new(
                    WORKSPACE_GENERATION,
                    Arc::clone(&resolved.witness_plan),
                ),
            )
            .unwrap();
        let summaries = Arc::new(ProductionTypestateSummaryRepository::new());
        let query = profiled_shared_scenario_query(case, PLAN_REF, true);

        for dimension in RetentionBudgetDimension::ALL {
            let defaults = CodeQueryExecutionLimits::default();
            let mut low = 1;
            let mut high = dimension.upper_limit(&defaults);
            while low < high {
                let middle = low + (high - low) / 2;
                let response = execute_retention_budget_limit(
                    &resolved,
                    &registrations,
                    &summaries,
                    &query,
                    dimension,
                    middle,
                );
                if public_witnesses_complete(&response) {
                    high = middle;
                } else {
                    low = middle + 1;
                }
            }
            let boundary = low;
            assert!(
                boundary > 1,
                "{} must have a truncating one-beyond limit",
                dimension.label()
            );
            let exact = execute_retention_budget_limit(
                &resolved,
                &registrations,
                &summaries,
                &query,
                dimension,
                boundary,
            );
            assert!(
                public_witnesses_complete(&exact),
                "{} exact boundary {boundary}: {exact:#}",
                dimension.label()
            );

            let exceeded = execute_retention_budget_limit(
                &resolved,
                &registrations,
                &summaries,
                &query,
                dimension,
                boundary - 1,
            );
            let exact_steps = &exact["result"]["results"][0]["steps"];
            let exceeded_rows = exceeded["result"]["results"].as_array().unwrap();
            assert!(
                !exceeded_rows.is_empty(),
                "{} must retain a deterministic partial witness: {exceeded:#}",
                dimension.label()
            );
            for witness in exceeded_rows {
                assert_eq!(witness["retention_truncated"], true, "{exceeded:#}");
                assert_eq!(witness["truncated"], true, "{exceeded:#}");
                assert_eq!(witness["quality"]["completeness"], "partial");
                assert_contiguous_step_prefix(exact_steps, &witness["steps"]);
            }
            assert!(
                has_diagnostic(&exceeded["result"], "value_flow_analysis_partial"),
                "{} truncation diagnostic: {exceeded:#}",
                dimension.label()
            );
            assert!(
                has_diagnostic(&exceeded["result"], "value_flow_witness_truncated"),
                "{} typed witness diagnostic: {exceeded:#}",
                dimension.label()
            );
            assert_eq!(
                exceeded.pointer("/work/semantic/value_flow/witness_truncated"),
                Some(&json!(true))
            );
            assert!(
                exceeded["result"]["results"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|row| row["reachability"] != "not_reached"
                        || row["completion"] != "complete"),
                "{} retention exhaustion became a clean negative: {exceeded:#}",
                dimension.label()
            );
        }
    });
}

fn execute_retention_budget_limit(
    resolved: &ResolvedValueFlowConformanceCase,
    registrations: &ValueFlowPlanRegistrationSet,
    summaries: &Arc<ProductionTypestateSummaryRepository>,
    query: &CodeQuery,
    dimension: RetentionBudgetDimension,
    limit: usize,
) -> serde_json::Value {
    let mut limits = CodeQueryExecutionLimits::default();
    dimension.set_limit(&mut limits, limit);
    let result = execute_workspace_request_with_analysis_registration_lease(
        &resolved.analyzer,
        WORKSPACE_GENERATION,
        &ProtocolRegistrationSet::default(),
        registrations,
        query,
        limits,
        None,
        summaries.lease(WORKSPACE_GENERATION).unwrap(),
    );
    serde_json::to_value(result).unwrap()
}

fn public_witnesses_complete(response: &serde_json::Value) -> bool {
    response["result"]["results"]
        .as_array()
        .is_some_and(|rows| {
            !rows.is_empty()
                && rows.iter().all(|row| {
                    !row["truncated"].as_bool().unwrap_or(false)
                        && !row["retention_truncated"].as_bool().unwrap_or(false)
                })
        })
}

fn assert_contiguous_step_prefix(full: &serde_json::Value, retained: &serde_json::Value) {
    let full = full.as_array().unwrap();
    let retained = retained.as_array().unwrap();
    assert!(retained.len() <= full.len());
    assert_eq!(retained, &full[..retained.len()]);
}

#[derive(Debug, Clone, Copy)]
enum ProjectionBudgetDimension {
    Endpoints,
    Witnesses,
    WitnessSteps,
    WitnessExpansions,
    WitnessBytes,
    TotalWitnessSteps,
    TotalWitnessExpansions,
    TotalWitnessBytes,
}

impl ProjectionBudgetDimension {
    const ALL: [Self; 8] = [
        Self::Endpoints,
        Self::Witnesses,
        Self::WitnessSteps,
        Self::WitnessExpansions,
        Self::WitnessBytes,
        Self::TotalWitnessSteps,
        Self::TotalWitnessExpansions,
        Self::TotalWitnessBytes,
    ];

    const fn label(self) -> &'static str {
        match self {
            Self::Endpoints => "endpoint count",
            Self::Witnesses => "witness count",
            Self::WitnessSteps => "per-witness steps",
            Self::WitnessExpansions => "per-witness expansions",
            Self::WitnessBytes => "per-witness bytes",
            Self::TotalWitnessSteps => "aggregate witness steps",
            Self::TotalWitnessExpansions => "aggregate witness expansions",
            Self::TotalWitnessBytes => "aggregate witness bytes",
        }
    }

    const fn upper_limit(self, limits: &CodeQueryExecutionLimits) -> usize {
        match self {
            Self::Endpoints => limits.value_flow.max_endpoints,
            Self::Witnesses => limits.value_flow.max_witnesses,
            Self::WitnessSteps => limits.value_flow.max_witness_steps,
            Self::WitnessExpansions => limits.value_flow.max_witness_expansions,
            Self::WitnessBytes => limits.value_flow.max_witness_bytes,
            Self::TotalWitnessSteps => limits.value_flow.max_total_witness_steps,
            Self::TotalWitnessExpansions => limits.value_flow.max_total_witness_expansions,
            Self::TotalWitnessBytes => limits.value_flow.max_total_witness_bytes,
        }
    }

    fn set_limit(self, limits: &mut CodeQueryExecutionLimits, limit: usize) {
        match self {
            Self::Endpoints => limits.value_flow.max_endpoints = limit,
            Self::Witnesses => limits.value_flow.max_witnesses = limit,
            Self::WitnessSteps => limits.value_flow.max_witness_steps = limit,
            Self::WitnessExpansions => limits.value_flow.max_witness_expansions = limit,
            Self::WitnessBytes => limits.value_flow.max_witness_bytes = limit,
            Self::TotalWitnessSteps => limits.value_flow.max_total_witness_steps = limit,
            Self::TotalWitnessExpansions => limits.value_flow.max_total_witness_expansions = limit,
            Self::TotalWitnessBytes => limits.value_flow.max_total_witness_bytes = limit,
        }
    }

    const fn expected_diagnostic(self) -> &'static str {
        match self {
            Self::Endpoints => "pipeline_budget_exhausted",
            Self::Witnesses
            | Self::WitnessSteps
            | Self::WitnessExpansions
            | Self::WitnessBytes
            | Self::TotalWitnessSteps
            | Self::TotalWitnessExpansions
            | Self::TotalWitnessBytes => "value_flow_witness_truncated",
        }
    }

    const fn uses_witness_query(self) -> bool {
        !matches!(self, Self::Endpoints)
    }
}

#[test]
fn endpoint_and_witness_budget_inventory_has_exact_contiguous_boundaries() {
    let fixture = Fixture::with_shape(
        ProofStatus::Proven,
        EvidenceCompleteness::Complete,
        Some(SemanticInputStatus::Complete),
        true,
        2,
    );

    for dimension in ProjectionBudgetDimension::ALL {
        let query = profiled_query(dimension.uses_witness_query());
        let defaults = CodeQueryExecutionLimits::default();
        let mut low = 1;
        let mut high = dimension.upper_limit(&defaults);
        while low < high {
            let middle = low + (high - low) / 2;
            let response = execute_projection_budget_limit(&fixture, &query, dimension, middle);
            if projection_is_complete(&response, dimension, 2) {
                high = middle;
            } else {
                low = middle + 1;
            }
        }
        let boundary = low;
        assert!(
            boundary > 1,
            "{} must permit a truncating one-beyond limit",
            dimension.label()
        );
        let exact = execute_projection_budget_limit(&fixture, &query, dimension, boundary);
        assert!(
            projection_is_complete(&exact, dimension, 2),
            "{} exact boundary {boundary}: {exact:#}",
            dimension.label()
        );

        let exceeded = execute_projection_budget_limit(&fixture, &query, dimension, boundary - 1);
        assert!(
            has_diagnostic(&exceeded["result"], dimension.expected_diagnostic()),
            "{} one beyond {}: {exceeded:#}",
            dimension.label(),
            boundary - 1
        );
        assert!(
            !projection_is_complete(&exceeded, dimension, 2),
            "{} one-beyond limit remained complete: {exceeded:#}",
            dimension.label()
        );
        if matches!(dimension, ProjectionBudgetDimension::Endpoints) {
            assert_eq!(
                exceeded.pointer("/work/semantic/value_flow/endpoint_truncated"),
                Some(&json!(true))
            );
            assert!(
                exceeded
                    .pointer("/work/semantic/value_flow/omitted_endpoints")
                    .and_then(serde_json::Value::as_u64)
                    .is_some_and(|omitted| omitted >= 1)
            );
            continue;
        }

        assert_eq!(
            exceeded.pointer("/work/semantic/value_flow/witness_truncated"),
            Some(&json!(true))
        );
        let exact_rows = exact["result"]["results"].as_array().unwrap();
        let exceeded_rows = exceeded["result"]["results"].as_array().unwrap();
        for witness in exceeded_rows {
            let full = exact_rows
                .iter()
                .find(|row| row["endpoint_id"] == witness["endpoint_id"])
                .expect("same endpoint in exact witness set");
            assert_contiguous_step_prefix(&full["steps"], &witness["steps"]);
            if witness["truncated"].as_bool().unwrap_or(false) {
                assert!(
                    witness["omitted_steps_lower_bound"]
                        .as_u64()
                        .is_some_and(|omitted| omitted >= 1),
                    "{} omitted step lower bound: {witness:#}",
                    dimension.label()
                );
            }
        }
        if matches!(dimension, ProjectionBudgetDimension::Witnesses) {
            assert!(
                exceeded
                    .pointer("/work/semantic/value_flow/omitted_witnesses")
                    .and_then(serde_json::Value::as_u64)
                    .is_some_and(|omitted| omitted >= 1)
            );
        }
    }
}

fn execute_projection_budget_limit(
    fixture: &Fixture,
    query: &CodeQuery,
    dimension: ProjectionBudgetDimension,
    limit: usize,
) -> serde_json::Value {
    let mut limits = CodeQueryExecutionLimits::default();
    dimension.set_limit(&mut limits, limit);
    fixture.execute(query, limits)
}

fn projection_is_complete(
    response: &serde_json::Value,
    dimension: ProjectionBudgetDimension,
    expected_rows: usize,
) -> bool {
    let Some(rows) = response["result"]["results"].as_array() else {
        return false;
    };
    if rows.len() != expected_rows {
        return false;
    }
    if matches!(dimension, ProjectionBudgetDimension::Endpoints) {
        return !response["result"]["truncated"].as_bool().unwrap_or(false);
    }
    !response
        .pointer("/work/semantic/value_flow/witness_truncated")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
        && rows
            .iter()
            .all(|row| !row["truncated"].as_bool().unwrap_or(false))
}

#[test]
fn query_local_witness_clamps_have_exact_contiguous_boundaries() {
    let fixture = Fixture::new(ProofStatus::Proven, EvidenceCompleteness::Complete);
    let baseline = fixture.execute(
        &profiled_witness_query(16_384, 16 * 1024 * 1024),
        CodeQueryExecutionLimits::default(),
    );
    let baseline_witness = &baseline["result"]["results"][0];
    let exact_steps = baseline_witness["steps"].as_array().unwrap().len();
    let exact_bytes = baseline_witness["retained_bytes"].as_u64().unwrap() as usize;
    assert!(exact_steps > 1);
    assert!(exact_bytes > 1);

    for (label, exact_limit, query) in [
        (
            "query-local witness steps",
            exact_steps,
            profiled_witness_query(exact_steps, 16 * 1024 * 1024),
        ),
        (
            "query-local witness bytes",
            exact_bytes,
            profiled_witness_query(16_384, exact_bytes),
        ),
    ] {
        let exact = fixture.execute(&query, CodeQueryExecutionLimits::default());
        assert!(
            !exact["result"]["results"][0]["truncated"]
                .as_bool()
                .unwrap_or(false),
            "{label}: {exact:#}"
        );
        assert_eq!(
            exact["result"]["results"][0]["steps"], baseline_witness["steps"],
            "{label} exact boundary"
        );

        let exceeded_query = if label.ends_with("steps") {
            profiled_witness_query(exact_limit - 1, 16 * 1024 * 1024)
        } else {
            profiled_witness_query(16_384, exact_limit - 1)
        };
        let exceeded = fixture.execute(&exceeded_query, CodeQueryExecutionLimits::default());
        let witness = &exceeded["result"]["results"][0];
        assert_eq!(witness["truncated"], true, "{label}: {exceeded:#}");
        assert_eq!(witness["quality"]["completeness"], "partial");
        assert!(
            witness["omitted_steps_lower_bound"]
                .as_u64()
                .is_some_and(|omitted| omitted >= 1)
        );
        assert_contiguous_step_prefix(&baseline_witness["steps"], &witness["steps"]);
        assert!(has_diagnostic(
            &exceeded["result"],
            "value_flow_witness_truncated"
        ));
        assert_eq!(
            exceeded.pointer("/work/semantic/value_flow/witness_truncated"),
            Some(&json!(true))
        );
    }
}

fn profiled_witness_query(max_steps: usize, max_bytes: usize) -> CodeQuery {
    CodeQuery::from_json(&json!({
        "schema_version": 1,
        "execution_mode": "profile",
        "match": {"kind": "method", "name": "run"},
        "steps": [
            {"op": "procedure_of"},
            {"op": "value_flow", "plan_ref": PLAN_REF},
            {"op": "witness", "max_steps": max_steps, "max_bytes": max_bytes}
        ]
    }))
    .unwrap()
}

#[test]
fn cancellation_checkpoints_preserve_typed_phase_evidence() {
    let fixture = Fixture::new(ProofStatus::Proven, EvidenceCompleteness::Complete);
    let query = profiled_query(true);
    let mut semantic_cancelled = None;
    let mut solver_cancelled = None;
    let mut before_witness_cancelled = None;

    for checks in 1..=256 {
        let cancellation = CancellationToken::cancel_after_checks_for_test(checks);
        let response = fixture.execute_with_cancellation(
            &query,
            CodeQueryExecutionLimits::default(),
            Some(&cancellation),
        );
        let result = &response["result"];
        if !has_diagnostic(result, "cancelled") {
            continue;
        }
        let solves = profile_u64(&response, "/work/semantic/value_flow/solves");
        let cancelled_solves = profile_u64(&response, "/work/semantic/value_flow/cancelled_solves");
        let fixed_point_solves =
            profile_u64(&response, "/work/semantic/value_flow/fixed_point_solves");
        let witnesses = profile_u64(&response, "/work/semantic/value_flow/witnesses");
        let materialization_attempts =
            profile_u64(&response, "/work/semantic/materialization_attempts");

        if semantic_cancelled.is_none() && materialization_attempts > 0 && solves == 0 {
            semantic_cancelled = Some(response.clone());
        }
        if solver_cancelled.is_none() && cancelled_solves == 1 {
            solver_cancelled = Some(response.clone());
        }
        if before_witness_cancelled.is_none() && fixed_point_solves == 1 && witnesses == 0 {
            before_witness_cancelled = Some(response);
        }
        if semantic_cancelled.is_some()
            && solver_cancelled.is_some()
            && before_witness_cancelled.is_some()
        {
            break;
        }
    }

    for (phase, response) in [
        (
            "semantic materialization",
            semantic_cancelled.expect("deterministic semantic cancellation checkpoint"),
        ),
        (
            "solver",
            solver_cancelled.expect("deterministic solver cancellation checkpoint"),
        ),
        (
            "between solving and witness reconstruction",
            before_witness_cancelled.expect("deterministic witness cancellation checkpoint"),
        ),
    ] {
        assert!(
            has_diagnostic(&response["result"], "cancelled"),
            "{phase}: {response:#}"
        );
        assert!(
            response["result"]["results"]
                .as_array()
                .unwrap()
                .iter()
                .all(|row| row["reachability"] != "not_reached" || row["completion"] != "complete"),
            "{phase} cancellation became a clean negative: {response:#}"
        );
    }
}

fn profile_u64(response: &serde_json::Value, pointer: &str) -> u64 {
    response
        .pointer(pointer)
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0)
}

fn assert_solver_budget_boundaries(
    case: &ValueFlowConformanceCase<'_>,
    dimensions: &[SolverBudgetDimension],
) {
    let resolved = resolve_value_flow_conformance_case(case);
    let used = direct_solver_work(&resolved);
    let mut registrations = ValueFlowPlanRegistrationSet::default();
    registrations
        .register(
            PLAN_REF.parse().unwrap(),
            ValueFlowPlanRegistration::new(WORKSPACE_GENERATION, Arc::clone(&resolved.plan)),
        )
        .unwrap();
    let summaries = Arc::new(ProductionTypestateSummaryRepository::new());
    for &dimension in dimensions {
        let upper_bound = used.get(dimension);
        assert!(
            upper_bound > 1,
            "{} {} must have a positive search bound: {used:#?}",
            case.name,
            dimension.label()
        );
        let upper = execute_solver_limit(
            &resolved,
            &registrations,
            &summaries,
            dimension,
            upper_bound,
        );
        assert!(
            !has_diagnostic(&upper["result"], "value_flow_solver_budget_exhausted"),
            "{} {} direct-work upper bound: {upper:#}",
            case.name,
            dimension.label()
        );
        let mut low = 1;
        let mut high = upper_bound;
        while low < high {
            let middle = low + (high - low) / 2;
            let result =
                execute_solver_limit(&resolved, &registrations, &summaries, dimension, middle);
            if has_diagnostic(&result["result"], "value_flow_solver_budget_exhausted") {
                low = middle + 1;
            } else {
                high = middle;
            }
        }
        let boundary = low;
        assert!(
            boundary > 1,
            "{} {} has no valid one-beyond limit",
            case.name,
            dimension.label()
        );
        let exact =
            execute_solver_limit(&resolved, &registrations, &summaries, dimension, boundary);
        assert!(
            !has_diagnostic(&exact["result"], "value_flow_solver_budget_exhausted"),
            "{} {} exact boundary: {exact:#}",
            case.name,
            dimension.label()
        );

        let exceeded = execute_solver_limit(
            &resolved,
            &registrations,
            &summaries,
            dimension,
            boundary - 1,
        );
        assert!(
            has_diagnostic(&exceeded["result"], "value_flow_solver_budget_exhausted"),
            "{} {} one beyond: {exceeded:#}",
            case.name,
            dimension.label()
        );
        assert_eq!(
            exceeded.pointer("/work/semantic/value_flow/budget_exhausted_solves"),
            Some(&json!(1)),
            "{} {} profile counter",
            case.name,
            dimension.label()
        );
        assert!(
            exceeded["result"]["results"]
                .as_array()
                .unwrap()
                .iter()
                .all(|row| row["reachability"] != "not_reached" || row["completion"] != "complete"),
            "{} {} exhaustion became a clean negative: {exceeded:#}",
            case.name,
            dimension.label()
        );
    }
}

fn execute_solver_limit(
    resolved: &ResolvedValueFlowConformanceCase,
    registrations: &ValueFlowPlanRegistrationSet,
    summaries: &Arc<ProductionTypestateSummaryRepository>,
    dimension: SolverBudgetDimension,
    limit: usize,
) -> serde_json::Value {
    let mut limits = CodeQueryExecutionLimits::default();
    set_solver_limit(&mut limits.value_flow.solver_work, dimension, limit);
    let result = execute_workspace_request_with_analysis_registration_lease(
        &resolved.analyzer,
        WORKSPACE_GENERATION,
        &ProtocolRegistrationSet::default(),
        registrations,
        &profiled_query(false),
        limits,
        None,
        summaries.lease(WORKSPACE_GENERATION).unwrap(),
    );
    serde_json::to_value(result).unwrap()
}

fn has_diagnostic(response: &serde_json::Value, code: &str) -> bool {
    response["diagnostics"]
        .as_array()
        .is_some_and(|diagnostics| {
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic["code"] == code)
        })
}

fn set_solver_limit(work: &mut SolverWork, dimension: SolverBudgetDimension, limit: usize) {
    match dimension {
        SolverBudgetDimension::InternedFacts => work.interned_facts = limit,
        SolverBudgetDimension::ReachedStates => work.reached_states = limit,
        SolverBudgetDimension::FlowEvaluations => work.flow_evaluations = limit,
        SolverBudgetDimension::CallbackRows => work.callback_rows = limit,
        SolverBudgetDimension::PropagatedOutputs => work.propagated_outputs = limit,
        SolverBudgetDimension::EndSummaries => work.end_summaries = limit,
        SolverBudgetDimension::IncomingCalls => work.incoming_calls = limit,
        SolverBudgetDimension::ProviderMaterializations => work.provider_materializations = limit,
        SolverBudgetDimension::SummaryApplications => work.summary_applications = limit,
        SolverBudgetDimension::CoverageRows => work.coverage_rows = limit,
        SolverBudgetDimension::WitnessRelations => work.witness_relations = limit,
        SolverBudgetDimension::IdeRelations => work.ide_relations = limit,
        SolverBudgetDimension::EdgeFunctions => work.edge_functions = limit,
        SolverBudgetDimension::EdgeFunctionOperations => work.edge_function_operations = limit,
        SolverBudgetDimension::IdeValues => work.ide_values = limit,
        SolverBudgetDimension::ValueOperations => work.value_operations = limit,
        SolverBudgetDimension::IdePropagations => work.ide_propagations = limit,
    }
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
        "schema_version": 1,
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

macro_rules! define_public_direct_ready_value_flow_tests {
    ($(($scenario:ident, $direct_test:ident, $public_test:ident),)*) => {
        $(
            #[test]
            fn $public_test() {
                let scenario = DirectReadyValueFlowScenario::$scenario;
                scenario.with_case(|case| {
                    let seed_kind = match scenario {
                        DirectReadyValueFlowScenario::Ruby => "function",
                        _ => shared_scenario_seed_kind(case),
                    };
                    assert_shared_helper_scenario_with_seed_kind(case, seed_kind);
                });
            }
        )*
    };
}
direct_ready_value_flow_scenario_entries!(define_public_direct_ready_value_flow_tests);

#[test]
fn direct_ready_value_flow_scenario_inventory_is_complete() {
    assert_direct_ready_value_flow_scenario_inventory();
}

#[test]
fn java_branch_merge_runs_through_direct_and_public_queries() {
    with_java_branch_merge(assert_shared_helper_scenario);
}

#[test]
fn typescript_branch_merge_runs_through_direct_and_public_queries() {
    with_typescript_branch_merge(assert_shared_helper_scenario);
}

#[test]
fn java_loop_exit_runs_through_direct_and_public_queries() {
    with_java_loop_exit(assert_shared_helper_scenario);
}

#[test]
fn typescript_loop_exit_runs_through_direct_and_public_queries() {
    with_typescript_loop_exit(assert_shared_helper_scenario);
}

#[test]
fn java_early_return_excludes_unreachable_public_meeting() {
    with_java_early_return(assert_shared_helper_scenario);
}

#[test]
fn typescript_early_return_excludes_unreachable_public_meeting() {
    with_typescript_early_return(assert_shared_helper_scenario);
}

#[test]
fn java_two_call_sites_preserve_matched_returns_in_public_query() {
    with_java_two_matched_calls(assert_shared_helper_scenario);
}

#[test]
fn typescript_two_call_sites_preserve_matched_returns_in_public_query() {
    with_typescript_two_matched_calls(assert_shared_helper_scenario);
}

#[test]
fn java_receiver_flow_preserves_public_receiver_symbols() {
    with_java_receiver_flow(assert_shared_helper_scenario);
}

#[test]
fn typescript_receiver_flow_preserves_public_receiver_symbols() {
    with_typescript_receiver_flow(assert_shared_helper_scenario);
}

#[test]
fn java_exceptional_flow_preserves_public_inconclusive_negative() {
    with_java_exceptional_flow(assert_shared_helper_scenario);
}

#[test]
fn typescript_exceptional_flow_preserves_public_exceptional_continuation_symbols() {
    with_typescript_exceptional_flow(assert_shared_helper_scenario);
}

#[test]
fn java_cleanup_flow_preserves_public_inconclusive_negative() {
    with_java_cleanup_flow(assert_shared_helper_scenario);
}

#[test]
fn typescript_cleanup_flow_preserves_public_inconclusive_negative() {
    with_typescript_cleanup_flow(assert_shared_helper_scenario);
}

#[test]
fn java_unresolved_capture_invocation_preserves_public_inconclusive_negative() {
    with_java_capture_flow(assert_shared_helper_scenario);
}

#[test]
fn typescript_unresolved_capture_invocation_preserves_public_inconclusive_negative() {
    with_typescript_capture_flow(assert_shared_helper_scenario);
}

#[test]
fn java_field_access_preserves_public_location_symbols() {
    with_java_field_access_flow(assert_shared_helper_scenario);
}

#[test]
fn typescript_field_access_preserves_public_location_symbols() {
    with_typescript_field_access_flow(assert_shared_helper_scenario);
}

#[test]
fn java_exact_indices_preserve_distinct_public_location_symbols() {
    with_java_index_access_flow(assert_shared_helper_scenario);
}

#[test]
fn typescript_exact_indices_preserve_distinct_public_location_symbols() {
    with_typescript_index_access_flow(assert_shared_helper_scenario);
}

#[test]
fn java_over_bound_access_path_preserves_public_summary_negative() {
    with_java_over_bound_field_flow(|case| {
        assert_shared_helper_scenario_with_status(
            case,
            SemanticInputStatus::Unsupported {
                capability: SemanticCapability::ExceptionalControlFlow,
            },
        );
    });
}

#[test]
fn typescript_over_bound_access_path_preserves_public_summary_negative() {
    with_typescript_over_bound_field_flow(|case| {
        assert_shared_helper_scenario_with_status(
            case,
            SemanticInputStatus::Unsupported {
                capability: SemanticCapability::ExceptionalControlFlow,
            },
        );
    });
}

#[test]
fn java_alias_field_flow_preserves_public_inconclusive_negative() {
    with_java_field_alias_flow(assert_shared_helper_scenario);
}

#[test]
fn typescript_alias_field_flow_preserves_public_inconclusive_negative() {
    with_typescript_field_alias_flow(assert_shared_helper_scenario);
}

#[test]
fn java_unresolved_call_preserves_public_inconclusive_negative() {
    with_java_unresolved_call_negative(assert_shared_helper_scenario);
}

#[test]
fn typescript_unresolved_call_preserves_public_inconclusive_negative() {
    with_typescript_unresolved_call_negative(assert_shared_helper_scenario);
}

#[test]
fn java_ambiguous_call_preserves_public_inconclusive_negative() {
    with_java_ambiguous_call_negative(assert_shared_helper_scenario);
}

#[test]
fn typescript_ambiguous_call_preserves_public_inconclusive_negative() {
    with_typescript_ambiguous_call_negative(assert_shared_helper_scenario);
}

fn assert_shared_helper_scenario(case: &ValueFlowConformanceCase<'_>) {
    assert_shared_helper_scenario_with_seed_kind_and_status(
        case,
        shared_scenario_seed_kind(case),
        case.expected_discovery_status,
    );
}

fn assert_shared_helper_scenario_with_status(
    case: &ValueFlowConformanceCase<'_>,
    expected_public_status: SemanticInputStatus,
) {
    assert_shared_helper_scenario_with_seed_kind_and_status(
        case,
        shared_scenario_seed_kind(case),
        expected_public_status,
    );
}

fn assert_shared_helper_scenario_with_seed_kind(
    case: &ValueFlowConformanceCase<'_>,
    seed_kind: &str,
) {
    assert_shared_helper_scenario_with_seed_kind_and_status(
        case,
        seed_kind,
        case.expected_discovery_status,
    );
}

fn assert_shared_helper_scenario_with_seed_kind_and_status(
    case: &ValueFlowConformanceCase<'_>,
    seed_kind: &str,
    expected_public_status: SemanticInputStatus,
) {
    let resolved = resolve_value_flow_conformance_case(case);
    assert_resolved_value_flow_conformance(case, &resolved);

    let mut registrations = ValueFlowPlanRegistrationSet::default();
    registrations
        .register(
            SHARED_PLAN_REF.parse().unwrap(),
            ValueFlowPlanRegistration::new(WORKSPACE_GENERATION, Arc::clone(&resolved.plan)),
        )
        .unwrap();
    registrations
        .register(
            SHARED_WITNESS_PLAN_REF.parse().unwrap(),
            ValueFlowPlanRegistration::new(
                WORKSPACE_GENERATION,
                Arc::clone(&resolved.witness_plan),
            ),
        )
        .unwrap();
    let summaries = Arc::new(ProductionTypestateSummaryRepository::new());

    let endpoints = execute_workspace_request_with_analysis_registration_lease(
        &resolved.analyzer,
        WORKSPACE_GENERATION,
        &ProtocolRegistrationSet::default(),
        &registrations,
        &shared_scenario_query_with_seed_kind(case, SHARED_PLAN_REF, false, seed_kind),
        CodeQueryExecutionLimits::default(),
        None,
        summaries.lease(WORKSPACE_GENERATION).unwrap(),
    );
    let endpoints = serde_json::to_value(endpoints).unwrap();
    let endpoints_rql = execute_workspace_request_with_analysis_registration_lease(
        &resolved.analyzer,
        WORKSPACE_GENERATION,
        &ProtocolRegistrationSet::default(),
        &registrations,
        &shared_scenario_rql_query_with_seed_kind(case, SHARED_PLAN_REF, false, seed_kind),
        CodeQueryExecutionLimits::default(),
        None,
        summaries.lease(WORKSPACE_GENERATION).unwrap(),
    );
    let endpoints_rql = serde_json::to_value(endpoints_rql).unwrap();
    assert_eq!(
        endpoints_rql, endpoints,
        "{} RQL and JSON endpoint responses",
        case.name
    );
    assert_public_sink_outcomes(case, &resolved, &endpoints, expected_public_status);

    let witnesses = execute_workspace_request_with_analysis_registration_lease(
        &resolved.analyzer,
        WORKSPACE_GENERATION,
        &ProtocolRegistrationSet::default(),
        &registrations,
        &shared_scenario_query_with_seed_kind(case, SHARED_WITNESS_PLAN_REF, true, seed_kind),
        CodeQueryExecutionLimits::default(),
        None,
        summaries.lease(WORKSPACE_GENERATION).unwrap(),
    );
    let witnesses = serde_json::to_value(witnesses).unwrap();
    let witnesses_rql = execute_workspace_request_with_analysis_registration_lease(
        &resolved.analyzer,
        WORKSPACE_GENERATION,
        &ProtocolRegistrationSet::default(),
        &registrations,
        &shared_scenario_rql_query_with_seed_kind(case, SHARED_WITNESS_PLAN_REF, true, seed_kind),
        CodeQueryExecutionLimits::default(),
        None,
        summaries.lease(WORKSPACE_GENERATION).unwrap(),
    );
    let witnesses_rql = serde_json::to_value(witnesses_rql).unwrap();
    assert_eq!(
        witnesses_rql, witnesses,
        "{} RQL and JSON witness responses",
        case.name
    );
    let rows = witnesses["results"].as_array().unwrap();
    let expected_symbols = direct_witness_symbol_sequences(case, &resolved);
    if case.expected_meetings.is_empty() {
        assert!(
            rows.is_empty(),
            "{} absent meetings must not produce public witnesses: {witnesses:#}",
            case.name
        );
        assert!(
            expected_symbols.is_empty(),
            "{} absent direct meetings must not produce witnesses",
            case.name
        );
        return;
    }
    assert!(
        !rows.is_empty(),
        "{} public witness rows: {witnesses:#}",
        case.name
    );
    for witness in rows {
        assert_eq!(witness["result_type"], "flow_witness", "{witnesses:#}");
        let steps = witness["steps"].as_array().unwrap();
        assert!(!steps.is_empty(), "{} empty public witness", case.name);
        assert!(
            steps.iter().all(|step| step.get("input").is_some()
                && step.get("output").is_some()
                && step.get("source_symbol").is_some()
                && (step.get("target").is_some() == step.get("target_symbol").is_some())
                && (step.get("origin").is_some() == step.get("origin_symbol").is_some())),
            "{} public witness lost fact symbols: {witnesses:#}",
            case.name
        );
        for step in steps {
            assert_public_symbol_site(&step["source_symbol"]);
            if let Some(target) = step.get("target_symbol") {
                assert_public_symbol_site(target);
            }
            if let Some(origin) = step.get("origin_symbol") {
                assert_public_symbol_site(origin);
            }
            assert_public_fact_symbol(&step["input"]);
            assert_public_fact_symbol(&step["output"]);
        }
    }
    let actual_symbols = rows
        .iter()
        .map(public_witness_symbol_sequence)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        actual_symbols, expected_symbols,
        "{} exact ordered public witness symbols",
        case.name
    );
}

fn shared_scenario_query(
    case: &ValueFlowConformanceCase<'_>,
    plan_ref: &str,
    with_witness: bool,
) -> CodeQuery {
    shared_scenario_query_with_seed_kind(
        case,
        plan_ref,
        with_witness,
        shared_scenario_seed_kind(case),
    )
}

fn shared_scenario_seed_kind(case: &ValueFlowConformanceCase<'_>) -> &'static str {
    match shared_scenario_root(case).kind {
        ProcedureKind::Method => "method",
        ProcedureKind::Function => "function",
        other => panic!("unsupported shared scenario root kind {other:?}"),
    }
}

fn shared_scenario_root<'case>(
    case: &ValueFlowConformanceCase<'case>,
) -> &'case ProcedureSelector<'case> {
    case.procedures
        .iter()
        .find(|procedure| procedure.alias == case.root)
        .expect("shared scenario root selector")
}

fn shared_scenario_query_with_seed_kind(
    case: &ValueFlowConformanceCase<'_>,
    plan_ref: &str,
    with_witness: bool,
    seed_kind: &str,
) -> CodeQuery {
    let root = shared_scenario_root(case);
    let mut steps = vec![
        json!({"op": "procedure_of"}),
        json!({"op": "value_flow", "plan_ref": plan_ref}),
    ];
    if with_witness {
        steps.push(json!({"op": "witness", "max_steps": 256, "max_bytes": 262_144}));
    }
    CodeQuery::from_json(&json!({
        "schema_version": 1,
        "match": {"kind": seed_kind, "name": root.name},
        "steps": steps,
    }))
    .unwrap()
}

fn profiled_shared_scenario_query(
    case: &ValueFlowConformanceCase<'_>,
    plan_ref: &str,
    with_witness: bool,
) -> CodeQuery {
    let mut value = shared_scenario_query(case, plan_ref, with_witness).to_canonical_json();
    value["execution_mode"] = json!("profile");
    CodeQuery::from_json(&value).unwrap()
}

fn shared_scenario_rql_query_with_seed_kind(
    case: &ValueFlowConformanceCase<'_>,
    plan_ref: &str,
    with_witness: bool,
    seed_kind: &str,
) -> CodeQuery {
    let root = shared_scenario_root(case);
    let root_name = serde_json::to_string(root.name).expect("RQL root name");
    let value_flow =
        format!("(value-flow :plan-ref {plan_ref} (procedure-of ({seed_kind} :name {root_name})))");
    let source = if with_witness {
        format!("(witness :max-steps 256 :max-bytes 262144 {value_flow})")
    } else {
        value_flow
    };
    CodeQuery::from_sexp(&source).unwrap_or_else(|error| panic!("{} RQL: {error}", case.name))
}

fn assert_public_sink_outcomes(
    case: &ValueFlowConformanceCase<'_>,
    resolved: &ResolvedValueFlowConformanceCase,
    response: &serde_json::Value,
    expected_public_status: SemanticInputStatus,
) {
    let rows = response["results"].as_array().unwrap();
    assert_eq!(
        rows.len(),
        case.expected_meetings
            .iter()
            .map(|meeting| meeting.public_endpoint_count)
            .sum::<usize>()
            + case
                .sinks
                .iter()
                .filter(|sink| sink.outcome != ExpectedSinkOutcome::Reached)
                .count(),
        "{} exact public endpoint count: expected {}, got {}",
        case.name,
        case.expected_meetings
            .iter()
            .map(|meeting| meeting.public_endpoint_count)
            .sum::<usize>()
            + case
                .sinks
                .iter()
                .filter(|sink| sink.outcome != ExpectedSinkOutcome::Reached)
                .count(),
        rows.len()
    );
    for sink in case.sinks {
        let sink_key = resolved.sink_event_key(sink.alias);
        let anchor = sink_key.site().anchor();
        let matching = rows
            .iter()
            .filter(|row| {
                row["sink"]["site"]["path"] == sink_key.site().path().as_str()
                    && row["sink"]["site"]["start_byte"] == anchor.span().start_byte()
                    && row["sink"]["site"]["end_byte"] == anchor.span().end_byte()
                    && row["sink"]["site"]["occurrence"] == anchor.occurrence()
                    && row["sink"]["ordinal"] == sink_key.ordinal()
            })
            .collect::<Vec<_>>();
        let expected_reachability = match sink.outcome {
            ExpectedSinkOutcome::Reached => "reached",
            ExpectedSinkOutcome::NotReached => "not_reached",
            ExpectedSinkOutcome::Inconclusive => "inconclusive",
        };
        let expected_count = case
            .expected_meetings
            .iter()
            .find(|meeting| meeting.sink == sink.alias)
            .map_or(1, |meeting| meeting.public_endpoint_count);
        assert_eq!(
            matching.len(),
            expected_count,
            "{} {} public endpoint count",
            case.name,
            sink.alias
        );
        assert!(
            matching
                .iter()
                .all(|row| row["reachability"] == expected_reachability),
            "{} {} public reachability: {response:#}",
            case.name,
            sink.alias
        );
        assert_eq!(
            matching
                .iter()
                .filter(|row| row["reachability"] == "reached")
                .count(),
            if sink.outcome == ExpectedSinkOutcome::Reached {
                expected_count
            } else {
                0
            },
            "{} {} exact detected/absent meeting count",
            case.name,
            sink.alias
        );
        let meeting = case
            .expected_meetings
            .iter()
            .find(|meeting| meeting.sink == sink.alias);
        let mut exact_complete_count = 0;
        let mut may_complete_count = 0;
        let mut may_partial_count = 0;
        for row in matching {
            assert_eq!(
                row["must"], "not_established",
                "{} {} must",
                case.name, sink.alias
            );
            assert_eq!(
                row["semantic_status"],
                expected_public_status.label(),
                "{} {} semantic status",
                case.name,
                sink.alias
            );
            assert_eq!(
                row["completion"],
                expected_public_completion(case, expected_public_status),
                "{} {} completion",
                case.name,
                sink.alias
            );
            assert_eq!(
                row["solver_termination"], "fixed_point",
                "{} {} solver termination",
                case.name, sink.alias
            );
            assert_eq!(
                row.get("ambiguous")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false),
                case.expected_public_ambiguous,
                "{} {} ambiguity",
                case.name,
                sink.alias
            );
            if meeting.is_some() {
                assert!(
                    row["source"].is_object(),
                    "{} {} source symbol",
                    case.name,
                    sink.alias
                );
                match (row["certainty"].as_str(), row["path_qualities"].as_array()) {
                    (Some("exact"), Some(qualities))
                        if qualities
                            == &[json!({"proof": "proven", "completeness": "complete"})] =>
                    {
                        exact_complete_count += 1;
                    }
                    (Some("may"), Some(qualities))
                        if qualities
                            == &[json!({"proof": "proven", "completeness": "complete"})] =>
                    {
                        may_complete_count += 1;
                    }
                    (Some("may"), Some(qualities))
                        if qualities
                            == &[json!({"proof": "unproven", "completeness": "partial"})] =>
                    {
                        may_partial_count += 1;
                    }
                    _ => panic!(
                        "{} {} unexpected public meeting evidence: {row:#}",
                        case.name, sink.alias
                    ),
                }
                assert_eq!(
                    row["retained_witnesses"], 1,
                    "{} {} retained witnesses",
                    case.name, sink.alias
                );
            } else {
                assert!(
                    row.get("source").is_none(),
                    "{} {} absent source",
                    case.name,
                    sink.alias
                );
                assert!(
                    row.get("certainty").is_none(),
                    "{} {} absent certainty",
                    case.name,
                    sink.alias
                );
                assert!(
                    row.get("path_qualities")
                        .is_none_or(|value| value == &json!([])),
                    "{} {} absent path qualities",
                    case.name,
                    sink.alias
                );
                assert_eq!(
                    row["retained_witnesses"], 0,
                    "{} {} retained witnesses",
                    case.name, sink.alias
                );
            }
            assert_eq!(
                row["omitted_witnesses"], 0,
                "{} {} omitted witnesses",
                case.name, sink.alias
            );
        }
        if let Some(meeting) = meeting {
            assert_eq!(
                may_complete_count, meeting.public_may_complete_count,
                "{} {} exact may/complete endpoint count",
                case.name, sink.alias
            );
            assert_eq!(
                may_partial_count, meeting.public_may_partial_count,
                "{} {} exact may/partial endpoint count",
                case.name, sink.alias
            );
            assert_eq!(
                exact_complete_count,
                meeting
                    .public_endpoint_count
                    .saturating_sub(meeting.public_may_complete_count)
                    .saturating_sub(meeting.public_may_partial_count),
                "{} {} exact exact/complete endpoint count",
                case.name,
                sink.alias
            );
        }
    }
}

fn expected_public_completion(
    case: &ValueFlowConformanceCase<'_>,
    expected_public_status: SemanticInputStatus,
) -> &'static str {
    if case.expected_result_complete && expected_public_status.is_complete() {
        return "complete";
    }
    match expected_public_status {
        SemanticInputStatus::Cancelled => "cancelled",
        SemanticInputStatus::ExceededBudget { .. } => "budget_exhausted",
        SemanticInputStatus::Unsupported { .. } => "unsupported",
        SemanticInputStatus::Complete
        | SemanticInputStatus::Ambiguous
        | SemanticInputStatus::Unknown
        | SemanticInputStatus::Unproven => "incomplete",
    }
}

fn assert_public_fact_symbol(fact: &serde_json::Value) {
    match fact["kind"].as_str().expect("public fact kind") {
        "zero" => assert_eq!(fact.as_object().unwrap().len(), 1),
        "carrier" => {
            assert_public_event(&fact["source"]);
            assert_public_carrier(&fact["carrier"]);
            assert!(
                fact.get("uncertain")
                    .is_none_or(serde_json::Value::is_boolean)
            );
        }
        "meeting" => {
            assert_public_event(&fact["source"]);
            assert_public_event(&fact["sink"]);
            assert!(
                fact.get("uncertain")
                    .is_none_or(serde_json::Value::is_boolean)
            );
        }
        other => panic!("unknown public fact kind {other}: {fact:#}"),
    }
}

fn assert_public_event(event: &serde_json::Value) {
    assert_eq!(event["id"].as_str().unwrap().len(), 64);
    assert_public_symbol_site(&event["site"]);
    assert!(event["path"].is_string());
    assert!(event["phase"].is_string());
    assert!(event["ordinal"].is_u64());
    assert!(event["range"].is_object());
    assert_public_carrier(&event["carrier"]);
}

fn assert_public_carrier(carrier: &serde_json::Value) {
    assert_eq!(carrier["id"].as_str().unwrap().len(), 64);
    match carrier["kind"].as_str().expect("public carrier kind") {
        "value" | "allocation" => assert_public_symbol_site(&carrier["site"]),
        "port" => {
            assert_public_symbol_site(&carrier["procedure"]);
            assert!(carrier["port"]["kind"].is_string());
        }
        "call_result" => {
            assert_public_symbol_site(&carrier["call"]);
            assert_public_carrier(&carrier["result"]);
            assert_public_symbol_site(&carrier["callee"]);
        }
        "scoped_root" => {
            assert!(carrier["root_kind"].is_string());
            assert_public_symbol_site(&carrier["site"]);
        }
        "location" => {
            assert_public_carrier(&carrier["root"]);
            assert!(carrier["selectors"].is_array());
            assert!(carrier["exact"].is_boolean());
        }
        other => panic!("unknown public carrier kind {other}: {carrier:#}"),
    }
}

fn assert_public_symbol_site(site: &serde_json::Value) {
    assert_eq!(site["id"].as_str().unwrap().len(), 64);
    assert!(site["path"].is_string());
    assert!(site["language"].is_string());
    assert!(!site["declaration"].as_array().unwrap().is_empty());
    assert!(site["role"].is_string());
    assert!(site["start_byte"].is_u64());
    assert!(site["end_byte"].is_u64());
    assert!(site["occurrence"].is_u64());
    assert!(site["range"].is_object());
    assert!(site.get("mount").is_none());
}

fn public_witness_symbol_sequence(witness: &serde_json::Value) -> String {
    let steps = witness["steps"]
        .as_array()
        .unwrap()
        .iter()
        .map(public_step_symbol)
        .collect::<Vec<_>>();
    serde_json::to_string(&steps).expect("canonical public witness JSON")
}

fn public_step_symbol(step: &serde_json::Value) -> serde_json::Value {
    let mut symbol = serde_json::Map::from_iter([
        ("kind".to_string(), step["kind"].clone()),
        (
            "source_symbol".to_string(),
            public_locator_symbol(&step["source_symbol"]),
        ),
        ("input".to_string(), public_fact_symbol(&step["input"])),
        ("output".to_string(), public_fact_symbol(&step["output"])),
    ]);
    for key in ["target_symbol", "origin_symbol"] {
        if let Some(site) = step.get(key) {
            symbol.insert(key.to_string(), public_locator_symbol(site));
        }
    }
    if let Some(boundary) = step.get("boundary") {
        symbol.insert("boundary".to_string(), boundary.clone());
    }
    serde_json::Value::Object(symbol)
}

fn public_fact_symbol(fact: &serde_json::Value) -> serde_json::Value {
    let mut symbol = serde_json::Map::from_iter([("kind".to_string(), fact["kind"].clone())]);
    match fact["kind"].as_str().unwrap() {
        "zero" => {}
        "carrier" => {
            symbol.insert("source".to_string(), public_event_symbol(&fact["source"]));
            symbol.insert(
                "carrier".to_string(),
                public_carrier_symbol(&fact["carrier"]),
            );
        }
        "meeting" => {
            symbol.insert("source".to_string(), public_event_symbol(&fact["source"]));
            symbol.insert("sink".to_string(), public_event_symbol(&fact["sink"]));
        }
        other => panic!("unknown public fact kind {other}"),
    }
    if fact["uncertain"] == true {
        symbol.insert("uncertain".to_string(), json!(true));
    }
    serde_json::Value::Object(symbol)
}

fn public_event_symbol(event: &serde_json::Value) -> serde_json::Value {
    json!({
        "site": public_locator_symbol(&event["site"]),
        "phase": event["phase"],
        "ordinal": event["ordinal"],
        "carrier": public_carrier_symbol(&event["carrier"]),
    })
}

fn public_carrier_symbol(carrier: &serde_json::Value) -> serde_json::Value {
    match carrier["kind"].as_str().unwrap() {
        "value" => {
            let mut symbol = serde_json::Map::from_iter([
                ("kind".to_string(), json!("value")),
                ("site".to_string(), public_locator_symbol(&carrier["site"])),
                ("role".to_string(), carrier["role"].clone()),
            ]);
            if let Some(ordinal) = carrier.get("ordinal") {
                symbol.insert("ordinal".to_string(), ordinal.clone());
            }
            serde_json::Value::Object(symbol)
        }
        "port" => json!({
            "kind": "port",
            "procedure": public_locator_symbol(&carrier["procedure"]),
            "port": carrier["port"],
        }),
        "allocation" => json!({
            "kind": "allocation",
            "site": public_locator_symbol(&carrier["site"]),
        }),
        "call_result" => json!({
            "kind": "call_result",
            "call": public_locator_symbol(&carrier["call"]),
            "result": public_carrier_symbol(&carrier["result"]),
            "callee": public_locator_symbol(&carrier["callee"]),
        }),
        "scoped_root" => json!({
            "kind": "scoped_root",
            "root_kind": carrier["root_kind"],
            "site": public_locator_symbol(&carrier["site"]),
        }),
        "location" => json!({
            "kind": "location",
            "root": public_carrier_symbol(&carrier["root"]),
            "selectors": carrier["selectors"].as_array().unwrap().iter().map(|selector| {
                match selector["kind"].as_str().unwrap() {
                    "field" => json!({
                        "kind": "field",
                        "field": public_locator_symbol(&selector["field"]),
                    }),
                    "exact_index" => json!({
                        "kind": "exact_index",
                        "index": public_carrier_symbol(&selector["index"]),
                    }),
                    "any_index" => json!({"kind": "any_index"}),
                    other => panic!("unknown public selector kind {other}"),
                }
            }).collect::<Vec<_>>(),
            "exact": carrier["exact"],
        }),
        other => panic!("unknown public carrier kind {other}"),
    }
}

fn public_locator_symbol(site: &serde_json::Value) -> serde_json::Value {
    json!({
        "path": site["path"],
        "language": site["language"],
        "declaration": site["declaration"],
        "role": site["role"],
        "start_byte": site["start_byte"],
        "end_byte": site["end_byte"],
        "occurrence": site["occurrence"],
    })
}
