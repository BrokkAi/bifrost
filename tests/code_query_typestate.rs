mod common;

use std::sync::Arc;

use brokk_bifrost::analyzer::semantic::{
    AbstractObject, AccessPathRoot, ObjectCardinality, ProcedureHandle, ProcedureKind,
    SemanticCallSite,
};
use brokk_bifrost::analyzer::structural::{
    CodeQuery, CodeQueryDiagnosticCode, CodeQueryExecutionLimits, CodeQueryResponse,
    CodeQueryResultValue, ProtocolRegistration, ProtocolRegistrationSet, execute_workspace_request,
    execute_workspace_request_with_registration_limits,
    execute_workspace_request_with_registrations,
};
use brokk_bifrost::analyzer::typestate::{
    BoundTypestateSubjectSpec, CompiledProtocol, ProtocolEventKey, ProtocolExpectationKey,
    ProtocolSpec, ProtocolStateKey, TypestateBindingContext, TypestateBindingPlan,
    TypestateBindingQuality, TypestateEventBindingSpec, TypestateInitialSeedSpec,
    TypestateObjectRole, TypestateObservationSite, TypestateSubjectClassKey, TypestateSubjectKey,
    TypestateTerminalBindingSpec,
};
use brokk_bifrost::{AnalyzerConfig, Language, WorkspaceAnalyzer};
use serde_json::json;

use common::semantic_graph::{SemanticGraph, mapped_source};
use common::{BuiltInlineTestProject, InlineTestProject};

const WORKSPACE_GENERATION: u64 = 17;
const PROTOCOL_REF: &str = "test:resource-lifecycle";
const RESOURCE_LIFECYCLE: &[u8] =
    include_bytes!("fixtures/typestate/resource-lifecycle.protocol.json");
const SOURCE: &str = r#"
function acquire(): object {
  return {};
}

function use(resource: object): void {}

function close(resource: object): void {}

function lifecycle(): void {
  const resource = acquire();
  close(resource);
  use(resource);
}
"#;

struct Fixture {
    _project: BuiltInlineTestProject,
    workspace: WorkspaceAnalyzer,
    registrations: ProtocolRegistrationSet,
}

impl Fixture {
    fn new() -> Self {
        let project = InlineTestProject::with_language(Language::TypeScript)
            .file("src/main.ts", SOURCE)
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let (root, protocol, bindings) = registered_plan(&project, &workspace);
        let mut registrations = ProtocolRegistrationSet::default();
        registrations
            .register(
                PROTOCOL_REF.parse().unwrap(),
                ProtocolRegistration::new(
                    WORKSPACE_GENERATION,
                    root,
                    Arc::new(protocol),
                    Arc::new(bindings),
                )
                .unwrap(),
            )
            .unwrap();
        Self {
            _project: project,
            workspace,
            registrations,
        }
    }

    fn execute(&self, query: &CodeQuery) -> CodeQueryResponse {
        execute_workspace_request_with_registrations(
            &self.workspace,
            WORKSPACE_GENERATION,
            &self.registrations,
            query,
        )
    }
}

fn registered_plan(
    project: &BuiltInlineTestProject,
    workspace: &WorkspaceAnalyzer,
) -> (ProcedureHandle, CompiledProtocol, TypestateBindingPlan) {
    let graph = SemanticGraph::materialize(project, workspace, "src/main.ts");
    let procedure = graph
        .artifact()
        .procedures()
        .iter()
        .find(|procedure| {
            procedure.kind() == ProcedureKind::Function
                && procedure
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|segment| segment.name())
                    == Some("lifecycle")
        })
        .expect("lifecycle procedure");
    let root = graph
        .artifact()
        .procedure_handle(procedure.id())
        .expect("scoped lifecycle handle");
    let close_call = call_containing(procedure, "close(resource)");
    let use_call = call_containing(procedure, "use(resource)");
    let subject_value = use_call.arguments[0].value;
    let object = AbstractObject::new(
        AccessPathRoot::Value(
            root.value_handle(subject_value)
                .expect("scoped resource value"),
        ),
        ObjectCardinality::Singleton,
    )
    .expect("valid resource object");
    let subject_class = TypestateSubjectClassKey::new("resource").unwrap();
    let subject_key = TypestateSubjectKey::for_object(subject_class.clone(), &object);
    let entry = root
        .point_handle(procedure.entry_point())
        .expect("entry point");
    let exit = root
        .point_handle(procedure.normal_exit_point())
        .expect("normal exit");
    let close_call = root
        .call_site_handle(close_call.id)
        .expect("close call handle");
    let use_call = root.call_site_handle(use_call.id).expect("use call handle");
    let context = TypestateBindingContext::root();
    let exact = TypestateBindingQuality::proven_unique();
    let protocol = ProtocolSpec::from_json(RESOURCE_LIFECYCLE)
        .unwrap()
        .compile()
        .unwrap();
    let bindings = TypestateBindingPlan::try_new(
        &protocol,
        vec![BoundTypestateSubjectSpec::new(
            subject_class,
            object,
            exact.clone(),
        )],
        vec![TypestateInitialSeedSpec::new(
            subject_key.clone(),
            ProtocolStateKey::new("unallocated").unwrap(),
            TypestateObservationSite::program_point(entry.clone(), context.clone()),
            TypestateObjectRole::MatchedValue,
            exact.clone(),
        )],
        vec![
            TypestateEventBindingSpec::new(
                ProtocolEventKey::new("acquire").unwrap(),
                subject_key.clone(),
                TypestateObservationSite::program_point(entry, context.clone()),
                0,
                TypestateObjectRole::AllocationResult,
                exact.clone(),
            ),
            TypestateEventBindingSpec::new(
                ProtocolEventKey::new("close").unwrap(),
                subject_key.clone(),
                TypestateObservationSite::call_site(close_call, context.clone()),
                0,
                TypestateObjectRole::Argument,
                exact.clone(),
            ),
            TypestateEventBindingSpec::new(
                ProtocolEventKey::new("use").unwrap(),
                subject_key.clone(),
                TypestateObservationSite::call_site(use_call, context.clone()),
                0,
                TypestateObjectRole::Argument,
                exact.clone(),
            ),
        ],
        vec![TypestateTerminalBindingSpec::new(
            ProtocolExpectationKey::new("normal-exit-closed").unwrap(),
            subject_key,
            TypestateObservationSite::program_point(exit, context),
            TypestateObjectRole::CurrentObject,
            exact,
        )],
    )
    .expect("pre-resolved lifecycle binding plan");
    (root, protocol, bindings)
}

fn call_containing<'procedure>(
    procedure: &'procedure brokk_bifrost::analyzer::semantic::ProcedureSemantics,
    text: &str,
) -> &'procedure SemanticCallSite {
    procedure
        .call_sites()
        .iter()
        .find(|call| mapped_source(procedure, SOURCE, call.source).contains(text))
        .unwrap_or_else(|| panic!("missing call containing {text:?}"))
}

fn json_query(steps: serde_json::Value) -> CodeQuery {
    CodeQuery::from_json(&json!({
        "schema_version": 4,
        "match": {"kind": "function", "name": "lifecycle"},
        "steps": steps,
    }))
    .unwrap()
}

fn finding_query() -> CodeQuery {
    json_query(json!([
        {"op": "procedure_of"},
        {"op": "typestate", "protocol_ref": PROTOCOL_REF},
    ]))
}

fn witness_query() -> CodeQuery {
    json_query(json!([
        {"op": "procedure_of"},
        {"op": "typestate", "protocol_ref": PROTOCOL_REF},
        {"op": "witness", "max_steps": 32, "max_bytes": 16384},
    ]))
}

fn diagnostic_codes(response: &CodeQueryResponse) -> Vec<CodeQueryDiagnosticCode> {
    response
        .result()
        .expect("test query executes")
        .diagnostics
        .iter()
        .map(|diagnostic| diagnostic.code)
        .collect()
}

#[test]
fn registered_json_and_rql_return_equal_findings_and_retained_witnesses() {
    let fixture = Fixture::new();
    let finding_response = fixture.execute(&finding_query());
    let findings = &finding_response.result().unwrap().results;
    let finding = findings
        .iter()
        .find_map(|item| match &item.value {
            CodeQueryResultValue::TypestateFinding { value } => Some(value),
            _ => None,
        })
        .expect("use-after-close finding");
    assert_eq!(finding.protocol_ref, PROTOCOL_REF);
    assert_eq!(finding.protocol_hash.len(), 64);
    assert_eq!(finding.binding_plan_hash.len(), 64);
    assert!(finding.retained_witnesses > 0);

    let json_response = fixture.execute(&witness_query());
    let rql = CodeQuery::from_sexp(&format!(
        r#"(witness :max-steps 32 :max-bytes 16384
              (typestate :protocol-ref "{PROTOCOL_REF}"
                (procedure-of (function :name "lifecycle"))))"#
    ))
    .unwrap();
    let rql_response = fixture.execute(&rql);
    assert_eq!(
        serde_json::to_value(&json_response).unwrap(),
        serde_json::to_value(&rql_response).unwrap()
    );
    let witnesses = &json_response.result().unwrap().results;
    let witness = witnesses
        .iter()
        .find_map(|item| match &item.value {
            CodeQueryResultValue::TypestateWitness { value } => Some(value),
            _ => None,
        })
        .expect("retained typestate witness");
    assert!(!witness.steps.is_empty());
    assert!(!witness.truncated);
    assert_eq!(witness.finding_id.len(), 64);
}

#[test]
fn witness_projection_trims_retained_evidence_without_a_second_solve() {
    let fixture = Fixture::new();
    let query = CodeQuery::from_json(&json!({
        "schema_version": 4,
        "match": {"kind": "function", "name": "lifecycle"},
        "steps": [
            {"op": "procedure_of"},
            {"op": "typestate", "protocol_ref": PROTOCOL_REF},
            {"op": "witness", "max_steps": 0, "max_bytes": 0}
        ],
        "execution_mode": "profile"
    }))
    .unwrap();
    let response = fixture.execute(&query);
    let report = serde_json::to_value(&response).unwrap();
    assert_eq!(
        report.pointer("/work/semantic/typestate/solves"),
        Some(&json!(1))
    );
    assert_eq!(
        report.pointer("/work/semantic/typestate/cache_hits"),
        Some(&json!(0))
    );
    let result = response.result().unwrap();
    assert!(result.results.iter().all(|item| match &item.value {
        CodeQueryResultValue::TypestateWitness { value } => {
            value.steps.is_empty() && value.truncated && value.omitted_steps_lower_bound > 0
        }
        _ => false,
    }));
    assert!(
        diagnostic_codes(&response).contains(&CodeQueryDiagnosticCode::TypestateWitnessTruncated)
    );
}

#[test]
fn duplicate_analysis_branches_share_one_request_local_solve() {
    let fixture = Fixture::new();
    let branch = json!({
        "match": {"kind": "function", "name": "lifecycle"},
        "steps": [
            {"op": "procedure_of"},
            {"op": "typestate", "protocol_ref": PROTOCOL_REF}
        ]
    });
    let query = CodeQuery::from_json(&json!({
        "schema_version": 4,
        "union": [branch.clone(), branch],
        "execution_mode": "profile"
    }))
    .unwrap();
    let response = fixture.execute(&query);
    let report = serde_json::to_value(&response).unwrap();
    assert_eq!(
        report.pointer("/work/semantic/typestate/solves"),
        Some(&json!(1))
    );
    assert_eq!(
        report.pointer("/work/semantic/typestate/cache_hits"),
        Some(&json!(1))
    );
}

#[test]
fn unresolved_stale_wrong_root_and_solver_budget_are_explicitly_incomplete() {
    let fixture = Fixture::new();
    let unresolved = execute_workspace_request(&fixture.workspace, &finding_query());
    assert!(
        diagnostic_codes(&unresolved)
            .contains(&CodeQueryDiagnosticCode::UnresolvedProtocolReference)
    );

    let stale = execute_workspace_request_with_registrations(
        &fixture.workspace,
        WORKSPACE_GENERATION + 1,
        &fixture.registrations,
        &finding_query(),
    );
    assert!(
        diagnostic_codes(&stale).contains(&CodeQueryDiagnosticCode::TypestateRegistrationStale)
    );

    let wrong_root = CodeQuery::from_json(&json!({
        "schema_version": 4,
        "match": {"kind": "function", "name": "use"},
        "steps": [
            {"op": "procedure_of"},
            {"op": "typestate", "protocol_ref": PROTOCOL_REF}
        ]
    }))
    .unwrap();
    let wrong_root = fixture.execute(&wrong_root);
    assert!(
        diagnostic_codes(&wrong_root).contains(&CodeQueryDiagnosticCode::TypestateRootMismatch)
    );

    let mut limits = CodeQueryExecutionLimits::default();
    limits.typestate.solver_work.reached_states = 1;
    let exhausted = execute_workspace_request_with_registration_limits(
        &fixture.workspace,
        WORKSPACE_GENERATION,
        &fixture.registrations,
        &finding_query(),
        limits,
    );
    assert!(
        diagnostic_codes(&exhausted)
            .contains(&CodeQueryDiagnosticCode::TypestateSolverBudgetExhausted)
    );
    assert!(
        exhausted.result().unwrap().truncated
            || !exhausted.result().unwrap().diagnostics.is_empty()
    );
}

#[test]
fn file_of_accepts_typestate_findings() {
    let fixture = Fixture::new();
    let query = json_query(json!([
        {"op": "procedure_of"},
        {"op": "typestate", "protocol_ref": PROTOCOL_REF},
        {"op": "file_of"}
    ]));
    let response = fixture.execute(&query);
    assert!(response.result().unwrap().results.iter().any(|item| {
        matches!(
            &item.value,
            CodeQueryResultValue::File { value } if value.path == "src/main.ts"
        )
    }));
}
