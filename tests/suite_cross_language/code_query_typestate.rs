use std::sync::Arc;

use brokk_bifrost::analyzer::semantic::{
    AbstractObject, AccessPathRoot, ObjectCardinality, ProcedureHandle, ProcedureKind,
    SemanticCallSite,
};
use brokk_bifrost::analyzer::structural::{
    CodeQuery, CodeQueryDiagnosticCode, CodeQueryExecutionLimits, CodeQueryResponse,
    CodeQueryResultValue, CodeQuerySemanticCompleteness, ProtocolRegistration,
    ProtocolRegistrationSet, execute_workspace_request,
    execute_workspace_request_with_registration_lease,
    execute_workspace_request_with_registration_limits,
    execute_workspace_request_with_registrations,
};
use brokk_bifrost::analyzer::typestate::{
    BoundTypestateSubjectSpec, CompiledProtocol, ProductionTypestateSummaryRepository,
    ProtocolEventKey, ProtocolExpectationKey, ProtocolSpec, ProtocolStateKey,
    TypestateBindingContext, TypestateBindingPlan, TypestateBindingQuality,
    TypestateEventBindingSpec, TypestateInitialSeedSpec, TypestateObjectRole,
    TypestateObservationSite, TypestateSubjectClassKey, TypestateSubjectKey,
    TypestateTerminalBindingSpec,
};
use brokk_bifrost::{AnalyzerConfig, Language, WorkspaceAnalyzer};
use serde_json::json;

use crate::common::semantic_graph::{SemanticGraph, mapped_source};
use crate::common::{BuiltInlineTestProject, InlineTestProject};

const WORKSPACE_GENERATION: u64 = 17;
const PROTOCOL_REF: &str = "test:resource-lifecycle";
const RESOURCE_LIFECYCLE: &[u8] =
    include_bytes!("../fixtures/typestate/resource-lifecycle.protocol.json");
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
const JAVA_SOURCE: &str = r#"
class Resource {}

class LifecycleFixture {
  static Resource acquire() {
    return null;
  }

  static void use(Resource resource) {}

  static void close(Resource resource) {}

  static void lifecycle() {
    Resource resource = acquire();
    close(resource);
    use(resource);
  }
}
"#;

struct Fixture {
    _project: BuiltInlineTestProject,
    workspace: WorkspaceAnalyzer,
    registrations: ProtocolRegistrationSet,
    summaries: Arc<ProductionTypestateSummaryRepository>,
}

impl Fixture {
    fn new() -> Self {
        Self::for_language(Language::TypeScript, "src/main.ts", SOURCE)
    }

    fn java() -> Self {
        Self::for_language(Language::Java, "src/LifecycleFixture.java", JAVA_SOURCE)
    }

    fn for_language(language: Language, path: &str, source: &str) -> Self {
        let project = InlineTestProject::with_language(language)
            .file(path, source)
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let (root, protocol, bindings) = registered_plan(&project, &workspace, path, source);
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
            summaries: Arc::new(ProductionTypestateSummaryRepository::new()),
        }
    }

    fn execute(&self, query: &CodeQuery) -> CodeQueryResponse {
        execute_workspace_request_with_registration_lease(
            &self.workspace,
            WORKSPACE_GENERATION,
            &self.registrations,
            query,
            CodeQueryExecutionLimits::default(),
            None,
            self.summaries.lease(WORKSPACE_GENERATION).unwrap(),
        )
    }
}

fn registered_plan(
    project: &BuiltInlineTestProject,
    workspace: &WorkspaceAnalyzer,
    path: &str,
    source: &str,
) -> (ProcedureHandle, CompiledProtocol, TypestateBindingPlan) {
    let graph = SemanticGraph::materialize(project, workspace, path);
    let procedure = graph
        .artifact()
        .procedures()
        .iter()
        .find(|procedure| {
            matches!(
                procedure.kind(),
                ProcedureKind::Function | ProcedureKind::Method
            ) && procedure
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
    let close_call = call_containing(procedure, source, "close(resource)");
    let use_call = call_containing(procedure, source, "use(resource)");
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
    source: &str,
    text: &str,
) -> &'procedure SemanticCallSite {
    procedure
        .call_sites()
        .iter()
        .find(|call| mapped_source(procedure, source, call.source).contains(text))
        .unwrap_or_else(|| panic!("missing call containing {text:?}"))
}

fn json_query(steps: serde_json::Value) -> CodeQuery {
    CodeQuery::from_json(&json!({
        "schema_version": 1,
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
fn java_and_typescript_resource_protocol_match_through_json_and_rql() {
    for (fixture, kind) in [(Fixture::new(), "function"), (Fixture::java(), "method")] {
        let json_query = CodeQuery::from_json(&json!({
            "schema_version": 1,
            "match": {"kind": kind, "name": "lifecycle"},
            "steps": [
                {"op": "procedure_of"},
                {"op": "typestate", "protocol_ref": PROTOCOL_REF},
                {"op": "witness", "max_steps": 32, "max_bytes": 16384},
            ],
        }))
        .unwrap();
        let json_response = fixture.execute(&json_query);
        let rql = CodeQuery::from_sexp(&format!(
            r#"(witness :max-steps 32 :max-bytes 16384
                  (typestate :protocol-ref "{PROTOCOL_REF}"
                    (procedure-of ({kind} :name "lifecycle"))))"#
        ))
        .unwrap();
        let rql_response = fixture.execute(&rql);
        assert_eq!(
            serde_json::to_value(&json_response).unwrap(),
            serde_json::to_value(&rql_response).unwrap()
        );
        assert!(
            json_response.result().unwrap().results.iter().any(|item| {
                matches!(item.value, CodeQueryResultValue::TypestateWitness { .. })
            })
        );
    }
}

#[test]
fn java_and_typescript_public_profiles_preserve_witnesses_on_exact_hits() {
    for (fixture, kind) in [(Fixture::new(), "function"), (Fixture::java(), "method")] {
        let query = CodeQuery::from_json(&json!({
            "schema_version": 1,
            "execution_mode": "profile",
            "match": {"kind": kind, "name": "lifecycle"},
            "steps": [
                {"op": "procedure_of"},
                {"op": "typestate", "protocol_ref": PROTOCOL_REF},
                {"op": "witness", "max_steps": 32, "max_bytes": 16384}
            ]
        }))
        .unwrap();
        let cold = fixture.execute(&query);
        let warm = fixture.execute(&query);
        assert_eq!(
            serde_json::to_value(cold.result().unwrap()).unwrap(),
            serde_json::to_value(warm.result().unwrap()).unwrap()
        );
        assert!(warm.result().unwrap().results.iter().any(|item| {
            matches!(
                &item.value,
                CodeQueryResultValue::TypestateWitness { value } if !value.steps.is_empty()
            )
        }));
        let cold = serde_json::to_value(cold).unwrap();
        let warm = serde_json::to_value(warm).unwrap();
        assert_eq!(
            cold.pointer("/work/semantic/typestate/summary_misses"),
            Some(&json!(1))
        );
        assert_eq!(
            cold.pointer("/work/semantic/typestate/summary_recomputations"),
            Some(&json!(1))
        );
        assert_eq!(
            warm.pointer("/work/semantic/typestate/summary_hits"),
            Some(&json!(1))
        );
        assert_eq!(
            warm.pointer("/work/semantic/typestate/summary_recomputations"),
            Some(&json!(0))
        );
    }
}

#[test]
fn typestate_public_identities_are_stable_across_absolute_checkout_roots() {
    fn identities(fixture: &Fixture) -> Vec<(String, String, String)> {
        let response = fixture.execute(&witness_query());
        let mut identities = response
            .result()
            .unwrap()
            .results
            .iter()
            .filter_map(|item| match &item.value {
                CodeQueryResultValue::TypestateWitness { value } => Some((
                    value.id.clone(),
                    value.finding_id.clone(),
                    value.subject.identity.clone(),
                )),
                _ => None,
            })
            .collect::<Vec<_>>();
        identities.sort_unstable();
        identities
    }

    let first = Fixture::new();
    let second = Fixture::new();
    assert_ne!(first._project.root(), second._project.root());
    assert_eq!(identities(&first), identities(&second));
}

#[test]
fn registered_root_survives_equivalent_semantic_rematerialization() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file("src/main.ts", SOURCE)
        .build();
    let registration_workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let (root, protocol, bindings) =
        registered_plan(&project, &registration_workspace, "src/main.ts", SOURCE);
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

    let rematerialized_workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let response = execute_workspace_request_with_registrations(
        &rematerialized_workspace,
        WORKSPACE_GENERATION,
        &registrations,
        &finding_query(),
    );
    assert!(
        response
            .result()
            .unwrap()
            .results
            .iter()
            .any(|item| matches!(&item.value, CodeQueryResultValue::TypestateFinding { .. }))
    );
    assert!(!diagnostic_codes(&response).contains(&CodeQueryDiagnosticCode::TypestateRootMismatch));
}

#[test]
fn witness_projection_trims_retained_evidence_without_a_second_solve() {
    let fixture = Fixture::new();
    let query = CodeQuery::from_json(&json!({
        "schema_version": 1,
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
            value.steps.is_empty()
                && value.truncated
                && value.omitted_steps_lower_bound > 0
                && value.quality.completeness == CodeQuerySemanticCompleteness::Partial
                && value.quality.completeness_reason.is_some()
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
        "schema_version": 1,
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
    assert_eq!(
        report.pointer("/work/semantic/typestate/summary_hits"),
        Some(&json!(0))
    );
    assert_eq!(
        report.pointer("/work/semantic/typestate/summary_misses"),
        Some(&json!(1))
    );
    assert_eq!(
        report.pointer("/work/semantic/typestate/summary_rejections"),
        Some(&json!(0))
    );
    assert_eq!(
        report.pointer("/work/semantic/typestate/summary_evictions"),
        Some(&json!(0))
    );
    assert_eq!(
        report.pointer("/work/semantic/typestate/summary_recomputations"),
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
        "schema_version": 1,
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
