use crate::common::InlineTestProject;
use brokk_bifrost::analyzer::policy::{
    HumanRenderColor, HumanRenderDetail, HumanRenderOptions, PolicyEvaluationDate,
    PolicyEvaluationInput, PolicyEvaluationOptions, PolicyFindingEvidence, PolicyIncompleteReason,
    PolicyRunCompletion, PolicySemanticModelContext, PolicySourceIdentity, SarifToolIdentity,
    evaluate_policy_inputs_with_analyzer, evaluate_policy_inputs_with_analyzer_and_semantic_models,
    write_policy_human, write_policy_json, write_policy_sarif,
};
use brokk_bifrost::analyzer::semantic_model::{
    CatalogCoordinate, CatalogOptions, CompiledSemanticModelPack, CompilerOptions,
    SemanticModelActivationControl, SemanticModelActivationEvidence,
    SemanticModelActivationRequest, SemanticModelControlAction, SemanticModelControlScope,
    SemanticModelPackSelector, SemanticModelResolutionOutcome, SemanticModelRuntimeLimits,
    SemanticPackCatalog, SessionPackSource, SessionPackSourceKind, SourceFormat, compile_source,
    resolve_active_semantic_models,
};
use brokk_bifrost::analyzer::structural::{
    CodeQuery, CodeQueryDiagnosticCode, CodeQueryExecutionLimits, ProtocolRegistrationSet,
    TaintResultRef, TaintResultRegistration, TaintResultRegistrationError,
    TaintResultRegistrationLimits, TaintResultRegistrationOutcome, TaintResultRegistrationSet,
    TaintResultRegistrationSetError, ValueFlowPlanRegistrationSet,
    execute_workspace_request_with_all_analysis_registration_lease,
};
use brokk_bifrost::analyzer::typestate::ProductionTypestateSummaryRepository;
use brokk_bifrost::{AnalyzerConfig, CancellationToken, Language};
use semver::Version;
use std::path::Path;
use std::sync::Arc;

const MODEL_ARTIFACT_SHA256: &str =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

const JAVA_EXTERNAL_SOURCE: &str = r#"
class App {
    static native String attacker();
    static native void sensitive(String value);
    native String external(String value);

    void run() {
        sensitive(this.external(attacker()));
    }
}
"#;

const JAVA_BODY_SOURCE: &str = r#"
class App {
    static native String attacker();
    static native void sensitive(String value);

    String external(String value) {
        return value;
    }

    void run() {
        sensitive(this.external(attacker()));
    }
}
"#;

const SOURCE: &str = r#"
def source_one():
    return "one"

def source_two():
    return "two"

def sink_one(value):
    pass

def sink_two(value):
    pass

def run():
    first = source_one()
    second = source_two()
    sink_one(first)
    sink_two(second)
"#;

const INTERPROCEDURAL_SOURCE: &str = r#"
def source_one():
    return "one"

def sink_one(value):
    pass

def helper():
    return source_one()

def run():
    sink_one(helper())
"#;

const MATCHED_VALUE_SOURCE: &str = r#"
def source_one():
    return "one"

def sink_one(value):
    pass

def run():
    first = source_one()
    sink_one(first)
"#;

const SIBLING_CALLEE_SOURCE: &str = r#"
def source_one():
    return "one"

def sink_one(value):
    pass

def produce():
    return source_one()

def consume(value):
    sink_one(value)

def run():
    produced = produce()
    consume(produced)
"#;

fn policy(id: &str, message: &str, severity: &str) -> String {
    format!(
        r#"(policy
          :schema-version 1
          :id "{id}"
          :name "Production taint adapter"
          :message "{message}"
          :severity {severity}
          :analysis (analysis
            :type taint
            :mode may
            :call-modeling (call-modeling :unmodeled optimistic)
            :sources (endpoint-set :entries [
              (source :id first :display-name "first source" :categories [input.user]
                :selector (rql :schema-version 6
                  (language python (call :callee (name "source_one"))))
                :bind return-value :labels [untrusted])
              (source :id second :display-name "second source" :categories [input.user]
                :selector (rql :schema-version 6
                  (language python (call :callee (name "source_two"))))
                :bind return-value :labels [untrusted])])
            :sinks (endpoint-set :entries [
              (sink :id first-store :display-name "first sink" :categories [data.sensitive]
                :selector (rql :schema-version 6
                  (language python (call :callee (name "sink_one"))))
                :dangerous-operand (argument :index 0) :accepts [untrusted])
              (sink :id second-store :display-name "second sink" :categories [data.sensitive]
                :selector (rql :schema-version 6
                  (language python (call :callee (name "sink_two"))))
                :dangerous-operand (argument :index 0) :accepts [untrusted])]))
          :classification (classification
            :fallback (classification-id :taxonomy "Test" :id "BROAD-TAINT")))"#
    )
}

fn subset_policy(id: &str) -> String {
    format!(
        r#"(policy
          :schema-version 1
          :id "{id}"
          :name "Endpoint-neutral production taint adapter"
          :message "subset presentation"
          :severity note
          :analysis (analysis
            :type taint
            :mode may
            :call-modeling (call-modeling :unmodeled optimistic)
            :sources (endpoint-set :entries [
              (source :id first :display-name "first source" :categories [input.user]
                :selector (rql :schema-version 6
                  (language python (call :callee (name "source_one"))))
                :bind return-value :labels [untrusted])])
            :sinks (endpoint-set :entries [
              (sink :id first-store :display-name "first sink" :categories [data.sensitive]
                :selector (rql :schema-version 6
                  (language python (call :callee (name "sink_one"))))
                :dangerous-operand (argument :index 0) :accepts [untrusted])]))
          :classification (classification
            :fallback (classification-id :taxonomy "Test" :id "BROAD-TAINT")))"#
    )
}

fn single_policy(id: &str, source_selector: &str, source_binding: &str) -> String {
    format!(
        r#"(policy
          :schema-version 1
          :id "{id}"
          :name "Production taint adapter boundary"
          :message "taint boundary"
          :severity warning
          :analysis (analysis
            :type taint
            :mode may
            :call-modeling (call-modeling :unmodeled optimistic)
            :sources (endpoint-set :entries [
              (source :id first :display-name "first source" :categories [input.user]
                :selector (rql :schema-version 6 {source_selector})
                :bind {source_binding} :labels [untrusted])])
            :sinks (endpoint-set :entries [
              (sink :id first-store :display-name "first sink" :categories [data.sensitive]
                :selector (rql :schema-version 6
                  (language python (call :callee (name "sink_one"))))
                :dangerous-operand (argument :index 0) :accepts [untrusted])]))
          :classification (classification
            :fallback (classification-id :taxonomy "Test" :id "BROAD-TAINT")))"#
    )
}

fn java_summary_policy(id: &str, message: &str) -> String {
    format!(
        r#"(policy
          :schema-version 1
          :id "{id}"
          :name "Semantic-pack taint summary"
          :message "{message}"
          :severity warning
          :analysis (analysis
            :type taint
            :mode may
            :call-modeling (call-modeling :unmodeled require-model)
            :sources (endpoint-set :entries [
              (source :id attacker :display-name "attacker input" :categories [input.user]
                :selector (rql :schema-version 6
                  (language java (call :callee (name "attacker"))))
                :bind return-value :labels [untrusted])])
            :sinks (endpoint-set :entries [
              (sink :id sensitive :display-name "sensitive sink" :categories [data.sensitive]
                :selector (rql :schema-version 6
                  (language java (call :callee (name "sensitive"))))
                :dangerous-operand (argument :index 0) :accepts [untrusted])]))
          :classification (classification
            :fallback (classification-id :taxonomy "Test" :id "BROAD-TAINT")))"#
    )
}

fn procedure_summary_pack(
    pack_id: &str,
    model_effect: Option<&str>,
    include_unrelated: bool,
) -> CompiledSemanticModelPack {
    let mut summaries = vec![serde_json::json!({
        "id": "summary.external",
        "target": {
            "path": "app.java",
            "symbol": "external(String)",
            "has_receiver": true,
            "parameter_count": 1
        },
        "completeness": "complete",
        "transfers": [{
            "input": { "kind": "parameter", "ordinal": 0 },
            "exit_kind": "normal",
            "output": { "kind": "normal_return" }
        }],
        "effects": model_effect.into_iter().map(|event| serde_json::json!({
            "kind": "unknown_call_boundary",
            "event": event
        })).collect::<Vec<_>>()
    })];
    if include_unrelated {
        summaries.push(serde_json::json!({
            "id": "summary.unrelated",
            "target": {
                "path": "other.java",
                "symbol": "unrelated(String)",
                "has_receiver": false,
                "parameter_count": 1
            },
            "completeness": "complete",
            "transfers": [{
                "input": { "kind": "parameter", "ordinal": 0 },
                "exit_kind": "normal",
                "output": { "kind": "normal_return" }
            }],
            "effects": []
        }));
    }
    let source = serde_json::to_vec(&serde_json::json!({
        "schema_version": 1,
        "pack_id": pack_id,
        "version": "1.0.0",
        "producer": { "name": "taint-summary-test", "version": "1.0.0" },
        "language": "java",
        "ecosystem": "maven",
        "compatibility": {
            "bifrost": ">=0.8.0, <1.0.0",
            "toolchains": [{ "name": "jdk", "requirement": ">=17.0.0" }]
        },
        "provenance": { "source": "test:semantic-pack", "revision": "reviewed" },
        "license": "Apache-2.0",
        "completeness": "complete",
        "safety": { "generated_code_only": false, "review_required": false },
        "shards": [{
            "id": "summaries.external",
            "activation": [{
                "package": { "name": "com.acme:external", "version": ">=1.0.0, <2.0.0" },
                "targets": ["jvm"],
                "configurations": ["release"],
                "artifact_sha256": MODEL_ARTIFACT_SHA256
            }],
            "payload": { "kind": "procedure_summaries", "summaries": summaries }
        }]
    }))
    .expect("semantic-pack source serialization");
    compile_source(SourceFormat::Json, &source, &CompilerOptions::default())
        .unwrap_or_else(|diagnostics| panic!("procedure-summary pack failed: {diagnostics:#?}"))
}

fn semantic_model_request(version: &str, artifact_sha256: &str) -> SemanticModelActivationRequest {
    SemanticModelActivationRequest {
        bifrost_version: Version::parse("0.8.17").unwrap(),
        evidence: vec![SemanticModelActivationEvidence {
            language: "java".to_owned(),
            ecosystem: "maven".to_owned(),
            package: Some(CatalogCoordinate {
                name: "com.acme:external".to_owned(),
                version: Some(Version::parse(version).unwrap()),
            }),
            module: None,
            toolchain: Some(CatalogCoordinate {
                name: "jdk".to_owned(),
                version: Some(Version::parse("17.0.1").unwrap()),
            }),
            target: Some("jvm".to_owned()),
            configuration: Some("release".to_owned()),
            artifact_sha256: Some(artifact_sha256.to_owned()),
        }],
        controls: Vec::new(),
        limits: SemanticModelRuntimeLimits::default(),
    }
}

fn semantic_model_request_with_cache_key(cache_key: &str) -> SemanticModelActivationRequest {
    let mut request = semantic_model_request("1.5.0", MODEL_ARTIFACT_SHA256);
    request.controls.push(SemanticModelActivationControl {
        scope: SemanticModelControlScope::User,
        action: SemanticModelControlAction::Disable,
        selector: SemanticModelPackSelector {
            pack_id: format!("test.unused-{cache_key}"),
            version: None,
            manifest_digest: None,
        },
    });
    request
}

fn register_pack(catalog: &SemanticPackCatalog, pack: &CompiledSemanticModelPack, source_id: &str) {
    catalog
        .register_session_pack(
            pack,
            &SessionPackSource {
                kind: SessionPackSourceKind::Embedded,
                source_id: source_id.to_owned(),
            },
        )
        .expect("register procedure-summary pack");
}

fn evaluate_java_with_models(
    source: &str,
    policies: &[(&str, &str)],
    catalog: &SemanticPackCatalog,
    request: &SemanticModelActivationRequest,
) -> brokk_bifrost::analyzer::policy::PolicyBatchOutcome {
    let project = InlineTestProject::with_language(Language::Java)
        .file("app.java", source)
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    evaluate_java_workspace_with_models(project.root(), &workspace, policies, catalog, request)
}

fn evaluate_java_workspace_with_models(
    root: &Path,
    workspace: &brokk_bifrost::analyzer::WorkspaceAnalyzer,
    policies: &[(&str, &str)],
    catalog: &SemanticPackCatalog,
    request: &SemanticModelActivationRequest,
) -> brokk_bifrost::analyzer::policy::PolicyBatchOutcome {
    let policy_sources = policies
        .iter()
        .map(|(id, message)| java_summary_policy(id, message))
        .collect::<Vec<_>>();
    let inputs = policy_sources
        .iter()
        .enumerate()
        .map(|(index, source)| {
            PolicyEvaluationInput::embedded(
                PolicySourceIdentity::new(format!("test:semantic-summary-{index}.rqlp")),
                source,
            )
        })
        .collect::<Vec<_>>();
    let options = PolicyEvaluationOptions::new(
        PolicyEvaluationDate::from_ymd(2026, 7, 31).expect("fixed evaluation date"),
    );
    evaluate_policy_inputs_with_analyzer_and_semantic_models(
        root,
        &inputs,
        workspace,
        &options,
        PolicySemanticModelContext {
            catalog,
            request,
            persistence: None,
        },
        None,
    )
    .expect("production taint evaluation with semantic models")
}

fn propagation_identity(outcome: &brokk_bifrost::analyzer::policy::PolicyBatchOutcome) -> &str {
    let [analysis] = outcome.taint_analysis_results() else {
        panic!(
            "expected one retained production analysis, got {}",
            outcome.taint_analysis_results().len()
        )
    };
    analysis.compatibility().propagation_semantics()
}

fn active_shard_count(
    catalog: &SemanticPackCatalog,
    request: &SemanticModelActivationRequest,
) -> usize {
    match resolve_active_semantic_models(catalog, request, &CancellationToken::default()) {
        SemanticModelResolutionOutcome::Ready(active) => active.shards().len(),
        other => panic!("expected complete activation result, got {other:#?}"),
    }
}

fn evaluate_one(
    source: &str,
    policy_source: &str,
) -> brokk_bifrost::analyzer::policy::PolicyBatchOutcome {
    let project = InlineTestProject::with_language(Language::Python)
        .file("app.py", source)
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let input = [PolicyEvaluationInput::embedded(
        PolicySourceIdentity::new("test:boundary.rqlp"),
        policy_source,
    )];
    let options = PolicyEvaluationOptions::new(
        PolicyEvaluationDate::from_ymd(2026, 7, 29).expect("fixed evaluation date"),
    );
    evaluate_policy_inputs_with_analyzer(project.root(), &input, &workspace, &options, None)
        .expect("production taint boundary evaluation")
}

#[test]
fn activated_java_parameter_to_return_summary_reaches_sensitive_sink_under_require_model() {
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    register_pack(
        &catalog,
        &procedure_summary_pack("test.external-flow", None, false),
        "external-flow",
    );
    let request = semantic_model_request("1.5.0", MODEL_ARTIFACT_SHA256);
    let outcome = evaluate_java_with_models(
        JAVA_EXTERNAL_SOURCE,
        &[("test.semantic-summary-flow", "modeled external flow")],
        &catalog,
        &request,
    );

    assert_eq!(
        outcome.report().runs().len(),
        1,
        "{:?}",
        outcome.report().diagnostics()
    );
    let run = &outcome.report().runs()[0];
    assert_eq!(
        run.findings().len(),
        1,
        "completion={:?} diagnostics={:?} work={:?} public={:?}",
        run.completion(),
        run.diagnostics(),
        run.work(),
        outcome.taint_findings()
    );
    assert_eq!(
        outcome.taint_findings().len(),
        1,
        "policy projection must retain the flow"
    );
    let finding = &run.findings()[0];
    assert_eq!(
        finding
            .classification()
            .broad()
            .expect("broad fallback classification")
            .identifier(),
        "BROAD-TAINT"
    );
    assert!(
        finding
            .witnesses()
            .iter()
            .any(|witness| witness.steps().len() > 2),
        "modeled external flow must retain a propagation witness: {:?}",
        finding.witnesses()
    );
    let PolicyFindingEvidence::Taint { evidence } = finding.evidence() else {
        panic!("expected taint policy projection")
    };
    assert_eq!(evidence.origins().len(), 1);
    assert_eq!(
        run.work()
            .metrics()
            .iter()
            .find(|metric| metric.name() == "taint.propagation_solves")
            .map(|metric| metric.value()),
        Some(1)
    );
}

#[test]
fn wrong_semantic_pack_artifact_or_version_never_activates_the_external_flow() {
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    register_pack(
        &catalog,
        &procedure_summary_pack("test.external-near-miss", None, false),
        "external-near-miss",
    );
    for request in [
        semantic_model_request("2.5.0", MODEL_ARTIFACT_SHA256),
        semantic_model_request(
            "1.5.0",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        ),
    ] {
        assert_eq!(active_shard_count(&catalog, &request), 0);
        let outcome = evaluate_java_with_models(
            JAVA_EXTERNAL_SOURCE,
            &[("test.semantic-summary-near-miss", "inactive external flow")],
            &catalog,
            &request,
        );
        assert!(outcome.report().runs()[0].findings().is_empty());
        assert!(outcome.taint_findings().is_empty());
    }
}

#[test]
fn conflicting_external_summary_targets_fail_closed() {
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    register_pack(
        &catalog,
        &procedure_summary_pack("test.external-conflict-a", None, false),
        "external-conflict-a",
    );
    register_pack(
        &catalog,
        &procedure_summary_pack(
            "test.external-conflict-b",
            Some("event.conflicting-model"),
            false,
        ),
        "external-conflict-b",
    );
    let outcome = evaluate_java_with_models(
        JAVA_EXTERNAL_SOURCE,
        &[(
            "test.semantic-summary-conflict",
            "conflicting external flow",
        )],
        &catalog,
        &semantic_model_request("1.5.0", MODEL_ARTIFACT_SHA256),
    );
    let run = &outcome.report().runs()[0];
    assert!(matches!(
        run.completion(),
        PolicyRunCompletion::Failed { .. }
    ));
    assert!(run.findings().is_empty());
    assert!(run.diagnostics().iter().any(|diagnostic| {
        diagnostic
            .message()
            .contains("conflicting activated procedure summaries")
    }));
}

#[test]
fn only_relevant_external_summaries_change_propagation_identity() {
    let project = InlineTestProject::with_language(Language::Java)
        .file("app.java", JAVA_EXTERNAL_SOURCE)
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let baseline_catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    register_pack(
        &baseline_catalog,
        &procedure_summary_pack("test.external-identity", None, false),
        "identity-baseline",
    );
    let baseline = evaluate_java_workspace_with_models(
        project.root(),
        &workspace,
        &[("test.semantic-summary-identity", "baseline")],
        &baseline_catalog,
        &semantic_model_request_with_cache_key("baseline"),
    );

    let changed_catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    register_pack(
        &changed_catalog,
        &procedure_summary_pack(
            "test.external-identity",
            Some("event.relevant-change"),
            false,
        ),
        "identity-changed",
    );
    let changed = evaluate_java_workspace_with_models(
        project.root(),
        &workspace,
        &[("test.semantic-summary-identity", "changed")],
        &changed_catalog,
        &semantic_model_request_with_cache_key("changed"),
    );
    assert_ne!(
        propagation_identity(&baseline),
        propagation_identity(&changed)
    );

    let unrelated_catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    register_pack(
        &unrelated_catalog,
        &procedure_summary_pack("test.external-identity", None, true),
        "identity-unrelated",
    );
    let unrelated = evaluate_java_workspace_with_models(
        project.root(),
        &workspace,
        &[("test.semantic-summary-identity", "unrelated")],
        &unrelated_catalog,
        &semantic_model_request_with_cache_key("unrelated"),
    );
    assert_eq!(
        propagation_identity(&baseline),
        propagation_identity(&unrelated),
        "an unrelated activated record must not enter the plan identity"
    );
}

#[test]
fn materialized_java_body_overrides_activated_external_summary() {
    let project = InlineTestProject::with_language(Language::Java)
        .file("app.java", JAVA_BODY_SOURCE)
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let first_catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    register_pack(
        &first_catalog,
        &procedure_summary_pack("test.body-precedence", None, false),
        "body-precedence-a",
    );
    let first = evaluate_java_workspace_with_models(
        project.root(),
        &workspace,
        &[("test.body-precedence", "body precedence")],
        &first_catalog,
        &semantic_model_request_with_cache_key("body-a"),
    );
    assert_eq!(first.report().runs()[0].findings().len(), 1);

    let second_catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    register_pack(
        &second_catalog,
        &procedure_summary_pack(
            "test.body-precedence",
            Some("event.model-change-hidden-by-body"),
            false,
        ),
        "body-precedence-b",
    );
    let second = evaluate_java_workspace_with_models(
        project.root(),
        &workspace,
        &[("test.body-precedence", "body precedence")],
        &second_catalog,
        &semantic_model_request_with_cache_key("body-b"),
    );
    assert_eq!(second.report().runs()[0].findings().len(), 1);
    assert_eq!(
        propagation_identity(&first),
        propagation_identity(&second),
        "a model for a materialized body must not affect propagation identity"
    );
}

#[test]
fn compatible_semantic_summary_policies_share_one_solve() {
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    register_pack(
        &catalog,
        &procedure_summary_pack("test.external-batch", None, false),
        "external-batch",
    );
    let outcome = evaluate_java_with_models(
        JAVA_EXTERNAL_SOURCE,
        &[
            ("test.semantic-summary-batch-a", "first presentation"),
            ("test.semantic-summary-batch-b", "second presentation"),
        ],
        &catalog,
        &semantic_model_request("1.5.0", MODEL_ARTIFACT_SHA256),
    );
    assert_eq!(outcome.report().runs().len(), 2);
    assert_eq!(outcome.taint_analysis_results().len(), 1);
    for run in outcome.report().runs() {
        assert_eq!(run.findings().len(), 1, "{:?}", run.diagnostics());
        assert_eq!(
            run.work()
                .metrics()
                .iter()
                .find(|metric| metric.name() == "taint.propagation_solves")
                .map(|metric| metric.value()),
            Some(1)
        );
        assert_eq!(
            run.work()
                .metrics()
                .iter()
                .find(|metric| metric.name() == "taint.propagation_shared_memberships")
                .map(|metric| metric.value()),
            Some(1)
        );
    }
}

#[test]
fn warm_semantic_summary_execution_performs_no_per_call_catalog_lookup() {
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    register_pack(
        &catalog,
        &procedure_summary_pack("test.external-warm", None, false),
        "external-warm",
    );
    let project = InlineTestProject::with_language(Language::Java)
        .file("app.java", JAVA_EXTERNAL_SOURCE)
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let policy = java_summary_policy("test.semantic-summary-warm", "warm execution");
    let inputs = [PolicyEvaluationInput::embedded(
        PolicySourceIdentity::new("test:semantic-summary-warm.rqlp"),
        &policy,
    )];
    let options = PolicyEvaluationOptions::new(
        PolicyEvaluationDate::from_ymd(2026, 7, 31).expect("fixed evaluation date"),
    );
    let request = semantic_model_request("1.5.0", MODEL_ARTIFACT_SHA256);
    let evaluate = || {
        evaluate_policy_inputs_with_analyzer_and_semantic_models(
            project.root(),
            &inputs,
            &workspace,
            &options,
            PolicySemanticModelContext {
                catalog: &catalog,
                request: &request,
                persistence: None,
            },
            None,
        )
        .expect("warm semantic-summary evaluation")
    };

    let first = evaluate();
    assert_eq!(first.report().runs()[0].findings().len(), 1);
    let after_first = catalog.accounting().unwrap();
    let first_lookup_counts = (after_first.lookup_hits, after_first.lookup_misses);
    assert_eq!(first_lookup_counts, (1, 0));

    let second = evaluate();
    assert_eq!(second.report().runs()[0].findings().len(), 1);
    let after_second = catalog.accounting().unwrap();
    assert_eq!(
        (after_second.lookup_hits, after_second.lookup_misses),
        first_lookup_counts,
        "cached acquisition and every per-call target lookup must stay in memory"
    );
}

#[test]
fn production_taint_keeps_caller_and_callee_endpoints_in_one_call_region() {
    let policy = single_policy(
        "test.interprocedural-taint",
        "(language python (call :callee (name \"source_one\")))",
        "return-value",
    );
    let outcome = evaluate_one(INTERPROCEDURAL_SOURCE, &policy);
    assert_eq!(
        outcome.report().runs().len(),
        1,
        "{:?}",
        outcome.report().diagnostics()
    );
    assert_eq!(outcome.report().runs()[0].findings().len(), 1);
    assert_eq!(outcome.taint_findings().len(), 1);
}

#[test]
fn production_taint_discovers_an_unselected_common_caller_for_sibling_callees() {
    let policy = single_policy(
        "test.sibling-callee-taint",
        "(language python (call :callee (name \"source_one\")))",
        "return-value",
    );
    let outcome = evaluate_one(SIBLING_CALLEE_SOURCE, &policy);
    assert_eq!(
        outcome.report().runs().len(),
        1,
        "{:?}",
        outcome.report().diagnostics()
    );
    let run = &outcome.report().runs()[0];
    assert!(matches!(
        run.completion(),
        PolicyRunCompletion::Inconclusive { reasons }
            if reasons.contains(&PolicyIncompleteReason::PartialDiscovery)
    ));
    assert!(run.findings().is_empty());
    assert_eq!(outcome.taint_findings().len(), 1);
    assert_eq!(
        run.work()
            .metrics()
            .iter()
            .find(|metric| metric.name() == "taint.propagation_solves")
            .map(|metric| metric.value()),
        Some(1)
    );
}

#[test]
fn production_taint_matched_value_uses_the_direct_source_observation() {
    let policy = single_policy(
        "test.matched-value-taint",
        "(language python (name \"first\"))",
        "matched-value",
    );
    let outcome = evaluate_one(MATCHED_VALUE_SOURCE, &policy);
    assert_eq!(
        outcome.report().runs().len(),
        1,
        "{:?}",
        outcome.report().diagnostics()
    );
    let run = &outcome.report().runs()[0];
    assert!(
        run.diagnostics()
            .iter()
            .all(|diagnostic| !diagnostic.message().contains("semantic call site")),
        "{:?}",
        run.diagnostics()
    );
    assert_eq!(run.findings().len(), 1, "{:?}", run.diagnostics());
    assert_eq!(outcome.taint_findings().len(), 1);
}

#[test]
fn production_taint_complete_zero_match_is_clean_without_propagation() {
    let policy = single_policy(
        "test.zero-match-taint",
        "(language python (call :callee (name \"source_one\")))",
        "return-value",
    );
    let outcome = evaluate_one(
        r#"
def sink_one(value):
    pass

def run():
    sink_one("constant")
"#,
        &policy,
    );
    let run = &outcome.report().runs()[0];
    assert!(matches!(run.completion(), PolicyRunCompletion::Complete));
    assert!(run.findings().is_empty());
    assert!(run.diagnostics().is_empty());
    assert!(outcome.taint_findings().is_empty());
    assert!(
        run.work()
            .metrics()
            .iter()
            .all(|metric| metric.name() != "taint.propagation_solves")
    );
}

#[test]
fn production_taint_policies_share_a_batch_and_all_renderers_keep_the_same_evidence() {
    let project = InlineTestProject::with_language(Language::Python)
        .file("app.py", SOURCE)
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let first = policy("test.taint-first", "first presentation", "warning");
    let second = subset_policy("test.taint-second");
    let inputs = [
        PolicyEvaluationInput::embedded(PolicySourceIdentity::new("test:first.rqlp"), &first),
        PolicyEvaluationInput::embedded(PolicySourceIdentity::new("test:second.rqlp"), &second),
    ];
    let options = PolicyEvaluationOptions::new(
        PolicyEvaluationDate::from_ymd(2026, 7, 29).expect("fixed evaluation date"),
    );
    let outcome =
        evaluate_policy_inputs_with_analyzer(project.root(), &inputs, &workspace, &options, None)
            .expect("production taint evaluation");

    assert_eq!(
        outcome.report().runs().len(),
        2,
        "report diagnostics: {:?}",
        outcome.report().diagnostics()
    );
    for run in outcome.report().runs() {
        assert!(
            matches!(
                run.completion(),
                PolicyRunCompletion::Complete | PolicyRunCompletion::Inconclusive { .. }
            ),
            "{:?}: {:?}",
            run.completion(),
            run.diagnostics()
        );
        let expected_findings = if run.policy_id().as_str() == "test.taint-first" {
            2
        } else {
            1
        };
        assert_eq!(run.findings().len(), expected_findings);
        assert_eq!(
            run.work()
                .metrics()
                .iter()
                .find(|metric| metric.name() == "taint.propagation_solves")
                .expect("taint solve metric")
                .value(),
            1
        );
        assert_eq!(
            run.work()
                .metrics()
                .iter()
                .find(|metric| metric.name() == "taint.propagation_shared_memberships")
                .expect("shared batch metric")
                .value(),
            1
        );
        for finding in run.findings() {
            assert_eq!(
                finding
                    .classification()
                    .broad()
                    .expect("broad fallback classification")
                    .identifier(),
                "BROAD-TAINT"
            );
            let PolicyFindingEvidence::Taint { evidence } = finding.evidence() else {
                panic!("expected taint evidence");
            };
            assert_eq!(evidence.reached_source_labels().len(), 1);
            assert_eq!(evidence.origins().len(), 1);
            assert!(!finding.witnesses().is_empty());
            assert_eq!(
                finding.completeness().is_complete(),
                matches!(run.completion(), PolicyRunCompletion::Complete)
            );
        }
    }

    assert_eq!(outcome.taint_findings().len(), 2);
    assert_eq!(outcome.taint_analysis_results().len(), 1);
    let retained = &outcome.taint_analysis_results()[0];
    assert!(retained.plan_report_match());
    assert!(retained.retained_plan_bytes() > 0);
    assert!(retained.retained_report_bytes() > 0);
    assert!(!retained.artifact_keys().is_empty());
    assert!(retained.retained_artifact_bytes() > 0);
    assert_eq!(
        retained
            .project_findings(&workspace, retained.projection_limits())
            .expect("retained production taint projection"),
        outcome.taint_findings()
    );
    assert_eq!(
        retained
            .project_findings(
                &workspace,
                brokk_bifrost::analyzer::structural::CodeQueryTaintProjectionLimits::new(
                    usize::MAX,
                    usize::MAX,
                    usize::MAX,
                    usize::MAX,
                ),
            )
            .expect("projection cannot exceed retained production authority"),
        outcome.taint_findings()
    );
    let first_ref = TaintResultRef::new("request", "primary").expect("bounded taint ref");
    let alias_ref = TaintResultRef::new("request", "alias").expect("bounded taint ref");
    let registration = TaintResultRegistration::new(7, vec![Arc::clone(retained)])
        .expect("valid retained taint registration");
    let mut registrations = TaintResultRegistrationSet::default();
    assert_eq!(
        registrations
            .register(first_ref.clone(), registration)
            .expect("insert retained taint result"),
        TaintResultRegistrationOutcome::Inserted
    );
    assert_eq!(
        registrations
            .register(
                alias_ref.clone(),
                TaintResultRegistration::new(7, vec![Arc::clone(retained)])
                    .expect("valid taint alias"),
            )
            .expect("alias retained taint result"),
        TaintResultRegistrationOutcome::Aliased
    );
    assert!(matches!(
        registrations.register(
            first_ref.clone(),
            TaintResultRegistration::new(8, vec![Arc::clone(retained)])
                .expect("different-generation registration"),
        ),
        Err(TaintResultRegistrationSetError::ReferenceConflict { .. })
    ));
    assert_eq!(registrations.reference_count(), 2);
    assert_eq!(registrations.registration_count(), 1);

    let json_query = CodeQuery::from_json(&serde_json::json!({
        "schema_version": 7,
        "match": { "kind": "function", "name": "run" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "taint", "taint_ref": "request:primary" }
        ]
    }))
    .expect("schema-v7 taint JSON query");
    let rql_query = CodeQuery::from_sexp(
        r#"(taint :taint-ref request:alias (procedure-of (function :name "run")))"#,
    )
    .expect("schema-v7 taint RQL query");
    let execute = |query: &CodeQuery,
                   generation: u64,
                   taint_registrations: &TaintResultRegistrationSet,
                   limits: CodeQueryExecutionLimits| {
        let summaries = Arc::new(ProductionTypestateSummaryRepository::new());
        let lease = summaries
            .lease(generation)
            .expect("generation-scoped summary lease");
        execute_workspace_request_with_all_analysis_registration_lease(
            &workspace,
            generation,
            &ProtocolRegistrationSet::default(),
            &ValueFlowPlanRegistrationSet::default(),
            taint_registrations,
            query,
            limits,
            None,
            lease,
        )
    };
    let json_response = execute(
        &json_query,
        7,
        &registrations,
        CodeQueryExecutionLimits::default(),
    );
    let rql_response = execute(
        &rql_query,
        7,
        &registrations,
        CodeQueryExecutionLimits::default(),
    );
    let json_result = json_response.result().expect("executed JSON result");
    let rql_result = rql_response.result().expect("executed RQL result");
    assert!(
        json_result.diagnostics.is_empty(),
        "{:?}",
        json_result.diagnostics
    );
    assert!(
        rql_result.diagnostics.is_empty(),
        "{:?}",
        rql_result.diagnostics
    );
    assert_eq!(
        serde_json::to_value(&json_result.results).expect("JSON result serialization"),
        serde_json::to_value(&rql_result.results).expect("RQL result serialization")
    );
    assert_eq!(json_result.results.len(), outcome.taint_findings().len());

    let mut row_limited = CodeQueryExecutionLimits::default();
    row_limited.taint.max_findings = 1;
    let row_limited = execute(&json_query, 7, &registrations, row_limited);
    let row_limited = row_limited.result().expect("row-limited taint result");
    assert_eq!(row_limited.results.len(), 1);
    assert!(
        row_limited.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == CodeQueryDiagnosticCode::TaintFindingTruncated
        })
    );

    let mut byte_limited = CodeQueryExecutionLimits::default();
    byte_limited.taint.max_projected_bytes = 1;
    let byte_limited = execute(&json_query, 7, &registrations, byte_limited);
    let byte_limited = byte_limited.result().expect("byte-limited taint result");
    assert!(byte_limited.results.is_empty());
    assert!(
        byte_limited.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == CodeQueryDiagnosticCode::TaintFindingTruncated
        })
    );

    let missing_query = CodeQuery::from_json(&serde_json::json!({
        "schema_version": 7,
        "match": { "kind": "function", "name": "run" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "taint", "taint_ref": "request:missing" }
        ]
    }))
    .expect("missing-ref taint query");
    let missing = execute(
        &missing_query,
        7,
        &registrations,
        CodeQueryExecutionLimits::default(),
    );
    assert!(
        missing
            .result()
            .expect("missing-ref result")
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code
                == CodeQueryDiagnosticCode::UnresolvedTaintResultReference)
    );

    let wrong_root_query = CodeQuery::from_json(&serde_json::json!({
        "schema_version": 7,
        "match": { "kind": "function", "name": "source_one" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "taint", "taint_ref": "request:primary" }
        ]
    }))
    .expect("wrong-root taint query");
    let wrong_root = execute(
        &wrong_root_query,
        7,
        &registrations,
        CodeQueryExecutionLimits::default(),
    );
    assert!(
        wrong_root
            .result()
            .expect("wrong-root result")
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == CodeQueryDiagnosticCode::TaintRootMismatch)
    );

    let stale = execute(
        &json_query,
        8,
        &registrations,
        CodeQueryExecutionLimits::default(),
    );
    assert!(
        stale
            .result()
            .expect("stale result")
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == CodeQueryDiagnosticCode::TaintRegistrationStale)
    );

    assert!(registrations.unregister(&first_ref));
    assert_eq!(registrations.reference_count(), 1);
    assert_eq!(registrations.registration_count(), 1);
    assert!(registrations.unregister(&alias_ref));
    assert_eq!(registrations.registration_count(), 0);

    assert!(matches!(
        TaintResultRegistration::new(7, vec![Arc::clone(retained), Arc::clone(retained)]),
        Err(TaintResultRegistrationError::DuplicateRoot)
    ));
    let mut bounded = TaintResultRegistrationSet::with_limits(
        TaintResultRegistrationLimits::bounded(1, 1, 0, usize::MAX, usize::MAX),
    );
    assert!(matches!(
        bounded.register(
            first_ref,
            TaintResultRegistration::new(7, vec![Arc::clone(retained)])
                .expect("valid bounded registration"),
        ),
        Err(TaintResultRegistrationSetError::RetainedPlanBytes(0))
    ));
    assert_eq!(bounded.reference_count(), 0);
    assert_eq!(bounded.registration_count(), 0);
    assert_eq!(outcome.taint_query_results().len(), 2);
    for result in outcome.taint_query_results() {
        let value = serde_json::to_value(result).expect("public taint query serialization");
        assert_eq!(value["result_type"], "taint_finding");
        assert!(value.get("plan_ref").is_none());
        assert!(
            value["witnesses"]
                .as_array()
                .expect("taint witness array")
                .iter()
                .all(|witness| witness.get("plan_ref").is_none()
                    && witness.get("finding_id").is_some())
        );
    }
    assert!(outcome.taint_findings().iter().all(|finding| {
        finding.reached_labels == ["untrusted"]
            && finding.origins.len() == 1
            && !finding.witnesses.is_empty()
            && finding
                .witnesses
                .iter()
                .all(|witness| witness.finding_id == finding.id)
    }));

    let finding_ids = outcome
        .report()
        .runs()
        .iter()
        .flat_map(|run| run.findings())
        .map(|finding| finding.id().to_string())
        .collect::<Vec<_>>();
    let mut human = Vec::new();
    write_policy_human(
        outcome.report(),
        &HumanRenderOptions::new(HumanRenderDetail::Verbose, HumanRenderColor::Plain),
        &mut human,
        usize::MAX,
    )
    .expect("human rendering");
    let mut json = Vec::new();
    write_policy_json(outcome.report(), &mut json, usize::MAX).expect("JSON rendering");
    let mut sarif = Vec::new();
    write_policy_sarif(
        outcome.report(),
        &SarifToolIdentity::default(),
        &mut sarif,
        usize::MAX,
    )
    .expect("SARIF rendering");
    let human = String::from_utf8(human).expect("human UTF-8");
    let json = String::from_utf8(json).expect("JSON UTF-8");
    let sarif = String::from_utf8(sarif).expect("SARIF UTF-8");
    for finding_id in finding_ids {
        assert!(human.contains(&finding_id));
        assert!(json.contains(&finding_id));
        assert!(sarif.contains(&finding_id));
    }
    for rendered in [&human, &json, &sarif] {
        assert!(rendered.contains("BROAD-TAINT"));
        assert!(rendered.contains("untrusted"));
    }
}
