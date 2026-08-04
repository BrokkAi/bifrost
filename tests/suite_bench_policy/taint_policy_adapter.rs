use crate::common::{InlineTestProject, semantic_graph::SemanticGraph};
use brokk_bifrost::analyzer::dataflow::{
    DataflowRequest, ExternalSummaryCompatibilityKey, SemanticInputStatus, SolverBudget,
    SummaryBehaviorKey, SummaryCompleteness, SummaryContextKey, SummaryEffectKey, SummaryExitKind,
    SummaryPort, SummarySchemaVersion, SummarySemanticsVersion, UnmodeledCallBehavior,
    WitnessReconstructionLimits, WitnessRetentionLimits,
};
use brokk_bifrost::analyzer::semantic::{
    ControlContinuation, EvidenceCompleteness, IcfgProvider, OracleCallContext, ProcedureHandle,
    ProcedureKind, ProofStatus, SemanticBudget, SemanticRequest, ValueFlowOracle,
};
use brokk_bifrost::analyzer::semantic_model::{
    CatalogCoordinate, CatalogOptions, CompiledSemanticModelPack, CompilerOptions, DecodeLimits,
    ExactProcedureSummaryBoundary, ExactProcedureSummaryParameter, ExactProcedureSummaryReceiver,
    ExactProcedureSummaryTargetBinding, SemanticModelActivationControl,
    SemanticModelActivationEvidence, SemanticModelActivationRequest, SemanticModelControlAction,
    SemanticModelControlScope, SemanticModelPackSelector, SemanticModelResolutionOutcome,
    SemanticModelRuntimeLimits, SemanticPackCatalog, SessionPackSource, SessionPackSourceKind,
    SourceFormat, bind_compiled_procedure_summaries, compile_source, decode_shard_for_manifest,
    resolve_active_semantic_models,
};
use brokk_bifrost::analyzer::structural::{
    CodeQuery, CodeQueryDiagnosticCode, CodeQueryExecutionLimits, CodeQueryFlowFactSymbol,
    CodeQueryFlowWitnessStepKind, CodeQuerySemanticCompleteness, CodeQuerySemanticProof,
    CodeQuerySourceSite, ProtocolRegistrationSet, TaintResultRef, TaintResultRegistration,
    TaintResultRegistrationError, TaintResultRegistrationLimits, TaintResultRegistrationOutcome,
    TaintResultRegistrationSet, TaintResultRegistrationSetError, ValueFlowPlanRegistrationSet,
    execute_workspace_request_with_all_analysis_registration_lease, project_taint_finding_report,
};
use brokk_bifrost::analyzer::taint::{
    SourceClassId, SourceEventKey, TaintAnalysisPlan, TaintClassSet, TaintFindingCollectionLimits,
    TaintSinkBinding, TaintSourceBinding, TaintUniverse, collect_taint_findings_with_limits,
    solve_taint_batch_with_witnesses,
};
use brokk_bifrost::analyzer::typestate::ProductionTypestateSummaryRepository;
use brokk_bifrost::analyzer::value_flow::{
    ValueFlowCarrier, ValueFlowEventKey, ValueFlowEventKind, ValueFlowInput,
    ValueFlowObservationPhase, ValueFlowPlan, ValueFlowSinkSpec, ValueFlowSourceSpec,
};
use brokk_bifrost::policy::{
    FindingCertainty, HumanRenderColor, HumanRenderDetail, HumanRenderOptions,
    PolicyEvaluationDate, PolicyEvaluationInput, PolicyEvaluationOptions, PolicyFindingEvidence,
    PolicyIncompleteReason, PolicyRunCompletion, PolicySemanticModelContext, PolicySourceIdentity,
    PolicySourceLocation, SarifToolIdentity, WitnessStepKind, evaluate_policy_inputs_with_analyzer,
    evaluate_policy_inputs_with_analyzer_and_semantic_models, write_policy_human,
    write_policy_json, write_policy_sarif,
};
use brokk_bifrost::{AnalyzerConfig, CancellationToken, Language};
use semver::Version;
use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;

const WORKSPACE_GENERATION: u64 = 71;

const MODEL_ARTIFACT_SHA256: &str =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

const JAVA_EXTERNAL_SOURCE: &str = r#"
class App {
    static native String attacker();
    static native String clean();
    static native void sensitive(String value);
    native String external(String value, String sibling);

    void run() {
        sensitive(this.external(attacker(), clean()));
    }
}
"#;

const JAVA_BODY_SOURCE: &str = r#"
class App {
    static native String attacker();
    static native String clean();
    static native void sensitive(String value);

    String external(String value, String sibling) {
        return value;
    }

    void run() {
        sensitive(this.external(attacker(), clean()));
    }
}
"#;

const JAVA_DEPENDENCY_SOURCE: &str = r#"
class App {
    static native String attacker();
    static native String clean();
    static native void sensitive(String value);
    native String relay(String value);
    native String external(String value, String sibling);

    void run() {
        sensitive(this.external(attacker(), clean()));
    }
}
"#;

const JAVA_COMPLETE_DEPENDENCY_SOURCE: &str = r#"
class App {
    static native String attacker();
    static native String clean();
    static native void sensitive(String value);
    native String relay(String value);
    native String external(String value, String sibling);

    void run() {
        this.relay(clean());
        sensitive(this.external(attacker(), clean()));
    }
}
"#;

const JAVA_MULTI_DEMAND_SOURCE: &str = r#"
class App {
    static native String attackerOne();
    static native String attackerTwo();
    static native String clean();
    static native void sensitiveOne(String value);
    static native void sensitiveTwo(String value);
    native String external(String value, String sibling);

    void run() {
        sensitiveOne(this.external(attackerOne(), clean()));
        sensitiveTwo(this.external(attackerTwo(), clean()));
        sensitiveTwo(this.external(clean(), clean()));
    }
}
"#;

const JAVA_EXECUTABLE_TRANSFER_SOURCE: &str = r#"
class App {
    static native String attackerParameter();
    static native App attackerReceiver();
    static native String attackerReceiverOutput();
    static native String attackerExceptional();
    static native App cleanReceiver();
    static native String clean();
    static native void normalSink(String value);
    static native void receiverSink(App value);
    static native void exceptionalSink(Exception value);
    native String parameterToReturn(String value);
    native String receiverToReturn(String value);
    native void parameterToReceiver(String value);
    native String parameterToExceptional(String value) throws Exception;

    void run() {
        normalSink(this.parameterToReturn(attackerParameter()));
        normalSink(attackerReceiver().receiverToReturn(clean()));
        App receiver = cleanReceiver();
        receiver.parameterToReceiver(attackerReceiverOutput());
        receiverSink(receiver);
        try {
            this.parameterToExceptional(attackerExceptional());
        } catch (Exception error) {
            exceptionalSink(error);
        }
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

fn duplicate_source_event_policy(id: &str) -> String {
    format!(
        r#"(policy
          :schema-version 1
          :id "{id}"
          :name "Distinct logical source events"
          :message "same topology from two source events"
          :severity warning
          :analysis (analysis
            :type taint
            :mode may
            :call-modeling (call-modeling :unmodeled optimistic)
            :sources (endpoint-set :entries [
              (source :id first :display-name "first logical source" :categories [input.user]
                :selector (rql :schema-version 6
                  (language python (call :callee (name "source_one"))))
                :bind return-value :labels [untrusted])
              (source :id second :display-name "second logical source" :categories [input.user]
                :selector (rql :schema-version 6
                  (language python (call :callee (name "source_one"))))
                :bind return-value :labels [untrusted])])
            :sinks (endpoint-set :entries [
              (sink :id store :display-name "sink" :categories [data.sensitive]
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
                :bind return-value :labels [untrusted])
              (source :id clean :display-name "clean sibling" :categories [input.user]
                :selector (rql :schema-version 6
                  (language java (call :callee (name "clean"))))
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

fn java_duplicate_source_summary_policy(id: &str) -> String {
    java_duplicate_source_summary_policy_with_order(id, false)
}

fn java_duplicate_source_summary_policy_with_order(id: &str, reverse_sources: bool) -> String {
    let first = r#"(source :id first :display-name "first logical source" :categories [input.user]
                :selector (rql :schema-version 6
                  (language java (call :callee (name "attacker"))))
                :bind return-value :labels [untrusted])"#;
    let second = r#"(source :id second :display-name "second logical source" :categories [input.user]
                :selector (rql :schema-version 6
                  (language java (call :callee (name "attacker"))))
                :bind return-value :labels [untrusted])"#;
    let sources = if reverse_sources {
        format!("{second}\n              {first}")
    } else {
        format!("{first}\n              {second}")
    };
    format!(
        r#"(policy
          :schema-version 1
          :id "{id}"
          :name "Model-backed distinct source origins"
          :message "two origins share one model-backed path"
          :severity warning
          :analysis (analysis
            :type taint
            :mode may
            :call-modeling (call-modeling :unmodeled require-model)
            :sources (endpoint-set :entries [
              {sources}])
            :sinks (endpoint-set :entries [
              (sink :id sensitive :display-name "sensitive sink" :categories [data.sensitive]
                :selector (rql :schema-version 6
                  (language java (call :callee (name "sensitive"))))
                :dangerous-operand (argument :index 0) :accepts [untrusted])]))
          :classification (classification
            :fallback (classification-id :taxonomy "Test" :id "BROAD-TAINT")))"#
    )
}

fn java_multi_demand_summary_policy(id: &str) -> String {
    format!(
        r#"(policy
          :schema-version 1
          :id "{id}"
          :name "Model-backed multi demand"
          :message "compatible source and sink demand"
          :severity warning
          :analysis (analysis
            :type taint
            :mode may
            :call-modeling (call-modeling :unmodeled require-model)
            :sources (endpoint-set :entries [
              (source :id first :display-name "first attacker" :categories [input.user]
                :selector (rql :schema-version 6
                  (language java (call :callee (name "attackerOne"))))
                :bind return-value :labels [first-label])
              (source :id second :display-name "second attacker" :categories [input.user]
                :selector (rql :schema-version 6
                  (language java (call :callee (name "attackerTwo"))))
                :bind return-value :labels [second-label])])
            :sinks (endpoint-set :entries [
              (sink :id first-sink :display-name "first sink" :categories [data.sensitive]
                :selector (rql :schema-version 6
                  (language java (call :callee (name "sensitiveOne"))))
                :dangerous-operand (argument :index 0) :accepts [first-label second-label])
              (sink :id second-sink :display-name "second sink" :categories [data.sensitive]
                :selector (rql :schema-version 6
                  (language java (call :callee (name "sensitiveTwo"))))
                :dangerous-operand (argument :index 0) :accepts [first-label second-label])]))
          :classification (classification
            :fallback (classification-id :taxonomy "Test" :id "BROAD-TAINT")))"#
    )
}

fn java_executable_transfer_policy(id: &str) -> String {
    format!(
        r#"(policy
          :schema-version 1
          :id "{id}"
          :name "Executable semantic-summary transfers"
          :message "each live boundary transfer reaches only its sink"
          :severity warning
          :analysis (analysis
            :type taint
            :mode may
            :call-modeling (call-modeling :unmodeled require-model)
            :sources (endpoint-set :entries [
              (source :id parameter :display-name "parameter input" :categories [input.user]
                :selector (rql :schema-version 6
                  (language java (call :callee (name "attackerParameter"))))
                :bind return-value :labels [parameter-label])
              (source :id receiver-input :display-name "receiver input" :categories [input.user]
                :selector (rql :schema-version 6
                  (language java (call :callee (name "attackerReceiver"))))
                :bind return-value :labels [receiver-input-label])
              (source :id receiver-output :display-name "receiver output" :categories [input.user]
                :selector (rql :schema-version 6
                  (language java (call :callee (name "attackerReceiverOutput"))))
                :bind return-value :labels [receiver-output-label])
              (source :id exceptional :display-name "exceptional input" :categories [input.user]
                :selector (rql :schema-version 6
                  (language java (call :callee (name "attackerExceptional"))))
                :bind return-value :labels [exceptional-label])])
            :sinks (endpoint-set :entries [
              (sink :id normal :display-name "normal sink" :categories [data.sensitive]
                :selector (rql :schema-version 6
                  (language java (call :callee (name "normalSink"))))
                :dangerous-operand (argument :index 0)
                :accepts [parameter-label receiver-input-label receiver-output-label exceptional-label])
              (sink :id receiver :display-name "receiver sink" :categories [data.sensitive]
                :selector (rql :schema-version 6
                  (language java (call :callee (name "receiverSink"))))
                :dangerous-operand (argument :index 0)
                :accepts [parameter-label receiver-input-label receiver-output-label exceptional-label])
              (sink :id exceptional-sink :display-name "exceptional sink" :categories [data.sensitive]
                :selector (rql :schema-version 6
                  (language java (call :callee (name "exceptionalSink"))))
                :dangerous-operand (argument :index 0)
                :accepts [parameter-label receiver-input-label receiver-output-label exceptional-label])]))
          :classification (classification
            :fallback (classification-id :taxonomy "Test" :id "BROAD-TAINT")))"#
    )
}

fn procedure_summary_pack(
    pack_id: &str,
    model_effect: Option<&str>,
    include_unrelated: bool,
) -> CompiledSemanticModelPack {
    let effects = model_effect
        .into_iter()
        .map(|event| {
            serde_json::json!({
                "kind": "unknown_call_boundary",
                "event": event
            })
        })
        .collect::<Vec<_>>();
    let mut summaries = vec![serde_json::json!({
        "id": "summary.external",
        "target": {
            "path": "app.java",
            "symbol": "external(String, String)",
            "has_receiver": true,
            "parameter_count": 2
        },
        "completeness": "complete",
        "transfers": [{
            "input": { "kind": "parameter", "ordinal": 0 },
            "exit_kind": "normal",
            "output": { "kind": "normal_return" }
        }],
        "effects": effects
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
    compile_procedure_summary_pack(pack_id, summaries)
}

fn procedure_summary_dependency_pack(pack_id: &str, recursive: bool) -> CompiledSemanticModelPack {
    let external_effects = [serde_json::json!({
        "kind": "call",
        "event": "event.external.relay",
        "callee": "summary.relay"
    })];
    let relay_effects = recursive
        .then(|| {
            serde_json::json!({
                "kind": "call",
                "event": "event.relay.external",
                "callee": "summary.external"
            })
        })
        .into_iter()
        .collect::<Vec<_>>();
    compile_procedure_summary_pack(
        pack_id,
        vec![
            serde_json::json!({
                "id": "summary.external",
                "target": {
                    "path": "app.java",
                    "symbol": "external(String, String)",
                    "has_receiver": true,
                    "parameter_count": 2
                },
                "completeness": "complete",
                "transfers": [{
                    "input": { "kind": "parameter", "ordinal": 0 },
                    "exit_kind": "normal",
                    "output": { "kind": "normal_return" }
                }],
                "effects": external_effects
            }),
            serde_json::json!({
                "id": "summary.relay",
                "target": {
                    "path": "app.java",
                    "symbol": "relay(String)",
                    "has_receiver": true,
                    "parameter_count": 1
                },
                "completeness": "complete",
                "transfers": [{
                    "input": { "kind": "parameter", "ordinal": 0 },
                    "exit_kind": "normal",
                    "output": { "kind": "normal_return" }
                }],
                "effects": relay_effects
            }),
        ],
    )
}

fn compile_procedure_summary_pack(
    pack_id: &str,
    summaries: Vec<serde_json::Value>,
) -> CompiledSemanticModelPack {
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

fn procedure_summary_transfer_matrix_pack(pack_id: &str) -> CompiledSemanticModelPack {
    compile_procedure_summary_pack(
        pack_id,
        vec![serde_json::json!({
            "id": "summary.external",
            "target": {
                "path": "app.java",
                "symbol": "external(String, String)",
                "has_receiver": true,
                "parameter_count": 2
            },
            "completeness": "partial",
            "locations": [
                { "id": "location.capture", "location_kind": "capture" },
                { "id": "location.heap", "location_kind": "heap" }
            ],
            "transfers": [
                {
                    "input": { "kind": "parameter", "ordinal": 0 },
                    "exit_kind": "normal",
                    "output": { "kind": "normal_return" }
                },
                {
                    "input": { "kind": "receiver" },
                    "exit_kind": "normal",
                    "output": { "kind": "receiver" }
                },
                {
                    "input": { "kind": "parameter", "ordinal": 0 },
                    "exit_kind": "exceptional",
                    "output": { "kind": "exceptional_return" }
                },
                {
                    "input": { "kind": "parameter", "ordinal": 0 },
                    "exit_kind": "normal",
                    "output": { "kind": "capture", "location": "location.capture" }
                },
                {
                    "input": { "kind": "parameter", "ordinal": 0 },
                    "exit_kind": "normal",
                    "output": { "kind": "heap", "location": "location.heap" }
                }
            ],
            "effects": [
                {
                    "kind": "allocation",
                    "event": "event.external.allocate",
                    "output": { "kind": "heap", "location": "location.heap" }
                },
                {
                    "kind": "escape",
                    "event": "event.external.escape",
                    "input": { "kind": "parameter", "ordinal": 0 }
                }
            ]
        })],
    )
}

fn executable_procedure_summary_transfer_pack(pack_id: &str) -> CompiledSemanticModelPack {
    let summary = |id: &str,
                   symbol: &str,
                   parameter_count: usize,
                   input: serde_json::Value,
                   exit_kind: &str,
                   output: serde_json::Value| {
        serde_json::json!({
            "id": id,
            "target": {
                "path": "app.java",
                "symbol": symbol,
                "has_receiver": true,
                "parameter_count": parameter_count
            },
            "completeness": "complete",
            "transfers": [{
                "input": input,
                "exit_kind": exit_kind,
                "output": output
            }],
            "effects": []
        })
    };
    compile_procedure_summary_pack(
        pack_id,
        vec![
            summary(
                "summary.parameter-to-return",
                "parameterToReturn(String)",
                1,
                serde_json::json!({ "kind": "parameter", "ordinal": 0 }),
                "normal",
                serde_json::json!({ "kind": "normal_return" }),
            ),
            summary(
                "summary.receiver-to-return",
                "receiverToReturn(String)",
                1,
                serde_json::json!({ "kind": "receiver" }),
                "normal",
                serde_json::json!({ "kind": "normal_return" }),
            ),
            summary(
                "summary.parameter-to-receiver",
                "parameterToReceiver(String)",
                1,
                serde_json::json!({ "kind": "parameter", "ordinal": 0 }),
                "normal",
                serde_json::json!({ "kind": "receiver" }),
            ),
            summary(
                "summary.parameter-to-exception",
                "parameterToExceptional(String)",
                1,
                serde_json::json!({ "kind": "parameter", "ordinal": 0 }),
                "exceptional",
                serde_json::json!({ "kind": "exceptional_return" }),
            ),
        ],
    )
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
        .unwrap_or_else(|| panic!("missing Java method {name}"));
    graph.artifact().procedure_handle(procedure.id()).unwrap()
}

fn direct_model_backed_findings(
    project: &crate::common::BuiltInlineTestProject,
    workspace: &brokk_bifrost::analyzer::WorkspaceAnalyzer,
    pack: &CompiledSemanticModelPack,
) -> Vec<brokk_bifrost::analyzer::structural::CodeQueryTaintFinding> {
    let graph = SemanticGraph::materialize(project, workspace, "app.java");
    let root = procedure_named(&graph, "run");
    let cancellation = CancellationToken::default();
    let calls_named = |symbol: &str| {
        root.semantics()
            .call_sites()
            .iter()
            .filter(|call| {
                let mut budget = SemanticBudget::default();
                workspace
                    .icfg_provider()
                    .call_transfers(
                        &root,
                        call.id,
                        &mut SemanticRequest::new(&mut budget, &cancellation),
                    )
                    .ok()
                    .and_then(|outcome| outcome.available_value().cloned())
                    .is_some_and(|transfers| {
                        transfers.boundaries.iter().any(|boundary| {
                            boundary
                                .dispatch
                                .exact_external_target()
                                .is_some_and(|target| target.symbol() == symbol)
                        })
                    })
            })
            .cloned()
            .collect::<Vec<_>>()
    };
    let call_named = |symbol: &str| {
        let calls = calls_named(symbol);
        let [call] = calls.as_slice() else {
            panic!("expected one Java call {symbol}, got {}", calls.len());
        };
        call.clone()
    };
    let attacker = call_named("attacker()");
    call_named("external(String, String)");
    let sensitive = call_named("sensitive(String)");
    let attacker_point = match attacker.normal_continuation {
        ControlContinuation::Target(point) => root.point_handle(point).unwrap(),
        ref other => panic!("attacker call lacks a normal continuation: {other:?}"),
    };
    let attacker_value = root.value_handle(attacker.result.unwrap()).unwrap();
    let sensitive_point = root.point_handle(sensitive.point).unwrap();
    let sensitive_value = root
        .value_handle(sensitive.arguments[0].value)
        .expect("sensitive argument value");
    let mut source_endpoints = vec![(attacker_point, ValueFlowCarrier::Value(attacker_value))];
    for clean in calls_named("clean()") {
        let point = match clean.normal_continuation {
            ControlContinuation::Target(point) => root.point_handle(point).unwrap(),
            ref other => panic!("clean call lacks a normal continuation: {other:?}"),
        };
        let value = root.value_handle(clean.result.unwrap()).unwrap();
        source_endpoints.push((point, ValueFlowCarrier::Value(value)));
    }
    source_endpoints.sort_by_key(|(point, _)| point.id());
    let sources = source_endpoints
        .into_iter()
        .enumerate()
        .map(|(index, (point, carrier))| {
            ValueFlowSourceSpec::new(
                ValueFlowEventKey::at_point(
                    &point,
                    u32::try_from(index).unwrap(),
                    ValueFlowEventKind::Source,
                )
                .unwrap(),
                point,
                ValueFlowObservationPhase::BeforeEffects,
                carrier,
                ProofStatus::Proven,
                EvidenceCompleteness::Complete,
            )
        })
        .collect();
    let sink = ValueFlowSinkSpec::new(
        ValueFlowEventKey::at_point(&sensitive_point, 0, ValueFlowEventKind::Sink).unwrap(),
        sensitive_point,
        ValueFlowObservationPhase::BeforeEffects,
        ValueFlowCarrier::Value(sensitive_value),
        ProofStatus::Proven,
        EvidenceCompleteness::Complete,
    );
    let mut semantic_budget = SemanticBudget::default();
    let snapshot = workspace
        .semantic_oracle_provider()
        .procedure_relations(
            &root,
            &OracleCallContext::empty(),
            &mut SemanticRequest::new(&mut semantic_budget, &cancellation),
        )
        .expect("direct oracle value-flow snapshot");
    let status = SemanticInputStatus::from_outcome(&snapshot);
    let snapshot = snapshot.available_value().unwrap().clone();
    let exact_targets = root
        .semantics()
        .call_sites()
        .iter()
        .flat_map(|call| {
            let mut budget = SemanticBudget::default();
            workspace
                .icfg_provider()
                .call_transfers(
                    &root,
                    call.id,
                    &mut SemanticRequest::new(&mut budget, &cancellation),
                )
                .ok()
                .and_then(|outcome| outcome.available_value().cloned())
                .into_iter()
                .flat_map(|transfers| {
                    transfers
                        .boundaries
                        .iter()
                        .filter_map(|boundary| boundary.dispatch.exact_external_target().cloned())
                        .collect::<Vec<_>>()
                })
        })
        .collect::<Vec<_>>();
    let shard = decode_shard_for_manifest(
        &pack.manifest,
        &pack.shards[0].descriptor,
        &pack.shards[0].bytes,
        &DecodeLimits::default(),
    )
    .expect("decode direct-oracle procedure summaries");
    let summaries = shard
        .payload()
        .procedure_summaries()
        .expect("procedure-summary payload");
    let compatibility = ExternalSummaryCompatibilityKey::new(
        SummarySchemaVersion::CURRENT,
        SummarySemanticsVersion::hash_bytes(b"bifrost.production-value-flow.semantic-pack.v1"),
        SummaryContextKey::hash_bytes(b"bifrost.production-value-flow.empty-call-context.v1"),
        SummaryBehaviorKey::hash_bytes(b"bifrost.production-value-flow.external-boundary.v1")
            .with_unmodeled_call_behavior(UnmodeledCallBehavior::RequireModel),
        root.artifact().key().dependencies(),
        UnmodeledCallBehavior::RequireModel,
    );
    let bindings = summaries
        .iter()
        .map(|summary| {
            let target = exact_targets
                .iter()
                .find(|target| {
                    target.artifact().path().as_str() == summary.target.path
                        && target.symbol() == summary.target.symbol
                        && target.has_receiver() == summary.target.has_receiver
                        && target.parameter_count() == summary.target.parameter_count
                })
                .unwrap_or_else(|| panic!("missing exact target for {}", summary.id));
            let boundary = ExactProcedureSummaryBoundary::new(
                summary
                    .target
                    .has_receiver
                    .then_some(ExactProcedureSummaryReceiver),
                (0..summary.target.parameter_count)
                    .map(ExactProcedureSummaryParameter::new)
                    .collect(),
            );
            ExactProcedureSummaryTargetBinding::new(
                summary.id.clone(),
                summary.target.clone(),
                target.artifact().clone(),
                target.procedure().clone(),
                boundary,
            )
        })
        .collect();
    let external_summaries = bind_compiled_procedure_summaries(summaries, bindings, compatibility)
        .expect("independent direct summary binding");
    let value_flow = ValueFlowPlan::with_call_behavior(
        root.clone(),
        vec![ValueFlowInput::new(snapshot, status)],
        Vec::new(),
        sources,
        vec![sink],
        UnmodeledCallBehavior::RequireModel,
    )
    .unwrap()
    .with_external_summaries(external_summaries)
    .expect("direct model-backed value-flow plan");
    let universe = TaintUniverse::new(vec![SourceClassId::new("untrusted").unwrap()]).unwrap();
    let classes: TaintClassSet = universe.class_set(universe.classes()).unwrap();
    let sources = value_flow
        .sources()
        .map(|(id, spec)| {
            TaintSourceBinding::new(id, classes.clone(), SourceEventKey::new(spec.key().clone()))
        })
        .collect();
    let sinks = value_flow
        .sinks()
        .map(|(id, _)| TaintSinkBinding::new(id, classes.clone()))
        .collect();
    let plan = TaintAnalysisPlan::new(value_flow, universe, sources, sinks, Vec::new(), Vec::new())
        .expect("direct taint plan");
    let mut solver_budget = SolverBudget::default();
    let result = solve_taint_batch_with_witnesses(
        &root,
        &workspace.icfg_provider(),
        &plan,
        WitnessRetentionLimits::new(8).unwrap(),
        &mut semantic_budget,
        &mut DataflowRequest::new(&mut solver_budget, &cancellation),
    )
    .expect("direct model-backed taint solve");
    let report = collect_taint_findings_with_limits(
        &plan,
        result,
        8,
        WitnessReconstructionLimits::default(),
        TaintFindingCollectionLimits::new(64, 64, 16_384, 16_384, 16 * 1024 * 1024).unwrap(),
    )
    .expect("direct model-backed taint findings");
    project_taint_finding_report(
        workspace,
        &plan,
        &report,
        "direct-model-backed-oracle",
        brokk_bifrost::analyzer::structural::CodeQueryTaintProjectionLimits::new(
            usize::MAX,
            usize::MAX,
            usize::MAX,
            usize::MAX,
        ),
    )
    .expect("direct public taint projection")
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
) -> brokk_bifrost::policy::PolicyBatchOutcome {
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
) -> brokk_bifrost::policy::PolicyBatchOutcome {
    let policy_sources = policies
        .iter()
        .map(|(id, message)| java_summary_policy(id, message))
        .collect::<Vec<_>>();
    evaluate_java_workspace_with_policy_sources_and_models(
        root,
        workspace,
        &policy_sources,
        catalog,
        request,
    )
}

fn evaluate_java_workspace_with_policy_sources_and_models(
    root: &Path,
    workspace: &brokk_bifrost::analyzer::WorkspaceAnalyzer,
    policy_sources: &[String],
    catalog: &SemanticPackCatalog,
    request: &SemanticModelActivationRequest,
) -> brokk_bifrost::policy::PolicyBatchOutcome {
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

fn propagation_identity(outcome: &brokk_bifrost::policy::PolicyBatchOutcome) -> &str {
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

fn evaluate_one(source: &str, policy_source: &str) -> brokk_bifrost::policy::PolicyBatchOutcome {
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

/// Exercises every public consumer of one already-solved production result.
///
/// The policy run is the only authority allowed to compile and solve the
/// taint analysis. JSON and RQL deliberately receive the same retained result
/// through two aliases, so this catches a projection that accidentally grows a
/// second analysis path.
fn assert_retained_taint_projection_matrix(
    outcome: &brokk_bifrost::policy::PolicyBatchOutcome,
    workspace: &brokk_bifrost::analyzer::WorkspaceAnalyzer,
) {
    let [retained] = outcome.taint_analysis_results() else {
        panic!(
            "expected one retained production analysis, got {}",
            outcome.taint_analysis_results().len()
        );
    };
    assert!(retained.plan_report_match());
    let expected = retained
        .project_findings(workspace, retained.projection_limits())
        .expect("retained production projection");
    assert_eq!(expected, outcome.taint_findings());

    let primary = TaintResultRef::new("production", "primary").expect("taint ref");
    let alias = TaintResultRef::new("production", "alias").expect("taint ref");
    let mut registrations = TaintResultRegistrationSet::default();
    for reference in [&primary, &alias] {
        registrations
            .register(
                reference.clone(),
                TaintResultRegistration::new(WORKSPACE_GENERATION, vec![Arc::clone(retained)])
                    .expect("retained result registration"),
            )
            .expect("register retained result");
    }
    assert_eq!(registrations.registration_count(), 1);

    let json_query = CodeQuery::from_json(&serde_json::json!({
        "schema_version": 7,
        "match": { "kind": "method", "name": "run" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "taint", "taint_ref": "production:primary" }
        ]
    }))
    .expect("schema-v7 taint JSON query");
    let rql_query = CodeQuery::from_sexp(
        r#"(taint :taint-ref production:alias (procedure-of (method :name "run")))"#,
    )
    .expect("schema-v7 taint RQL query");
    let execute = |query: &CodeQuery| {
        let summaries = Arc::new(ProductionTypestateSummaryRepository::new());
        execute_workspace_request_with_all_analysis_registration_lease(
            workspace,
            WORKSPACE_GENERATION,
            &ProtocolRegistrationSet::default(),
            &ValueFlowPlanRegistrationSet::default(),
            &registrations,
            query,
            CodeQueryExecutionLimits::default(),
            None,
            summaries
                .lease(WORKSPACE_GENERATION)
                .expect("generation-scoped summary lease"),
        )
    };
    let json_response = execute(&json_query);
    let json = json_response.result().expect("JSON taint result");
    let rql_response = execute(&rql_query);
    let rql = rql_response.result().expect("RQL taint result");
    assert!(json.diagnostics.is_empty(), "{:?}", json.diagnostics);
    assert!(rql.diagnostics.is_empty(), "{:?}", rql.diagnostics);
    let expected = serde_json::to_value(&expected).expect("canonical retained findings");
    let json_findings = serde_json::to_value(&json.results).expect("canonical JSON findings");
    let rql_findings = serde_json::to_value(&rql.results).expect("canonical RQL findings");
    assert_eq!(
        json_findings, rql_findings,
        "JSON and RQL must project identical retained taint evidence"
    );
    assert_eq!(canonical_retained_taint_findings(json_findings), expected);
    assert_eq!(
        canonical_public_taint_meetings(outcome),
        canonical_policy_taint_meetings(outcome),
        "policy and retained projections must keep the same typed source/sink meetings"
    );
    assert_eq!(
        canonical_public_taint_witnesses(outcome),
        canonical_policy_taint_witnesses(outcome),
        "policy and retained projections must keep the same ordered witness paths"
    );
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct CanonicalTaintLocation {
    path: String,
    start_line: usize,
    start_column: usize,
    end_line: usize,
    end_column: usize,
}

impl CanonicalTaintLocation {
    fn public(site: &CodeQuerySourceSite) -> Self {
        Self {
            path: site.path.clone(),
            start_line: site.range.start_line,
            start_column: site.range.start_column,
            end_line: site.range.end_line,
            end_column: site.range.end_column,
        }
    }

    fn policy(location: &PolicySourceLocation) -> Self {
        let region = location
            .region()
            .expect("taint evidence must retain a source-backed region");
        Self {
            path: location.path().to_owned(),
            start_line: region.start_line() as usize,
            start_column: region.start_column() as usize,
            end_line: region.end_line() as usize,
            end_column: region.end_column() as usize,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct CanonicalTaintMeeting {
    sink: CanonicalTaintLocation,
    source: CanonicalTaintLocation,
    label: String,
    proven: bool,
    complete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct CanonicalTaintWitness {
    steps: Vec<(&'static str, CanonicalTaintLocation)>,
    truncated: bool,
    omitted_steps_lower_bound: u64,
}

fn canonical_public_taint_witnesses(
    outcome: &brokk_bifrost::policy::PolicyBatchOutcome,
) -> BTreeSet<CanonicalTaintWitness> {
    outcome
        .taint_findings()
        .iter()
        .flat_map(|finding| &finding.witnesses)
        .map(|witness| {
            let mut omitted = u64::try_from(witness.omitted_steps_lower_bound).unwrap_or(u64::MAX);
            if (witness.truncated || witness.alternatives_truncated || witness.retention_truncated)
                && omitted == 0
            {
                omitted = 1;
            }
            CanonicalTaintWitness {
                steps: witness
                    .steps
                    .iter()
                    .map(|step| {
                        let kind = match step.kind {
                            CodeQueryFlowWitnessStepKind::Seed => "source",
                            CodeQueryFlowWitnessStepKind::Edge { .. } => "propagation",
                            CodeQueryFlowWitnessStepKind::EndSummaryGap { .. } => "return",
                        };
                        (kind, CanonicalTaintLocation::public(&step.source))
                    })
                    .collect(),
                truncated: omitted > 0,
                omitted_steps_lower_bound: omitted,
            }
        })
        .collect()
}

fn canonical_policy_taint_witnesses(
    outcome: &brokk_bifrost::policy::PolicyBatchOutcome,
) -> BTreeSet<CanonicalTaintWitness> {
    outcome
        .report()
        .runs()
        .iter()
        .flat_map(|run| run.findings())
        .flat_map(|finding| finding.witnesses())
        .map(|witness| CanonicalTaintWitness {
            steps: witness
                .steps()
                .iter()
                .map(|step| {
                    let kind = match step.kind() {
                        WitnessStepKind::Source => "source",
                        WitnessStepKind::Propagation => "propagation",
                        WitnessStepKind::Return => "return",
                        other => panic!("unexpected taint witness step kind: {other:?}"),
                    };
                    let location = step
                        .location()
                        .expect("taint policy witness steps must retain locations");
                    (kind, CanonicalTaintLocation::policy(location))
                })
                .collect(),
            truncated: witness.truncated(),
            omitted_steps_lower_bound: witness.omitted_steps_lower_bound(),
        })
        .collect()
}

fn canonical_public_taint_meetings(
    outcome: &brokk_bifrost::policy::PolicyBatchOutcome,
) -> BTreeSet<CanonicalTaintMeeting> {
    outcome
        .taint_findings()
        .iter()
        .flat_map(|finding| {
            finding.origins.iter().flat_map(|origin| {
                origin.labels.iter().map(|label| CanonicalTaintMeeting {
                    sink: CanonicalTaintLocation::public(&finding.sink),
                    source: CanonicalTaintLocation::public(&origin.site),
                    label: label.clone(),
                    proven: finding.evidence.proof == CodeQuerySemanticProof::Proven,
                    complete: finding.evidence.completeness
                        == CodeQuerySemanticCompleteness::Complete,
                })
            })
        })
        .collect()
}

fn canonical_policy_taint_meetings(
    outcome: &brokk_bifrost::policy::PolicyBatchOutcome,
) -> BTreeSet<CanonicalTaintMeeting> {
    outcome
        .report()
        .runs()
        .iter()
        .flat_map(|run| run.findings())
        .flat_map(|finding| {
            let PolicyFindingEvidence::Taint { evidence } = finding.evidence() else {
                panic!("expected taint policy evidence")
            };
            evidence
                .origins()
                .iter()
                .map(|origin| CanonicalTaintMeeting {
                    sink: CanonicalTaintLocation::policy(finding.primary()),
                    source: CanonicalTaintLocation::policy(origin.primary()),
                    label: origin.source_label().to_string(),
                    proven: matches!(finding.certainty(), FindingCertainty::Definite),
                    complete: finding.completeness().is_complete(),
                })
                .collect::<Vec<_>>()
        })
        .collect()
}

fn policy_origin_scenario_mapping(
    outcome: &brokk_bifrost::policy::PolicyBatchOutcome,
) -> BTreeSet<(String, String)> {
    outcome
        .report()
        .runs()
        .iter()
        .flat_map(|run| run.findings())
        .flat_map(|finding| {
            let PolicyFindingEvidence::Taint { evidence } = finding.evidence() else {
                panic!("expected taint policy evidence")
            };
            evidence.origins().iter().map(|origin| {
                (
                    serde_json::to_string(origin.source_endpoint())
                        .expect("source endpoint identity serialization"),
                    origin.scenario_id().to_string(),
                )
            })
        })
        .collect()
}

fn canonical_retained_taint_findings(mut findings: serde_json::Value) -> serde_json::Value {
    let serde_json::Value::Array(rows) = &mut findings else {
        panic!("taint query results must be an array: {findings}");
    };
    for finding in rows {
        let serde_json::Value::Object(finding) = finding else {
            panic!("taint query result must be an object: {finding}");
        };
        assert_eq!(
            finding.remove("result_type"),
            Some(serde_json::json!("taint_finding"))
        );
        assert!(
            finding.remove("provenance").is_some(),
            "public query result must retain its query provenance"
        );
    }
    findings
}

fn canonical_taint_evidence(mut value: serde_json::Value) -> serde_json::Value {
    fn strip_projection_identity(value: &mut serde_json::Value) {
        match value {
            serde_json::Value::Array(values) => {
                for value in values {
                    strip_projection_identity(value);
                }
            }
            serde_json::Value::Object(fields) => {
                if fields.contains_key("sink_event_id") && fields.contains_key("witnesses") {
                    fields.remove("id");
                    fields.remove("sink_event_id");
                } else if fields.contains_key("event_id") && fields.contains_key("labels") {
                    fields.remove("id");
                    fields.remove("event_id");
                } else if fields.contains_key("finding_id") && fields.contains_key("steps") {
                    fields.remove("id");
                    fields.remove("finding_id");
                } else if fields.contains_key("phase")
                    && fields.contains_key("ordinal")
                    && fields.contains_key("carrier")
                    && fields.contains_key("site")
                {
                    fields.remove("id");
                }
                for value in fields.values_mut() {
                    strip_projection_identity(value);
                }
            }
            _ => {}
        }
    }
    strip_projection_identity(&mut value);
    value
}

#[test]
fn projected_witnesses_preserve_each_distinct_source_event_origin() {
    let outcome = evaluate_one(
        MATCHED_VALUE_SOURCE,
        &duplicate_source_event_policy("test.duplicate-source-events"),
    );
    let [finding] = outcome.taint_findings() else {
        panic!(
            "expected one projected finding, got {:?}; report={:#?}",
            outcome.taint_findings(),
            outcome.report()
        );
    };
    assert_eq!(finding.origins.len(), 2);
    assert!(!finding.witnesses.is_empty());

    let expected_origins = finding
        .origins
        .iter()
        .map(|origin| origin.event_id.clone())
        .collect::<BTreeSet<_>>();
    assert_eq!(expected_origins.len(), 2);

    let mut projected_origins = BTreeSet::new();
    let mut projected_ordinals = BTreeSet::new();
    for witness in &finding.witnesses {
        let mut witness_origins = BTreeSet::new();
        let mut carrier_facts = 0usize;
        let mut meeting_facts = 0usize;
        for step in &witness.steps {
            for fact in [&step.input, &step.output].into_iter().flatten() {
                let source = match fact {
                    CodeQueryFlowFactSymbol::Carrier { source, .. } => {
                        carrier_facts += 1;
                        source
                    }
                    CodeQueryFlowFactSymbol::Meeting { source, .. } => {
                        meeting_facts += 1;
                        source
                    }
                    CodeQueryFlowFactSymbol::Zero => continue,
                };
                assert!(expected_origins.contains(&source.id));
                witness_origins.insert(source.id.clone());
                projected_ordinals.insert(source.ordinal);
            }
        }
        assert!(carrier_facts > 0, "witness must project Carrier facts");
        assert!(meeting_facts > 0, "witness must project Meeting facts");
        assert_eq!(
            witness_origins.len(),
            1,
            "every Carrier and Meeting fact must retain one exact origin: {witness:#?}"
        );
        projected_origins.insert(
            witness_origins
                .into_iter()
                .next()
                .expect("one exact witness origin was checked"),
        );
    }
    assert_eq!(projected_origins, expected_origins);
    assert_eq!(projected_ordinals, BTreeSet::from([0, 1]));
}

#[test]
fn model_backed_witnesses_preserve_each_distinct_source_event_origin() {
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    let pack = procedure_summary_pack("test.external-origins", None, false);
    register_pack(&catalog, &pack, "external-origins");
    let project = InlineTestProject::with_language(Language::Java)
        .file("app.java", JAVA_EXTERNAL_SOURCE)
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let policies = [java_duplicate_source_summary_policy(
        "test.semantic-summary-origins",
    )];
    let outcome = evaluate_java_workspace_with_policy_sources_and_models(
        project.root(),
        &workspace,
        &policies,
        &catalog,
        &semantic_model_request("1.5.0", MODEL_ARTIFACT_SHA256),
    );
    let [finding] = outcome.taint_findings() else {
        panic!(
            "expected one model-backed finding, got {:?}; report={:#?}",
            outcome.taint_findings(),
            outcome.report()
        );
    };
    let expected_origins = finding
        .origins
        .iter()
        .map(|origin| origin.event_id.clone())
        .collect::<BTreeSet<_>>();
    assert_eq!(expected_origins.len(), 2);

    let mut projected_origins = BTreeSet::new();
    for witness in &finding.witnesses {
        let witness_origins = witness
            .steps
            .iter()
            .flat_map(|step| [&step.input, &step.output])
            .flatten()
            .filter_map(|fact| match fact {
                CodeQueryFlowFactSymbol::Carrier { source, .. }
                | CodeQueryFlowFactSymbol::Meeting { source, .. } => Some(source.id.clone()),
                CodeQueryFlowFactSymbol::Zero => None,
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(
            witness_origins.len(),
            1,
            "each model-backed witness must retain one exact origin: {witness:#?}"
        );
        projected_origins.extend(witness_origins);
    }
    assert_eq!(projected_origins, expected_origins);
    assert_retained_taint_projection_matrix(&outcome, &workspace);
    let [run] = outcome.report().runs() else {
        panic!("expected one model-backed policy run")
    };
    assert_eq!(run.findings().len(), 2, "{:?}", run.diagnostics());
    let mut policy_sources = BTreeSet::new();
    let mut policy_scenarios = BTreeSet::new();
    let mut policy_origin_count = 0usize;
    for policy_finding in run.findings() {
        let PolicyFindingEvidence::Taint { evidence } = policy_finding.evidence() else {
            panic!("expected model-backed taint evidence")
        };
        assert_eq!(evidence.origins().len(), 1);
        assert_eq!(evidence.reached_source_labels().len(), 1);
        for origin in evidence.origins() {
            policy_sources.insert(format!("{:?}", origin.source_endpoint()));
            policy_scenarios.insert(format!("{:?}", origin.scenario_id()));
            policy_origin_count += 1;
        }
    }
    assert_eq!(policy_origin_count, finding.origins.len());
    assert_eq!(policy_sources.len(), 2);
    assert_eq!(policy_scenarios.len(), 2);
    let stable_scenarios = policy_origin_scenario_mapping(&outcome);
    let reversed_policies = [java_duplicate_source_summary_policy_with_order(
        "test.semantic-summary-origins",
        true,
    )];
    let reversed = evaluate_java_workspace_with_policy_sources_and_models(
        project.root(),
        &workspace,
        &reversed_policies,
        &catalog,
        &semantic_model_request("1.5.0", MODEL_ARTIFACT_SHA256),
    );
    assert_eq!(
        policy_origin_scenario_mapping(&reversed),
        stable_scenarios,
        "source scenario identity must not depend on authored endpoint order"
    );
    assert_retained_taint_projection_matrix(&reversed, &workspace);
    assert_eq!(
        run.work()
            .metrics()
            .iter()
            .find(|metric| metric.name() == "taint.propagation_solves")
            .map(|metric| metric.value()),
        Some(1)
    );
}

fn assert_model_backed_renderers(outcome: &brokk_bifrost::policy::PolicyBatchOutcome) {
    let finding_id = outcome.report().runs()[0].findings()[0].id().to_string();
    let mut human = Vec::new();
    write_policy_human(
        outcome.report(),
        &HumanRenderOptions::new(HumanRenderDetail::Verbose, HumanRenderColor::Plain),
        &mut human,
        usize::MAX,
    )
    .expect("model-backed human rendering");
    let mut json = Vec::new();
    write_policy_json(outcome.report(), &mut json, usize::MAX)
        .expect("model-backed JSON rendering");
    let mut sarif = Vec::new();
    write_policy_sarif(
        outcome.report(),
        &SarifToolIdentity::default(),
        &mut sarif,
        usize::MAX,
    )
    .expect("model-backed SARIF rendering");

    let human = String::from_utf8(human).expect("UTF-8 human policy output");
    for expected in [&finding_id, "BROAD-TAINT", "untrusted", "app.java"] {
        assert!(human.contains(expected), "missing {expected} in:\n{human}");
    }

    let json: serde_json::Value =
        serde_json::from_slice(&json).expect("canonical model-backed JSON report");
    let sarif: serde_json::Value =
        serde_json::from_slice(&sarif).expect("model-backed SARIF report");
    let findings = json["runs"][0]["findings"]
        .as_array()
        .expect("canonical findings");
    let results = sarif["runs"][0]["results"]
        .as_array()
        .expect("SARIF results");
    assert_eq!(findings.len(), 1, "expected one model-backed taint finding");
    assert_eq!(results.len(), findings.len());

    let assert_location = |expected: &serde_json::Value, actual: &serde_json::Value| {
        assert_eq!(
            actual["artifactLocation"]["uri"], expected["path"],
            "SARIF artifact must match the canonical workspace-relative path"
        );
        let expected_region = &expected["region"];
        let actual_region = &actual["region"];
        for (canonical, sarif) in [
            ("start_line", "startLine"),
            ("start_column", "startColumn"),
            ("end_line", "endLine"),
            ("end_column", "endColumn"),
        ] {
            assert_eq!(
                actual_region[sarif], expected_region[canonical],
                "SARIF {sarif} must match canonical {canonical}"
            );
        }
    };

    let mut saw_propagation = false;
    for (finding, result) in findings.iter().zip(results) {
        assert_eq!(result["properties"]["bifrost.findingId"], finding["id"]);
        assert_eq!(result["ruleId"], finding["policy_id"]);
        assert_eq!(
            result["properties"]["bifrost.certainty"],
            finding["certainty"]
        );
        assert_eq!(
            result["properties"]["bifrost.findingCompleteness"],
            finding["completeness"]
        );
        // This production fixture is intentionally not forced through a synthetic
        // budget. True/nonzero witness truncation encoding is covered by the shared
        // SARIF witness test; these comparisons preserve whatever production retains.
        assert_eq!(
            result["properties"]["bifrost.witnessesTruncated"],
            finding["witnesses_truncated"]
        );
        assert_eq!(
            result["properties"]["bifrost.omittedWitnessesLowerBound"],
            finding["omitted_witnesses_lower_bound"]
        );
        assert_location(
            &finding["primary"],
            &result["locations"][0]["physicalLocation"],
        );

        let witnesses = finding["witnesses"]
            .as_array()
            .expect("canonical witnesses");
        let code_flows = result["codeFlows"].as_array().expect("SARIF code flows");
        assert_eq!(code_flows.len(), witnesses.len());
        for (witness, code_flow) in witnesses.iter().zip(code_flows) {
            assert_eq!(code_flow["properties"]["bifrost.witnessId"], witness["id"]);
            assert_eq!(
                code_flow["properties"]["bifrost.truncated"],
                witness["truncated"]
            );
            assert_eq!(
                code_flow["properties"]["bifrost.omittedStepsLowerBound"],
                witness["omitted_steps_lower_bound"]
            );
            let thread_flows = code_flow["threadFlows"]
                .as_array()
                .expect("one SARIF thread flow per witness");
            assert_eq!(thread_flows.len(), 1);
            assert_eq!(thread_flows[0]["id"], witness["id"]);

            let expected_steps = witness["steps"]
                .as_array()
                .expect("canonical witness steps");
            let actual_steps = thread_flows[0]["locations"]
                .as_array()
                .expect("SARIF thread flow locations");
            assert_eq!(actual_steps.len(), expected_steps.len());
            for (expected_step, actual_step) in expected_steps.iter().zip(actual_steps) {
                saw_propagation |= expected_step["kind"] == "propagation";
                assert_eq!(
                    actual_step["location"]["message"]["text"],
                    expected_step["label"]
                );
                assert_eq!(
                    actual_step["properties"]["bifrost.kind"],
                    expected_step["kind"]
                );
                assert_eq!(
                    actual_step["properties"]["bifrost.evidenceRefs"],
                    expected_step["evidence_refs"]
                );
                match expected_step
                    .get("location")
                    .filter(|location| !location.is_null())
                {
                    Some(location) => {
                        assert_location(location, &actual_step["location"]["physicalLocation"])
                    }
                    None => assert!(
                        actual_step["location"].get("physicalLocation").is_none(),
                        "location-free canonical steps must stay location-free in SARIF"
                    ),
                }
            }
        }
    }
    assert!(
        saw_propagation,
        "model-backed flow must include propagation"
    );
}

#[test]
fn activated_java_parameter_to_return_summary_reaches_sensitive_sink_under_require_model() {
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    let pack = procedure_summary_pack("test.external-flow", None, false);
    register_pack(&catalog, &pack, "external-flow");
    let request = semantic_model_request("1.5.0", MODEL_ARTIFACT_SHA256);
    let project = InlineTestProject::with_language(Language::Java)
        .file("app.java", JAVA_EXTERNAL_SOURCE)
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let direct = direct_model_backed_findings(&project, &workspace, &pack);
    let outcome = evaluate_java_workspace_with_models(
        project.root(),
        &workspace,
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
        canonical_taint_evidence(serde_json::to_value(&direct).unwrap()),
        canonical_taint_evidence(serde_json::to_value(outcome.taint_findings()).unwrap()),
        "production compilation must agree with the independent direct-flow oracle"
    );
    assert_retained_taint_projection_matrix(&outcome, &workspace);
    assert_model_backed_renderers(&outcome);
    let projected =
        serde_json::to_value(outcome.taint_findings()).expect("stable public taint serialization");
    assert_eq!(projected[0]["origins"].as_array().map(Vec::len), Some(1));
    assert_eq!(
        projected[0]["reached_labels"],
        serde_json::json!(["untrusted"])
    );
    assert_eq!(projected[0]["evidence"]["proof"], "unproven");
    assert_eq!(projected[0]["evidence"]["completeness"], "partial");
    assert_eq!(projected[0]["ambiguous"], true);
    assert!(projected[0].get("origins_truncated").is_none());
    assert!(projected[0].get("witnesses_truncated").is_none());
    assert_eq!(
        projected[0]["origins"][0]["site"],
        serde_json::json!({
            "path": "app.java",
            "range": {"start_line": 9, "start_column": 33, "end_line": 9, "end_column": 43}
        })
    );
    assert_eq!(
        projected[0]["sink"],
        serde_json::json!({
            "path": "app.java",
            "range": {"start_line": 9, "start_column": 9, "end_line": 9, "end_column": 54}
        })
    );
    let witnesses = projected[0]["witnesses"]
        .as_array()
        .expect("ordered retained witnesses");
    assert_eq!(witnesses.len(), 2);
    let step_signature = |step: &serde_json::Value| {
        serde_json::json!({
            "kind": step["kind"],
            "boundary": step.get("boundary"),
            "source": step["source"]["range"],
            "target": step.get("target").and_then(|target| target.get("range")),
            "origin": step.get("origin").and_then(|origin| origin.get("range")),
            "input": step["input"]["kind"],
            "output": step["output"]["kind"],
        })
    };
    let signatures = witnesses
        .iter()
        .map(|witness| {
            witness["steps"]
                .as_array()
                .unwrap()
                .iter()
                .map(step_signature)
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let expected_prefix = serde_json::json!([
        {"kind":{"type":"seed"},"boundary":null,"source":{"start_line":8,"start_column":5,"end_line":10,"end_column":6},"target":null,"origin":null,"input":"zero","output":"zero"},
        {"kind":{"type":"edge","edge_kind":"normal"},"boundary":null,"source":{"start_line":8,"start_column":5,"end_line":10,"end_column":6},"target":{"start_line":8,"start_column":16,"end_line":10,"end_column":6},"origin":null,"input":"zero","output":"zero"},
        {"kind":{"type":"edge","edge_kind":"normal"},"boundary":null,"source":{"start_line":8,"start_column":16,"end_line":10,"end_column":6},"target":{"start_line":9,"start_column":9,"end_line":9,"end_column":55},"origin":null,"input":"zero","output":"zero"},
        {"kind":{"type":"edge","edge_kind":"normal"},"boundary":null,"source":{"start_line":9,"start_column":9,"end_line":9,"end_column":55},"target":{"start_line":9,"start_column":19,"end_line":9,"end_column":53},"origin":null,"input":"zero","output":"zero"},
        {"kind":{"type":"edge","edge_kind":"normal"},"boundary":null,"source":{"start_line":9,"start_column":19,"end_line":9,"end_column":53},"target":{"start_line":9,"start_column":19,"end_line":9,"end_column":23},"origin":null,"input":"zero","output":"zero"},
        {"kind":{"type":"edge","edge_kind":"normal"},"boundary":null,"source":{"start_line":9,"start_column":19,"end_line":9,"end_column":23},"target":{"start_line":9,"start_column":33,"end_line":9,"end_column":43},"origin":null,"input":"zero","output":"zero"},
        {"kind":{"type":"edge","edge_kind":"normal"},"boundary":null,"source":{"start_line":9,"start_column":33,"end_line":9,"end_column":43},"target":{"start_line":9,"start_column":33,"end_line":9,"end_column":43},"origin":null,"input":"zero","output":"zero"},
        {"kind":{"type":"edge","edge_kind":"call_to_normal_continuation"},"boundary":"unmaterialized","source":{"start_line":9,"start_column":33,"end_line":9,"end_column":43},"target":{"start_line":9,"start_column":33,"end_line":9,"end_column":43},"origin":{"start_line":9,"start_column":33,"end_line":9,"end_column":43},"input":"zero","output":"zero"},
        {"kind":{"type":"edge","edge_kind":"normal"},"boundary":null,"source":{"start_line":9,"start_column":33,"end_line":9,"end_column":43},"target":{"start_line":9,"start_column":45,"end_line":9,"end_column":52},"origin":null,"input":"zero","output":"carrier"},
        {"kind":{"type":"edge","edge_kind":"normal"},"boundary":null,"source":{"start_line":9,"start_column":45,"end_line":9,"end_column":52},"target":{"start_line":9,"start_column":45,"end_line":9,"end_column":52},"origin":null,"input":"carrier","output":"carrier"},
        {"kind":{"type":"edge","edge_kind":"call_to_normal_continuation"},"boundary":"unmaterialized","source":{"start_line":9,"start_column":45,"end_line":9,"end_column":52},"target":{"start_line":9,"start_column":45,"end_line":9,"end_column":52},"origin":{"start_line":9,"start_column":45,"end_line":9,"end_column":52},"input":"carrier","output":"carrier"},
        {"kind":{"type":"edge","edge_kind":"normal"},"boundary":null,"source":{"start_line":9,"start_column":45,"end_line":9,"end_column":52},"target":{"start_line":9,"start_column":19,"end_line":9,"end_column":53},"origin":null,"input":"carrier","output":"carrier"},
        {"kind":{"type":"edge","edge_kind":"call_to_normal_continuation"},"boundary":"unmaterialized","source":{"start_line":9,"start_column":19,"end_line":9,"end_column":53},"target":{"start_line":9,"start_column":19,"end_line":9,"end_column":53},"origin":{"start_line":9,"start_column":19,"end_line":9,"end_column":53},"input":"carrier","output":"carrier"},
        {"kind":{"type":"edge","edge_kind":"normal"},"boundary":null,"source":{"start_line":9,"start_column":19,"end_line":9,"end_column":53},"target":{"start_line":9,"start_column":9,"end_line":9,"end_column":54},"origin":null,"input":"carrier","output":"carrier"}
    ]);
    assert_eq!(signatures[0][..14], expected_prefix.as_array().unwrap()[..]);
    assert_eq!(signatures[1][..14], expected_prefix.as_array().unwrap()[..]);
    assert_eq!(
        signatures[0][14],
        serde_json::json!({"kind":{"type":"edge","edge_kind":"call_to_normal_continuation"},"boundary":"unmaterialized","source":{"start_line":9,"start_column":9,"end_line":9,"end_column":54},"target":{"start_line":9,"start_column":9,"end_line":9,"end_column":54},"origin":{"start_line":9,"start_column":9,"end_line":9,"end_column":54},"input":"carrier","output":"meeting"})
    );
    assert_eq!(
        signatures[1][14],
        serde_json::json!({"kind":{"type":"edge","edge_kind":"call_to_exceptional_continuation"},"boundary":"unmaterialized","source":{"start_line":9,"start_column":9,"end_line":9,"end_column":54},"target":{"start_line":9,"start_column":9,"end_line":9,"end_column":54},"origin":{"start_line":9,"start_column":9,"end_line":9,"end_column":54},"input":"carrier","output":"meeting"})
    );
    for witness in witnesses {
        assert_eq!(witness["omitted_steps_lower_bound"], 0);
        assert!(witness.get("truncated").is_none());
        assert!(witness.get("alternatives_truncated").is_none());
        assert!(witness.get("retention_truncated").is_none());
        for step in witness["steps"].as_array().unwrap() {
            assert!(step.get("source_symbol").is_some());
            assert!(step.get("input").is_some());
            assert!(step.get("output").is_some());
            if step.get("origin").is_some() {
                assert!(step.get("origin_symbol").is_some());
            }
        }
    }
    let projected = projected.to_string();
    assert!(
        !projected.contains("clean"),
        "the unrelated external-call argument must not contribute taint: {projected}"
    );
    assert!(
        !projected.contains(project.root().to_string_lossy().as_ref()),
        "public taint evidence must stay workspace-relative: {projected}"
    );
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
fn activated_java_summary_retains_every_supported_transfer_and_effect() {
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    let pack = procedure_summary_transfer_matrix_pack("test.external-transfer-matrix");
    register_pack(&catalog, &pack, "external-transfer-matrix");
    let project = InlineTestProject::with_language(Language::Java)
        .file("app.java", JAVA_EXTERNAL_SOURCE)
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let outcome = evaluate_java_workspace_with_models(
        project.root(),
        &workspace,
        &[("test.semantic-summary-transfer-matrix", "transfer matrix")],
        &catalog,
        &semantic_model_request("1.5.0", MODEL_ARTIFACT_SHA256),
    );
    let [retained] = outcome.taint_analysis_results() else {
        panic!("expected one retained transfer-matrix analysis")
    };
    let summaries = retained.plan().value_flow().external_summaries();
    let entries = summaries.entries().collect::<Vec<_>>();
    let [(_, summary)] = entries.as_slice() else {
        panic!("expected one selected transfer-matrix summary: {entries:#?}")
    };
    assert!(matches!(
        summary.completeness(),
        SummaryCompleteness::Partial(_)
    ));
    assert_eq!(summary.transfers().len(), 5);
    assert!(summary.transfers().iter().any(|transfer| {
        transfer.input() == &SummaryPort::Parameter(0)
            && transfer.exit().kind() == SummaryExitKind::Normal
            && transfer.exit().port() == &SummaryPort::NormalReturn
    }));
    assert!(summary.transfers().iter().any(|transfer| {
        transfer.input() == &SummaryPort::Receiver
            && transfer.exit().kind() == SummaryExitKind::Normal
            && transfer.exit().port() == &SummaryPort::Receiver
    }));
    assert!(summary.transfers().iter().any(|transfer| {
        transfer.exit().kind() == SummaryExitKind::Exceptional
            && transfer.exit().port() == &SummaryPort::ExceptionalReturn
    }));
    assert!(
        summary
            .transfers()
            .iter()
            .any(|transfer| matches!(transfer.exit().port(), SummaryPort::Capture(_)))
    );
    assert!(
        summary
            .transfers()
            .iter()
            .any(|transfer| matches!(transfer.exit().port(), SummaryPort::Heap(_)))
    );
    assert!(
        summary
            .effects()
            .iter()
            .any(|effect| matches!(effect.key(), SummaryEffectKey::Escape { .. }))
    );
    assert!(
        summary
            .effects()
            .iter()
            .any(|effect| matches!(effect.key(), SummaryEffectKey::Allocation { .. }))
    );
    assert!(
        summary
            .transfers()
            .iter()
            .all(|transfer| !transfer.evidence().is_proven() && !transfer.evidence().is_complete())
    );

    let [run] = outcome.report().runs() else {
        panic!("expected one transfer-matrix policy run")
    };
    assert!(matches!(
        run.completion(),
        PolicyRunCompletion::Inconclusive { .. }
    ));
    assert_eq!(run.findings().len(), 1, "{:?}", run.diagnostics());
    let [finding] = outcome.taint_findings() else {
        panic!("expected one transfer-matrix public finding")
    };
    assert_eq!(finding.reached_labels, ["untrusted"]);
    assert_eq!(finding.witnesses.len(), 2);
    let expected_source_symbols = [
        ("procedure", 195, 268, 0),
        ("procedure", 195, 268, 0),
        ("program_point", 206, 268, 0),
        ("program_point", 216, 262, 0),
        ("program_point", 226, 260, 0),
        ("program_point", 226, 230, 0),
        ("program_point", 240, 250, 0),
        ("program_point", 240, 250, 1),
        ("program_point", 240, 250, 2),
        ("program_point", 252, 259, 0),
        ("program_point", 252, 259, 1),
        ("program_point", 252, 259, 2),
        ("program_point", 226, 260, 1),
        ("program_point", 226, 260, 2),
        ("program_point", 216, 261, 0),
    ];
    let expected_step_completeness = [
        "proven/complete",
        "proven/complete",
        "proven/complete",
        "proven/complete",
        "proven/complete",
        "proven/complete",
        "proven/complete",
        "proven/partial",
        "proven/complete",
        "proven/complete",
        "proven/partial",
        "proven/complete",
        "proven/partial",
        "proven/complete",
        "proven/partial",
    ];
    for witness in &finding.witnesses {
        let source_symbols = witness
            .steps
            .iter()
            .map(|step| {
                let symbol = step
                    .source_symbol
                    .as_ref()
                    .expect("each witness step must retain its stable source symbol");
                (
                    symbol.role,
                    symbol.start_byte,
                    symbol.end_byte,
                    symbol.occurrence,
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(source_symbols, expected_source_symbols);
        assert_eq!(
            witness
                .steps
                .iter()
                .map(|step| step.evidence.status_label())
                .collect::<Vec<_>>(),
            expected_step_completeness
        );
        assert!(matches!(
            witness.steps.first().and_then(|step| step.input.as_ref()),
            Some(CodeQueryFlowFactSymbol::Zero)
        ));
        assert!(matches!(
            witness.steps.last().and_then(|step| step.output.as_ref()),
            Some(CodeQueryFlowFactSymbol::Meeting { .. })
        ));
        assert!(witness.steps.iter().any(|step| matches!(
            step.output.as_ref(),
            Some(CodeQueryFlowFactSymbol::Carrier { .. })
        )));
        for pair in witness.steps[1..].windows(2) {
            assert_eq!(
                pair[0].target_symbol, pair[1].source_symbol,
                "ordered witness symbols must join at the exact stable site"
            );
            assert_eq!(
                pair[0].output, pair[1].input,
                "ordered witness facts must keep the exact stable carrier identity"
            );
        }
        for step in &witness.steps {
            assert!(step.source_symbol.is_some());
            assert!(step.input.is_some());
            assert!(step.output.is_some());
            if step.origin.is_some() {
                assert_eq!(step.origin_symbol, step.source_symbol);
            }
        }
    }
    assert_retained_taint_projection_matrix(&outcome, &workspace);
}

#[test]
fn activated_java_summary_executes_bound_transfers_and_marks_unbound_cases_partial() {
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    let pack = executable_procedure_summary_transfer_pack("test.executable-transfer-matrix");
    register_pack(&catalog, &pack, "executable-transfer-matrix");
    let project = InlineTestProject::with_language(Language::Java)
        .file("app.java", JAVA_EXECUTABLE_TRANSFER_SOURCE)
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let policies = [java_executable_transfer_policy(
        "test.semantic-summary-executable-transfer-matrix",
    )];
    let outcome = evaluate_java_workspace_with_policy_sources_and_models(
        project.root(),
        &workspace,
        &policies,
        &catalog,
        &semantic_model_request("1.5.0", MODEL_ARTIFACT_SHA256),
    );
    let [retained] = outcome.taint_analysis_results() else {
        panic!(
            "expected one retained executable transfer analysis: {:#?}",
            outcome.report()
        )
    };
    assert_eq!(
        retained
            .plan()
            .value_flow()
            .external_summaries()
            .entries()
            .count(),
        4
    );
    let meeting_labels = canonical_public_taint_meetings(&outcome)
        .into_iter()
        .map(|meeting| meeting.label)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        meeting_labels,
        BTreeSet::from([
            "parameter-label".to_owned(),
            "receiver-input-label".to_owned(),
        ]),
        "only ports with live production carriers may reach a sink"
    );
    let reached_sinks = retained
        .report()
        .findings()
        .iter()
        .map(|finding| finding.key().sink())
        .collect::<BTreeSet<_>>();
    let absent_sinks = retained
        .plan()
        .value_flow()
        .sinks()
        .map(|(_, sink)| sink.key())
        .filter(|sink| !reached_sinks.contains(sink))
        .collect::<BTreeSet<_>>();
    let event_line =
        |event: &ValueFlowEventKey| event.site().anchor().span().start().line() as usize + 1;
    assert_eq!(
        reached_sinks
            .iter()
            .map(|sink| event_line(sink))
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([18, 19])
    );
    assert_eq!(
        absent_sinks
            .iter()
            .map(|sink| event_line(sink))
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([22, 26]),
        "unbound receiver-output and exceptional-output carriers must remain absent"
    );
    let [run] = outcome.report().runs() else {
        panic!("expected one executable transfer policy run")
    };
    assert!(matches!(
        run.completion(),
        PolicyRunCompletion::Inconclusive { .. }
    ));
    assert!(
        outcome
            .taint_findings()
            .iter()
            .all(|finding| finding.evidence.completeness == CodeQuerySemanticCompleteness::Partial)
    );
    assert_retained_taint_projection_matrix(&outcome, &workspace);
}

#[test]
fn activated_java_summary_dependency_closure_matches_the_direct_oracle() {
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    let pack = procedure_summary_dependency_pack("test.external-dependency-complete", false);
    register_pack(&catalog, &pack, "external-dependency-complete");
    let project = InlineTestProject::with_language(Language::Java)
        .file("app.java", JAVA_COMPLETE_DEPENDENCY_SOURCE)
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let direct = direct_model_backed_findings(&project, &workspace, &pack);
    let outcome = evaluate_java_workspace_with_models(
        project.root(),
        &workspace,
        &[(
            "test.semantic-summary-dependency-complete",
            "complete dependency closure",
        )],
        &catalog,
        &semantic_model_request("1.5.0", MODEL_ARTIFACT_SHA256),
    );
    let run = &outcome.report().runs()[0];
    assert_eq!(run.findings().len(), 1, "{:?}", run.diagnostics());
    assert_eq!(outcome.taint_analysis_results().len(), 1);
    assert_eq!(
        outcome.taint_analysis_results()[0]
            .plan()
            .value_flow()
            .external_summaries()
            .entries()
            .len(),
        2,
        "the selected family must retain its complete declared closure"
    );
    assert_eq!(
        canonical_taint_evidence(serde_json::to_value(direct).unwrap()),
        canonical_taint_evidence(serde_json::to_value(outcome.taint_findings()).unwrap()),
        "the complete two-summary closure must preserve direct-flow evidence"
    );
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
fn activated_java_summary_dependency_closure_selects_unobserved_relay() {
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    let pack = procedure_summary_dependency_pack("test.external-dependency", false);
    register_pack(&catalog, &pack, "external-dependency");
    let project = InlineTestProject::with_language(Language::Java)
        .file("app.java", JAVA_DEPENDENCY_SOURCE)
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let outcome = evaluate_java_workspace_with_models(
        project.root(),
        &workspace,
        &[("test.semantic-summary-dependency", "dependency closure")],
        &catalog,
        &semantic_model_request("1.5.0", MODEL_ARTIFACT_SHA256),
    );
    let run = &outcome.report().runs()[0];
    assert!(matches!(
        run.completion(),
        PolicyRunCompletion::Failed { .. }
    ));
    assert!(run.findings().is_empty());
    assert!(outcome.taint_findings().is_empty());
    assert!(outcome.taint_analysis_results().is_empty());
    assert!(run.diagnostics().iter().any(|diagnostic| {
        diagnostic.message().contains(
            "procedure summary `summary.relay` dependency closure lacks one exact external target descriptor",
        )
    }), "dependency traversal must select summary.relay even though no direct relay call independently selects it: {:?}", run.diagnostics());
}

#[test]
fn recursive_summary_group_preserves_the_complete_external_flow() {
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    let pack = procedure_summary_dependency_pack("test.external-dependency-recursive", true);
    register_pack(&catalog, &pack, "external-dependency-recursive");
    let outcome = evaluate_java_with_models(
        JAVA_COMPLETE_DEPENDENCY_SOURCE,
        &[(
            "test.semantic-summary-dependency-recursive",
            "recursive dependency closure",
        )],
        &catalog,
        &semantic_model_request("1.5.0", MODEL_ARTIFACT_SHA256),
    );
    let run = &outcome.report().runs()[0];
    assert_eq!(run.findings().len(), 1, "{:?}", run.diagnostics());
    let [retained] = outcome.taint_analysis_results() else {
        panic!("expected one retained recursive analysis")
    };
    let summaries = retained.plan().value_flow().external_summaries();
    let recursive_groups = summaries
        .entries()
        .map(|(_, summary)| summary.recursive_group())
        .collect::<Vec<_>>();
    assert_eq!(recursive_groups.len(), 2);
    assert!(recursive_groups[0].is_some());
    assert_eq!(recursive_groups[0], recursive_groups[1]);
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
        let run = &outcome.report().runs()[0];
        assert!(matches!(
            run.completion(),
            PolicyRunCompletion::Inconclusive { reasons }
                if reasons.contains(&PolicyIncompleteReason::PartialDiscovery)
        ));
        assert!(run.findings().is_empty());
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
    assert!(outcome.taint_findings().is_empty());
    assert!(outcome.taint_analysis_results().is_empty());
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
        canonical_taint_evidence(serde_json::to_value(first.taint_findings()).unwrap()),
        canonical_taint_evidence(serde_json::to_value(second.taint_findings()).unwrap()),
        "external model changes must not alter exact public evidence for an inspectable body"
    );
    assert_model_backed_renderers(&first);
    assert_model_backed_renderers(&second);
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
fn compatible_model_backed_multi_demand_has_complete_meeting_sets_and_one_solve() {
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    let pack = procedure_summary_pack("test.external-multi-demand", None, false);
    register_pack(&catalog, &pack, "external-multi-demand");
    let project = InlineTestProject::with_language(Language::Java)
        .file("app.java", JAVA_MULTI_DEMAND_SOURCE)
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let policies = [java_multi_demand_summary_policy(
        "test.semantic-summary-multi-demand",
    )];
    let outcome = evaluate_java_workspace_with_policy_sources_and_models(
        project.root(),
        &workspace,
        &policies,
        &catalog,
        &semantic_model_request("1.5.0", MODEL_ARTIFACT_SHA256),
    );
    let [retained] = outcome.taint_analysis_results() else {
        panic!("expected one retained multi-demand analysis")
    };
    assert_eq!(retained.plan().sources().len(), 2);
    assert_eq!(retained.plan().sinks().len(), 3);
    let reached_sinks = retained
        .report()
        .findings()
        .iter()
        .map(|finding| finding.key().sink())
        .collect::<BTreeSet<_>>();
    let absent_sinks = retained
        .plan()
        .value_flow()
        .sinks()
        .map(|(_, sink)| sink.key())
        .filter(|sink| !reached_sinks.contains(sink))
        .collect::<BTreeSet<_>>();
    let event_line =
        |event: &ValueFlowEventKey| event.site().anchor().span().start().line() as usize + 1;
    assert_eq!(
        reached_sinks
            .iter()
            .map(|sink| event_line(sink))
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([11, 12]),
        "the first two stable sink events must be the complete reached set"
    );
    assert_eq!(
        absent_sinks
            .iter()
            .map(|sink| event_line(sink))
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([13]),
        "the clean third call must be the complete absent sink set"
    );

    let reached_label_sets = outcome
        .taint_findings()
        .iter()
        .map(|finding| finding.reached_labels.clone())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        reached_label_sets,
        BTreeSet::from([
            vec!["first-label".to_owned()],
            vec!["second-label".to_owned()]
        ])
    );
    assert_retained_taint_projection_matrix(&outcome, &workspace);
    let exact_meetings = canonical_public_taint_meetings(&outcome)
        .into_iter()
        .map(|meeting| {
            (
                meeting.sink.start_line,
                meeting.source.start_line,
                meeting.label,
            )
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        exact_meetings,
        BTreeSet::from([
            (11, 11, "first-label".to_owned()),
            (12, 12, "second-label".to_owned()),
        ]),
        "each stable sink site must retain only its intended source meeting"
    );

    let [run] = outcome.report().runs() else {
        panic!("expected one multi-demand policy run")
    };
    assert_eq!(run.findings().len(), 2, "{:?}", run.diagnostics());
    let policy_label_sets = run
        .findings()
        .iter()
        .map(|finding| {
            let PolicyFindingEvidence::Taint { evidence } = finding.evidence() else {
                panic!("expected multi-demand taint evidence")
            };
            evidence
                .reached_source_labels()
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(policy_label_sets, reached_label_sets);
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
