//! Production semantic-summary taint lifecycle benchmark for issue #824.
//!
//! The ignored measurement test is driven by
//! `scripts/run-semantic-summary-taint-lifecycle-benchmarks.sh`. It exercises
//! catalog activation, generation-scoped acquisition, the production policy
//! compiler and batch planner, one propagation solve, retained finding and
//! witness collection, standalone JSON/RQL projection, and policy rendering.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use std::time::Instant;

use brokk_bifrost::analyzer::semantic_model::{
    CatalogCoordinate, CatalogOptions, CompiledSemanticModelPack, CompilerOptions,
    SemanticModelActivationEvidence, SemanticModelActivationRequest, SemanticModelRuntimeLifecycle,
    SemanticModelRuntimeLimits, SemanticModelRuntimeOutcome, SemanticPackCatalog,
    SessionPackSource, SessionPackSourceKind, SourceFormat, acquire_active_semantic_models,
    compile_source,
};
use brokk_bifrost::analyzer::structural::{
    CodeQuery, CodeQueryExecutionLimits, ProtocolRegistrationSet, TaintResultRef,
    TaintResultRegistration, TaintResultRegistrationSet, ValueFlowPlanRegistrationSet,
    execute_workspace_request_with_all_analysis_registration_lease,
};
use brokk_bifrost::analyzer::typestate::ProductionTypestateSummaryRepository;
use brokk_bifrost::policy::{
    PolicyEvaluationDate, PolicyEvaluationInput, PolicyEvaluationOptions,
    PolicySemanticModelContext, PolicySourceIdentity,
    evaluate_policy_inputs_with_analyzer_and_semantic_models, write_policy_json,
};
use brokk_bifrost::{AnalyzerConfig, CancellationToken, Language};
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::common::InlineTestProject;

const RESULT_PREFIX: &str = "BIFROST_SEMANTIC_SUMMARY_TAINT_LIFECYCLE_BENCHMARK=";
const CASE_ENV: &str = "BIFROST_SEMANTIC_SUMMARY_TAINT_LIFECYCLE_CASE";
const ROUND_ENV: &str = "BIFROST_SEMANTIC_SUMMARY_TAINT_LIFECYCLE_ROUND";
const SAMPLES_FILE_ENV: &str = "BIFROST_SEMANTIC_SUMMARY_TAINT_LIFECYCLE_SAMPLES_FILE";
const CAMPAIGN_ENV: &str = "BIFROST_SEMANTIC_SUMMARY_TAINT_LIFECYCLE_CAMPAIGN";
const FORMAT: &str = "bifrost_semantic_summary_taint_lifecycle_sample/v1";
const AGGREGATE_FORMAT: &str = "bifrost_semantic_summary_taint_lifecycle_aggregate/v1";
const MODEL_ARTIFACT_SHA256: &str =
    "8248248248248248248248248248248248248248248248248248248248248248";
const WORKSPACE_GENERATION: u64 = 824;
const RETAINED_ROUNDS: std::ops::RangeInclusive<usize> = 2..=8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CaseSpec {
    name: &'static str,
    summary_count: usize,
    dependency_depth: usize,
    source_count: usize,
    sink_count: usize,
}

const CASES: &[CaseSpec] = &[
    CaseSpec {
        name: "inline_s1_d1_src1_sink1",
        summary_count: 1,
        dependency_depth: 1,
        source_count: 1,
        sink_count: 1,
    },
    CaseSpec {
        name: "inline_s16_d1_src1_sink1",
        summary_count: 16,
        dependency_depth: 1,
        source_count: 1,
        sink_count: 1,
    },
    CaseSpec {
        name: "inline_s64_d1_src1_sink1",
        summary_count: 64,
        dependency_depth: 1,
        source_count: 1,
        sink_count: 1,
    },
    CaseSpec {
        name: "inline_s16_d4_src1_sink1",
        summary_count: 16,
        dependency_depth: 4,
        source_count: 1,
        sink_count: 1,
    },
    CaseSpec {
        name: "inline_s16_d8_src1_sink1",
        summary_count: 16,
        dependency_depth: 8,
        source_count: 1,
        sink_count: 1,
    },
    CaseSpec {
        name: "inline_s1_d1_src4_sink4",
        summary_count: 1,
        dependency_depth: 1,
        source_count: 4,
        sink_count: 4,
    },
    CaseSpec {
        name: "inline_s1_d1_src16_sink16",
        summary_count: 1,
        dependency_depth: 1,
        source_count: 16,
        sink_count: 16,
    },
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct BenchmarkProvenance {
    bifrost_commit: Option<String>,
    bifrost_tracked_dirty: Option<bool>,
    benchmark_source_sha256: Option<String>,
    rustc_version: Option<String>,
    operating_system: String,
    architecture: String,
    logical_parallelism: Option<usize>,
    build_profile: String,
    crate_version: String,
    timer: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CaseDimensions {
    summary_count: usize,
    dependency_depth: usize,
    source_count: usize,
    sink_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PhaseMeasurements {
    workspace_build_ms: f64,
    catalog_compile_and_registration_ms: f64,
    cold_model_resolution_ms: f64,
    warm_generation_acquisition_ms: f64,
    production_route_ms: f64,
    plan_discovery_and_summary_binding_ms: f64,
    batch_planning_ms: f64,
    propagation_ms: f64,
    finding_and_witness_reconstruction_ms: f64,
    initial_standalone_projection_ms: f64,
    retained_projection_ms: f64,
    codequery_json_projection_ms: f64,
    rql_projection_ms: f64,
    policy_projection_ms: f64,
    policy_json_render_ms: f64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CatalogMeasurements {
    cold_lookup_hits: u64,
    cold_lookup_misses: u64,
    warm_lookup_hits: u64,
    warm_lookup_misses: u64,
    production_lookup_hits: u64,
    production_lookup_misses: u64,
    cold_lifecycle: String,
    warm_lifecycle: String,
    warm_execution_per_call_sql_lookups: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RetainedMeasurements {
    plan_bytes: u64,
    report_bytes: u64,
    witness_bytes: u64,
    artifact_bytes: u64,
    findings: usize,
    witnesses: usize,
    witness_steps: usize,
    bound_summaries: usize,
    compatible_policies: usize,
    propagation_solves: usize,
    peak_rss_bytes: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SampleResult {
    format: String,
    provenance: BenchmarkProvenance,
    case: String,
    dimensions: CaseDimensions,
    round: usize,
    phases: PhaseMeasurements,
    catalog: CatalogMeasurements,
    retained: RetainedMeasurements,
    result_checksum: String,
    policy_checksum: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
struct Percentiles {
    p50_ms: f64,
    p95_ms: f64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
struct BytePercentiles {
    p50: u64,
    p95: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct AggregateCase {
    case: String,
    dimensions: CaseDimensions,
    samples: usize,
    phases: BTreeMap<String, Percentiles>,
    catalog: CatalogMeasurements,
    retained: RetainedMeasurements,
    peak_rss_bytes: Option<BytePercentiles>,
    result_checksum: String,
    policy_checksum: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct AggregateResult {
    format: String,
    campaign: String,
    aggregation_provenance: BenchmarkProvenance,
    discarded_warmups_per_case: usize,
    retained_samples_per_case: usize,
    cases: Vec<AggregateCase>,
    raw_samples: Vec<SampleResult>,
    thresholds: Vec<String>,
}

#[test]
#[ignore = "run through scripts/run-semantic-summary-taint-lifecycle-benchmarks.sh"]
fn semantic_summary_taint_lifecycle_measurement() {
    if let Some(path) = std::env::var_os(SAMPLES_FILE_ENV) {
        let campaign = std::env::var(CAMPAIGN_ENV).unwrap_or_else(|_| "smoke".to_owned());
        emit(&aggregate(Path::new(&path), &campaign));
        return;
    }
    emit(&sample());
}

fn sample() -> SampleResult {
    let case_name = required_env(CASE_ENV);
    let spec = case_spec(&case_name);
    let round = required_env(ROUND_ENV).parse::<usize>().unwrap();
    assert!(spec.summary_count >= spec.dependency_depth);
    assert_eq!(spec.source_count, spec.sink_count);

    let workspace_started = Instant::now();
    let project = InlineTestProject::with_language(Language::Java)
        .file("app.java", fixture_source(spec))
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let workspace_build_ms = elapsed_ms(workspace_started);

    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    let registration_started = Instant::now();
    let pack = procedure_summary_pack(spec);
    catalog
        .register_session_pack(
            &pack,
            &SessionPackSource {
                kind: SessionPackSourceKind::Embedded,
                source_id: format!("benchmark:{}", spec.name),
            },
        )
        .expect("register benchmark semantic-summary pack");
    let catalog_compile_and_registration_ms = elapsed_ms(registration_started);
    let request = semantic_model_request();
    let cancellation = CancellationToken::default();
    let before_cold = catalog.accounting().unwrap();
    let cold_started = Instant::now();
    let cold_lifecycle = acquire_lifecycle(&workspace, &catalog, &request, &cancellation);
    let cold_model_resolution_ms = elapsed_ms(cold_started);
    let after_cold = catalog.accounting().unwrap();
    assert_eq!(cold_lifecycle, SemanticModelRuntimeLifecycle::Built);

    let warm_started = Instant::now();
    let warm_lifecycle = acquire_lifecycle(&workspace, &catalog, &request, &cancellation);
    let warm_generation_acquisition_ms = elapsed_ms(warm_started);
    let after_warm = catalog.accounting().unwrap();
    assert_eq!(warm_lifecycle, SemanticModelRuntimeLifecycle::Cached);

    let policy_source = policy_source(spec);
    let inputs = [PolicyEvaluationInput::embedded(
        PolicySourceIdentity::new(format!("benchmark:{}.rqlp", spec.name)),
        &policy_source,
    )];
    let options = PolicyEvaluationOptions::new(
        PolicyEvaluationDate::from_ymd(2026, 8, 3).expect("fixed evaluation date"),
    );
    let before_production = catalog.accounting().unwrap();
    let production_started = Instant::now();
    let outcome = evaluate_policy_inputs_with_analyzer_and_semantic_models(
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
    .expect("production semantic-summary taint evaluation");
    let production_route_ms = elapsed_ms(production_started);
    let after_production = catalog.accounting().unwrap();

    let [retained] = outcome.taint_analysis_results() else {
        panic!(
            "expected one retained compatible analysis, got {}; report={:#?}",
            outcome.taint_analysis_results().len(),
            outcome.report()
        );
    };
    assert!(retained.plan_report_match());
    assert_eq!(retained.bound_summary_count(), spec.dependency_depth);
    assert!(
        retained.finding_count() >= spec.sink_count,
        "every declared sink must retain at least one modeled meeting"
    );
    assert_eq!(retained.phase_metrics().compatible_policy_count(), 1);
    assert_eq!(retained.phase_metrics().propagation_solves(), 1);
    let [run] = outcome.report().runs() else {
        panic!("expected one policy run: {:#?}", outcome.report());
    };
    assert_eq!(
        run.work()
            .metrics()
            .iter()
            .find(|metric| metric.name() == "taint.propagation_solves")
            .map(|metric| metric.value()),
        Some(1),
    );

    let retained_projection_started = Instant::now();
    let projected = retained
        .project_findings(&workspace, retained.projection_limits())
        .expect("retained standalone projection");
    let retained_projection_ms = elapsed_ms(retained_projection_started);
    assert_eq!(projected, outcome.taint_findings());

    let (codequery_json_projection_ms, json_rows, rql_projection_ms, rql_rows) =
        retained_query_projections(&workspace, retained);
    assert_eq!(json_rows, rql_rows);
    assert_eq!(
        canonical_query_rows(json_rows.clone()),
        serde_json::to_value(&projected).unwrap()
    );

    let policy_render_started = Instant::now();
    let mut policy_json = Vec::new();
    write_policy_json(outcome.report(), &mut policy_json, usize::MAX)
        .expect("render production policy JSON");
    let policy_json_render_ms = elapsed_ms(policy_render_started);
    assert!(!policy_json.is_empty());

    let cold_hits = delta(after_cold.lookup_hits, before_cold.lookup_hits);
    let cold_misses = delta(after_cold.lookup_misses, before_cold.lookup_misses);
    let warm_hits = delta(after_warm.lookup_hits, after_cold.lookup_hits);
    let warm_misses = delta(after_warm.lookup_misses, after_cold.lookup_misses);
    let production_hits = delta(after_production.lookup_hits, before_production.lookup_hits);
    let production_misses = delta(
        after_production.lookup_misses,
        before_production.lookup_misses,
    );
    assert_eq!((cold_hits, cold_misses), (1, 0));
    assert_eq!((warm_hits, warm_misses), (0, 0));
    assert_eq!((production_hits, production_misses), (0, 0));

    let metrics = retained.phase_metrics();
    let canonical_result = canonical_taint_evidence(canonical_query_rows(json_rows));
    let canonical_policy = canonical_taint_evidence(serde_json::to_value(run.findings()).unwrap());
    SampleResult {
        format: FORMAT.to_owned(),
        provenance: benchmark_provenance(),
        case: spec.name.to_owned(),
        dimensions: dimensions(spec),
        round,
        phases: PhaseMeasurements {
            workspace_build_ms,
            catalog_compile_and_registration_ms,
            cold_model_resolution_ms,
            warm_generation_acquisition_ms,
            production_route_ms,
            plan_discovery_and_summary_binding_ms: ns_ms(
                metrics.plan_discovery_and_summary_binding_ns(),
            ),
            batch_planning_ms: ns_ms(metrics.batch_planning_ns()),
            propagation_ms: ns_ms(metrics.propagation_ns()),
            finding_and_witness_reconstruction_ms: ns_ms(
                metrics.finding_and_witness_reconstruction_ns(),
            ),
            initial_standalone_projection_ms: ns_ms(metrics.standalone_projection_ns()),
            retained_projection_ms,
            codequery_json_projection_ms,
            rql_projection_ms,
            policy_projection_ms: ns_ms(metrics.policy_projection_ns()),
            policy_json_render_ms,
        },
        catalog: CatalogMeasurements {
            cold_lookup_hits: cold_hits,
            cold_lookup_misses: cold_misses,
            warm_lookup_hits: warm_hits,
            warm_lookup_misses: warm_misses,
            production_lookup_hits: production_hits,
            production_lookup_misses: production_misses,
            cold_lifecycle: "built".to_owned(),
            warm_lifecycle: "cached".to_owned(),
            warm_execution_per_call_sql_lookups: production_hits.saturating_add(production_misses),
        },
        retained: RetainedMeasurements {
            plan_bytes: as_u64(retained.retained_plan_bytes()),
            report_bytes: as_u64(retained.retained_report_bytes()),
            witness_bytes: as_u64(retained.retained_witness_bytes()),
            artifact_bytes: as_u64(retained.retained_artifact_bytes()),
            findings: retained.finding_count(),
            witnesses: retained.retained_witnesses(),
            witness_steps: retained.retained_witness_steps(),
            bound_summaries: retained.bound_summary_count(),
            compatible_policies: metrics.compatible_policy_count(),
            propagation_solves: metrics.propagation_solves(),
            peak_rss_bytes: peak_rss_bytes(),
        },
        result_checksum: json_sha256(&canonical_result),
        policy_checksum: json_sha256(&canonical_policy),
    }
}

fn acquire_lifecycle(
    workspace: &brokk_bifrost::analyzer::WorkspaceAnalyzer,
    catalog: &SemanticPackCatalog,
    request: &SemanticModelActivationRequest,
    cancellation: &CancellationToken,
) -> SemanticModelRuntimeLifecycle {
    match acquire_active_semantic_models(workspace.analyzer(), catalog, None, request, cancellation)
    {
        SemanticModelRuntimeOutcome::Ready { lifecycle, .. } => lifecycle,
        other => panic!("semantic-model acquisition failed: {other:#?}"),
    }
}

fn retained_query_projections(
    workspace: &brokk_bifrost::analyzer::WorkspaceAnalyzer,
    retained: &Arc<brokk_bifrost::policy::ProductionTaintAnalysisResult>,
) -> (f64, serde_json::Value, f64, serde_json::Value) {
    let primary = TaintResultRef::new("benchmark", "primary").unwrap();
    let alias = TaintResultRef::new("benchmark", "alias").unwrap();
    let mut registrations = TaintResultRegistrationSet::default();
    for reference in [&primary, &alias] {
        registrations
            .register(
                reference.clone(),
                TaintResultRegistration::new(WORKSPACE_GENERATION, vec![Arc::clone(retained)])
                    .unwrap(),
            )
            .unwrap();
    }
    assert_eq!(registrations.registration_count(), 1);
    let json_query = CodeQuery::from_json(&serde_json::json!({
        "schema_version": 1,
        "match": { "kind": "method", "name": "run" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "taint", "taint_ref": "benchmark:primary" }
        ]
    }))
    .unwrap();
    let rql_query = CodeQuery::from_sexp(
        r#"(taint :taint-ref benchmark:alias (procedure-of (method :name "run")))"#,
    )
    .unwrap();
    let summaries = Arc::new(ProductionTypestateSummaryRepository::new());
    let execute = |query: &CodeQuery| {
        execute_workspace_request_with_all_analysis_registration_lease(
            workspace,
            WORKSPACE_GENERATION,
            &ProtocolRegistrationSet::default(),
            &ValueFlowPlanRegistrationSet::default(),
            &registrations,
            query,
            CodeQueryExecutionLimits::default(),
            None,
            summaries.lease(WORKSPACE_GENERATION).unwrap(),
        )
    };
    let json_started = Instant::now();
    let json = execute(&json_query);
    let json_ms = elapsed_ms(json_started);
    let json = json.result().expect("JSON retained taint result");
    assert!(json.diagnostics.is_empty(), "{:?}", json.diagnostics);
    let json_rows = serde_json::to_value(&json.results).unwrap();

    let rql_started = Instant::now();
    let rql = execute(&rql_query);
    let rql_ms = elapsed_ms(rql_started);
    let rql = rql.result().expect("RQL retained taint result");
    assert!(rql.diagnostics.is_empty(), "{:?}", rql.diagnostics);
    let rql_rows = serde_json::to_value(&rql.results).unwrap();
    (json_ms, json_rows, rql_ms, rql_rows)
}

fn canonical_query_rows(mut rows: serde_json::Value) -> serde_json::Value {
    let serde_json::Value::Array(findings) = &mut rows else {
        panic!("taint query results must be an array: {rows}");
    };
    for finding in findings {
        let serde_json::Value::Object(fields) = finding else {
            panic!("taint query result must be an object: {finding}");
        };
        assert_eq!(
            fields.remove("result_type"),
            Some(serde_json::json!("taint_finding"))
        );
        assert!(fields.remove("provenance").is_some());
    }
    rows
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

fn fixture_source(spec: CaseSpec) -> String {
    let mut source = String::from("class App {\n");
    for index in 0..spec.source_count {
        source.push_str(&format!("  static native String attacker_{index}();\n"));
    }
    for index in 0..spec.sink_count {
        source.push_str(&format!(
            "  static native void sensitive_{index}(String value);\n"
        ));
    }
    source.push_str("  native String external(String value);\n");
    for depth in 1..spec.dependency_depth {
        source.push_str(&format!("  native String relay_{depth}(String value);\n"));
    }
    source.push_str("  void run() {\n");
    for index in 0..spec.source_count {
        source.push_str(&format!(
            "    sensitive_{index}(this.external(attacker_{index}()));\n"
        ));
    }
    if spec.dependency_depth > 1 {
        source.push_str("    String relayValue = \"clean\";\n");
        for depth in 1..spec.dependency_depth {
            source.push_str(&format!(
                "    relayValue = this.relay_{depth}(relayValue);\n"
            ));
        }
    }
    source.push_str("  }\n}\n");
    source
}

fn policy_source(spec: CaseSpec) -> String {
    let sources = (0..spec.source_count)
        .map(|index| {
            format!(
                r#"(source :id attacker-{index} :display-name "attacker {index}" :categories [input.user]
                :selector (rql :schema-version 1
                  (language java (call :callee (name "attacker_{index}"))))
                :bind return-value :labels [untrusted])"#
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let sinks = (0..spec.sink_count)
        .map(|index| {
            format!(
                r#"(sink :id sensitive-{index} :display-name "sensitive {index}" :categories [data.sensitive]
                :selector (rql :schema-version 1
                  (language java (call :callee (name "sensitive_{index}"))))
                :dangerous-operand (argument :index 0) :accepts [untrusted])"#
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        r#"(policy
          :schema-version 1
          :id "benchmark.semantic-summary-taint"
          :name "Production semantic-summary taint lifecycle"
          :message "semantic-summary taint lifecycle"
          :severity warning
          :analysis (analysis
            :type taint
            :mode may
            :call-modeling (call-modeling :unmodeled require-model)
            :sources (endpoint-set :entries [{sources}])
            :sinks (endpoint-set :entries [{sinks}]))
          :classification (classification
            :fallback (classification-id :taxonomy "Benchmark" :id "SUMMARY-TAINT")))"#
    )
}

fn procedure_summary_pack(spec: CaseSpec) -> CompiledSemanticModelPack {
    let mut summaries = Vec::with_capacity(spec.summary_count);
    for depth in 0..spec.dependency_depth {
        let id = summary_id(depth);
        let target_symbol = if depth == 0 {
            "external(String)".to_owned()
        } else {
            format!("relay_{depth}(String)")
        };
        let last = depth + 1 == spec.dependency_depth;
        let effects = if last {
            Vec::new()
        } else {
            vec![serde_json::json!({
                "kind": "call",
                "event": format!("event.summary.{depth}"),
                "callee": summary_id(depth + 1),
            })]
        };
        let transfers = vec![serde_json::json!({
            "input": { "kind": "parameter", "ordinal": 0 },
            "exit_kind": "normal",
            "output": { "kind": "normal_return" }
        })];
        summaries.push(serde_json::json!({
            "id": id,
            "target": {
                "path": "app.java",
                "symbol": target_symbol,
                "has_receiver": true,
                "parameter_count": 1
            },
            "completeness": "complete",
            "transfers": transfers,
            "effects": effects
        }));
    }
    for index in spec.dependency_depth..spec.summary_count {
        summaries.push(serde_json::json!({
            "id": format!("summary.unrelated.{index}"),
            "target": {
                "path": format!("unrelated/{index}.java"),
                "symbol": format!("unrelated_{index}(String)"),
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
        "pack_id": format!("benchmark.semantic-summary-taint.{}", spec.name),
        "version": "1.0.0",
        "producer": { "name": "bifrost-benchmark", "version": "1.0.0" },
        "language": "java",
        "ecosystem": "maven",
        "compatibility": {
            "bifrost": ">=0.8.0, <1.0.0",
            "toolchains": [{ "name": "jdk", "requirement": ">=17.0.0" }]
        },
        "provenance": { "source": "benchmark:inline", "revision": spec.name },
        "license": "Apache-2.0",
        "completeness": "complete",
        "safety": { "generated_code_only": false, "review_required": false },
        "shards": [{
            "id": "summaries.production-taint",
            "activation": [{
                "package": { "name": "com.acme:external", "version": ">=1.0.0, <2.0.0" },
                "targets": ["jvm"],
                "configurations": ["release"],
                "artifact_sha256": MODEL_ARTIFACT_SHA256
            }],
            "payload": { "kind": "procedure_summaries", "summaries": summaries }
        }]
    }))
    .unwrap();
    compile_source(SourceFormat::Json, &source, &CompilerOptions::default())
        .unwrap_or_else(|diagnostics| panic!("benchmark semantic pack failed: {diagnostics:#?}"))
}

fn summary_id(depth: usize) -> String {
    if depth == 0 {
        "summary.external".to_owned()
    } else {
        format!("summary.relay.{depth}")
    }
}

fn semantic_model_request() -> SemanticModelActivationRequest {
    SemanticModelActivationRequest {
        bifrost_version: Version::parse(env!("CARGO_PKG_VERSION")).unwrap(),
        evidence: vec![SemanticModelActivationEvidence {
            language: "java".to_owned(),
            ecosystem: "maven".to_owned(),
            package: Some(CatalogCoordinate {
                name: "com.acme:external".to_owned(),
                version: Some(Version::parse("1.5.0").unwrap()),
            }),
            module: None,
            toolchain: Some(CatalogCoordinate {
                name: "jdk".to_owned(),
                version: Some(Version::parse("17.0.1").unwrap()),
            }),
            target: Some("jvm".to_owned()),
            configuration: Some("release".to_owned()),
            artifact_sha256: Some(MODEL_ARTIFACT_SHA256.to_owned()),
        }],
        controls: Vec::new(),
        limits: SemanticModelRuntimeLimits::default(),
    }
}

fn aggregate(path: &Path, campaign: &str) -> AggregateResult {
    assert!(matches!(campaign, "smoke" | "full"));
    let contents = fs::read_to_string(path).unwrap();
    let mut raw_samples = contents
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str::<SampleResult>(line).unwrap())
        .collect::<Vec<_>>();
    assert!(!raw_samples.is_empty(), "aggregation requires samples");
    assert!(raw_samples.iter().all(|sample| sample.format == FORMAT));
    raw_samples.sort_by(|left, right| {
        left.case
            .cmp(&right.case)
            .then(left.round.cmp(&right.round))
    });
    let aggregation_provenance = raw_samples[0].provenance.clone();
    assert!(
        raw_samples
            .iter()
            .all(|sample| sample.provenance == aggregation_provenance)
    );
    let mut groups = BTreeMap::<String, Vec<&SampleResult>>::new();
    for sample in &raw_samples {
        groups.entry(sample.case.clone()).or_default().push(sample);
    }
    if campaign == "full" {
        assert_eq!(
            groups.keys().cloned().collect::<BTreeSet<_>>(),
            CASES.iter().map(|case| case.name.to_owned()).collect(),
        );
    }
    let mut cases = Vec::with_capacity(groups.len());
    for (case, samples) in groups {
        let reference = samples[0];
        if campaign == "full" {
            assert_eq!(samples.len(), RETAINED_ROUNDS.clone().count());
            assert_eq!(
                samples
                    .iter()
                    .map(|sample| sample.round)
                    .collect::<BTreeSet<_>>(),
                RETAINED_ROUNDS.clone().collect(),
            );
        }
        for sample in &samples {
            assert_eq!(sample.dimensions, reference.dimensions);
            assert_eq!(sample.catalog, reference.catalog);
            assert_retained_stable(&sample.retained, &reference.retained);
            assert_eq!(sample.result_checksum, reference.result_checksum);
            assert_eq!(sample.policy_checksum, reference.policy_checksum);
            assert_eq!(sample.catalog.warm_execution_per_call_sql_lookups, 0);
            assert_eq!(sample.retained.propagation_solves, 1);
            assert_eq!(sample.retained.compatible_policies, 1);
            assert_eq!(
                sample.retained.bound_summaries,
                sample.dimensions.dependency_depth
            );
        }
        let peak_rss_bytes = optional_byte_percentiles(
            samples
                .iter()
                .map(|sample| sample.retained.peak_rss_bytes)
                .collect(),
        );
        let mut retained = reference.retained.clone();
        retained.peak_rss_bytes = peak_rss_bytes.map(|percentiles| percentiles.p50);
        cases.push(AggregateCase {
            case,
            dimensions: reference.dimensions.clone(),
            samples: samples.len(),
            phases: phase_percentiles(&samples),
            catalog: reference.catalog.clone(),
            retained,
            peak_rss_bytes,
            result_checksum: reference.result_checksum.clone(),
            policy_checksum: reference.policy_checksum.clone(),
        });
    }
    AggregateResult {
        format: AGGREGATE_FORMAT.to_owned(),
        campaign: campaign.to_owned(),
        aggregation_provenance,
        discarded_warmups_per_case: usize::from(campaign == "full") * 2,
        retained_samples_per_case: if campaign == "full" {
            7
        } else {
            cases[0].samples
        },
        cases,
        raw_samples,
        thresholds: Vec::new(),
    }
}

fn assert_retained_stable(left: &RetainedMeasurements, right: &RetainedMeasurements) {
    assert_eq!(left.plan_bytes, right.plan_bytes);
    assert_eq!(left.report_bytes, right.report_bytes);
    assert_eq!(left.witness_bytes, right.witness_bytes);
    assert_eq!(left.artifact_bytes, right.artifact_bytes);
    assert_eq!(left.findings, right.findings);
    assert_eq!(left.witnesses, right.witnesses);
    assert_eq!(left.witness_steps, right.witness_steps);
    assert_eq!(left.bound_summaries, right.bound_summaries);
    assert_eq!(left.compatible_policies, right.compatible_policies);
    assert_eq!(left.propagation_solves, right.propagation_solves);
}

fn optional_byte_percentiles(values: Vec<Option<u64>>) -> Option<BytePercentiles> {
    let mut values = values.into_iter().collect::<Option<Vec<_>>>()?;
    values.sort_unstable();
    Some(BytePercentiles {
        p50: nearest_rank_u64(&values, 50),
        p95: nearest_rank_u64(&values, 95),
    })
}

fn nearest_rank_u64(values: &[u64], percentile: usize) -> u64 {
    assert!(!values.is_empty());
    let rank = values.len().saturating_mul(percentile).div_ceil(100);
    values[rank.saturating_sub(1)]
}

fn phase_percentiles(samples: &[&SampleResult]) -> BTreeMap<String, Percentiles> {
    let values = |select: fn(&PhaseMeasurements) -> f64| {
        percentile_pair(
            samples
                .iter()
                .map(|sample| select(&sample.phases))
                .collect(),
        )
    };
    [
        (
            "workspace_build_ms",
            values(|phase| phase.workspace_build_ms),
        ),
        (
            "catalog_compile_and_registration_ms",
            values(|phase| phase.catalog_compile_and_registration_ms),
        ),
        (
            "cold_model_resolution_ms",
            values(|phase| phase.cold_model_resolution_ms),
        ),
        (
            "warm_generation_acquisition_ms",
            values(|phase| phase.warm_generation_acquisition_ms),
        ),
        (
            "production_route_ms",
            values(|phase| phase.production_route_ms),
        ),
        (
            "plan_discovery_and_summary_binding_ms",
            values(|phase| phase.plan_discovery_and_summary_binding_ms),
        ),
        ("batch_planning_ms", values(|phase| phase.batch_planning_ms)),
        ("propagation_ms", values(|phase| phase.propagation_ms)),
        (
            "finding_and_witness_reconstruction_ms",
            values(|phase| phase.finding_and_witness_reconstruction_ms),
        ),
        (
            "initial_standalone_projection_ms",
            values(|phase| phase.initial_standalone_projection_ms),
        ),
        (
            "retained_projection_ms",
            values(|phase| phase.retained_projection_ms),
        ),
        (
            "codequery_json_projection_ms",
            values(|phase| phase.codequery_json_projection_ms),
        ),
        ("rql_projection_ms", values(|phase| phase.rql_projection_ms)),
        (
            "policy_projection_ms",
            values(|phase| phase.policy_projection_ms),
        ),
        (
            "policy_json_render_ms",
            values(|phase| phase.policy_json_render_ms),
        ),
    ]
    .into_iter()
    .map(|(name, value)| (name.to_owned(), value))
    .collect()
}

fn percentile_pair(mut values: Vec<f64>) -> Percentiles {
    assert!(!values.is_empty());
    values.sort_by(f64::total_cmp);
    Percentiles {
        p50_ms: nearest_rank(&values, 50),
        p95_ms: nearest_rank(&values, 95),
    }
}

fn nearest_rank(values: &[f64], percentile: usize) -> f64 {
    assert!(!values.is_empty());
    assert!((1..=100).contains(&percentile));
    let rank = values.len().saturating_mul(percentile).div_ceil(100);
    values[rank.saturating_sub(1)]
}

fn dimensions(spec: CaseSpec) -> CaseDimensions {
    CaseDimensions {
        summary_count: spec.summary_count,
        dependency_depth: spec.dependency_depth,
        source_count: spec.source_count,
        sink_count: spec.sink_count,
    }
}

fn case_spec(name: &str) -> CaseSpec {
    CASES
        .iter()
        .copied()
        .find(|spec| spec.name == name)
        .unwrap_or_else(|| panic!("unknown benchmark case {name:?}"))
}

fn required_env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} is required"))
}

fn delta(after: u64, before: u64) -> u64 {
    after
        .checked_sub(before)
        .expect("catalog counters are monotonic")
}

fn elapsed_ms(started: Instant) -> f64 {
    started.elapsed().as_secs_f64() * 1_000.0
}

fn ns_ms(value: u64) -> f64 {
    value as f64 / 1_000_000.0
}

fn as_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

fn json_sha256(value: &serde_json::Value) -> String {
    sha256_bytes(&serde_json::to_vec(value).unwrap())
}

fn sha256_bytes(value: &[u8]) -> String {
    format!("{:x}", Sha256::digest(value))
}

fn emit(value: &impl Serialize) {
    println!("{RESULT_PREFIX}{}", serde_json::to_string(value).unwrap());
}

#[cfg(unix)]
fn peak_rss_bytes() -> Option<u64> {
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    let result = unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) };
    assert_eq!(result, 0, "getrusage failed");
    let max_rss = usage.ru_maxrss.max(0) as u64;
    Some(if cfg!(target_os = "macos") {
        max_rss
    } else {
        max_rss.saturating_mul(1024)
    })
}

#[cfg(not(unix))]
fn peak_rss_bytes() -> Option<u64> {
    None
}

fn benchmark_provenance() -> BenchmarkProvenance {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    BenchmarkProvenance {
        bifrost_commit: command_output_in(root, "git", &["rev-parse", "HEAD"]),
        bifrost_tracked_dirty: command_output_in(root, "git", &["diff", "--quiet", "HEAD", "--"])
            .map(|_| false)
            .or(Some(true)),
        benchmark_source_sha256: fs::read(
            root.join("tests/suite_bench_policy/measure_semantic_summary_taint_lifecycle.rs"),
        )
        .ok()
        .map(|bytes| sha256_bytes(&bytes)),
        rustc_version: command_output("rustc", &["--version"]),
        operating_system: std::env::consts::OS.to_owned(),
        architecture: std::env::consts::ARCH.to_owned(),
        logical_parallelism: std::thread::available_parallelism()
            .ok()
            .map(std::num::NonZeroUsize::get),
        build_profile: if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        }
        .to_owned(),
        crate_version: env!("CARGO_PKG_VERSION").to_owned(),
        timer: "std::time::Instant monotonic elapsed wall time".to_owned(),
    }
}

fn command_output_in(root: &Path, program: &str, arguments: &[&str]) -> Option<String> {
    Command::new(program)
        .current_dir(root)
        .args(arguments)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|output| output.trim().to_owned())
}

fn command_output(program: &str, arguments: &[&str]) -> Option<String> {
    Command::new(program)
        .args(arguments)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|output| output.trim().to_owned())
}

#[test]
fn aggregation_uses_nearest_rank_p50_and_p95_for_retained_rounds() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("samples.jsonl");
    let samples = RETAINED_ROUNDS
        .clone()
        .enumerate()
        .map(|(offset, round)| {
            serde_json::to_string(&synthetic_sample(round, offset as f64)).unwrap()
        })
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(&path, format!("{samples}\n")).unwrap();
    let aggregate = aggregate(&path, "smoke");
    let phase = aggregate.cases[0].phases.get("propagation_ms").unwrap();
    assert_eq!(phase.p50_ms, 3.0);
    assert_eq!(phase.p95_ms, 6.0);
    assert!(aggregate.thresholds.is_empty());
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")]
fn aggregation_rejects_deterministic_result_drift() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("samples.jsonl");
    let first = synthetic_sample(2, 0.0);
    let mut second = synthetic_sample(3, 1.0);
    second.result_checksum = "drift".to_owned();
    fs::write(
        &path,
        format!(
            "{}\n{}\n",
            serde_json::to_string(&first).unwrap(),
            serde_json::to_string(&second).unwrap()
        ),
    )
    .unwrap();
    let _ = aggregate(&path, "smoke");
}

fn synthetic_sample(round: usize, elapsed: f64) -> SampleResult {
    let phases = PhaseMeasurements {
        workspace_build_ms: elapsed,
        catalog_compile_and_registration_ms: elapsed,
        cold_model_resolution_ms: elapsed,
        warm_generation_acquisition_ms: elapsed,
        production_route_ms: elapsed,
        plan_discovery_and_summary_binding_ms: elapsed,
        batch_planning_ms: elapsed,
        propagation_ms: elapsed,
        finding_and_witness_reconstruction_ms: elapsed,
        initial_standalone_projection_ms: elapsed,
        retained_projection_ms: elapsed,
        codequery_json_projection_ms: elapsed,
        rql_projection_ms: elapsed,
        policy_projection_ms: elapsed,
        policy_json_render_ms: elapsed,
    };
    SampleResult {
        format: FORMAT.to_owned(),
        provenance: BenchmarkProvenance {
            bifrost_commit: Some("commit".to_owned()),
            bifrost_tracked_dirty: Some(true),
            benchmark_source_sha256: Some("source".to_owned()),
            rustc_version: Some("rustc".to_owned()),
            operating_system: "test".to_owned(),
            architecture: "test".to_owned(),
            logical_parallelism: Some(1),
            build_profile: "test".to_owned(),
            crate_version: "test".to_owned(),
            timer: "test".to_owned(),
        },
        case: CASES[0].name.to_owned(),
        dimensions: dimensions(CASES[0]),
        round,
        phases,
        catalog: CatalogMeasurements {
            cold_lookup_hits: 1,
            cold_lookup_misses: 0,
            warm_lookup_hits: 0,
            warm_lookup_misses: 0,
            production_lookup_hits: 0,
            production_lookup_misses: 0,
            cold_lifecycle: "built".to_owned(),
            warm_lifecycle: "cached".to_owned(),
            warm_execution_per_call_sql_lookups: 0,
        },
        retained: RetainedMeasurements {
            plan_bytes: 1,
            report_bytes: 1,
            witness_bytes: 1,
            artifact_bytes: 1,
            findings: 1,
            witnesses: 1,
            witness_steps: 1,
            bound_summaries: 1,
            compatible_policies: 1,
            propagation_solves: 1,
            peak_rss_bytes: Some(1),
        },
        result_checksum: "result".to_owned(),
        policy_checksum: "policy".to_owned(),
    }
}
