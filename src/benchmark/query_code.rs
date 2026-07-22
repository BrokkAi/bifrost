use crate::analyzer::structural::CodeQueryProfile;
use crate::benchmark::mcp_iteration::{
    IterationId, run_profiled_iteration, start_initialized_session,
};
use crate::benchmark::mcp_session::McpSession;
use crate::benchmark::report::{
    QueryCodeAccessPathMetrics, QueryCodeAccessPathTermMetrics, QueryCodeBenchmarkMetrics,
    QueryCodeDerivedLayerMetrics, QueryCodeFactsCacheMetrics, QueryCodeProfileMetrics,
    ScenarioReport, ScenarioTransport,
};
use crate::benchmark::runner::BenchmarkProfile;
use crate::benchmark::{
    BenchmarkManifest, BenchmarkRepoTarget, BenchmarkScenario, QueryCodeBenchmarkCase,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

const COLD_CONTRACT: &str = "fresh MCP process and analyzer snapshot; empty in-memory query indexes and derived layers; pinned checkout and durable structural-facts store retained; production Auto records one viable use before building on reuse";

#[derive(Debug)]
struct QueryCodeIteration {
    duration_ms: f64,
    result: Value,
    metrics: QueryCodeProfileMetrics,
}

pub(super) fn run_scenarios(
    target: &BenchmarkRepoTarget,
    manifest: &BenchmarkManifest,
    workspace_path: &Path,
    profile: Option<&BenchmarkProfile>,
) -> Vec<ScenarioReport> {
    target
        .query_code_queries
        .iter()
        .map(
            |case| match start_initialized_session(workspace_path, false, profile.is_some()) {
                Ok(mut session) => run_case(target, manifest, case, &mut session, profile),
                Err(error) => failure_report(
                    case,
                    Vec::new(),
                    format!(
                        "failed to start MCP session for query_code case `{}` in `{}`: {error}",
                        case.id, target.name
                    ),
                ),
            },
        )
        .collect()
}

fn run_case(
    target: &BenchmarkRepoTarget,
    manifest: &BenchmarkManifest,
    case: &QueryCodeBenchmarkCase,
    session: &mut McpSession,
    profile: Option<&BenchmarkProfile>,
) -> ScenarioReport {
    let mut warmup_durations_ms = Vec::with_capacity(manifest.warmup_iterations);
    let mut measured_durations_ms = Vec::with_capacity(manifest.measured_iterations);
    let mut measured_metrics = Vec::with_capacity(manifest.measured_iterations);
    let mut warmup_transition = None;
    let mut profile_artifacts = Vec::new();

    let (first_outcome, artifact) = run_iteration(target, case, session, profile, "first", 1);
    profile_artifacts.extend(artifact);
    let first = match first_outcome {
        Ok(first) => first,
        Err(error) => return failure_report(case, profile_artifacts, error),
    };
    let first_duration_ms = first.duration_ms;
    let expected_result = first.result;
    let first_metrics = first.metrics;

    for iteration in 0..manifest.warmup_iterations {
        let (outcome, artifact) =
            run_iteration(target, case, session, profile, "warmup", iteration + 1);
        profile_artifacts.extend(artifact);
        match outcome.and_then(|observation| {
            ensure_stable_result(case, &expected_result, &observation.result)?;
            Ok(observation)
        }) {
            Ok(observation) => {
                if warmup_transition.is_none()
                    && observation
                        .metrics
                        .access_path
                        .as_ref()
                        .is_some_and(|access| {
                            access.index_builds > 0
                                || access.index_unavailable > 0
                                || access.index_cancelled > 0
                        })
                {
                    warmup_transition = Some(observation.metrics.clone());
                }
                warmup_durations_ms.push(observation.duration_ms);
            }
            Err(error) => return failure_report(case, profile_artifacts, error),
        }
    }

    for iteration in 0..manifest.measured_iterations {
        let (outcome, artifact) =
            run_iteration(target, case, session, profile, "measured", iteration + 1);
        profile_artifacts.extend(artifact);
        match outcome.and_then(|observation| {
            ensure_stable_result(case, &expected_result, &observation.result)?;
            Ok(observation)
        }) {
            Ok(observation) => {
                measured_durations_ms.push(observation.duration_ms);
                measured_metrics.push(observation.metrics);
            }
            Err(error) => return failure_report(case, profile_artifacts, error),
        }
    }

    let warm_metrics = match aggregate_metrics(&measured_metrics) {
        Ok(metrics) => metrics,
        Err(error) => return failure_report(case, profile_artifacts, error),
    };
    let mut report = ScenarioReport::from_timings(
        BenchmarkScenario::QueryCode,
        ScenarioTransport::Mcp,
        true,
        warmup_durations_ms,
        measured_durations_ms,
        None,
    )
    .with_query_code(
        case.id.clone(),
        first_duration_ms,
        QueryCodeBenchmarkMetrics {
            cold_contract: COLD_CONTRACT.to_string(),
            first: first_metrics,
            warmup_transition,
            warm: warm_metrics,
        },
    );
    report.profile_artifacts = profile_artifacts;
    report
}

/// A failed correctness oracle makes every timing from the case unusable.
fn failure_report(
    case: &QueryCodeBenchmarkCase,
    profile_artifacts: Vec<PathBuf>,
    error: String,
) -> ScenarioReport {
    let mut report = ScenarioReport::from_timings(
        BenchmarkScenario::QueryCode,
        ScenarioTransport::Mcp,
        false,
        Vec::new(),
        Vec::new(),
        Some(error),
    )
    .with_case_id(case.id.clone());
    report.profile_artifacts = profile_artifacts;
    report
}

fn run_iteration(
    target: &BenchmarkRepoTarget,
    case: &QueryCodeBenchmarkCase,
    session: &mut McpSession,
    profile: Option<&BenchmarkProfile>,
    phase: &str,
    iteration: usize,
) -> (Result<QueryCodeIteration, String>, Option<PathBuf>) {
    let (outcome, artifact) = run_profiled_iteration(
        session,
        profile,
        IterationId {
            target,
            scenario: BenchmarkScenario::QueryCode,
            case_id: Some(&case.id),
            phase,
            iteration,
        },
        |session| {
            let arguments = query_arguments(case)?;
            let result = session.call_tool("query_code", arguments)?;
            parse_profile(case, &result)
        },
    );
    (
        outcome.map(|timed| QueryCodeIteration {
            duration_ms: timed.duration_ms,
            result: timed.value.0,
            metrics: timed.value.1,
        }),
        artifact,
    )
}

fn query_arguments(case: &QueryCodeBenchmarkCase) -> Result<Value, String> {
    let mut query = serde_json::from_str::<Value>(&case.query_json).map_err(|error| {
        format!(
            "query_code case `{}` has invalid query_json: {error}",
            case.id
        )
    })?;
    let object = query.as_object_mut().ok_or_else(|| {
        format!(
            "query_code case `{}` query_json must contain an object",
            case.id
        )
    })?;
    object.insert("execution_mode".to_string(), json!("profile"));
    Ok(query)
}

#[derive(Debug, Deserialize)]
struct ProfileWire {
    format: String,
    result: Value,
    timings_ns: TimingWire,
    work: WorkWire,
    cache_layers: Vec<CacheLayerWire>,
    access_path: Value,
}

#[derive(Debug, Deserialize)]
struct TimingWire {
    total: u64,
}

#[derive(Debug, Deserialize)]
struct WorkWire {
    scanned_files: u64,
    scanned_source_bytes: u64,
    fact_nodes: u64,
    pipeline_rows: u64,
    examined_references: u64,
    import_files_resolved: u64,
    import_edges_resolved: u64,
}

#[derive(Debug, Deserialize)]
struct CacheLayerWire {
    layer: String,
    metrics: Value,
}

#[derive(Debug, Deserialize)]
struct FactsCacheWire {
    lookups: u64,
    memory_hits: u64,
    persisted_hydrations: u64,
    extractions: u64,
    unavailable: u64,
    unknown_outcomes: u64,
    replayed_files: u64,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct DerivedLayerCacheWire {
    lookups: u64,
    hits: u64,
    misses: u64,
    builds: u64,
    waits: u64,
    wait_ns: u64,
    complete_hits: u64,
    incomplete_hits: u64,
    complete_builds: u64,
    incomplete_builds: u64,
    unknown_outcomes: u64,
    cancelled: u64,
    unavailable: u64,
    over_budget: u64,
    fallbacks: u64,
    replayed_items: u64,
    build_files: u64,
    build_edges: u64,
    build_ns: u64,
    retained_bytes: u64,
}

fn parse_profile(
    case: &QueryCodeBenchmarkCase,
    tool_result: &Value,
) -> Result<(Value, QueryCodeProfileMetrics), String> {
    let structured = tool_result.get("structuredContent").ok_or_else(|| {
        format!(
            "query_code case `{}` returned no structuredContent",
            case.id
        )
    })?;
    let profile: ProfileWire = serde_json::from_value(structured.clone()).map_err(|error| {
        format!(
            "query_code case `{}` returned an invalid profile payload: {error}",
            case.id
        )
    })?;
    if profile.format != CodeQueryProfile::FORMAT {
        return Err(format!(
            "query_code case `{}` returned unsupported profile format `{}`; expected `{}`",
            case.id,
            profile.format,
            CodeQueryProfile::FORMAT
        ));
    }

    validate_result(case, &profile.result)?;
    let results = profile.result["results"].as_array().ok_or_else(|| {
        format!(
            "query_code case `{}` result is missing results array",
            case.id
        )
    })?;
    let result_cardinality = results.len();
    let truncated = profile.result["truncated"].as_bool().ok_or_else(|| {
        format!(
            "query_code case `{}` result is missing truncated boolean",
            case.id
        )
    })?;
    let diagnostic_codes = diagnostic_codes(&profile.result)?;
    let facts_layer = profile
        .cache_layers
        .iter()
        .find(|layer| layer.layer == "seed_structural_facts")
        .ok_or_else(|| {
            format!(
                "query_code case `{}` profile is missing seed_structural_facts cache metrics",
                case.id
            )
        })?;
    let facts: FactsCacheWire =
        serde_json::from_value(facts_layer.metrics.clone()).map_err(|error| {
            format!(
                "query_code case `{}` returned invalid seed_structural_facts metrics: {error}",
                case.id
            )
        })?;
    let topology = profile
        .cache_layers
        .iter()
        .find(|layer| layer.layer == "direct_import_topology")
        .map(|layer| serde_json::from_value::<DerivedLayerCacheWire>(layer.metrics.clone()))
        .transpose()
        .map_err(|error| {
            format!(
                "query_code case `{}` returned invalid direct_import_topology metrics: {error}",
                case.id
            )
        })?
        .unwrap_or_default();

    Ok((
        profile.result,
        QueryCodeProfileMetrics {
            profile_format: profile.format,
            result_cardinality,
            truncated,
            diagnostic_codes,
            total_ns: profile.timings_ns.total,
            scanned_files: profile.work.scanned_files,
            scanned_source_bytes: profile.work.scanned_source_bytes,
            fact_nodes: profile.work.fact_nodes,
            pipeline_rows: profile.work.pipeline_rows,
            examined_references: profile.work.examined_references,
            import_files_resolved: profile.work.import_files_resolved,
            import_edges_resolved: profile.work.import_edges_resolved,
            facts_cache: QueryCodeFactsCacheMetrics {
                lookups: facts.lookups,
                memory_hits: facts.memory_hits,
                persisted_hydrations: facts.persisted_hydrations,
                extractions: facts.extractions,
                unavailable: facts.unavailable,
                unknown_outcomes: facts.unknown_outcomes,
                replayed_files: facts.replayed_files,
            },
            direct_import_topology: QueryCodeDerivedLayerMetrics {
                lookups: topology.lookups,
                hits: topology.hits,
                misses: topology.misses,
                builds: topology.builds,
                waits: topology.waits,
                wait_ns: topology.wait_ns,
                complete_hits: topology.complete_hits,
                incomplete_hits: topology.incomplete_hits,
                complete_builds: topology.complete_builds,
                incomplete_builds: topology.incomplete_builds,
                unknown_outcomes: topology.unknown_outcomes,
                cancelled: topology.cancelled,
                unavailable: topology.unavailable,
                over_budget: topology.over_budget,
                fallbacks: topology.fallbacks,
                replayed_items: topology.replayed_items,
                build_files: topology.build_files,
                build_edges: topology.build_edges,
                build_ns: topology.build_ns,
                retained_bytes: topology.retained_bytes,
            },
            access_path: Some(parse_access_path(&profile.access_path)?),
        },
    ))
}

fn validate_result(case: &QueryCodeBenchmarkCase, result: &Value) -> Result<(), String> {
    let results = result["results"].as_array().ok_or_else(|| {
        format!(
            "query_code case `{}` result is missing results array",
            case.id
        )
    })?;
    if let Some(minimum) = case.min_results
        && results.len() < minimum
    {
        return Err(format!(
            "query_code case `{}` returned {} result(s), expected at least {minimum}",
            case.id,
            results.len()
        ));
    }
    if let Some(maximum) = case.max_results
        && results.len() > maximum
    {
        return Err(format!(
            "query_code case `{}` returned {} result(s), expected at most {maximum}",
            case.id,
            results.len()
        ));
    }
    if let Some(witness_json) = &case.expected_witness_json {
        let witness = serde_json::from_str::<Value>(witness_json).map_err(|error| {
            format!(
                "query_code case `{}` has invalid expected witness: {error}",
                case.id
            )
        })?;
        if !results
            .iter()
            .any(|candidate| json_value_contains(candidate, &witness))
        {
            return Err(format!(
                "query_code case `{}` returned no result matching witness {witness}",
                case.id
            ));
        }
    }

    let truncated = result["truncated"].as_bool().ok_or_else(|| {
        format!(
            "query_code case `{}` result is missing truncated boolean",
            case.id
        )
    })?;
    if truncated != case.expected_truncated {
        return Err(format!(
            "query_code case `{}` returned truncated={truncated}, expected {}",
            case.id, case.expected_truncated
        ));
    }

    let actual_codes = diagnostic_codes(result)?;
    let mut expected_codes = case.expected_diagnostic_codes.clone();
    expected_codes.sort();
    if actual_codes != expected_codes {
        return Err(format!(
            "query_code case `{}` returned diagnostic codes {:?}, expected {:?}",
            case.id, actual_codes, expected_codes
        ));
    }
    Ok(())
}

fn diagnostic_codes(result: &Value) -> Result<Vec<String>, String> {
    let diagnostics = match result.get("diagnostics") {
        Some(value) => value
            .as_array()
            .ok_or_else(|| "query_code diagnostics must be an array".to_string())?,
        None => return Ok(Vec::new()),
    };
    let mut codes = diagnostics
        .iter()
        .map(|diagnostic| {
            diagnostic["code"]
                .as_str()
                .map(str::to_string)
                .ok_or_else(|| "query_code diagnostic is missing string code".to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    codes.sort();
    Ok(codes)
}

fn json_value_contains(actual: &Value, expected: &Value) -> bool {
    match expected {
        Value::Object(expected) => actual.as_object().is_some_and(|actual| {
            expected.iter().all(|(key, expected_value)| {
                actual
                    .get(key)
                    .is_some_and(|actual_value| json_value_contains(actual_value, expected_value))
            })
        }),
        Value::Array(expected) => actual.as_array().is_some_and(|actual| {
            actual.len() == expected.len()
                && actual
                    .iter()
                    .zip(expected)
                    .all(|(actual, expected)| json_value_contains(actual, expected))
        }),
        _ => actual == expected,
    }
}

fn ensure_stable_result(
    case: &QueryCodeBenchmarkCase,
    expected: &Value,
    actual: &Value,
) -> Result<(), String> {
    if actual == expected {
        Ok(())
    } else {
        Err(format!(
            "query_code case `{}` returned a different ordinary result on repeated execution",
            case.id
        ))
    }
}

fn required_u64(value: &Value, pointer: &str) -> Result<u64, String> {
    value
        .pointer(pointer)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("query_code profile is missing unsigned integer `{pointer}`"))
}

fn required_string<'a>(value: &'a Value, pointer: &str) -> Result<&'a str, String> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("query_code profile is missing string `{pointer}`"))
}

fn parse_access_path(value: &Value) -> Result<QueryCodeAccessPathMetrics, String> {
    let selected_terms = value
        .pointer("/selected_terms")
        .and_then(Value::as_array)
        .ok_or_else(|| "query_code profile is missing array `/selected_terms`".to_string())?
        .iter()
        .map(|term| {
            Ok(QueryCodeAccessPathTermMetrics {
                label: required_string(term, "/label")?.to_string(),
                candidate_facts: required_u64(term, "/candidate_facts")?,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(QueryCodeAccessPathMetrics {
        selected: required_string(value, "/selected")?.to_string(),
        representation_version: required_u64(value, "/representation_version")?
            .try_into()
            .map_err(|_| "query_code representation version exceeds u32".to_string())?,
        estimated_provider_files: required_u64(value, "/estimated_provider_files")?,
        scoped_files: required_u64(value, "/scoped_files")?,
        scoped_fact_nodes: required_u64(value, "/scoped_fact_nodes")?,
        admitted_fact_nodes: required_u64(value, "/admitted_fact_nodes")?,
        candidate_files: required_u64(value, "/candidate_files")?,
        candidate_facts: required_u64(value, "/candidate_facts")?,
        selected_terms,
        source_verification_required: value
            .pointer("/source_verification_required")
            .and_then(Value::as_bool)
            .ok_or_else(|| {
                "query_code profile is missing boolean `/source_verification_required`".to_string()
            })?,
        cache_ready_lookups: required_u64(value, "/cache_ready_lookups")?,
        materialized_files: required_u64(value, "/materialized_files")?,
        materialized_fact_nodes: required_u64(value, "/materialized_fact_nodes")?,
        inspected_source_bytes: required_u64(value, "/inspected_source_bytes")?,
        examined_fact_nodes: required_u64(value, "/examined_fact_nodes")?,
        index_lookups: required_u64(value, "/index_lookups")?,
        index_hits: required_u64(value, "/index_hits")?,
        index_misses: required_u64(value, "/index_misses")?,
        index_builds: required_u64(value, "/index_builds")?,
        index_waits: required_u64(value, "/index_waits")?,
        index_wait_ns: required_u64(value, "/index_wait_ns")?,
        index_cancelled: required_u64(value, "/index_cancelled")?,
        index_unavailable: required_u64(value, "/index_unavailable")?,
        index_over_budget: required_u64(value, "/index_over_budget")?,
        scan_fallbacks: required_u64(value, "/scan_fallbacks")?,
        index_build_files: required_u64(value, "/index_build_files")?,
        index_build_source_bytes: required_u64(value, "/index_build_source_bytes")?,
        index_build_fact_nodes: required_u64(value, "/index_build_fact_nodes")?,
        index_build_facts_bytes: required_u64(value, "/index_build_facts_bytes")?,
        index_build_ns: required_u64(value, "/index_build_ns")?,
        retained_bytes: required_u64(value, "/retained_bytes")?,
    })
}

fn aggregate_metrics(
    observations: &[QueryCodeProfileMetrics],
) -> Result<QueryCodeProfileMetrics, String> {
    let first = observations
        .first()
        .ok_or_else(|| "query_code benchmark produced no measured observations".to_string())?;
    if observations.iter().any(|observation| {
        observation.profile_format != first.profile_format
            || observation.result_cardinality != first.result_cardinality
            || observation.truncated != first.truncated
            || observation.diagnostic_codes != first.diagnostic_codes
    }) {
        return Err("query_code profile metadata changed across measured iterations".to_string());
    }

    Ok(QueryCodeProfileMetrics {
        profile_format: first.profile_format.clone(),
        result_cardinality: first.result_cardinality,
        truncated: first.truncated,
        diagnostic_codes: first.diagnostic_codes.clone(),
        total_ns: median_counter(observations, |value| value.total_ns),
        scanned_files: median_counter(observations, |value| value.scanned_files),
        scanned_source_bytes: median_counter(observations, |value| value.scanned_source_bytes),
        fact_nodes: median_counter(observations, |value| value.fact_nodes),
        pipeline_rows: median_counter(observations, |value| value.pipeline_rows),
        examined_references: median_counter(observations, |value| value.examined_references),
        import_files_resolved: median_counter(observations, |value| value.import_files_resolved),
        import_edges_resolved: median_counter(observations, |value| value.import_edges_resolved),
        facts_cache: QueryCodeFactsCacheMetrics {
            lookups: median_counter(observations, |value| value.facts_cache.lookups),
            memory_hits: median_counter(observations, |value| value.facts_cache.memory_hits),
            persisted_hydrations: median_counter(observations, |value| {
                value.facts_cache.persisted_hydrations
            }),
            extractions: median_counter(observations, |value| value.facts_cache.extractions),
            unavailable: median_counter(observations, |value| value.facts_cache.unavailable),
            unknown_outcomes: median_counter(observations, |value| {
                value.facts_cache.unknown_outcomes
            }),
            replayed_files: median_counter(observations, |value| value.facts_cache.replayed_files),
        },
        direct_import_topology: aggregate_derived_layer_metrics(observations),
        access_path: aggregate_access_path_metrics(observations)?,
    })
}

fn aggregate_derived_layer_metrics(
    observations: &[QueryCodeProfileMetrics],
) -> QueryCodeDerivedLayerMetrics {
    let counter = |select: fn(&QueryCodeDerivedLayerMetrics) -> u64| {
        median_u64(
            observations
                .iter()
                .map(|value| select(&value.direct_import_topology))
                .collect(),
        )
    };
    QueryCodeDerivedLayerMetrics {
        lookups: counter(|value| value.lookups),
        hits: counter(|value| value.hits),
        misses: counter(|value| value.misses),
        builds: counter(|value| value.builds),
        waits: counter(|value| value.waits),
        wait_ns: counter(|value| value.wait_ns),
        complete_hits: counter(|value| value.complete_hits),
        incomplete_hits: counter(|value| value.incomplete_hits),
        complete_builds: counter(|value| value.complete_builds),
        incomplete_builds: counter(|value| value.incomplete_builds),
        unknown_outcomes: counter(|value| value.unknown_outcomes),
        cancelled: counter(|value| value.cancelled),
        unavailable: counter(|value| value.unavailable),
        over_budget: counter(|value| value.over_budget),
        fallbacks: counter(|value| value.fallbacks),
        replayed_items: counter(|value| value.replayed_items),
        build_files: counter(|value| value.build_files),
        build_edges: counter(|value| value.build_edges),
        build_ns: counter(|value| value.build_ns),
        retained_bytes: counter(|value| value.retained_bytes),
    }
}

fn aggregate_access_path_metrics(
    observations: &[QueryCodeProfileMetrics],
) -> Result<Option<QueryCodeAccessPathMetrics>, String> {
    let paths = observations
        .iter()
        .map(|observation| observation.access_path.as_ref())
        .collect::<Vec<_>>();
    if paths.iter().all(|path| path.is_none()) {
        return Ok(None);
    }
    let first = paths[0].ok_or_else(|| {
        "query_code access-path metrics appeared only after the first measured iteration"
            .to_string()
    })?;
    if paths.iter().any(|path| {
        path.is_none_or(|path| {
            path.selected != first.selected
                || path.representation_version != first.representation_version
                || path.selected_terms != first.selected_terms
                || path.source_verification_required != first.source_verification_required
        })
    }) {
        return Err(
            "query_code selected access path or representation changed across measured iterations"
                .to_string(),
        );
    }
    let paths = paths.into_iter().flatten().collect::<Vec<_>>();
    Ok(Some(QueryCodeAccessPathMetrics {
        selected: first.selected.clone(),
        representation_version: first.representation_version,
        estimated_provider_files: median_path_counter(&paths, |value| {
            value.estimated_provider_files
        }),
        scoped_files: median_path_counter(&paths, |value| value.scoped_files),
        scoped_fact_nodes: median_path_counter(&paths, |value| value.scoped_fact_nodes),
        admitted_fact_nodes: median_path_counter(&paths, |value| value.admitted_fact_nodes),
        candidate_files: median_path_counter(&paths, |value| value.candidate_files),
        candidate_facts: median_path_counter(&paths, |value| value.candidate_facts),
        selected_terms: first.selected_terms.clone(),
        source_verification_required: first.source_verification_required,
        cache_ready_lookups: median_path_counter(&paths, |value| value.cache_ready_lookups),
        materialized_files: median_path_counter(&paths, |value| value.materialized_files),
        materialized_fact_nodes: median_path_counter(&paths, |value| value.materialized_fact_nodes),
        inspected_source_bytes: median_path_counter(&paths, |value| value.inspected_source_bytes),
        examined_fact_nodes: median_path_counter(&paths, |value| value.examined_fact_nodes),
        index_lookups: median_path_counter(&paths, |value| value.index_lookups),
        index_hits: median_path_counter(&paths, |value| value.index_hits),
        index_misses: median_path_counter(&paths, |value| value.index_misses),
        index_builds: median_path_counter(&paths, |value| value.index_builds),
        index_waits: median_path_counter(&paths, |value| value.index_waits),
        index_wait_ns: median_path_counter(&paths, |value| value.index_wait_ns),
        index_cancelled: median_path_counter(&paths, |value| value.index_cancelled),
        index_unavailable: median_path_counter(&paths, |value| value.index_unavailable),
        index_over_budget: median_path_counter(&paths, |value| value.index_over_budget),
        scan_fallbacks: median_path_counter(&paths, |value| value.scan_fallbacks),
        index_build_files: median_path_counter(&paths, |value| value.index_build_files),
        index_build_source_bytes: median_path_counter(&paths, |value| {
            value.index_build_source_bytes
        }),
        index_build_fact_nodes: median_path_counter(&paths, |value| value.index_build_fact_nodes),
        index_build_facts_bytes: median_path_counter(&paths, |value| value.index_build_facts_bytes),
        index_build_ns: median_path_counter(&paths, |value| value.index_build_ns),
        retained_bytes: median_path_counter(&paths, |value| value.retained_bytes),
    }))
}

fn median_counter(
    observations: &[QueryCodeProfileMetrics],
    select: impl Fn(&QueryCodeProfileMetrics) -> u64,
) -> u64 {
    median_u64(observations.iter().map(select).collect())
}

fn median_path_counter(
    observations: &[&QueryCodeAccessPathMetrics],
    select: impl Fn(&QueryCodeAccessPathMetrics) -> u64,
) -> u64 {
    median_u64(observations.iter().map(|value| select(value)).collect())
}

fn median_u64(mut values: Vec<u64>) -> u64 {
    values.sort_unstable();
    values[values.len() / 2]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::benchmark::QueryCodeWorkload;

    fn benchmark_case() -> QueryCodeBenchmarkCase {
        QueryCodeBenchmarkCase {
            id: "class-app".to_string(),
            workloads: vec![QueryCodeWorkload::ExactName],
            query_json: r#"{"match":{"kind":"class","name":"App"}}"#.to_string(),
            required_paths: Vec::new(),
            expected_witness_json: Some(
                r#"{"result_type":"structural_match","path":"app.py","kind":"class","enclosing_symbol":"module.App"}"#.to_string(),
            ),
            min_results: Some(1),
            max_results: Some(1),
            expected_truncated: false,
            expected_diagnostic_codes: Vec::new(),
        }
    }

    #[test]
    fn profile_parser_validates_witness_and_metrics() {
        let case = benchmark_case();
        let response = profiled_query_response();

        let (result, metrics) = parse_profile(&case, &response).expect("valid profiled response");

        assert_eq!(result["results"][0]["name"], "App");
        assert_eq!(metrics.result_cardinality, 1);
        assert_eq!(metrics.total_ns, 11);
        assert_eq!(metrics.scanned_files, 2);
        assert_eq!(metrics.facts_cache.extractions, 2);
        assert_eq!(metrics.direct_import_topology.lookups, 1);
        assert_eq!(metrics.direct_import_topology.hits, 1);
        assert_eq!(metrics.direct_import_topology.replayed_items, 2);
        assert_eq!(metrics.direct_import_topology.retained_bytes, 512);
        assert_eq!(
            metrics
                .access_path
                .as_ref()
                .map(|path| path.selected.as_str()),
            Some("posting:kind+name")
        );
    }

    #[test]
    fn profile_parser_rejects_same_kind_candidate_with_wrong_identity() {
        let mut response = profiled_query_response();
        response["structuredContent"]["result"]["results"][0]["enclosing_symbol"] =
            json!("module.Decoy");

        let error = parse_profile(&benchmark_case(), &response)
            .expect_err("same-path same-kind decoy must not satisfy witness");

        assert!(error.contains("no result matching witness"), "{error}");
    }

    #[test]
    fn profile_parser_rejects_unimplemented_future_format() {
        let mut response = profiled_query_response();
        response["structuredContent"]["format"] = json!("bifrost_code_query_profile/v3");

        let error = parse_profile(&benchmark_case(), &response)
            .expect_err("future format must require an explicit parser update");

        assert!(error.contains("unsupported profile format"), "{error}");
    }

    #[test]
    fn failed_case_exposes_no_partial_timings() {
        let report = failure_report(
            &benchmark_case(),
            vec![PathBuf::from("first.log")],
            "later oracle failure".to_string(),
        );

        assert!(!report.success);
        assert_eq!(report.first_duration_ms, None);
        assert!(report.warmup_durations_ms.is_empty());
        assert!(report.measured_durations_ms.is_empty());
        assert_eq!(report.median_ms, None);
        assert_eq!(report.p95_ms, None);
        assert_eq!(report.mean_ms, None);
    }

    fn profiled_query_response() -> Value {
        json!({
            "structuredContent": {
                "format": "bifrost_code_query_profile/v2",
                "result": {
                    "results": [{
                        "result_type": "structural_match",
                        "path": "app.py",
                        "language": "python",
                        "kind": "class",
                        "name": "App",
                        "enclosing_symbol": "module.App"
                    }],
                    "truncated": false
                },
                "timings_ns": {
                    "planning": 1,
                    "execution": 8,
                    "rendering": 2,
                    "total": 11
                },
                "work": {
                    "scanned_files": 2,
                    "scanned_source_bytes": 80,
                    "fact_nodes": 4,
                    "pipeline_rows": 1,
                    "examined_references": 0,
                    "provenance_steps": 0,
                    "import_files_resolved": 0,
                    "import_edges_resolved": 0
                },
                "cache_layers": [
                    {
                        "layer": "seed_structural_facts",
                        "metrics": {
                            "kind": "structural_facts",
                            "lookups": 2,
                            "memory_hits": 0,
                            "persisted_hydrations": 0,
                            "extractions": 2,
                            "unavailable": 0,
                            "unknown_outcomes": 0,
                            "replayed_files": 2
                        }
                    },
                    {
                        "layer": "direct_import_topology",
                        "metrics": {
                            "kind": "complete_value",
                            "lookups": 1,
                            "hits": 1,
                            "complete_hits": 1,
                            "replayed_items": 2,
                            "retained_bytes": 512
                        }
                    }
                ],
                "access_path": {
                    "selected": "posting:kind+name",
                    "representation_version": 1,
                    "estimated_provider_files": 2,
                    "scoped_files": 2,
                    "scoped_fact_nodes": 4,
                    "admitted_fact_nodes": 4,
                    "candidate_files": 1,
                    "candidate_facts": 1,
                    "selected_terms": [
                        {"label": "name", "candidate_facts": 1},
                        {"label": "kind", "candidate_facts": 2}
                    ],
                    "source_verification_required": true,
                    "cache_ready_lookups": 1,
                    "materialized_files": 1,
                    "materialized_fact_nodes": 2,
                    "inspected_source_bytes": 40,
                    "examined_fact_nodes": 1,
                    "index_lookups": 1,
                    "index_hits": 1,
                    "index_misses": 0,
                    "index_builds": 0,
                    "index_waits": 0,
                    "index_wait_ns": 0,
                    "index_cancelled": 0,
                    "index_unavailable": 0,
                    "index_over_budget": 0,
                    "scan_fallbacks": 0,
                    "index_build_files": 0,
                    "index_build_source_bytes": 0,
                    "index_build_fact_nodes": 0,
                    "index_build_facts_bytes": 0,
                    "index_build_ns": 0,
                    "retained_bytes": 512
                }
            }
        })
    }
}
