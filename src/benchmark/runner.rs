use crate::benchmark::mcp_iteration::{
    IterationId, run_profiled_iteration, start_initialized_session, transport_phase_report,
};
use crate::benchmark::mcp_session::McpSession;
use crate::benchmark::query_code;
use crate::benchmark::repo_cache::prepare_repo;
use crate::benchmark::report::{
    BenchmarkRepoReport, BenchmarkRunReport, McpFairnessTimingReport, ScenarioReport,
    ScenarioTransport,
};
use crate::benchmark::subset_workspace::prepare_subset_workspace;
use crate::benchmark::{
    BenchmarkLocationSelector, BenchmarkManifest, BenchmarkRepoTarget, BenchmarkScenario,
    CodeQualityProbe, HierarchyQueryTarget, InteractiveQueryBenchmarkCase,
    McpFairnessBenchmarkCase,
};
use crate::lsp::benchmark_api::{call_hierarchy, type_hierarchy};
use crate::lsp::conversion::path_to_uri_string;
use crate::{AnalyzerConfig, FilesystemProject, Project, WorkspaceAnalyzer};
use chrono::Utc;
use lsp_types::{
    CallHierarchyIncomingCallsParams, CallHierarchyOutgoingCallsParams, CallHierarchyPrepareParams,
    PartialResultParams, Position, TextDocumentIdentifier, TextDocumentPositionParams,
    TypeHierarchyPrepareParams, TypeHierarchySubtypesParams, TypeHierarchySupertypesParams, Uri,
    WorkDoneProgressParams,
};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct RunRequest {
    pub manifest_path: PathBuf,
    pub repo_cache_dir: PathBuf,
    pub selected_repo: Option<String>,
    /// When set, each selected repo runs only this scenario (repos that do not
    /// enable it are skipped). Intended for probe authoring and operator
    /// spot-checks; baseline-quality reports come from unfiltered runs.
    pub selected_scenario: Option<BenchmarkScenario>,
    pub max_files: Option<usize>,
    pub profile: Option<BenchmarkProfile>,
}

#[derive(Debug, Clone)]
pub struct BenchmarkProfile {
    pub output_dir: PathBuf,
    pub report_path_prefix: PathBuf,
}

pub fn run_benchmark(
    manifest: &BenchmarkManifest,
    request: &RunRequest,
) -> Result<BenchmarkRunReport, String> {
    let selected_repo = request.selected_repo.as_deref();
    let selected_targets: Vec<_> = manifest
        .repos
        .iter()
        .filter(|repo| selected_repo.is_none_or(|name| repo.name == name))
        .filter(|repo| {
            request
                .selected_scenario
                .is_none_or(|scenario| repo.scenario_set().contains(&scenario))
        })
        .collect();

    if selected_targets.is_empty() {
        return Err(match (selected_repo, request.selected_scenario) {
            (Some(name), Some(scenario)) => format!(
                "repo `{name}` does not enable scenario `{}` (or does not exist)",
                scenario.label()
            ),
            (Some(name), None) => format!("manifest contains no repo named `{name}`"),
            (None, Some(scenario)) => {
                format!("no manifest repo enables scenario `{}`", scenario.label())
            }
            (None, None) => "manifest contains no repos to run".to_string(),
        });
    }

    let current_identity = current_bifrost_commit();
    if current_identity.as_deref() != Some(crate::BIFROST_BUILD_IDENTITY) {
        return Err(format!(
            "benchmark harness build identity `{}` does not match current checkout `{}`; rebuild both bifrost and bifrost_benchmark",
            crate::BIFROST_BUILD_IDENTITY,
            current_identity.as_deref().unwrap_or("unknown")
        ));
    }
    let bifrost_commit = Some(crate::BIFROST_BUILD_IDENTITY.to_string());
    let mut repos = Vec::with_capacity(selected_targets.len());
    for target in selected_targets {
        repos.push(run_repo(target, manifest, request)?);
    }

    Ok(BenchmarkRunReport {
        generated_at: Utc::now().to_rfc3339(),
        manifest_path: request.manifest_path.display().to_string(),
        bifrost_commit,
        selected_repo: request.selected_repo.clone(),
        max_files: request.max_files,
        repos,
    })
}

fn run_repo(
    target: &BenchmarkRepoTarget,
    manifest: &BenchmarkManifest,
    request: &RunRequest,
) -> Result<BenchmarkRepoReport, String> {
    let scenario_filtered;
    let target = match request.selected_scenario {
        Some(scenario) => {
            scenario_filtered = BenchmarkRepoTarget {
                scenarios: vec![scenario],
                ..target.clone()
            };
            &scenario_filtered
        }
        None => target,
    };
    let checkout_path = prepare_repo(target, &request.repo_cache_dir)?;
    let workspace_path = match request.max_files {
        Some(max_files) => {
            prepare_subset_workspace(&checkout_path, &request.repo_cache_dir, target, max_files)?
        }
        None => checkout_path.clone(),
    };
    let mut scenario_reports = Vec::with_capacity(target.scenarios.len());

    if target
        .scenario_set()
        .contains(&BenchmarkScenario::WorkspaceBuild)
    {
        scenario_reports.push(run_workspace_build(target, manifest, &workspace_path));
    }

    let mcp_scenarios: Vec<_> = target
        .scenarios
        .iter()
        .copied()
        .filter(|scenario| {
            !matches!(
                scenario,
                BenchmarkScenario::WorkspaceBuild
                    | BenchmarkScenario::CallHierarchy
                    | BenchmarkScenario::TypeHierarchy
                    | BenchmarkScenario::QueryCode
                    | BenchmarkScenario::InteractiveCodeIntelligence
                    | BenchmarkScenario::McpFairness
            )
        })
        .collect();
    let (reference_scan_scenarios, location_mode_scenarios): (Vec<_>, Vec<_>) =
        mcp_scenarios.into_iter().partition(|scenario| {
            *scenario == BenchmarkScenario::ScanUsages && target.usage_targets.is_empty()
        });
    scenario_reports.extend(run_mcp_scenarios(
        target,
        manifest,
        &workspace_path,
        location_mode_scenarios,
        false,
        request.profile.as_ref(),
    ));

    if target
        .scenario_set()
        .contains(&BenchmarkScenario::InteractiveCodeIntelligence)
    {
        scenario_reports.extend(run_interactive_query_scenarios(
            target,
            manifest,
            &workspace_path,
            request.profile.as_ref(),
        ));
    }

    if target
        .scenario_set()
        .contains(&BenchmarkScenario::McpFairness)
    {
        scenario_reports.push(run_mcp_fairness_scenario(
            target,
            manifest,
            &workspace_path,
            request.profile.as_ref(),
        ));
    }

    if target
        .scenario_set()
        .contains(&BenchmarkScenario::QueryCode)
    {
        if request.max_files.is_some() {
            scenario_reports.extend(target.query_code_queries.iter().map(|case| {
                ScenarioReport::from_timings(
                    BenchmarkScenario::QueryCode,
                    ScenarioTransport::Mcp,
                    true,
                    Vec::new(),
                    Vec::new(),
                    None,
                )
                .with_case_id(case.id.clone())
                .as_skipped(
                    "query_code full-workspace oracle skipped for --max-files subset run"
                        .to_string(),
                )
            }));
        } else {
            scenario_reports.extend(query_code::run_scenarios(
                target,
                manifest,
                &workspace_path,
                request.profile.as_ref(),
            ));
        }
    }
    scenario_reports.extend(run_mcp_scenarios(
        target,
        manifest,
        &workspace_path,
        reference_scan_scenarios,
        true,
        request.profile.as_ref(),
    ));

    if target
        .scenario_set()
        .contains(&BenchmarkScenario::CallHierarchy)
    {
        scenario_reports.push(run_hierarchy_scenario(
            target,
            manifest,
            &workspace_path,
            BenchmarkScenario::CallHierarchy,
        ));
    }

    if target
        .scenario_set()
        .contains(&BenchmarkScenario::TypeHierarchy)
    {
        scenario_reports.push(run_hierarchy_scenario(
            target,
            manifest,
            &workspace_path,
            BenchmarkScenario::TypeHierarchy,
        ));
    }

    scenario_reports.sort_by_key(|report| {
        let scenario_index = target
            .scenarios
            .iter()
            .position(|scenario| *scenario == report.name)
            .unwrap_or(usize::MAX);
        let case_index = report.case_id.as_ref().map_or(0, |case_id| {
            target
                .query_code_queries
                .iter()
                .position(|case| case.id == *case_id)
                .or_else(|| {
                    target
                        .interactive_queries
                        .iter()
                        .position(|case| case.id == *case_id)
                })
                .unwrap_or(usize::MAX)
        });
        (scenario_index, case_index)
    });

    Ok(BenchmarkRepoReport {
        name: target.name.clone(),
        url: target.url.clone(),
        commit: target.commit.clone(),
        checkout_path,
        workspace_path,
        subset_max_files: request.max_files,
        scenarios: scenario_reports,
    })
}

fn run_mcp_scenarios(
    target: &BenchmarkRepoTarget,
    manifest: &BenchmarkManifest,
    workspace_path: &Path,
    scenarios: Vec<BenchmarkScenario>,
    no_line_numbers: bool,
    profile: Option<&BenchmarkProfile>,
) -> Vec<ScenarioReport> {
    if scenarios.is_empty() {
        return Vec::new();
    }

    let session = start_initialized_session(workspace_path, no_line_numbers, profile.is_some());
    match session {
        Ok(mut session) => scenarios
            .into_iter()
            .map(|scenario| run_mcp_scenario(target, manifest, &mut session, scenario, profile))
            .collect(),
        Err(err) => scenarios
            .into_iter()
            .map(|scenario| {
                ScenarioReport::from_timings(
                    scenario,
                    ScenarioTransport::Mcp,
                    false,
                    Vec::new(),
                    Vec::new(),
                    Some(format!(
                        "failed to start MCP session for `{}`: {err}",
                        target.name
                    )),
                )
            })
            .collect(),
    }
}

fn run_interactive_query_scenarios(
    target: &BenchmarkRepoTarget,
    manifest: &BenchmarkManifest,
    workspace_path: &Path,
    profile: Option<&BenchmarkProfile>,
) -> Vec<ScenarioReport> {
    let session = start_initialized_session(workspace_path, false, profile.is_some());
    match session {
        Ok(mut session) => match prewarm_interactive_session(&mut session) {
            Ok(()) => target
                .interactive_queries
                .iter()
                .map(|case| {
                    run_interactive_query_case(target, manifest, &mut session, case, profile)
                })
                .collect(),
            Err(error) => target
                .interactive_queries
                .iter()
                .map(|case| {
                    ScenarioReport::from_timings(
                        BenchmarkScenario::InteractiveCodeIntelligence,
                        ScenarioTransport::Mcp,
                        false,
                        Vec::new(),
                        Vec::new(),
                        Some(format!(
                            "failed to prewarm interactive MCP session for `{}`: {error}",
                            target.name
                        )),
                    )
                    .with_case_id(case.id.clone())
                    .with_latency_budget(case.max_p95_ms)
                })
                .collect(),
        },
        Err(error) => target
            .interactive_queries
            .iter()
            .map(|case| {
                ScenarioReport::from_timings(
                    BenchmarkScenario::InteractiveCodeIntelligence,
                    ScenarioTransport::Mcp,
                    false,
                    Vec::new(),
                    Vec::new(),
                    Some(format!(
                        "failed to start interactive MCP session for `{}`: {error}",
                        target.name
                    )),
                )
                .with_case_id(case.id.clone())
                .with_latency_budget(case.max_p95_ms)
            })
            .collect(),
    }
}

fn prewarm_interactive_session(session: &mut McpSession) -> Result<(), String> {
    // Search is deliberately a guaranteed-miss: it forces the lazy workspace
    // snapshot to materialize without making a scenario-specific assertion or
    // contributing a timing sample. The next request is therefore genuinely
    // warm while retaining the same MCP process and caches.
    //
    // Each attempt is bounded by the server's request-wide budget (#1199): while
    // the deferred initial build is still running the server answers with an
    // explicit not-ready error, so keep polling until the snapshot is installed.
    loop {
        let result = session.call_tool(
            "search_symbols",
            json!({
                "patterns": ["__bifrost_benchmark_prewarm__"],
                "limit": 1,
            }),
        );
        match result {
            Ok(_) => return Ok(()),
            Err(error)
                if error.contains(
                    brokk_bifrost_mcp::benchmark_api::WORKSPACE_SNAPSHOT_NOT_READY_MESSAGE,
                ) => {}
            Err(error) => return Err(error),
        }
    }
}

fn run_interactive_query_case(
    target: &BenchmarkRepoTarget,
    manifest: &BenchmarkManifest,
    session: &mut McpSession,
    case: &InteractiveQueryBenchmarkCase,
    profile: Option<&BenchmarkProfile>,
) -> ScenarioReport {
    let arguments = match parse_arguments(&case.arguments_json, &case.id) {
        Ok(arguments) => arguments,
        Err(error) => {
            return ScenarioReport::from_timings(
                BenchmarkScenario::InteractiveCodeIntelligence,
                ScenarioTransport::Mcp,
                false,
                Vec::new(),
                Vec::new(),
                Some(error),
            )
            .with_case_id(case.id.clone())
            .with_latency_budget(case.max_p95_ms);
        }
    };
    let mut warmup_durations_ms = Vec::with_capacity(manifest.warmup_iterations);
    let mut measured_durations_ms = Vec::with_capacity(manifest.measured_iterations);
    let mut bounded_incomplete_iterations = 0;
    let mut profile_artifacts = Vec::new();

    for iteration in 0..manifest.warmup_iterations {
        let (outcome, artifact) = run_interactive_query_iteration(
            target,
            session,
            case,
            &arguments,
            profile,
            "warmup",
            iteration + 1,
        );
        profile_artifacts.extend(artifact);
        match outcome {
            Ok(iteration) => warmup_durations_ms.push(iteration.duration_ms),
            Err(error) => {
                return interactive_case_report(
                    case,
                    false,
                    warmup_durations_ms,
                    measured_durations_ms,
                    bounded_incomplete_iterations,
                    Some(error),
                    profile_artifacts,
                    profile,
                );
            }
        }
    }

    for iteration in 0..manifest.measured_iterations {
        let (outcome, artifact) = run_interactive_query_iteration(
            target,
            session,
            case,
            &arguments,
            profile,
            "measured",
            iteration + 1,
        );
        profile_artifacts.extend(artifact);
        match outcome {
            Ok(iteration) => {
                measured_durations_ms.push(iteration.duration_ms);
                bounded_incomplete_iterations +=
                    usize::from(iteration.completion == InteractiveCompletion::BoundedIncomplete);
            }
            Err(error) => {
                return interactive_case_report(
                    case,
                    false,
                    warmup_durations_ms,
                    measured_durations_ms,
                    bounded_incomplete_iterations,
                    Some(error),
                    profile_artifacts,
                    profile,
                );
            }
        }
    }

    interactive_case_report(
        case,
        true,
        warmup_durations_ms,
        measured_durations_ms,
        bounded_incomplete_iterations,
        None,
        profile_artifacts,
        profile,
    )
}

#[allow(clippy::too_many_arguments)]
fn interactive_case_report(
    case: &InteractiveQueryBenchmarkCase,
    mut success: bool,
    warmup_durations_ms: Vec<f64>,
    measured_durations_ms: Vec<f64>,
    bounded_incomplete_iterations: usize,
    mut failure_message: Option<String>,
    profile_artifacts: Vec<PathBuf>,
    profile: Option<&BenchmarkProfile>,
) -> ScenarioReport {
    let phases = match transport_phase_report(profile, &profile_artifacts) {
        Ok(phases) => phases,
        Err(error) => {
            success = false;
            failure_message = Some(match failure_message {
                Some(primary) => format!("{primary}; profile diagnostics failed: {error}"),
                None => error,
            });
            Vec::new()
        }
    };
    let mut report = ScenarioReport::from_timings(
        BenchmarkScenario::InteractiveCodeIntelligence,
        ScenarioTransport::Mcp,
        success,
        warmup_durations_ms,
        measured_durations_ms,
        failure_message,
    )
    .with_case_id(case.id.clone())
    .with_latency_budget(case.max_p95_ms)
    .with_transport_phases(phases);
    report.bounded_incomplete_iterations = bounded_incomplete_iterations;
    report.profile_artifacts = profile_artifacts;
    report
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InteractiveCompletion {
    Complete,
    BoundedIncomplete,
}

#[derive(Debug, Clone, Copy)]
struct InteractiveIteration {
    duration_ms: f64,
    completion: InteractiveCompletion,
}

#[allow(clippy::too_many_arguments)]
fn run_interactive_query_iteration(
    target: &BenchmarkRepoTarget,
    session: &mut McpSession,
    case: &InteractiveQueryBenchmarkCase,
    arguments: &Value,
    profile: Option<&BenchmarkProfile>,
    phase: &str,
    iteration: usize,
) -> (Result<InteractiveIteration, String>, Option<PathBuf>) {
    let (outcome, artifact) = run_profiled_iteration(
        session,
        profile,
        IterationId {
            target,
            scenario: BenchmarkScenario::InteractiveCodeIntelligence,
            case_id: Some(&case.id),
            phase,
            iteration,
        },
        |session| {
            session
                .call_tool(case.tool.tool_name(), arguments.clone())
                .and_then(|result| assert_interactive_result(case, &result))
        },
    );
    (
        outcome.map(|timed| InteractiveIteration {
            duration_ms: timed.duration_ms,
            completion: timed.value,
        }),
        artifact,
    )
}

fn assert_interactive_result(
    case: &InteractiveQueryBenchmarkCase,
    result: &Value,
) -> Result<InteractiveCompletion, String> {
    if case.allow_bounded_incomplete
        && result.pointer("/structuredContent/summary/partial") == Some(&Value::Bool(true))
    {
        let arguments = parse_arguments(&case.arguments_json, &case.id)?;
        let expected_targets = arguments["targets"]
            .as_array()
            .ok_or_else(|| format!("interactive scan case `{}` omitted target inputs", case.id))?;
        assert_scan_results_are_complete_or_bounded(
            &case.id,
            result,
            true,
            Some(expected_targets),
        )?;
        if let Some(observed) = result.pointer(&case.expected_json_pointer) {
            assert_expected_benchmark_value(case, observed)?;
        }
        return Ok(InteractiveCompletion::BoundedIncomplete);
    }
    let observed = result.pointer(&case.expected_json_pointer).ok_or_else(|| {
        format!(
            "interactive case `{}` result omitted JSON pointer `{}`; {}",
            case.id,
            case.expected_json_pointer,
            redacted_result_shape(result)
        )
    })?;
    assert_expected_benchmark_value(case, observed)?;
    Ok(InteractiveCompletion::Complete)
}

fn assert_expected_benchmark_value(
    case: &InteractiveQueryBenchmarkCase,
    observed: &Value,
) -> Result<(), String> {
    if let Some(expected) = &case.expected_json_value {
        if observed != expected {
            return Err(format!(
                "interactive case `{}` expected `{}` at `{}` but got {}",
                case.id,
                expected,
                case.expected_json_pointer,
                json_value_shape(observed)
            ));
        }
    } else if !is_meaningful_benchmark_value(observed) {
        return Err(format!(
            "interactive case `{}` returned an empty value at `{}`",
            case.id, case.expected_json_pointer
        ));
    }
    Ok(())
}

fn is_meaningful_benchmark_value(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(_) | Value::Number(_) => true,
        Value::String(value) => !value.trim().is_empty(),
        Value::Array(values) => !values.is_empty(),
        Value::Object(values) => !values.is_empty(),
    }
}

fn redacted_result_shape(result: &Value) -> String {
    fn sorted_keys(value: &Value) -> Vec<&str> {
        let mut keys = value
            .as_object()
            .into_iter()
            .flat_map(|object| object.keys().map(String::as_str))
            .collect::<Vec<_>>();
        keys.sort_unstable();
        keys
    }

    format!(
        "result shape={} top-level keys={:?} structuredContent keys={:?}",
        json_value_shape(result),
        sorted_keys(result),
        sorted_keys(&result["structuredContent"])
    )
}

fn json_value_shape(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(_) => "boolean".to_string(),
        Value::Number(_) => "number".to_string(),
        Value::String(value) => format!("string({} bytes)", value.len()),
        Value::Array(values) => format!("array({} items)", values.len()),
        Value::Object(values) => format!("object({} keys)", values.len()),
    }
}

fn run_mcp_fairness_scenario(
    target: &BenchmarkRepoTarget,
    manifest: &BenchmarkManifest,
    workspace_path: &Path,
    profile: Option<&BenchmarkProfile>,
) -> ScenarioReport {
    let case = target
        .mcp_fairness
        .as_ref()
        .expect("validated mcp_fairness scenario has a case");
    let scan_arguments = match parse_arguments(&case.scan_arguments_json, &case.id) {
        Ok(arguments) => arguments,
        Err(error) => {
            return fairness_report(
                case,
                false,
                Vec::new(),
                Vec::new(),
                McpFairnessSamples::default(),
                Some(error),
                Vec::new(),
                profile,
            );
        }
    };
    let source_arguments = match parse_arguments(&case.source_arguments_json, &case.id) {
        Ok(arguments) => arguments,
        Err(error) => {
            return fairness_report(
                case,
                false,
                Vec::new(),
                Vec::new(),
                McpFairnessSamples::default(),
                Some(error),
                Vec::new(),
                profile,
            );
        }
    };
    // Timing stays enabled even without profile artifacts because the backend
    // marker below is the synchronization proof that the heavy scan is active.
    let mut session = match start_initialized_session(workspace_path, false, true) {
        Ok(session) => session,
        Err(error) => {
            return fairness_report(
                case,
                false,
                Vec::new(),
                Vec::new(),
                McpFairnessSamples::default(),
                Some(format!(
                    "failed to start fairness MCP session for `{}`: {error}",
                    target.name
                )),
                Vec::new(),
                profile,
            );
        }
    };
    let mut warmup_durations_ms = Vec::with_capacity(manifest.warmup_iterations);
    let mut measured_durations_ms = Vec::with_capacity(manifest.measured_iterations);
    let mut measured_samples = McpFairnessSamples::default();
    let mut profile_artifacts = Vec::new();

    for iteration in 0..manifest.warmup_iterations {
        let (outcome, artifact) = run_mcp_fairness_iteration(
            target,
            &mut session,
            case,
            &scan_arguments,
            &source_arguments,
            profile,
            "warmup",
            iteration + 1,
        );
        profile_artifacts.extend(artifact);
        match outcome {
            Ok(iteration) => warmup_durations_ms.push(iteration.budget_duration_ms()),
            Err(error) => {
                return fairness_report(
                    case,
                    false,
                    warmup_durations_ms,
                    measured_durations_ms,
                    measured_samples,
                    Some(error),
                    profile_artifacts,
                    profile,
                );
            }
        }
    }

    for iteration in 0..manifest.measured_iterations {
        let (outcome, artifact) = run_mcp_fairness_iteration(
            target,
            &mut session,
            case,
            &scan_arguments,
            &source_arguments,
            profile,
            "measured",
            iteration + 1,
        );
        profile_artifacts.extend(artifact);
        match outcome {
            Ok(iteration) => {
                measured_durations_ms.push(iteration.budget_duration_ms());
                measured_samples
                    .light_request_durations_ms
                    .push(iteration.light_request_ms);
                measured_samples
                    .cancellation_durations_ms
                    .push(iteration.cancellation_ms);
            }
            Err(error) => {
                return fairness_report(
                    case,
                    false,
                    warmup_durations_ms,
                    measured_durations_ms,
                    measured_samples,
                    Some(error),
                    profile_artifacts,
                    profile,
                );
            }
        }
    }

    fairness_report(
        case,
        true,
        warmup_durations_ms,
        measured_durations_ms,
        measured_samples,
        None,
        profile_artifacts,
        profile,
    )
}

#[allow(clippy::too_many_arguments)]
fn fairness_report(
    case: &McpFairnessBenchmarkCase,
    mut success: bool,
    warmup_durations_ms: Vec<f64>,
    measured_durations_ms: Vec<f64>,
    measured_samples: McpFairnessSamples,
    mut failure_message: Option<String>,
    profile_artifacts: Vec<PathBuf>,
    profile: Option<&BenchmarkProfile>,
) -> ScenarioReport {
    let phases = match transport_phase_report(profile, &profile_artifacts) {
        Ok(phases) => phases,
        Err(error) => {
            success = false;
            failure_message = Some(match failure_message {
                Some(primary) => format!("{primary}; profile diagnostics failed: {error}"),
                None => error,
            });
            Vec::new()
        }
    };
    let mut report = ScenarioReport::from_timings(
        BenchmarkScenario::McpFairness,
        ScenarioTransport::Mcp,
        success,
        warmup_durations_ms,
        measured_durations_ms,
        failure_message,
    )
    .with_case_id(case.id.clone())
    .with_latency_budget(case.max_p95_ms)
    .with_transport_phases(phases);
    if !measured_samples.light_request_durations_ms.is_empty()
        || !measured_samples.cancellation_durations_ms.is_empty()
    {
        report.mcp_fairness = Some(McpFairnessTimingReport::from_timings(
            measured_samples.light_request_durations_ms,
            measured_samples.cancellation_durations_ms,
        ));
    }
    report.profile_artifacts = profile_artifacts;
    report
}

#[derive(Debug, Default)]
struct McpFairnessSamples {
    light_request_durations_ms: Vec<f64>,
    cancellation_durations_ms: Vec<f64>,
}

#[derive(Debug, Clone, Copy)]
struct McpFairnessIteration {
    light_request_ms: f64,
    cancellation_ms: f64,
}

impl McpFairnessIteration {
    fn budget_duration_ms(self) -> f64 {
        self.light_request_ms.max(self.cancellation_ms)
    }
}

#[allow(clippy::too_many_arguments)]
fn run_mcp_fairness_iteration(
    target: &BenchmarkRepoTarget,
    session: &mut McpSession,
    case: &McpFairnessBenchmarkCase,
    scan_arguments: &Value,
    source_arguments: &Value,
    profile: Option<&BenchmarkProfile>,
    phase: &str,
    iteration: usize,
) -> (Result<McpFairnessIteration, String>, Option<PathBuf>) {
    let (outcome, artifact) = run_profiled_iteration(
        session,
        profile,
        IterationId {
            target,
            scenario: BenchmarkScenario::McpFairness,
            case_id: Some(&case.id),
            phase,
            iteration,
        },
        |session| {
            let response_timeout = Duration::from_secs_f64(case.max_p95_ms / 1_000.0);
            let scan_start_cursor = session.stderr_cursor();
            let scan_id =
                session.send_tool_call("scan_usages_by_location", scan_arguments.clone())?;
            session.wait_for_stderr_marker(
                scan_start_cursor,
                "BEGIN searchtools.scan_usages_backend",
                response_timeout,
            )?;
            let source_start = Instant::now();
            let source_id =
                session.send_tool_call("get_symbol_sources", source_arguments.clone())?;
            let source_result =
                session.receive_tool_response_with_timeout(source_id, response_timeout)?;
            let source_duration_ms = elapsed_ms(source_start);
            assert_fairness_source_result(case, &source_result)?;

            // Cancelling is measured by how quickly the server serves the next
            // request, not by waiting for the cancelled one to answer. MCP says
            // a receiver SHOULD NOT respond to a request it was told to cancel,
            // and the SDK-backed host obeys that -- the previous hand-written
            // host replied with the analyzer's incomplete result, which was
            // convenient to measure and not conformant. What the product
            // actually promises is that cancelling a heavy scan leaves the
            // session responsive, and that is what this now times.
            let cancellation_start = Instant::now();
            session.cancel_and_abandon_request(scan_id)?;
            let followup_id =
                session.send_tool_call("get_symbol_sources", source_arguments.clone())?;
            let followup_result =
                session.receive_tool_response_with_timeout(followup_id, response_timeout)?;
            let cancellation_duration_ms = elapsed_ms(cancellation_start);
            assert_fairness_source_result(case, &followup_result)?;

            // Cancellation is cooperative. Keep its unwind outside the measured
            // latency, but do not let successive samples compound unfinished
            // scans until the legacy host's bounded admission registry rejects
            // an otherwise lightweight lookup. rmcp suppresses the cancelled
            // response, so the timing marker is the shared completion signal.
            session
                .wait_for_stderr_marker(
                    scan_start_cursor,
                    "END mcp_request.execution[scan_usages_by_location]",
                    response_timeout,
                )
                .map_err(|error| {
                    format!(
                        "fairness case `{}` cancelled scan did not finish teardown: {error}",
                        case.id
                    )
                })?;
            Ok(McpFairnessIteration {
                light_request_ms: source_duration_ms,
                cancellation_ms: cancellation_duration_ms,
            })
        },
    );
    (outcome.map(|timed| timed.value), artifact)
}

fn assert_fairness_source_result(
    case: &McpFairnessBenchmarkCase,
    result: &Value,
) -> Result<(), String> {
    let sources = result
        .pointer("/structuredContent/sources")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            format!(
                "fairness case `{}` source lookup omitted sources; {}",
                case.id,
                redacted_result_shape(result)
            )
        })?;
    let valid_source = sources.iter().any(|source| {
        source["path"].as_str() == Some(case.expected_source_path.as_str())
            && source["text"]
                .as_str()
                .is_some_and(|text| !text.trim().is_empty())
    });
    if !valid_source {
        return Err(format!(
            "fairness case `{}` did not return a non-empty source block for `{}`; {}",
            case.id,
            case.expected_source_path,
            redacted_result_shape(result)
        ));
    }
    Ok(())
}

fn assert_scan_results_are_complete_or_bounded(
    case_id: &str,
    result: &Value,
    require_incomplete: bool,
    expected_targets: Option<&[Value]>,
) -> Result<(), String> {
    let structured = result
        .get("structuredContent")
        .ok_or_else(|| format!("case `{case_id}` scan omitted structuredContent"))?;
    let results = structured["results"].as_array().ok_or_else(|| {
        format!(
            "case `{case_id}` scan omitted results; {}",
            redacted_result_shape(result)
        )
    })?;
    if let Some(expected_targets) = expected_targets {
        let requested = structured["summary"]["requested"].as_u64();
        if requested != Some(expected_targets.len() as u64)
            || results.len() != expected_targets.len()
            || results
                .iter()
                .zip(expected_targets)
                .any(|(result, expected)| result.get("input") != Some(expected))
        {
            return Err(format!(
                "case `{case_id}` scan did not preserve requested target count, identity, and order"
            ));
        }
    }
    let mut saw_incomplete = false;
    let honest_completion = !results.is_empty()
        && results.iter().all(|entry| {
            let incomplete_reason = entry["incomplete_reason"].as_str();
            let complete = entry.get("complete").and_then(Value::as_bool);
            if matches!(complete, None | Some(true)) && incomplete_reason.is_none() {
                return true;
            }
            let explicitly_bounded = complete == Some(false)
                && entry["status"].as_str() != Some("verified_absent")
                && matches!(
                    incomplete_reason,
                    Some(
                        "cancelled"
                            | "time_budget"
                            | "candidate_files"
                            | "source_bytes"
                            | "callsites"
                            | "response_budget"
                    )
                );
            let has_recovery = entry["message"]
                .as_str()
                .is_some_and(|message| !message.trim().is_empty())
                || entry["notes"].as_array().is_some_and(|notes| {
                    notes
                        .iter()
                        .any(|note| note.as_str().is_some_and(|note| !note.trim().is_empty()))
                });
            let explicitly_bounded = explicitly_bounded && has_recovery;
            saw_incomplete |= explicitly_bounded;
            explicitly_bounded
        });
    if !honest_completion || require_incomplete && !saw_incomplete {
        return Err(format!(
            "case `{case_id}` scan did not report complete or explicitly bounded results; {}",
            redacted_result_shape(result)
        ));
    }
    Ok(())
}

fn parse_arguments(arguments_json: &str, case_id: &str) -> Result<Value, String> {
    let arguments: Value = serde_json::from_str(arguments_json)
        .map_err(|error| format!("benchmark case `{case_id}` arguments are invalid: {error}"))?;
    if !arguments.is_object() {
        return Err(format!(
            "benchmark case `{case_id}` arguments must decode to an object"
        ));
    }
    Ok(arguments)
}

fn run_hierarchy_scenario(
    target: &BenchmarkRepoTarget,
    manifest: &BenchmarkManifest,
    checkout_path: &Path,
    scenario: BenchmarkScenario,
) -> ScenarioReport {
    let mut warmup_durations_ms = Vec::with_capacity(manifest.warmup_iterations);
    let mut measured_durations_ms = Vec::with_capacity(manifest.measured_iterations);

    for _ in 0..manifest.warmup_iterations {
        match measure_hierarchy_scenario(target, checkout_path, scenario) {
            Ok(duration) => warmup_durations_ms.push(duration),
            Err(err) => {
                return ScenarioReport::from_timings(
                    scenario,
                    ScenarioTransport::Direct,
                    false,
                    warmup_durations_ms,
                    measured_durations_ms,
                    Some(err),
                );
            }
        }
    }

    for _ in 0..manifest.measured_iterations {
        match measure_hierarchy_scenario(target, checkout_path, scenario) {
            Ok(duration) => measured_durations_ms.push(duration),
            Err(err) => {
                return ScenarioReport::from_timings(
                    scenario,
                    ScenarioTransport::Direct,
                    false,
                    warmup_durations_ms,
                    measured_durations_ms,
                    Some(err),
                );
            }
        }
    }

    ScenarioReport::from_timings(
        scenario,
        ScenarioTransport::Direct,
        true,
        warmup_durations_ms,
        measured_durations_ms,
        None,
    )
}

fn measure_hierarchy_scenario(
    target: &BenchmarkRepoTarget,
    checkout_path: &Path,
    scenario: BenchmarkScenario,
) -> Result<f64, String> {
    let selected_languages = target
        .language_set()
        .into_iter()
        .map(|language| language.analyzer_language())
        .collect::<BTreeSet<_>>();
    let project: Arc<dyn Project> =
        Arc::new(FilesystemProject::new(checkout_path).map_err(|err| {
            format!(
                "failed to open workspace `{}`: {err}",
                checkout_path.display()
            )
        })?);

    let total_start = Instant::now();
    let build_start = Instant::now();
    let workspace = if selected_languages.is_empty() {
        WorkspaceAnalyzer::build(Arc::clone(&project), AnalyzerConfig::default())
    } else {
        WorkspaceAnalyzer::build_for_languages(
            Arc::clone(&project),
            AnalyzerConfig::default(),
            &selected_languages,
        )
    };
    let build_ms = elapsed_ms(build_start);

    let query_start = Instant::now();
    let outcome = match scenario {
        BenchmarkScenario::CallHierarchy => {
            for query in &target.call_hierarchy_queries {
                run_call_hierarchy_query(&workspace, project.as_ref(), checkout_path, query)?;
            }
            Ok(())
        }
        BenchmarkScenario::TypeHierarchy => {
            for query in &target.type_hierarchy_queries {
                run_type_hierarchy_query(&workspace, project.as_ref(), checkout_path, query)?;
            }
            Ok(())
        }
        _ => Err(format!(
            "scenario `{}` is not a hierarchy scenario",
            scenario.label()
        )),
    };
    let query_ms = elapsed_ms(query_start);
    outcome?;

    let total_ms = elapsed_ms(total_start);
    if profile_hierarchy_enabled() {
        eprintln!(
            "bifrost_benchmark_profile scenario={} repo={} build_ms={:.3} query_ms={:.3} total_ms={:.3}",
            scenario.label(),
            target.name,
            build_ms,
            query_ms,
            total_ms
        );
    }

    Ok(total_ms)
}

fn run_call_hierarchy_query(
    workspace: &WorkspaceAnalyzer,
    project: &dyn Project,
    checkout_path: &Path,
    query: &HierarchyQueryTarget,
) -> Result<(), String> {
    let params = call_hierarchy_prepare_params(checkout_path, &query.selector)?;
    let profile = profile_hierarchy_enabled();
    let query_start = Instant::now();
    let prepare_start = Instant::now();
    let items = call_hierarchy::prepare(workspace, project, &params)
        .filter(|items| !items.is_empty())
        .ok_or_else(|| {
            format!(
                "call_hierarchy prepare returned no item for `{}`",
                query.selector.path
            )
        })?;
    let prepare_ms = elapsed_ms(prepare_start);
    let item = items
        .into_iter()
        .next()
        .expect("non-empty call hierarchy item list");

    let incoming_start = Instant::now();
    let incoming = call_hierarchy::incoming_calls(
        workspace,
        project,
        &CallHierarchyIncomingCallsParams {
            item: item.clone(),
            work_done_progress_params: WorkDoneProgressParams::default(),
            partial_result_params: PartialResultParams::default(),
        },
    )
    .ok_or_else(|| {
        format!(
            "call_hierarchy incomingCalls failed for `{}`",
            query.selector.path
        )
    })?;
    let incoming_ms = elapsed_ms(incoming_start);
    if incoming.len() < query.min_incoming {
        return Err(format!(
            "call_hierarchy incomingCalls for `{}` returned {} result(s), expected at least {}",
            query.selector.path,
            incoming.len(),
            query.min_incoming
        ));
    }

    let outgoing_start = Instant::now();
    let outgoing = call_hierarchy::outgoing_calls(
        workspace,
        project,
        &CallHierarchyOutgoingCallsParams {
            item,
            work_done_progress_params: WorkDoneProgressParams::default(),
            partial_result_params: PartialResultParams::default(),
        },
    )
    .ok_or_else(|| {
        format!(
            "call_hierarchy outgoingCalls failed for `{}`",
            query.selector.path
        )
    })?;
    let outgoing_ms = elapsed_ms(outgoing_start);
    if outgoing.len() < query.min_outgoing {
        return Err(format!(
            "call_hierarchy outgoingCalls for `{}` returned {} result(s), expected at least {}",
            query.selector.path,
            outgoing.len(),
            query.min_outgoing
        ));
    }

    if profile {
        eprintln!(
            "bifrost_benchmark_profile scenario=call_hierarchy selector={} prepare_ms={:.3} incoming_ms={:.3} outgoing_ms={:.3} incoming_count={} outgoing_count={} total_query_ms={:.3}",
            query.selector.path,
            prepare_ms,
            incoming_ms,
            outgoing_ms,
            incoming.len(),
            outgoing.len(),
            elapsed_ms(query_start)
        );
    }

    Ok(())
}

fn profile_hierarchy_enabled() -> bool {
    std::env::var_os("BIFROST_BENCHMARK_PROFILE_HIERARCHY").is_some()
}

fn run_type_hierarchy_query(
    workspace: &WorkspaceAnalyzer,
    project: &dyn Project,
    checkout_path: &Path,
    query: &HierarchyQueryTarget,
) -> Result<(), String> {
    let params = type_hierarchy_prepare_params(checkout_path, &query.selector)?;
    let items = type_hierarchy::prepare(workspace, project, &params)
        .filter(|items| !items.is_empty())
        .ok_or_else(|| {
            format!(
                "type_hierarchy prepare returned no item for `{}`",
                query.selector.path
            )
        })?;
    let item = items
        .into_iter()
        .next()
        .expect("non-empty type hierarchy item list");

    let supertypes = type_hierarchy::supertypes(
        workspace,
        project,
        &TypeHierarchySupertypesParams {
            item: item.clone(),
            work_done_progress_params: WorkDoneProgressParams::default(),
            partial_result_params: PartialResultParams::default(),
        },
    )
    .ok_or_else(|| {
        format!(
            "type_hierarchy supertypes failed for `{}`",
            query.selector.path
        )
    })?;
    if supertypes.len() < query.min_supertypes {
        return Err(format!(
            "type_hierarchy supertypes for `{}` returned {} result(s), expected at least {}",
            query.selector.path,
            supertypes.len(),
            query.min_supertypes
        ));
    }

    let subtypes = type_hierarchy::subtypes(
        workspace,
        project,
        &TypeHierarchySubtypesParams {
            item,
            work_done_progress_params: WorkDoneProgressParams::default(),
            partial_result_params: PartialResultParams::default(),
        },
    )
    .ok_or_else(|| {
        format!(
            "type_hierarchy subtypes failed for `{}`",
            query.selector.path
        )
    })?;
    if subtypes.len() < query.min_subtypes {
        return Err(format!(
            "type_hierarchy subtypes for `{}` returned {} result(s), expected at least {}",
            query.selector.path,
            subtypes.len(),
            query.min_subtypes
        ));
    }

    Ok(())
}

fn call_hierarchy_prepare_params(
    checkout_path: &Path,
    selector: &BenchmarkLocationSelector,
) -> Result<CallHierarchyPrepareParams, String> {
    Ok(CallHierarchyPrepareParams {
        text_document_position_params: text_document_position_params(checkout_path, selector)?,
        work_done_progress_params: WorkDoneProgressParams::default(),
    })
}

fn type_hierarchy_prepare_params(
    checkout_path: &Path,
    selector: &BenchmarkLocationSelector,
) -> Result<TypeHierarchyPrepareParams, String> {
    Ok(TypeHierarchyPrepareParams {
        text_document_position_params: text_document_position_params(checkout_path, selector)?,
        work_done_progress_params: WorkDoneProgressParams::default(),
    })
}

fn text_document_position_params(
    checkout_path: &Path,
    selector: &BenchmarkLocationSelector,
) -> Result<TextDocumentPositionParams, String> {
    let line = selector
        .line
        .ok_or_else(|| format!("hierarchy selector `{}` is missing line", selector.path))?;
    let column = selector
        .column
        .ok_or_else(|| format!("hierarchy selector `{}` is missing column", selector.path))?;
    Ok(TextDocumentPositionParams {
        text_document: TextDocumentIdentifier {
            uri: file_uri(checkout_path, selector)?,
        },
        position: Position {
            line: (line - 1) as u32,
            character: (column - 1) as u32,
        },
    })
}

fn file_uri(checkout_path: &Path, selector: &BenchmarkLocationSelector) -> Result<Uri, String> {
    let path = checkout_path.join(&selector.path);
    path_to_uri_string(&path)
        .parse()
        .map_err(|err| format!("failed to convert `{}` to URI: {err}", path.display()))
}

fn run_workspace_build(
    target: &BenchmarkRepoTarget,
    manifest: &BenchmarkManifest,
    checkout_path: &Path,
) -> ScenarioReport {
    let mut warmup_durations_ms = Vec::with_capacity(manifest.warmup_iterations);
    let mut measured_durations_ms = Vec::with_capacity(manifest.measured_iterations);
    let selected_languages = target
        .language_set()
        .into_iter()
        .map(|language| language.analyzer_language())
        .collect::<BTreeSet<_>>();

    for _ in 0..manifest.warmup_iterations {
        match measure_workspace_build(checkout_path, &selected_languages) {
            Ok(duration) => warmup_durations_ms.push(duration),
            Err(err) => {
                return ScenarioReport::from_timings(
                    BenchmarkScenario::WorkspaceBuild,
                    ScenarioTransport::Direct,
                    false,
                    warmup_durations_ms,
                    measured_durations_ms,
                    Some(err),
                );
            }
        }
    }

    for _ in 0..manifest.measured_iterations {
        match measure_workspace_build(checkout_path, &selected_languages) {
            Ok(duration) => measured_durations_ms.push(duration),
            Err(err) => {
                return ScenarioReport::from_timings(
                    BenchmarkScenario::WorkspaceBuild,
                    ScenarioTransport::Direct,
                    false,
                    warmup_durations_ms,
                    measured_durations_ms,
                    Some(err),
                );
            }
        }
    }

    ScenarioReport::from_timings(
        BenchmarkScenario::WorkspaceBuild,
        ScenarioTransport::Direct,
        true,
        warmup_durations_ms,
        measured_durations_ms,
        None,
    )
}

fn measure_workspace_build(
    checkout_path: &Path,
    selected_languages: &BTreeSet<crate::Language>,
) -> Result<f64, String> {
    let project = Arc::new(FilesystemProject::new(checkout_path).map_err(|err| {
        format!(
            "failed to open workspace `{}`: {err}",
            checkout_path.display()
        )
    })?);
    let start = Instant::now();
    if selected_languages.is_empty() {
        let _workspace = WorkspaceAnalyzer::build(project, AnalyzerConfig::default());
    } else {
        let _workspace = WorkspaceAnalyzer::build_for_languages(
            project,
            AnalyzerConfig::default(),
            selected_languages,
        );
    }
    Ok(elapsed_ms(start))
}

fn run_mcp_scenario(
    target: &BenchmarkRepoTarget,
    manifest: &BenchmarkManifest,
    session: &mut McpSession,
    scenario: BenchmarkScenario,
    profile: Option<&BenchmarkProfile>,
) -> ScenarioReport {
    let mut warmup_durations_ms = Vec::with_capacity(manifest.warmup_iterations);
    let mut measured_durations_ms = Vec::with_capacity(manifest.measured_iterations);
    let mut profile_artifacts = Vec::new();

    for iteration in 0..manifest.warmup_iterations {
        let (outcome, artifact) =
            run_mcp_iteration(target, session, scenario, profile, "warmup", iteration + 1);
        profile_artifacts.extend(artifact);
        match outcome {
            Ok(duration_ms) => warmup_durations_ms.push(duration_ms),
            Err(err) => {
                let mut report = ScenarioReport::from_timings(
                    scenario,
                    ScenarioTransport::Mcp,
                    false,
                    warmup_durations_ms,
                    measured_durations_ms,
                    Some(err),
                );
                report.profile_artifacts = profile_artifacts;
                return report;
            }
        }
    }

    for iteration in 0..manifest.measured_iterations {
        let (outcome, artifact) = run_mcp_iteration(
            target,
            session,
            scenario,
            profile,
            "measured",
            iteration + 1,
        );
        profile_artifacts.extend(artifact);
        match outcome {
            Ok(duration_ms) => measured_durations_ms.push(duration_ms),
            Err(err) => {
                let mut report = ScenarioReport::from_timings(
                    scenario,
                    ScenarioTransport::Mcp,
                    false,
                    warmup_durations_ms,
                    measured_durations_ms,
                    Some(err),
                );
                report.profile_artifacts = profile_artifacts;
                return report;
            }
        }
    }

    let mut report = ScenarioReport::from_timings(
        scenario,
        ScenarioTransport::Mcp,
        true,
        warmup_durations_ms,
        measured_durations_ms,
        None,
    );
    report.profile_artifacts = profile_artifacts;
    report
}

fn run_mcp_iteration(
    target: &BenchmarkRepoTarget,
    session: &mut McpSession,
    scenario: BenchmarkScenario,
    profile: Option<&BenchmarkProfile>,
    phase: &str,
    iteration: usize,
) -> (Result<f64, String>, Option<PathBuf>) {
    let (outcome, artifact) = run_profiled_iteration(
        session,
        profile,
        IterationId {
            target,
            scenario,
            case_id: None,
            phase,
            iteration,
        },
        |session| {
            if scenario.is_code_quality() {
                run_code_quality_probes(target, session, scenario)
            } else {
                session
                    .call_tool(
                        scenario_tool_name(target, scenario),
                        tool_arguments(target, scenario),
                    )
                    .and_then(|result| assert_scenario_result(target, scenario, &result))
            }
        },
    );
    (outcome.map(|timed| timed.duration_ms), artifact)
}

/// Code-quality scenarios issue one tool call per manifest probe inside the
/// timed iteration; the probe set is pinned, so the summed duration is a
/// stable series. Each probe's report is checked against its own oracle.
fn run_code_quality_probes(
    target: &BenchmarkRepoTarget,
    session: &mut McpSession,
    scenario: BenchmarkScenario,
) -> Result<(), String> {
    let mut probes = target.code_quality_probes_for(scenario).peekable();
    assert!(
        probes.peek().is_some(),
        "manifest validation guarantees at least one probe for `{}`",
        scenario.label()
    );
    for probe in probes {
        let result = session.call_tool(
            scenario.tool_name(),
            code_quality_arguments(scenario, probe),
        )?;
        assert_code_quality_report(target, scenario, probe, &result)?;
    }
    Ok(())
}

fn code_quality_arguments(scenario: BenchmarkScenario, probe: &CodeQualityProbe) -> Value {
    let mut arguments = match scenario {
        BenchmarkScenario::DeadCodeSmells => json!({
            "fq_names": probe.fq_names,
            "file_paths": probe.file_paths,
            "max_usage_candidate_files": 2000
        }),
        BenchmarkScenario::CommentDensityCodeUnit => json!({
            "fq_name": probe.fq_names[0]
        }),
        BenchmarkScenario::GitHotspots => json!({}),
        BenchmarkScenario::CommentDensityFiles
        | BenchmarkScenario::ExceptionSmells
        | BenchmarkScenario::TestAssertionSmells
        | BenchmarkScenario::StructuralCloneSmells
        | BenchmarkScenario::LongMethodSmells
        | BenchmarkScenario::SecretLikeCode => json!({
            "file_paths": probe.file_paths
        }),
        other => unreachable!("`{}` is not a code-quality scenario", other.label()),
    };
    let merged = arguments
        .as_object_mut()
        .expect("code-quality payloads are objects");
    for (key, value) in &probe.arguments {
        merged.insert(key.clone(), value.clone());
    }
    arguments
}

fn assert_code_quality_report(
    target: &BenchmarkRepoTarget,
    scenario: BenchmarkScenario,
    probe: &CodeQualityProbe,
    result: &Value,
) -> Result<(), String> {
    let structured = result
        .get("structuredContent")
        .ok_or_else(|| format!("tool `{}` returned no structuredContent", scenario.label()))?;
    let report = structured["report"].as_str().ok_or_else(|| {
        format!(
            "{} result missing report string for `{}`",
            scenario.label(),
            target.name
        )
    })?;
    for expected in &probe.expect_report_contains {
        if !report.contains(expected) {
            return Err(format!(
                "{} report for `{}` did not contain expected text `{expected}`\n\nActual report:\n{report}",
                scenario.label(),
                target.name,
            ));
        }
    }
    for forbidden in &probe.expect_report_absent {
        if report.contains(forbidden) {
            return Err(format!(
                "{} report for `{}` contained forbidden text `{forbidden}`\n\nActual report:\n{report}",
                scenario.label(),
                target.name,
            ));
        }
    }
    Ok(())
}

fn scenario_tool_name(target: &BenchmarkRepoTarget, scenario: BenchmarkScenario) -> &'static str {
    if scenario == BenchmarkScenario::ScanUsages && !target.usage_targets.is_empty() {
        "scan_usages_by_location"
    } else {
        scenario.tool_name()
    }
}

fn tool_arguments(target: &BenchmarkRepoTarget, scenario: BenchmarkScenario) -> Value {
    match scenario {
        BenchmarkScenario::WorkspaceBuild => json!({}),
        BenchmarkScenario::SearchSymbols => json!({
            "patterns": target.search_patterns,
            "include_tests": true
        }),
        BenchmarkScenario::GetSymbolLocations => json!({
            "symbols": target.location_symbols
        }),
        BenchmarkScenario::GetSymbolAncestors => json!({
            "symbols": target.ancestor_symbols
        }),
        BenchmarkScenario::GetSummaries => json!({
            "targets": target.summary_targets
        }),
        BenchmarkScenario::MostRelevantFiles => json!({
            "seed_file_paths": target.seed_file_paths,
            "limit": 20
        }),
        BenchmarkScenario::ScanUsages => {
            let mut args = json!({
                "include_tests": true,
                // A benchmark establishes whether the resolver can discover a
                // real call site, rather than whether that site is external to
                // its declaring type. Ask the structured scan to return the
                // separately classified self/own-type sites so a same-owner-only
                // target (such as FastRoute::RouteCollector::addRoute) remains a
                // valid resolver regression probe.
                "include_same_owner": true,
                // The regular benchmark is a compatibility and performance
                // comparison, not an interactive request. It needs a complete
                // result so it can compare semantics with the blessed baseline.
                "max_duration_secs": crate::mcp_common::BENCHMARK_MCP_REQUEST_BUDGET_SECS,
            });
            if !target.usage_symbols.is_empty() {
                args["symbols"] = json!(target.usage_symbols);
            }
            if !target.usage_targets.is_empty() {
                args["targets"] = json!(
                    target
                        .usage_targets
                        .iter()
                        .map(location_selector_arguments)
                        .collect::<Vec<_>>()
                );
            }
            args
        }
        BenchmarkScenario::GetDefinition => json!({
            "references": target.definition_queries.iter().map(|query| {
                location_selector_arguments(&query.selector)
            }).collect::<Vec<_>>(),
        }),
        BenchmarkScenario::CallHierarchy
        | BenchmarkScenario::TypeHierarchy
        | BenchmarkScenario::QueryCode
        | BenchmarkScenario::InteractiveCodeIntelligence
        | BenchmarkScenario::McpFairness => json!({}),
        BenchmarkScenario::DeadCodeSmells
        | BenchmarkScenario::CommentDensityFiles
        | BenchmarkScenario::CommentDensityCodeUnit
        | BenchmarkScenario::ExceptionSmells
        | BenchmarkScenario::TestAssertionSmells
        | BenchmarkScenario::StructuralCloneSmells
        | BenchmarkScenario::LongMethodSmells
        | BenchmarkScenario::SecretLikeCode
        | BenchmarkScenario::GitHotspots => {
            unreachable!("code-quality scenarios build per-probe arguments")
        }
    }
}

fn location_selector_arguments(selector: &BenchmarkLocationSelector) -> Value {
    let mut arguments = json!({
        "path": selector.path,
        "line": selector.line,
        "column": selector.column
    });
    if let Some(symbol) = &selector.symbol {
        arguments["symbol"] = json!(symbol);
    }
    arguments
}

fn assert_scenario_result(
    target: &BenchmarkRepoTarget,
    scenario: BenchmarkScenario,
    result: &Value,
) -> Result<(), String> {
    let structured = result
        .get("structuredContent")
        .ok_or_else(|| format!("tool `{}` returned no structuredContent", scenario.label()))?;
    match scenario {
        BenchmarkScenario::WorkspaceBuild => Ok(()),
        BenchmarkScenario::SearchSymbols => {
            let files = structured["files"].as_array().ok_or_else(|| {
                format!(
                    "search_symbols result missing files array for `{}`",
                    target.name
                )
            })?;
            if files.is_empty() {
                return Err(format!(
                    "search_symbols returned no files for `{}`",
                    target.name
                ));
            }
            Ok(())
        }
        BenchmarkScenario::GetSymbolLocations => {
            let locations = structured["locations"].as_array().ok_or_else(|| {
                format!(
                    "get_symbol_locations result missing locations array for `{}`",
                    target.name
                )
            })?;
            if locations.is_empty() {
                return Err(format!(
                    "get_symbol_locations returned no locations for `{}`",
                    target.name
                ));
            }
            Ok(())
        }
        BenchmarkScenario::GetSymbolAncestors => {
            let ancestors = structured["ancestors"].as_array().ok_or_else(|| {
                format!(
                    "get_symbol_ancestors result missing ancestors array for `{}`",
                    target.name
                )
            })?;
            if ancestors.is_empty() {
                return Err(format!(
                    "get_symbol_ancestors returned no results for `{}`",
                    target.name
                ));
            }
            let has_ancestor = ancestors.iter().any(|entry| {
                entry["ancestors"]
                    .as_array()
                    .is_some_and(|items| !items.is_empty())
            });
            if !has_ancestor {
                return Err(format!(
                    "get_symbol_ancestors returned no ancestor entries for `{}`",
                    target.name
                ));
            }
            Ok(())
        }
        BenchmarkScenario::GetSummaries => {
            if structured["not_found"]
                .as_array()
                .is_some_and(|items| !items.is_empty())
            {
                return Err(format!(
                    "get_summaries reported unresolved targets for `{}`",
                    target.name
                ));
            }
            let summaries = structured["summaries"].as_array().ok_or_else(|| {
                format!(
                    "get_summaries result missing summaries array for `{}`",
                    target.name
                )
            })?;
            let compact_files = structured["compact_symbols"]["files"].as_array();
            let has_compact_symbols = structured["degraded"].as_bool() == Some(true)
                && compact_files.is_some_and(|files| !files.is_empty());
            if summaries.is_empty() && !has_compact_symbols {
                return Err(format!(
                    "get_summaries returned no summaries or compact symbols for `{}`",
                    target.name
                ));
            }
            Ok(())
        }
        BenchmarkScenario::MostRelevantFiles => {
            let files = structured["files"].as_array().ok_or_else(|| {
                format!(
                    "most_relevant_files result missing files array for `{}`",
                    target.name
                )
            })?;
            if files.is_empty() {
                return Err(format!(
                    "most_relevant_files returned no related files for `{}`",
                    target.name
                ));
            }
            let seed_paths = target
                .seed_file_paths
                .iter()
                .map(|seed| seed.trim())
                .collect::<BTreeSet<_>>();
            let has_non_seed = files
                .iter()
                .filter_map(|file| file.get("path").and_then(Value::as_str))
                .any(|path| !seed_paths.contains(path));
            if !has_non_seed {
                return Err(format!(
                    "most_relevant_files only returned seed files for `{}`",
                    target.name
                ));
            }
            Ok(())
        }
        BenchmarkScenario::ScanUsages => {
            let results = structured["results"].as_array().ok_or_else(|| {
                format!(
                    "scan_usages result missing results array for `{}`",
                    target.name
                )
            })?;
            if results.is_empty() {
                return Err(format!(
                    "scan_usages returned no result entries for `{}`",
                    target.name
                ));
            }
            let has_hits = results.iter().any(|entry| {
                matches!(
                    entry["status"].as_str(),
                    Some("found" | "too_many_callsites")
                ) && (entry["total_hits"].as_u64().unwrap_or(0) > 0
                    || entry["total_callsites"].as_u64().unwrap_or(0) > 0
                    || entry["files"]
                        .as_array()
                        .is_some_and(|files| !files.is_empty()))
                    || entry["status"].as_str() == Some("no_external_usages")
                        && (entry["same_owner_sites"].as_u64().unwrap_or(0) > 0
                            || entry["same_owner_files"]
                                .as_array()
                                .is_some_and(|files| !files.is_empty()))
            });
            if !has_hits {
                if structured["summary"]["partial"].as_bool() == Some(true) {
                    let reasons = results
                        .iter()
                        .filter_map(|entry| entry["incomplete_reason"].as_str())
                        .collect::<BTreeSet<_>>();
                    let reasons = if reasons.is_empty() {
                        "unspecified reason".to_string()
                    } else {
                        reasons.into_iter().collect::<Vec<_>>().join(", ")
                    };
                    return Err(format!(
                        "scan_usages returned explicitly bounded incomplete results for `{}` ({reasons}); it did not establish call-site absence",
                        target.name
                    ));
                }
                return Err(format!(
                    "scan_usages found no call sites for `{}`",
                    target.name
                ));
            }
            Ok(())
        }
        BenchmarkScenario::GetDefinition => {
            let results = structured["results"].as_array().ok_or_else(|| {
                format!(
                    "get_definition result missing results array for `{}`",
                    target.name
                )
            })?;
            if results.len() != target.definition_queries.len() {
                return Err(format!(
                    "get_definition returned {} result(s) for {} query/queries in `{}`",
                    results.len(),
                    target.definition_queries.len(),
                    target.name
                ));
            }

            for (index, (query, result)) in target
                .definition_queries
                .iter()
                .zip(results.iter())
                .enumerate()
            {
                let actual_status = result["status"].as_str().ok_or_else(|| {
                    format!(
                        "get_definition result {index} missing status for `{}`",
                        target.name
                    )
                })?;
                if actual_status != query.expected_status {
                    return Err(format!(
                        "get_definition result {index} for `{}` expected status `{}` but got `{actual_status}`",
                        target.name, query.expected_status
                    ));
                }

                if let Some(expected_fqn) = query.expected_fqn.as_deref() {
                    let definition = result["definitions"]
                        .as_array()
                        .and_then(|definitions| definitions.first())
                        .and_then(|definition| definition.as_object())
                        .ok_or_else(|| {
                            format!(
                                "get_definition result {index} missing definitions object for `{}`",
                                target.name
                            )
                        })?;
                    let actual_fqn = definition.get("fqn").and_then(|value| value.as_str());
                    if actual_fqn != Some(expected_fqn) {
                        return Err(format!(
                            "get_definition result {index} for `{}` expected fqn `{expected_fqn}` but got `{}`",
                            target.name,
                            actual_fqn.unwrap_or("<missing>")
                        ));
                    }
                }
            }
            Ok(())
        }
        BenchmarkScenario::CallHierarchy
        | BenchmarkScenario::TypeHierarchy
        | BenchmarkScenario::QueryCode
        | BenchmarkScenario::InteractiveCodeIntelligence
        | BenchmarkScenario::McpFairness => Ok(()),
        BenchmarkScenario::DeadCodeSmells
        | BenchmarkScenario::CommentDensityFiles
        | BenchmarkScenario::CommentDensityCodeUnit
        | BenchmarkScenario::ExceptionSmells
        | BenchmarkScenario::TestAssertionSmells
        | BenchmarkScenario::StructuralCloneSmells
        | BenchmarkScenario::LongMethodSmells
        | BenchmarkScenario::SecretLikeCode
        | BenchmarkScenario::GitHotspots => {
            unreachable!("code-quality scenarios assert per-probe reports")
        }
    }
}

fn elapsed_ms(start: Instant) -> f64 {
    start.elapsed().as_secs_f64() * 1000.0
}

fn current_bifrost_commit() -> Option<String> {
    current_bifrost_commit_at(Path::new(env!("CARGO_MANIFEST_DIR")))
}

fn current_bifrost_commit_at(repo_root: &Path) -> Option<String> {
    let output = std::process::Command::new("git")
        .arg("rev-parse")
        .arg("HEAD")
        .current_dir(repo_root)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let sha = String::from_utf8(output.stdout).ok()?;
    let trimmed = sha.trim();
    if trimmed.is_empty() {
        return None;
    }
    let diff = std::process::Command::new("git")
        .args([
            "diff",
            "--binary",
            "HEAD",
            "--",
            "src",
            "crates",
            "Cargo.toml",
            "Cargo.lock",
            "build.rs",
            "resources",
        ])
        .current_dir(repo_root)
        .output()
        .ok()?;
    if !diff.status.success() || diff.stdout.is_empty() {
        return Some(trimmed.to_string());
    }
    let mut hasher = std::process::Command::new("git")
        .args(["hash-object", "--stdin"])
        .current_dir(repo_root)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .ok()?;
    hasher.stdin.take()?.write_all(&diff.stdout).ok()?;
    let hash = hasher.wait_with_output().ok()?;
    if !hash.status.success() {
        return None;
    }
    let fingerprint = String::from_utf8(hash.stdout).ok()?;
    Some(format!("{trimmed}-dirty.{}", fingerprint.trim()))
}

#[cfg(test)]
mod issue_1375_tests {
    use super::current_bifrost_commit_at;
    use std::fs;
    use std::process::Command;

    fn git(root: &std::path::Path, args: &[&str]) {
        let output = Command::new("git")
            .args(args)
            .current_dir(root)
            .output()
            .expect("run git");
        assert!(
            output.status.success(),
            "git {args:?} failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn runtime_identity_includes_crates_only_dirty_changes() {
        let temp = tempfile::tempdir().expect("temp repo");
        let root = temp.path();
        fs::create_dir(root.join("src")).expect("src directory");
        fs::create_dir(root.join("crates")).expect("crates directory");
        fs::write(root.join("src/lib.rs"), "pub fn stable() {}\n").expect("write src");
        fs::write(root.join("crates/lib.rs"), "pub fn original() {}\n").expect("write crate");

        git(root, &["init"]);
        git(root, &["add", "src/lib.rs", "crates/lib.rs"]);
        git(
            root,
            &[
                "-c",
                "user.name=Bifrost Test",
                "-c",
                "user.email=bifrost@example.invalid",
                "commit",
                "-m",
                "initial",
            ],
        );

        let clean_identity = current_bifrost_commit_at(root).expect("clean identity");
        fs::write(root.join("crates/lib.rs"), "pub fn changed() {}\n").expect("change crate");
        let dirty_identity = current_bifrost_commit_at(root).expect("dirty identity");

        assert!(
            dirty_identity.starts_with(&format!("{clean_identity}-dirty.")),
            "crates-only edits must dirty the runtime identity: {dirty_identity}"
        );
    }
}

#[cfg(test)]
mod issue_1228_tests {
    use super::*;
    use crate::benchmark::InteractiveQueryTool;

    fn bounded_scan_case() -> InteractiveQueryBenchmarkCase {
        InteractiveQueryBenchmarkCase {
            id: "bounded-scan".to_string(),
            tool: InteractiveQueryTool::ScanUsagesByLocation,
            arguments_json: r#"{"targets":[{"path":"lib.rs","line":7,"symbol":"target"}]}"#
                .to_string(),
            expected_json_pointer: "/structuredContent/results/0/definition_path".to_string(),
            expected_json_value: Some(Value::String("lib.rs".to_string())),
            allow_bounded_incomplete: true,
            max_p95_ms: 5_000.0,
        }
    }

    #[test]
    fn issue_1228_interactive_gate_accepts_only_truthful_bounded_scan_results() {
        let bounded = json!({
            "structuredContent": {
                "summary": { "partial": true, "requested": 1 },
                "results": [{
                    "input": {"path":"lib.rs","line":7,"symbol":"target"},
                    "status": "failure",
                    "complete": false,
                    "incomplete_reason": "time_budget",
                    "reason_kind": "time_budget",
                    "message": "Retry with a narrower path scope"
                }]
            }
        });
        assert_eq!(
            assert_interactive_result(&bounded_scan_case(), &bounded).unwrap(),
            InteractiveCompletion::BoundedIncomplete
        );

        let false_absence = json!({
            "structuredContent": {
                "summary": { "partial": true, "requested": 1 },
                "results": [{
                    "input": {"path":"lib.rs","line":7,"symbol":"target"},
                    "status": "verified_absent",
                    "complete": false,
                    "incomplete_reason": "time_budget",
                    "message": "Retry with a narrower path scope"
                }]
            }
        });
        assert!(
            assert_interactive_result(&bounded_scan_case(), &false_absence).is_err(),
            "a timed-out scan must never pass the gate as verified absence"
        );

        let arbitrary_partial = json!({
            "structuredContent": {
                "summary": { "partial": true, "requested": 1 },
                "results": [{
                    "input": {"path":"other.rs","line":1},
                    "status": "failure",
                    "complete": false,
                    "incomplete_reason": "time_budget"
                }]
            }
        });
        assert!(
            assert_interactive_result(&bounded_scan_case(), &arbitrary_partial).is_err(),
            "a partial result must preserve input identity and actionable recovery guidance"
        );
    }

    #[test]
    fn benchmark_scan_reports_bounded_incompleteness_without_claiming_absence() {
        let target: BenchmarkRepoTarget = serde_json::from_value(json!({
            "name": "bounded-scan",
            "url": "https://example.invalid/bounded-scan",
            "commit": "deadbeef",
            "languages": [],
            "scenarios": []
        }))
        .expect("minimal benchmark target");
        let result = json!({
            "structuredContent": {
                "summary": { "partial": true },
                "results": [{
                    "status": "failure",
                    "complete": false,
                    "incomplete_reason": "time_budget"
                }]
            }
        });

        let error = assert_scenario_result(&target, BenchmarkScenario::ScanUsages, &result)
            .expect_err("a bounded scan is not a complete compatibility result");

        assert!(error.contains("explicitly bounded incomplete"), "{error}");
        assert!(error.contains("time_budget"), "{error}");
        assert!(!error.contains("no call sites"), "{error}");
    }

    #[test]
    fn benchmark_scan_accepts_bounded_response_that_preserves_call_site_evidence() {
        let target: BenchmarkRepoTarget = serde_json::from_value(json!({
            "name": "bounded-hit",
            "url": "https://example.invalid/bounded-hit",
            "commit": "deadbeef",
            "languages": [],
            "scenarios": []
        }))
        .expect("minimal benchmark target");
        let result = json!({
            "structuredContent": {
                "summary": { "partial": true },
                "results": [{
                    "status": "found",
                    "complete": false,
                    "incomplete_reason": "response_budget",
                    "total_hits": 1
                }]
            }
        });

        assert!(
            assert_scenario_result(&target, BenchmarkScenario::ScanUsages, &result).is_ok(),
            "the scenario verifies discoverable call sites, not exhaustive rendering"
        );
    }

    #[test]
    fn benchmark_scan_requests_and_accepts_same_owner_callsite_evidence() {
        let target: BenchmarkRepoTarget = serde_json::from_value(json!({
            "name": "fastroute-shaped",
            "url": "https://example.invalid/fastroute-shaped",
            "commit": "deadbeef",
            "languages": ["php"],
            "scenarios": ["scan_usages"],
            "usage_symbols": ["FastRoute.RouteCollector.addRoute"]
        }))
        .expect("minimal benchmark target");

        let arguments = tool_arguments(&target, BenchmarkScenario::ScanUsages);
        assert_eq!(arguments["include_same_owner"], Value::Bool(true));

        let result = json!({
            "structuredContent": {
                "summary": { "partial": false },
                "results": [{
                    "status": "no_external_usages",
                    "total_hits": 0,
                    "same_owner_sites": 2,
                    "same_owner_files": [{ "path": "src/RouteCollector.php", "hits": [{}] }]
                }]
            }
        });
        assert!(
            assert_scenario_result(&target, BenchmarkScenario::ScanUsages, &result).is_ok(),
            "a classified same-owner call site is still structured resolver evidence"
        );
    }

    #[test]
    fn benchmark_scan_rejects_empty_same_owner_status() {
        let target: BenchmarkRepoTarget = serde_json::from_value(json!({
            "name": "same-owner-near-miss",
            "url": "https://example.invalid/same-owner-near-miss",
            "commit": "deadbeef",
            "languages": [],
            "scenarios": []
        }))
        .expect("minimal benchmark target");
        let result = json!({
            "structuredContent": {
                "summary": { "partial": false },
                "results": [{
                    "status": "no_external_usages",
                    "total_hits": 0,
                    "same_owner_sites": 0,
                    "same_owner_files": []
                }]
            }
        });

        assert!(
            assert_scenario_result(&target, BenchmarkScenario::ScanUsages, &result).is_err(),
            "status alone is not call-site evidence"
        );
    }

    #[test]
    fn issue_1228_oracle_failures_redact_returned_source_text() {
        let mut case = bounded_scan_case();
        case.allow_bounded_incomplete = false;
        let result = json!({
            "structuredContent": {
                "sources": [{"path": "secret.rs", "text": "TOP-SECRET-SOURCE"}]
            }
        });

        let error = assert_interactive_result(&case, &result)
            .expect_err("missing oracle pointer must fail");

        assert!(!error.contains("TOP-SECRET-SOURCE"), "{error}");
        assert!(error.contains("structuredContent keys"), "{error}");
    }
}
