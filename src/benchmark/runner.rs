use crate::benchmark::artifact_path::{sanitize_component, unique_component};
use crate::benchmark::mcp_session::McpSession;
use crate::benchmark::repo_cache::prepare_repo;
use crate::benchmark::report::{
    BenchmarkRepoReport, BenchmarkRunReport, ScenarioReport, ScenarioTransport,
};
use crate::benchmark::subset_workspace::prepare_subset_workspace;
use crate::benchmark::{
    BenchmarkLocationSelector, BenchmarkManifest, BenchmarkRepoTarget, BenchmarkScenario,
    HierarchyQueryTarget,
};
use crate::lsp::conversion::path_to_uri_string;
use crate::lsp::handlers::{call_hierarchy, type_hierarchy};
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
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

#[derive(Debug, Clone)]
pub struct RunRequest {
    pub manifest_path: PathBuf,
    pub repo_cache_dir: PathBuf,
    pub selected_repo: Option<String>,
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
        .collect();

    if selected_targets.is_empty() {
        return Err(match selected_repo {
            Some(name) => format!("manifest contains no repo named `{name}`"),
            None => "manifest contains no repos to run".to_string(),
        });
    }

    let bifrost_commit = current_bifrost_commit();
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
        target
            .scenarios
            .iter()
            .position(|scenario| *scenario == report.name)
            .unwrap_or(usize::MAX)
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

    let session = McpSession::start(workspace_path, no_line_numbers, profile.is_some()).and_then(
        |mut session| match session.initialize() {
            Ok(()) => Ok(session),
            Err(err) => {
                let tail = session.shutdown_and_stderr_tail();
                Err(error_with_stderr_tail(err, tail))
            }
        },
    );
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
    let cursor = if profile.is_some() {
        if let Err(err) = session.profile_boundary() {
            return (
                Err(error_with_stderr_tail(err, session.stderr_tail())),
                None,
            );
        }
        Some(session.stderr_cursor())
    } else {
        None
    };
    let start = Instant::now();
    let mut outcome = session
        .call_tool(
            scenario_tool_name(target, scenario),
            tool_arguments(target, scenario),
        )
        .and_then(|result| assert_scenario_result(target, scenario, &result))
        .map(|()| elapsed_ms(start));

    if profile.is_some() {
        outcome = preserve_outcome_on_boundary_failure(outcome, session.profile_boundary());
    } else if outcome.is_err() {
        // Flush stderr written before a normal JSON-RPC error response so the
        // diagnostic tail below is complete even outside profile mode.
        let _ = session.profile_boundary();
    }

    let artifact = profile.and_then(|profile| {
        let captured = session.stderr_since(cursor.expect("profile cursor"));
        match write_profile_trace(
            profile, target, scenario, phase, iteration, &outcome, &captured,
        ) {
            Ok(path) => Some(path),
            Err(err) => {
                outcome = Err(err);
                None
            }
        }
    });

    if let Err(err) = outcome {
        outcome = Err(error_with_stderr_tail(err, session.stderr_tail()));
    }
    (outcome, artifact)
}

fn preserve_outcome_on_boundary_failure(
    outcome: Result<f64, String>,
    boundary: Result<(), String>,
) -> Result<f64, String> {
    match (outcome, boundary) {
        (outcome, Ok(())) => outcome,
        (Ok(_), Err(boundary_error)) => Err(format!(
            "failed to synchronize benchmark profile output: {boundary_error}"
        )),
        (Err(request_error), Err(boundary_error)) => Err(format!(
            "{request_error}\nadditionally failed to synchronize benchmark profile output: {boundary_error}"
        )),
    }
}

fn write_profile_trace(
    profile: &BenchmarkProfile,
    target: &BenchmarkRepoTarget,
    scenario: BenchmarkScenario,
    phase: &str,
    iteration: usize,
    outcome: &Result<f64, String>,
    captured: &crate::benchmark::mcp_session::CapturedStderr,
) -> Result<PathBuf, String> {
    std::fs::create_dir_all(&profile.output_dir).map_err(|err| {
        format!(
            "failed to create benchmark profile dir `{}`: {err}",
            profile.output_dir.display()
        )
    })?;
    let filename = format!(
        "{}-{}-{phase}-{iteration}.log",
        unique_component(&target.name),
        sanitize_component(scenario.label())
    );
    let output_path = profile.output_dir.join(&filename);
    let report_path = profile.report_path_prefix.join(&filename);
    let (success, duration_ms, failure) = match outcome {
        Ok(duration_ms) => (true, format!("{duration_ms:.3}"), String::new()),
        Err(err) => (false, String::new(), format!("failure={err}\n")),
    };
    let contents = format!(
        "repository={}\nscenario={}\nphase={phase}\niteration={iteration}\nsuccess={success}\nduration_ms={duration_ms}\ntruncated={}\n{failure}{}",
        target.name,
        scenario.label(),
        captured.truncated,
        captured.text
    );
    std::fs::write(&output_path, contents).map_err(|err| {
        format!(
            "failed to write benchmark profile trace `{}`: {err}",
            output_path.display()
        )
    })?;
    Ok(report_path)
}

fn error_with_stderr_tail(
    error: String,
    tail: crate::benchmark::mcp_session::CapturedStderr,
) -> String {
    if tail.text.trim().is_empty() {
        return error;
    }
    let truncation = if tail.truncated { " (truncated)" } else { "" };
    format!(
        "{error}\nbifrost MCP stderr tail{truncation}:\n{}",
        tail.text
    )
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
                "include_tests": true
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
        BenchmarkScenario::DeadCodeSmells => json!({
            "fq_names": target.dead_code_fq_names,
            "file_paths": target.dead_code_file_paths,
            "max_usage_candidate_files": 2000,
            "max_usages_per_symbol": 1000
        }),
        BenchmarkScenario::GetDefinition => json!({
            "references": target.definition_queries.iter().map(|query| {
                location_selector_arguments(&query.selector)
            }).collect::<Vec<_>>(),
        }),
        BenchmarkScenario::CallHierarchy | BenchmarkScenario::TypeHierarchy => json!({}),
    }
}

fn location_selector_arguments(selector: &BenchmarkLocationSelector) -> Value {
    json!({
        "path": selector.path,
        "line": selector.line,
        "column": selector.column
    })
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
                .filter_map(Value::as_str)
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
            });
            if !has_hits {
                return Err(format!(
                    "scan_usages found no call sites for `{}`",
                    target.name
                ));
            }
            Ok(())
        }
        BenchmarkScenario::DeadCodeSmells => {
            let report = structured["report"].as_str().ok_or_else(|| {
                format!(
                    "dead_code_smells result missing report string for `{}`",
                    target.name
                )
            })?;
            for expected in &target.dead_code_expect_report_contains {
                if !report.contains(expected) {
                    return Err(format!(
                        "dead_code_smells report for `{}` did not contain expected text `{expected}`",
                        target.name
                    ));
                }
            }
            for forbidden in &target.dead_code_expect_report_absent {
                if report.contains(forbidden) {
                    return Err(format!(
                        "dead_code_smells report for `{}` contained forbidden text `{forbidden}`",
                        target.name
                    ));
                }
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
        BenchmarkScenario::CallHierarchy | BenchmarkScenario::TypeHierarchy => Ok(()),
    }
}

fn elapsed_ms(start: Instant) -> f64 {
    start.elapsed().as_secs_f64() * 1000.0
}

fn current_bifrost_commit() -> Option<String> {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"));
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
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

#[cfg(test)]
mod tests {
    use super::preserve_outcome_on_boundary_failure;

    #[test]
    fn boundary_failure_preserves_the_primary_request_error() {
        let error = preserve_outcome_on_boundary_failure(
            Err("MCP child closed early".to_string()),
            Err("stderr boundary unavailable".to_string()),
        )
        .expect_err("combined failure");

        assert!(error.starts_with("MCP child closed early"), "{error}");
        assert!(error.contains("stderr boundary unavailable"), "{error}");
    }
}
