use crate::benchmark::mcp_session::McpSession;
use crate::benchmark::repo_cache::prepare_repo;
use crate::benchmark::report::{
    BenchmarkRepoReport, BenchmarkRunReport, ScenarioReport, ScenarioTransport,
};
use crate::benchmark::subset_workspace::prepare_subset_workspace;
use crate::benchmark::{BenchmarkManifest, BenchmarkRepoTarget, BenchmarkScenario};
use crate::{AnalyzerConfig, FilesystemProject, WorkspaceAnalyzer};
use chrono::Utc;
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
        .filter(|scenario| *scenario != BenchmarkScenario::WorkspaceBuild)
        .collect();
    if !mcp_scenarios.is_empty() {
        match McpSession::start(&workspace_path).and_then(|mut session| {
            session.initialize()?;
            Ok(session)
        }) {
            Ok(mut session) => {
                for scenario in mcp_scenarios {
                    scenario_reports.push(run_mcp_scenario(
                        target,
                        manifest,
                        &mut session,
                        scenario,
                    ));
                }
            }
            Err(err) => {
                for scenario in mcp_scenarios {
                    scenario_reports.push(ScenarioReport::from_timings(
                        scenario,
                        ScenarioTransport::Mcp,
                        false,
                        Vec::new(),
                        Vec::new(),
                        Some(format!(
                            "failed to start MCP session for `{}`: {err}",
                            target.name
                        )),
                    ));
                }
            }
        }
    }

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
) -> ScenarioReport {
    let mut warmup_durations_ms = Vec::with_capacity(manifest.warmup_iterations);
    let mut measured_durations_ms = Vec::with_capacity(manifest.measured_iterations);

    for _ in 0..manifest.warmup_iterations {
        let start = Instant::now();
        let outcome = session
            .call_tool(scenario.label(), tool_arguments(target, scenario))
            .and_then(|result| assert_scenario_result(target, scenario, &result));
        match outcome {
            Ok(()) => warmup_durations_ms.push(elapsed_ms(start)),
            Err(err) => {
                return ScenarioReport::from_timings(
                    scenario,
                    ScenarioTransport::Mcp,
                    false,
                    warmup_durations_ms,
                    measured_durations_ms,
                    Some(err),
                );
            }
        }
    }

    for _ in 0..manifest.measured_iterations {
        let start = Instant::now();
        let outcome = session
            .call_tool(scenario.label(), tool_arguments(target, scenario))
            .and_then(|result| assert_scenario_result(target, scenario, &result));
        match outcome {
            Ok(()) => measured_durations_ms.push(elapsed_ms(start)),
            Err(err) => {
                return ScenarioReport::from_timings(
                    scenario,
                    ScenarioTransport::Mcp,
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
        ScenarioTransport::Mcp,
        true,
        warmup_durations_ms,
        measured_durations_ms,
        None,
    )
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
        BenchmarkScenario::GetSummaries => json!({
            "targets": target.summary_targets
        }),
        BenchmarkScenario::MostRelevantFiles => json!({
            "seed_file_paths": target.seed_file_paths,
            "limit": 20
        }),
        BenchmarkScenario::ScanUsages => json!({
            "symbols": target.usage_symbols,
            "include_tests": true
        }),
    }
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
        BenchmarkScenario::GetSummaries => {
            let summaries = structured["summaries"].as_array().ok_or_else(|| {
                format!(
                    "get_summaries result missing summaries array for `{}`",
                    target.name
                )
            })?;
            if summaries.is_empty() {
                return Err(format!(
                    "get_summaries returned no summaries for `{}`",
                    target.name
                ));
            }
            if structured["not_found"]
                .as_array()
                .is_some_and(|items| !items.is_empty())
            {
                return Err(format!(
                    "get_summaries reported unresolved targets for `{}`",
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
            let usages = structured["usages"].as_array().ok_or_else(|| {
                format!(
                    "scan_usages result missing usages array for `{}`",
                    target.name
                )
            })?;
            if usages.is_empty() {
                return Err(format!(
                    "scan_usages returned no usages for `{}`",
                    target.name
                ));
            }
            let has_hits = usages.iter().any(|usage| {
                usage["total_hits"].as_u64().unwrap_or(0) > 0
                    || usage["files"]
                        .as_array()
                        .is_some_and(|files| !files.is_empty())
            });
            if !has_hits {
                return Err(format!(
                    "scan_usages found no call sites for `{}`",
                    target.name
                ));
            }
            Ok(())
        }
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
