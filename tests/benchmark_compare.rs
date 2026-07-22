use brokk_bifrost::benchmark::{
    BenchmarkCompareReport, BenchmarkRepoReport, BenchmarkRunReport, BenchmarkScenario,
    ScenarioCompareOutcome, ScenarioReport, ScenarioTransport,
};
use serde_json::Value;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use tempfile::TempDir;

#[test]
fn compare_report_detects_threshold_and_failure_regressions() {
    let baseline = report_with_scenarios(vec![repo_with_scenarios(
        "fixture-java",
        vec![
            scenario(BenchmarkScenario::WorkspaceBuild, true, Some(100.0)),
            scenario(BenchmarkScenario::SearchSymbols, true, Some(100.0)),
            scenario(BenchmarkScenario::GetSymbolLocations, true, Some(100.0)),
            scenario(BenchmarkScenario::GetSummaries, true, Some(100.0)),
            scenario(BenchmarkScenario::MostRelevantFiles, true, Some(80.0)),
            scenario(BenchmarkScenario::ScanUsages, false, None),
        ],
    )]);
    let candidate = report_with_scenarios(vec![repo_with_scenarios(
        "fixture-java",
        vec![
            scenario(BenchmarkScenario::WorkspaceBuild, true, Some(100.0)),
            scenario(BenchmarkScenario::SearchSymbols, true, Some(118.0)),
            scenario(BenchmarkScenario::GetSymbolLocations, true, Some(160.0)),
            scenario(BenchmarkScenario::GetSummaries, false, None),
            scenario(BenchmarkScenario::ScanUsages, true, Some(20.0)),
            scenario(BenchmarkScenario::MostRelevantFiles, true, Some(45.0)),
        ],
    )]);

    let comparison = BenchmarkCompareReport::from_reports(&baseline, &candidate);

    assert!(comparison.has_regressions, "{comparison:?}");
    assert!(comparison.has_actionable_regressions, "{comparison:?}");
    assert_eq!(comparison.environment_variance, None, "{comparison:?}");
    assert_eq!(comparison.regression_count, 2, "{comparison:?}");
    assert_eq!(comparison.actionable_regression_count, 2, "{comparison:?}");
    assert_eq!(comparison.improvement_count, 1, "{comparison:?}");
    assert_eq!(comparison.missing_candidate_count, 0, "{comparison:?}");
    assert_eq!(comparison.new_candidate_count, 0, "{comparison:?}");

    let location = find_scenario(
        &comparison,
        "fixture-java",
        BenchmarkScenario::GetSymbolLocations,
    );
    assert_eq!(location.outcome, ScenarioCompareOutcome::Regression);
    assert_eq!(location.delta_ms, Some(60.0));
    assert_eq!(location.delta_pct, Some(60.0));

    let search = find_scenario(
        &comparison,
        "fixture-java",
        BenchmarkScenario::SearchSymbols,
    );
    assert_eq!(search.outcome, ScenarioCompareOutcome::Unchanged);
    assert_eq!(search.delta_ms, Some(18.0));
    assert_eq!(search.delta_pct, Some(18.0));

    let summaries = find_scenario(&comparison, "fixture-java", BenchmarkScenario::GetSummaries);
    assert_eq!(summaries.outcome, ScenarioCompareOutcome::Regression);
    assert!(summaries.is_regression);

    let usages = find_scenario(&comparison, "fixture-java", BenchmarkScenario::ScanUsages);
    assert_eq!(usages.outcome, ScenarioCompareOutcome::Improvement);
    assert!(!usages.is_regression);
}

#[test]
fn isolated_timing_regressions_remain_actionable() {
    let baseline = report_with_scenarios(vec![
        repo_with_scenarios(
            "fixture-a",
            vec![scenario_with_transport(
                BenchmarkScenario::WorkspaceBuild,
                ScenarioTransport::Direct,
                true,
                Some(200.0),
            )],
        ),
        repo_with_scenarios(
            "fixture-b",
            vec![scenario_with_transport(
                BenchmarkScenario::SearchSymbols,
                ScenarioTransport::Mcp,
                true,
                Some(200.0),
            )],
        ),
    ]);
    let candidate = report_with_scenarios(vec![
        repo_with_scenarios(
            "fixture-a",
            vec![scenario_with_transport(
                BenchmarkScenario::WorkspaceBuild,
                ScenarioTransport::Direct,
                true,
                Some(270.0),
            )],
        ),
        repo_with_scenarios(
            "fixture-b",
            vec![scenario_with_transport(
                BenchmarkScenario::SearchSymbols,
                ScenarioTransport::Mcp,
                true,
                Some(270.0),
            )],
        ),
    ]);

    let comparison = BenchmarkCompareReport::from_reports(&baseline, &candidate);

    assert!(comparison.has_regressions, "{comparison:?}");
    assert!(comparison.has_actionable_regressions, "{comparison:?}");
    assert_eq!(comparison.environment_variance, None, "{comparison:?}");
    assert_eq!(comparison.regression_count, 2, "{comparison:?}");
    assert_eq!(comparison.actionable_regression_count, 2, "{comparison:?}");
}

#[test]
fn selected_repo_comparison_ignores_unselected_baseline_scenarios() {
    let baseline = report_with_scenarios(vec![
        repo_with_scenarios(
            "fixture-a",
            vec![
                scenario(BenchmarkScenario::WorkspaceBuild, true, Some(100.0)),
                scenario(BenchmarkScenario::ScanUsages, true, Some(100.0)),
            ],
        ),
        repo_with_scenarios(
            "fixture-b",
            vec![scenario(
                BenchmarkScenario::SearchSymbols,
                true,
                Some(100.0),
            )],
        ),
    ]);
    let mut candidate = report_with_scenarios(vec![repo_with_scenarios(
        "fixture-a",
        vec![scenario(
            BenchmarkScenario::WorkspaceBuild,
            true,
            Some(100.0),
        )],
    )]);
    candidate.selected_repo = Some("fixture-a".to_string());

    let comparison = BenchmarkCompareReport::from_reports(&baseline, &candidate);

    assert_eq!(comparison.compared_scenarios_count, 2, "{comparison:?}");
    assert_eq!(comparison.regression_count, 1, "{comparison:?}");
    assert_eq!(comparison.missing_candidate_count, 1, "{comparison:?}");
    assert!(comparison.has_regressions, "{comparison:?}");
    assert!(
        comparison
            .scenarios
            .iter()
            .all(|scenario| scenario.repo_name == "fixture-a")
    );
}

#[test]
fn query_code_cases_are_compared_independently() {
    let baseline = report_with_scenarios(vec![repo_with_scenarios(
        "fixture-java",
        vec![
            query_scenario("exact-class", 100.0),
            query_scenario("typed-callers", 100.0),
        ],
    )]);
    let candidate = report_with_scenarios(vec![repo_with_scenarios(
        "fixture-java",
        vec![
            query_scenario("exact-class", 170.0),
            query_scenario("typed-callers", 110.0),
        ],
    )]);

    let comparison = BenchmarkCompareReport::from_reports(&baseline, &candidate);

    assert_eq!(comparison.compared_scenarios_count, 2, "{comparison:?}");
    let exact = comparison
        .scenarios
        .iter()
        .find(|scenario| scenario.case_id.as_deref() == Some("exact-class"))
        .expect("exact-name case");
    assert_eq!(exact.outcome, ScenarioCompareOutcome::Regression);
    let typed = comparison
        .scenarios
        .iter()
        .find(|scenario| scenario.case_id.as_deref() == Some("typed-callers"))
        .expect("typed traversal case");
    assert_eq!(typed.outcome, ScenarioCompareOutcome::Unchanged);
}

#[test]
fn query_code_cold_to_warm_ratio_blocks_false_warm_improvement() {
    let baseline = report_with_scenarios(vec![repo_with_scenarios(
        "fixture-java",
        vec![query_scenario_with_first("workspace", 200.0, 100.0)],
    )]);
    let candidate = report_with_scenarios(vec![repo_with_scenarios(
        "fixture-java",
        vec![query_scenario_with_first("workspace", 330.0, 25.0)],
    )]);

    let comparison = BenchmarkCompareReport::from_reports(&baseline, &candidate);
    let scenario = &comparison.scenarios[0];
    assert_eq!(scenario.outcome, ScenarioCompareOutcome::Regression);
    assert!(scenario.is_regression);
    assert!(
        scenario
            .detail
            .as_deref()
            .is_some_and(|detail| detail.contains("13.20x")),
        "{scenario:?}"
    );
}

#[test]
fn broad_workspace_slowdown_is_classified_as_environment_variance() {
    let baseline = report_with_scenarios(broad_slowdown_repos(200.0, 100.0, 200.0));
    let candidate = report_with_scenarios(broad_slowdown_repos(260.0, 125.0, 230.0));

    let comparison = BenchmarkCompareReport::from_reports(&baseline, &candidate);

    assert!(comparison.has_regressions, "{comparison:?}");
    assert!(!comparison.has_actionable_regressions, "{comparison:?}");
    assert_eq!(comparison.regression_count, 4, "{comparison:?}");
    assert_eq!(comparison.actionable_regression_count, 0, "{comparison:?}");
    let variance = comparison
        .environment_variance
        .as_ref()
        .expect("environment variance report");
    assert_eq!(variance.affected_repo_count, 4, "{variance:?}");
    assert_eq!(variance.timed_scenario_count, 12, "{variance:?}");
    assert_eq!(variance.timing_regression_count, 4, "{variance:?}");
    assert_eq!(variance.covered_regression_count, 4, "{variance:?}");
    assert_eq!(variance.workspace_build_regression_count, 4, "{variance:?}");
    assert_eq!(variance.median_workspace_build_delta_ms, 60.0);
    assert_eq!(variance.median_workspace_build_delta_pct, 30.0);
}

#[test]
fn broad_slowdown_with_uncovered_regression_remains_actionable() {
    let mut baseline_repos = broad_slowdown_repos(200.0, 100.0, 200.0);
    baseline_repos.push(repo_with_scenarios(
        "fixture-extra",
        vec![scenario_with_transport(
            BenchmarkScenario::ScanUsages,
            ScenarioTransport::Mcp,
            true,
            Some(100.0),
        )],
    ));
    let mut candidate_repos = broad_slowdown_repos(260.0, 125.0, 230.0);
    candidate_repos.push(repo_with_scenarios(
        "fixture-extra",
        vec![scenario_with_transport(
            BenchmarkScenario::ScanUsages,
            ScenarioTransport::Mcp,
            true,
            Some(500.0),
        )],
    ));

    let comparison = BenchmarkCompareReport::from_reports(
        &report_with_scenarios(baseline_repos),
        &report_with_scenarios(candidate_repos),
    );

    assert!(comparison.has_regressions, "{comparison:?}");
    assert!(comparison.has_actionable_regressions, "{comparison:?}");
    assert_eq!(comparison.regression_count, 5, "{comparison:?}");
    assert_eq!(comparison.actionable_regression_count, 1, "{comparison:?}");
    let variance = comparison
        .environment_variance
        .as_ref()
        .expect("environment variance report");
    assert_eq!(variance.covered_regression_count, 4, "{variance:?}");
}

#[test]
fn compare_subcommand_writes_json_and_fails_in_strict_mode() {
    let (output, compare_report) = run_compare_subcommand(
        report_with_scenarios(vec![repo_with_scenarios(
            "fixture-java",
            vec![scenario(
                BenchmarkScenario::WorkspaceBuild,
                true,
                Some(100.0),
            )],
        )]),
        report_with_scenarios(vec![repo_with_scenarios(
            "fixture-java",
            vec![scenario(
                BenchmarkScenario::WorkspaceBuild,
                true,
                Some(160.0),
            )],
        )]),
    );

    assert!(
        !output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("regressions detected: 1"), "{stdout}");
    assert!(
        stdout.contains("threshold: 20.0% and 50.0 ms absolute floor"),
        "{stdout}"
    );

    assert_eq!(compare_report["has_regressions"], true, "{compare_report}");
    assert_eq!(
        compare_report["has_actionable_regressions"], true,
        "{compare_report}"
    );
    assert_eq!(
        compare_report["actionable_regression_count"], 1,
        "{compare_report}"
    );
    assert_eq!(compare_report["regression_count"], 1, "{compare_report}");
}

#[test]
fn compare_subcommand_strict_mode_allows_environment_variance() {
    let (output, compare_report) = run_compare_subcommand(
        report_with_scenarios(broad_slowdown_repos(200.0, 100.0, 200.0)),
        report_with_scenarios(broad_slowdown_repos(260.0, 125.0, 230.0)),
    );

    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("regressions detected: 4"), "{stdout}");
    assert!(
        stdout.contains("suspected environment variance:"),
        "{stdout}"
    );

    assert_eq!(compare_report["has_regressions"], true, "{compare_report}");
    assert_eq!(
        compare_report["has_actionable_regressions"], false,
        "{compare_report}"
    );
    assert_eq!(
        compare_report["actionable_regression_count"], 0,
        "{compare_report}"
    );
    assert!(
        compare_report["environment_variance"].is_object(),
        "{compare_report}"
    );
}

fn run_compare_subcommand(
    baseline: BenchmarkRunReport,
    candidate: BenchmarkRunReport,
) -> (Output, Value) {
    let temp = TempDir::new().expect("temp dir");
    let baseline_path = temp.path().join("baseline.json");
    let candidate_path = temp.path().join("candidate.json");
    let output_path = temp.path().join("compare.json");

    fs::write(
        &baseline_path,
        serde_json::to_string_pretty(&baseline).expect("serialize baseline"),
    )
    .expect("write baseline");
    fs::write(
        &candidate_path,
        serde_json::to_string_pretty(&candidate).expect("serialize candidate"),
    )
    .expect("write candidate");

    let output = Command::new(env!("CARGO_BIN_EXE_bifrost_benchmark"))
        .arg("compare")
        .arg("--baseline")
        .arg(&baseline_path)
        .arg("--candidate")
        .arg(&candidate_path)
        .arg("--output")
        .arg(&output_path)
        .arg("--strict")
        .output()
        .expect("run bifrost_benchmark compare");
    let compare_report =
        serde_json::from_str(&fs::read_to_string(output_path).expect("read compare report"))
            .expect("parse compare report");
    (output, compare_report)
}

fn report_with_scenarios(repos: Vec<BenchmarkRepoReport>) -> BenchmarkRunReport {
    BenchmarkRunReport {
        generated_at: "2026-06-04T14:00:00Z".to_string(),
        manifest_path: "benchmark/targets.toml".to_string(),
        bifrost_commit: Some("deadbeef".to_string()),
        selected_repo: None,
        max_files: None,
        repos,
    }
}

fn repo_with_scenarios(name: &str, scenarios: Vec<ScenarioReport>) -> BenchmarkRepoReport {
    BenchmarkRepoReport {
        name: name.to_string(),
        url: format!("https://example.com/{name}.git"),
        commit: "deadbeef".to_string(),
        checkout_path: PathBuf::from(format!("/tmp/{name}")),
        workspace_path: PathBuf::from(format!("/tmp/{name}")),
        subset_max_files: None,
        scenarios,
    }
}

fn scenario(name: BenchmarkScenario, success: bool, median_ms: Option<f64>) -> ScenarioReport {
    scenario_with_transport(name, ScenarioTransport::Mcp, success, median_ms)
}

fn query_scenario(case_id: &str, median_ms: f64) -> ScenarioReport {
    scenario(BenchmarkScenario::QueryCode, true, Some(median_ms)).with_case_id(case_id.to_string())
}

fn query_scenario_with_first(
    case_id: &str,
    first_duration_ms: f64,
    median_ms: f64,
) -> ScenarioReport {
    let mut scenario = query_scenario(case_id, median_ms);
    scenario.first_duration_ms = Some(first_duration_ms);
    scenario
}

fn scenario_with_transport(
    name: BenchmarkScenario,
    transport: ScenarioTransport,
    success: bool,
    median_ms: Option<f64>,
) -> ScenarioReport {
    let measured_durations_ms = median_ms.into_iter().collect::<Vec<_>>();
    ScenarioReport::from_timings(
        name,
        transport,
        success,
        Vec::new(),
        measured_durations_ms,
        (!success).then_some("scenario failed".to_string()),
    )
}

fn broad_slowdown_repos(
    workspace_build_ms: f64,
    search_symbols_ms: f64,
    get_summaries_ms: f64,
) -> Vec<BenchmarkRepoReport> {
    ["fixture-a", "fixture-b", "fixture-c", "fixture-d"]
        .into_iter()
        .map(|name| {
            repo_with_scenarios(
                name,
                vec![
                    scenario_with_transport(
                        BenchmarkScenario::WorkspaceBuild,
                        ScenarioTransport::Direct,
                        true,
                        Some(workspace_build_ms),
                    ),
                    scenario_with_transport(
                        BenchmarkScenario::SearchSymbols,
                        ScenarioTransport::Mcp,
                        true,
                        Some(search_symbols_ms),
                    ),
                    scenario_with_transport(
                        BenchmarkScenario::GetSummaries,
                        ScenarioTransport::Mcp,
                        true,
                        Some(get_summaries_ms),
                    ),
                ],
            )
        })
        .collect()
}

fn find_scenario<'a>(
    report: &'a BenchmarkCompareReport,
    repo_name: &str,
    scenario: BenchmarkScenario,
) -> &'a brokk_bifrost::benchmark::ScenarioCompareReport {
    report
        .scenarios
        .iter()
        .find(|entry| entry.repo_name == repo_name && entry.scenario == scenario)
        .expect("scenario present")
}
