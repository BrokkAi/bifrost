use brokk_bifrost::benchmark::{
    BenchmarkCompareReport, BenchmarkRepoReport, BenchmarkRunReport, BenchmarkScenario,
    ScenarioCompareOutcome, ScenarioReport, ScenarioTransport,
};
use serde_json::Value;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
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
    assert_eq!(comparison.regression_count, 2, "{comparison:?}");
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
fn compare_subcommand_writes_json_and_fails_in_strict_mode() {
    let temp = TempDir::new().expect("temp dir");
    let baseline_path = temp.path().join("baseline.json");
    let candidate_path = temp.path().join("candidate.json");
    let output_path = temp.path().join("compare.json");

    fs::write(
        &baseline_path,
        serde_json::to_string_pretty(&report_with_scenarios(vec![repo_with_scenarios(
            "fixture-java",
            vec![scenario(
                BenchmarkScenario::WorkspaceBuild,
                true,
                Some(100.0),
            )],
        )]))
        .expect("serialize baseline"),
    )
    .expect("write baseline");
    fs::write(
        &candidate_path,
        serde_json::to_string_pretty(&report_with_scenarios(vec![repo_with_scenarios(
            "fixture-java",
            vec![scenario(
                BenchmarkScenario::WorkspaceBuild,
                true,
                Some(160.0),
            )],
        )]))
        .expect("serialize candidate"),
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

    let compare_report: Value =
        serde_json::from_str(&fs::read_to_string(output_path).expect("read compare report"))
            .expect("parse compare report");
    assert_eq!(compare_report["has_regressions"], true, "{compare_report}");
    assert_eq!(compare_report["regression_count"], 1, "{compare_report}");
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
    let measured_durations_ms = median_ms.into_iter().collect::<Vec<_>>();
    ScenarioReport::from_timings(
        name,
        ScenarioTransport::Mcp,
        success,
        Vec::new(),
        measured_durations_ms,
        (!success).then_some("scenario failed".to_string()),
    )
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
