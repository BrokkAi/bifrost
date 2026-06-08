use crate::benchmark::BenchmarkScenario;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BenchmarkRunReport {
    pub generated_at: String,
    pub manifest_path: String,
    pub bifrost_commit: Option<String>,
    pub selected_repo: Option<String>,
    pub max_files: Option<usize>,
    pub repos: Vec<BenchmarkRepoReport>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BenchmarkRepoReport {
    pub name: String,
    pub url: String,
    pub commit: String,
    pub checkout_path: PathBuf,
    pub workspace_path: PathBuf,
    pub subset_max_files: Option<usize>,
    pub scenarios: Vec<ScenarioReport>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScenarioTransport {
    Direct,
    Mcp,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScenarioReport {
    pub name: BenchmarkScenario,
    pub transport: ScenarioTransport,
    pub success: bool,
    pub warmup_durations_ms: Vec<f64>,
    pub measured_durations_ms: Vec<f64>,
    pub median_ms: Option<f64>,
    pub mean_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_message: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BenchmarkCompareReport {
    pub thresholds: CompareThresholds,
    pub compared_scenarios_count: usize,
    pub regression_count: usize,
    pub improvement_count: usize,
    pub missing_candidate_count: usize,
    pub new_candidate_count: usize,
    pub has_regressions: bool,
    pub scenarios: Vec<ScenarioCompareReport>,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct CompareThresholds {
    pub relative_pct: f64,
    pub absolute_ms: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScenarioCompareOutcome {
    Unchanged,
    Improvement,
    Regression,
    MissingCandidate,
    NewCandidate,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScenarioCompareReport {
    pub repo_name: String,
    pub scenario: BenchmarkScenario,
    pub transport: ScenarioTransport,
    pub outcome: ScenarioCompareOutcome,
    pub baseline_success: Option<bool>,
    pub candidate_success: Option<bool>,
    pub baseline_median_ms: Option<f64>,
    pub candidate_median_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delta_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delta_pct: Option<f64>,
    pub is_regression: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl ScenarioReport {
    pub fn from_timings(
        name: BenchmarkScenario,
        transport: ScenarioTransport,
        success: bool,
        warmup_durations_ms: Vec<f64>,
        measured_durations_ms: Vec<f64>,
        failure_message: Option<String>,
    ) -> Self {
        Self {
            name,
            transport,
            success,
            median_ms: median_ms(&measured_durations_ms),
            mean_ms: mean_ms(&measured_durations_ms),
            warmup_durations_ms,
            measured_durations_ms,
            failure_message,
        }
    }
}

impl BenchmarkRunReport {
    pub fn failed_scenarios_count(&self) -> usize {
        self.repos
            .iter()
            .map(BenchmarkRepoReport::failed_scenarios_count)
            .sum()
    }

    pub fn has_failures(&self) -> bool {
        self.failed_scenarios_count() > 0
    }
}

impl BenchmarkRepoReport {
    pub fn failed_scenarios_count(&self) -> usize {
        self.scenarios
            .iter()
            .filter(|scenario| !scenario.success)
            .count()
    }
}

impl BenchmarkCompareReport {
    pub const DEFAULT_RELATIVE_THRESHOLD_PCT: f64 = 20.0;
    pub const DEFAULT_ABSOLUTE_THRESHOLD_MS: f64 = 50.0;

    pub fn from_reports(baseline: &BenchmarkRunReport, candidate: &BenchmarkRunReport) -> Self {
        let thresholds = CompareThresholds::default();
        let baseline_index = index_scenarios(baseline);
        let candidate_index = index_scenarios(candidate);

        let mut keys = baseline_index.keys().copied().collect::<Vec<_>>();
        keys.extend(
            candidate_index
                .keys()
                .filter(|key| !baseline_index.contains_key(*key))
                .copied(),
        );
        keys.sort_unstable_by(compare_keys);

        let mut scenarios = Vec::with_capacity(keys.len());
        let mut regression_count = 0;
        let mut improvement_count = 0;
        let mut missing_candidate_count = 0;
        let mut new_candidate_count = 0;

        for key in keys {
            let comparison = compare_scenario_pair(
                key,
                baseline_index.get(&key).copied(),
                candidate_index.get(&key).copied(),
                thresholds,
            );
            if comparison.is_regression {
                regression_count += 1;
            }
            match comparison.outcome {
                ScenarioCompareOutcome::Improvement => improvement_count += 1,
                ScenarioCompareOutcome::MissingCandidate => missing_candidate_count += 1,
                ScenarioCompareOutcome::NewCandidate => new_candidate_count += 1,
                ScenarioCompareOutcome::Unchanged | ScenarioCompareOutcome::Regression => {}
            }
            scenarios.push(comparison);
        }

        Self {
            thresholds,
            compared_scenarios_count: scenarios.len(),
            regression_count,
            improvement_count,
            missing_candidate_count,
            new_candidate_count,
            has_regressions: regression_count > 0,
            scenarios,
        }
    }
}

impl CompareThresholds {
    pub fn is_regression(self, baseline_ms: f64, candidate_ms: f64) -> bool {
        let delta_ms = candidate_ms - baseline_ms;
        let delta_pct = relative_delta_pct(baseline_ms, candidate_ms);
        delta_ms >= self.absolute_ms && delta_pct.is_some_and(|delta| delta >= self.relative_pct)
    }

    pub fn is_improvement(self, baseline_ms: f64, candidate_ms: f64) -> bool {
        let delta_ms = candidate_ms - baseline_ms;
        let delta_pct = relative_delta_pct(baseline_ms, candidate_ms);
        delta_ms <= -self.absolute_ms && delta_pct.is_some_and(|delta| delta <= -self.relative_pct)
    }
}

impl Default for CompareThresholds {
    fn default() -> Self {
        Self {
            relative_pct: BenchmarkCompareReport::DEFAULT_RELATIVE_THRESHOLD_PCT,
            absolute_ms: BenchmarkCompareReport::DEFAULT_ABSOLUTE_THRESHOLD_MS,
        }
    }
}

fn mean_ms(values: &[f64]) -> Option<f64> {
    (!values.is_empty()).then(|| values.iter().sum::<f64>() / values.len() as f64)
}

fn median_ms(values: &[f64]) -> Option<f64> {
    if values.is_empty() {
        return None;
    }

    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    let middle = sorted.len() / 2;
    if sorted.len() % 2 == 1 {
        Some(sorted[middle])
    } else {
        Some((sorted[middle - 1] + sorted[middle]) / 2.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct ScenarioKey<'a> {
    repo_name: &'a str,
    scenario: BenchmarkScenario,
    transport: ScenarioTransport,
}

fn index_scenarios(report: &BenchmarkRunReport) -> HashMap<ScenarioKey<'_>, &ScenarioReport> {
    let mut index = HashMap::new();
    for repo in &report.repos {
        for scenario in &repo.scenarios {
            index.insert(
                ScenarioKey {
                    repo_name: repo.name.as_str(),
                    scenario: scenario.name,
                    transport: scenario.transport,
                },
                scenario,
            );
        }
    }
    index
}

fn compare_keys(left: &ScenarioKey<'_>, right: &ScenarioKey<'_>) -> std::cmp::Ordering {
    left.repo_name
        .cmp(right.repo_name)
        .then_with(|| left.scenario.cmp(&right.scenario))
        .then_with(|| left.transport.cmp(&right.transport))
}

fn compare_scenario_pair(
    key: ScenarioKey<'_>,
    baseline: Option<&ScenarioReport>,
    candidate: Option<&ScenarioReport>,
    thresholds: CompareThresholds,
) -> ScenarioCompareReport {
    match (baseline, candidate) {
        (Some(baseline), Some(candidate)) => {
            compare_present_scenarios(key, baseline, candidate, thresholds)
        }
        (Some(baseline), None) => ScenarioCompareReport {
            repo_name: key.repo_name.to_string(),
            scenario: key.scenario,
            transport: key.transport,
            outcome: ScenarioCompareOutcome::MissingCandidate,
            baseline_success: Some(baseline.success),
            candidate_success: None,
            baseline_median_ms: baseline.median_ms,
            candidate_median_ms: None,
            delta_ms: None,
            delta_pct: None,
            is_regression: true,
            detail: Some("scenario missing from candidate report".to_string()),
        },
        (None, Some(candidate)) => ScenarioCompareReport {
            repo_name: key.repo_name.to_string(),
            scenario: key.scenario,
            transport: key.transport,
            outcome: ScenarioCompareOutcome::NewCandidate,
            baseline_success: None,
            candidate_success: Some(candidate.success),
            baseline_median_ms: None,
            candidate_median_ms: candidate.median_ms,
            delta_ms: None,
            delta_pct: None,
            is_regression: false,
            detail: Some("scenario only present in candidate report".to_string()),
        },
        (None, None) => unreachable!("scenario key without baseline or candidate"),
    }
}

fn compare_present_scenarios(
    key: ScenarioKey<'_>,
    baseline: &ScenarioReport,
    candidate: &ScenarioReport,
    thresholds: CompareThresholds,
) -> ScenarioCompareReport {
    let delta_ms = match (baseline.median_ms, candidate.median_ms) {
        (Some(baseline_ms), Some(candidate_ms)) => Some(candidate_ms - baseline_ms),
        _ => None,
    };
    let delta_pct = match (baseline.median_ms, candidate.median_ms) {
        (Some(baseline_ms), Some(candidate_ms)) => relative_delta_pct(baseline_ms, candidate_ms),
        _ => None,
    };

    let (outcome, is_regression, detail) = if baseline.success && !candidate.success {
        (
            ScenarioCompareOutcome::Regression,
            true,
            Some("candidate failed after a passing baseline".to_string()),
        )
    } else if !baseline.success && candidate.success {
        (
            ScenarioCompareOutcome::Improvement,
            false,
            Some("candidate recovered from a failing baseline".to_string()),
        )
    } else if baseline.success && candidate.success {
        match (baseline.median_ms, candidate.median_ms) {
            (Some(baseline_ms), Some(candidate_ms))
                if thresholds.is_regression(baseline_ms, candidate_ms) =>
            {
                (
                    ScenarioCompareOutcome::Regression,
                    true,
                    Some(format!(
                        "median increased beyond threshold ({:.1}% and {:.1} ms floor)",
                        thresholds.relative_pct, thresholds.absolute_ms
                    )),
                )
            }
            (Some(baseline_ms), Some(candidate_ms))
                if thresholds.is_improvement(baseline_ms, candidate_ms) =>
            {
                (
                    ScenarioCompareOutcome::Improvement,
                    false,
                    Some(format!(
                        "median improved beyond threshold ({:.1}% and {:.1} ms floor)",
                        thresholds.relative_pct, thresholds.absolute_ms
                    )),
                )
            }
            _ => (ScenarioCompareOutcome::Unchanged, false, None),
        }
    } else {
        (ScenarioCompareOutcome::Unchanged, false, None)
    };

    ScenarioCompareReport {
        repo_name: key.repo_name.to_string(),
        scenario: key.scenario,
        transport: key.transport,
        outcome,
        baseline_success: Some(baseline.success),
        candidate_success: Some(candidate.success),
        baseline_median_ms: baseline.median_ms,
        candidate_median_ms: candidate.median_ms,
        delta_ms,
        delta_pct,
        is_regression,
        detail,
    }
}

fn relative_delta_pct(baseline_ms: f64, candidate_ms: f64) -> Option<f64> {
    (baseline_ms > 0.0).then_some(((candidate_ms - baseline_ms) / baseline_ms) * 100.0)
}
