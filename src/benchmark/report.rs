use crate::benchmark::BenchmarkScenario;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub case_id: Option<String>,
    pub transport: ScenarioTransport,
    pub success: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_duration_ms: Option<f64>,
    pub warmup_durations_ms: Vec<f64>,
    pub measured_durations_ms: Vec<f64>,
    pub median_ms: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub p95_ms: Option<f64>,
    pub mean_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_message: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub profile_artifacts: Vec<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query_code: Option<QueryCodeBenchmarkMetrics>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryCodeBenchmarkMetrics {
    pub cold_contract: String,
    pub first: QueryCodeProfileMetrics,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warmup_transition: Option<QueryCodeProfileMetrics>,
    pub warm: QueryCodeProfileMetrics,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryCodeProfileMetrics {
    pub profile_format: String,
    pub result_cardinality: usize,
    pub truncated: bool,
    pub diagnostic_codes: Vec<String>,
    pub total_ns: u64,
    pub scanned_files: u64,
    pub scanned_source_bytes: u64,
    pub fact_nodes: u64,
    pub pipeline_rows: u64,
    pub examined_references: u64,
    pub import_files_resolved: u64,
    pub import_edges_resolved: u64,
    pub facts_cache: QueryCodeFactsCacheMetrics,
    #[serde(default)]
    pub direct_import_topology: QueryCodeDerivedLayerMetrics,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_path: Option<QueryCodeAccessPathMetrics>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryCodeFactsCacheMetrics {
    pub lookups: u64,
    pub memory_hits: u64,
    pub persisted_hydrations: u64,
    pub extractions: u64,
    pub unavailable: u64,
    pub unknown_outcomes: u64,
    pub replayed_files: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryCodeDerivedLayerMetrics {
    pub lookups: u64,
    pub hits: u64,
    pub misses: u64,
    pub builds: u64,
    pub waits: u64,
    pub wait_ns: u64,
    pub complete_hits: u64,
    pub incomplete_hits: u64,
    pub complete_builds: u64,
    pub incomplete_builds: u64,
    pub unknown_outcomes: u64,
    pub cancelled: u64,
    pub unavailable: u64,
    pub over_budget: u64,
    pub fallbacks: u64,
    pub replayed_items: u64,
    pub build_files: u64,
    pub build_edges: u64,
    pub build_ns: u64,
    pub retained_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryCodeAccessPathMetrics {
    pub selected: String,
    pub representation_version: u32,
    pub estimated_provider_files: u64,
    pub scoped_files: u64,
    pub scoped_fact_nodes: u64,
    pub admitted_fact_nodes: u64,
    pub candidate_files: u64,
    pub candidate_facts: u64,
    pub selected_terms: Vec<QueryCodeAccessPathTermMetrics>,
    pub source_verification_required: bool,
    pub cache_ready_lookups: u64,
    pub materialized_files: u64,
    pub materialized_fact_nodes: u64,
    pub inspected_source_bytes: u64,
    pub examined_fact_nodes: u64,
    pub index_lookups: u64,
    pub index_hits: u64,
    pub index_misses: u64,
    pub index_builds: u64,
    pub index_waits: u64,
    pub index_wait_ns: u64,
    pub index_cancelled: u64,
    pub index_unavailable: u64,
    pub index_over_budget: u64,
    pub scan_fallbacks: u64,
    pub index_build_files: u64,
    pub index_build_source_bytes: u64,
    pub index_build_fact_nodes: u64,
    pub index_build_facts_bytes: u64,
    pub index_build_ns: u64,
    pub retained_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryCodeAccessPathTermMetrics {
    pub label: String,
    pub candidate_facts: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BenchmarkCompareReport {
    pub thresholds: CompareThresholds,
    pub compared_scenarios_count: usize,
    pub regression_count: usize,
    pub improvement_count: usize,
    pub missing_candidate_count: usize,
    pub new_candidate_count: usize,
    pub actionable_regression_count: usize,
    pub has_regressions: bool,
    pub has_actionable_regressions: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub environment_variance: Option<EnvironmentVarianceReport>,
    pub scenarios: Vec<ScenarioCompareReport>,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct CompareThresholds {
    pub relative_pct: f64,
    pub absolute_ms: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EnvironmentVarianceReport {
    pub affected_repo_count: usize,
    pub timed_scenario_count: usize,
    pub timing_regression_count: usize,
    pub covered_regression_count: usize,
    pub workspace_build_regression_count: usize,
    pub median_workspace_build_delta_pct: f64,
    pub median_workspace_build_delta_ms: f64,
    pub detail: String,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub case_id: Option<String>,
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
            case_id: None,
            transport,
            success,
            first_duration_ms: None,
            median_ms: median_ms(&measured_durations_ms),
            p95_ms: None,
            mean_ms: mean_ms(&measured_durations_ms),
            warmup_durations_ms,
            measured_durations_ms,
            failure_message,
            profile_artifacts: Vec::new(),
            query_code: None,
        }
    }

    pub fn with_query_code(
        mut self,
        case_id: String,
        first_duration_ms: f64,
        metrics: QueryCodeBenchmarkMetrics,
    ) -> Self {
        self.case_id = Some(case_id);
        self.first_duration_ms = Some(first_duration_ms);
        self.p95_ms = percentile_ms(&self.measured_durations_ms, 95);
        self.query_code = Some(metrics);
        self
    }

    pub fn with_case_id(mut self, case_id: String) -> Self {
        self.case_id = Some(case_id);
        self
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
        let selected_repo = candidate.selected_repo.as_deref();

        let mut keys = baseline_index
            .keys()
            .filter(|key| selected_repo.is_none_or(|repo| key.repo_name == repo))
            .copied()
            .collect::<Vec<_>>();
        keys.extend(
            candidate_index
                .keys()
                .filter(|key| {
                    selected_repo.is_none_or(|repo| key.repo_name == repo)
                        && !baseline_index.contains_key(*key)
                })
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

        let environment_variance = detect_environment_variance(&scenarios, thresholds);
        let actionable_regression_count = regression_count
            - environment_variance
                .as_ref()
                .map_or(0, |variance| variance.covered_regression_count);
        let has_actionable_regressions = actionable_regression_count > 0;

        Self {
            thresholds,
            compared_scenarios_count: scenarios.len(),
            regression_count,
            improvement_count,
            missing_candidate_count,
            new_candidate_count,
            actionable_regression_count,
            has_regressions: regression_count > 0,
            has_actionable_regressions,
            environment_variance,
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

fn percentile_ms(values: &[f64], percentile: usize) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    debug_assert!((1..=100).contains(&percentile));
    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    let rank = sorted.len().saturating_mul(percentile).div_ceil(100).max(1);
    sorted.get(rank - 1).copied()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct ScenarioKey<'a> {
    repo_name: &'a str,
    scenario: BenchmarkScenario,
    case_id: Option<&'a str>,
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
                    case_id: scenario.case_id.as_deref(),
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
        .then_with(|| left.case_id.cmp(&right.case_id))
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
            case_id: key.case_id.map(str::to_string),
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
            case_id: key.case_id.map(str::to_string),
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

    let cold_ratio_failure = query_code_cold_ratio_failure(key.scenario, candidate);
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
    } else if baseline.success && candidate.success && cold_ratio_failure.is_some() {
        (ScenarioCompareOutcome::Regression, true, cold_ratio_failure)
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
        case_id: key.case_id.map(str::to_string),
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

fn query_code_cold_ratio_failure(
    scenario: BenchmarkScenario,
    candidate: &ScenarioReport,
) -> Option<String> {
    const MAX_COLD_TO_WARM_RATIO: f64 = 10.0;
    if scenario != BenchmarkScenario::QueryCode {
        return None;
    }
    let (Some(first_ms), Some(warm_median_ms)) = (candidate.first_duration_ms, candidate.median_ms)
    else {
        return None;
    };
    if !first_ms.is_finite() || !warm_median_ms.is_finite() || warm_median_ms <= 0.0 {
        return None;
    }
    let ratio = first_ms / warm_median_ms;
    (ratio > MAX_COLD_TO_WARM_RATIO).then(|| {
        format!(
            "query_code first request is {ratio:.2}x warm median, above the {MAX_COLD_TO_WARM_RATIO:.1}x retention limit"
        )
    })
}

fn relative_delta_pct(baseline_ms: f64, candidate_ms: f64) -> Option<f64> {
    (baseline_ms > 0.0).then_some(((candidate_ms - baseline_ms) / baseline_ms) * 100.0)
}

fn detect_environment_variance(
    scenarios: &[ScenarioCompareReport],
    thresholds: CompareThresholds,
) -> Option<EnvironmentVarianceReport> {
    if scenarios.iter().any(non_timing_regression) {
        return None;
    }

    let timed = scenarios
        .iter()
        .filter(|scenario| {
            scenario.baseline_success == Some(true)
                && scenario.candidate_success == Some(true)
                && scenario.delta_ms.is_some()
                && scenario.delta_pct.is_some()
        })
        .collect::<Vec<_>>();
    if timed.len() < 10 {
        return None;
    }

    let timing_regressions = timed
        .iter()
        .copied()
        .filter(|scenario| scenario.is_regression)
        .collect::<Vec<_>>();
    if timing_regressions.is_empty() {
        return None;
    }

    let workspace_builds = timed
        .iter()
        .copied()
        .filter(|scenario| {
            scenario.scenario == BenchmarkScenario::WorkspaceBuild
                && scenario.transport == ScenarioTransport::Direct
        })
        .collect::<Vec<_>>();
    let workspace_build_regressions = workspace_builds
        .iter()
        .copied()
        .filter(|scenario| scenario.is_regression)
        .collect::<Vec<_>>();
    if workspace_build_regressions.len() < 3
        || workspace_build_regressions.len() * 2 < workspace_builds.len()
    {
        return None;
    }

    let median_workspace_build_delta_ms = median_ms(
        &workspace_builds
            .iter()
            .filter_map(|scenario| scenario.delta_ms)
            .collect::<Vec<_>>(),
    )?;
    let median_workspace_build_delta_pct = median_ms(
        &workspace_builds
            .iter()
            .filter_map(|scenario| scenario.delta_pct)
            .collect::<Vec<_>>(),
    )?;
    if median_workspace_build_delta_ms < thresholds.absolute_ms
        || median_workspace_build_delta_pct < thresholds.relative_pct
    {
        return None;
    }

    let positive_delta_count = timed
        .iter()
        .filter(|scenario| scenario.delta_ms.is_some_and(|delta| delta > 0.0))
        .count();
    if positive_delta_count * 10 < timed.len() * 7 {
        return None;
    }

    let affected_repo_count = timing_regressions
        .iter()
        .map(|scenario| scenario.repo_name.as_str())
        .collect::<HashSet<_>>()
        .len();
    if affected_repo_count < 3 {
        return None;
    }

    let workspace_build_regression_repos = workspace_build_regressions
        .iter()
        .map(|scenario| scenario.repo_name.as_str())
        .collect::<HashSet<_>>();
    let covered_regression_count = timing_regressions
        .iter()
        .filter(|scenario| workspace_build_regression_repos.contains(scenario.repo_name.as_str()))
        .count();

    Some(EnvironmentVarianceReport {
        affected_repo_count,
        timed_scenario_count: timed.len(),
        timing_regression_count: timing_regressions.len(),
        covered_regression_count,
        workspace_build_regression_count: workspace_build_regressions.len(),
        median_workspace_build_delta_pct,
        median_workspace_build_delta_ms,
        detail: format!(
            "broad timing slowdown across {affected_repo_count} repos; median direct workspace_build delta={median_workspace_build_delta_ms:.1} ms ({median_workspace_build_delta_pct:.1}%)"
        ),
    })
}

fn non_timing_regression(scenario: &ScenarioCompareReport) -> bool {
    scenario.is_regression
        && !(scenario.baseline_success == Some(true)
            && scenario.candidate_success == Some(true)
            && scenario.delta_ms.is_some()
            && scenario.delta_pct.is_some())
}

#[cfg(test)]
mod tests {
    use super::percentile_ms;

    #[test]
    fn percentile_uses_nearest_rank() {
        assert_eq!(percentile_ms(&[], 95), None);
        assert_eq!(percentile_ms(&[4.0], 95), Some(4.0));
        assert_eq!(percentile_ms(&[4.0, 1.0], 95), Some(4.0));
        assert_eq!(percentile_ms(&[5.0, 1.0, 3.0], 95), Some(5.0));
        assert_eq!(
            percentile_ms(&[10.0, 9.0, 8.0, 7.0, 6.0, 5.0, 4.0, 3.0, 2.0, 1.0], 95),
            Some(10.0)
        );
    }
}
