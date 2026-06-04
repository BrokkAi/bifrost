use crate::benchmark::BenchmarkScenario;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BenchmarkRunReport {
    pub generated_at: String,
    pub manifest_path: String,
    pub bifrost_commit: Option<String>,
    pub selected_repo: Option<String>,
    pub repos: Vec<BenchmarkRepoReport>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BenchmarkRepoReport {
    pub name: String,
    pub url: String,
    pub commit: String,
    pub checkout_path: PathBuf,
    pub scenarios: Vec<ScenarioReport>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
