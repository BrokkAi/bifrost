//! Decision-grade measurement harness for composed CodeQuery execution.
//!
//! This stays inside the crate's test build so Milestone 2 can inspect the
//! internal execution profile without prematurely making it a supported public
//! surface. Run the optimized benchmark with:
//!
//! ```text
//! BIFROST_SEMANTIC_INDEX=off \
//!   cargo test --release --lib code_query_execution_profile_measurement \
//!   -- --ignored --nocapture
//! ```
//!
//! The first request for every case uses a fresh analyzer. Later requests reuse
//! that analyzer but receive a new request-local `QueryExecutionState`, which
//! deliberately distinguishes analyzer-generation cache warmth from sibling
//! reuse inside one composed request.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Instant;

use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

use super::plan::PhysicalQueryOperator;
use super::profile::QueryExecutionProfile;
use crate::analyzer::structural::query::{CodeQuery, MAX_LIMIT};
use crate::analyzer::structural::search::{
    CodeQueryCompletion, CodeQueryExecutionLimits, CodeQueryExecutionWork, DetailedCodeQueryResult,
    execute_code_query_detailed, execute_code_query_profiled,
};
use crate::{AnalyzerConfig, IAnalyzer, Language, Project, TestProject, WorkspaceAnalyzer};

const RESULT_PREFIX: &str = "BIFROST_CODE_QUERY_EXECUTION_BENCHMARK=";
const SMALL_FILES_ENV: &str = "BIFROST_CODE_QUERY_BENCH_SMALL_FILES";
const LARGE_FILES_ENV: &str = "BIFROST_CODE_QUERY_BENCH_LARGE_FILES";
const ITERATIONS_ENV: &str = "BIFROST_CODE_QUERY_BENCH_ITERATIONS";
const ROUND_ENV: &str = "BIFROST_CODE_QUERY_BENCH_ROUND";
const DEFAULT_SMALL_FILES: usize = 16;
const DEFAULT_LARGE_FILES: usize = 128;
const DEFAULT_ITERATIONS: usize = 8;
const MEMO_CACHE_BUDGET_BYTES: u64 = 2 * 1024 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum BenchmarkScale {
    Small,
    Large,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum BranchRelationship {
    Identical,
    Distinct,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ExecutionMode {
    Profiled,
    Unprofiled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum CacheState {
    FreshAnalyzerFirstRequest,
    SameAnalyzerLaterRequest,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
struct StructuralCacheCounts {
    extractions: u64,
    hydrations: u64,
}

impl StructuralCacheCounts {
    fn delta_from(self, earlier: Self) -> Self {
        Self {
            extractions: self.extractions.saturating_sub(earlier.extractions),
            hydrations: self.hydrations.saturating_sub(earlier.hydrations),
        }
    }
}

#[derive(Debug, Serialize)]
struct IdealizedHeadroom {
    observed_request_ns: u64,
    idealized_request_lower_bound_ns: u64,
    observed_set_ns: u64,
    idealized_set_lower_bound_ns: u64,
    branch_total_ns: Vec<u64>,
    set_self_ns: u64,
    merge_ns: u64,
    potential_savings_ns: u64,
    potential_savings_pct: f64,
}

#[derive(Debug, Serialize)]
struct ExecutionSample {
    cache_state: CacheState,
    mode: ExecutionMode,
    iteration: Option<usize>,
    order_in_iteration: usize,
    elapsed_ns: u64,
    profile_total_elapsed_ns: Option<u64>,
    result_count: usize,
    completion: CodeQueryCompletion,
    truncated: bool,
    result_sha256: String,
    work: CodeQueryExecutionWork,
    structural_cache: StructuralCacheCounts,
    idealized_headroom: Option<IdealizedHeadroom>,
    #[serde(skip_serializing_if = "Option::is_none")]
    profile: Option<QueryExecutionProfile>,
}

#[derive(Debug, Serialize)]
struct TimingSummary {
    samples: usize,
    min_ns: u64,
    median_ns: u64,
    median_absolute_deviation_ns: u64,
    max_ns: u64,
}

#[derive(Debug, Serialize)]
struct IdealizedHeadroomSummary {
    samples: usize,
    median_observed_request_ns: u64,
    median_idealized_request_lower_bound_ns: u64,
    median_potential_savings_ns: u64,
    potential_savings_pct_from_medians: f64,
}

#[derive(Debug, Serialize)]
struct CaseResult {
    name: String,
    fixture: &'static str,
    language: &'static str,
    scale: BenchmarkScale,
    branch_relationship: BranchRelationship,
    shared_dependency: Option<&'static str>,
    headroom_eligible: bool,
    workspace_files: usize,
    workspace_source_bytes: u64,
    expected_results: usize,
    query: Value,
    analyzer_build_ns: u64,
    cold: ExecutionSample,
    warm: Vec<ExecutionSample>,
    warm_profiled_timing: TimingSummary,
    warm_unprofiled_timing: TimingSummary,
    profiling_overhead_pct: f64,
    paired_profiling_overhead_median_pct: f64,
    idealized_headroom: Option<IdealizedHeadroomSummary>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct BenchmarkProvenance {
    bifrost_commit: Option<String>,
    bifrost_dirty: Option<bool>,
    bifrost_tree_fingerprint: Option<String>,
    rustc_version_verbose: Option<String>,
    operating_system: String,
    architecture: String,
    system_identity: Option<String>,
    cpu_model: Option<String>,
    logical_parallelism: Option<usize>,
    build_profile: &'static str,
    pointer_width_bits: usize,
    crate_version: &'static str,
    timer: &'static str,
}

#[derive(Debug, Serialize)]
struct BenchmarkConfiguration {
    small_files_per_branch: usize,
    large_files_per_branch: usize,
    warm_iterations_per_mode: usize,
    analyzer_parallelism: usize,
    memo_cache_budget_bytes: u64,
    maximum_query_results: usize,
    physical_execution: &'static str,
    headroom_model: &'static str,
    headroom_assumptions: [&'static str; 3],
    execution_limits: BenchmarkExecutionLimits,
}

#[derive(Debug, Serialize)]
struct BenchmarkExecutionLimits {
    max_scanned_files: usize,
    max_scanned_source_bytes: usize,
    max_fact_nodes: usize,
    max_pipeline_rows: usize,
}

#[derive(Debug, Serialize)]
struct BenchmarkResult {
    format: &'static str,
    kind: &'static str,
    round: usize,
    provenance: BenchmarkProvenance,
    configuration: BenchmarkConfiguration,
    cases: Vec<CaseResult>,
}

#[derive(Debug, Clone, Copy, Default)]
struct FixtureStats {
    files: usize,
    source_bytes: u64,
}

#[derive(Debug)]
struct CaseSpec {
    name: &'static str,
    branch_relationship: BranchRelationship,
    shared_dependency: Option<&'static str>,
    headroom_eligible: bool,
    expected_results: usize,
    expected_branch_results: usize,
    query: CodeQuery,
}

fn positive_env(name: &str, default: usize, maximum: usize) -> usize {
    match std::env::var(name) {
        Ok(raw) => {
            let value = raw
                .parse::<usize>()
                .unwrap_or_else(|_| panic!("{name} must be a positive integer, got {raw:?}"));
            assert!(
                (1..=maximum).contains(&value),
                "{name} must be between 1 and {maximum}, got {value}"
            );
            value
        }
        Err(std::env::VarError::NotPresent) => default,
        Err(error) => panic!("failed to read {name}: {error}"),
    }
}

fn non_negative_env(name: &str) -> usize {
    match std::env::var(name) {
        Ok(raw) => raw
            .parse::<usize>()
            .unwrap_or_else(|_| panic!("{name} must be a non-negative integer, got {raw:?}")),
        Err(std::env::VarError::NotPresent) => 0,
        Err(error) => panic!("failed to read {name}: {error}"),
    }
}

fn write_fixture_file(
    root: &Path,
    relative: impl AsRef<Path>,
    source: &str,
    stats: &mut FixtureStats,
) {
    let path = root.join(relative);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create CodeQuery benchmark fixture directory");
    }
    fs::write(&path, source).expect("write CodeQuery benchmark fixture file");
    stats.files = stats.files.saturating_add(1);
    stats.source_bytes = stats
        .source_bytes
        .saturating_add(u64::try_from(source.len()).expect("source length fits u64"));
}

fn generate_typescript_fixture(root: &Path, files_per_branch: usize) -> FixtureStats {
    let mut stats = FixtureStats::default();
    write_fixture_file(
        root,
        "shared.ts",
        "export function shared_target(): void {}\n",
        &mut stats,
    );
    for index in 0..files_per_branch {
        let left = format!(
            "import {{ shared_target }} from \"../shared\";\n\
             export function left_{index:04}(): number {{\n    shared_target();\n    return {index};\n}}\n"
        );
        write_fixture_file(
            root,
            PathBuf::from("left").join(format!("module_{index:04}.ts")),
            &left,
            &mut stats,
        );
        let right = format!(
            "import {{ shared_target }} from \"../shared\";\n\
             export function right_{index:04}(): number {{\n    shared_target();\n    return {index};\n}}\n"
        );
        write_fixture_file(
            root,
            PathBuf::from("right").join(format!("module_{index:04}.ts")),
            &right,
            &mut stats,
        );
    }
    stats
}

fn generate_java_import_fixture(root: &Path, node_count: usize) -> FixtureStats {
    let mut stats = FixtureStats::default();
    write_fixture_file(
        root,
        "bench/LeftHub.java",
        "package bench;\npublic class LeftHub {}\n",
        &mut stats,
    );
    write_fixture_file(
        root,
        "bench/RightHub.java",
        "package bench;\npublic class RightHub {}\n",
        &mut stats,
    );
    for index in 0..node_count {
        let source = format!(
            "package bench;\n\
             import bench.LeftHub;\n\
             import bench.RightHub;\n\
             public class Node{index:04} {{\n\
             \x20   LeftHub left;\n\
             \x20   RightHub right;\n\
             }}\n"
        );
        write_fixture_file(
            root,
            format!("bench/Node{index:04}.java"),
            &source,
            &mut stats,
        );
    }
    stats
}

fn parse_query(value: Value) -> CodeQuery {
    CodeQuery::from_json(&value).expect("benchmark CodeQuery must parse")
}

fn typescript_cases(files_per_branch: usize) -> Vec<CaseSpec> {
    let left_exact = json!({
        "where": ["left/module_0000.ts"],
        "languages": ["typescript"],
        "match": { "kind": "function", "name": "left_0000" }
    });
    let right_exact = json!({
        "where": ["right/module_0000.ts"],
        "languages": ["typescript"],
        "match": { "kind": "function", "name": "right_0000" }
    });
    let left_broad = json!({
        "where": ["left/*.ts"],
        "languages": ["typescript"],
        "match": { "kind": "function", "name": { "regex": "^left_[0-9]+$" } }
    });
    let right_broad = json!({
        "where": ["right/*.ts"],
        "languages": ["typescript"],
        "match": { "kind": "function", "name": { "regex": "^right_[0-9]+$" } }
    });
    let shared_references = json!({
        "where": ["shared.ts"],
        "languages": ["typescript"],
        "match": { "kind": "function", "name": "shared_target" },
        "steps": [
            { "op": "enclosing_decl" },
            { "op": "references_of", "proof": "proven", "reference_kinds": ["method_call"] }
        ]
    });
    vec![
        CaseSpec {
            name: "identical_exact_union",
            branch_relationship: BranchRelationship::Identical,
            shared_dependency: Some("exact structural seed"),
            headroom_eligible: false,
            expected_results: 1,
            expected_branch_results: 1,
            query: parse_query(json!({
                "union": [left_exact.clone(), left_exact],
                "limit": MAX_LIMIT
            })),
        },
        CaseSpec {
            name: "distinct_exact_union",
            branch_relationship: BranchRelationship::Distinct,
            shared_dependency: None,
            headroom_eligible: true,
            expected_results: 2,
            expected_branch_results: 1,
            query: parse_query(json!({
                "union": [left_exact, right_exact],
                "limit": MAX_LIMIT
            })),
        },
        CaseSpec {
            name: "identical_broad_union",
            branch_relationship: BranchRelationship::Identical,
            shared_dependency: Some("exact structural seed"),
            headroom_eligible: false,
            expected_results: files_per_branch,
            expected_branch_results: files_per_branch,
            query: parse_query(json!({
                "union": [left_broad.clone(), left_broad],
                "limit": MAX_LIMIT
            })),
        },
        CaseSpec {
            name: "distinct_broad_union",
            branch_relationship: BranchRelationship::Distinct,
            shared_dependency: None,
            headroom_eligible: true,
            expected_results: files_per_branch.saturating_mul(2),
            expected_branch_results: files_per_branch,
            query: parse_query(json!({
                "union": [left_broad, right_broad],
                "limit": MAX_LIMIT
            })),
        },
        CaseSpec {
            name: "identical_shared_reference_union",
            branch_relationship: BranchRelationship::Identical,
            shared_dependency: Some("complete inbound reference relation"),
            headroom_eligible: false,
            expected_results: files_per_branch.saturating_mul(2),
            expected_branch_results: files_per_branch.saturating_mul(2),
            query: parse_query(json!({
                "union": [shared_references.clone(), shared_references],
                "limit": MAX_LIMIT
            })),
        },
    ]
}

fn java_import_case(node_count: usize) -> CaseSpec {
    let branch = |side: &str| {
        json!({
            "where": [format!("bench/{side}Hub.java")],
            "languages": ["java"],
            "match": { "kind": "class", "name": format!("{side}Hub") },
            "steps": [{ "op": "file_of" }, { "op": "importers_of" }]
        })
    };
    CaseSpec {
        name: "distinct_shared_import_graph_union",
        branch_relationship: BranchRelationship::Distinct,
        shared_dependency: Some("complete direct import graph"),
        headroom_eligible: false,
        expected_results: node_count,
        expected_branch_results: node_count,
        query: parse_query(json!({
            "union": [branch("Left"), branch("Right")],
            "limit": MAX_LIMIT
        })),
    }
}

fn structural_cache_counts(analyzer: &dyn IAnalyzer) -> StructuralCacheCounts {
    analyzer.structural_search_providers().into_iter().fold(
        StructuralCacheCounts::default(),
        |counts, provider| StructuralCacheCounts {
            extractions: counts
                .extractions
                .saturating_add(provider.structural_extraction_count()),
            hydrations: counts
                .hydrations
                .saturating_add(provider.structural_hydration_count()),
        },
    )
}

fn sha256_json(value: &impl Serialize) -> String {
    let payload = serde_json::to_vec(value).expect("serialize CodeQuery benchmark result");
    digest_hex(Sha256::digest(payload))
}

fn digest_hex(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn idealized_headroom(profile: &QueryExecutionProfile) -> Option<IdealizedHeadroom> {
    let set = profile.operators.iter().find(|observation| {
        observation.operator == PhysicalQueryOperator::SequentialUnion
            && observation.branch.is_empty()
    })?;
    let branch_count = profile
        .operators
        .iter()
        .filter_map(|observation| observation.branch.first().copied())
        .max()?
        .saturating_add(1);
    let branch_total_ns = (0..branch_count)
        .map(|branch| {
            profile
                .operators
                .iter()
                .filter(|observation| observation.branch.first() == Some(&branch))
                .map(|observation| observation.total_elapsed_ns)
                .max()
                .unwrap_or(0)
        })
        .collect::<Vec<_>>();
    if branch_total_ns.len() < 2 || branch_total_ns.contains(&0) {
        return None;
    }
    let idealized_set_lower_bound_ns = set
        .elapsed_ns
        .saturating_add(branch_total_ns.iter().copied().max().unwrap_or(0));
    let idealized_request_lower_bound_ns = profile
        .total_elapsed_ns
        .saturating_sub(set.total_elapsed_ns)
        .saturating_add(idealized_set_lower_bound_ns);
    let potential_savings_ns = profile
        .total_elapsed_ns
        .saturating_sub(idealized_request_lower_bound_ns);
    let potential_savings_pct = percentage(potential_savings_ns, profile.total_elapsed_ns);
    Some(IdealizedHeadroom {
        observed_request_ns: profile.total_elapsed_ns,
        idealized_request_lower_bound_ns,
        observed_set_ns: set.total_elapsed_ns,
        idealized_set_lower_bound_ns,
        branch_total_ns,
        set_self_ns: set.elapsed_ns,
        merge_ns: set.merge_ns,
        potential_savings_ns,
        potential_savings_pct,
    })
}

fn percentage(numerator: u64, denominator: u64) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 * 100.0 / denominator as f64
    }
}

fn execute_sample(
    analyzer: &dyn IAnalyzer,
    query: &CodeQuery,
    mode: ExecutionMode,
    cache_state: CacheState,
    iteration: Option<usize>,
    order_in_iteration: usize,
    headroom_eligible: bool,
) -> ExecutionSample {
    let limits = CodeQueryExecutionLimits::default();
    let cache_before = structural_cache_counts(analyzer);
    let started = Instant::now();
    let detailed = match mode {
        ExecutionMode::Profiled => execute_code_query_profiled(analyzer, query, limits),
        ExecutionMode::Unprofiled => execute_code_query_detailed(analyzer, query, limits, None),
    };
    let elapsed_ns = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
    let cache_after = structural_cache_counts(analyzer);
    finish_sample(
        detailed,
        mode,
        cache_state,
        iteration,
        order_in_iteration,
        elapsed_ns,
        cache_after.delta_from(cache_before),
        headroom_eligible,
    )
}

#[allow(clippy::too_many_arguments)]
fn finish_sample(
    detailed: DetailedCodeQueryResult,
    mode: ExecutionMode,
    cache_state: CacheState,
    iteration: Option<usize>,
    order_in_iteration: usize,
    elapsed_ns: u64,
    structural_cache: StructuralCacheCounts,
    headroom_eligible: bool,
) -> ExecutionSample {
    let DetailedCodeQueryResult {
        result,
        work,
        profile,
        ..
    } = detailed;
    assert_eq!(
        profile.is_some(),
        mode == ExecutionMode::Profiled,
        "profile presence must match the requested benchmark mode"
    );
    let completion = result.completion();
    let idealized_headroom = (headroom_eligible && completion == CodeQueryCompletion::Complete)
        .then(|| profile.as_ref().and_then(idealized_headroom))
        .flatten();
    let profile_total_elapsed_ns = profile.as_ref().map(|value| value.total_elapsed_ns);
    ExecutionSample {
        cache_state,
        mode,
        iteration,
        order_in_iteration,
        elapsed_ns,
        profile_total_elapsed_ns,
        result_count: result.results.len(),
        completion,
        truncated: result.truncated,
        result_sha256: sha256_json(&result),
        work,
        structural_cache,
        idealized_headroom,
        profile,
    }
}

fn median(values: &mut [u64]) -> u64 {
    values.sort_unstable();
    let middle = values.len() / 2;
    if values.len().is_multiple_of(2) {
        let lower = values[middle - 1];
        lower.saturating_add(values[middle].saturating_sub(lower) / 2)
    } else {
        values[middle]
    }
}

fn timing_summary(samples: &[ExecutionSample], mode: ExecutionMode) -> TimingSummary {
    let mut values = samples
        .iter()
        .filter(|sample| sample.mode == mode)
        .map(|sample| sample.elapsed_ns)
        .collect::<Vec<_>>();
    assert!(!values.is_empty(), "timing summary requires samples");
    let min_ns = values.iter().copied().min().unwrap_or(0);
    let max_ns = values.iter().copied().max().unwrap_or(0);
    let median_ns = median(&mut values);
    let mut deviations = values
        .iter()
        .map(|value| value.abs_diff(median_ns))
        .collect::<Vec<_>>();
    TimingSummary {
        samples: values.len(),
        min_ns,
        median_ns,
        median_absolute_deviation_ns: median(&mut deviations),
        max_ns,
    }
}

fn paired_profiling_overhead_median_pct(samples: &[ExecutionSample]) -> f64 {
    let mut pairs = samples
        .chunks_exact(2)
        .map(|pair| {
            let profiled = pair
                .iter()
                .find(|sample| sample.mode == ExecutionMode::Profiled)
                .expect("paired iteration has a profiled sample")
                .elapsed_ns;
            let unprofiled = pair
                .iter()
                .find(|sample| sample.mode == ExecutionMode::Unprofiled)
                .expect("paired iteration has an unprofiled sample")
                .elapsed_ns;
            if unprofiled == 0 {
                0.0
            } else {
                (profiled as f64 - unprofiled as f64) * 100.0 / unprofiled as f64
            }
        })
        .collect::<Vec<_>>();
    assert!(!pairs.is_empty(), "paired overhead requires samples");
    pairs.sort_by(f64::total_cmp);
    let middle = pairs.len() / 2;
    if pairs.len().is_multiple_of(2) {
        (pairs[middle - 1] + pairs[middle]) / 2.0
    } else {
        pairs[middle]
    }
}

fn headroom_summary(samples: &[ExecutionSample]) -> Option<IdealizedHeadroomSummary> {
    let headrooms = samples
        .iter()
        .filter_map(|sample| sample.idealized_headroom.as_ref())
        .collect::<Vec<_>>();
    if headrooms.is_empty() {
        return None;
    }
    let mut observed = headrooms
        .iter()
        .map(|value| value.observed_request_ns)
        .collect::<Vec<_>>();
    let mut idealized = headrooms
        .iter()
        .map(|value| value.idealized_request_lower_bound_ns)
        .collect::<Vec<_>>();
    let mut savings = headrooms
        .iter()
        .map(|value| value.potential_savings_ns)
        .collect::<Vec<_>>();
    let median_observed_request_ns = median(&mut observed);
    let median_idealized_request_lower_bound_ns = median(&mut idealized);
    let median_potential_savings_ns = median(&mut savings);
    Some(IdealizedHeadroomSummary {
        samples: headrooms.len(),
        median_observed_request_ns,
        median_idealized_request_lower_bound_ns,
        median_potential_savings_ns,
        potential_savings_pct_from_medians: percentage(
            median_potential_savings_ns,
            median_observed_request_ns,
        ),
    })
}

fn run_case(
    root: &Path,
    stats: FixtureStats,
    language: Language,
    scale: BenchmarkScale,
    spec: CaseSpec,
    iterations: usize,
    round: usize,
) -> CaseResult {
    assert!(
        spec.expected_results <= MAX_LIMIT,
        "primary benchmark cases must remain below the public result limit"
    );
    let project: Arc<dyn Project> = Arc::new(TestProject::new(root.to_path_buf(), language));
    let build_started = Instant::now();
    let workspace = WorkspaceAnalyzer::build(
        project,
        AnalyzerConfig {
            parallelism: Some(1),
            memo_cache_budget_bytes: Some(MEMO_CACHE_BUDGET_BYTES),
            ..AnalyzerConfig::default()
        },
    );
    let analyzer_build_ns = u64::try_from(build_started.elapsed().as_nanos()).unwrap_or(u64::MAX);
    let analyzer = workspace.analyzer();
    let workspace_files = analyzer.analyzed_files().len();
    assert_eq!(workspace_files, stats.files);

    let cold = execute_sample(
        analyzer,
        &spec.query,
        ExecutionMode::Profiled,
        CacheState::FreshAnalyzerFirstRequest,
        None,
        0,
        spec.headroom_eligible,
    );
    assert_complete_expected(&cold, spec.expected_results, spec.name);
    assert!(
        cold.structural_cache.extractions > 0,
        "{} cold request must materialize structural facts",
        spec.name
    );
    assert_eq!(
        cold.structural_cache.hydrations, 0,
        "{} fresh analyzer must not inherit a persisted benchmark snapshot",
        spec.name
    );
    assert_profile_cache_contract(&cold, &spec);

    let mut warm = Vec::with_capacity(iterations.saturating_mul(2));
    for iteration in 0..iterations {
        let profiled_first = iteration.is_multiple_of(2) == round.is_multiple_of(2);
        let modes = if profiled_first {
            [ExecutionMode::Profiled, ExecutionMode::Unprofiled]
        } else {
            [ExecutionMode::Unprofiled, ExecutionMode::Profiled]
        };
        for (order, mode) in modes.into_iter().enumerate() {
            let sample = execute_sample(
                analyzer,
                &spec.query,
                mode,
                CacheState::SameAnalyzerLaterRequest,
                Some(iteration),
                order,
                spec.headroom_eligible,
            );
            assert_complete_expected(&sample, spec.expected_results, spec.name);
            assert_eq!(
                sample.result_sha256, cold.result_sha256,
                "{} cold and warm execution must be exactly deterministic",
                spec.name
            );
            assert_eq!(
                sample.structural_cache.extractions, 0,
                "{} warm request must reuse analyzer-generation structural facts",
                spec.name
            );
            assert_eq!(
                sample.structural_cache.hydrations, 0,
                "{} same-analyzer request must remain an in-memory reuse",
                spec.name
            );
            if mode == ExecutionMode::Profiled {
                assert_profile_cache_contract(&sample, &spec);
            }
            warm.push(sample);
        }
    }

    let warm_profiled_timing = timing_summary(&warm, ExecutionMode::Profiled);
    let warm_unprofiled_timing = timing_summary(&warm, ExecutionMode::Unprofiled);
    let profiling_overhead_pct = if warm_unprofiled_timing.median_ns == 0 {
        0.0
    } else {
        (warm_profiled_timing.median_ns as f64 - warm_unprofiled_timing.median_ns as f64) * 100.0
            / warm_unprofiled_timing.median_ns as f64
    };
    let paired_profiling_overhead_median_pct = paired_profiling_overhead_median_pct(&warm);
    let idealized_headroom = headroom_summary(&warm);
    assert_eq!(
        idealized_headroom.is_some(),
        spec.headroom_eligible,
        "headroom must be emitted only for eligible distinct complete branches"
    );

    CaseResult {
        name: format!(
            "{}_{}",
            match scale {
                BenchmarkScale::Small => "small",
                BenchmarkScale::Large => "large",
            },
            spec.name
        ),
        fixture: match language {
            Language::TypeScript => "generated_typescript",
            Language::Java => "generated_java_import_graph",
            _ => unreachable!("benchmark only declares TypeScript and Java fixtures"),
        },
        language: language.config_label(),
        scale,
        branch_relationship: spec.branch_relationship,
        shared_dependency: spec.shared_dependency,
        headroom_eligible: spec.headroom_eligible,
        workspace_files,
        workspace_source_bytes: stats.source_bytes,
        expected_results: spec.expected_results,
        query: spec.query.to_canonical_json(),
        analyzer_build_ns,
        cold,
        warm,
        warm_profiled_timing,
        warm_unprofiled_timing,
        profiling_overhead_pct,
        paired_profiling_overhead_median_pct,
        idealized_headroom,
    }
}

fn assert_profile_cache_contract(sample: &ExecutionSample, spec: &CaseSpec) {
    let profile = sample.profile.as_ref().expect("profiled cache contract");
    let seed = profile.cache.seed_result;
    assert_eq!(seed.lookups, 2, "{} seed lookups", spec.name);
    match spec.branch_relationship {
        BranchRelationship::Identical => {
            assert_eq!(seed.misses, 1, "{} first seed build", spec.name);
            assert_eq!(seed.complete_builds, 1, "{} complete seed build", spec.name);
            assert_eq!(seed.hits, 1, "{} sibling seed hit", spec.name);
            assert_eq!(seed.complete_hits, 1, "{} complete sibling hit", spec.name);
        }
        BranchRelationship::Distinct => {
            assert_eq!(seed.misses, 2, "{} distinct seed builds", spec.name);
            assert_eq!(
                seed.complete_builds, 2,
                "{} complete seed builds",
                spec.name
            );
            assert_eq!(
                seed.hits, 0,
                "{} has no request-local seed reuse",
                spec.name
            );
        }
    }

    let facts = profile.cache.seed_structural_facts;
    assert!(facts.lookups > 0, "{} must observe seed facts", spec.name);
    assert_eq!(facts.persisted_hydrations, 0, "{} hydration", spec.name);
    assert_eq!(facts.unavailable, 0, "{} unavailable facts", spec.name);
    assert_eq!(facts.unknown_outcomes, 0, "{} unknown facts", spec.name);
    match sample.cache_state {
        CacheState::FreshAnalyzerFirstRequest => {
            assert!(facts.extractions > 0, "{} cold extraction", spec.name);
            assert_eq!(facts.memory_hits, 0, "{} cold memory hits", spec.name);
        }
        CacheState::SameAnalyzerLaterRequest => {
            assert_eq!(facts.extractions, 0, "{} warm extraction", spec.name);
            assert!(facts.memory_hits > 0, "{} warm memory hit", spec.name);
        }
    }

    let reverse = profile.cache.import_reverse;
    if spec.shared_dependency == Some("complete direct import graph") {
        assert_eq!(reverse.lookups, 2, "{} import lookups", spec.name);
        assert_eq!(reverse.misses, 1, "{} import build miss", spec.name);
        assert_eq!(reverse.complete_builds, 1, "{} import build", spec.name);
        assert_eq!(reverse.hits, 1, "{} import sibling hit", spec.name);
        assert_eq!(
            reverse.complete_hits, 1,
            "{} complete import hit",
            spec.name
        );
        assert_eq!(
            reverse.replayed_items,
            u64::try_from(spec.expected_branch_results).unwrap_or(u64::MAX),
            "{} relevant reverse edges replayed",
            spec.name
        );
        let build = profile
            .operators
            .iter()
            .find(|observation| observation.cache.import_reverse.complete_builds == 1)
            .expect("import benchmark observes the graph builder");
        assert_eq!(
            build.work.import_files_resolved,
            u64::try_from(spec.expected_branch_results.saturating_add(2)).unwrap_or(u64::MAX),
            "{} import files resolved",
            spec.name
        );
        assert_eq!(
            build.work.import_edges_resolved,
            u64::try_from(spec.expected_branch_results.saturating_mul(2)).unwrap_or(u64::MAX),
            "{} import edges resolved",
            spec.name
        );
    } else {
        assert_eq!(reverse.lookups, 0, "{} has no import dependency", spec.name);
    }

    let inbound = profile.cache.inbound_reference;
    if spec.shared_dependency == Some("complete inbound reference relation") {
        assert_eq!(inbound.lookups, 2, "{} reference lookups", spec.name);
        assert_eq!(inbound.misses, 1, "{} reference build miss", spec.name);
        assert_eq!(
            inbound.complete_builds, 1,
            "{} complete reference build",
            spec.name
        );
        assert_eq!(inbound.hits, 1, "{} reference sibling hit", spec.name);
        assert_eq!(
            inbound.complete_hits, 1,
            "{} complete reference hit",
            spec.name
        );
        assert!(
            inbound.replayed_items
                >= u64::try_from(spec.expected_branch_results).unwrap_or(u64::MAX),
            "{} cached reference payload must cover every emitted branch result",
            spec.name
        );
    } else {
        assert_eq!(
            inbound.lookups, 0,
            "{} has no reference dependency",
            spec.name
        );
    }

    for branch in 0..2 {
        let branch_root = profile
            .operators
            .iter()
            .filter(|observation| observation.branch == [branch])
            .max_by_key(|observation| observation.total_elapsed_ns)
            .expect("each composed benchmark branch has an observed root");
        assert_eq!(
            branch_root.output_rows, spec.expected_branch_results,
            "{} branch {branch} output cardinality",
            spec.name
        );
    }
}

fn assert_complete_expected(sample: &ExecutionSample, expected: usize, name: &str) {
    assert_eq!(sample.result_count, expected, "{name} result count");
    assert_eq!(
        sample.completion,
        CodeQueryCompletion::Complete,
        "{name} must remain a complete primary timing case"
    );
    assert!(!sample.truncated, "{name} must not be truncated");
    if sample.mode == ExecutionMode::Profiled {
        assert_eq!(
            sample
                .profile
                .as_ref()
                .map(|profile| profile.peak_concurrency),
            Some(1),
            "M2 profile must remain sequential"
        );
    }
}

fn git_commit(root: &Path) -> Option<String> {
    command_output_in(root, "git", &["rev-parse", "HEAD"])
}

fn git_dirty(root: &Path) -> Option<bool> {
    command_output_in(
        root,
        "git",
        &["status", "--porcelain", "--untracked-files=normal"],
    )
    .map(|status| !status.is_empty())
}

fn git_tree_fingerprint(root: &Path) -> Option<String> {
    let commit = git_commit(root)?;
    let diff = Command::new("git")
        .current_dir(root)
        .args(["diff", "--binary", "HEAD", "--"])
        .output()
        .ok()
        .filter(|output| output.status.success())?;
    let untracked = Command::new("git")
        .current_dir(root)
        .args(["ls-files", "--others", "--exclude-standard", "-z"])
        .output()
        .ok()
        .filter(|output| output.status.success())?;
    let mut hasher = Sha256::new();
    hasher.update(commit.as_bytes());
    hasher.update(&diff.stdout);
    for raw_path in untracked.stdout.split(|byte| *byte == 0) {
        if raw_path.is_empty() {
            continue;
        }
        let relative = std::str::from_utf8(raw_path).ok()?;
        let contents = fs::read(root.join(relative)).ok()?;
        hasher.update(u64::try_from(raw_path.len()).ok()?.to_le_bytes());
        hasher.update(raw_path);
        hasher.update(u64::try_from(contents.len()).ok()?.to_le_bytes());
        hasher.update(contents);
    }
    Some(digest_hex(hasher.finalize()))
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

fn cpu_model() -> Option<String> {
    if cfg!(target_os = "macos") {
        command_output("sysctl", &["-n", "machdep.cpu.brand_string"])
            .or_else(|| command_output("sysctl", &["-n", "hw.model"]))
            .or_else(|| {
                command_output("system_profiler", &["SPHardwareDataType"]).and_then(|output| {
                    output.lines().find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        matches!(name.trim(), "Chip" | "Processor Name")
                            .then(|| value.trim().to_owned())
                    })
                })
            })
    } else if cfg!(target_os = "linux") {
        fs::read_to_string("/proc/cpuinfo")
            .ok()
            .and_then(|contents| {
                contents.lines().find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    matches!(name.trim(), "model name" | "Hardware")
                        .then(|| value.trim().to_owned())
                })
            })
    } else {
        std::env::var("PROCESSOR_IDENTIFIER").ok()
    }
}

fn provenance() -> BenchmarkProvenance {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_owned());
    BenchmarkProvenance {
        bifrost_commit: git_commit(root),
        bifrost_dirty: git_dirty(root),
        bifrost_tree_fingerprint: git_tree_fingerprint(root),
        rustc_version_verbose: command_output(&rustc, &["--version", "--verbose"]),
        operating_system: std::env::consts::OS.to_owned(),
        architecture: std::env::consts::ARCH.to_owned(),
        system_identity: command_output("uname", &["-a"]),
        cpu_model: cpu_model(),
        logical_parallelism: std::thread::available_parallelism()
            .ok()
            .map(std::num::NonZeroUsize::get),
        build_profile: if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        },
        pointer_width_bits: usize::BITS as usize,
        crate_version: env!("CARGO_PKG_VERSION"),
        timer: "std::time::Instant monotonic elapsed wall time",
    }
}

fn run_typescript_scale(
    scale: BenchmarkScale,
    files_per_branch: usize,
    iterations: usize,
    round: usize,
) -> Vec<CaseResult> {
    let temp = TempDir::new().expect("TypeScript CodeQuery benchmark temp directory");
    let root = temp
        .path()
        .canonicalize()
        .expect("canonicalize TypeScript benchmark root");
    let stats = generate_typescript_fixture(&root, files_per_branch);
    let mut specs = typescript_cases(files_per_branch);
    if !round.is_multiple_of(2) {
        specs.reverse();
    }
    specs
        .into_iter()
        .map(|spec| {
            run_case(
                &root,
                stats,
                Language::TypeScript,
                scale,
                spec,
                iterations,
                round,
            )
        })
        .collect()
}

fn run_java_scale(
    scale: BenchmarkScale,
    node_count: usize,
    iterations: usize,
    round: usize,
) -> CaseResult {
    let temp = TempDir::new().expect("Java CodeQuery benchmark temp directory");
    let root = temp
        .path()
        .canonicalize()
        .expect("canonicalize Java benchmark root");
    let stats = generate_java_import_fixture(&root, node_count);
    run_case(
        &root,
        stats,
        Language::Java,
        scale,
        java_import_case(node_count),
        iterations,
        round,
    )
}

#[test]
#[ignore = "measure-first CodeQuery execution benchmark; run explicitly in release mode"]
fn code_query_execution_profile_measurement() {
    let small_files = positive_env(SMALL_FILES_ENV, DEFAULT_SMALL_FILES, MAX_LIMIT / 2);
    let large_files = positive_env(LARGE_FILES_ENV, DEFAULT_LARGE_FILES, MAX_LIMIT / 2);
    let iterations = positive_env(ITERATIONS_ENV, DEFAULT_ITERATIONS, 30);
    let round = non_negative_env(ROUND_ENV);
    assert!(
        small_files < large_files,
        "{SMALL_FILES_ENV} must be smaller than {LARGE_FILES_ENV}"
    );

    let scales = if round.is_multiple_of(2) {
        [
            (BenchmarkScale::Small, small_files),
            (BenchmarkScale::Large, large_files),
        ]
    } else {
        [
            (BenchmarkScale::Large, large_files),
            (BenchmarkScale::Small, small_files),
        ]
    };
    let mut cases = Vec::new();
    for (scale, files) in scales {
        cases.extend(run_typescript_scale(scale, files, iterations, round));
        cases.push(run_java_scale(scale, files, iterations, round));
    }

    let provenance = provenance();
    assert!(
        provenance.bifrost_tree_fingerprint.is_some(),
        "decision-grade benchmark must fingerprint the exact source tree"
    );
    let limits = CodeQueryExecutionLimits::default();

    let result = BenchmarkResult {
        format: "bifrost_code_query_execution_benchmark/v2",
        kind: "sample",
        round,
        provenance,
        configuration: BenchmarkConfiguration {
            small_files_per_branch: small_files,
            large_files_per_branch: large_files,
            warm_iterations_per_mode: iterations,
            analyzer_parallelism: 1,
            memo_cache_budget_bytes: MEMO_CACHE_BUDGET_BYTES,
            maximum_query_results: MAX_LIMIT,
            physical_execution: "sequential_recursive",
            headroom_model: "ideal_perfect_overlap_projection",
            headroom_assumptions: [
                "distinct complete branches share no derived dependency",
                "set self and rendering costs remain unchanged",
                "scheduler contention and dispatch overhead are zero",
            ],
            execution_limits: BenchmarkExecutionLimits {
                max_scanned_files: limits.max_scanned_files,
                max_scanned_source_bytes: limits.max_scanned_source_bytes,
                max_fact_nodes: limits.max_fact_nodes,
                max_pipeline_rows: limits.max_pipeline_rows,
            },
        },
        cases,
    };
    eprintln!(
        "{RESULT_PREFIX}{}",
        serde_json::to_string(&result).expect("serialize CodeQuery execution benchmark")
    );
}
