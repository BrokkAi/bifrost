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

use std::collections::BTreeSet;
use std::fs;
use std::io;
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
    UnionExecutionStrategy, execute_code_query_with_union_strategy,
};
use crate::{
    AnalyzerConfig, FileSetProject, IAnalyzer, Language, Project, ProjectFile, TestProject,
    WorkspaceAnalyzer, analyzer::AnalyzerQueryScope,
};

const RESULT_PREFIX: &str = "BIFROST_CODE_QUERY_EXECUTION_BENCHMARK=";
const SMALL_FILES_ENV: &str = "BIFROST_CODE_QUERY_BENCH_SMALL_FILES";
const LARGE_FILES_ENV: &str = "BIFROST_CODE_QUERY_BENCH_LARGE_FILES";
const ITERATIONS_ENV: &str = "BIFROST_CODE_QUERY_BENCH_ITERATIONS";
const ROUND_ENV: &str = "BIFROST_CODE_QUERY_BENCH_ROUND";
const PARALLEL_SIZES_ENV: &str = "BIFROST_CODE_QUERY_PARALLEL_BENCH_SIZES";
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

#[derive(Debug, Serialize)]
struct CandidateTimingPair {
    iteration: usize,
    candidate: &'static str,
    first: &'static str,
    baseline_sequential_ns: u64,
    candidate_ns: u64,
    savings_ns: i128,
    savings_pct: f64,
}

#[derive(Debug, Serialize)]
struct CandidateTimingSummary {
    samples: usize,
    baseline_sequential_median_ns: u64,
    candidate_median_ns: u64,
    median_savings_ns: i128,
    savings_pct_from_medians: f64,
    candidate_wins: usize,
}

#[derive(Debug, Serialize)]
struct ParallelSchedulerSummary {
    worker_limit: usize,
    tasks_enqueued: usize,
    tasks_completed: usize,
    tasks_observed_cancelled_before_start: usize,
    peak_concurrency: usize,
    queue_wait_ns: u64,
    worker_task_elapsed_ns: u64,
    budget_wait_ns: u64,
    coordinator_wait_ns: u64,
    dispatch_overhead_ns: u64,
}

#[derive(Debug, Serialize)]
struct ParallelCaseResult {
    name: String,
    files_per_branch: usize,
    workspace_files: usize,
    workspace_source_bytes: u64,
    candidate_files_per_branch: usize,
    cold: CandidateTimingPair,
    warm: Vec<CandidateTimingPair>,
    warm_summary: CandidateTimingSummary,
    result_sha256: String,
    work: CodeQueryExecutionWork,
    scheduler: ParallelSchedulerSummary,
    auto_selected_parallel: bool,
    auto_cold: CandidateTimingPair,
    auto_warm: Vec<CandidateTimingPair>,
    auto_warm_summary: CandidateTimingSummary,
}

#[derive(Debug, Serialize)]
struct ParallelBenchmarkResult {
    format: &'static str,
    kind: &'static str,
    round: usize,
    provenance: BenchmarkProvenance,
    scheduler_workers: usize,
    warm_iterations_per_strategy: usize,
    cache_contract: [&'static str; 3],
    cases: Vec<ParallelCaseResult>,
}

#[derive(Debug, Clone, Copy, Default)]
struct FixtureStats {
    files: usize,
    source_bytes: u64,
}

/// Fixed benchmark sources with a caller-owned, strategy-private durable
/// store. This preserves real snapshot encoding and SQLite writes without
/// allowing one cold candidate to hydrate another candidate's artifacts.
struct PersistentFileSetProject {
    sources: FileSetProject,
    persistence_root: PathBuf,
}

impl PersistentFileSetProject {
    fn new(
        source_root: &Path,
        paths: impl IntoIterator<Item = PathBuf>,
        persistence_root: &Path,
    ) -> Self {
        Self {
            sources: FileSetProject::new(source_root.to_path_buf(), paths),
            persistence_root: persistence_root.to_path_buf(),
        }
    }
}

impl Project for PersistentFileSetProject {
    fn root(&self) -> &Path {
        self.sources.root()
    }

    fn analyzer_languages(&self) -> BTreeSet<Language> {
        self.sources.analyzer_languages()
    }

    fn all_files(&self) -> io::Result<BTreeSet<ProjectFile>> {
        self.sources.all_files()
    }

    fn analyzable_files(&self, language: Language) -> io::Result<BTreeSet<ProjectFile>> {
        self.sources.analyzable_files(language)
    }

    fn file_by_rel_path(&self, rel_path: &Path) -> Option<ProjectFile> {
        self.sources.file_by_rel_path(rel_path)
    }

    fn persistence_root(&self) -> Option<&Path> {
        Some(&self.persistence_root)
    }
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

fn parallel_benchmark_sizes() -> Vec<usize> {
    let raw = std::env::var(PARALLEL_SIZES_ENV).unwrap_or_else(|_| "8,16,32,64,128".to_string());
    let sizes =
        raw.split(',')
            .map(|value| {
                value.trim().parse::<usize>().unwrap_or_else(|_| {
                    panic!("{PARALLEL_SIZES_ENV} contains invalid size {value:?}")
                })
            })
            .collect::<Vec<_>>();
    assert!(!sizes.is_empty(), "{PARALLEL_SIZES_ENV} must not be empty");
    assert!(
        sizes.iter().all(|size| (1..=MAX_LIMIT / 2).contains(size)),
        "{PARALLEL_SIZES_ENV} sizes must be between 1 and {}",
        MAX_LIMIT / 2
    );
    sizes
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

fn typescript_fixture_paths(files_per_branch: usize) -> Vec<PathBuf> {
    let mut paths = Vec::with_capacity(files_per_branch.saturating_mul(2).saturating_add(1));
    paths.push(PathBuf::from("shared.ts"));
    for index in 0..files_per_branch {
        paths.push(PathBuf::from("left").join(format!("module_{index:04}.ts")));
        paths.push(PathBuf::from("right").join(format!("module_{index:04}.ts")));
    }
    paths
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
    let detailed = execute_code_query_with_union_strategy(
        analyzer,
        query,
        limits,
        UnionExecutionStrategy::Sequential,
        mode == ExecutionMode::Profiled,
    );
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

fn benchmark_workspace(project: Arc<dyn Project>) -> WorkspaceAnalyzer {
    WorkspaceAnalyzer::build(
        project,
        AnalyzerConfig {
            parallelism: Some(1),
            memo_cache_budget_bytes: Some(MEMO_CACHE_BUDGET_BYTES),
            ..AnalyzerConfig::default()
        },
    )
}

struct TimedExecution {
    detailed: DetailedCodeQueryResult,
    elapsed_ns: u64,
    structural_cache: StructuralCacheCounts,
}

struct CandidateTimingEvidence {
    timing: CandidateTimingPair,
    result_sha256: String,
    work: CodeQueryExecutionWork,
    baseline_structural_cache: StructuralCacheCounts,
    candidate_structural_cache: StructuralCacheCounts,
}

fn timed_forced_execution(
    analyzer: &dyn IAnalyzer,
    query: &CodeQuery,
    strategy: UnionExecutionStrategy,
) -> TimedExecution {
    let cache_before = structural_cache_counts(analyzer);
    let started = Instant::now();
    let query_scope = AnalyzerQueryScope::new(analyzer);
    let detailed = execute_code_query_with_union_strategy(
        analyzer,
        query,
        CodeQueryExecutionLimits::default(),
        strategy,
        false,
    );
    let store_error = query_scope.store_error();
    drop(query_scope);
    let elapsed_ns = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
    let structural_cache = structural_cache_counts(analyzer).delta_from(cache_before);
    assert!(
        store_error.is_none(),
        "parallel benchmark query scope must not observe a store error"
    );
    TimedExecution {
        detailed,
        elapsed_ns,
        structural_cache,
    }
}

fn assert_forced_pair_parity(
    sequential: &DetailedCodeQueryResult,
    parallel: &DetailedCodeQueryResult,
    expected_results: usize,
    case: &str,
) {
    assert_eq!(
        serde_json::to_value(&parallel.result).expect("parallel benchmark result serializes"),
        serde_json::to_value(&sequential.result).expect("sequential benchmark result serializes"),
        "{case} public result parity"
    );
    assert_eq!(parallel.work, sequential.work, "{case} work parity");
    assert_eq!(
        parallel.evidence, sequential.evidence,
        "{case} evidence parity"
    );
    assert_eq!(parallel.result.results.len(), expected_results, "{case}");
    assert_eq!(
        parallel.result.completion(),
        CodeQueryCompletion::Complete,
        "{case}"
    );
}

#[allow(clippy::too_many_arguments)]
fn strategy_timing_pair(
    sequential_analyzer: &dyn IAnalyzer,
    candidate_analyzer: &dyn IAnalyzer,
    query: &CodeQuery,
    expected_results: usize,
    case: &str,
    iteration: usize,
    candidate_first: bool,
    candidate_strategy: UnionExecutionStrategy,
    candidate_label: &'static str,
) -> CandidateTimingEvidence {
    let (sequential, candidate) = if candidate_first {
        let candidate = timed_forced_execution(candidate_analyzer, query, candidate_strategy);
        let sequential = timed_forced_execution(
            sequential_analyzer,
            query,
            UnionExecutionStrategy::Sequential,
        );
        (sequential, candidate)
    } else {
        let sequential = timed_forced_execution(
            sequential_analyzer,
            query,
            UnionExecutionStrategy::Sequential,
        );
        let candidate = timed_forced_execution(candidate_analyzer, query, candidate_strategy);
        (sequential, candidate)
    };
    assert_forced_pair_parity(
        &sequential.detailed,
        &candidate.detailed,
        expected_results,
        case,
    );
    let result_sha256 = sha256_json(&sequential.detailed.result);
    let work = sequential.detailed.work;
    let savings_ns = i128::from(sequential.elapsed_ns) - i128::from(candidate.elapsed_ns);
    let savings_pct = if sequential.elapsed_ns == 0 {
        0.0
    } else {
        savings_ns as f64 * 100.0 / sequential.elapsed_ns as f64
    };
    CandidateTimingEvidence {
        timing: CandidateTimingPair {
            iteration,
            candidate: candidate_label,
            first: if candidate_first {
                candidate_label
            } else {
                "sequential"
            },
            baseline_sequential_ns: sequential.elapsed_ns,
            candidate_ns: candidate.elapsed_ns,
            savings_ns,
            savings_pct,
        },
        result_sha256,
        work,
        baseline_structural_cache: sequential.structural_cache,
        candidate_structural_cache: candidate.structural_cache,
    }
}

fn candidate_timing_summary(samples: &[CandidateTimingPair]) -> CandidateTimingSummary {
    let mut baseline = samples
        .iter()
        .map(|sample| sample.baseline_sequential_ns)
        .collect::<Vec<_>>();
    let mut candidate = samples
        .iter()
        .map(|sample| sample.candidate_ns)
        .collect::<Vec<_>>();
    let baseline_sequential_median_ns = median(&mut baseline);
    let candidate_median_ns = median(&mut candidate);
    let median_savings_ns =
        i128::from(baseline_sequential_median_ns) - i128::from(candidate_median_ns);
    CandidateTimingSummary {
        samples: samples.len(),
        baseline_sequential_median_ns,
        candidate_median_ns,
        median_savings_ns,
        savings_pct_from_medians: if baseline_sequential_median_ns == 0 {
            0.0
        } else {
            median_savings_ns as f64 * 100.0 / baseline_sequential_median_ns as f64
        },
        candidate_wins: samples
            .iter()
            .filter(|sample| sample.candidate_ns < sample.baseline_sequential_ns)
            .count(),
    }
}

fn candidate_first_for_case(round: usize, files_per_branch: usize, case: &str) -> bool {
    let case_ordinal = match case {
        "distinct_exact_union" => 0,
        "distinct_broad_union" => 1,
        other => panic!("parallel benchmark case has no stable order ordinal: {other}"),
    };
    round
        .saturating_add(files_per_branch.saturating_mul(2))
        .saturating_add(case_ordinal)
        .is_multiple_of(2)
}

fn assert_isolated_cold_pair(evidence: &CandidateTimingEvidence, case: &str) {
    assert_eq!(
        evidence.baseline_structural_cache.extractions,
        evidence.candidate_structural_cache.extractions,
        "{case} cold strategies must perform equal structural extraction work"
    );
    assert!(
        evidence.baseline_structural_cache.extractions > 0,
        "{case} cold strategies must extract structural facts"
    );
    assert_eq!(
        evidence.baseline_structural_cache.hydrations, 0,
        "{case} cold sequential baseline must not hydrate persisted facts"
    );
    assert_eq!(
        evidence.candidate_structural_cache.hydrations, 0,
        "{case} cold candidate must not hydrate persisted facts"
    );
}

fn assert_memory_warm_pair(evidence: &CandidateTimingEvidence, case: &str) {
    assert_eq!(
        evidence.baseline_structural_cache,
        StructuralCacheCounts::default(),
        "{case} warm sequential baseline must reuse memory-resident facts"
    );
    assert_eq!(
        evidence.candidate_structural_cache,
        StructuralCacheCounts::default(),
        "{case} warm candidate must reuse memory-resident facts"
    );
}

fn run_parallel_case(
    root: &Path,
    stats: FixtureStats,
    files_per_branch: usize,
    spec: CaseSpec,
    iterations: usize,
    round: usize,
) -> ParallelCaseResult {
    let paths = typescript_fixture_paths(files_per_branch);
    let cold_sequential_store = TempDir::new().expect("cold sequential benchmark store");
    let cold_parallel_store = TempDir::new().expect("cold parallel benchmark store");
    let cold_auto_sequential_store = TempDir::new().expect("cold auto baseline benchmark store");
    let cold_auto_candidate_store = TempDir::new().expect("cold auto candidate benchmark store");
    let warm_store = TempDir::new().expect("warm benchmark store");
    let project = |store: &TempDir| -> Arc<dyn Project> {
        Arc::new(PersistentFileSetProject::new(
            root,
            paths.clone(),
            store.path(),
        ))
    };
    let cold_sequential = benchmark_workspace(project(&cold_sequential_store));
    let cold_parallel = benchmark_workspace(project(&cold_parallel_store));
    let cold_auto_sequential = benchmark_workspace(project(&cold_auto_sequential_store));
    let cold_auto_candidate = benchmark_workspace(project(&cold_auto_candidate_store));
    let parallel_first = candidate_first_for_case(round, files_per_branch, spec.name);
    let cold_evidence = strategy_timing_pair(
        cold_sequential.analyzer(),
        cold_parallel.analyzer(),
        &spec.query,
        spec.expected_results,
        spec.name,
        0,
        parallel_first,
        UnionExecutionStrategy::Parallel,
        "parallel",
    );
    assert_isolated_cold_pair(&cold_evidence, spec.name);
    let auto_cold_evidence = strategy_timing_pair(
        cold_auto_sequential.analyzer(),
        cold_auto_candidate.analyzer(),
        &spec.query,
        spec.expected_results,
        spec.name,
        0,
        !parallel_first,
        UnionExecutionStrategy::Auto,
        "auto",
    );
    assert_isolated_cold_pair(&auto_cold_evidence, spec.name);
    assert_eq!(
        auto_cold_evidence.result_sha256,
        cold_evidence.result_sha256
    );
    assert_eq!(auto_cold_evidence.work, cold_evidence.work);
    let cold = cold_evidence.timing;
    let cold_digest = cold_evidence.result_sha256;
    let cold_work = cold_evidence.work;
    let auto_cold = auto_cold_evidence.timing;

    let warm_workspace = benchmark_workspace(project(&warm_store));
    let warm_analyzer = warm_workspace.analyzer();
    let warmup = timed_forced_execution(
        warm_analyzer,
        &spec.query,
        UnionExecutionStrategy::Sequential,
    );
    assert_eq!(warmup.detailed.result.results.len(), spec.expected_results);
    assert!(warmup.structural_cache.extractions > 0);
    assert_eq!(warmup.structural_cache.hydrations, 0);
    let mut warm = Vec::with_capacity(iterations);
    for iteration in 0..iterations {
        let evidence = strategy_timing_pair(
            warm_analyzer,
            warm_analyzer,
            &spec.query,
            spec.expected_results,
            spec.name,
            iteration,
            if iteration.is_multiple_of(2) {
                parallel_first
            } else {
                !parallel_first
            },
            UnionExecutionStrategy::Parallel,
            "parallel",
        );
        assert_memory_warm_pair(&evidence, spec.name);
        assert_eq!(
            evidence.result_sha256, cold_digest,
            "{} deterministic digest",
            spec.name
        );
        assert_eq!(evidence.work, cold_work, "{} deterministic work", spec.name);
        warm.push(evidence.timing);
    }
    let mut auto_warm = Vec::with_capacity(iterations);
    for iteration in 0..iterations {
        let evidence = strategy_timing_pair(
            warm_analyzer,
            warm_analyzer,
            &spec.query,
            spec.expected_results,
            spec.name,
            iteration,
            if iteration.is_multiple_of(2) {
                !parallel_first
            } else {
                parallel_first
            },
            UnionExecutionStrategy::Auto,
            "auto",
        );
        assert_memory_warm_pair(&evidence, spec.name);
        assert_eq!(
            evidence.result_sha256, cold_digest,
            "{} auto deterministic digest",
            spec.name
        );
        assert_eq!(
            evidence.work, cold_work,
            "{} auto deterministic work",
            spec.name
        );
        auto_warm.push(evidence.timing);
    }

    let profiled = execute_code_query_with_union_strategy(
        warm_analyzer,
        &spec.query,
        CodeQueryExecutionLimits::default(),
        UnionExecutionStrategy::Parallel,
        true,
    );
    assert_forced_pair_parity(
        &warmup.detailed,
        &profiled,
        spec.expected_results,
        spec.name,
    );
    let profile = profiled.profile.expect("forced parallel profile");
    assert!(
        profile
            .operators
            .iter()
            .any(|operator| { operator.operator == PhysicalQueryOperator::ParallelUnion })
    );
    let scheduler = profile.scheduler;
    assert_eq!(scheduler.tasks_enqueued, 2);
    assert_eq!(scheduler.tasks_completed, 2);
    assert!(scheduler.peak_concurrency <= scheduler.worker_limit);
    let auto = execute_code_query_with_union_strategy(
        warm_analyzer,
        &spec.query,
        CodeQueryExecutionLimits::default(),
        UnionExecutionStrategy::Auto,
        true,
    );
    assert_forced_pair_parity(&warmup.detailed, &auto, spec.expected_results, spec.name);
    let auto_profile = auto.profile.expect("auto-selection profile");
    let auto_selected_parallel = auto_profile
        .operators
        .iter()
        .any(|operator| operator.operator == PhysicalQueryOperator::ParallelUnion);
    assert!(
        !auto_selected_parallel,
        "{} Auto policy must retain the benchmark-derived sequential fallback at {} workspace files",
        spec.name, stats.files
    );

    ParallelCaseResult {
        name: spec.name.to_string(),
        files_per_branch,
        workspace_files: stats.files,
        workspace_source_bytes: stats.source_bytes,
        candidate_files_per_branch: if spec.name.contains("broad") {
            files_per_branch
        } else {
            1
        },
        cold,
        warm_summary: candidate_timing_summary(&warm),
        warm,
        result_sha256: cold_digest,
        work: cold_work,
        scheduler: ParallelSchedulerSummary {
            worker_limit: scheduler.worker_limit,
            tasks_enqueued: scheduler.tasks_enqueued,
            tasks_completed: scheduler.tasks_completed,
            tasks_observed_cancelled_before_start: scheduler.tasks_observed_cancelled_before_start,
            peak_concurrency: scheduler.peak_concurrency,
            queue_wait_ns: scheduler.queue_wait_ns,
            worker_task_elapsed_ns: scheduler.worker_task_elapsed_ns,
            budget_wait_ns: scheduler.budget_wait_ns,
            coordinator_wait_ns: scheduler.coordinator_wait_ns,
            dispatch_overhead_ns: scheduler.dispatch_overhead_ns,
        },
        auto_selected_parallel,
        auto_cold,
        auto_warm_summary: candidate_timing_summary(&auto_warm),
        auto_warm,
    }
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
        format: "bifrost_code_query_execution_benchmark/v4",
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
            physical_execution: "forced_sequential_recursive",
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

#[test]
#[ignore = "M4 sequential/parallel CodeQuery benchmark; run explicitly in release mode"]
fn code_query_parallel_execution_measurement() {
    assert!(
        std::thread::available_parallelism().is_ok_and(|value| value.get() >= 2),
        "parallel CodeQuery benchmark requires at least two available processors"
    );
    let mut sizes = parallel_benchmark_sizes();
    let iterations = positive_env(ITERATIONS_ENV, DEFAULT_ITERATIONS, 30);
    let round = non_negative_env(ROUND_ENV);
    if !round.is_multiple_of(2) {
        sizes.reverse();
    }

    let mut cases = Vec::new();
    for files_per_branch in sizes {
        let temp = TempDir::new().expect("parallel CodeQuery benchmark temp directory");
        let root = temp
            .path()
            .canonicalize()
            .expect("canonicalize parallel benchmark root");
        let stats = generate_typescript_fixture(&root, files_per_branch);
        let mut specs = typescript_cases(files_per_branch)
            .into_iter()
            .filter(|spec| matches!(spec.name, "distinct_exact_union" | "distinct_broad_union"))
            .collect::<Vec<_>>();
        if !round.saturating_add(files_per_branch).is_multiple_of(2) {
            specs.reverse();
        }
        for spec in specs {
            cases.push(run_parallel_case(
                &root,
                stats,
                files_per_branch,
                spec,
                iterations,
                round,
            ));
        }
    }

    let provenance = provenance();
    assert!(
        provenance.bifrost_tree_fingerprint.is_some(),
        "decision-grade benchmark must fingerprint the exact source tree"
    );
    let scheduler_workers = cases
        .first()
        .map(|case| case.scheduler.worker_limit)
        .unwrap_or_default();
    let result = ParallelBenchmarkResult {
        format: "bifrost_code_query_parallel_execution_benchmark/v4",
        kind: "isolated_query_scoped_sequential_candidate_ab",
        round,
        provenance,
        scheduler_workers,
        warm_iterations_per_strategy: iterations,
        cache_contract: [
            "cold strategies share fixed source files but use separate fresh analyzers and strategy-private durable stores",
            "timing includes analyzer query-scope setup and cleanup; cold pairs assert equal extraction work and zero hydration",
            "warm pairs alternate order on one analyzer after an untimed extracting warmup and assert memory reuse",
        ],
        cases,
    };
    eprintln!(
        "{RESULT_PREFIX}{}",
        serde_json::to_string(&result).expect("serialize parallel CodeQuery benchmark")
    );
}

#[test]
fn paired_parallel_benchmark_rounds_flip_every_cold_candidate_order() {
    for files_per_branch in [128, 256, 500] {
        for case in ["distinct_exact_union", "distinct_broad_union"] {
            assert_ne!(
                candidate_first_for_case(12, files_per_branch, case),
                candidate_first_for_case(13, files_per_branch, case),
                "paired rounds must flip cold order for {case} at {files_per_branch} files per branch"
            );
        }
    }
}
