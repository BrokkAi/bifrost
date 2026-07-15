//! Reproducible cold-extraction versus persisted-hydration benchmark for structural facts.
//!
//! The first analyzer lifetime parses and normalizes every requested file. After it is
//! dropped, a second persisted analyzer reopens the same Git workspace and materializes
//! the same facts. On the pre-snapshot baseline both lifetimes extract; a snapshot-backed
//! candidate should hydrate during the second lifetime without changing the hot facts.
//!
//! Run with:
//!   BIFROST_SEMANTIC_INDEX=off cargo test --release --test measure_structural_facts_persistence -- --ignored --nocapture

use brokk_bifrost::analyzer::structural::{CodeQuery, execute};
use brokk_bifrost::{AnalyzerConfig, IAnalyzer, Language, Project, TestProject, WorkspaceAnalyzer};
use git2::{IndexAddOption, Repository, Signature};
use rusqlite::Connection;
use serde::Serialize;
use serde_json::json;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Instant;
use tempfile::TempDir;

const FILE_COUNT_ENV: &str = "BIFROST_STRUCTURAL_PERSIST_BENCH_FILES";
const CALLS_PER_FILE_ENV: &str = "BIFROST_STRUCTURAL_PERSIST_BENCH_CALLS_PER_FILE";
const ITERATIONS_ENV: &str = "BIFROST_STRUCTURAL_PERSIST_BENCH_ITERATIONS";
const PARALLELISM_ENV: &str = "BIFROST_STRUCTURAL_PERSIST_BENCH_PARALLELISM";
const DEFAULT_FILE_COUNT: usize = 200;
const DEFAULT_CALLS_PER_FILE: usize = 50;
const DEFAULT_ITERATIONS: usize = 7;
const DEFAULT_PARALLELISM: usize = 1;

#[derive(Debug, Serialize)]
struct MaterializationMetrics {
    duration_ms: f64,
    extractions: u64,
    candidate_files: usize,
    materialized_files: usize,
    facts: usize,
    roles: usize,
    estimated_retained_bytes: u64,
    hot_query_median_ms: f64,
}

#[derive(Debug, Default, Serialize)]
struct SnapshotMetrics {
    rows: u64,
    payload_bytes: u64,
}

#[derive(Serialize)]
struct StructuralPersistenceBenchmarkResult {
    format: &'static str,
    bifrost_commit: Option<String>,
    workspace_commit: Option<String>,
    files: usize,
    calls_per_file: usize,
    iterations: usize,
    parallelism: usize,
    cold_build_ms: f64,
    cold: MaterializationMetrics,
    warm_build_ms: f64,
    warm: MaterializationMetrics,
    snapshots_after_cold: SnapshotMetrics,
    snapshots_after_warm: SnapshotMetrics,
    database_main_bytes_after_cold: u64,
    database_total_bytes_after_cold: u64,
    database_main_bytes_after_warm: u64,
    database_total_bytes_after_warm: u64,
    peak_rss_start_bytes: u64,
    peak_rss_after_cold_bytes: u64,
    peak_rss_after_warm_bytes: u64,
}

#[cfg(unix)]
fn peak_rss_bytes() -> u64 {
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) };
    assert_eq!(rc, 0, "getrusage failed");
    let maxrss = usage.ru_maxrss.max(0) as u64;
    if cfg!(target_os = "macos") {
        maxrss
    } else {
        maxrss * 1024
    }
}

#[cfg(not(unix))]
fn peak_rss_bytes() -> u64 {
    0
}

fn mb(bytes: u64) -> f64 {
    bytes as f64 / (1024.0 * 1024.0)
}

fn positive_env(name: &str, default: usize, maximum: usize) -> usize {
    match std::env::var(name) {
        Ok(raw) => {
            let value = raw
                .trim()
                .parse::<usize>()
                .unwrap_or_else(|_| panic!("{name} must be a positive integer, got `{raw}`"));
            assert!(
                (1..=maximum).contains(&value),
                "{name} must be between 1 and {maximum}, got {value}"
            );
            value
        }
        Err(_) => default,
    }
}

fn git_commit(root: &Path) -> Option<String> {
    Command::new("git")
        .current_dir(root)
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|commit| commit.trim().to_owned())
}

fn generate_workspace(root: &Path, file_count: usize, calls_per_file: usize) {
    fs::write(root.join(".gitignore"), ".brokk/\n").expect("write benchmark .gitignore");
    for file in 0..file_count {
        let mut source = String::with_capacity(calls_per_file.saturating_mul(180));
        source.push_str(
            "export function sink(a: number, b: number, c: number, d: number): number {\n",
        );
        source.push_str("    return a + b + c + d;\n}\n\n");
        for call in 0..calls_per_file {
            source.push_str(&format!(
                "export function caller_{file:04}_{call:04}(input: number): number {{\n\
                 \x20   const base = input + {call};\n\
                 \x20   return sink(base, input, 1, 2);\n\
                 }}\n\n"
            ));
        }
        fs::write(root.join(format!("module_{file:04}.ts")), source)
            .expect("write structural persistence benchmark module");
    }
}

fn initialize_git_workspace(root: &Path) {
    let repository = Repository::init(root).expect("initialize benchmark Git repository");
    let mut config = repository.config().expect("open benchmark Git config");
    config
        .set_str("user.name", "Bifrost Benchmark")
        .expect("set benchmark Git user name");
    config
        .set_str("user.email", "bifrost-benchmark@example.com")
        .expect("set benchmark Git email");
    let mut index = repository.index().expect("open benchmark Git index");
    index
        .add_all(["*"], IndexAddOption::DEFAULT, None)
        .expect("stage benchmark fixture");
    index.write().expect("write benchmark Git index");
    let tree_id = index.write_tree().expect("write benchmark Git tree");
    let tree = repository
        .find_tree(tree_id)
        .expect("load benchmark Git tree");
    let signature = Signature::now("Bifrost Benchmark", "bifrost-benchmark@example.com")
        .expect("create benchmark Git signature");
    repository
        .commit(
            Some("HEAD"),
            &signature,
            &signature,
            "structural persistence benchmark fixture",
            &tree,
            &[],
        )
        .expect("commit benchmark fixture");
}

fn median(values: &mut [f64]) -> f64 {
    values.sort_by(f64::total_cmp);
    let middle = values.len() / 2;
    if values.len().is_multiple_of(2) {
        (values[middle - 1] + values[middle]) / 2.0
    } else {
        values[middle]
    }
}

fn role_heavy_query() -> CodeQuery {
    CodeQuery::from_json(&json!({
        "match": {
            "kind": "call",
            "args": [{ "kind": "identifier", "not_kind": "identifier" }]
        },
        "limit": 1
    }))
    .expect("structural persistence benchmark query should parse")
}

fn materialize(
    analyzer: &dyn IAnalyzer,
    expected_files: usize,
    iterations: usize,
) -> MaterializationMetrics {
    let providers = analyzer.structural_search_providers();
    assert!(
        !providers.is_empty(),
        "benchmark workspace should expose structural facts"
    );
    let extractions_before = providers
        .iter()
        .map(|provider| provider.structural_extraction_count())
        .sum::<u64>();
    let started = Instant::now();
    let mut retained = Vec::with_capacity(expected_files);
    let mut candidate_files = 0usize;
    for provider in &providers {
        let mut files = provider.structural_files();
        files.sort();
        candidate_files = candidate_files.saturating_add(files.len());
        retained.extend(
            files
                .iter()
                .filter_map(|file| provider.structural_facts(file)),
        );
    }
    let duration_ms = started.elapsed().as_secs_f64() * 1_000.0;
    let extractions_after = providers
        .iter()
        .map(|provider| provider.structural_extraction_count())
        .sum::<u64>();

    assert_eq!(candidate_files, expected_files);
    assert_eq!(retained.len(), expected_files);
    let facts = retained.iter().map(|entry| entry.nodes().len()).sum();
    let roles = retained.iter().map(|entry| entry.role_count()).sum();
    let estimated_retained_bytes = retained
        .iter()
        .map(|entry| entry.estimated_bytes())
        .sum::<u64>();
    assert!(facts > 0, "benchmark must materialize structural facts");
    assert!(roles > 0, "benchmark must materialize structural roles");

    let query = role_heavy_query();
    let mut query_times = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let started = Instant::now();
        let result = execute(analyzer, &query);
        query_times.push(started.elapsed().as_secs_f64() * 1_000.0);
        assert!(
            result.results.is_empty(),
            "a role target cannot both be and not be an identifier"
        );
        std::hint::black_box(result);
    }

    MaterializationMetrics {
        duration_ms,
        extractions: extractions_after.saturating_sub(extractions_before),
        candidate_files,
        materialized_files: retained.len(),
        facts,
        roles,
        estimated_retained_bytes,
        hot_query_median_ms: median(&mut query_times),
    }
}

fn snapshot_metrics(database: &Path) -> SnapshotMetrics {
    if !database.exists() {
        return SnapshotMetrics::default();
    }
    let connection = Connection::open(database).expect("open benchmark analyzer database");
    let exists = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'structural_facts_snapshots')",
            [],
            |row| row.get::<_, bool>(0),
        )
        .expect("query structural snapshot table existence");
    if !exists {
        return SnapshotMetrics::default();
    }
    connection
        .query_row(
            "SELECT COUNT(*), COALESCE(SUM(length(payload)), 0) FROM structural_facts_snapshots",
            [],
            |row| {
                Ok(SnapshotMetrics {
                    rows: row.get(0)?,
                    payload_bytes: row.get(1)?,
                })
            },
        )
        .expect("query structural snapshot size")
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut value: OsString = path.as_os_str().to_owned();
    value.push(suffix);
    PathBuf::from(value)
}

fn file_size(path: &Path) -> u64 {
    path.metadata().map_or(0, |metadata| metadata.len())
}

fn database_sizes(database: &Path) -> (u64, u64) {
    let main = file_size(database);
    let total = main
        .saturating_add(file_size(&with_suffix(database, "-wal")))
        .saturating_add(file_size(&with_suffix(database, "-shm")));
    (main, total)
}

#[test]
#[ignore = "measure-first persisted structural facts benchmark; run explicitly with --ignored --nocapture"]
fn structural_facts_cold_extraction_and_warm_persisted_hydration() {
    let file_count = positive_env(FILE_COUNT_ENV, DEFAULT_FILE_COUNT, 5_000);
    let calls_per_file = positive_env(CALLS_PER_FILE_ENV, DEFAULT_CALLS_PER_FILE, 1_000);
    let iterations = positive_env(ITERATIONS_ENV, DEFAULT_ITERATIONS, 50);
    let parallelism = positive_env(PARALLELISM_ENV, DEFAULT_PARALLELISM, 256);

    let temp = TempDir::new().expect("structural persistence benchmark temp directory");
    let root = temp
        .path()
        .canonicalize()
        .expect("canonicalize structural persistence benchmark root");
    generate_workspace(&root, file_count, calls_per_file);
    initialize_git_workspace(&root);
    let database = root.join(".brokk/bifrost_cache.db");
    let project: Arc<dyn Project> = Arc::new(TestProject::new(root.clone(), Language::TypeScript));
    let config = AnalyzerConfig {
        parallelism: Some(parallelism),
        memo_cache_budget_bytes: Some(2 * 1024 * 1024 * 1024),
        ..AnalyzerConfig::default()
    };

    let rss_start = peak_rss_bytes();
    let cold_build_started = Instant::now();
    let cold_workspace = WorkspaceAnalyzer::build_persisted(Arc::clone(&project), config.clone());
    let cold_build_ms = cold_build_started.elapsed().as_secs_f64() * 1_000.0;
    let cold = materialize(cold_workspace.analyzer(), file_count, iterations);
    drop(cold_workspace);
    let snapshots_after_cold = snapshot_metrics(&database);
    let (database_main_bytes_after_cold, database_total_bytes_after_cold) =
        database_sizes(&database);
    let rss_after_cold = peak_rss_bytes();

    let warm_build_started = Instant::now();
    let warm_workspace = WorkspaceAnalyzer::build_persisted(Arc::clone(&project), config);
    let warm_build_ms = warm_build_started.elapsed().as_secs_f64() * 1_000.0;
    let warm = materialize(warm_workspace.analyzer(), file_count, iterations);
    drop(warm_workspace);
    let snapshots_after_warm = snapshot_metrics(&database);
    let (database_main_bytes_after_warm, database_total_bytes_after_warm) =
        database_sizes(&database);
    let rss_after_warm = peak_rss_bytes();

    assert_eq!(cold.candidate_files, warm.candidate_files);
    assert_eq!(cold.materialized_files, warm.materialized_files);
    assert_eq!(cold.facts, warm.facts);
    assert_eq!(cold.roles, warm.roles);

    eprintln!("\n=== structural facts persistence benchmark ===");
    eprintln!(
        "fixture: {file_count} files x {calls_per_file} calls, facts: {}, roles: {}",
        cold.facts, cold.roles
    );
    eprintln!(
        "cold build/materialize/query: {:.1} / {:.1} / {:.1} ms; extractions: {}",
        cold_build_ms, cold.duration_ms, cold.hot_query_median_ms, cold.extractions
    );
    eprintln!(
        "warm build/materialize/query: {:.1} / {:.1} / {:.1} ms; extractions: {}",
        warm_build_ms, warm.duration_ms, warm.hot_query_median_ms, warm.extractions
    );
    eprintln!(
        "snapshots after cold/warm: {} / {} rows, {:.1} / {:.1} MB payload",
        snapshots_after_cold.rows,
        snapshots_after_warm.rows,
        mb(snapshots_after_cold.payload_bytes),
        mb(snapshots_after_warm.payload_bytes)
    );
    eprintln!(
        "database total after cold/warm: {:.1} / {:.1} MB",
        mb(database_total_bytes_after_cold),
        mb(database_total_bytes_after_warm)
    );
    eprintln!(
        "estimated retained facts cold/warm: {:.1} / {:.1} MB; peak RSS start/cold/warm: {:.1} / {:.1} / {:.1} MB\n",
        mb(cold.estimated_retained_bytes),
        mb(warm.estimated_retained_bytes),
        mb(rss_start),
        mb(rss_after_cold),
        mb(rss_after_warm)
    );

    let result = StructuralPersistenceBenchmarkResult {
        format: "bifrost_structural_facts_persistence_benchmark/v1",
        bifrost_commit: git_commit(Path::new(env!("CARGO_MANIFEST_DIR"))),
        workspace_commit: git_commit(&root),
        files: file_count,
        calls_per_file,
        iterations,
        parallelism,
        cold_build_ms,
        cold,
        warm_build_ms,
        warm,
        snapshots_after_cold,
        snapshots_after_warm,
        database_main_bytes_after_cold,
        database_total_bytes_after_cold,
        database_main_bytes_after_warm,
        database_total_bytes_after_warm,
        peak_rss_start_bytes: rss_start,
        peak_rss_after_cold_bytes: rss_after_cold,
        peak_rss_after_warm_bytes: rss_after_warm,
    };
    eprintln!(
        "BIFROST_STRUCTURAL_FACTS_PERSISTENCE_BENCHMARK={}",
        serde_json::to_string(&result).expect("serialize structural persistence benchmark result")
    );
}
