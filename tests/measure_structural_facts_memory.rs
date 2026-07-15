//! Reproducible retained-memory and read-throughput benchmark for structural facts.
//!
//! This is the baseline harness for issue #748's compact-role experiment. It creates a
//! role-dense TypeScript workspace, retains every extracted `FileFacts`, and then runs a
//! role-constrained query repeatedly against the warm cache. The machine-readable output
//! is intentionally stable so the same test can compare representations across commits.
//!
//! Run with:
//!   BIFROST_SEMANTIC_INDEX=off cargo test --test measure_structural_facts_memory -- --ignored --nocapture
//!
//! Point at a real checkout with `BIFROST_STRUCTURAL_BENCH_REPO=/path/to/repo`.

use brokk_bifrost::analyzer::structural::{CodeQuery, execute};
use brokk_bifrost::{AnalyzerConfig, Language, Project, TestProject, WorkspaceAnalyzer};
use serde::Serialize;
use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Instant;
use tempfile::TempDir;

const FILE_COUNT_ENV: &str = "BIFROST_STRUCTURAL_BENCH_FILES";
const CALLS_PER_FILE_ENV: &str = "BIFROST_STRUCTURAL_BENCH_CALLS_PER_FILE";
const ITERATIONS_ENV: &str = "BIFROST_STRUCTURAL_BENCH_ITERATIONS";
const PARALLELISM_ENV: &str = "BIFROST_STRUCTURAL_BENCH_PARALLELISM";
const REPOSITORY_ENV: &str = "BIFROST_STRUCTURAL_BENCH_REPO";
const DEFAULT_FILE_COUNT: usize = 400;
const DEFAULT_CALLS_PER_FILE: usize = 100;
const DEFAULT_ITERATIONS: usize = 7;
const DEFAULT_PARALLELISM: usize = 1;

#[derive(Serialize)]
struct StructuralFactsBenchmarkResult {
    format: &'static str,
    fixture: &'static str,
    workspace: String,
    bifrost_commit: Option<String>,
    workspace_commit: Option<String>,
    candidate_files: usize,
    extracted_files: usize,
    skipped_files: usize,
    calls_per_file: Option<usize>,
    iterations: usize,
    parallelism: usize,
    analyzer_build_ms: f64,
    cold_extraction_ms: f64,
    warm_match_median_ms: f64,
    facts: usize,
    roles: usize,
    estimated_retained_bytes: u64,
    peak_rss_start_bytes: u64,
    peak_rss_after_analyzer_bytes: u64,
    peak_rss_after_extraction_bytes: u64,
    peak_rss_after_matching_bytes: u64,
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

fn workspace_commit(root: &Path) -> Option<String> {
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
            .expect("write structural benchmark module");
    }
}

fn median(values: &mut [f64]) -> f64 {
    values.sort_by(f64::total_cmp);
    let middle = values.len() / 2;
    if values.len() % 2 == 0 {
        (values[middle - 1] + values[middle]) / 2.0
    } else {
        values[middle]
    }
}

#[test]
#[ignore = "measure-first structural facts benchmark; run explicitly with --ignored --nocapture"]
fn structural_facts_retained_memory_and_warm_role_reads() {
    let file_count = positive_env(FILE_COUNT_ENV, DEFAULT_FILE_COUNT, 5_000);
    let calls_per_file = positive_env(CALLS_PER_FILE_ENV, DEFAULT_CALLS_PER_FILE, 1_000);
    let iterations = positive_env(ITERATIONS_ENV, DEFAULT_ITERATIONS, 50);
    let parallelism = positive_env(PARALLELISM_ENV, DEFAULT_PARALLELISM, 256);

    let (root, _temp, generated): (PathBuf, Option<TempDir>, bool) =
        match std::env::var(REPOSITORY_ENV) {
            Ok(path) => (PathBuf::from(path), None, false),
            Err(_) => {
                let temp = TempDir::new().expect("structural benchmark temp dir");
                generate_workspace(temp.path(), file_count, calls_per_file);
                (temp.path().to_path_buf(), Some(temp), true)
            }
        };

    let rss_start = peak_rss_bytes();
    let project: Arc<dyn Project> = if generated {
        Arc::new(TestProject::new(root.clone(), Language::TypeScript))
    } else {
        Arc::new(
            TestProject::from_root_with_inferred_languages(root.clone())
                .expect("infer structural benchmark repository languages"),
        )
    };
    let analyzer_started = Instant::now();
    let workspace = WorkspaceAnalyzer::build(
        project,
        AnalyzerConfig {
            parallelism: Some(parallelism),
            memo_cache_budget_bytes: Some(2 * 1024 * 1024 * 1024),
            ..AnalyzerConfig::default()
        },
    );
    let analyzer_build_ms = analyzer_started.elapsed().as_secs_f64() * 1_000.0;
    let rss_after_analyzer = peak_rss_bytes();
    let analyzer = workspace.analyzer();

    let providers = analyzer.structural_search_providers();
    assert!(
        !providers.is_empty(),
        "benchmark workspace should expose structural facts"
    );

    let extraction_started = Instant::now();
    let mut retained = Vec::new();
    let mut candidate_file_count = 0usize;
    for provider in providers {
        let mut files = provider.structural_files();
        files.sort();
        candidate_file_count = candidate_file_count.saturating_add(files.len());
        retained.extend(
            files
                .iter()
                .filter_map(|file| provider.structural_facts(file)),
        );
    }
    if generated {
        assert_eq!(
            retained.len(),
            file_count,
            "all generated files must yield structural facts"
        );
    }
    let extracted_file_count = retained.len();
    let skipped_file_count = candidate_file_count.saturating_sub(extracted_file_count);
    let cold_extraction_ms = extraction_started.elapsed().as_secs_f64() * 1_000.0;
    let rss_after_extraction = peak_rss_bytes();
    let fact_count = retained.iter().map(|facts| facts.nodes().len()).sum();
    let role_count = retained.iter().map(|facts| facts.role_count()).sum();
    let estimated_retained_bytes = retained
        .iter()
        .map(|facts| facts.estimated_bytes())
        .sum::<u64>();
    assert!(fact_count > 0, "benchmark must extract facts");
    assert!(role_count > 0, "benchmark must extract semantic role edges");

    let query = CodeQuery::from_json(&json!({
        "match": {
            "kind": "call",
            "args": [{ "kind": "identifier", "not_kind": "identifier" }]
        },
        "limit": 1
    }))
    .expect("structural benchmark query should parse");
    let mut match_times = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let started = Instant::now();
        let result = execute(analyzer, &query);
        match_times.push(started.elapsed().as_secs_f64() * 1_000.0);
        assert!(
            result.results.is_empty(),
            "a role target cannot both be and not be an identifier"
        );
        std::hint::black_box(result);
    }
    let warm_match_median_ms = median(&mut match_times);
    let rss_after_matching = peak_rss_bytes();

    eprintln!("\n=== structural facts role-storage benchmark ===");
    eprintln!(
        "fixture: {}, workspace: {}",
        if generated { "generated" } else { "repository" },
        root.display()
    );
    eprintln!(
        "candidate files: {candidate_file_count}, extracted: {extracted_file_count}, skipped: {skipped_file_count}, calls/file: {}, facts: {fact_count}, roles: {role_count}",
        if generated {
            calls_per_file.to_string()
        } else {
            "n/a".to_string()
        }
    );
    eprintln!(
        "analyzer build: {analyzer_build_ms:.1} ms, cold extraction: {cold_extraction_ms:.1} ms"
    );
    eprintln!("warm role-heavy match median: {warm_match_median_ms:.1} ms");
    eprintln!(
        "estimated retained facts: {:.1} MB",
        mb(estimated_retained_bytes)
    );
    eprintln!("peak RSS at start:             {:.1} MB", mb(rss_start));
    eprintln!(
        "peak RSS after analyzer:        {:.1} MB",
        mb(rss_after_analyzer)
    );
    eprintln!(
        "peak RSS after fact extraction: {:.1} MB",
        mb(rss_after_extraction)
    );
    eprintln!(
        "peak RSS after warm matching:   {:.1} MB\n",
        mb(rss_after_matching)
    );

    let result = StructuralFactsBenchmarkResult {
        format: "bifrost_structural_facts_benchmark/v1",
        fixture: if generated { "generated" } else { "repository" },
        workspace: root.display().to_string(),
        bifrost_commit: workspace_commit(Path::new(env!("CARGO_MANIFEST_DIR"))),
        workspace_commit: workspace_commit(&root),
        candidate_files: candidate_file_count,
        extracted_files: extracted_file_count,
        skipped_files: skipped_file_count,
        calls_per_file: generated.then_some(calls_per_file),
        iterations,
        parallelism,
        analyzer_build_ms,
        cold_extraction_ms,
        warm_match_median_ms,
        facts: fact_count,
        roles: role_count,
        estimated_retained_bytes,
        peak_rss_start_bytes: rss_start,
        peak_rss_after_analyzer_bytes: rss_after_analyzer,
        peak_rss_after_extraction_bytes: rss_after_extraction,
        peak_rss_after_matching_bytes: rss_after_matching,
    };
    eprintln!(
        "BIFROST_STRUCTURAL_FACTS_BENCHMARK={}",
        serde_json::to_string(&result).expect("serialize structural benchmark result")
    );
}
