//! Reproducible hierarchy and ownership benchmark for issue #748.
//!
//! The generated Java workspace is a bounded-depth tree of exact declarations.
//! It measures construction and reads of the global reverse hierarchy index,
//! transitive RQL traversal, and both cached and standalone ownership paths.

use brokk_bifrost::analyzer::structural::{CodeQuery, execute};
use brokk_bifrost::{AnalyzerConfig, Language, Project, TestProject, WorkspaceAnalyzer};
use serde::Serialize;
use serde_json::json;
use std::fs;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use std::time::Instant;
use tempfile::TempDir;

const TYPE_COUNT_ENV: &str = "BIFROST_HIERARCHY_BENCH_TYPES";
const FANOUT_ENV: &str = "BIFROST_HIERARCHY_BENCH_FANOUT";
const MEMBERS_ENV: &str = "BIFROST_HIERARCHY_BENCH_MEMBERS";
const ITERATIONS_ENV: &str = "BIFROST_HIERARCHY_BENCH_ITERATIONS";
const DEFAULT_TYPE_COUNT: usize = 800;
const DEFAULT_FANOUT: usize = 4;
const DEFAULT_MEMBERS: usize = 4;
const DEFAULT_ITERATIONS: usize = 7;

#[derive(Serialize)]
struct HierarchyBenchmarkResult {
    format: &'static str,
    bifrost_commit: Option<String>,
    types: usize,
    hierarchy_edges: usize,
    fanout: usize,
    members_per_type: usize,
    iterations: usize,
    analyzer_build_ms: f64,
    direct_descendants_first_ms: f64,
    direct_descendants_warm_median_ms: f64,
    direct_descendants: usize,
    descendants_first_ms: f64,
    descendants_warm_median_ms: f64,
    descendants: usize,
    rql_subtypes_first_ms: f64,
    rql_subtypes_warm_median_ms: f64,
    rql_subtypes: usize,
    rql_members_owner_first_ms: f64,
    rql_members_owner_warm_median_ms: f64,
    rql_members_owner_results: usize,
    rql_standalone_owner_first_ms: f64,
    rql_standalone_owner_warm_median_ms: f64,
    rql_standalone_owner_results: usize,
    peak_rss_start_bytes: u64,
    peak_rss_after_analyzer_bytes: u64,
    peak_rss_after_hierarchy_index_bytes: u64,
    peak_rss_after_rql_subtypes_bytes: u64,
    peak_rss_after_members_owner_bytes: u64,
    peak_rss_after_standalone_owner_bytes: u64,
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

fn generate_workspace(root: &Path, type_count: usize, fanout: usize, members: usize) {
    let package = root.join("bench");
    fs::create_dir(&package).expect("create hierarchy benchmark package");
    for index in 0..type_count {
        let parent = (index > 0).then(|| (index - 1) / fanout);
        let mut source = String::from("package bench;\n");
        match parent {
            Some(parent) => source.push_str(&format!(
                "public class Node{index:04} extends Node{parent:04} {{\n"
            )),
            None => source.push_str(&format!("public class Node{index:04} {{\n")),
        }
        source.push_str("    int field;\n");
        for member in 0..members {
            source.push_str(&format!("    void member{member:02}() {{ sink(); }}\n"));
        }
        source.push_str("    void sink() {}\n");
        source.push_str("}\n");
        fs::write(package.join(format!("Node{index:04}.java")), source)
            .expect("write hierarchy benchmark type");
    }
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

fn timed_median<T>(iterations: usize, mut operation: impl FnMut() -> T) -> f64 {
    let mut times = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let started = Instant::now();
        std::hint::black_box(operation());
        times.push(started.elapsed().as_secs_f64() * 1_000.0);
    }
    median(&mut times)
}

#[test]
#[ignore = "measure-first hierarchy benchmark; run explicitly with --ignored --nocapture"]
fn hierarchy_memory_and_reads() {
    let type_count = positive_env(TYPE_COUNT_ENV, DEFAULT_TYPE_COUNT, 1_000);
    let fanout = positive_env(FANOUT_ENV, DEFAULT_FANOUT, 32).min(type_count);
    let members = positive_env(MEMBERS_ENV, DEFAULT_MEMBERS, 16);
    let iterations = positive_env(ITERATIONS_ENV, DEFAULT_ITERATIONS, 50);
    let temp = TempDir::new().expect("hierarchy benchmark temp dir");
    generate_workspace(temp.path(), type_count, fanout, members);

    let rss_start = peak_rss_bytes();
    let project: Arc<dyn Project> =
        Arc::new(TestProject::new(temp.path().to_path_buf(), Language::Java));
    let analyzer_started = Instant::now();
    let workspace = WorkspaceAnalyzer::build(
        project,
        AnalyzerConfig {
            parallelism: Some(1),
            memo_cache_budget_bytes: Some(2 * 1024 * 1024 * 1024),
            ..AnalyzerConfig::default()
        },
    );
    let analyzer_build_ms = analyzer_started.elapsed().as_secs_f64() * 1_000.0;
    let rss_after_analyzer = peak_rss_bytes();
    let analyzer = workspace.analyzer();
    let root = analyzer
        .all_declarations()
        .find(|unit| unit.fq_name() == "bench.Node0000")
        .expect("generated hierarchy root declaration");
    let hierarchy = analyzer
        .type_hierarchy_provider()
        .expect("Java hierarchy provider");

    let direct_started = Instant::now();
    let direct = hierarchy.get_direct_descendants(&root);
    let direct_descendants_first_ms = direct_started.elapsed().as_secs_f64() * 1_000.0;
    assert_eq!(direct.len(), fanout.min(type_count.saturating_sub(1)));
    let direct_descendants_warm_median_ms =
        timed_median(iterations, || hierarchy.get_direct_descendants(&root));
    let rss_after_hierarchy_index = peak_rss_bytes();

    let descendants_started = Instant::now();
    let descendants = hierarchy.get_descendants(&root);
    let descendants_first_ms = descendants_started.elapsed().as_secs_f64() * 1_000.0;
    assert_eq!(descendants.len(), type_count - 1);
    let descendants_warm_median_ms = timed_median(iterations, || hierarchy.get_descendants(&root));

    let subtypes_query = CodeQuery::from_json(&json!({
        "match": { "kind": "class", "name": "Node0000" },
        "steps": [
            { "op": "enclosing_decl" },
            { "op": "subtypes", "transitive": true }
        ],
        "limit": type_count
    }))
    .expect("hierarchy benchmark query should parse");
    let subtypes_started = Instant::now();
    let subtypes = execute(analyzer, &subtypes_query);
    let rql_subtypes_first_ms = subtypes_started.elapsed().as_secs_f64() * 1_000.0;
    assert!(!subtypes.truncated, "{:#?}", subtypes.diagnostics);
    assert_eq!(subtypes.results.len(), type_count - 1);
    let rql_subtypes_warm_median_ms =
        timed_median(iterations, || execute(analyzer, &subtypes_query));
    let rss_after_rql_subtypes = peak_rss_bytes();

    let members_owner_query = CodeQuery::from_json(&json!({
        "match": { "kind": "class", "name": { "regex": "^Node[0-9]+$" } },
        "steps": [
            { "op": "enclosing_decl" },
            { "op": "members" },
            { "op": "owner" }
        ],
        "limit": type_count
    }))
    .expect("members-owner benchmark query should parse");
    let members_owner_started = Instant::now();
    let members_owner = execute(analyzer, &members_owner_query);
    let rql_members_owner_first_ms = members_owner_started.elapsed().as_secs_f64() * 1_000.0;
    assert!(!members_owner.truncated, "{:#?}", members_owner.diagnostics);
    assert_eq!(members_owner.results.len(), type_count);
    let rql_members_owner_warm_median_ms =
        timed_median(iterations, || execute(analyzer, &members_owner_query));
    let rss_after_members_owner = peak_rss_bytes();

    let standalone_owner_query = CodeQuery::from_json(&json!({
        "match": { "kind": "call", "callee": { "name": "sink" } },
        "steps": [{ "op": "enclosing_decl" }, { "op": "owner" }],
        "limit": type_count
    }))
    .expect("standalone owner benchmark query should parse");
    let standalone_owner_started = Instant::now();
    let standalone_owner = execute(analyzer, &standalone_owner_query);
    let rql_standalone_owner_first_ms = standalone_owner_started.elapsed().as_secs_f64() * 1_000.0;
    assert!(
        !standalone_owner.truncated,
        "{:#?}",
        standalone_owner.diagnostics
    );
    assert_eq!(standalone_owner.results.len(), type_count);
    let rql_standalone_owner_warm_median_ms =
        timed_median(iterations, || execute(analyzer, &standalone_owner_query));
    let rss_after_standalone_owner = peak_rss_bytes();

    let result = HierarchyBenchmarkResult {
        format: "bifrost_hierarchy_benchmark/v1",
        bifrost_commit: workspace_commit(Path::new(env!("CARGO_MANIFEST_DIR"))),
        types: type_count,
        hierarchy_edges: type_count - 1,
        fanout,
        members_per_type: members,
        iterations,
        analyzer_build_ms,
        direct_descendants_first_ms,
        direct_descendants_warm_median_ms,
        direct_descendants: direct.len(),
        descendants_first_ms,
        descendants_warm_median_ms,
        descendants: descendants.len(),
        rql_subtypes_first_ms,
        rql_subtypes_warm_median_ms,
        rql_subtypes: subtypes.results.len(),
        rql_members_owner_first_ms,
        rql_members_owner_warm_median_ms,
        rql_members_owner_results: members_owner.results.len(),
        rql_standalone_owner_first_ms,
        rql_standalone_owner_warm_median_ms,
        rql_standalone_owner_results: standalone_owner.results.len(),
        peak_rss_start_bytes: rss_start,
        peak_rss_after_analyzer_bytes: rss_after_analyzer,
        peak_rss_after_hierarchy_index_bytes: rss_after_hierarchy_index,
        peak_rss_after_rql_subtypes_bytes: rss_after_rql_subtypes,
        peak_rss_after_members_owner_bytes: rss_after_members_owner,
        peak_rss_after_standalone_owner_bytes: rss_after_standalone_owner,
    };
    eprintln!(
        "BIFROST_HIERARCHY_BENCHMARK={}",
        serde_json::to_string(&result).expect("serialize hierarchy benchmark")
    );
}
