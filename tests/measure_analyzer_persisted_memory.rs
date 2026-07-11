//! Measure-first resident-memory benchmark for the SQL-native persisted analyzer.
//!
//! Ignored by default (large fixture, subprocesses). Run:
//!   BIFROST_SEMANTIC_INDEX=off cargo test --test measure_analyzer_persisted_memory -- --ignored --nocapture

use brokk_bifrost::analyzer::store::AnalyzerStore;
use brokk_bifrost::analyzer::{BuildProgressEvent, BuildProgressPhase};
use brokk_bifrost::{AnalyzerConfig, Language, Project, TestProject, WorkspaceAnalyzer};
use git2::{IndexAddOption, Repository, Signature};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

const SMALL_MODULES: usize = 200;
const LARGE_MODULES: usize = 2000;
const CHILD_ENV: &str = "BIFROST_ANALYZER_MEMORY_CHILD_MODULES";
const CHILD_ROOT_ENV: &str = "BIFROST_ANALYZER_MEMORY_CHILD_ROOT";
const CHILD_MODE_ENV: &str = "BIFROST_ANALYZER_MEMORY_CHILD_MODE";
const RESULT_PREFIX: &str = "ANALYZER_MEMORY_RESULT ";

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

#[cfg(target_os = "linux")]
fn current_rss_bytes() -> u64 {
    let statm = std::fs::read_to_string("/proc/self/statm").expect("read /proc/self/statm");
    let resident_pages = statm
        .split_whitespace()
        .nth(1)
        .expect("resident pages")
        .parse::<u64>()
        .expect("parse resident pages");
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    assert!(page_size > 0, "sysconf(_SC_PAGESIZE) failed");
    resident_pages * page_size as u64
}

#[cfg(not(target_os = "linux"))]
fn current_rss_bytes() -> u64 {
    peak_rss_bytes()
}

fn mb(bytes: u64) -> f64 {
    bytes as f64 / (1024.0 * 1024.0)
}

fn init_repo(root: &Path) -> Repository {
    let repo = Repository::init(root).unwrap();
    let mut config = repo.config().unwrap();
    config.set_str("user.name", "Bifrost Test").unwrap();
    config.set_str("user.email", "bifrost@example.com").unwrap();
    repo
}

fn commit_all(repo: &Repository, message: &str) {
    let mut index = repo.index().unwrap();
    index.add_all(["*"], IndexAddOption::DEFAULT, None).unwrap();
    index.write().unwrap();
    let tree_oid = index.write_tree().unwrap();
    let tree = repo.find_tree(tree_oid).unwrap();
    let sig = Signature::now("Bifrost Test", "bifrost@example.com").unwrap();
    let parents = repo
        .head()
        .ok()
        .and_then(|head| head.target())
        .and_then(|oid| repo.find_commit(oid).ok())
        .into_iter()
        .collect::<Vec<_>>();
    let parent_refs = parents.iter().collect::<Vec<_>>();
    repo.commit(Some("HEAD"), &sig, &sig, message, &tree, &parent_refs)
        .unwrap();
}

fn generate_python_workspace(root: &Path, module_count: usize) {
    std::fs::create_dir_all(root.join("pkg")).unwrap();
    std::fs::write(root.join("pkg/__init__.py"), "").unwrap();
    for module in 0..module_count {
        let mut source = format!("class Module{module:05}:\n");
        for method in 0..18 {
            source.push_str(&format!(
                "    def method_{method}(self, value):\n\
                 \x20       total = value + {method}\n\
                 \x20       label = \"module_{module:05}_{method}\"\n\
                 \x20       return f\"{{label}}:{{total}}\"\n\n"
            ));
        }
        std::fs::write(root.join(format!("pkg/mod_{module:05}.py")), source).unwrap();
    }
}

#[derive(Debug, Clone, Copy)]
enum MeasureMode {
    Cold,
    Warm,
}

impl MeasureMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Cold => "cold",
            Self::Warm => "warm",
        }
    }

    fn parse(value: &str) -> Self {
        match value {
            "cold" => Self::Cold,
            "warm" => Self::Warm,
            other => panic!("unknown benchmark mode {other:?}"),
        }
    }
}

#[derive(Debug, Clone)]
struct Measurement {
    mode: String,
    modules: usize,
    before: u64,
    after: u64,
    delta: u64,
    peak_after: u64,
    parses: usize,
    fresh_parse_error_files: usize,
}

fn setup_workspace(module_count: usize) -> tempfile::TempDir {
    let temp = tempfile::tempdir().unwrap();
    let root: PathBuf = temp.path().canonicalize().unwrap();
    generate_python_workspace(&root, module_count);
    let repo = init_repo(&root);
    commit_all(&repo, "fixture");

    let store = AnalyzerStore::open_for_workspace(&root).unwrap();
    store.gc_with(|_| true).unwrap();

    temp
}

fn run_child(root: &Path, modules: usize, mode: MeasureMode) -> Measurement {
    let exe = std::env::current_exe().expect("current test binary");
    let output = Command::new(exe)
        .arg("--exact")
        .arg("analyzer_persisted_memory_child")
        .arg("--ignored")
        .arg("--nocapture")
        .env(CHILD_ENV, modules.to_string())
        .env(CHILD_ROOT_ENV, root)
        .env(CHILD_MODE_ENV, mode.as_str())
        .output()
        .expect("spawn child benchmark");
    assert!(
        output.status.success(),
        "child benchmark failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    parse_measurement(&combined).unwrap_or_else(|| {
        panic!("child benchmark did not print result line:\n{combined}");
    })
}

fn parse_measurement(output: &str) -> Option<Measurement> {
    let line = output
        .lines()
        .find_map(|line| line.strip_prefix(RESULT_PREFIX))?;
    let mut mode = None;
    let mut modules = None;
    let mut before = None;
    let mut after = None;
    let mut delta = None;
    let mut peak_after = None;
    let mut parses = None;
    let mut fresh_parse_error_files = None;
    for part in line.split_whitespace() {
        let (key, value) = part.split_once('=')?;
        if key == "mode" {
            mode = Some(value.to_string());
            continue;
        }
        let value = value.parse::<u64>().ok()?;
        match key {
            "modules" => modules = Some(value as usize),
            "before" => before = Some(value),
            "after" => after = Some(value),
            "delta" => delta = Some(value),
            "peak_after" => peak_after = Some(value),
            "parses" => parses = Some(value as usize),
            "fresh_parse_error_files" => fresh_parse_error_files = Some(value as usize),
            _ => {}
        }
    }
    Some(Measurement {
        mode: mode?,
        modules: modules?,
        before: before?,
        after: after?,
        delta: delta?,
        peak_after: peak_after?,
        parses: parses?,
        fresh_parse_error_files: fresh_parse_error_files?,
    })
}

fn run_size(module_count: usize) -> (Measurement, Measurement, tempfile::TempDir) {
    let temp = setup_workspace(module_count);
    let root = temp.path().canonicalize().unwrap();
    let cold = run_child(&root, module_count, MeasureMode::Cold);
    let warm = run_child(&root, module_count, MeasureMode::Warm);
    (cold, warm, temp)
}

fn print_measurement(label: &str, measurement: &Measurement) {
    eprintln!(
        "{label} {mode}: modules={modules}, before={before:.1} MB, after={after:.1} MB, delta={delta:.1} MB, peak_after={peak_after:.1} MB, parses={parses}, fresh_parse_error_files={fresh_parse_error_files}",
        mode = measurement.mode,
        modules = measurement.modules,
        before = mb(measurement.before),
        after = mb(measurement.after),
        delta = mb(measurement.delta),
        peak_after = mb(measurement.peak_after),
        parses = measurement.parses,
        fresh_parse_error_files = measurement.fresh_parse_error_files,
    );
}

#[test]
#[ignore = "measure-first memory benchmark; run explicitly with --ignored --nocapture"]
fn analyzer_persisted_memory_does_not_scale_with_total_source_size() {
    let (small_cold, small_warm, _small_temp) = run_size(SMALL_MODULES);
    let (large_cold, large_warm, _large_temp) = run_size(LARGE_MODULES);
    eprintln!("\n=== persisted analyzer resident RSS ===");
    print_measurement("small", &small_cold);
    print_measurement("small", &small_warm);
    print_measurement("large", &large_cold);
    print_measurement("large", &large_warm);

    assert_eq!(small_cold.modules, SMALL_MODULES);
    assert_eq!(small_warm.modules, SMALL_MODULES);
    assert_eq!(large_cold.modules, LARGE_MODULES);
    assert_eq!(large_warm.modules, LARGE_MODULES);
    assert_eq!(large_warm.modules / small_warm.modules, 10);
    assert_eq!(small_cold.mode, "cold");
    assert_eq!(small_warm.mode, "warm");
    assert_eq!(large_cold.mode, "cold");
    assert_eq!(large_warm.mode, "warm");
    assert_eq!(small_warm.parses, 0);
    assert_eq!(large_warm.parses, 0);
    assert_eq!(small_warm.fresh_parse_error_files, 0);
    assert_eq!(large_warm.fresh_parse_error_files, 0);

    // Observed warm deltas on the benchmark host were near-flat for 200 vs 2000
    // modules: 11.9 MB and 15.0 MB. Cold cache-population deltas were 24.4 MB
    // and 96.7 MB because parsing and SQLite/allocator retention scale during
    // cache population. The 2x multiplier catches revived per-file resident
    // state; the fixed 32 MB covers SQLite mmap/page-cache variation and the
    // tiny O(files) LivePathMap/path allocation.
    let allowed = small_warm.delta.saturating_mul(2) + 32 * 1024 * 1024;
    assert!(
        large_warm.delta <= allowed,
        "warm resident construction delta grew too much: small {:.1} MB, large {:.1} MB, bound {:.1} MB",
        mb(small_warm.delta),
        mb(large_warm.delta),
        mb(allowed)
    );
}

#[test]
#[ignore = "subprocess entry point for analyzer_persisted_memory_does_not_scale_with_total_source_size"]
fn analyzer_persisted_memory_child() {
    let Ok(modules) = std::env::var(CHILD_ENV) else {
        return;
    };
    let modules = modules.parse::<usize>().expect("parse child module count");
    let root = PathBuf::from(std::env::var(CHILD_ROOT_ENV).expect("child root env"));
    let mode = MeasureMode::parse(&std::env::var(CHILD_MODE_ENV).expect("child mode env"));
    let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Python));
    let parses = Arc::new(AtomicUsize::new(0));
    let parse_counter = Arc::clone(&parses);
    let before = current_rss_bytes();
    let workspace = WorkspaceAnalyzer::build_persisted_with_progress(
        project.clone(),
        AnalyzerConfig::default(),
        {
            move |event: BuildProgressEvent| {
                if event.phase == BuildProgressPhase::Parse {
                    parse_counter.fetch_add(1, Ordering::Relaxed);
                }
            }
        },
    );
    let after = current_rss_bytes();
    let peak_after = peak_rss_bytes();
    let parses = parses.load(Ordering::Relaxed);
    if matches!(mode, MeasureMode::Cold) {
        assert!(parses > 0, "cold build should parse at least one file");
        let declarations = workspace.analyzer().all_declarations().count();
        assert!(
            declarations >= modules,
            "expected at least one declaration per module, got {declarations}"
        );
    }
    let fresh_parse_error_files = project
        .analyzable_files(Language::Python)
        .unwrap()
        .iter()
        .filter(|file| workspace.analyzer().parse_errors(file).is_some())
        .count();
    println!(
        "{RESULT_PREFIX}mode={} modules={modules} before={before} after={after} delta={} peak_after={peak_after} parses={parses} fresh_parse_error_files={fresh_parse_error_files}",
        mode.as_str(),
        after.saturating_sub(before),
    );
}
