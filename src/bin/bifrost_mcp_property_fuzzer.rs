//! CLI driver for the MCP property fuzzer (see
//! `.agents/plans/mcp_property_fuzzer.md`). Mirrors the argument, record, and
//! resume conventions of `bifrost_reference_differential` (FIRD) so operators
//! can run both campaigns with the same muscle memory:
//!
//!     bifrost_mcp_property_fuzzer \
//!       --clones-root /path/to/clones --repo owner__name \
//!       --invariants I1 --out ledger.jsonl
//!
//! Current scope: `--repo` selection (repeatable), I1 as an index walk plus
//! I1(c)/I2–I5 through an in-process `SearchToolsService` (both render modes),
//! JSONL ledger with FIRD-style resume. Corpus-wide selection, concurrency,
//! shrinking, and `--rerun` arrive in M3.

use brokk_bifrost::mcp_property_fuzzer::service_probes::{
    DEFAULT_MAX_SCAN_PROBES, DEFAULT_MAX_SERVICE_SYMBOLS,
};
use brokk_bifrost::mcp_property_fuzzer::{
    FuzzerConfig, FuzzerReport, InvariantKind, run_invariants_with_service,
};
use brokk_bifrost::searchtools_service::SearchToolsService;
use brokk_bifrost::{AnalyzerConfig, FilesystemProject, Project};
use git2::{Repository, StatusOptions};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

const SCHEMA_VERSION: u32 = 1;
const CORPUS_LANGUAGES: [&str; 11] = [
    "c", "cpp", "csharp", "go", "java", "js", "php", "py", "rust", "scala", "ts",
];

const DEFAULT_MAX_SYMBOLS: usize = 5_000;
const DEFAULT_PARALLELISM: usize = 8;

fn main() -> ExitCode {
    match run() {
        Ok(true) => ExitCode::from(2),
        Ok(false) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("{err}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<bool, String> {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        print_help();
        return Err("missing arguments".to_string());
    }
    if args
        .iter()
        .any(|arg| matches!(arg.as_str(), "--help" | "-h"))
    {
        print_help();
        return Ok(false);
    }
    let parsed = parse_args(&args)?;
    execute(&parsed)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CacheMode {
    Persisted,
    Ephemeral,
}

impl CacheMode {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "persisted" => Ok(Self::Persisted),
            "ephemeral" => Ok(Self::Ephemeral),
            _ => Err(format!(
                "--cache-mode expects `persisted` or `ephemeral`, got `{value}`"
            )),
        }
    }

    /// Ledger label. Recorded per run because the mode determines whether
    /// parse-error-dependent checks (I1d) were live: only cold parses retain
    /// tree-sitter ERROR nodes.
    fn as_str(self) -> &'static str {
        match self {
            Self::Persisted => "persisted",
            Self::Ephemeral => "ephemeral",
        }
    }
}

#[derive(Debug)]
struct FuzzerArgs {
    clones_root: PathBuf,
    commits_root: Option<PathBuf>,
    out: PathBuf,
    repos: Vec<String>,
    languages: Vec<String>,
    invariants: Vec<InvariantKind>,
    max_symbols: usize,
    max_service_symbols: usize,
    max_scan_probes: usize,
    symbol_filter: Option<String>,
    dump_probes: Option<PathBuf>,
    seed: u64,
    parallelism: usize,
    cache_mode: CacheMode,
    strict: bool,
    force: bool,
    dry_run: bool,
}

fn parse_args(args: &[String]) -> Result<FuzzerArgs, String> {
    let mut clones_root = None;
    let mut commits_root = None;
    let mut out = None;
    let mut repos = Vec::new();
    let mut languages = Vec::new();
    let mut invariants = None;
    let mut max_symbols = DEFAULT_MAX_SYMBOLS;
    let mut max_service_symbols = DEFAULT_MAX_SERVICE_SYMBOLS;
    let mut max_scan_probes = DEFAULT_MAX_SCAN_PROBES;
    let mut symbol_filter = None;
    let mut dump_probes = None;
    let mut seed = 0_u64;
    let mut parallelism = DEFAULT_PARALLELISM;
    let mut cache_mode = CacheMode::Persisted;
    let mut strict = false;
    let mut force = false;
    let mut dry_run = false;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--clones-root" => {
                clones_root = Some(PathBuf::from(take_value(
                    args,
                    &mut index,
                    "--clones-root",
                )?))
            }
            "--commits-root" => {
                commits_root = Some(PathBuf::from(take_value(
                    args,
                    &mut index,
                    "--commits-root",
                )?))
            }
            "--out" => out = Some(PathBuf::from(take_value(args, &mut index, "--out")?)),
            "--repo" => repos.push(take_value(args, &mut index, "--repo")?),
            "--language" => languages.push(normalize_language(&take_value(
                args,
                &mut index,
                "--language",
            )?)?),
            "--invariants" => {
                invariants = Some(InvariantKind::parse_list(&take_value(
                    args,
                    &mut index,
                    "--invariants",
                )?)?)
            }
            "--max-symbols" => {
                max_symbols = take_positive_usize(args, &mut index, "--max-symbols")?
            }
            "--max-service-symbols" => {
                max_service_symbols =
                    take_positive_usize(args, &mut index, "--max-service-symbols")?
            }
            "--max-scan-probes" => {
                max_scan_probes = take_positive_usize(args, &mut index, "--max-scan-probes")?
            }
            "--symbol-filter" => {
                symbol_filter = Some(take_value(args, &mut index, "--symbol-filter")?)
            }
            "--dump-probes" => {
                dump_probes = Some(PathBuf::from(take_value(
                    args,
                    &mut index,
                    "--dump-probes",
                )?))
            }
            "--seed" => {
                let value = take_value(args, &mut index, "--seed")?;
                seed = value
                    .parse::<u64>()
                    .map_err(|_| format!("--seed expects a non-negative integer, got `{value}`"))?;
            }
            "--jobs" => parallelism = take_positive_usize(args, &mut index, "--jobs")?,
            "--cache-mode" => {
                cache_mode = CacheMode::parse(&take_value(args, &mut index, "--cache-mode")?)?
            }
            "--strict" => strict = true,
            "--force" => force = true,
            "--dry-run" => dry_run = true,
            other => return Err(format!("unknown argument: {other}")),
        }
        index += 1;
    }
    if repos.is_empty() {
        return Err(
            "--repo is required (corpus-wide selection arrives with M3; repeat --repo to audit several clones)"
                .to_string(),
        );
    }
    if !dry_run && out.is_none() {
        return Err("--out is required unless --dry-run is used".to_string());
    }
    Ok(FuzzerArgs {
        clones_root: clones_root.ok_or_else(|| "--clones-root is required".to_string())?,
        commits_root,
        out: out.unwrap_or_default(),
        repos,
        languages,
        invariants: invariants.unwrap_or_else(|| {
            vec![
                InvariantKind::I1,
                InvariantKind::I2,
                InvariantKind::I3,
                InvariantKind::I4,
                InvariantKind::I5,
            ]
        }),
        max_symbols,
        max_service_symbols,
        max_scan_probes,
        symbol_filter,
        dump_probes,
        seed,
        parallelism,
        cache_mode,
        strict,
        force,
        dry_run,
    })
}

fn take_value(args: &[String], index: &mut usize, option: &str) -> Result<String, String> {
    *index += 1;
    args.get(*index)
        .cloned()
        .ok_or_else(|| format!("{option} requires a value"))
}

fn take_positive_usize(args: &[String], index: &mut usize, option: &str) -> Result<usize, String> {
    let value = take_value(args, index, option)?;
    let parsed = value
        .parse::<usize>()
        .map_err(|_| format!("{option} expects a positive integer, got `{value}`"))?;
    if parsed == 0 {
        return Err(format!("{option} must be greater than zero"));
    }
    Ok(parsed)
}

fn normalize_language(value: &str) -> Result<String, String> {
    let normalized = match value.trim().to_ascii_lowercase().as_str() {
        "c" => "c",
        "cpp" | "c++" => "cpp",
        "csharp" | "c#" | "cs" => "csharp",
        "go" => "go",
        "java" => "java",
        "js" | "javascript" => "js",
        "php" => "php",
        "py" | "python" => "py",
        "rust" => "rust",
        "scala" => "scala",
        "ts" | "typescript" => "ts",
        _ => {
            return Err(format!(
                "unsupported corpus language `{value}`; expected one of {}",
                CORPUS_LANGUAGES.join(", ")
            ));
        }
    };
    Ok(normalized.to_string())
}

#[derive(Debug)]
struct SelectedRepository {
    language: String,
    slug: String,
    root: PathBuf,
}

/// Resolve each `--repo` slug to a validated clone and its corpus language.
/// The language comes from the single `--language` flag when exactly one is
/// given, otherwise from `<commits-root>/<language>/<slug>.jsonl` membership,
/// falling back to `unknown` when no commits root is available.
fn select_repositories(args: &FuzzerArgs) -> Result<Vec<SelectedRepository>, String> {
    let clones_root = args.clones_root.canonicalize().map_err(|err| {
        format!(
            "failed to canonicalize clones root `{}`: {err}",
            args.clones_root.display()
        )
    })?;
    let mut selected = Vec::new();
    for slug in &args.repos {
        let root = validate_clone(&clones_root.join(slug))?;
        let language = repository_language(args, slug)?;
        if !args.languages.is_empty() && !args.languages.contains(&language) {
            return Err(format!(
                "repo `{slug}` is registered as `{language}` which is not among the --language filter(s) {}",
                args.languages.join(", ")
            ));
        }
        selected.push(SelectedRepository {
            language,
            slug: slug.clone(),
            root,
        });
    }
    Ok(selected)
}

fn repository_language(args: &FuzzerArgs, slug: &str) -> Result<String, String> {
    if args.languages.len() == 1 {
        return Ok(args.languages[0].clone());
    }
    let Some(commits_root) = &args.commits_root else {
        return Ok("unknown".to_string());
    };
    let mut matches = Vec::new();
    for language in CORPUS_LANGUAGES {
        if commits_root
            .join(language)
            .join(format!("{slug}.jsonl"))
            .is_file()
        {
            matches.push(language.to_string());
        }
    }
    match matches.len() {
        0 => Ok("unknown".to_string()),
        1 => Ok(matches.remove(0)),
        _ => Err(format!(
            "repo `{slug}` is registered under multiple corpus languages: {}",
            matches.join(", ")
        )),
    }
}

fn validate_clone(path: &Path) -> Result<PathBuf, String> {
    let root = path
        .canonicalize()
        .map_err(|err| format!("invalid clone `{}`: {err}", path.display()))?;
    if !root.is_dir() {
        return Err(format!(
            "invalid clone `{}`: not a directory",
            root.display()
        ));
    }
    let repo = Repository::open(&root)
        .map_err(|err| format!("invalid clone `{}`: {err}", root.display()))?;
    if repo.is_bare() || repo.workdir().is_none() {
        return Err(format!(
            "invalid clone `{}`: expected a non-bare working tree",
            root.display()
        ));
    }
    repo.head()
        .and_then(|head| head.peel_to_commit())
        .map_err(|err| format!("invalid clone `{}`: no HEAD commit: {err}", root.display()))?;
    Ok(root)
}

#[derive(Debug)]
struct RepositoryMetadata {
    head: String,
    dirty: bool,
}

fn repository_metadata(root: &Path) -> Result<RepositoryMetadata, String> {
    let repo = Repository::open(root)
        .map_err(|err| format!("failed to open repository `{}`: {err}", root.display()))?;
    let head = repo
        .head()
        .and_then(|head| head.peel_to_commit())
        .map_err(|err| format!("failed to resolve HEAD for `{}`: {err}", root.display()))?
        .id()
        .to_string();
    let mut options = StatusOptions::new();
    options
        .include_untracked(true)
        .recurse_untracked_dirs(true)
        .include_ignored(false);
    let dirty = !repo
        .statuses(Some(&mut options))
        .map_err(|err| format!("failed to inspect status for `{}`: {err}", root.display()))?
        .is_empty();
    Ok(RepositoryMetadata { head, dirty })
}

#[derive(Debug, Serialize)]
struct RepositoryRecord {
    schema_version: u32,
    record_type: &'static str,
    bifrost_version: &'static str,
    bifrost_head: String,
    bifrost_dirty: bool,
    corpus_language: String,
    analyzer_language: &'static str,
    repo_slug: String,
    repo_head: String,
    repo_dirty: bool,
    cache_mode: &'static str,
    run_fingerprint: String,
    elapsed_seconds: f64,
    #[serde(flatten)]
    result: RepositoryResult,
}

#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum RepositoryResult {
    Completed { report: Box<FuzzerReport> },
    EngineError { message: String },
}

fn execute(args: &FuzzerArgs) -> Result<bool, String> {
    let selected = select_repositories(args)?;
    if args.dry_run {
        for repo in &selected {
            println!("{}\t{}\t{}", repo.language, repo.slug, repo.root.display());
        }
        return Ok(false);
    }

    let bifrost_metadata = repository_metadata(Path::new(env!("CARGO_MANIFEST_DIR")))?;
    let completed = if args.force {
        HashSet::new()
    } else {
        completed_runs(&args.out)?
    };
    let mut strict_failure = false;
    let total = selected.len();
    for (position, repo) in selected.into_iter().enumerate() {
        let config = FuzzerConfig {
            corpus_language: repo.language.clone(),
            invariants: args.invariants.clone(),
            max_symbols: args.max_symbols,
            max_service_symbols: args.max_service_symbols,
            max_scan_probes: args.max_scan_probes,
            symbol_filter: args.symbol_filter.clone(),
            seed: args.seed,
        };
        let fingerprint = run_fingerprint(&config)?;
        let metadata = repository_metadata(&repo.root)?;
        let key = CompletionKey::new(
            &repo.language,
            &repo.slug,
            &metadata.head,
            &bifrost_metadata.head,
            &fingerprint,
        );
        if completed.contains(&key) {
            eprintln!(
                "[{}/{}] skip {} {}: already completed",
                position + 1,
                total,
                repo.language,
                repo.slug
            );
            continue;
        }
        eprintln!(
            "[{}/{}] run {} {} ({})",
            position + 1,
            total,
            repo.language,
            repo.slug,
            repo.root.display()
        );
        let started = Instant::now();
        // With several repos selected the dump path is suffixed per slug so
        // later repos never overwrite earlier ones.
        let dump_path = args.dump_probes.as_ref().map(|path| {
            if total > 1 {
                path.with_file_name(format!(
                    "{}.{}",
                    path.file_name()
                        .map(|name| name.to_string_lossy().into_owned())
                        .unwrap_or_else(|| "probes.jsonl".to_string()),
                    repo.slug
                ))
            } else {
                path.clone()
            }
        });
        let result = run_engine(
            &repo.root,
            &config,
            args.parallelism,
            args.cache_mode,
            dump_path.as_deref(),
        );
        let record = RepositoryRecord {
            schema_version: SCHEMA_VERSION,
            record_type: "repository",
            bifrost_version: env!("CARGO_PKG_VERSION"),
            bifrost_head: bifrost_metadata.head.clone(),
            bifrost_dirty: bifrost_metadata.dirty,
            corpus_language: repo.language.clone(),
            analyzer_language: analyzer_language(&repo.language),
            repo_slug: repo.slug.clone(),
            repo_head: metadata.head.clone(),
            repo_dirty: metadata.dirty,
            cache_mode: args.cache_mode.as_str(),
            run_fingerprint: fingerprint,
            elapsed_seconds: started.elapsed().as_secs_f64(),
            result: match result {
                Ok(report) => RepositoryResult::Completed {
                    report: Box::new(report),
                },
                Err(message) => RepositoryResult::EngineError { message },
            },
        };
        append_record(&args.out, &record)?;
        match &record.result {
            RepositoryResult::Completed { report } => {
                eprintln!(
                    "[{}/{}] done {} {}: violations={} ({} distinct signature(s)) elapsed={:.1}s",
                    position + 1,
                    total,
                    repo.language,
                    repo.slug,
                    report.violation_count(),
                    report.violations.len(),
                    record.elapsed_seconds
                );
                if args.strict && report.has_actionable_findings() {
                    strict_failure = true;
                }
            }
            RepositoryResult::EngineError { message } => {
                eprintln!(
                    "[{}/{}] failed {} {}: {} elapsed={:.1}s",
                    position + 1,
                    total,
                    repo.language,
                    repo.slug,
                    message,
                    record.elapsed_seconds
                );
            }
        }
    }
    Ok(strict_failure)
}

fn run_engine(
    root: &Path,
    config: &FuzzerConfig,
    parallelism: usize,
    cache_mode: CacheMode,
    probe_dump: Option<&Path>,
) -> Result<FuzzerReport, String> {
    let started = Instant::now();
    eprintln!(
        "progress phase=workspace status=started repo={} jobs={parallelism} elapsed=0.0s",
        config.corpus_language
    );
    let project: std::sync::Arc<dyn Project> = std::sync::Arc::new(
        FilesystemProject::new(root.to_path_buf())
            .map_err(|err| format!("failed to open project: {err}"))?,
    );
    let analyzer_config = AnalyzerConfig {
        parallelism: Some(parallelism),
        ..AnalyzerConfig::default()
    };
    let service = match cache_mode {
        CacheMode::Persisted => {
            SearchToolsService::new_manual_persisted_for_project(project, analyzer_config)
        }
        CacheMode::Ephemeral => {
            SearchToolsService::new_manual_ephemeral_for_project(project, analyzer_config)
        }
    }
    .map_err(|error| format!("failed to build searchtools service: {error}"))?;
    eprintln!(
        "progress phase=workspace status=completed repo={} elapsed={:.1}s",
        config.corpus_language,
        started.elapsed().as_secs_f64()
    );
    let workspace = service.analyzer_snapshot()?;
    let report = run_invariants_with_service(&service, workspace.analyzer(), config, probe_dump)?;
    let probe_calls = report
        .probe_summary
        .as_ref()
        .map(|summary| summary.calls_executed)
        .unwrap_or(0);
    eprintln!(
        "progress phase=checks status=completed repo={} symbols={} probe_calls={} violations={} elapsed={:.1}s",
        config.corpus_language,
        report.i1_summary.symbols_selected,
        probe_calls,
        report.violations.len(),
        started.elapsed().as_secs_f64()
    );
    Ok(report)
}

fn analyzer_language(corpus_language: &str) -> &'static str {
    match corpus_language {
        "c" | "cpp" => "cpp",
        "csharp" => "csharp",
        "js" => "javascript",
        "py" => "python",
        "ts" => "typescript",
        "go" => "go",
        "java" => "java",
        "php" => "php",
        "rust" => "rust",
        "scala" => "scala",
        _ => "unknown",
    }
}

fn run_fingerprint(config: &FuzzerConfig) -> Result<String, String> {
    let bytes = serde_json::to_vec(config)
        .map_err(|err| format!("failed to serialize fuzzer config: {err}"))?;
    let digest = Sha256::digest(bytes);
    Ok(format!("{digest:x}"))
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CompletionKey {
    language: String,
    repo_slug: String,
    repo_head: String,
    bifrost_head: String,
    fingerprint: String,
}

impl CompletionKey {
    fn new(
        language: &str,
        repo_slug: &str,
        repo_head: &str,
        bifrost_head: &str,
        fingerprint: &str,
    ) -> Self {
        Self {
            language: language.to_string(),
            repo_slug: repo_slug.to_string(),
            repo_head: repo_head.to_string(),
            bifrost_head: bifrost_head.to_string(),
            fingerprint: fingerprint.to_string(),
        }
    }
}

fn completed_runs(path: &Path) -> Result<HashSet<CompletionKey>, String> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(HashSet::new()),
        Err(err) => return Err(format!("failed to read output `{}`: {err}", path.display())),
    };
    let mut completed = HashSet::new();
    for (line_index, line) in BufReader::new(file).lines().enumerate() {
        let line = line.map_err(|err| {
            format!(
                "failed to read output `{}` line {}: {err}",
                path.display(),
                line_index + 1
            )
        })?;
        if line.trim().is_empty() {
            continue;
        }
        let value: Value = match serde_json::from_str(&line) {
            Ok(value) => value,
            Err(err) => {
                eprintln!(
                    "ignore invalid JSONL record {}:{}: {err}",
                    path.display(),
                    line_index + 1
                );
                continue;
            }
        };
        if value.get("record_type").and_then(Value::as_str) != Some("repository")
            || value.get("status").and_then(Value::as_str) != Some("completed")
        {
            continue;
        }
        let Some(language) = value.get("corpus_language").and_then(Value::as_str) else {
            continue;
        };
        let Some(repo_slug) = value.get("repo_slug").and_then(Value::as_str) else {
            continue;
        };
        let Some(repo_head) = value.get("repo_head").and_then(Value::as_str) else {
            continue;
        };
        let Some(bifrost_head) = value.get("bifrost_head").and_then(Value::as_str) else {
            continue;
        };
        let Some(fingerprint) = value.get("run_fingerprint").and_then(Value::as_str) else {
            continue;
        };
        completed.insert(CompletionKey::new(
            language,
            repo_slug,
            repo_head,
            bifrost_head,
            fingerprint,
        ));
    }
    Ok(completed)
}

fn append_record(path: &Path, record: &RepositoryRecord) -> Result<(), String> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent).map_err(|err| {
            format!(
                "failed to create output directory `{}`: {err}",
                parent.display()
            )
        })?;
    }
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|err| format!("failed to open output `{}`: {err}", path.display()))?;
    let mut writer = BufWriter::new(file);
    serde_json::to_writer(&mut writer, record)
        .map_err(|err| format!("failed to serialize output record: {err}"))?;
    writer
        .write_all(b"\n")
        .and_then(|_| writer.flush())
        .map_err(|err| format!("failed to append output `{}`: {err}", path.display()))
}

fn print_help() {
    println!(
        "Usage: bifrost_mcp_property_fuzzer --clones-root PATH --repo SLUG [--repo SLUG...] --out PATH [options]"
    );
    println!("  --clones-root PATH     Directory containing corpus clones named owner__repo");
    println!(
        "  --commits-root PATH    Corpus metadata (sft-tools-commits); used to infer repo language"
    );
    println!("  --repo SLUG            Corpus clone to audit; repeatable");
    println!("  --language LANG        Corpus language filter/inference hint; repeatable");
    println!(
        "  --invariants LIST      Comma-separated invariants to check (default: I1,I2,I3,I4,I5)"
    );
    println!("  --out PATH             JSONL ledger to append repository records to");
    println!(
        "  --max-symbols N        Deterministically sampled symbols per repository (default: {DEFAULT_MAX_SYMBOLS})"
    );
    println!(
        "  --max-service-symbols N  Sampled symbols receiving tool-call probes (default: {DEFAULT_MAX_SERVICE_SYMBOLS})"
    );
    println!(
        "  --max-scan-probes N    scan_usages_by_reference probes per repository (default: {DEFAULT_MAX_SCAN_PROBES})"
    );
    println!(
        "  --symbol-filter TEXT   Restrict service probes to symbols whose fq name contains TEXT"
    );
    println!(
        "  --dump-probes PATH     Write every executed probe (arguments + outcomes) as JSONL for triage"
    );
    println!("  --seed N               Deterministic sampling seed (default: 0)");
    println!(
        "  --jobs N               Analyzer workers per repository (default: {DEFAULT_PARALLELISM})"
    );
    println!(
        "  --cache-mode MODE      persisted for warm/resumable campaigns (default); ephemeral for one-off smoke runs"
    );
    println!("  --dry-run              Print the selected repositories without auditing");
    println!("  --strict               Exit 2 when any violation is found");
    println!("  --force                Ignore completed records already in the ledger");
}
