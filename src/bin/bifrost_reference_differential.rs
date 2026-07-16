use brokk_bifrost::reference_differential::{
    ExactReferenceSite, ReferenceDifferentialConfig, ReferenceDifferentialReport,
    run_reference_differential,
};
use brokk_bifrost::{AnalyzerConfig, FilesystemProject, Project, WorkspaceAnalyzer};
use git2::{Repository, StatusOptions};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Instant;

const SCHEMA_VERSION: u32 = 1;
const CORPUS_LANGUAGES: [&str; 11] = [
    "c", "cpp", "csharp", "go", "java", "js", "php", "py", "rust", "scala", "ts",
];

const DEFAULT_MAX_FILES: usize = 1_000;
const DEFAULT_MAX_SITES: usize = 10_000;
const DEFAULT_MAX_CANDIDATES_PER_FILE: usize = 50_000;
const DEFAULT_MAX_SOURCE_BYTES: usize = 4 * 1024 * 1024;
const DEFAULT_MAX_TARGETS: usize = 1_000;
const DEFAULT_MAX_USAGE_FILES: usize = 1_000;
const DEFAULT_MAX_USAGES: usize = 100_000;

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
    let mut args = env::args().skip(1);
    let Some(command) = args.next() else {
        print_help();
        return Err("missing subcommand".to_string());
    };
    let remaining = args.collect::<Vec<_>>();
    match command.as_str() {
        "run-repo" => run_repo_command(parse_run_repo_args(&remaining)?),
        "run-corpus" => run_corpus_command(parse_run_corpus_args(&remaining)?),
        "--help" | "-h" => {
            print_help();
            Ok(false)
        }
        other => Err(format!("unknown subcommand: {other}")),
    }
}

#[derive(Debug, Clone)]
struct EngineOptions {
    max_files: usize,
    max_sites: usize,
    max_candidates_per_file: usize,
    max_source_bytes: usize,
    max_targets: usize,
    max_usage_files: usize,
    max_usages: usize,
    seed: u64,
    include_tests: bool,
    exact_site: Option<ExactReferenceSite>,
    cache_mode: CacheMode,
}

impl Default for EngineOptions {
    fn default() -> Self {
        Self {
            max_files: DEFAULT_MAX_FILES,
            max_sites: DEFAULT_MAX_SITES,
            max_candidates_per_file: DEFAULT_MAX_CANDIDATES_PER_FILE,
            max_source_bytes: DEFAULT_MAX_SOURCE_BYTES,
            max_targets: DEFAULT_MAX_TARGETS,
            max_usage_files: DEFAULT_MAX_USAGE_FILES,
            max_usages: DEFAULT_MAX_USAGES,
            seed: 0,
            include_tests: false,
            exact_site: None,
            cache_mode: CacheMode::Persisted,
        }
    }
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
}

impl EngineOptions {
    fn config(&self, corpus_language: &str) -> ReferenceDifferentialConfig {
        ReferenceDifferentialConfig {
            corpus_language: corpus_language.to_string(),
            max_files: self.max_files,
            max_sites: self.max_sites,
            max_candidates_per_file: self.max_candidates_per_file,
            max_source_bytes: self.max_source_bytes,
            max_targets: self.max_targets,
            max_usage_files: self.max_usage_files,
            max_usages: self.max_usages,
            seed: self.seed,
            include_tests: self.include_tests,
            exact_site: self.exact_site.clone(),
        }
    }
}

#[derive(Debug)]
struct RunRepoArgs {
    root: PathBuf,
    language: String,
    output: PathBuf,
    strict: bool,
    force: bool,
    options: EngineOptions,
}

#[derive(Debug)]
struct RunCorpusArgs {
    clones_root: PathBuf,
    commits_root: PathBuf,
    output: Option<PathBuf>,
    repos_per_language: usize,
    languages: Vec<String>,
    repos: HashSet<String>,
    strict: bool,
    force: bool,
    dry_run: bool,
    options: EngineOptions,
}

fn parse_run_repo_args(args: &[String]) -> Result<RunRepoArgs, String> {
    if args
        .iter()
        .any(|arg| matches!(arg.as_str(), "--help" | "-h"))
    {
        print_run_repo_help();
        std::process::exit(0);
    }
    let mut root = None;
    let mut language = None;
    let mut output = None;
    let mut strict = false;
    let mut force = false;
    let mut options = EngineOptions::default();
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--root" => root = Some(PathBuf::from(take_value(args, &mut index, "--root")?)),
            "--language" => {
                language = Some(normalize_language(&take_value(
                    args,
                    &mut index,
                    "--language",
                )?)?)
            }
            "--output" => output = Some(PathBuf::from(take_value(args, &mut index, "--output")?)),
            "--strict" => strict = true,
            "--force" => force = true,
            other if parse_engine_option(other, args, &mut index, &mut options)? => {}
            other => return Err(format!("unknown run-repo argument: {other}")),
        }
        index += 1;
    }
    finish_exact_site(&mut options)?;
    Ok(RunRepoArgs {
        root: root.ok_or_else(|| "--root is required".to_string())?,
        language: language.ok_or_else(|| "--language is required".to_string())?,
        output: output.ok_or_else(|| "--output is required".to_string())?,
        strict,
        force,
        options,
    })
}

fn parse_run_corpus_args(args: &[String]) -> Result<RunCorpusArgs, String> {
    if args
        .iter()
        .any(|arg| matches!(arg.as_str(), "--help" | "-h"))
    {
        print_run_corpus_help();
        std::process::exit(0);
    }
    let mut clones_root = None;
    let mut commits_root = None;
    let mut output = None;
    let mut repos_per_language = 1;
    let mut languages = Vec::new();
    let mut repos = HashSet::new();
    let mut strict = false;
    let mut force = false;
    let mut dry_run = false;
    let mut options = EngineOptions::default();
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
            "--output" => output = Some(PathBuf::from(take_value(args, &mut index, "--output")?)),
            "--repos-per-language" => {
                repos_per_language = take_positive_usize(args, &mut index, "--repos-per-language")?
            }
            "--language" => languages.push(normalize_language(&take_value(
                args,
                &mut index,
                "--language",
            )?)?),
            "--repo" => {
                repos.insert(take_value(args, &mut index, "--repo")?);
            }
            "--strict" => strict = true,
            "--force" => force = true,
            "--dry-run" => dry_run = true,
            other if parse_engine_option(other, args, &mut index, &mut options)? => {}
            other => return Err(format!("unknown run-corpus argument: {other}")),
        }
        index += 1;
    }
    finish_exact_site(&mut options)?;
    if languages.is_empty() {
        languages.extend(CORPUS_LANGUAGES.map(str::to_string));
    } else {
        dedupe_preserving_order(&mut languages);
    }
    if !dry_run && output.is_none() {
        return Err("--output is required unless --dry-run is used".to_string());
    }
    Ok(RunCorpusArgs {
        clones_root: clones_root.ok_or_else(|| "--clones-root is required".to_string())?,
        commits_root: commits_root.ok_or_else(|| "--commits-root is required".to_string())?,
        output,
        repos_per_language,
        languages,
        repos,
        strict,
        force,
        dry_run,
        options,
    })
}

fn parse_engine_option(
    option: &str,
    args: &[String],
    index: &mut usize,
    options: &mut EngineOptions,
) -> Result<bool, String> {
    match option {
        "--max-files" => options.max_files = take_positive_usize(args, index, option)?,
        "--max-sites" => options.max_sites = take_positive_usize(args, index, option)?,
        "--max-candidates-per-file" => {
            options.max_candidates_per_file = take_positive_usize(args, index, option)?
        }
        "--max-source-bytes" => {
            options.max_source_bytes = take_positive_usize(args, index, option)?
        }
        "--max-targets" => options.max_targets = take_positive_usize(args, index, option)?,
        "--max-usage-files" => options.max_usage_files = take_positive_usize(args, index, option)?,
        "--max-usages" => options.max_usages = take_positive_usize(args, index, option)?,
        "--seed" => {
            let value = take_value(args, index, option)?;
            options.seed = value
                .parse::<u64>()
                .map_err(|_| format!("--seed expects a non-negative integer, got `{value}`"))?;
        }
        "--include-tests" => options.include_tests = true,
        "--cache-mode" => options.cache_mode = CacheMode::parse(&take_value(args, index, option)?)?,
        "--path" => {
            let value = take_value(args, index, option)?;
            let site = options.exact_site.get_or_insert_with(empty_exact_site);
            site.path = value;
        }
        "--start-byte" => {
            let value = take_value(args, index, option)?;
            let parsed = value.parse::<usize>().map_err(|_| {
                format!("--start-byte expects a non-negative integer, got `{value}`")
            })?;
            let site = options.exact_site.get_or_insert_with(empty_exact_site);
            site.start_byte = parsed;
        }
        "--end-byte" => {
            let value = take_value(args, index, option)?;
            let parsed = value
                .parse::<usize>()
                .map_err(|_| format!("--end-byte expects a non-negative integer, got `{value}`"))?;
            let site = options.exact_site.get_or_insert_with(empty_exact_site);
            site.end_byte = Some(parsed);
        }
        _ => return Ok(false),
    }
    Ok(true)
}

fn empty_exact_site() -> ExactReferenceSite {
    ExactReferenceSite {
        path: String::new(),
        start_byte: usize::MAX,
        end_byte: None,
    }
}

fn finish_exact_site(options: &mut EngineOptions) -> Result<(), String> {
    let Some(site) = &options.exact_site else {
        return Ok(());
    };
    if site.path.is_empty() || site.start_byte == usize::MAX {
        return Err("exact-site reruns require both --path and --start-byte".to_string());
    }
    if site.end_byte.is_some_and(|end| end <= site.start_byte) {
        return Err("--end-byte must be greater than --start-byte".to_string());
    }
    Ok(())
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

fn dedupe_preserving_order(values: &mut Vec<String>) {
    let mut seen = HashSet::new();
    values.retain(|value| seen.insert(value.clone()));
}

fn run_repo_command(args: RunRepoArgs) -> Result<bool, String> {
    let root = validate_clone(&args.root)?;
    let repo_slug = root
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("repository")
        .to_string();
    let metadata = repository_metadata(&root)?;
    let bifrost_metadata = repository_metadata(Path::new(env!("CARGO_MANIFEST_DIR")))?;
    let config = args.options.config(&args.language);
    let fingerprint = run_fingerprint(&config)?;
    let completed = if args.force {
        HashSet::new()
    } else {
        completed_runs(&args.output)?
    };
    let key = CompletionKey::new(
        &args.language,
        &repo_slug,
        &metadata.head,
        &bifrost_metadata.head,
        &fingerprint,
    );
    if completed.contains(&key) {
        eprintln!("skip {} {}: already completed", args.language, repo_slug);
        return Ok(false);
    }

    eprintln!("run {} {} ({})", args.language, repo_slug, root.display());
    let started = Instant::now();
    let result = run_engine(&root, &config, args.options.cache_mode);
    let record = repository_record(
        &args.language,
        &repo_slug,
        None,
        &metadata,
        &bifrost_metadata,
        fingerprint,
        started.elapsed().as_secs_f64(),
        result,
    );
    append_record(&args.output, &record)?;
    print_record_summary(&record);
    match record.result {
        RepositoryResult::Completed { ref report } => {
            Ok(args.strict && report.has_actionable_findings())
        }
        RepositoryResult::EngineError { ref message } => Err(format!(
            "reference differential failed for {} {}: {message}",
            args.language, repo_slug
        )),
    }
}

fn run_corpus_command(args: RunCorpusArgs) -> Result<bool, String> {
    let selected = select_corpus_repositories(&args)?;
    if args.dry_run {
        for repo in &selected {
            println!(
                "{}\t{}\t{}\t{}",
                repo.language,
                repo.slug,
                repo.code_loc,
                repo.root.display()
            );
        }
        return Ok(false);
    }

    let output = args.output.as_ref().expect("validated output");
    let bifrost_metadata = repository_metadata(Path::new(env!("CARGO_MANIFEST_DIR")))?;
    let completed = if args.force {
        HashSet::new()
    } else {
        completed_runs(output)?
    };
    let mut strict_failure = false;
    for (position, selected_repo) in selected.iter().enumerate() {
        let metadata = match repository_metadata(&selected_repo.root) {
            Ok(metadata) => metadata,
            Err(err) => {
                eprintln!(
                    "[{}/{}] {} {} metadata error: {err}",
                    position + 1,
                    selected.len(),
                    selected_repo.language,
                    selected_repo.slug
                );
                let record = repository_record(
                    &selected_repo.language,
                    &selected_repo.slug,
                    Some(selected_repo.code_loc),
                    &RepositoryMetadata {
                        head: "unknown".to_string(),
                        dirty: false,
                    },
                    &bifrost_metadata,
                    run_fingerprint(&args.options.config(&selected_repo.language))?,
                    0.0,
                    Err(format!("failed to read repository metadata: {err}")),
                );
                append_record(output, &record)?;
                continue;
            }
        };
        let config = args.options.config(&selected_repo.language);
        let fingerprint = run_fingerprint(&config)?;
        let key = CompletionKey::new(
            &selected_repo.language,
            &selected_repo.slug,
            &metadata.head,
            &bifrost_metadata.head,
            &fingerprint,
        );
        if completed.contains(&key) {
            eprintln!(
                "[{}/{}] skip {} {}: already completed",
                position + 1,
                selected.len(),
                selected_repo.language,
                selected_repo.slug
            );
            continue;
        }

        eprintln!(
            "[{}/{}] run {} {} ({} LOC)",
            position + 1,
            selected.len(),
            selected_repo.language,
            selected_repo.slug,
            selected_repo.code_loc
        );
        let started = Instant::now();
        let result = run_engine(&selected_repo.root, &config, args.options.cache_mode);
        let record = repository_record(
            &selected_repo.language,
            &selected_repo.slug,
            Some(selected_repo.code_loc),
            &metadata,
            &bifrost_metadata,
            fingerprint,
            started.elapsed().as_secs_f64(),
            result,
        );
        append_record(output, &record)?;
        print_record_summary(&record);
        if args.strict
            && matches!(
                &record.result,
                RepositoryResult::Completed { report } if report.has_actionable_findings()
            )
        {
            strict_failure = true;
        }
    }
    Ok(strict_failure)
}

fn run_engine(
    root: &Path,
    config: &ReferenceDifferentialConfig,
    cache_mode: CacheMode,
) -> Result<ReferenceDifferentialReport, String> {
    let project: Arc<dyn Project> = Arc::new(
        FilesystemProject::new(root.to_path_buf())
            .map_err(|err| format!("failed to open project: {err}"))?,
    );
    let workspace = match cache_mode {
        CacheMode::Persisted => {
            WorkspaceAnalyzer::build_persisted(project, AnalyzerConfig::default())
                .map_err(|error| format!("failed to build persisted analyzer: {error}"))?
        }
        CacheMode::Ephemeral => WorkspaceAnalyzer::build(project, AnalyzerConfig::default()),
    };
    run_reference_differential(workspace.analyzer(), config)
}

#[derive(Debug, Clone)]
struct SelectedRepository {
    language: String,
    slug: String,
    code_loc: u64,
    root: PathBuf,
}

#[derive(Debug, Deserialize)]
struct RepoSizeRow {
    repo: String,
    code_loc: String,
}

fn select_corpus_repositories(args: &RunCorpusArgs) -> Result<Vec<SelectedRepository>, String> {
    let sizes = read_repo_sizes(&args.commits_root.join("repos.csv"))?;
    let clones_root = args.clones_root.canonicalize().map_err(|err| {
        format!(
            "failed to canonicalize clones root `{}`: {err}",
            args.clones_root.display()
        )
    })?;
    let mut selected = Vec::new();
    let mut matched_repo_filters = HashSet::new();

    for language in &args.languages {
        let language_dir = args.commits_root.join(language);
        let members = language_members(&language_dir)?;
        let mut ranked = Vec::new();
        let mut missing_size_count = 0;
        for slug in members {
            if !args.repos.is_empty() && !args.repos.contains(&slug) {
                continue;
            }
            matched_repo_filters.insert(slug.clone());
            let Some(&code_loc) = sizes.get(&slug) else {
                missing_size_count += 1;
                continue;
            };
            ranked.push((code_loc, slug));
        }
        ranked.sort_by(|left, right| right.0.cmp(&left.0).then_with(|| left.1.cmp(&right.1)));
        let take = if args.repos.is_empty() {
            args.repos_per_language
        } else {
            ranked.len()
        };
        if missing_size_count != 0 {
            eprintln!(
                "skip {missing_size_count} {language} metadata member(s) with missing or invalid code_loc"
            );
        }
        let mut selected_for_language = 0;
        for (code_loc, slug) in ranked {
            if selected_for_language == take {
                break;
            }
            let root = clones_root.join(&slug);
            match validate_clone(&root) {
                Ok(root) => {
                    selected.push(SelectedRepository {
                        language: language.clone(),
                        slug,
                        code_loc,
                        root,
                    });
                    selected_for_language += 1;
                }
                Err(err) => eprintln!("skip {language} {slug}: {err}"),
            }
        }
    }

    if !args.repos.is_empty() {
        let mut missing = args
            .repos
            .difference(&matched_repo_filters)
            .cloned()
            .collect::<Vec<_>>();
        missing.sort();
        if !missing.is_empty() {
            return Err(format!(
                "requested repo filter(s) not found in selected language metadata: {}",
                missing.join(", ")
            ));
        }
    }
    for language in &args.languages {
        if !selected.iter().any(|repo| &repo.language == language) {
            return Err(format!(
                "no valid repositories selected for corpus language `{language}`"
            ));
        }
    }
    Ok(selected)
}

fn read_repo_sizes(path: &Path) -> Result<HashMap<String, u64>, String> {
    let mut reader = csv::Reader::from_path(path)
        .map_err(|err| format!("failed to read size metadata `{}`: {err}", path.display()))?;
    let mut sizes = HashMap::new();
    for row in reader.deserialize::<RepoSizeRow>() {
        let row = row.map_err(|err| format!("failed to parse `{}`: {err}", path.display()))?;
        let Ok(code_loc) = row.code_loc.trim().parse::<u64>() else {
            continue;
        };
        sizes.insert(row.repo, code_loc);
    }
    Ok(sizes)
}

fn language_members(path: &Path) -> Result<Vec<String>, String> {
    let entries = fs::read_dir(path).map_err(|err| {
        format!(
            "failed to read language metadata `{}`: {err}",
            path.display()
        )
    })?;
    let mut members = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|err| {
            format!(
                "failed to read language metadata `{}`: {err}",
                path.display()
            )
        })?;
        if !entry
            .file_type()
            .map_err(|err| format!("failed to inspect `{}`: {err}", entry.path().display()))?
            .is_file()
        {
            continue;
        }
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !name.ends_with(".jsonl") || name.ends_with(".testsome.jsonl") {
            continue;
        }
        members.push(name.trim_end_matches(".jsonl").to_string());
    }
    members.sort();
    members.dedup();
    Ok(members)
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
    #[serde(skip_serializing_if = "Option::is_none")]
    code_loc: Option<u64>,
    run_fingerprint: String,
    elapsed_seconds: f64,
    #[serde(flatten)]
    result: RepositoryResult,
}

#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum RepositoryResult {
    Completed {
        report: Box<ReferenceDifferentialReport>,
    },
    EngineError {
        message: String,
    },
}

#[allow(clippy::too_many_arguments)]
fn repository_record(
    language: &str,
    repo_slug: &str,
    code_loc: Option<u64>,
    metadata: &RepositoryMetadata,
    bifrost_metadata: &RepositoryMetadata,
    fingerprint: String,
    elapsed_seconds: f64,
    result: Result<ReferenceDifferentialReport, String>,
) -> RepositoryRecord {
    RepositoryRecord {
        schema_version: SCHEMA_VERSION,
        record_type: "repository",
        bifrost_version: env!("CARGO_PKG_VERSION"),
        bifrost_head: bifrost_metadata.head.clone(),
        bifrost_dirty: bifrost_metadata.dirty,
        corpus_language: language.to_string(),
        analyzer_language: analyzer_language(language),
        repo_slug: repo_slug.to_string(),
        repo_head: metadata.head.clone(),
        repo_dirty: metadata.dirty,
        code_loc,
        run_fingerprint: fingerprint,
        elapsed_seconds,
        result: match result {
            Ok(report) => RepositoryResult::Completed {
                report: Box::new(report),
            },
            Err(message) => RepositoryResult::EngineError { message },
        },
    }
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

fn run_fingerprint(config: &ReferenceDifferentialConfig) -> Result<String, String> {
    let bytes = serde_json::to_vec(config)
        .map_err(|err| format!("failed to serialize differential config: {err}"))?;
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

fn print_record_summary(record: &RepositoryRecord) {
    match &record.result {
        RepositoryResult::Completed { report } => eprintln!(
            "done {} {}: actionable={} elapsed={:.1}s",
            record.corpus_language,
            record.repo_slug,
            report.actionable_count(),
            record.elapsed_seconds
        ),
        RepositoryResult::EngineError { message } => eprintln!(
            "failed {} {}: {} elapsed={:.1}s",
            record.corpus_language, record.repo_slug, message, record.elapsed_seconds
        ),
    }
}

fn print_help() {
    println!("Usage: bifrost_reference_differential <subcommand> [options]");
    println!("Subcommands:");
    println!("  run-repo    Audit one repository checkout");
    println!("  run-corpus  Select and audit repositories from corpus metadata");
}

fn print_run_repo_help() {
    println!(
        "Usage: bifrost_reference_differential run-repo --root PATH --language LANG --output PATH [options]"
    );
    print_common_options();
}

fn print_run_corpus_help() {
    println!(
        "Usage: bifrost_reference_differential run-corpus --clones-root PATH --commits-root PATH [--output PATH] [options]"
    );
    println!("  --repos-per-language N   Largest valid clones per language (default: 1)");
    println!("  --language LANG          Exact corpus language filter; repeatable");
    println!("  --repo SLUG              Exact repository filter; repeatable");
    println!("  --dry-run                Print deterministic selection without auditing");
    print_common_options();
}

fn print_common_options() {
    println!("  --max-files N            Stable-hash sampled files (default: {DEFAULT_MAX_FILES})");
    println!("  --max-sites N            Stable-hash sampled sites (default: {DEFAULT_MAX_SITES})");
    println!(
        "  --max-candidates-per-file N   Structured candidates per file (default: {DEFAULT_MAX_CANDIDATES_PER_FILE})"
    );
    println!(
        "  --max-source-bytes N     Indexed source bytes per file (default: {DEFAULT_MAX_SOURCE_BYTES})"
    );
    println!(
        "  --max-targets N          Distinct inverse target groups (default: {DEFAULT_MAX_TARGETS})"
    );
    println!(
        "  --max-usage-files N      Files per inverse target query (default: {DEFAULT_MAX_USAGE_FILES})"
    );
    println!(
        "  --max-usages N           Usage hits per inverse query (default: {DEFAULT_MAX_USAGES})"
    );
    println!("  --seed N                 Deterministic sampling seed (default: 0)");
    println!("  --include-tests          Include references in test files");
    println!(
        "  --cache-mode MODE        persisted for warm/resumable campaigns (default); ephemeral for one-off smoke runs"
    );
    println!("  --path PATH --start-byte N [--end-byte N]   Re-run one exact site");
    println!("  --strict                 Exit 2 when actionable findings are present");
    println!("  --force                  Ignore completed records already in output");
}
