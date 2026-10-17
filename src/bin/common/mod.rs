use brokk_bifrost::repo_status::{DirtyState, inspect_dirty_state};
use git2::Repository;
use serde::Serialize;
use serde_json::Value;
use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::Path;
use std::process::ExitCode;
use std::str::FromStr;

pub(super) const CORPUS_LANGUAGES: [&str; 13] = [
    "c", "cpp", "csharp", "go", "java", "js", "kotlin", "php", "py", "ruby", "rust", "scala", "ts",
];

pub(super) fn is_generated_analyzer_state(path: &str) -> bool {
    let first = path.split('/').next().unwrap_or(path);
    first == ".bifrost" || first == ".brokk"
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct CompletionKey {
    language: String,
    repo_slug: String,
    repo_head: String,
    bifrost_head: String,
    fingerprint: String,
}

#[derive(Debug)]
pub(super) struct RepositoryMetadata {
    pub(super) head: String,
    pub(super) dirty: DirtyState,
}

pub(super) fn repository_metadata(root: &Path) -> Result<RepositoryMetadata, String> {
    let repo = Repository::open(root)
        .map_err(|error| format!("failed to open repository `{}`: {error}", root.display()))?;
    let head = repo
        .head()
        .and_then(|head| head.peel_to_commit())
        .map_err(|error| format!("failed to resolve HEAD for `{}`: {error}", root.display()))?
        .id()
        .to_string();
    let dirty = inspect_dirty_state(root, |path| !is_generated_analyzer_state(path));
    Ok(RepositoryMetadata { head, dirty })
}

pub(super) fn print_record_summary(
    corpus_language: &str,
    repo_slug: &str,
    elapsed_seconds: f64,
    outcome: Result<(&str, usize), &str>,
) {
    match outcome {
        Ok((metric, count)) => eprintln!(
            "done {} {}: {metric}={count} elapsed={elapsed_seconds:.1}s",
            corpus_language, repo_slug
        ),
        Err(message) => eprintln!(
            "failed {} {}: {} elapsed={:.1}s",
            corpus_language, repo_slug, message, elapsed_seconds
        ),
    }
}

impl CompletionKey {
    pub(super) fn new(
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

pub(super) fn finish_boolean_result(result: Result<bool, String>) -> ExitCode {
    match result {
        Ok(true) => ExitCode::from(2),
        Ok(false) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

pub(super) fn finish_unit_result(result: Result<(), String>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

pub(super) fn take_value(
    args: &[String],
    index: &mut usize,
    option: &str,
) -> Result<String, String> {
    *index += 1;
    args.get(*index)
        .cloned()
        .ok_or_else(|| format!("{option} requires a value"))
}

pub(super) fn take_integer<T: FromStr>(
    args: &[String],
    index: &mut usize,
    option: &str,
    expectation: &str,
) -> Result<T, String> {
    let value = take_value(args, index, option)?;
    value
        .parse::<T>()
        .map_err(|_| format!("{option} expects a {expectation}, got `{value}`"))
}

pub(super) fn take_positive_integer<T>(
    args: &[String],
    index: &mut usize,
    option: &str,
    expectation: &str,
) -> Result<T, String>
where
    T: FromStr + Default + PartialEq,
{
    let parsed = take_integer(args, index, option, expectation)?;
    if parsed == T::default() {
        return Err(format!("{option} must be greater than zero"));
    }
    Ok(parsed)
}

pub(super) fn take_positive_usize(
    args: &[String],
    index: &mut usize,
    option: &str,
) -> Result<usize, String> {
    take_positive_integer(args, index, option, "positive integer")
}

pub(super) fn normalize_corpus_language(value: &str) -> Option<&'static str> {
    match value.trim().to_ascii_lowercase().as_str() {
        "c" => Some("c"),
        "cpp" | "c++" => Some("cpp"),
        "csharp" | "c#" | "cs" => Some("csharp"),
        "go" => Some("go"),
        "java" => Some("java"),
        "js" | "javascript" => Some("js"),
        "kotlin" | "kt" => Some("kotlin"),
        "php" => Some("php"),
        "py" | "python" => Some("py"),
        "ruby" | "rb" => Some("ruby"),
        "rust" => Some("rust"),
        "scala" => Some("scala"),
        "ts" | "typescript" => Some("ts"),
        _ => None,
    }
}

pub(super) fn analyzer_language(corpus_language: &str) -> &'static str {
    match corpus_language {
        "c" | "cpp" => "cpp",
        "csharp" => "csharp",
        "js" => "javascript",
        "py" => "python",
        "ts" => "typescript",
        "go" => "go",
        "java" => "java",
        "kotlin" => "kotlin",
        "php" => "php",
        "ruby" => "ruby",
        "rust" => "rust",
        "scala" => "scala",
        _ => "unknown",
    }
}

pub(super) fn dedupe_preserving_order(values: &mut Vec<String>) {
    let mut seen = HashSet::new();
    values.retain(|value| seen.insert(value.clone()));
}

pub(super) fn catch_engine_panic<T>(run: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
    catch_unwind(AssertUnwindSafe(run)).unwrap_or_else(|payload| {
        let message = if let Some(message) = payload.downcast_ref::<&str>() {
            (*message).to_string()
        } else if let Some(message) = payload.downcast_ref::<String>() {
            message.clone()
        } else {
            "unknown panic payload".to_string()
        };
        Err(format!("analyzer panicked: {message}"))
    })
}

pub(super) fn run_worker_pool<J, R>(
    jobs: Vec<J>,
    worker_count: usize,
    run_job: impl Fn(J, &std::sync::mpsc::Sender<R>) + Sync,
    mut receive_record: impl FnMut(R) -> Result<(), String>,
) -> Result<(), String>
where
    J: Send,
    R: Send,
{
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex, mpsc};
    use std::thread;

    assert!(worker_count > 0 || jobs.is_empty());
    let queue = Arc::new(Mutex::new(VecDeque::from(jobs)));
    let (sender, receiver) = mpsc::channel();
    thread::scope(|scope| -> Result<(), String> {
        for _ in 0..worker_count {
            let queue = Arc::clone(&queue);
            let sender = sender.clone();
            let run_job = &run_job;
            scope.spawn(move || {
                loop {
                    let Some(job) = queue
                        .lock()
                        .expect("worker queue lock poisoned")
                        .pop_front()
                    else {
                        break;
                    };
                    run_job(job, &sender);
                }
            });
        }
        drop(sender);
        for record in receiver {
            receive_record(record)?;
        }
        Ok(())
    })
}

#[cfg(test)]
pub(super) fn deep_git_repository_with_author(
    author_name: &str,
    author_email: &str,
) -> (tempfile::TempDir, std::path::PathBuf) {
    let temp = tempfile::tempdir().expect("tempdir");
    let mut deep = temp.path().to_path_buf();
    for i in 0..110u32 {
        let name = (b'a' + (i % 26) as u8) as char;
        deep.push(name.to_string());
    }
    std::fs::create_dir_all(&deep).expect("deep directory chain");
    std::fs::write(deep.join("tracked.txt"), "leaf\n").expect("tracked leaf file");

    let git = |args: &[&str]| {
        let output = std::process::Command::new("git")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .arg("-C")
            .arg(temp.path())
            .arg("-c")
            .arg("core.longpaths=true")
            .args(args)
            .output()
            .expect("spawn git");
        assert!(
            output.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    };
    git(&["init", "--quiet"]);
    git(&["add", "--all"]);
    git(&[
        "-c",
        &format!("user.name={author_name}"),
        "-c",
        &format!("user.email={author_email}"),
        "commit",
        "--quiet",
        "-m",
        "fixture",
    ]);
    (temp, deep)
}

#[cfg(test)]
pub(super) fn assert_deep_repository_metadata(author_name: &str, author_email: &str) {
    let (temp, deep) = deep_git_repository_with_author(author_name, author_email);

    let metadata = repository_metadata(temp.path()).expect("status inspection must succeed");
    assert_eq!(metadata.dirty, DirtyState::Known(false));
    assert_eq!(metadata.head.len(), 40);

    fs::write(deep.join("untracked.txt"), "new\n").expect("deep untracked file");
    let metadata = repository_metadata(temp.path()).expect("status inspection must succeed");
    assert_eq!(metadata.dirty, DirtyState::Known(true));
}

pub(super) fn completed_runs(path: &Path) -> Result<HashSet<CompletionKey>, String> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(HashSet::new()),
        Err(error) => {
            return Err(format!(
                "failed to read output `{}`: {error}",
                path.display()
            ));
        }
    };
    let mut completed = HashSet::new();
    for (line_index, line) in BufReader::new(file).lines().enumerate() {
        let line = line.map_err(|error| {
            format!(
                "failed to read output `{}` line {}: {error}",
                path.display(),
                line_index + 1
            )
        })?;
        if line.trim().is_empty() {
            continue;
        }
        let value: Value = match serde_json::from_str(&line) {
            Ok(value) => value,
            Err(error) => {
                eprintln!(
                    "ignore invalid JSONL record {}:{}: {error}",
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

pub(super) fn append_record<T: Serialize>(path: &Path, record: &T) -> Result<(), String> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent).map_err(|error| {
            format!(
                "failed to create output directory `{}`: {error}",
                parent.display()
            )
        })?;
    }
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|error| format!("failed to open output `{}`: {error}", path.display()))?;
    let mut writer = BufWriter::new(file);
    serde_json::to_writer(&mut writer, record)
        .map_err(|error| format!("failed to serialize output record: {error}"))?;
    writer
        .write_all(b"\n")
        .and_then(|_| writer.flush())
        .map_err(|error| format!("failed to append output `{}`: {error}", path.display()))
}
