use git2::{Repository, Signature};
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::process::Command;
use tempfile::TempDir;

#[test]
fn help_describes_repo_and_corpus_modes() {
    let output = Command::new(env!("CARGO_BIN_EXE_bifrost_reference_differential"))
        .arg("--help")
        .output()
        .expect("run help");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("run-repo"), "{stdout}");
    assert!(stdout.contains("run-corpus"), "{stdout}");

    let repo_help = Command::new(env!("CARGO_BIN_EXE_bifrost_reference_differential"))
        .args(["run-repo", "--help"])
        .output()
        .expect("run repository help");
    assert!(repo_help.status.success());
    let repo_stdout = String::from_utf8(repo_help.stdout).expect("utf8 stdout");
    assert!(repo_stdout.contains("--cache-mode"), "{repo_stdout}");
    assert!(repo_stdout.contains("ephemeral"), "{repo_stdout}");

    let corpus_help = Command::new(env!("CARGO_BIN_EXE_bifrost_reference_differential"))
        .args(["run-corpus", "--help"])
        .output()
        .expect("run corpus help");
    assert!(corpus_help.status.success());
    let corpus_stdout = String::from_utf8(corpus_help.stdout).expect("utf8 stdout");
    assert!(corpus_stdout.contains("--repo-jobs"), "{corpus_stdout}");
    assert!(
        corpus_stdout.contains("workers per repository"),
        "{corpus_stdout}"
    );
}

#[test]
fn corpus_dry_run_selects_largest_valid_clone_by_recorded_loc() {
    let fixture = CorpusFixture::new();
    fixture.add_repo("java", "small__repo", 100, true);
    fixture.add_repo("java", "large__repo", 300, true);
    fixture.add_repo("java", "invalid__repo", 500, false);

    let output = fixture.run(&[
        "run-corpus",
        "--language",
        "java",
        "--repos-per-language",
        "1",
        "--dry-run",
    ]);
    assert!(
        output.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("java\tlarge__repo\t300"), "{stdout}");
    assert!(!stdout.contains("small__repo"), "{stdout}");
    assert!(!stdout.contains("invalid__repo"), "{stdout}");
}

#[test]
fn corpus_exact_repo_and_language_filters_override_size_ranking() {
    let fixture = CorpusFixture::new();
    fixture.add_repo("java", "small__repo", 100, true);
    fixture.add_repo("java", "large__repo", 300, true);
    fixture.add_repo("go", "small__repo", 100, true);

    let output = fixture.run(&[
        "run-corpus",
        "--language",
        "java",
        "--repo",
        "small__repo",
        "--dry-run",
    ]);
    assert!(
        output.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("java\tsmall__repo\t100"), "{stdout}");
    assert!(!stdout.contains("large__repo"), "{stdout}");
    assert!(!stdout.contains("go\t"), "{stdout}");
}

#[test]
fn corpus_runs_distinct_repositories_concurrently_and_resumes_safely() {
    let fixture = CorpusFixture::new();
    for (slug, code_loc) in [
        ("large__rust", 300),
        ("medium__rust", 200),
        ("small__rust", 100),
    ] {
        fixture.add_rust_repo(slug, code_loc, 32);
    }
    let report = fixture.path("concurrent.jsonl");
    let report_arg = report.to_string_lossy().into_owned();
    let args = [
        "run-corpus",
        "--language",
        "rust",
        "--repos-per-language",
        "3",
        "--repo-jobs",
        "2",
        "--output",
        report_arg.as_str(),
        "--max-files",
        "32",
        "--max-sites",
        "64",
        "--max-targets",
        "64",
        "--jobs",
        "1",
        "--cache-mode",
        "ephemeral",
    ];

    let output = fixture.run(&args);
    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8(output.stderr).expect("utf8 stderr");
    assert!(
        stderr.contains("run-corpus repositories=3 clone_groups=3 repo_jobs=2 jobs_per_repo=1"),
        "{stderr}"
    );
    assert_eq!(maximum_active_repositories(&stderr), 2, "{stderr}");
    for slug in ["large__rust", "medium__rust", "small__rust"] {
        assert!(
            stderr.contains(&format!(
                "progress phase=workspace status=started repo=rust/{slug} jobs=1"
            )),
            "{stderr}"
        );
    }

    let report_text = fs::read_to_string(&report).expect("read concurrent report");
    let mut slugs = Vec::new();
    for line in report_text.lines() {
        let record: serde_json::Value = serde_json::from_str(line).expect("parse record");
        assert_eq!(record["status"], "completed", "{record}");
        assert_eq!(record["report"]["config"]["parallelism"], 1, "{record}");
        slugs.push(record["repo_slug"].as_str().expect("repo slug").to_string());
    }
    slugs.sort();
    assert_eq!(slugs, ["large__rust", "medium__rust", "small__rust"]);

    let resumed = fixture.run(&args);
    assert!(
        resumed.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&resumed.stderr)
    );
    let resumed_stderr = String::from_utf8(resumed.stderr).expect("utf8 stderr");
    assert_eq!(resumed_stderr.matches("already completed").count(), 3);
    assert_eq!(
        fs::read_to_string(&report)
            .expect("read resumed report")
            .lines()
            .count(),
        3
    );
}

#[test]
fn corpus_serializes_language_jobs_that_share_one_clone() {
    let fixture = CorpusFixture::new();
    fixture.add_rust_and_java_repo("shared__repo", 100);
    let report = fixture.path("shared.jsonl");
    let report_arg = report.to_string_lossy().into_owned();
    let output = fixture.run(&[
        "run-corpus",
        "--language",
        "rust",
        "--language",
        "java",
        "--repo",
        "shared__repo",
        "--repo-jobs",
        "2",
        "--output",
        report_arg.as_str(),
        "--max-files",
        "10",
        "--max-sites",
        "10",
        "--max-targets",
        "10",
        "--jobs",
        "1",
        "--cache-mode",
        "ephemeral",
    ]);
    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8(output.stderr).expect("utf8 stderr");
    assert!(
        stderr.contains("run-corpus repositories=2 clone_groups=1 repo_jobs=1 jobs_per_repo=1"),
        "{stderr}"
    );
    assert_eq!(maximum_active_repositories(&stderr), 1, "{stderr}");
    assert_eq!(
        fs::read_to_string(report)
            .expect("read shared report")
            .lines()
            .count(),
        2
    );
}

fn maximum_active_repositories(stderr: &str) -> usize {
    let mut active = HashSet::<(String, String)>::new();
    let mut maximum = 0;
    for line in stderr.lines() {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        let event = fields.get(1).copied();
        if !fields.first().is_some_and(|field| field.starts_with('['))
            || !matches!(event, Some("run" | "complete"))
        {
            continue;
        }
        let language = fields.get(2).expect("event language").to_string();
        let slug = fields.get(3).expect("event slug").to_string();
        if event == Some("run") {
            assert!(
                active.insert((language, slug)),
                "duplicate run event: {line}"
            );
            maximum = maximum.max(active.len());
        } else {
            assert!(
                active.remove(&(language, slug)),
                "completion without active run: {line}"
            );
        }
    }
    assert!(active.is_empty(), "unfinished repositories: {active:?}");
    maximum
}

#[test]
fn run_repo_writes_completed_jsonl_report_for_tiny_project() {
    let fixture = TinyRepoFixture::new("tiny__rust");
    let output = fixture.run(&[]);
    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report_text = fs::read_to_string(&fixture.output).expect("read JSONL report");
    let lines = report_text.lines().collect::<Vec<_>>();
    assert_eq!(lines.len(), 1, "{report_text}");
    let record: serde_json::Value = serde_json::from_str(lines[0]).expect("parse record");
    assert_eq!(record["record_type"], "repository", "{record}");
    assert_eq!(record["status"], "completed", "{record}");
    assert_eq!(record["corpus_language"], "rust", "{record}");
    assert_eq!(record["repo_slug"], "tiny__rust", "{record}");
    assert!(record["bifrost_version"].is_string(), "{record}");
    assert!(record["bifrost_head"].is_string(), "{record}");
    assert!(record["report"]["summary"].is_object(), "{record}");
    assert_eq!(record["report"]["config"]["parallelism"], 2, "{record}");
    assert!(fixture.root.join(".brokk/bifrost_cache.db").is_file());

    let stderr = String::from_utf8(output.stderr).expect("utf8 stderr");
    assert!(
        stderr.contains("progress phase=workspace status=started"),
        "{stderr}"
    );
    assert!(stderr.contains("progress phase=inventory"), "{stderr}");
    assert!(stderr.contains("progress phase=sampling"), "{stderr}");
    assert!(
        stderr.contains("progress phase=forward completed=1 total=2"),
        "{stderr}"
    );
    assert!(
        stderr.contains("progress phase=forward completed=2 total=2"),
        "{stderr}"
    );
    assert!(stderr.contains("progress phase=forward"), "{stderr}");
    assert!(
        stderr.contains("progress phase=inverse completed=1 total=2"),
        "{stderr}"
    );
    assert!(
        stderr.contains("progress phase=inverse completed=2 total=2"),
        "{stderr}"
    );

    let resumed = fixture.run(&[]);
    assert!(
        resumed.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&resumed.stderr)
    );
    assert!(
        String::from_utf8_lossy(&resumed.stderr).contains("already completed"),
        "stderr:\n{}",
        String::from_utf8_lossy(&resumed.stderr)
    );
    assert_eq!(
        fs::read_to_string(&fixture.output)
            .expect("read resumed report")
            .lines()
            .count(),
        1
    );
}

#[test]
fn run_repo_ephemeral_cache_does_not_create_persisted_database() {
    let fixture = TinyRepoFixture::new("tiny__rust_ephemeral");
    let output = fixture.run(&["--cache-mode", "ephemeral"]);
    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(fixture.output.is_file());
    assert!(!fixture.root.join(".brokk/bifrost_cache.db").exists());
}

#[test]
fn invalid_cache_mode_is_rejected() {
    let output = Command::new(env!("CARGO_BIN_EXE_bifrost_reference_differential"))
        .args([
            "run-repo",
            "--root",
            ".",
            "--language",
            "rust",
            "--output",
            "/tmp/unused-reference-differential.jsonl",
            "--cache-mode",
            "temporary",
        ])
        .output()
        .expect("run invalid cache mode");
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("--cache-mode expects `persisted` or `ephemeral`")
    );
}

struct TinyRepoFixture {
    _temp: TempDir,
    root: std::path::PathBuf,
    output: std::path::PathBuf,
}

impl TinyRepoFixture {
    fn new(slug: &str) -> Self {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().join(slug);
        fs::create_dir_all(&root).expect("repo root");
        fs::write(
            root.join("lib.rs"),
            "mod helpers;\npub fn second() {}\npub fn caller() { second(); }\n",
        )
        .expect("rust source");
        fs::write(
            root.join("helpers.rs"),
            "pub fn first() {}\npub fn caller() { first(); }\n",
        )
        .expect("rust helper source");
        init_repo(&root);
        let output = temp.path().join("report.jsonl");
        Self {
            _temp: temp,
            root,
            output,
        }
    }

    fn run(&self, extra_args: &[&str]) -> std::process::Output {
        Command::new(env!("CARGO_BIN_EXE_bifrost_reference_differential"))
            .arg("run-repo")
            .arg("--root")
            .arg(&self.root)
            .arg("--language")
            .arg("rust")
            .arg("--output")
            .arg(&self.output)
            .args([
                "--max-files",
                "10",
                "--max-sites",
                "10",
                "--max-targets",
                "10",
                "--jobs",
                "2",
            ])
            .args(extra_args)
            .output()
            .expect("run repository differential")
    }
}

struct CorpusFixture {
    _temp: TempDir,
    clones: std::path::PathBuf,
    commits: std::path::PathBuf,
}

impl CorpusFixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().expect("temp dir");
        let clones = temp.path().join("clones");
        let commits = temp.path().join("commits");
        fs::create_dir_all(&clones).expect("clones dir");
        fs::create_dir_all(&commits).expect("commits dir");
        fs::write(
            commits.join("repos.csv"),
            "repo,code_loc,n_files,blank,comment,error,build_time\n",
        )
        .expect("repos csv");
        Self {
            _temp: temp,
            clones,
            commits,
        }
    }

    fn add_repo(&self, language: &str, slug: &str, code_loc: u64, valid_clone: bool) {
        self.add_repo_metadata(language, slug, code_loc);
        let clone = self.clones.join(slug);
        fs::create_dir_all(&clone).expect("clone dir");
        if valid_clone && !clone.join(".git").exists() {
            init_repo(&clone);
        }
    }

    fn add_rust_repo(&self, slug: &str, code_loc: u64, files: usize) {
        self.add_repo_metadata("rust", slug, code_loc);
        let clone = self.clones.join(slug);
        fs::create_dir_all(&clone).expect("clone dir");
        for index in 0..files {
            fs::write(
                clone.join(format!("module_{index}.rs")),
                format!(
                    "pub fn target_{index}() {{}}\npub fn caller_{index}() {{ target_{index}(); }}\n"
                ),
            )
            .expect("rust source");
        }
        init_repo(&clone);
    }

    fn add_rust_and_java_repo(&self, slug: &str, code_loc: u64) {
        self.add_repo_metadata("rust", slug, code_loc);
        self.add_repo_metadata("java", slug, code_loc);
        let clone = self.clones.join(slug);
        fs::create_dir_all(&clone).expect("clone dir");
        fs::write(
            clone.join("lib.rs"),
            "pub fn target() {}\npub fn caller() { target(); }\n",
        )
        .expect("rust source");
        fs::write(
            clone.join("Main.java"),
            "class Main { static void target() {} void caller() { target(); } }\n",
        )
        .expect("java source");
        init_repo(&clone);
    }

    fn add_repo_metadata(&self, language: &str, slug: &str, code_loc: u64) {
        let language_dir = self.commits.join(language);
        fs::create_dir_all(&language_dir).expect("language dir");
        fs::write(language_dir.join(format!("{slug}.jsonl")), "{}\n").expect("metadata");
        let mut csv = fs::OpenOptions::new()
            .append(true)
            .open(self.commits.join("repos.csv"))
            .expect("open repos csv");
        use std::io::Write;
        writeln!(csv, "{slug},{code_loc},1,0,0,,1").expect("append repos csv");
    }

    fn path(&self, name: &str) -> std::path::PathBuf {
        self._temp.path().join(name)
    }

    fn run(&self, args: &[&str]) -> std::process::Output {
        Command::new(env!("CARGO_BIN_EXE_bifrost_reference_differential"))
            .args(args)
            .arg("--clones-root")
            .arg(&self.clones)
            .arg("--commits-root")
            .arg(&self.commits)
            .output()
            .expect("run differential CLI")
    }
}

fn init_repo(root: &Path) {
    let repo = Repository::init(root).expect("init repo");
    fs::write(root.join("README.md"), "fixture\n").expect("fixture file");
    let mut index = repo.index().expect("index");
    index
        .add_all(["*"], git2::IndexAddOption::DEFAULT, None)
        .expect("add files");
    index.write().expect("write index");
    let tree_id = index.write_tree().expect("tree id");
    let tree = repo.find_tree(tree_id).expect("tree");
    let signature = Signature::now("Bifrost Test", "test@example.com").expect("signature");
    repo.commit(Some("HEAD"), &signature, &signature, "fixture", &tree, &[])
        .expect("commit");
}
