use git2::{Repository, Signature};
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
        let language_dir = self.commits.join(language);
        fs::create_dir_all(&language_dir).expect("language dir");
        fs::write(language_dir.join(format!("{slug}.jsonl")), "{}\n").expect("metadata");
        let mut csv = fs::OpenOptions::new()
            .append(true)
            .open(self.commits.join("repos.csv"))
            .expect("open repos csv");
        use std::io::Write;
        writeln!(csv, "{slug},{code_loc},1,0,0,,1").expect("append repos csv");

        let clone = self.clones.join(slug);
        fs::create_dir_all(&clone).expect("clone dir");
        if valid_clone && !clone.join(".git").exists() {
            init_repo(&clone);
        }
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
