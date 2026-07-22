//! CLI tests for `src/bin/bifrost_mcp_property_fuzzer.rs`, mirroring the
//! conventions of `tests/bifrost_reference_differential_cli.rs`.

use git2::{Repository, Signature};
use std::fs;
use std::path::Path;
use std::process::Command;
use tempfile::TempDir;

#[test]
fn help_describes_flags() {
    let output = Command::new(env!("CARGO_BIN_EXE_bifrost_mcp_property_fuzzer"))
        .arg("--help")
        .output()
        .expect("run help");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    for flag in [
        "--clones-root",
        "--repo",
        "--top",
        "--repo-jobs",
        "--rerun",
        "--signature",
        "--invariants",
        "--out",
        "--cache-mode",
        "--strict",
    ] {
        assert!(stdout.contains(flag), "missing {flag}:\n{stdout}");
    }
}

#[test]
fn run_repo_writes_completed_jsonl_record_and_resumes() {
    let fixture = ClonesFixture::new();
    fixture.add_rust_repo("tiny__rust");
    let out = fixture.run(&[
        "--repo",
        "tiny__rust",
        "--language",
        "rust",
        "--invariants",
        "I1",
        "--cache-mode",
        "ephemeral",
    ]);
    assert!(
        out.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let ledger_text = fs::read_to_string(&fixture.ledger).expect("read ledger");
    let lines = ledger_text.lines().collect::<Vec<_>>();
    assert_eq!(lines.len(), 1, "{ledger_text}");
    let record: serde_json::Value = serde_json::from_str(lines[0]).expect("parse record");
    assert_eq!(record["record_type"], "repository", "{record}");
    assert_eq!(record["status"], "completed", "{record}");
    assert_eq!(record["corpus_language"], "rust", "{record}");
    assert_eq!(record["repo_slug"], "tiny__rust", "{record}");
    assert!(record["bifrost_head"].is_string(), "{record}");
    assert!(record["run_fingerprint"].is_string(), "{record}");
    let report = &record["report"];
    assert_eq!(report["config"]["corpus_language"], "rust", "{record}");
    assert_eq!(report["config"]["invariants"][0], "I1", "{record}");
    assert!(
        report["i1_summary"]["symbols_selected"]
            .as_u64()
            .expect("symbols_selected")
            > 0,
        "{record}"
    );
    assert!(report["violations"].is_array(), "{record}");

    let resumed = fixture.run(&[
        "--repo",
        "tiny__rust",
        "--language",
        "rust",
        "--invariants",
        "I1",
        "--cache-mode",
        "ephemeral",
    ]);
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
        fs::read_to_string(&fixture.ledger)
            .expect("read resumed ledger")
            .lines()
            .count(),
        1
    );
}

#[test]
fn dry_run_prints_selection_without_writing() {
    let fixture = ClonesFixture::new();
    fixture.add_rust_repo("tiny__rust");
    let out = fixture.run(&["--repo", "tiny__rust", "--language", "rust", "--dry-run"]);
    assert!(
        out.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).expect("utf8 stdout");
    assert!(stdout.contains("rust\ttiny__rust\t"), "{stdout}");
    assert!(!fixture.ledger.exists());
}

#[test]
fn strict_exits_two_only_when_violations_exist() {
    let fixture = ClonesFixture::new();
    fixture.add_rust_repo("tiny__rust");
    let out = fixture.run(&[
        "--repo",
        "tiny__rust",
        "--language",
        "rust",
        "--strict",
        "--force",
        "--cache-mode",
        "ephemeral",
    ]);
    assert!(
        out.status.success(),
        "healthy fixture must not trip --strict: stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn invalid_invariant_is_rejected() {
    let fixture = ClonesFixture::new();
    fixture.add_rust_repo("tiny__rust");
    let out = fixture.run(&["--repo", "tiny__rust", "--invariants", "I9"]);
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("unknown invariant"),
        "stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn corpus_mode_requires_commits_root() {
    let out = Command::new(env!("CARGO_BIN_EXE_bifrost_mcp_property_fuzzer"))
        .args(["--clones-root", ".", "--out", "/tmp/unused-fuzzer.jsonl"])
        .output()
        .expect("run without --repo or --commits-root");
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("--commits-root is required"),
        "stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn corpus_mode_requires_top() {
    let out = Command::new(env!("CARGO_BIN_EXE_bifrost_mcp_property_fuzzer"))
        .args([
            "--clones-root",
            ".",
            "--commits-root",
            ".",
            "--out",
            "/tmp/unused-fuzzer.jsonl",
        ])
        .output()
        .expect("run corpus mode without --top");
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("--top N is required"),
        "stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn signature_without_rerun_is_rejected() {
    let out = Command::new(env!("CARGO_BIN_EXE_bifrost_mcp_property_fuzzer"))
        .args([
            "--clones-root",
            ".",
            "--repo",
            "x__y",
            "--out",
            "/tmp/unused-fuzzer.jsonl",
            "--signature",
            "sig",
        ])
        .output()
        .expect("run with bare --signature");
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr)
            .contains("--signature only applies together with --rerun"),
        "stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn rerun_rejects_selection_flags() {
    let out = Command::new(env!("CARGO_BIN_EXE_bifrost_mcp_property_fuzzer"))
        .args([
            "--clones-root",
            ".",
            "--repo",
            "x__y",
            "--out",
            "/tmp/unused-fuzzer.jsonl",
            "--rerun",
            "1",
        ])
        .output()
        .expect("run --rerun with --repo");
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("--rerun cannot be combined"),
        "stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn rerun_line_out_of_range_is_rejected() {
    let fixture = ClonesFixture::new();
    fixture.add_rust_repo("tiny__rust");
    fs::write(&fixture.ledger, "{\"record_type\":\"repository\"}\n").expect("seed ledger");
    let out = fixture.run(&["--rerun", "5"]);
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("has no line 5"),
        "stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn rerun_requires_a_completed_record() {
    let fixture = ClonesFixture::new();
    fixture.add_rust_repo("tiny__rust");
    fs::write(
        &fixture.ledger,
        "{\"record_type\":\"repository\",\"status\":\"engine_error\"}\n",
    )
    .expect("seed ledger");
    let out = fixture.run(&["--rerun", "1"]);
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("is not a completed repository record"),
        "stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn rerun_reports_records_without_violations() {
    let fixture = ClonesFixture::new();
    fixture.add_rust_repo("tiny__rust");
    fs::write(
        &fixture.ledger,
        format!(
            "{}\n",
            serde_json::json!({
                "record_type": "repository",
                "status": "completed",
                "corpus_language": "rust",
                "repo_slug": "tiny__rust",
                "repo_head": "unresolved-fixture-head",
                "cache_mode": "ephemeral",
                "report": {
                    "config": {
                        "corpus_language": "rust",
                        "invariants": ["I1"],
                        "max_symbols": 5000,
                        "max_service_symbols": 200,
                        "max_scan_probes": 40,
                        "seed": 0
                    },
                    "violations": []
                }
            })
        ),
    )
    .expect("seed ledger");
    let out = fixture.run(&["--rerun", "1"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("no violations"), "stderr:\n{stderr}");
}

/// Corpus mode shells out to `scripts/mcp-fuzzer-repo-rank.py`; pointing
/// `BROKK_BENCH_DIR` at a fake venv lets the test stub the ranking while the
/// binary exercises the real selection/validation path. Unix-only: the stub
/// interpreter is a shell script.
#[cfg(unix)]
#[test]
fn corpus_mode_selects_ranked_clones_and_skips_broken_ones() {
    use std::os::unix::fs::PermissionsExt;

    let fixture = ClonesFixture::new();
    fixture.add_rust_repo("alpha__rust");
    fixture.add_rust_repo("beta__rust");
    // No clone for ghost__rust: ranked but missing from the clones root.
    let bench = fixture._temp.path().join("bench");
    let venv_bin = bench.join(".venv").join("bin");
    fs::create_dir_all(&venv_bin).expect("venv bin");
    let interpreter = venv_bin.join("python3");
    fs::write(
        &interpreter,
        "#!/bin/sh\nprintf '%s\\n' '{\"rust\":[{\"slug\":\"ghost__rust\",\"sft_count\":9,\"scan_records\":90,\"rank_key\":\"sft\"},{\"slug\":\"alpha__rust\",\"sft_count\":5,\"scan_records\":50,\"rank_key\":\"sft\"},{\"slug\":\"beta__rust\",\"sft_count\":1,\"scan_records\":10,\"rank_key\":\"sft\"}]}'\n",
    )
    .expect("stub interpreter");
    fs::set_permissions(&interpreter, fs::Permissions::from_mode(0o755)).expect("chmod");

    let out = Command::new(env!("CARGO_BIN_EXE_bifrost_mcp_property_fuzzer"))
        .arg("--clones-root")
        .arg(&fixture.clones)
        .arg("--out")
        .arg(&fixture.ledger)
        .args([
            "--commits-root",
            "/nonexistent-commits-root",
            "--top",
            "2",
            "--language",
            "rust",
            "--invariants",
            "I1",
            "--cache-mode",
            "ephemeral",
        ])
        .env("BROKK_BENCH_DIR", &bench)
        .output()
        .expect("run corpus mode");
    assert!(
        out.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("skip rust ghost__rust"),
        "missing clone must be skipped with a warning:\n{stderr}"
    );
    let ledger_text = fs::read_to_string(&fixture.ledger).expect("read ledger");
    let slugs = ledger_text
        .lines()
        .map(|line| {
            serde_json::from_str::<serde_json::Value>(line).expect("record json")["repo_slug"]
                .as_str()
                .expect("slug")
                .to_string()
        })
        .collect::<Vec<_>>();
    assert_eq!(slugs.len(), 2, "{ledger_text}");
    assert!(slugs.contains(&"alpha__rust".to_string()), "{slugs:?}");
    assert!(slugs.contains(&"beta__rust".to_string()), "{slugs:?}");
}

#[test]
fn invalid_cache_mode_is_rejected() {
    let fixture = ClonesFixture::new();
    fixture.add_rust_repo("tiny__rust");
    let out = fixture.run(&[
        "--repo",
        "tiny__rust",
        "--language",
        "rust",
        "--cache-mode",
        "temporary",
    ]);
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr)
            .contains("--cache-mode expects `persisted` or `ephemeral`"),
        "stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

struct ClonesFixture {
    _temp: TempDir,
    clones: std::path::PathBuf,
    ledger: std::path::PathBuf,
}

impl ClonesFixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().expect("temp dir");
        let clones = temp.path().join("clones");
        fs::create_dir_all(&clones).expect("clones dir");
        let ledger = temp.path().join("ledger.jsonl");
        Self {
            _temp: temp,
            clones,
            ledger,
        }
    }

    fn add_rust_repo(&self, slug: &str) {
        let clone = self.clones.join(slug);
        fs::create_dir_all(&clone).expect("clone dir");
        fs::write(
            clone.join("lib.rs"),
            "pub struct Greeter {\n    pub prefix: String,\n}\n\nimpl Greeter {\n    pub fn greet(&self, name: &str) -> String {\n        format!(\"{} {name}\", self.prefix)\n    }\n}\n",
        )
        .expect("rust source");
        init_repo(&clone);
    }

    fn run(&self, extra_args: &[&str]) -> std::process::Output {
        Command::new(env!("CARGO_BIN_EXE_bifrost_mcp_property_fuzzer"))
            .arg("--clones-root")
            .arg(&self.clones)
            .arg("--out")
            .arg(&self.ledger)
            .args(extra_args)
            .output()
            .expect("run fuzzer CLI")
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
