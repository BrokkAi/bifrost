mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use serde_json::Value;

use common::{BuiltInlineTestProject, InlineTestProject};

const APP: &str = include_str!("fixtures/policy-cli/project/src/app.py");
const DYNAMIC: &str = include_str!("fixtures/policy-cli/project/policies/dynamic-eval.rqlp");
const INFERRED: &str =
    include_str!("fixtures/policy-cli/project/policies/inferred-dynamic-eval.rqlp");
const NO_EXEC: &str = include_str!("fixtures/policy-cli/project/policies/no-exec.rqlp");
const RESOURCE: &str = include_str!("fixtures/policy-cli/project/policies/resource-lifecycle.rqlp");
const UNRATED: &str = include_str!("fixtures/policy-cli/project/policies/unrated-eval.rqlp");
const NOTE: &str = include_str!("fixtures/policy-cli/project/policies/note-eval.rqlp");
const HTTP_ENDPOINT: &str =
    include_str!("fixtures/policy-cli/project/policies/endpoints/http-request-parameter.rqlp");
const ACQUIRE_ENDPOINT: &str =
    include_str!("fixtures/policy-cli/project/policies/endpoints/resource-acquire.rqlp");
const INFERRED_ACQUIRE_ENDPOINT: &str =
    include_str!("fixtures/policy-cli/project/policies/endpoints/resource-acquire-inferred.rqlp");
const CLOSE_ENDPOINT: &str =
    include_str!("fixtures/policy-cli/project/policies/endpoints/resource-close.rqlp");

fn policy_project(extra: &[(&str, String)]) -> BuiltInlineTestProject {
    let mut project = InlineTestProject::new()
        .file("src/app.py", APP)
        .file("policies/dynamic-eval.rqlp", DYNAMIC)
        .file("policies/inferred-dynamic-eval.rqlp", INFERRED)
        .file("policies/no-exec.rqlp", NO_EXEC)
        .file("policies/resource-lifecycle.rqlp", RESOURCE)
        .file("policies/unrated-eval.rqlp", UNRATED)
        .file("policies/note-eval.rqlp", NOTE)
        .file(
            "policies/endpoints/http-request-parameter.rqlp",
            HTTP_ENDPOINT,
        )
        .file("policies/endpoints/resource-acquire.rqlp", ACQUIRE_ENDPOINT)
        .file("policies/endpoints/resource-close.rqlp", CLOSE_ENDPOINT);
    for (path, source) in extra {
        project = project.file(*path, source.clone());
    }
    project.build()
}

fn bifrost(root: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_bifrost"));
    command
        .arg("--root")
        .arg(root)
        .env("BIFROST_PARALLELISM", "1");
    command
}

fn run(root: &Path, args: &[&str]) -> Output {
    bifrost(root)
        .args(args)
        .output()
        .unwrap_or_else(|error| panic!("failed to run bifrost {args:?}: {error}"))
}

fn assert_status(output: &Output, expected: i32) {
    assert_eq!(
        output.status.code(),
        Some(expected),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

fn json_stdout(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "invalid JSON stdout: {error}\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        )
    })
}

fn assert_single_terminal_safe_line(output: &Output) {
    let stderr = String::from_utf8(output.stderr.clone()).expect("UTF-8 stderr");
    assert_eq!(stderr.matches('\n').count(), 1, "{stderr:?}");
    for character in ['\u{001B}', '\u{202E}', '\u{2066}'] {
        assert!(
            !stderr.contains(character),
            "raw {character:?} in {stderr:?}"
        );
    }
    for escaped in ["\\u{A}", "\\u{1B}", "\\u{202E}", "\\u{2066}"] {
        assert!(stderr.contains(escaped), "missing {escaped} in {stderr:?}");
    }
}

#[test]
fn thresholds_cover_clean_rated_and_unrated_findings() {
    let project = policy_project(&[]);
    let cases: &[(&[&str], i32)] = &[
        (&["--policy-file", "policies/no-exec.rqlp"], 0),
        (
            &[
                "--policy-file",
                "policies/dynamic-eval.rqlp",
                "--fail-on",
                "never",
            ],
            0,
        ),
        (
            &[
                "--policy-file",
                "policies/dynamic-eval.rqlp",
                "--fail-on",
                "warning",
            ],
            1,
        ),
        (
            &[
                "--policy-file",
                "policies/dynamic-eval.rqlp",
                "--fail-on",
                "error",
            ],
            0,
        ),
        (
            &[
                "--policy-file",
                "policies/note-eval.rqlp",
                "--fail-on",
                "note",
            ],
            1,
        ),
        (
            &[
                "--policy-file",
                "policies/note-eval.rqlp",
                "--fail-on",
                "warning",
            ],
            0,
        ),
        (
            &[
                "--policy-file",
                "policies/unrated-eval.rqlp",
                "--fail-on",
                "finding",
            ],
            1,
        ),
        (
            &[
                "--policy-file",
                "policies/unrated-eval.rqlp",
                "--fail-on",
                "note",
            ],
            0,
        ),
    ];
    for (args, expected) in cases {
        let output = run(project.root(), args);
        assert_status(&output, *expected);
    }

    let default = run(
        project.root(),
        &["--policy-file", "policies/dynamic-eval.rqlp"],
    );
    assert_status(&default, 1);
    let stdout = String::from_utf8(default.stdout).expect("UTF-8 human report");
    assert!(
        stdout.contains("src/app.py:2:12: [warning] bifrost.security.dynamic-eval"),
        "{stdout}"
    );
    assert!(
        stdout.contains("  evidence: structural_match call\n"),
        "{stdout}"
    );
    assert!(stdout.contains("summary: 1 finding; 1 complete policy run"));
}

#[test]
fn strict_versions_endpoint_roots_and_unsupported_runs_are_status_two_reports() {
    let project = policy_project(&[]);

    let inferred = run(
        project.root(),
        &[
            "--policy-file",
            "policies/inferred-dynamic-eval.rqlp",
            "--format",
            "json",
            "--require-explicit-schema-versions",
        ],
    );
    assert_status(&inferred, 2);
    let report = json_stdout(&inferred);
    assert!(report["rules"].as_array().unwrap().is_empty());
    assert!(report["runs"].as_array().unwrap().is_empty());
    let codes = report["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .map(|diagnostic| diagnostic["code"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert!(codes.contains(&"explicit-policy-schema-version-required"));
    assert!(codes.contains(&"explicit-rql-schema-version-required"));

    let accepted_inference = run(
        project.root(),
        &["--policy-file", "policies/inferred-dynamic-eval.rqlp"],
    );
    assert_status(&accepted_inference, 1);
    assert!(
        String::from_utf8_lossy(&accepted_inference.stdout)
            .contains(
                "policy bifrost.security.inferred-dynamic-eval inferred policy schema 1 and RQL schema 2"
            )
    );

    let endpoint = run(
        project.root(),
        &[
            "--policy-file",
            "policies/endpoints/http-request-parameter.rqlp",
        ],
    );
    assert_status(&endpoint, 2);
    assert!(String::from_utf8_lossy(&endpoint.stdout).contains("not-executable-endpoint"));

    let resource = run(
        project.root(),
        &[
            "--policy-file",
            "policies/resource-lifecycle.rqlp",
            "--format",
            "json",
        ],
    );
    assert_status(&resource, 2);
    let report = json_stdout(&resource);
    assert_eq!(report["rules"].as_array().unwrap().len(), 1);
    assert_eq!(report["runs"].as_array().unwrap().len(), 1);
    assert_eq!(
        report["rules"][0]["endpoint_dependencies"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(report["runs"][0]["completion"]["type"], "unsupported");

    let dependency_project = policy_project(&[(
        "policies/endpoints/resource-acquire.rqlp",
        INFERRED_ACQUIRE_ENDPOINT.to_string(),
    )]);
    let strict_dependency = run(
        dependency_project.root(),
        &[
            "--policy-file",
            "policies/resource-lifecycle.rqlp",
            "--format",
            "json",
            "--require-explicit-schema-versions",
        ],
    );
    assert_status(&strict_dependency, 2);
    let report = json_stdout(&strict_dependency);
    assert!(report["rules"].as_array().unwrap().is_empty());
    assert!(report["runs"].as_array().unwrap().is_empty());
    let dependency_diagnostics = report["diagnostics"].as_array().unwrap();
    assert!(dependency_diagnostics.iter().any(|diagnostic| {
        diagnostic["code"] == "explicit-policy-schema-version-required"
            && diagnostic["source"] == "policies/endpoints/resource-acquire.rqlp"
    }));
    assert!(dependency_diagnostics.iter().any(|diagnostic| {
        diagnostic["code"] == "explicit-rql-schema-version-required"
            && diagnostic["source"] == "policies/endpoints/resource-acquire.rqlp"
    }));
}

#[test]
fn json_sarif_stdout_and_atomic_file_output_are_deterministic() {
    let project = policy_project(&[]);
    let json_args = [
        "--policy-file",
        "policies/dynamic-eval.rqlp",
        "--format",
        "json",
        "--fail-on",
        "never",
    ];
    let first = run(project.root(), &json_args);
    let second = run(project.root(), &json_args);
    assert_status(&first, 0);
    assert_status(&second, 0);
    assert_eq!(first.stdout, second.stdout);
    let report = json_stdout(&first);
    assert_eq!(report["rules"].as_array().unwrap().len(), 1);
    assert_eq!(report["runs"][0]["findings"].as_array().unwrap().len(), 1);
    assert_eq!(report["runs"][0]["completion"]["type"], "complete");

    let sarif = run(
        project.root(),
        &[
            "--policy-file",
            "policies/dynamic-eval.rqlp",
            "--format",
            "sarif",
            "--fail-on",
            "never",
        ],
    );
    assert_status(&sarif, 0);
    let sarif = json_stdout(&sarif);
    assert_eq!(sarif["version"], "2.1.0");
    assert_eq!(sarif["runs"][0]["columnKind"], "unicodeCodePoints");
    assert_eq!(
        sarif["runs"][0]["invocations"][0]["executionSuccessful"],
        true
    );
    assert_eq!(
        sarif["runs"][0]["results"][0]["ruleId"],
        "bifrost.security.dynamic-eval"
    );

    let destination = tempfile::tempdir().expect("output directory");
    let output_path = destination.path().join("report.json");
    let written = bifrost(project.root())
        .args(json_args)
        .arg("--output")
        .arg(&output_path)
        .output()
        .expect("write policy JSON");
    assert_status(&written, 0);
    assert!(written.stdout.is_empty());
    assert_eq!(fs::read(&output_path).unwrap(), first.stdout);
}

#[test]
fn policy_id_order_is_stable_and_duplicate_roots_are_all_excluded() {
    let duplicate = DYNAMIC.replace(
        ":name \"No dynamic evaluation\"",
        ":name \"Duplicate dynamic evaluation\"",
    );
    let project = policy_project(&[("policies/duplicate.rqlp", duplicate)]);

    let first = run(
        project.root(),
        &[
            "--policy-file",
            "policies/note-eval.rqlp",
            "--policy-file",
            "policies/dynamic-eval.rqlp",
            "--format",
            "json",
            "--fail-on",
            "never",
        ],
    );
    let reversed = run(
        project.root(),
        &[
            "--policy-file",
            "policies/dynamic-eval.rqlp",
            "--policy-file",
            "policies/note-eval.rqlp",
            "--format",
            "json",
            "--fail-on",
            "never",
        ],
    );
    assert_status(&first, 0);
    assert_status(&reversed, 0);
    assert_eq!(first.stdout, reversed.stdout);

    let duplicates = run(
        project.root(),
        &[
            "--policy-file",
            "policies/dynamic-eval.rqlp",
            "--policy-file",
            "policies/duplicate.rqlp",
            "--format",
            "json",
        ],
    );
    let duplicates_reversed = run(
        project.root(),
        &[
            "--policy-file",
            "policies/duplicate.rqlp",
            "--policy-file",
            "policies/dynamic-eval.rqlp",
            "--format",
            "json",
        ],
    );
    assert_status(&duplicates, 2);
    assert_status(&duplicates_reversed, 2);
    assert_eq!(duplicates.stdout, duplicates_reversed.stdout);
    let report = json_stdout(&duplicates);
    assert!(report["rules"].as_array().unwrap().is_empty());
    assert!(report["runs"].as_array().unwrap().is_empty());
    assert_eq!(report["diagnostics"].as_array().unwrap().len(), 2);
    let diagnostics = report["diagnostics"].as_array().unwrap();
    let mut sources = Vec::new();
    for diagnostic in diagnostics {
        assert_eq!(diagnostic["code"], "duplicate-policy-id");
        assert_eq!(
            diagnostic["message"],
            "policy ID `bifrost.security.dynamic-eval` has 2 requested definitions across 2 source identities; every definition was excluded"
        );
        sources.push(diagnostic["source"].as_str().unwrap());
        assert_eq!(diagnostic["related"].as_array().unwrap().len(), 1);
    }
    sources.sort_unstable();
    assert_eq!(
        sources,
        ["policies/duplicate.rqlp", "policies/dynamic-eval.rqlp"]
    );
}

#[test]
fn mixed_invalid_and_unsupported_batches_retain_valid_findings_with_status_two() {
    let project = policy_project(&[(
        "policies/invalid.rqlp",
        "(policy :id \"broken\"".to_string(),
    )]);
    let destination = tempfile::tempdir().expect("output directory");
    let output_path = destination.path().join("mixed.json");
    let mixed = bifrost(project.root())
        .args([
            "--policy-file",
            "policies/dynamic-eval.rqlp",
            "--policy-file",
            "policies/invalid.rqlp",
            "--format",
            "json",
            "--output",
        ])
        .arg(&output_path)
        .output()
        .expect("run mixed valid/invalid policy batch");
    assert_status(&mixed, 2);
    assert!(mixed.stdout.is_empty());
    let report: Value = serde_json::from_slice(&fs::read(&output_path).unwrap()).unwrap();
    assert_eq!(report["rules"].as_array().unwrap().len(), 1);
    assert_eq!(report["runs"][0]["findings"].as_array().unwrap().len(), 1);
    assert_eq!(report["diagnostics"].as_array().unwrap().len(), 1);

    let unsupported = run(
        project.root(),
        &[
            "--policy-file",
            "policies/dynamic-eval.rqlp",
            "--policy-file",
            "policies/resource-lifecycle.rqlp",
            "--format",
            "sarif",
        ],
    );
    assert_status(&unsupported, 2);
    let sarif = json_stdout(&unsupported);
    assert_eq!(sarif["runs"][0]["results"].as_array().unwrap().len(), 1);
    assert_eq!(
        sarif["runs"][0]["invocations"][0]["executionSuccessful"],
        false
    );
    assert!(
        !sarif["runs"][0]["invocations"][0]["toolExecutionNotifications"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn policy_mode_is_exclusive_and_output_failures_use_status_two_without_clobbering() {
    let project = policy_project(&[]);
    let missing = run(
        project.root(),
        &["--policy-file", "policies/missing.rqlp", "--format", "json"],
    );
    assert_status(&missing, 2);
    let missing_report = json_stdout(&missing);
    assert_eq!(
        missing_report["diagnostics"][0]["code"],
        "policy-load-failed"
    );

    let conflict = run(
        project.root(),
        &[
            "--policy-file",
            "policies/dynamic-eval.rqlp",
            "--sources",
            "src",
        ],
    );
    assert_status(&conflict, 2);
    assert!(conflict.stdout.is_empty());
    assert!(String::from_utf8_lossy(&conflict.stderr).contains("cannot be combined"));

    for arguments in [
        vec!["--format", "xml"],
        vec!["--policy-file"],
        vec!["--policy-file", "policies/dynamic-eval.rqlp", "--unknown"],
        vec!["--unknown", "--policy-file", "policies/dynamic-eval.rqlp"],
        vec![
            "--args",
            "not-json",
            "--policy-file",
            "policies/dynamic-eval.rqlp",
        ],
    ] {
        let invalid_invocation = run(project.root(), &arguments);
        assert_status(&invalid_invocation, 2);
        assert!(invalid_invocation.stdout.is_empty());
    }

    let legacy_value = run(
        project.root(),
        &["--tool", "--format", "--args", "not-json"],
    );
    assert_status(&legacy_value, 1);
    assert!(String::from_utf8_lossy(&legacy_value.stderr).contains("--args must be valid JSON"));

    let destination = tempfile::tempdir().expect("destination parent");
    let output_path = destination.path().join("report.json");
    fs::write(&output_path, "previous report\n").expect("existing destination");

    let directory_destination = destination.path().join("nonempty-destination");
    fs::create_dir(&directory_destination).expect("nonempty destination directory");
    let sentinel = directory_destination.join("sentinel.txt");
    fs::write(&sentinel, "keep me\n").expect("destination sentinel");
    let directory_failure = bifrost(project.root())
        .args([
            "--policy-file",
            "policies/dynamic-eval.rqlp",
            "--format",
            "json",
            "--output",
        ])
        .arg(&directory_destination)
        .output()
        .expect("run platform-neutral persist failure");
    assert_status(&directory_failure, 2);
    assert!(directory_failure.stdout.is_empty());
    assert_eq!(fs::read_to_string(&sentinel).unwrap(), "keep me\n");
    assert!(
        String::from_utf8_lossy(&directory_failure.stderr).contains("failed to atomically replace")
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let original = fs::metadata(destination.path()).unwrap().permissions();
        fs::set_permissions(destination.path(), fs::Permissions::from_mode(0o555)).unwrap();
        let failed = bifrost(project.root())
            .args([
                "--policy-file",
                "policies/dynamic-eval.rqlp",
                "--format",
                "json",
                "--output",
            ])
            .arg(&output_path)
            .output()
            .expect("run policy output failure");
        fs::set_permissions(destination.path(), original).unwrap();

        assert_status(&failed, 2);
        assert!(failed.stdout.is_empty());
        assert_eq!(
            fs::read_to_string(&output_path).unwrap(),
            "previous report\n"
        );
        assert!(String::from_utf8_lossy(&failed.stderr).contains("policy report output failed"));
    }
}

#[test]
fn policy_stderr_escapes_control_and_bidirectional_text() {
    let project = policy_project(&[]);
    let unsafe_text = "line\n\u{001B}[31m\u{202E}\u{2066}";

    let invalid_format = run(project.root(), &["--format", unsafe_text]);
    assert_status(&invalid_format, 2);
    assert!(invalid_format.stdout.is_empty());
    assert_single_terminal_safe_line(&invalid_format);

    let unsafe_destination = project.root().join(unsafe_text).join("report.json");
    let failed_output = bifrost(project.root())
        .args(["--policy-file", "policies/dynamic-eval.rqlp", "--output"])
        .arg(unsafe_destination)
        .output()
        .expect("run policy output failure with unsafe path");
    assert_status(&failed_output, 2);
    assert!(failed_output.stdout.is_empty());
    assert_single_terminal_safe_line(&failed_output);
}

#[test]
fn broken_stdout_pipe_is_an_operational_status_two_failure() {
    let project = policy_project(&[]);
    let mut child = bifrost(project.root())
        .args([
            "--policy-file",
            "policies/dynamic-eval.rqlp",
            "--format",
            "json",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn policy CLI");
    drop(child.stdout.take());
    let output = child.wait_with_output().expect("wait for policy CLI");
    assert_status(&output, 2);
    assert!(String::from_utf8_lossy(&output.stderr).contains("policy report output failed"));
}

#[test]
fn output_path_may_be_outside_the_analyzed_workspace() {
    let project = policy_project(&[]);
    let outside = tempfile::tempdir().expect("outside output root");
    let output_path: PathBuf = outside.path().join("report.txt");
    let output = bifrost(project.root())
        .args(["--policy-file", "policies/dynamic-eval.rqlp", "--output"])
        .arg(&output_path)
        .output()
        .expect("write outside workspace");
    assert_status(&output, 1);
    assert!(output.stdout.is_empty());
    assert!(
        fs::read_to_string(output_path)
            .unwrap()
            .contains("bifrost.security.dynamic-eval")
    );
}
