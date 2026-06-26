use brokk_bifrost::SearchToolsService;
use serde_json::Value;
use std::fs;
use std::path::Path;
use std::process::Command;
use tempfile::TempDir;

fn git(root: &Path, args: &[&str]) {
    let status = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .status()
        .expect("run git");
    assert!(status.success(), "git {args:?} failed");
}

fn commit(root: &Path, message: &str) -> String {
    git(root, &["add", "."]);
    git(root, &["commit", "-m", message]);
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["rev-parse", "HEAD"])
        .output()
        .expect("rev-parse");
    assert!(output.status.success());
    String::from_utf8(output.stdout).unwrap().trim().to_string()
}

#[test]
fn analyze_commit_reports_symbol_and_edge_effects() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path();
    git(root, &["init"]);
    git(root, &["config", "user.email", "tester@example.com"]);
    git(root, &["config", "user.name", "Tester"]);

    fs::write(
        root.join("lib.go"),
        r#"package sample

func Existing() int {
	return 1
}

func Caller() int {
	return Existing()
}
"#,
    )
    .unwrap();
    commit(root, "base");

    fs::write(
        root.join("lib.go"),
        r#"package sample

import "strings"

func Existing() int {
	return 2
}

func Added(name string) string {
	return strings.TrimSpace(name)
}

func Caller() string {
	return Added(" x ")
}
"#,
    )
    .unwrap();
    let head = commit(root, "change");

    let service = SearchToolsService::new(root.to_path_buf()).expect("service");
    let result: Value = serde_json::from_str(
        &service
            .call_tool_json(
                "analyze_commit",
                &serde_json::json!({"revision": head}).to_string(),
            )
            .expect("analyze_commit"),
    )
    .expect("json");

    assert_eq!(
        result["commit"]["hash"].as_str().unwrap().len(),
        40,
        "resolved hash is returned"
    );
    assert!(
        result["introduced_symbols"]
            .as_array()
            .unwrap()
            .iter()
            .any(|symbol| symbol["fqn"].as_str().unwrap().ends_with("Added"))
    );
    assert!(
        result["edited_symbols"]
            .as_array()
            .unwrap()
            .iter()
            .any(|symbol| symbol["fqn"].as_str().unwrap().ends_with("Existing"))
    );
    assert!(
        result["import_changes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|change| change["added"].as_array().unwrap().iter().any(|item| item
                .as_str()
                .unwrap()
                .contains("strings")))
    );
    assert!(
        result["call_edge_changes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|edge| edge["change"] == "added")
    );
}

#[test]
fn analyze_commit_rejects_root_commit() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path();
    git(root, &["init"]);
    git(root, &["config", "user.email", "tester@example.com"]);
    git(root, &["config", "user.name", "Tester"]);
    fs::write(root.join("lib.go"), "package sample\nfunc A() {}\n").unwrap();
    let root_commit = commit(root, "root");

    let service = SearchToolsService::new(root.to_path_buf()).expect("service");
    let err = service
        .call_tool_json(
            "analyze_commit",
            &serde_json::json!({"revision": root_commit}).to_string(),
        )
        .unwrap_err();
    assert!(err.message.contains("root commits"));
}
