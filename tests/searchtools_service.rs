use brokk_analyzer::{SearchToolsService, SearchToolsServiceErrorCode};
use git2::{Repository, Signature};
use serde_json::Value;
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("testcode-java")
}

#[test]
fn python_boundary_returns_structured_json() {
    let mut service = SearchToolsService::new_for_python(fixture_root()).unwrap();
    let payload = service
        .call_tool_json("get_summaries", r#"{"targets":["A.java"]}"#)
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    assert_eq!(value["summaries"][0]["path"], "A.java");
    assert_eq!(value["summaries"][0]["elements"][0]["start_line"], 3);
}

#[test]
fn python_boundary_returns_summarize_symbols_json() {
    let mut service = SearchToolsService::new_for_python(fixture_root()).unwrap();
    let payload = service
        .call_tool_json("summarize_symbols", r#"{"file_patterns":["A.java"]}"#)
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    assert_eq!(value["files"][0]["path"], "A.java");
    let lines = value["files"][0]["lines"].as_array().unwrap();
    assert!(lines.iter().any(|line| line.as_str() == Some("  - AInner")));
    assert!(
        lines
            .iter()
            .any(|line| line.as_str() == Some("    - AInnerInner"))
    );
    assert!(
        lines
            .iter()
            .any(|line| line.as_str() == Some("      - method7"))
    );
}

#[test]
fn python_boundary_surfaces_invalid_params() {
    let mut service = SearchToolsService::new_for_python(fixture_root()).unwrap();
    let err = service
        .call_tool_json("search_symbols", r#"{"patterns":1}"#)
        .unwrap_err();

    assert_eq!(err.code, SearchToolsServiceErrorCode::InvalidParams);
    assert!(err.message.contains("Invalid tool arguments"));
}

#[test]
fn python_boundary_returns_most_relevant_files_json() {
    let temp = TempDir::new().unwrap();
    fs::write(temp.path().join("A.java"), "public class A { }\n").unwrap();
    fs::write(temp.path().join("B.java"), "public class B { }\n").unwrap();
    let repo = Repository::init(temp.path()).unwrap();
    let mut index = repo.index().unwrap();
    index.add_path(std::path::Path::new("A.java")).unwrap();
    index.add_path(std::path::Path::new("B.java")).unwrap();
    index.write().unwrap();
    let tree_id = index.write_tree().unwrap();
    let tree = repo.find_tree(tree_id).unwrap();
    let signature = Signature::now("Test User", "test@example.com").unwrap();
    repo.commit(Some("HEAD"), &signature, &signature, "initial", &tree, &[])
        .unwrap();

    let mut service = SearchToolsService::new_for_python(temp.path().to_path_buf()).unwrap();
    let payload = service
        .call_tool_json(
            "most_relevant_files",
            r#"{"seed_files":["A.java"],"limit":5}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    let files = value["files"].as_array().unwrap();
    assert!(
        files.iter().any(|item| item == "B.java"),
        "payload: {value}"
    );
    assert_eq!(0, value["not_found"].as_array().unwrap().len());
}

#[test]
fn search_symbols_limit_selects_git_important_file_then_renders_alphabetically() {
    let temp = TempDir::new().unwrap();
    fs::write(temp.path().join("a_low.java"), "class ALow {}\n").unwrap();
    fs::write(temp.path().join("z_high.java"), "class ZHigh {}\n").unwrap();
    let repo = Repository::init(temp.path()).unwrap();
    commit_paths(&repo, &["a_low.java"], "add low");
    commit_paths(&repo, &["z_high.java"], "add high");
    fs::write(
        temp.path().join("z_high.java"),
        "class ZHigh { int value; }\n",
    )
    .unwrap();
    commit_paths(&repo, &["z_high.java"], "update high");

    let mut service = SearchToolsService::new_for_python(temp.path().to_path_buf()).unwrap();
    let payload = service
        .call_tool_json(
            "search_symbols",
            r#"{"patterns":[".*"],"include_tests":true,"limit":1}"#,
        )
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    assert_eq!(true, value["truncated"]);
    let files = value["files"].as_array().unwrap();
    assert_eq!(1, files.len(), "payload: {value}");
    assert_eq!("z_high.java", files[0]["path"]);
    assert_eq!("class ZHigh", files[0]["classes"][0]["signature"]);
    assert_eq!(1, files[0]["classes"][0]["line"]);
}

#[test]
fn get_active_workspace_returns_initial_root() {
    let mut service = SearchToolsService::new_for_python(fixture_root()).unwrap();
    let payload = service
        .call_tool_json("get_active_workspace", "{}")
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    let expected = fixture_root().canonicalize().unwrap();
    assert_eq!(value["workspace_path"], expected.display().to_string());
}

#[test]
fn activate_workspace_rejects_relative_path() {
    let mut service = SearchToolsService::new_for_python(fixture_root()).unwrap();
    let err = service
        .call_tool_json(
            "activate_workspace",
            r#"{"workspace_path":"relative/path"}"#,
        )
        .unwrap_err();

    assert_eq!(err.code, SearchToolsServiceErrorCode::InvalidParams);
    assert!(
        err.message.contains("must be absolute"),
        "unexpected message: {}",
        err.message
    );
}

#[test]
fn activate_workspace_rejects_nonexistent_path() {
    let mut service = SearchToolsService::new_for_python(fixture_root()).unwrap();
    let err = service
        .call_tool_json(
            "activate_workspace",
            r#"{"workspace_path":"/this/path/should/not/exist/bifrost-test"}"#,
        )
        .unwrap_err();

    assert_eq!(err.code, SearchToolsServiceErrorCode::InvalidParams);
}

#[test]
fn activate_workspace_idempotent_for_same_root() {
    // Use a fresh git repo as a self-contained root so resolve_workspace_root
    // returns the same path that was passed in.
    let temp = TempDir::new().unwrap();
    fs::write(temp.path().join("Same.java"), "public class Same {}\n").unwrap();
    let repo = Repository::init(temp.path()).unwrap();
    commit_paths(&repo, &["Same.java"], "initial");
    let same_root = temp.path().canonicalize().unwrap();

    let mut service = SearchToolsService::new_for_python(same_root.clone()).unwrap();
    let arguments = format!(
        r#"{{"workspace_path":{}}}"#,
        serde_json::to_string(&same_root.display().to_string()).unwrap()
    );
    let payload = service
        .call_tool_json("activate_workspace", &arguments)
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();
    assert_eq!(value["workspace_path"], same_root.display().to_string());
}

#[test]
fn activate_workspace_switches_to_new_root() {
    let temp = TempDir::new().unwrap();
    fs::write(
        temp.path().join("Switched.java"),
        "public class Switched {}\n",
    )
    .unwrap();
    let new_root = temp.path().canonicalize().unwrap();

    let mut service = SearchToolsService::new_for_python(fixture_root()).unwrap();
    let arguments = format!(
        r#"{{"workspace_path":{}}}"#,
        serde_json::to_string(&new_root.display().to_string()).unwrap()
    );
    let activate_payload = service
        .call_tool_json("activate_workspace", &arguments)
        .unwrap();
    let activate_value: Value = serde_json::from_str(&activate_payload).unwrap();
    assert_eq!(
        activate_value["workspace_path"],
        new_root.display().to_string()
    );

    let get_payload = service
        .call_tool_json("get_active_workspace", "{}")
        .unwrap();
    let get_value: Value = serde_json::from_str(&get_payload).unwrap();
    assert_eq!(get_value["workspace_path"], new_root.display().to_string());

    // The new workspace should index files from the new root, not the old one.
    let summary_payload = service
        .call_tool_json(
            "summarize_symbols",
            r#"{"file_patterns":["Switched.java"]}"#,
        )
        .unwrap();
    let summary_value: Value = serde_json::from_str(&summary_payload).unwrap();
    assert_eq!(summary_value["files"][0]["path"], "Switched.java");
}

#[test]
fn activate_workspace_failure_preserves_existing_workspace() {
    // Pointing activate at a regular file (not a directory) makes
    // FilesystemProject::new reject the path. The existing workspace must
    // still answer queries afterwards.
    let temp = TempDir::new().unwrap();
    let bad_path = temp.path().join("not_a_dir.txt");
    fs::write(&bad_path, "not a directory").unwrap();
    let bad_path = bad_path.canonicalize().unwrap();

    let mut service = SearchToolsService::new_for_python(fixture_root()).unwrap();

    let arguments = format!(
        r#"{{"workspace_path":{}}}"#,
        serde_json::to_string(&bad_path.display().to_string()).unwrap()
    );
    let err = service
        .call_tool_json("activate_workspace", &arguments)
        .unwrap_err();
    assert_eq!(err.code, SearchToolsServiceErrorCode::InvalidParams);

    // Original workspace must remain queryable.
    let active_payload = service
        .call_tool_json("get_active_workspace", "{}")
        .unwrap();
    let active_value: Value = serde_json::from_str(&active_payload).unwrap();
    let expected = fixture_root().canonicalize().unwrap();
    assert_eq!(
        active_value["workspace_path"],
        expected.display().to_string()
    );

    let summary_payload = service
        .call_tool_json("get_summaries", r#"{"targets":["A.java"]}"#)
        .unwrap();
    let summary_value: Value = serde_json::from_str(&summary_payload).unwrap();
    assert_eq!(summary_value["summaries"][0]["path"], "A.java");
}

#[test]
fn activate_workspace_normalizes_to_git_root() {
    let temp = TempDir::new().unwrap();
    fs::write(temp.path().join("Top.java"), "public class Top {}\n").unwrap();
    fs::create_dir_all(temp.path().join("nested")).unwrap();
    fs::write(
        temp.path().join("nested").join("Inner.java"),
        "public class Inner {}\n",
    )
    .unwrap();
    let repo = Repository::init(temp.path()).unwrap();
    commit_paths(&repo, &["Top.java", "nested/Inner.java"], "initial");

    let repo_root = temp.path().canonicalize().unwrap();
    let nested = repo_root.join("nested");

    let mut service = SearchToolsService::new_for_python(fixture_root()).unwrap();
    let arguments = format!(
        r#"{{"workspace_path":{}}}"#,
        serde_json::to_string(&nested.display().to_string()).unwrap()
    );
    let payload = service
        .call_tool_json("activate_workspace", &arguments)
        .unwrap();
    let value: Value = serde_json::from_str(&payload).unwrap();

    assert_eq!(value["workspace_path"], repo_root.display().to_string());
}

fn commit_paths(repo: &Repository, paths: &[&str], message: &str) {
    let mut index = repo.index().unwrap();
    for path in paths {
        index.add_path(std::path::Path::new(path)).unwrap();
    }
    index.write().unwrap();
    let tree_id = index.write_tree().unwrap();
    let tree = repo.find_tree(tree_id).unwrap();
    let signature = Signature::now("Test User", "test@example.com").unwrap();
    let parent = repo
        .head()
        .ok()
        .and_then(|head| head.target())
        .and_then(|oid| repo.find_commit(oid).ok());
    let parents = parent.iter().collect::<Vec<_>>();
    repo.commit(
        Some("HEAD"),
        &signature,
        &signature,
        message,
        &tree,
        &parents,
    )
    .unwrap();
}
