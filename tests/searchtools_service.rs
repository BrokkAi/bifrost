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
        .call_tool_json("get_file_summaries", r#"{"file_patterns":["A.java"]}"#)
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
