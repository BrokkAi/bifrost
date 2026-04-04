use brokk_analyzer::{SearchToolsService, SearchToolsServiceErrorCode};
use serde_json::Value;
use std::path::PathBuf;

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
