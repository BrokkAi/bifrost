use crate::common::InlineTestProject;
use brokk_bifrost::SearchToolsService;
use serde_json::Value;
use std::fs;
use std::path::Path;

#[test]
fn bifrostignore_hides_symbols_but_not_file_tools_and_refreshes() {
    let project = InlineTestProject::new()
        .file(".bifrostignore", "vendor/\n")
        .file("src/visible.rs", "fn visible_symbol() {}\n")
        .file("vendor/generated.rs", "fn ignored_generated_symbol() {}\n")
        .build();
    let repository = git2::Repository::init(project.root()).unwrap();
    let mut index = repository.index().unwrap();
    for path in [".bifrostignore", "src/visible.rs", "vendor/generated.rs"] {
        index.add_path(Path::new(path)).unwrap();
    }
    index.write().unwrap();

    let service =
        SearchToolsService::new_without_semantic_index(project.root().to_path_buf()).unwrap();

    let visible = service
        .call_tool_json("search_symbols", r#"{"patterns":["visible_symbol"]}"#)
        .unwrap();
    assert!(visible.contains("visible_symbol"), "payload: {visible}");

    let ignored = service
        .call_tool_json(
            "search_symbols",
            r#"{"patterns":["ignored_generated_symbol"]}"#,
        )
        .unwrap();
    let ignored_value: Value = serde_json::from_str(&ignored).unwrap();
    assert!(
        ignored_value["files"]
            .as_array()
            .is_some_and(|files| files.is_empty()),
        "payload: {ignored}"
    );

    let filenames = service
        .call_tool_json("find_filenames", r#"{"patterns":["generated.rs"]}"#)
        .unwrap();
    assert!(
        filenames.contains("vendor/generated.rs"),
        "payload: {filenames}"
    );

    let listing = service
        .call_tool_json("list_files", r#"{"directory_path":"vendor"}"#)
        .unwrap();
    assert!(
        listing.contains("vendor/generated.rs"),
        "payload: {listing}"
    );

    fs::write(project.root().join(".bifrostignore"), "").unwrap();
    service.call_tool_json("refresh", "{}").unwrap();
    let refreshed = service
        .call_tool_json(
            "search_symbols",
            r#"{"patterns":["ignored_generated_symbol"]}"#,
        )
        .unwrap();
    let refreshed_value: Value = serde_json::from_str(&refreshed).unwrap();
    assert!(
        refreshed_value["files"]
            .as_array()
            .is_some_and(|files| !files.is_empty()),
        "payload: {refreshed}"
    );
}
