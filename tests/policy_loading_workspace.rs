//! Public regression coverage for the workspace-document boundary shared by
//! query and policy loading.

mod common;

use brokk_bifrost::{Language, SearchToolsService};
use common::InlineTestProject;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::symlink;
use tempfile::TempDir;

#[test]
fn query_file_keeps_normalized_workspace_relative_behavior() {
    let project = InlineTestProject::with_language(Language::Python)
        .file("app.py", "class App:\n    pass\n")
        .build();
    fs::create_dir(project.root().join("queries")).unwrap();
    fs::write(
        project.root().join("queries/app.rql"),
        "(class :name \"App\")",
    )
    .unwrap();
    let service =
        SearchToolsService::new_manual_without_semantic_index(project.root().to_path_buf())
            .unwrap();

    for path in [
        "queries/app.rql".to_string(),
        "queries/./app.rql".to_string(),
        r"queries\app.rql".to_string(),
        project.root().join("queries/app.rql").display().to_string(),
    ] {
        let result = service
            .call_tool_value("query_code", serde_json::json!({ "query_file": path }))
            .unwrap();
        assert_eq!(result["results"][0]["path"], "app.py");
    }

    let error = service
        .call_tool_value(
            "query_code",
            serde_json::json!({ "query_file": "../outside.rql" }),
        )
        .unwrap_err();
    assert!(
        error
            .message
            .contains("query file path escapes active workspace"),
        "{error}"
    );
}

#[test]
fn query_file_preserves_unicode_paths_and_query_content() {
    let project = InlineTestProject::with_language(Language::Python)
        .file("app.py", "class Données:\n    pass\n")
        .build();
    fs::create_dir(project.root().join("requêtes-données")).unwrap();
    fs::write(
        project.root().join("requêtes-données/sélection.rql"),
        "(class :name \"Données\")",
    )
    .unwrap();
    let service =
        SearchToolsService::new_manual_without_semantic_index(project.root().to_path_buf())
            .unwrap();

    let result = service
        .call_tool_value(
            "query_code",
            serde_json::json!({ "query_file": "requêtes-données/sélection.rql" }),
        )
        .unwrap();

    assert_eq!(result["results"][0]["path"], "app.py");
}

#[cfg(unix)]
#[test]
fn query_file_rejects_portable_windows_prefixes_before_relative_normalization() {
    let project = InlineTestProject::with_language(Language::Python)
        .file("app.py", "class App:\n    pass\n")
        .build();
    let service =
        SearchToolsService::new_manual_without_semantic_index(project.root().to_path_buf())
            .unwrap();

    for path in [
        "C:foo",
        r"C:\foo",
        r"\\server\share\foo",
        r"\\?\C:\foo",
        r"\\?\UNC\server\share\foo",
        r"\\.\pipe\foo",
    ] {
        let error = service
            .call_tool_value("query_code", serde_json::json!({ "query_file": path }))
            .unwrap_err();
        assert!(
            error.message.contains("outside active workspace"),
            "portable prefix was not rejected during argument normalization: {path}: {error}"
        );
    }
}

#[cfg(unix)]
#[test]
fn explicit_file_symlinks_are_confined_by_the_workspace_capability() {
    let project = InlineTestProject::with_language(Language::Python)
        .file("app.py", "class App:\n    pass\n")
        .build();
    fs::create_dir(project.root().join("queries")).unwrap();
    fs::write(
        project.root().join("queries/app.rql"),
        "(class :name \"App\")",
    )
    .unwrap();
    symlink("app.rql", project.root().join("queries/internal.rql")).unwrap();
    symlink("queries", project.root().join("query-directory-link")).unwrap();

    let outside = TempDir::new().unwrap();
    fs::write(outside.path().join("outside.rql"), "(class :name \"App\")").unwrap();
    symlink(
        outside.path().join("outside.rql"),
        project.root().join("queries/outside.rql"),
    )
    .unwrap();

    let service =
        SearchToolsService::new_manual_without_semantic_index(project.root().to_path_buf())
            .unwrap();
    for path in ["queries/internal.rql", "query-directory-link/app.rql"] {
        service
            .call_tool_value("query_code", serde_json::json!({ "query_file": path }))
            .unwrap();
    }

    let error = service
        .call_tool_value(
            "query_code",
            serde_json::json!({ "query_file": "queries/outside.rql" }),
        )
        .unwrap_err();
    assert!(
        error.message.contains("outside active workspace"),
        "{error}"
    );
}
